import { spawn, spawnSync, execSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { toWslPath } from './execUtils.js';

/**
 * ProofSandbox
 * 
 * Provides an isolated local execution environment adhering to Section 9:
 * - isolated temporary directory
 * - controlled working directory
 * - controlled PATH
 * - explicit environment variables
 * - timeout enforcement
 * - stdout / stderr limits
 * - process-tree cleanup
 * - rejection of external network access & cloud/production hosts
 */
export class ProofSandbox {
    /**
     * @param {Object} [options]
     * @param {string} [options.baseDir] Base directory for sandbox runs
     * @param {number} [options.defaultTimeoutMs=20000] Timeout in milliseconds (default 20s)
     * @param {number} [options.maxBufferBytes=131072] Max stdout/stderr buffer (128 KB)
     * @param {boolean} [options.networkAllowed=false] Network access disallowed by default
     */
    constructor(options = {}) {
        this.baseDir = options.baseDir || path.join(process.cwd(), 'hwsec-output', 'sandbox');
        this.defaultTimeoutMs = options.defaultTimeoutMs || 20000;
        this.maxBufferBytes = options.maxBufferBytes || 131072;
        this.networkAllowed = !!options.networkAllowed;

        if (!fs.existsSync(this.baseDir)) {
            fs.mkdirSync(this.baseDir, { recursive: true });
        }
    }

    /**
     * Creates an isolated workspace directory for a specific proof run.
     * @param {string} proofId 
     * @returns {string} Absolute path to isolated workspace
     */
    createIsolatedWorkspace(proofId = null) {
        const id = proofId || `proof-${crypto.randomBytes(6).toString('hex')}`;
        const wsDir = path.join(this.baseDir, id);
        if (!fs.existsSync(wsDir)) {
            fs.mkdirSync(wsDir, { recursive: true });
        }
        return wsDir;
    }

    /**
     * Inspects a command or script to ensure it does not target external / production systems.
     * @param {string} commandLine
     * @throws {Error} If command attempts external network connection
     */
    validateCommandSafety(commandLine = '') {
        const cmd = String(commandLine).toLowerCase();

        // Check for disallowed external network indicators
        const externalTargets = [
            /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
            /\b(aws|amazonaws\.com|gcp|googleapis\.com|azure|s3\.amazonaws\.com)\b/i,
            /\b(nc|netcat|ncat|socat|curl|wget)\s+[^\s]+(:\d+)?\b/i,
            /\b(ping|traceroute|ssh|scp|ftp|telnet)\s+/i,
            /\b(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b/
        ];

        for (const pattern of externalTargets) {
            if (pattern.test(cmd)) {
                // Check if it's explicitly targeting localhost
                if (!cmd.includes('localhost') && !cmd.includes('127.0.0.1')) {
                    throw new Error(`[ProofSandbox Safety Violation] Command blocked: execution targets external or cloud system ('${cmd.slice(0, 60)}...')`);
                }
            }
        }

        return true;
    }

    /**
     * Prepares a sanitized environment variable map with credentials stripped.
     * @param {Object} [customEnv={}] 
     * @returns {Object}
     */
    buildSanitizedEnv(customEnv = {}) {
        const env = { ...process.env };

        // Strip sensitive API keys from child process environment
        const sensitiveKeys = [
            'NVIDIA_API_KEY',
            'OPENROUTER_API_KEY',
            'GEMINI_API_KEY',
            'GOOGLE_API_KEY',
            'AWS_SECRET_ACCESS_KEY',
            'AWS_ACCESS_KEY_ID',
            'AZURE_API_KEY',
            'SSH_AUTH_SOCK',
            'GITHUB_TOKEN',
            'GH_TOKEN'
        ];

        for (const k of sensitiveKeys) {
            delete env[k];
        }

        // Set isolation & safety variables
        env.NODE_ENV = 'test';
        env.HWSEC_SANDBOX = '1';
        env.HWSEC_ISOLATED = '1';

        // Neutralize external network access
        if (!this.networkAllowed) {
            env.http_proxy = 'http://127.0.0.1:0';
            env.https_proxy = 'http://127.0.0.1:0';
            env.HTTP_PROXY = 'http://127.0.0.1:0';
            env.HTTPS_PROXY = 'http://127.0.0.1:0';
            env.NO_PROXY = 'localhost,127.0.0.1';
            env.JAVA_TOOL_OPTIONS = '-DsocksProxyHost=127.0.0.1 -DsocksProxyPort=1 -Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=1';
        }

        // Apply custom variables
        return { ...env, ...customEnv };
    }

    /**
     * Executes a command inside the isolated sandbox synchronously.
     * 
     * @param {string} command 
     * @param {Array<string>} [args=[]]
     * @param {Object} [options]
     * @param {string} [options.cwd]
     * @param {number} [options.timeout]
     * @param {Object} [options.env]
     * @returns {{ exitCode: number|null, stdout: string, stderr: string, timedOut: boolean, durationMs: number }}
     */
    execute(command, args = [], options = {}) {
        const fullCmd = [command, ...args].join(' ');
        this.validateCommandSafety(fullCmd);

        const cwd = options.cwd || this.createIsolatedWorkspace();
        const timeout = options.timeout || this.defaultTimeoutMs;
        const env = this.buildSanitizedEnv(options.env || {});

        const startTime = Date.now();
        let timedOut = false;

        const result = spawnSync(command, args, {
            cwd,
            timeout,
            maxBuffer: this.maxBufferBytes,
            env,
            shell: false
        });

        const durationMs = Date.now() - startTime;
        if (result.error && result.error.code === 'ETIMEDOUT') {
            timedOut = true;
            this.killProcessTree(result.pid);
        }

        const stdout = (result.stdout || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
        const stderr = (result.stderr || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
        const exitCode = result.status;

        return {
            command: fullCmd,
            cwd,
            exitCode,
            stdout,
            stderr,
            timedOut,
            durationMs
        };
    }

    /**
     * Checks if a Java runtime (host javac/mvn or docker hwsec-java-sandbox) is available.
     * @returns {{ available: boolean, runtimeType?: 'host'|'docker', version?: string, reason?: string }}
     */
    checkJavaAvailability() {
        if (this._javaAvailability !== undefined) return this._javaAvailability;

        // 1. Check host javac
        try {
            const hostCmd = process.platform === 'win32' ? 'javac.exe' : 'javac';
            const hostCheck = spawnSync(hostCmd, ['-version'], { timeout: 3000 });
            if (hostCheck.status === 0 || (hostCheck.stderr && hostCheck.stderr.toString().includes('javac'))) {
                const ver = (hostCheck.stdout || hostCheck.stderr || '').toString().trim();
                this._javaAvailability = { available: true, runtimeType: 'host', version: ver };
                return this._javaAvailability;
            }
        } catch (e) {}

        // 2. Check WSL javac on Windows
        if (process.platform === 'win32') {
            try {
                const wslCheck = spawnSync('wsl', ['javac', '-version'], { timeout: 5000 });
                if (wslCheck.status === 0 || (wslCheck.stderr && wslCheck.stderr.toString().includes('javac'))) {
                    const ver = (wslCheck.stdout || wslCheck.stderr || '').toString().trim();
                    this._javaAvailability = { available: true, runtimeType: 'wsl', version: ver };
                    return this._javaAvailability;
                }
            } catch (e) {}
        }

        // 3. Check docker hwsec-java-sandbox
        try {
            const dCheck = spawnSync('docker', ['run', '--rm', 'hwsec-java-sandbox', 'javac', '-version'], { timeout: 6000 });
            if (dCheck.status === 0 || (dCheck.stdout && dCheck.stdout.toString().includes('javac'))) {
                const ver = (dCheck.stdout || dCheck.stderr || '').toString().trim();
                this._javaAvailability = { available: true, runtimeType: 'docker', version: ver };
                return this._javaAvailability;
            }
        } catch (e) {}

        this._javaAvailability = { available: false, reason: 'Java/Maven validation environment unavailable on host, WSL, and docker' };
        return this._javaAvailability;
    }

    /**
     * Executes a Java or Maven command inside the isolated sandbox, using host, WSL, or container runtime.
     * Enforces credential stripping, network restrictions, timeout bounding, and output capture.
     * @param {string|Array<string>} commandOrArgs 
     * @param {Object} [options]
     * @returns {{ exitCode: number|null, stdout: string, stderr: string, timedOut: boolean, durationMs: number, toolVersion?: string, unavailable?: boolean, failure_reason?: string }}
     */
    executeJava(commandOrArgs, options = {}) {
        const avail = this.checkJavaAvailability();
        if (!avail.available) {
            return {
                unavailable: true,
                failure_reason: avail.reason,
                exitCode: -1,
                stdout: '',
                stderr: avail.reason,
                timedOut: false,
                durationMs: 0,
                toolVersion: 'none'
            };
        }

        const cwd = options.cwd || this.createIsolatedWorkspace();
        const timeout = options.timeout || this.defaultTimeoutMs;

        // Structured arguments or command line string
        let commandString = '';
        let cmdArgs = [];
        if (Array.isArray(commandOrArgs)) {
            cmdArgs = commandOrArgs;
            commandString = commandOrArgs.map(a => /\s/.test(a) ? `"${a.replace(/"/g, '\\"')}"` : a).join(' ');
        } else {
            commandString = String(commandOrArgs);
            cmdArgs = ['bash', '-c', commandString];
        }

        this.validateCommandSafety(commandString);

        if (avail.runtimeType === 'host') {
            const args = process.platform === 'win32' ? ['/c', commandString] : ['-c', commandString];
            const shell = process.platform === 'win32' ? 'cmd.exe' : '/bin/sh';
            const res = this.execute(shell, args, { cwd, timeout, env: options.env });
            res.toolVersion = avail.version;
            return res;
        } else if (avail.runtimeType === 'wsl') {
            const wslCwd = toWslPath(cwd);
            const startTime = Date.now();
            let timedOut = false;
            const env = this.buildSanitizedEnv(options.env || {});
            const envVarsToPass = [];
            for (const [k, v] of Object.entries(env)) {
                if (k.startsWith('HWSEC_') || k.startsWith('JAVA_') || k.toLowerCase().includes('proxy') || k === 'NODE_ENV') {
                    envVarsToPass.push(`${k}=${v}`);
                }
            }
            const wslArgs = ['--cd', wslCwd, 'env', ...envVarsToPass, ...cmdArgs];
            const res = spawnSync('wsl', wslArgs, {
                cwd,
                timeout,
                env,
                maxBuffer: this.maxBufferBytes
            });
            const durationMs = Date.now() - startTime;
            if (res.error && res.error.code === 'ETIMEDOUT') {
                timedOut = true;
            }
            const stdout = (res.stdout || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
            const stderr = (res.stderr || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
            return {
                command: commandString,
                cwd,
                exitCode: res.status,
                stdout,
                stderr,
                timedOut,
                durationMs,
                toolVersion: avail.version
            };
        } else {
            // Docker containerized execution
            const normCwd = path.resolve(cwd).replace(/\\/g, '/');
            const dockerArgs = [
                'run', '--rm',
                '--network', 'none',
                '-v', `${normCwd}:/workspace:rw`,
                '-w', '/workspace',
                'hwsec-java-sandbox',
                ...(Array.isArray(commandOrArgs) ? commandOrArgs : ['bash', '-c', commandString])
            ];
            const startTime = Date.now();
            let timedOut = false;
            const res = spawnSync('docker', dockerArgs, {
                timeout,
                maxBuffer: this.maxBufferBytes
            });
            const durationMs = Date.now() - startTime;
            if (res.error && res.error.code === 'ETIMEDOUT') {
                timedOut = true;
            }
            const stdout = (res.stdout || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
            const stderr = (res.stderr || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
            return {
                command: commandString,
                cwd,
                exitCode: res.status,
                stdout,
                stderr,
                timedOut,
                durationMs,
                toolVersion: avail.version
            };
        }
    }

    /**
     * Terminates a process tree across Windows and Linux.
     * @param {number} pid 
     */
    killProcessTree(pid) {
        if (!pid) return;
        try {
            if (process.platform === 'win32') {
                execSync(`taskkill /pid ${pid} /T /F`, { stdio: 'ignore' });
            } else {
                process.kill(-pid, 'SIGKILL');
            }
        } catch (e) {
            // Already dead or permission error
        }
    }

    /**
     * Removes an isolated workspace directory when cleanup is requested.
     * @param {string} workspacePath 
     */
    cleanupWorkspace(workspacePath) {
        if (workspacePath && fs.existsSync(workspacePath)) {
            try {
                fs.rmSync(workspacePath, { recursive: true, force: true });
            } catch (e) {
                // Ignore cleanup lock errors
            }
        }
    }
}
