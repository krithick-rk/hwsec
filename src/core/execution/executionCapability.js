import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import os from 'os';
import crypto from 'crypto';
import { toWslPath, toWindowsPath } from '../execUtils.js';

export const ExecutionCapability = {
    C_COMPILER: 'c_compiler',
    CXX_COMPILER: 'cxx_compiler',
    VERILOG_SIMULATOR: 'verilog_simulator',
    VERILOG_SYNTHESIS: 'verilog_synthesis',
    FORMAL_VERIFIER: 'formal_verifier',
    PYTHON_RUNTIME: 'python_runtime',
    JAVA_RUNTIME: 'java_runtime'
};

export const BackendType = {
    PROJECT_LOCAL: 'project-local',
    NATIVE_HOST: 'native',
    WSL: 'wsl',
    CONTAINER: 'container',
    UNAVAILABLE: 'unavailable'
};

export const ExecutionReasonCode = {
    SUCCESS: 'SUCCESS',
    TOOLCHAIN_UNAVAILABLE: 'TOOLCHAIN_UNAVAILABLE',
    EXECUTION_BACKEND_UNAVAILABLE: 'EXECUTION_BACKEND_UNAVAILABLE',
    EXECUTION_BLOCKED_POLICY: 'EXECUTION_BLOCKED_POLICY',
    TIMEOUT: 'TIMEOUT',
    BUILD_FAILED: 'BUILD_FAILED',
    SIMULATOR_FAILED: 'SIMULATOR_FAILED'
};

/**
 * Centralized Execution Capability Abstraction Layer
 * Resolves toolchains in preferred order: project-local -> native host -> WSL -> container
 */
export class ExecutionCapabilityManager {
    constructor(options = {}) {
        this.cache = new Map();
        this.maxBufferBytes = options.maxBufferBytes || 131072; // 128KB
        this.defaultTimeoutMs = options.defaultTimeoutMs || 25000;
        this.forceUnavailable = !!options.forceUnavailable;
    }

    /**
     * Discovers available backends for a requested capability.
     * @param {string} capability 
     * @param {Object} [options]
     * @returns {Array<Object>} List of discovered capability records
     */
    discover(capability, options = {}) {
        if (this.forceUnavailable) {
            return [];
        }

        const records = [];
        const cwd = options.cwd || process.cwd();

        // 1. Project-local check
        const localCheck = this._checkProjectLocal(capability, cwd);
        if (localCheck.available) {
            records.push({
                backend: BackendType.PROJECT_LOCAL,
                capability,
                executable: localCheck.path,
                version: localCheck.version
            });
        }

        // 2. Native host check
        const hostCheck = this._checkNativeHost(capability);
        if (hostCheck.available) {
            records.push({
                backend: BackendType.NATIVE_HOST,
                capability,
                executable: hostCheck.path,
                version: hostCheck.version
            });
        }

        // 3. WSL check (on Windows)
        if (process.platform === 'win32') {
            const wslCheck = this._checkWsl(capability);
            if (wslCheck.available) {
                records.push({
                    backend: BackendType.WSL,
                    capability,
                    executable: wslCheck.path,
                    version: wslCheck.version
                });
            }
        }

        // 4. Container check
        const containerCheck = this._checkContainer(capability);
        if (containerCheck.available) {
            records.push({
                backend: BackendType.CONTAINER,
                capability,
                image: containerCheck.image,
                version: containerCheck.version
            });
        }

        return records;
    }

    /**
     * Probes a specific capability on a specific backend.
     */
    probe(capability, backend, options = {}) {
        const cacheKey = `${capability}:${backend}`;
        if (this.cache.has(cacheKey)) {
            return this.cache.get(cacheKey);
        }

        const t0 = Date.now();
        let res = { available: false, probe_latency_ms: 0, version: null, path: null };

        switch (backend) {
            case BackendType.PROJECT_LOCAL:
                res = this._checkProjectLocal(capability, options.cwd || process.cwd());
                break;
            case BackendType.NATIVE_HOST:
                res = this._checkNativeHost(capability);
                break;
            case BackendType.WSL:
                res = this._checkWsl(capability);
                break;
            case BackendType.CONTAINER:
                res = this._checkContainer(capability);
                break;
        }

        res.probe_latency_ms = Date.now() - t0;
        this.cache.set(cacheKey, res);
        return res;
    }

    /**
     * Selects the highest priority operational backend for the capability.
     * Order: project-local -> native host -> WSL -> container
     */
    select(capability, policy = {}) {
        if (this.forceUnavailable) {
            return { backend: BackendType.UNAVAILABLE, reason: ExecutionReasonCode.TOOLCHAIN_UNAVAILABLE };
        }

        const order = [BackendType.PROJECT_LOCAL, BackendType.NATIVE_HOST, BackendType.WSL, BackendType.CONTAINER];
        for (const b of order) {
            const probeRes = this.probe(capability, b, policy);
            if (probeRes.available) {
                return {
                    backend: b,
                    capability,
                    executable: probeRes.path || probeRes.image,
                    version: probeRes.version,
                    provenance: probeRes
                };
            }
        }

        return { backend: BackendType.UNAVAILABLE, reason: ExecutionReasonCode.TOOLCHAIN_UNAVAILABLE };
    }

    /**
     * Executes a command using structured argv arrays (never shell concatenation).
     * Enforces sanitization, timeout bounding, network policies, and output capture.
     */
    execute(argv, options = {}) {
        if (!Array.isArray(argv) || argv.length === 0) {
            throw new Error('[ExecutionCapability] argv must be a non-empty Array of strings. Shell string interpolation is strictly disallowed.');
        }

        const backend = options.backend || BackendType.NATIVE_HOST;
        const cwd = options.cwd || process.cwd();
        const timeout = options.timeout || this.defaultTimeoutMs;
        const startTime = Date.now();

        // 1. Safety validation: Reject destructive / network indicators
        this._validateArgvSafety(argv);

        // 2. Sanitized environment
        const env = this._buildSanitizedEnv(options.env || {});

        let execResult;
        if (backend === BackendType.WSL) {
            execResult = this._executeWsl(argv, cwd, timeout, env);
        } else if (backend === BackendType.CONTAINER) {
            execResult = this._executeContainer(argv, options.image, cwd, timeout, env);
        } else {
            // NATIVE_HOST or PROJECT_LOCAL
            execResult = this._executeNative(argv, cwd, timeout, env);
        }

        const durationMs = Date.now() - startTime;
        const stdout = (execResult.stdout || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
        const stderr = (execResult.stderr || Buffer.alloc(0)).toString('utf-8', 0, this.maxBufferBytes);
        const exitCode = execResult.status !== undefined ? execResult.status : (execResult.exitCode ?? 1);
        const timedOut = !!execResult.timedOut || (execResult.error && execResult.error.code === 'ETIMEDOUT');

        const stdoutDigest = crypto.createHash('sha256').update(stdout).digest('hex');
        const stderrDigest = crypto.createHash('sha256').update(stderr).digest('hex');

        let failureReason = null;
        if (timedOut) {
            failureReason = ExecutionReasonCode.TIMEOUT;
        } else if (exitCode !== 0) {
            failureReason = options.failureReason || 'NONZERO_EXIT_CODE';
        }

        return {
            command_argv: argv,
            backend,
            executable_or_image: argv[0],
            cwd,
            environment_fingerprint: crypto.createHash('sha256').update(JSON.stringify(Object.keys(env).sort())).digest('hex').slice(0, 16),
            start_time: startTime,
            end_time: Date.now(),
            duration_ms: durationMs,
            exit_code: exitCode,
            stdout,
            stdout_digest: stdoutDigest,
            stderr,
            stderr_digest: stderrDigest,
            timeout: timedOut,
            safety_decision: 'ALLOWED',
            failure_reason: failureReason
        };
    }

    _validateArgvSafety(argv) {
        const fullString = argv.join(' ').toLowerCase();
        const forbiddenPatterns = [
            /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/i,
            /\b(aws|amazonaws\.com|gcp|googleapis\.com|azure)\b/i,
            /\b(nc|netcat|ncat|socat)\s+[^\s]+(\s+\d+)?\b/i,
            /\b(curl|wget)\s+https?:\/\/(?!localhost|127\.0\.0\.1)/i,
            /\/dev\/tcp\/[^\s]+/i,
            /\brm\s+-rf\s+\/(?:\s|$|\*)/i,
            /\bdd\s+if=[^\s]+\s+of=\/dev\/(?:sd|nvme|hd)/i
        ];

        for (const pat of forbiddenPatterns) {
            if (pat.test(fullString)) {
                throw new Error(`[ExecutionCapability Safety Violation] Command blocked by policy: detected forbidden network or destructive operation (${fullString.slice(0, 60)}...)`);
            }
        }
    }

    _buildSanitizedEnv(customEnv = {}) {
        const env = { ...process.env };
        const sensitiveKeys = [
            'NVIDIA_API_KEY', 'OPENROUTER_API_KEY', 'GEMINI_API_KEY',
            'GOOGLE_API_KEY', 'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID',
            'AZURE_API_KEY', 'SSH_AUTH_SOCK', 'GITHUB_TOKEN', 'GH_TOKEN'
        ];
        for (const k of Object.keys(env)) {
            if (/API_KEY|SECRET|TOKEN|PASSWORD|AUTH|CREDENTIAL/i.test(k) || sensitiveKeys.includes(k)) {
                delete env[k];
            }
        }
        env.HWSEC_SANDBOX = '1';
        env.NODE_ENV = 'test';
        // Deny external network access
        env.http_proxy = 'http://127.0.0.1:0';
        env.https_proxy = 'http://127.0.0.1:0';
        env.HTTP_PROXY = 'http://127.0.0.1:0';
        env.HTTPS_PROXY = 'http://127.0.0.1:0';
        env.NO_PROXY = 'localhost,127.0.0.1';

        return { ...env, ...customEnv };
    }

    _executeNative(argv, cwd, timeout, env) {
        const cmd = argv[0];
        const args = argv.slice(1);
        try {
            return spawnSync(cmd, args, {
                cwd,
                timeout,
                maxBuffer: this.maxBufferBytes,
                env,
                shell: false
            });
        } catch (err) {
            return { status: 1, stdout: '', stderr: err.message, timedOut: false };
        }
    }

    _executeWsl(argv, cwd, timeout, env) {
        const wslCwd = toWslPath(cwd);
        // Map any paths in argv to WSL paths if they contain Windows drive/path formatting
        const mappedArgv = argv.map((arg) => {
            if (typeof arg === 'string' && (arg.includes(':\\') || arg.includes(':/') || (arg.startsWith('\\') && !arg.startsWith('-')))) {
                return toWslPath(arg);
            }
            return arg;
        });

        const defaultLinuxPath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
        const envAssignments = [`PATH=${defaultLinuxPath}`];
        for (const [k, v] of Object.entries(env)) {
            if (k.startsWith('HWSEC_') || k === 'NODE_ENV') {
                const val = typeof v === 'string' && v.includes(':\\') ? toWslPath(v) : v;
                envAssignments.push(`${k}=${val}`);
            }
        }
        const wslArgs = ['--cd', wslCwd, '-e', 'env', ...envAssignments, ...mappedArgv];

        try {
            return spawnSync('wsl', wslArgs, {
                cwd,
                timeout,
                maxBuffer: this.maxBufferBytes,
                env,
                shell: false
            });
        } catch (err) {
            return { status: 1, stdout: '', stderr: err.message, timedOut: false };
        }
    }

    _executeContainer(argv, image, cwd, timeout, env) {
        const dockerArgs = [
            'run', '--rm',
            '--network', 'none',
            '-v', `${cwd}:/workspace`,
            '-w', '/workspace',
            image || 'hwsec-java-sandbox:latest',
            ...argv
        ];

        try {
            return spawnSync('docker', dockerArgs, {
                cwd,
                timeout,
                maxBuffer: this.maxBufferBytes,
                env,
                shell: false
            });
        } catch (err) {
            return { status: 1, stdout: '', stderr: err.message, timedOut: false };
        }
    }

    // --- Probe Helpers ---

    _checkProjectLocal(capability, cwd) {
        const localBinDir = path.join(cwd, 'bin');
        const toolNames = this._getToolNames(capability);
        for (const t of toolNames) {
            const candidate = path.join(localBinDir, process.platform === 'win32' ? `${t}.exe` : t);
            if (fs.existsSync(candidate)) {
                return { available: true, path: candidate, version: 'project-local' };
            }
        }
        return { available: false, path: null, version: null };
    }

    _checkNativeHost(capability) {
        const toolNames = this._getToolNames(capability);

        // On Windows: build a PATH that includes OSS CAD Suite bin/ and lib/
        // so that DLL-dependent tools like yosys.exe and verilator_bin.exe can load.
        let nativeEnv = process.env;
        if (process.platform === 'win32') {
            const suiteRoot = process.env.OSS_CAD_SUITE || process.env.YOSYSHQ_ROOT || null;
            if (suiteRoot && fs.existsSync(suiteRoot)) {
                const binDir = path.join(suiteRoot, 'bin');
                const libDir = path.join(suiteRoot, 'lib');
                const existingPath = process.env.PATH || '';
                nativeEnv = {
                    ...process.env,
                    PATH: `${binDir};${libDir};${existingPath}`,
                    YOSYSHQ_ROOT: suiteRoot + (suiteRoot.endsWith('\\') || suiteRoot.endsWith('/') ? '' : path.sep)
                };
            }
        }

        for (const t of toolNames) {
            const binName = process.platform === 'win32' ? `${t}.exe` : t;
            try {
                const res = spawnSync(binName, ['--version'], { timeout: 5000, shell: false, env: nativeEnv });
                if (res.status === 0 || (res.stdout && res.stdout.length > 0)) {
                    const firstLine = (res.stdout || '').toString().split('\n')[0].trim();
                    return { available: true, path: binName, version: firstLine };
                }
            } catch (e) {}
        }
        return { available: false, path: null, version: null };
    }

    _checkWsl(capability) {
        const toolNames = this._getToolNames(capability);
        // Include /usr/local/bin for tools built from source (e.g. spike, semgrep)
        const wslPath = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
        for (const t of toolNames) {
            try {
                const res = spawnSync('wsl', ['-e', 'env', `PATH=${wslPath}`, 'which', t], { timeout: 10000, shell: false });
                if (res.status === 0 && res.stdout && res.stdout.toString().trim().length > 0) {
                    const discoveredPath = res.stdout.toString().trim().split('\n')[0].trim();
                    // Get version
                    const verRes = spawnSync('wsl', ['-e', 'env', `PATH=${wslPath}`, t, '--version'], { timeout: 10000, shell: false });
                    const verOut = (verRes.stdout || verRes.stderr || '').toString().split('\n')[0].trim();
                    return { available: true, path: discoveredPath, version: verOut };
                }
            } catch (e) {}
        }
        return { available: false, path: null, version: null };
    }

    _checkContainer(capability) {
        if (capability === ExecutionCapability.JAVA_RUNTIME) {
            try {
                const res = spawnSync('docker', ['image', 'inspect', 'hwsec-java-sandbox:latest'], { timeout: 3000, shell: false });
                if (res.status === 0) {
                    return { available: true, image: 'hwsec-java-sandbox:latest', version: 'docker-openjdk-17' };
                }
            } catch (e) {}
        }
        return { available: false, image: null, version: null };
    }

    _getToolNames(capability) {
        switch (capability) {
            case ExecutionCapability.C_COMPILER:
                return ['gcc', 'clang'];
            case ExecutionCapability.CXX_COMPILER:
                return ['g++', 'clang++'];
            case ExecutionCapability.VERILOG_SIMULATOR:
                return ['iverilog', 'verilator'];
            case ExecutionCapability.VERILOG_SYNTHESIS:
                return ['yosys'];
            case ExecutionCapability.FORMAL_VERIFIER:
                return ['sby', 'symbiyosys'];
            case ExecutionCapability.PYTHON_RUNTIME:
                return process.platform === 'win32' ? ['py', 'python', 'python3'] : ['python3', 'python'];
            case ExecutionCapability.JAVA_RUNTIME:
                return ['java'];
            default:
                return [];
        }
    }
}
