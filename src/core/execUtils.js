import { spawn } from 'child_process';
import os from 'os';
import path from 'path';

/**
 * Converts a Windows absolute path to a WSL path (e.g. E:\dir -> /mnt/e/dir)
 * @param {string} winPath 
 * @returns {string}
 */
export function toWslPath(winPath) {
    if (!winPath) return winPath;
    const resolved = path.resolve(winPath);
    const driveMatch = resolved.match(/^([a-zA-Z]):[\\/](.*)/);
    if (driveMatch) {
        const driveLetter = driveMatch[1].toLowerCase();
        const rest = driveMatch[2].replace(/\\/g, '/');
        return `/mnt/${driveLetter}/${rest}`;
    }
    return winPath.replace(/\\/g, '/');
}

/**
 * Converts a WSL path to a Windows path (e.g. /mnt/e/dir -> E:\dir)
 * @param {string} wslPath 
 * @returns {string}
 */
export function toWindowsPath(wslPath) {
    if (!wslPath) return wslPath;
    const mntMatch = wslPath.match(/^\/mnt\/([a-zA-Z])\/(.*)/);
    if (mntMatch) {
        const driveLetter = mntMatch[1].toUpperCase();
        const rest = mntMatch[2].replace(/\//g, '\\');
        return `${driveLetter}:\\${rest}`;
    }
    return wslPath;
}

export const ExecutionTransport = {
    LOCAL_PROCESS: 'LOCAL_PROCESS',
    MCP: 'MCP',
    REMOTE: 'REMOTE'
};

/**
 * Executes a command in WSL safely without shell interpolation.
 * @param {string} command - Linux binary or command inside WSL
 * @param {string[]} args - Arguments
 * @param {Object} options - Standard options
 * @returns {Promise<Object>}
 */
export async function runWslCommand(command, args = [], options = {}) {
    const defaultLinuxPath = '/home/intern/tools/jdk-26/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
    const wslArgs = ['-e', 'env', `PATH=${defaultLinuxPath}`, command, ...args];
    return runCommand('wsl', wslArgs, {
        ...options,
        shell: false
    });
}

/**
 * Deterministically executes a command with a timeout, capturing telemetry.
 * @param {string} command 
 * @param {string[]} args 
 * @param {Object} options 
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {string} [options.cwd]
 * @param {boolean} [options.shell]
 * @returns {Promise<Object>}
 */
function sanitizeEnv(customEnv) {
    if (customEnv) {
        return customEnv;
    }
    const cleanEnv = { ...process.env };
    for (const key of ['PATH', 'Path']) {
        if (cleanEnv[key]) {
            cleanEnv[key] = cleanEnv[key]
                .split(path.delimiter)
                .filter(entry => !entry.toLowerCase().includes('krithick'))
                .join(path.delimiter);
        }
    }
    return cleanEnv;
}

export function runCommand(command, args = [], options = {}) {
    const timeout = options.timeout || 60000;
    const maxOutputBytes = options.maxOutputBytes || 10485760; // 10MB default buffer ceiling
    const useShell = options.shell === true; // Never default to shell: true!

    return new Promise((resolve) => {
        const startTime = Date.now();
        
        let stdout = '';
        let stderr = '';
        let isTimeout = false;
        let stdoutTruncated = false;
        let stderrTruncated = false;
        
        let child;
        try {
            const isWindowsBatch = process.platform === 'win32' && (command.toLowerCase().endsWith('.bat') || command.toLowerCase().endsWith('.cmd'));
            child = spawn(command, args, {
                cwd: options.cwd || process.cwd(),
                shell: useShell || isWindowsBatch,
                env: sanitizeEnv(options.env)
            });
        } catch (err) {
            return resolve({
                command: `${command} ${args.join(' ')}`,
                exitCode: null,
                stdout: '',
                stderr: `Spawn Error: ${err.message}`,
                timeout: false,
                durationMs: 0,
                environment: {
                    platform: os.platform(),
                    release: os.release(),
                    wsl: command === 'wsl'
                },
                executionError: err.message
            });
        }

        const killTree = () => {
            if (!child || !child.pid) return;
            if (process.platform === 'win32') {
                try {
                    spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { shell: false });
                } catch {
                    try { child.kill('SIGKILL'); } catch {}
                }
            } else {
                try {
                    child.kill('SIGKILL');
                } catch {}
            }
        };

        const timer = setTimeout(() => {
            isTimeout = true;
            killTree();
        }, timeout);

        child.stdout?.on('data', (data) => {
            if (stdout.length < maxOutputBytes) {
                stdout += data.toString();
                if (stdout.length >= maxOutputBytes && !stdoutTruncated) {
                    stdoutTruncated = true;
                    stdout += '\n[HWSEC: Output truncated at max buffer size]';
                }
            }
        });

        child.stderr?.on('data', (data) => {
            if (stderr.length < maxOutputBytes) {
                stderr += data.toString();
                if (stderr.length >= maxOutputBytes && !stderrTruncated) {
                    stderrTruncated = true;
                    stderr += '\n[HWSEC: Error output truncated at max buffer size]';
                }
            }
        });

        child.on('close', (code) => {
            clearTimeout(timer);
            const durationMs = Date.now() - startTime;
            
            resolve({
                command: `${command} ${args.join(' ')}`,
                exitCode: isTimeout ? null : code,
                stdout,
                stderr,
                timeout: isTimeout,
                durationMs,
                environment: {
                    platform: os.platform(),
                    release: os.release(),
                    wsl: command === 'wsl'
                }
            });
        });
        
        child.on('error', (err) => {
            clearTimeout(timer);
            const durationMs = Date.now() - startTime;
            resolve({
                command: `${command} ${args.join(' ')}`,
                exitCode: null,
                stdout,
                stderr: stderr + `\nExecution Error: ${err.message}`,
                timeout: false,
                durationMs,
                environment: {
                    platform: os.platform(),
                    release: os.release(),
                    wsl: command === 'wsl'
                },
                executionError: err.message
            });
        });
    });
}

