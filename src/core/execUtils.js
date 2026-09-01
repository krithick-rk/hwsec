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

/**
 * Deterministically executes a command with a timeout, capturing telemetry.
 * @param {string} command 
 * @param {string[]} args 
 * @param {Object} options 
 * @param {number} [options.timeout=60000] - Timeout in milliseconds
 * @param {string} [options.cwd]
 * @returns {Promise<Object>}
 */
export function runCommand(command, args, options = {}) {
    const timeout = options.timeout || 60000;
    
    return new Promise((resolve) => {
        const startTime = Date.now();
        
        let stdout = '';
        let stderr = '';
        let isTimeout = false;
        
        const child = spawn(command, args, {
            cwd: options.cwd || process.cwd(),
            shell: process.platform === 'win32' && command !== 'cmd.exe' && command !== 'wsl'
        });

        const timer = setTimeout(() => {
            isTimeout = true;
            child.kill('SIGKILL');
        }, timeout);

        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        child.stderr.on('data', (data) => {
            stderr += data.toString();
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
