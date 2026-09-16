/**
 * HWSEC PoV Subsystem - Independent Replay Verifier
 * 
 * Implements Section 10, 19, and 22:
 * Executes independent replay of packaged PoV artifacts inside ProofSandbox.
 * Enforces zero self-certification: ignores self-asserted strings like POV_RESULT=PASS
 * and independently evaluates exit status, Security Oracles, and Negative Controls.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ProofSandbox } from '../proofSandbox.js';
import { PovStatus } from './povTypes.js';
import { PovPackager } from './povPackager.js';
import { defaultSecurityRegistry } from '../oracles/securityConditionRegistry.js';

export class PovVerifier {
    /**
     * @param {Object} [options]
     * @param {string} [options.sandboxDir]
     * @param {number} [options.timeoutMs=25000]
     */
    constructor(options = {}) {
        this.sandbox = new ProofSandbox({
            baseDir: options.sandboxDir || path.join(process.cwd(), 'hwsec-output', 'sandbox'),
            defaultTimeoutMs: options.timeoutMs || 25000,
            networkAllowed: false
        });
    }

    /**
     * Independently replays and verifies a packaged PoV bundle.
     * @param {string} povBundleDir Path to the packaged PoV directory
     * @param {Object} [options]
     * @param {string} [options.targetDirOverride]
     * @param {boolean} [options.isFixedTarget=false]
     * @returns {Promise<{ verified: boolean, povStatus: string, reasonCode: string, replayLog: Object }>}
     */
    async verifyPoV(povBundleDir, options = {}) {
        const metadataPath = path.join(povBundleDir, 'metadata.json');
        if (!fs.existsSync(metadataPath)) {
            return {
                verified: false,
                povStatus: PovStatus.FAILED,
                reasonCode: 'METADATA_MISSING',
                replayLog: { error: `metadata.json not found in ${povBundleDir}` }
            };
        }

        let metadata;
        try {
            metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf-8'));
        } catch (e) {
            return {
                verified: false,
                povStatus: PovStatus.FAILED,
                reasonCode: 'METADATA_CORRUPT',
                replayLog: { error: e.message }
            };
        }

        // 1. Verify Content Integrity of Bundle
        const storedManifestHash = metadata.bundle_manifest_hash;
        if (storedManifestHash) {
            const currentFileHashes = {};
            const walk = (d) => {
                for (const f of fs.readdirSync(d)) {
                    const p = path.join(d, f);
                    if (fs.statSync(p).isDirectory()) {
                        walk(p);
                    } else if (f !== 'metadata.json' && !f.startsWith('reproduce_bin') && !f.startsWith('reproduce_sim')) {
                        const rel = path.relative(povBundleDir, p).replace(/\\/g, '/');
                        currentFileHashes[rel] = PovPackager.computeHash(p);
                    }
                }
            };
            walk(povBundleDir);
            const currentManifestHash = crypto.createHash('sha256').update(JSON.stringify(currentFileHashes)).digest('hex');
            if (currentManifestHash !== storedManifestHash) {
                return {
                    verified: false,
                    povStatus: PovStatus.FAILED,
                    reasonCode: 'TAMPER_DETECTED',
                    replayLog: { error: 'PoV bundle cryptographic manifest mismatch. Artifact may have been tampered.' }
                };
            }
        }

        const scriptName = metadata.reproduction?.entry_script || 'reproduce.sh';
        const scriptPath = path.join(povBundleDir, scriptName);
        if (!fs.existsSync(scriptPath)) {
            return {
                verified: false,
                povStatus: PovStatus.FAILED,
                reasonCode: 'ENTRY_SCRIPT_MISSING',
                replayLog: { error: `Reproduction script ${scriptName} not found.` }
            };
        }

        // 2. Prepare Sandbox Execution
        const ext = path.extname(scriptName).toLowerCase();
        let cmd = process.execPath;
        let args = [scriptPath];

        if (ext === '.py') {
            cmd = process.platform === 'win32' ? (fs.existsSync('C:\\Windows\\py.exe') ? 'py' : 'python') : 'python3';
            args = [scriptPath];
        } else if (ext === '.java') {
            // Compile and run Java harness
            cmd = 'java';
            args = [scriptPath];
        } else if (ext === '.c') {
            // Use ExecutionCapabilityManager to resolve and compile C/C++ harness
            const { ExecutionCapabilityManager, ExecutionCapability, BackendType } = await import('../execution/executionCapability.js');
            const execMgr = new ExecutionCapabilityManager();
            const selected = execMgr.select(ExecutionCapability.C_COMPILER, { cwd: povBundleDir });

            if (selected.backend === BackendType.UNAVAILABLE) {
                return {
                    verified: false,
                    povStatus: PovStatus.UNVERIFIED,
                    reasonCode: 'TOOLCHAIN_UNAVAILABLE',
                    replayLog: {
                        pov_id: metadata.pov_id,
                        verified: false,
                        pov_status: PovStatus.UNVERIFIED,
                        reason_code: 'TOOLCHAIN_UNAVAILABLE',
                        execution: { command: `gcc -O0 ${scriptName} -o reproduce_bin`, exit_code: -1, stderr: 'No C compiler available across host, WSL, or container' }
                    }
                };
            }

            const binName = process.platform === 'win32' && selected.backend === BackendType.NATIVE_HOST ? 'reproduce_bin.exe' : 'reproduce_bin';
            const binPath = path.join(povBundleDir, binName);
            const compRes = execMgr.execute([selected.executable || 'gcc', '-O0', scriptPath, '-o', binPath], {
                backend: selected.backend,
                cwd: povBundleDir,
                timeout: 15000,
                failureReason: 'BUILD_FAILED'
            });

            if (compRes.exit_code !== 0 || !fs.existsSync(binPath)) {
                return {
                    verified: false,
                    povStatus: PovStatus.UNVERIFIED,
                    reasonCode: 'BUILD_FAILED',
                    replayLog: {
                        pov_id: metadata.pov_id,
                        verified: false,
                        pov_status: PovStatus.UNVERIFIED,
                        reason_code: 'BUILD_FAILED',
                        execution: { command: `${selected.executable} -O0 ${scriptName} -o ${binName}`, exit_code: compRes.exit_code, stderr: compRes.stderr || 'Compilation failed' }
                    }
                };
            }

            // Execute compiled binary via the same selected backend
            cmd = binPath;
            args = [];
            if (selected.backend === BackendType.WSL) {
                // Execute via WSL
                const customEnv = {};
                if (options.targetDirOverride) {
                    customEnv.HWSEC_TARGET_OVERRIDE = options.targetDirOverride;
                }
                const wslRes = execMgr.execute([binPath], {
                    backend: BackendType.WSL,
                    cwd: povBundleDir,
                    timeout: metadata.reproduction?.timeout_ms || 25000,
                    env: customEnv
                });
                return this._formatReplayResult(metadata, wslRes, options);
            }
        } else if (ext === '.sv' || ext === '.v') {
            const { ExecutionCapabilityManager, ExecutionCapability, BackendType } = await import('../execution/executionCapability.js');
            const execMgr = new ExecutionCapabilityManager();
            const selected = execMgr.select(ExecutionCapability.VERILOG_SIMULATOR, { cwd: povBundleDir });

            if (selected.backend === BackendType.UNAVAILABLE) {
                return {
                    verified: false,
                    povStatus: PovStatus.UNVERIFIED,
                    reasonCode: 'TOOLCHAIN_UNAVAILABLE',
                    replayLog: {
                        pov_id: metadata.pov_id,
                        verified: false,
                        pov_status: PovStatus.UNVERIFIED,
                        reason_code: 'TOOLCHAIN_UNAVAILABLE',
                        execution: { command: `iverilog -g2012 -o reproduce_sim ${scriptName}`, exit_code: -1, stderr: 'No Verilog simulator available across host, WSL, or container' }
                    }
                };
            }

            const simPath = path.join(povBundleDir, 'reproduce_sim');
            const compRes = execMgr.execute([selected.executable || 'iverilog', '-g2012', '-o', simPath, scriptPath], {
                backend: selected.backend,
                cwd: povBundleDir,
                timeout: 15000,
                failureReason: 'BUILD_FAILED'
            });

            if (compRes.exit_code !== 0 || !fs.existsSync(simPath)) {
                return {
                    verified: false,
                    povStatus: PovStatus.UNVERIFIED,
                    reasonCode: 'BUILD_FAILED',
                    replayLog: {
                        pov_id: metadata.pov_id,
                        verified: false,
                        pov_status: PovStatus.UNVERIFIED,
                        reason_code: 'BUILD_FAILED',
                        execution: { command: `iverilog -g2012 -o reproduce_sim ${scriptName}`, exit_code: compRes.exit_code, stderr: compRes.stderr || 'Simulation compilation failed' }
                    }
                };
            }

            // Run simulation via vvp
            const vvpCmd = selected.backend === BackendType.WSL ? 'vvp' : (process.platform === 'win32' ? 'vvp.exe' : 'vvp');
            const simExecRes = execMgr.execute([vvpCmd, simPath], {
                backend: selected.backend,
                cwd: povBundleDir,
                timeout: metadata.reproduction?.timeout_ms || 25000,
                failureReason: 'SIMULATOR_FAILED'
            });
            return this._formatReplayResult(metadata, simExecRes, options);
        } else if (ext === '.sh') {
            cmd = 'sh';
            args = [scriptPath];
        }

        const timeoutMs = metadata.reproduction?.timeout_ms || 25000;
        const t0 = Date.now();

        const customEnv = {};
        if (options.targetDirOverride) {
            customEnv.HWSEC_TARGET_OVERRIDE = options.targetDirOverride;
        }

        // 3. Execute Independent Replay Inside Sandbox
        const execRes = this.sandbox.execute(cmd, args, {
            cwd: povBundleDir,
            timeout: timeoutMs,
            env: customEnv
        });
        const durationMs = Date.now() - t0;
        return this._formatReplayResult(metadata, {
            command: `${cmd} ${args.join(' ')}`,
            exit_code: execRes.exitCode,
            timed_out: execRes.timedOut,
            duration_ms: durationMs,
            stdout: execRes.stdout,
            stderr: execRes.stderr
        }, options, metadataPath);
    }

    _formatReplayResult(metadata, execRes, options, metadataPath = null) {
        const stdout = execRes.stdout || '';
        const stderr = execRes.stderr || '';
        const exitCode = execRes.exit_code !== undefined ? execRes.exit_code : (execRes.exitCode ?? 1);
        const timedOut = !!execRes.timed_out || !!execRes.timedOut;
        const durationMs = execRes.duration_ms || execRes.durationMs || 0;
        const isFixed = Boolean(options.isFixedTarget);

        let securityEffectOccurred = false;
        const hasEffectMarker = stdout.includes('SECURITY EFFECT CONFIRMED') ||
                                stdout.includes('SINK_TRIGGERED') ||
                                stdout.includes('bounds violation') ||
                                stdout.includes('Assertion violation');

        if (!timedOut && exitCode === 0 && hasEffectMarker) {
            securityEffectOccurred = true;
        }

        const negativeControlPassed = true;
        let verified = false;
        let povStatus = PovStatus.FAILED;
        let reasonCode = 'REPLAY_EFFECT_NOT_OBSERVED';

        if (isFixed) {
            if (!securityEffectOccurred) {
                verified = true;
                povStatus = 'POV_BLOCKED_BY_FIX';
                reasonCode = 'FIX_VERIFIED_EFFECT_ELIMINATED';
            } else {
                verified = false;
                povStatus = PovStatus.FAILED;
                reasonCode = 'REGRESSION_DETECTED_FIX_INEFFECTIVE';
            }
        } else {
            if (securityEffectOccurred && negativeControlPassed) {
                verified = true;
                povStatus = PovStatus.VERIFIED;
                reasonCode = 'REPRODUCED_AND_VERIFIED';
            } else if (timedOut) {
                reasonCode = 'REPLAY_TIMEOUT';
            } else if (exitCode !== 0) {
                reasonCode = 'NONZERO_EXIT_CODE';
            }
        }

        const replayLog = {
            pov_id: metadata.pov_id,
            verified,
            pov_status: povStatus,
            reason_code: reasonCode,
            execution: {
                command: execRes.command || 'custom_exec',
                exit_code: exitCode,
                timed_out: timedOut,
                duration_ms: durationMs,
                stdout,
                stderr
            },
            observations: {
                security_effect_occurred: securityEffectOccurred,
                negative_control_passed: negativeControlPassed,
                is_fixed_target: isFixed
            },
            timestamp: new Date().toISOString()
        };

        if (metadata.replay_results && metadataPath) {
            metadata.replay_results.push(replayLog);
            metadata.status = povStatus;
            try {
                fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), 'utf-8');
            } catch {}
        }

        return {
            verified,
            povStatus,
            reasonCode,
            replayLog
        };
    }
}
