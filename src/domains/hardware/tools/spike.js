import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand, toWslPath } from '../../../core/execUtils.js';
import { createFinding, Severity, VerificationState, createEvidence, createSourceLocation } from '../../../core/schema.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export class SpikeTool extends ToolAdapter {
    get name() {
        return "spike";
    }

    get id() {
        return "spike";
    }

    get capabilities() {
        return ["reference_model", "isa_simulation", "trace_divergence_check"];
    }

    get supportedLanguages() {
        return ["riscv", "c", "cpp", "verilog"];
    }

    /**
     * Checks if Spike RISC-V ISA Simulator is available in Windows PATH or WSL.
     */
    async checkInstalled() {
        const configured = this.config.tool_paths?.spike || 'spike';

        try {
            const res = await runCommand(configured, ['-h'], { timeout: 8000 });
            if (res.exitCode === 0 || (res.stderr && res.stderr.includes('Spike'))) {
                return { installed: true, isWsl: false, cmd: configured, version: 'Spike RISC-V ISA Simulator' };
            }
        } catch {}

        if (process.platform === 'win32') {
            try {
                const wslRes = await runWslCommand('spike', ['-h'], { timeout: 8000 });
                if (wslRes.exitCode === 0 || (wslRes.stderr && wslRes.stderr.includes('Spike'))) {
                    return { installed: true, isWsl: true, cmd: 'spike', version: 'Spike RISC-V ISA Simulator (WSL)' };
                }
            } catch {}
        }

        return { installed: false, error: 'Spike RISC-V ISA Simulator not found in PATH or WSL' };
    }

    /**
     * Parses Spike commit log trace into instruction state steps.
     * Format: core   0: 3 0x0000000080000004 (0x02028593) x11 0x0000000080000020
     */
    parseCommitLog(traceContent) {
        const lines = traceContent.split('\n');
        const steps = [];

        for (const line of lines) {
            const match = line.match(/core\s+(\d+):\s*(?:(\d+)\s+)?(0x[0-9a-fA-F]+)\s+\((0x[0-9a-fA-F]+)\)(?:\s+([a-zA-Z0-9]+)\s+(0x[0-9a-fA-F]+))?/);
            if (match) {
                steps.push({
                    core: match[1],
                    priv: match[2] || '3',
                    pc: match[3],
                    insn: match[4],
                    rd: match[5] || null,
                    val: match[6] || null,
                    raw: line.trim()
                });
            }
        }

        return steps;
    }

    /**
     * Compares Spike reference trace against RTL simulation commit trace.
     */
    compareTraces(spikeSteps, rtlSteps) {
        const divergences = [];
        const maxLen = Math.min(spikeSteps.length, rtlSteps.length);

        for (let i = 0; i < maxLen; i++) {
            const s = spikeSteps[i];
            const r = rtlSteps[i];

            if (s.pc.toLowerCase() !== r.pc.toLowerCase()) {
                divergences.push({
                    step: i,
                    type: 'PC_MISMATCH',
                    spike: s,
                    rtl: r,
                    description: `PC divergence at step ${i}: Spike PC ${s.pc} vs RTL PC ${r.pc}`
                });
                break;
            }

            if (s.rd && r.rd && s.rd === r.rd && s.val && r.val && s.val.toLowerCase() !== r.val.toLowerCase()) {
                divergences.push({
                    step: i,
                    type: 'REGISTER_MISMATCH',
                    spike: s,
                    rtl: r,
                    description: `Register state divergence at step ${i}: Register ${s.rd} Spike value ${s.val} vs RTL value ${r.val}`
                });
                break;
            }
        }

        return divergences;
    }

    /**
     * Executes Spike reference simulation and optional RTL comparison.
     */
    async run(params, legacyOutputDir, legacyOptions) {
        const startTime = Date.now();
        let files = [];
        let outputDir = legacyOutputDir;
        let timeout = 60000;
        let isa = 'RV64GC';

        if (Array.isArray(params)) {
            files = params;
            outputDir = legacyOutputDir || path.resolve('hwsec-output');
        } else if (params && typeof params === 'object') {
            files = params.files || [];
            outputDir = params.outputDir || legacyOutputDir || path.resolve('hwsec-output');
            timeout = params.timeout || timeout;
            isa = params.isa || isa;
        }

        // 1. Availability check
        const check = await this.checkInstalled();
        if (!check.installed) {
            return {
                status: "UNAVAILABLE",
                findings: [],
                reason: check.error,
                telemetry: { error: check.error, checkedAt: new Date().toISOString() }
            };
        }

        // 2. Locate compatible RISC-V binary
        const elfFiles = files.filter(f => {
            const ext = path.extname(f).toLowerCase();
            return ext === '.elf' || ext === '.riscv' || ext === '.bin' || path.basename(f).includes('riscv');
        });

        if (elfFiles.length === 0) {
            return {
                status: "SKIPPED",
                findings: [],
                reason: "No compatible RISC-V ELF executable or test input provided"
            };
        }

        const targetElf = path.resolve(elfFiles[0]);
        const toolsDir = path.join(outputDir, 'tools', 'spike');
        if (!fs.existsSync(toolsDir)) {
            fs.mkdirSync(toolsDir, { recursive: true });
        }

        const traceLogPath = path.join(toolsDir, 'spike_commit_trace.log');

        try {
            const spikeArgs = [`--isa=${isa}`, '-l', '--log-commits', check.isWsl ? toWslPath(targetElf) : targetElf];

            const simRes = check.isWsl
                ? await runWslCommand('spike', spikeArgs, { timeout })
                : await runCommand(check.cmd, spikeArgs, { timeout });

            const traceOutput = `${simRes.stderr}\n${simRes.stdout}`;
            fs.writeFileSync(traceLogPath, traceOutput, 'utf-8');

            const spikeSteps = this.parseCommitLog(traceOutput);
            const findings = [];
            const artifacts = [traceLogPath];

            // 3. Optional RTL Trace Comparison
            const rtlLogFile = files.find(f => f.endsWith('.log') && f !== traceLogPath);
            if (rtlLogFile && fs.existsSync(rtlLogFile)) {
                const rtlLogContent = fs.readFileSync(rtlLogFile, 'utf-8');
                const rtlSteps = this.parseCommitLog(rtlLogContent);

                const divergences = this.compareTraces(spikeSteps, rtlSteps);
                for (const div of divergences) {
                    const findingId = `SPIKE-DIV-${crypto.randomBytes(4).toString('hex')}`;
                    const evidenceObj = createEvidence({
                        id: `EV-${crypto.randomBytes(4).toString('hex')}`,
                        finding_id: findingId,
                        tool_name: "spike",
                        evidence_type: "ISA_REFERENCE_DIVERGENCE",
                        description: div.description,
                        artifact_path: traceLogPath,
                        raw_evidence: div,
                        confidence: 0.95
                    });

                    findings.push(createFinding({
                        id: findingId,
                        title: `[CWE-1234] Hardware Architecture Divergence (${div.type}) at Step ${div.step}`,
                        description: `RTL execution diverged from Spike golden reference model.\n${div.description}\nSpike Trace: \`${div.spike.raw}\`\nRTL Trace: \`${div.rtl.raw}\``,
                        severity: Severity.HIGH,
                        confidence: 0.95,
                        source_tool: "spike",
                        source_locations: [createSourceLocation({
                            path: targetElf,
                            startLine: div.step,
                            endLine: div.step,
                            line: div.step,
                            symbol: div.spike.pc
                        })],
                        evidence: [evidenceObj],
                        verification_state: VerificationState.VERIFIED,
                        cwe_id: "CWE-1234",
                        security_property: "ISA_SPEC_COMPLIANCE"
                    }));
                }
            }

            return {
                status: "SUCCESS",
                findings,
                artifacts,
                telemetry: {
                    instructionsSimulated: spikeSteps.length,
                    durationMs: Date.now() - startTime
                }
            };
        } catch (err) {
            return {
                status: "ERROR",
                findings: [],
                telemetry: {
                    error: err.message,
                    durationMs: Date.now() - startTime
                }
            };
        }
    }
}
