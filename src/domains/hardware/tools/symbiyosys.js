import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand } from '../../../core/execUtils.js';
import { createFinding, Severity, VerificationState, createEvidence, createSourceLocation } from '../../../core/schema.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export class SymbiYosysTool extends ToolAdapter {
    get name() {
        return "symbiyosys";
    }

    get id() {
        return "symbiyosys";
    }

    get capabilities() {
        return ["rtl_formal", "bounded_model_check", "formal_invariant_verification"];
    }

    get supportedLanguages() {
        return ["verilog", "systemverilog"];
    }

    /**
     * Resolves the environment for OSS CAD Suite binaries (sby, yosys, smtbmc).
     */
    _resolveEnvironment() {
        let sbyCmd = this.config?.tool_paths?.sby || 'sby';
        let binDir = null;
        let libDir = null;
        let suiteRoot = null;

        if (fs.existsSync(sbyCmd)) {
            binDir = path.dirname(sbyCmd);
            suiteRoot = path.dirname(binDir);
            const possibleLib = path.join(suiteRoot, 'lib');
            if (fs.existsSync(possibleLib)) {
                libDir = possibleLib;
            }
        } else {
            const defaultOssCadSuite = process.env.OSS_CAD_SUITE || process.env.YOSYSHQ_ROOT || 'E:/Intern/krithick/Downloads/oss-cad-suite';
            if (fs.existsSync(defaultOssCadSuite)) {
                suiteRoot = defaultOssCadSuite;
                binDir = path.join(suiteRoot, 'bin');
                libDir = path.join(suiteRoot, 'lib');
                sbyCmd = path.join(binDir, 'sby.exe');
            }
        }

        const env = { ...process.env };
        if (suiteRoot && binDir) {
            env.YOSYSHQ_ROOT = suiteRoot + (suiteRoot.endsWith('\\') || suiteRoot.endsWith('/') ? '' : path.sep);
            env.PATH = libDir ? `${binDir};${libDir};${env.PATH || ''}` : `${binDir};${env.PATH || ''}`;
            if (libDir) {
                const pyExe = path.join(libDir, 'python3.exe');
                if (fs.existsSync(pyExe)) {
                    env.PYTHON_EXECUTABLE = pyExe;
                }
            }
        }

        return { sbyCmd, binDir, libDir, env };
    }

    async checkInstalled() {
        const { sbyCmd, env } = this._resolveEnvironment();

        try {
            const res = await runCommand(sbyCmd, ['--version'], { env, timeout: 8000 });
            if (res.exitCode === 0) {
                return { installed: true, version: res.stdout.trim() || 'SBY', cmd: sbyCmd, env };
            }
        } catch {}

        // Probe WSL if on Windows
        if (process.platform === 'win32') {
            try {
                const wslRes = await runWslCommand('sby', ['--version'], { timeout: 8000 });
                if (wslRes.exitCode === 0) {
                    return { installed: true, version: wslRes.stdout.trim(), isWsl: true, cmd: 'sby', env: process.env };
                }
            } catch {}
        }

        return { installed: false, error: 'SymbiYosys (sby) not found in configured paths or system PATH' };
    }

    /**
     * Auto-detects top module name from Verilog source.
     */
    _detectTopModule(verilogFiles) {
        for (const file of verilogFiles) {
            if (fs.existsSync(file)) {
                const content = fs.readFileSync(file, 'utf-8');
                const match = content.match(/\bmodule\s+([a-zA-Z_][a-zA-Z0-9_]*)/);
                if (match) {
                    return { top: match[1], file };
                }
            }
        }
        return { top: 'top', file: verilogFiles[0] };
    }

    /**
     * Generates a valid and sanitized .sby configuration project.
     */
    generateSbyConfig({ targetFiles, topModule, mode = 'bmc', depth = 20, engine = 'smtbmc' }) {
        if (!/^[a-zA-Z_][a-zA-Z0-9_$]*$/.test(topModule)) {
            throw new Error(`Invalid or potentially malicious top module name: ${topModule}`);
        }
        if (!/^[a-zA-Z0-9_]+$/.test(mode)) {
            throw new Error(`Invalid formal mode: ${mode}`);
        }
        if (!/^[a-zA-Z0-9_ -]+$/.test(engine)) {
            throw new Error(`Invalid formal engine: ${engine}`);
        }

        const safeBasenames = [];
        const safeFullPaths = [];

        for (const f of targetFiles) {
            if (/[\r\n;]/.test(f)) {
                throw new Error(`Potentially malicious characters detected in formal target filename: ${f}`);
            }
            const base = path.basename(f);
            if (/[\r\n; "]/.test(base)) {
                throw new Error(`Potentially malicious characters or spaces in Verilog basename: ${base}`);
            }
            safeBasenames.push(base);
            safeFullPaths.push(path.resolve(f).replace(/\\/g, '/'));
        }

        let readCmd = 'read -formal';
        if (targetFiles.some(f => f.toLowerCase().endsWith('.sv'))) {
            readCmd += ' -sv';
        }

        let config = `[options]\nmode ${mode}\ndepth ${depth}\n\n`;
        config += `[engines]\n${engine}\n\n`;
        config += `[script]\n${readCmd} ${safeBasenames.join(' ')}\nprep -top ${topModule}\n\n`;
        config += `[files]\n`;
        for (const f of safeFullPaths) {
            config += `${f}\n`;
        }
        return config;
    }

    /**
     * Executes formal verification and parses counterexample artifacts.
     */
    async run(params, legacyOutputDir, legacyOptions) {
        const startTime = Date.now();
        let files = [];
        let outputDir = legacyOutputDir;
        let timeout = 120000;
        let customSbyFile = null;
        let depth = 20;

        if (Array.isArray(params)) {
            files = params;
            outputDir = legacyOutputDir || path.resolve('hwsec-output');
        } else if (params && typeof params === 'object') {
            files = params.files || [];
            outputDir = params.outputDir || legacyOutputDir || path.resolve('hwsec-output');
            timeout = params.timeout || timeout;
            customSbyFile = params.sbyFile || null;
            depth = params.depth || depth;
        }

        const install = await this.checkInstalled();
        if (!install.installed) {
            return {
                status: "UNAVAILABLE",
                findings: [],
                reason: install.error,
                telemetry: { error: install.error }
            };
        }

        const verilogFiles = files.filter(f => {
            const ext = path.extname(f).toLowerCase();
            return ext === '.v' || ext === '.sv';
        });

        const sbyFiles = files.filter(f => path.extname(f).toLowerCase() === '.sby');
        if (customSbyFile && fs.existsSync(customSbyFile)) {
            sbyFiles.push(customSbyFile);
        }

        if (verilogFiles.length === 0 && sbyFiles.length === 0) {
            return {
                status: "SKIPPED",
                findings: [],
                reason: "No Verilog or .sby files provided for formal verification"
            };
        }

        const toolsDir = path.join(outputDir, 'tools', 'symbiyosys');
        if (!fs.existsSync(toolsDir)) {
            fs.mkdirSync(toolsDir, { recursive: true });
        }

        let effectiveSbyPath;
        let targetSbyDir;

        if (sbyFiles.length > 0) {
            effectiveSbyPath = path.resolve(sbyFiles[0]);
            const sbyBase = path.basename(effectiveSbyPath, '.sby');
            targetSbyDir = path.join(path.dirname(effectiveSbyPath), sbyBase);
        } else {
            const top = (params && typeof params === 'object' && params.topModule)
                ? params.topModule
                : this._detectTopModule(verilogFiles).top;
            effectiveSbyPath = path.join(toolsDir, `${top}_formal.sby`);
            targetSbyDir = path.join(toolsDir, `${top}_formal`);
            const sbyContent = this.generateSbyConfig({
                targetFiles: verilogFiles,
                topModule: top,
                mode: 'bmc',
                depth
            });
            fs.writeFileSync(effectiveSbyPath, sbyContent, 'utf-8');
        }

        try {
            const res = await runCommand(install.cmd, ['-f', effectiveSbyPath], {
                env: install.env,
                timeout
            });

            const combinedOutput = `${res.stdout}\n${res.stderr}`;
            const findings = [];
            const artifacts = [effectiveSbyPath];

            const isFail = combinedOutput.includes('Status: failed') ||
                           combinedOutput.includes('DONE (FAIL') ||
                           combinedOutput.includes('BMC failed!');

            const isPass = combinedOutput.includes('Status: passed') ||
                           combinedOutput.includes('DONE (PASS');

            if (isFail) {
                // Parse assertion failure details
                const assertMatch = combinedOutput.match(/Assert failed in ([a-zA-Z0-9_]+):\s*([^:\s]+):(\d+)(?:\.(\d+))?/);
                const modName = assertMatch ? assertMatch[1] : 'RTL';
                const sourceFile = assertMatch ? assertMatch[2] : (verilogFiles[0] || 'design.v');
                const line = assertMatch ? parseInt(assertMatch[3], 10) : 1;

                // Locate generated trace artifacts
                const vcdTrace = path.join(targetSbyDir, 'engine_0', 'trace.vcd');
                const tbTrace = path.join(targetSbyDir, 'engine_0', 'trace_tb.v');
                const smtcTrace = path.join(targetSbyDir, 'engine_0', 'trace.smtc');

                if (fs.existsSync(vcdTrace)) artifacts.push(vcdTrace);
                if (fs.existsSync(tbTrace)) artifacts.push(tbTrace);
                if (fs.existsSync(smtcTrace)) artifacts.push(smtcTrace);

                const chosenArtifact = fs.existsSync(vcdTrace) ? vcdTrace : effectiveSbyPath;
                const artifactHash = fs.existsSync(chosenArtifact)
                    ? crypto.createHash('sha256').update(fs.readFileSync(chosenArtifact)).digest('hex')
                    : null;

                const findingId = `SBY-${crypto.randomBytes(4).toString('hex')}`;
                const evidenceObj = createEvidence({
                    id: `EV-${crypto.randomBytes(4).toString('hex')}`,
                    finding_id: findingId,
                    tool_name: "symbiyosys",
                    evidence_type: "COUNTEREXAMPLE_TRACE",
                    description: `SymbiYosys Bounded Model Check disproved invariant. Counterexample trace generated at ${chosenArtifact}`,
                    artifact_path: chosenArtifact,
                    artifact_hash: artifactHash,
                    raw_evidence: {
                        engine: 'smtbmc',
                        module: modName,
                        failedAssertion: assertMatch ? assertMatch[0] : 'Formal assertion failure',
                        artifacts: artifacts
                    },
                    confidence: 0.99
                });

                const matchedSrc = verilogFiles.find(f => f.endsWith(sourceFile) || path.basename(f) === path.basename(sourceFile)) || sourceFile;

                findings.push(createFinding({
                    id: findingId,
                    title: `[CWE-1234] Formal Invariant Violation in ${modName} (BMC Step Failure)`,
                    description: `SymbiYosys formal model checking encountered an assertion failure:\n${assertMatch ? assertMatch[0] : 'Invariant violated'}.\nConcrete counterexample waveforms generated in VCD trace.`,
                    severity: Severity.CRITICAL,
                    confidence: 0.99,
                    source_tool: "symbiyosys",
                    source_locations: [createSourceLocation({
                        path: matchedSrc,
                        startLine: line,
                        endLine: line,
                        line
                    })],
                    evidence: [evidenceObj],
                    verification_state: VerificationState.PROPOSED,
                    cwe_id: "CWE-1234",
                    security_property: "FORMAL_BMC_INVARIANT"
                }));
            }

            return {
                status: isFail ? "SUCCESS" : (isPass ? "SUCCESS" : (res.exitCode === 0 ? "SUCCESS" : "ERROR")),
                formalResult: isFail ? "FAIL" : (isPass ? "PASS" : "UNKNOWN"),
                findings,
                artifacts,
                telemetry: {
                    formalResult: isFail ? "FAIL" : (isPass ? "PASS" : "UNKNOWN"),
                    durationMs: Date.now() - startTime,
                    artifactsProduced: artifacts.length,
                    rawExitCode: res.exitCode
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
