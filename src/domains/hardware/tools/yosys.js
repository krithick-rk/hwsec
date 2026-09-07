import path from 'path';
import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand } from '../../../core/execUtils.js';
import { createFinding, Severity, createEvidence, createSourceLocation } from '../../../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class YosysTool extends ToolAdapter {
    get name() {
        return "yosys";
    }

    get id() {
        return "yosys";
    }

    get capabilities() {
        return ["rtl_formal"];
    }

    get supportedLanguages() {
        return ["verilog", "systemverilog"];
    }

    _resolveEnvironment() {
        let command = this.config?.tool_paths?.yosys;
        let binDir = null;
        let libDir = null;
        let suiteRoot = null;

        if (command && fs.existsSync(command)) {
            binDir = path.dirname(command);
            suiteRoot = path.dirname(binDir);
            const possibleLib = path.join(suiteRoot, 'lib');
            if (fs.existsSync(possibleLib)) {
                libDir = possibleLib;
            }
        } else {
            const defaultSuite = process.env.OSS_CAD_SUITE || process.env.YOSYSHQ_ROOT || 'E:/Intern/krithick/Downloads/oss-cad-suite';
            if (fs.existsSync(defaultSuite)) {
                suiteRoot = defaultSuite;
                binDir = path.join(suiteRoot, 'bin');
                libDir = path.join(suiteRoot, 'lib');
                const candidateBin = path.join(binDir, 'yosys.exe');
                if (fs.existsSync(candidateBin)) {
                    command = candidateBin;
                }
            }
        }

        if (!command) {
            command = 'yosys';
        }

        const env = { ...process.env };
        if (process.platform === 'win32' && suiteRoot && binDir) {
            env.YOSYSHQ_ROOT = suiteRoot + (suiteRoot.endsWith('\\') || suiteRoot.endsWith('/') ? '' : path.sep);
            env.PATH = libDir ? `${binDir};${libDir};${env.PATH || ''}` : `${binDir};${env.PATH || ''}`;
        }
        return { command, binDir, libDir, env };
    }

    _buildCommand(baseArgs) {
        const { command, env } = this._resolveEnvironment();
        return { command, args: [...baseArgs], env };
    }

    async checkInstalled() {
        const { command, env } = this._resolveEnvironment();
        try {
            const result = await runCommand(command, ["-V"], { timeout: 10000, env, shell: false });
            if (result.exitCode === 0) {
                return { installed: true, version: result.stdout.trim() || result.stderr.trim(), cmd: command, env };
            }
        } catch {}

        if (process.platform === 'win32') {
            try {
                const wslRes = await runWslCommand('yosys', ['-V'], { timeout: 8000 });
                if (wslRes.exitCode === 0) {
                    return { installed: true, version: wslRes.stdout.trim(), isWsl: true, cmd: 'yosys', env: process.env };
                }
            } catch {}
        }

        return { installed: false, error: 'Yosys not found in configured paths or system PATH' };
    }

    _generateScript(rtlFiles) {
        const safeLines = [];
        for (const f of rtlFiles) {
            if (/[\r\n;]/.test(f)) {
                throw new Error(`Potentially malicious characters detected in RTL filename: ${f}`);
            }
            const sanitized = f.replace(/\\/g, '/').replace(/"/g, '\\"');
            const isSv = f.toLowerCase().endsWith('.sv');
            safeLines.push(isSv ? `read_verilog -sv "${sanitized}"` : `read_verilog "${sanitized}"`);
        }
        return safeLines.join('\n') + '\nhierarchy -check\nprep\n';
    }

    async run(params, legacyOutputDir, legacyOptions) {
        let files = [];
        let outputDir = '';
        if (Array.isArray(params)) {
            files = params;
            outputDir = legacyOutputDir || 'hwsec-output/tools';
        } else if (params && typeof params === 'object') {
            files = params.files || [];
            outputDir = params.outputDir || 'hwsec-output/tools';
        }

        const install = await this.checkInstalled();
        if (!install.installed) {
            return {
                status: "UNAVAILABLE",
                findings: [],
                toolErrors: [{ type: "TOOL_UNAVAILABLE", message: install.error }],
                telemetry: { error: install.error }
            };
        }

        const rtlFiles = files.filter(f => {
            const ext = path.extname(f).toLowerCase();
            return ext === '.v' || ext === '.sv';
        });

        if (rtlFiles.length === 0) {
            return {
                status: "SKIPPED",
                findings: [],
                toolErrors: [],
                telemetry: { reason: "No Verilog or SystemVerilog files provided" }
            };
        }

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const scriptPath = path.join(outputDir, 'yosys_check.ys');
        const scriptContent = this._generateScript(rtlFiles);
        fs.writeFileSync(scriptPath, scriptContent, 'utf-8');

        const { command, args, env } = this._buildCommand(["-s", scriptPath]);
        
        const telemetry = await runCommand(command, args, { timeout: 300000, env, shell: false });
        
        const telemetryPath = path.join(outputDir, 'yosys_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');
        
        const { findings, toolErrors } = this._parseOutput(telemetry.stdout + "\n" + telemetry.stderr, telemetryPath, rtlFiles);
        
        if (toolErrors.length > 0) {
            telemetry.parsed_tool_errors = toolErrors;
            fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');
        }

        return {
            status: telemetry.exitCode === 0 ? "SUCCESS" : "COMPLETED_WITH_FAILURES",
            findings,
            toolErrors,
            telemetry
        };
    }

    _parseOutput(output, telemetryPath, rtlFiles = []) {
        const findings = [];
        const toolErrors = [];
        const lines = output ? output.split('\n') : [];
        
        const errorRegex = /ERROR:\s+(.*)/;
        const warningRegex = /Warning:\s+(.*)/;
        const locationRegex = /(?:(?:[a-zA-Z]:)?[^:\r\n]+):(\d+):/;

        const telemetryHash = fs.existsSync(telemetryPath)
            ? crypto.createHash('sha256').update(fs.readFileSync(telemetryPath)).digest('hex')
            : null;

        for (const line of lines) {
            let match = line.match(warningRegex);
            if (match) {
                const [, msg] = match;
                const locMatch = line.match(locationRegex);
                const lineNum = locMatch ? parseInt(locMatch[1], 10) : 1;
                const srcPath = rtlFiles[0] || 'design.v';

                findings.push(createFinding({
                    id: `YOSYS-${crypto.randomBytes(4).toString('hex')}`,
                    title: `Yosys Lint Warning`,
                    description: msg.trim(),
                    severity: Severity.LOW,
                    source_tool: this.name,
                    source_locations: [createSourceLocation({
                        path: srcPath,
                        startLine: lineNum,
                        endLine: lineNum,
                        line: lineNum
                    })],
                    evidence: [createEvidence({
                        id: `EV-${crypto.randomBytes(4).toString('hex')}`,
                        tool_name: this.name,
                        artifact_path: telemetryPath,
                        artifact_hash: telemetryHash,
                        description: `Yosys emitted warning`,
                        metadata: { raw_line: line }
                    })],
                    verification_state: "PROPOSED"
                }));
                continue;
            }

            match = line.match(errorRegex);
            if (match) {
                const [, msg] = match;
                toolErrors.push({
                    type: "SYNTHESIS_ERROR",
                    message: msg.trim(),
                    raw: line
                });
            }
        }
        
        return { findings, toolErrors };
    }
}
