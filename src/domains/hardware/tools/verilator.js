import path from 'path';
import { ToolAdapter } from '../../../tools/base.js';
import { runCommand } from '../../../core/execUtils.js';
import { createFinding, Severity } from '../../../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class VerilatorTool extends ToolAdapter {
    get name() {
        return "verilator";
    }

    get id() {
        return "verilator";
    }

    get capabilities() {
        return ["rtl_lint"];
    }

    get supportedLanguages() {
        return ["verilog"];
    }

    _buildCommand(baseArgs) {
        let command = this.config.tool_paths?.verilator;
        if (!command || (!fs.existsSync(command) && !fs.existsSync(command + '_bin.exe'))) {
            const defaultSuite = 'E:/Intern/krithick/Downloads/oss-cad-suite/bin/verilator';
            if (fs.existsSync(defaultSuite) || fs.existsSync(defaultSuite + '_bin.exe')) {
                command = defaultSuite;
            } else {
                command = "verilator";
            }
        }
        let args = [...baseArgs];
        const env = { ...process.env };

        if (process.platform === 'win32') {
            const binDir = path.dirname(command);
            const rootDir = path.dirname(binDir);
            const verilatorBin = path.join(binDir, 'verilator_bin.exe');
            const verilatorRoot = path.join(rootDir, 'share', 'verilator');

            if (fs.existsSync(verilatorBin)) {
                command = verilatorBin;
                env.VERILATOR_ROOT = verilatorRoot;
                env.PATH = `${binDir};${path.join(rootDir, 'lib')};${env.PATH || ''}`;
            }
        }
        return { command, args, env };
    }

    async checkInstalled() {
        const { command, args, env } = this._buildCommand(["--version"]);
        const result = await runCommand(command, args, { timeout: 10000, env, shell: false });
        if (result.exitCode === 0) {
            return { installed: true, version: result.stdout.trim() || result.stderr.trim() };
        }
        return { installed: false, error: result.stderr || result.executionError };
    }

    async run(params, legacyOutputDir, legacyOptions) {
        let rtlFiles = [];
        let outputDir = '';
        if (Array.isArray(params)) {
            rtlFiles = params;
            outputDir = legacyOutputDir;
        } else if (params && typeof params === 'object') {
            rtlFiles = params.files || [];
            outputDir = params.outputDir || 'hwsec-output/tools';
        }

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const { command, args, env } = this._buildCommand(["--lint-only", "-Wall", ...rtlFiles]);
        
        const telemetry = await runCommand(command, args, { timeout: 300000, env, shell: false });
        
        const telemetryPath = path.join(outputDir, 'verilator_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');
        
        const { findings, toolErrors } = this._parseOutput(telemetry.stderr, telemetryPath);
        
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

    _parseOutput(stderr, telemetryPath) {
        const findings = [];
        const toolErrors = [];
        const lines = stderr ? stderr.split('\n') : [];
        
        const warningRegex = /%Warning-([A-Z0-9_]+):\s+((?:[a-zA-Z]:)?[^:\r\n]+):(\d+):(?:\d+:)?\s+([^\r\n]*)/;
        const errorRegex = /%Error:\s+((?:[a-zA-Z]:)?[^:\r\n]+):(\d+):(?:\d+:)?\s+([^\r\n]*)/;
        const genericErrorRegex = /%Error:\s+([^\r\n]*)/;

        for (const line of lines) {
            let match = line.match(warningRegex);
            if (match) {
                const [, type, file, lineNum, msg] = match;
                const lineNumInt = parseInt(lineNum, 10) || 1;
                findings.push(createFinding({
                    id: `VERI-${crypto.randomBytes(4).toString('hex')}`,
                    title: `Verilator Lint Warning: ${type}`,
                    description: msg,
                    severity: Severity.LOW,
                    source_tool: this.name,
                    source_locations: [{
                        path: file,
                        startLine: lineNumInt,
                        endLine: lineNumInt,
                        startColumn: 1,
                        endColumn: 1,
                        symbol: null
                    }],
                    rtl_location: `${file}:${lineNum}`,
                    evidence: [{
                        id: crypto.randomBytes(4).toString('hex'),
                        tool_name: this.name,
                        artifact_path: telemetryPath,
                        description: `Verilator emitted lint warning ${type}`,
                        metadata: { raw_line: line }
                    }],
                    verification_state: "PROPOSED"
                }));
                continue;
            }
            
            match = line.match(errorRegex);
            if (match) {
                const [, file, lineNum, msg] = match;
                toolErrors.push({
                    type: "COMPILATION_ERROR",
                    location: `${file}:${lineNum}`,
                    message: msg,
                    raw: line
                });
                continue;
            }

            match = line.match(genericErrorRegex);
            if (match && !line.includes('Exiting due to')) {
                const [, msg] = match;
                toolErrors.push({
                    type: "GENERIC_ERROR",
                    message: msg,
                    raw: line
                });
            }
        }
        
        return { findings, toolErrors };
    }
}
