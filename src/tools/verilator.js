import path from 'path';
import { ToolAdapter } from './base.js';
import { runCommand } from '../core/execUtils.js';
import { createFinding, Severity } from '../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class VerilatorTool extends ToolAdapter {
    get name() {
        return "verilator";
    }

    _buildCommand(baseArgs) {
        let command = this.config.tool_paths?.verilator || "verilator";
        let args = [...baseArgs];

        if (process.platform === 'win32' && command.includes('oss-cad-suite')) {
            const rootDir = path.dirname(path.dirname(command));
            const envBat = path.join(rootDir, 'environment.bat');
            const verilatorRoot = path.join(rootDir, 'share', 'verilator');
            args = ['/c', `set VERILATOR_ROOT=${verilatorRoot}& ${envBat} & verilator_bin.exe ${baseArgs.join(' ')}`];
            command = 'cmd.exe';
        }
        return { command, args };
    }

    async checkInstalled() {
        const { command, args } = this._buildCommand(["--version"]);
        const result = await runCommand(command, args, { timeout: 10000 });
        if (result.exitCode === 0) {
            return { installed: true, version: result.stdout.trim() || result.stderr.trim() };
        }
        return { installed: false, error: result.stderr };
    }

    async run(rtlFiles, outputDir) {
        const { command, args } = this._buildCommand(["--lint-only", "-Wall", ...rtlFiles]);
        
        const telemetry = await runCommand(command, args, { timeout: 300000 }); // 5 min max
        
        // Save raw telemetry as evidence
        const telemetryPath = path.join(outputDir, 'verilator_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');
        
        const { findings, toolErrors } = this._parseOutput(telemetry.stderr, telemetryPath);
        
        // Enrich telemetry with parsed tool errors if any
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
        const lines = stderr.split('\n');
        
        // Verilator warnings look like:
        // %Warning-WIDTH: file.v:10:15: Operator ASSIGN expects 8 bits on the Assign RHS, but Assign RHS's CONST '1'h1' generates 1 bits.
        // Or on Windows: %Warning-WIDTHTRUNC: E:\path\to\file.v:6:14: ...
        const warningRegex = /%Warning-([A-Z0-9_]+):\s+((?:[a-zA-Z]:)?[^:\r\n]+):(\d+):(?:\d+:)?\s+([^\r\n]*)/;
        const errorRegex = /%Error:\s+((?:[a-zA-Z]:)?[^:\r\n]+):(\d+):(?:\d+:)?\s+([^\r\n]*)/;
        const genericErrorRegex = /%Error:\s+([^\r\n]*)/;

        for (const line of lines) {
            let match = line.match(warningRegex);
            if (match) {
                const [, type, file, lineNum, msg] = match;
                findings.push(createFinding({
                    id: `VERI-${crypto.randomBytes(4).toString('hex')}`,
                    title: `Verilator Lint Warning: ${type}`,
                    description: msg,
                    severity: Severity.LOW,
                    source_tool: this.name,
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
            
            // Compiler/Syntax errors must be recorded as tool errors, NOT security findings
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
