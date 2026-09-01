import path from 'path';
import { ToolAdapter } from './base.js';
import { runCommand } from '../core/execUtils.js';
import { createFinding, Severity } from '../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class YosysTool extends ToolAdapter {
    get name() {
        return "yosys";
    }

    _buildCommand(baseArgs) {
        let command = this.config.tool_paths?.yosys || "yosys";
        let args = [...baseArgs];

        if (process.platform === 'win32' && command.includes('oss-cad-suite')) {
            const rootDir = path.dirname(path.dirname(command));
            const envBat = path.join(rootDir, 'environment.bat');
            args = ['/c', `${envBat} & yosys.exe ${baseArgs.join(' ')}`];
            command = 'cmd.exe';
        }
        return { command, args };
    }

    async checkInstalled() {
        const { command, args } = this._buildCommand(["-V"]);
        const result = await runCommand(command, args, { timeout: 10000 });
        if (result.exitCode === 0) {
            return { installed: true, version: result.stdout.trim() || result.stderr.trim() };
        }
        return { installed: false, error: result.stderr };
    }

    async run(rtlFiles, outputDir) {
        // Build a yosys script to read verilog and check syntax
        const scriptPath = path.join(outputDir, 'yosys_check.ys');
        const scriptContent = rtlFiles.map(f => `read_verilog ${f}`).join('\n') + '\nhierarchy -check\nprep\n';
        fs.writeFileSync(scriptPath, scriptContent, 'utf-8');

        const { command, args } = this._buildCommand(["-s", scriptPath]);
        
        const telemetry = await runCommand(command, args, { timeout: 300000 }); // 5 min max
        
        const telemetryPath = path.join(outputDir, 'yosys_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');
        
        const { findings, toolErrors } = this._parseOutput(telemetry.stdout + "\n" + telemetry.stderr, telemetryPath);
        
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

    _parseOutput(output, telemetryPath) {
        const findings = [];
        const toolErrors = [];
        const lines = output.split('\n');
        
        const errorRegex = /ERROR:\s+(.*)/;
        const warningRegex = /Warning:\s+(.*)/;

        for (const line of lines) {
            let match = line.match(warningRegex);
            if (match) {
                const [, msg] = match;
                findings.push(createFinding({
                    id: `YOSYS-${crypto.randomBytes(4).toString('hex')}`,
                    title: `Yosys Lint Warning`,
                    description: msg.trim(),
                    severity: Severity.LOW,
                    source_tool: this.name,
                    evidence: [{
                        id: crypto.randomBytes(4).toString('hex'),
                        tool_name: this.name,
                        artifact_path: telemetryPath,
                        description: `Yosys emitted warning`,
                        metadata: { raw_line: line }
                    }],
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
