import path from 'path';
import { ToolAdapter } from './base.js';
import { runCommand } from '../core/execUtils.js';
import { createFinding, Severity } from '../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class AflTool extends ToolAdapter {
    get name() {
        return "afl++";
    }

    _translatePath(winPath) {
        if (process.platform !== 'win32') return winPath;
        let p = winPath.replace(/\\/g, '/');
        p = p.replace(/^([A-Za-z]):/, (match, drive) => `/mnt/${drive.toLowerCase()}`);
        return p;
    }

    async checkInstalled() {
        const command = process.platform === 'win32' ? 'wsl' : 'afl-cc';
        const args = process.platform === 'win32' ? ['afl-cc', '--version'] : ['--version'];
        
        const result = await runCommand(command, args, { timeout: 10000 });
        if (result.exitCode === 0) {
            return { installed: true, version: result.stdout.trim() || result.stderr.trim() };
        }
        return { installed: false, error: result.stderr || result.executionError };
    }

    async run(rtlFiles, outputDir, aflOptions = {}) {
        const findings = [];
        const topModuleFile = path.resolve(rtlFiles[0]);
        const absOutputDir = path.resolve(outputDir);
        const objDir = path.join(absOutputDir, 'obj_dir');
        
        if (fs.existsSync(objDir)) fs.rmSync(objDir, { recursive: true, force: true });

        // 1. Generate C++ model using Verilator
        let command = this.config.tool_paths?.verilator || "verilator";
        let baseArgs = ["--cc", "-Wno-fatal", "--Mdir", objDir, topModuleFile];
        // If there are other RTL files (like spec_monitor.sv), include them
        for (let i = 1; i < rtlFiles.length; i++) {
            baseArgs.push(path.resolve(rtlFiles[i]));
        }
        
        let args = [...baseArgs];

        let rootDir = "";
        if (process.platform === 'win32' && command.includes('oss-cad-suite')) {
            rootDir = path.dirname(path.dirname(command));
            const envBat = path.join(rootDir, 'environment.bat');
            const verilatorRoot = path.join(rootDir, 'share', 'verilator');
            args = ['/c', `set VERILATOR_ROOT=${verilatorRoot}& ${envBat} & verilator_bin.exe ${baseArgs.join(' ')}`];
            command = 'cmd.exe';
        }
        console.log(`[AFL++] Generating C++ model via Verilator...`);
        let res = await runCommand(command, args, { timeout: 30000 });
        if (res.exitCode !== 0) {
            return { status: "COMPLETED_WITH_FAILURES", findings, telemetry: res };
        }

        // 2. Generate Harness
        console.log(`[AFL++] Generating fuzz.cpp harness...`);
        const headerFile = path.join(objDir, `Vtop.h`); // Assuming top module is named top
        const harnessPath = path.join(absOutputDir, 'fuzz.cpp');
        
        let harnessContent = "";
        try {
            // Use advanced harness generator that handles clocks, resets, wide inputs, and assertions
            const { generateHarness } = await import('./harnessGen.js');
            harnessContent = generateHarness(headerFile);
        } catch (e) {
            console.error(`[-] Harness generation failed: ${e.message}`);
        }
        
        if (!harnessContent) {
            // Fallback to basic if something goes wrong
            harnessContent = `#include "Vtop.h"\n#include "verilated.h"\n#include <stdint.h>\n#include <stddef.h>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    if (size < 1) return 0;\n    Verilated::commandArgs(0, (const char**)nullptr);\n    Vtop* top = new Vtop;\n    top->eval();\n    delete top;\n    return 0;\n}`;
        }
        fs.writeFileSync(harnessPath, harnessContent, 'utf-8');

        // 3. Compile Harness in WSL
        console.log(`[AFL++] Compiling harness with afl-c++...`);
        const wslObjDir = this._translatePath(objDir);
        const wslHarness = this._translatePath(harnessPath);
        const wslVerilatorInc = this._translatePath(path.join(rootDir, 'share', 'verilator', 'include'));
        const wslOutExe = this._translatePath(path.join(absOutputDir, 'fuzz_exe'));

        // Delete .d files as they contain Windows paths that break make
        const compileCmd = `cd ${wslObjDir} && afl-c++ -fsanitize=fuzzer -DVL_USER_FATAL ${wslHarness} *.cpp ${wslVerilatorInc}/verilated.cpp ${wslVerilatorInc}/verilated_threads.cpp -I${wslVerilatorInc} -I${wslVerilatorInc}/vltstd -I. -o ${wslOutExe}`;
        
        const ccCommand = process.platform === 'win32' ? 'wsl' : 'bash';
        const ccArgs = process.platform === 'win32' ? ['bash', '-c', compileCmd] : ['-c', compileCmd];
        
        res = await runCommand(ccCommand, ccArgs, { timeout: 60000 });
        if (res.exitCode !== 0) {
            findings.push(createFinding({
                id: `AFL-${crypto.randomBytes(4).toString('hex')}`,
                title: `AFL Compilation Failed`,
                description: res.stderr,
                severity: Severity.HIGH,
                source_tool: this.name,
                evidence: [],
                verification_state: "PROPOSED"
            }));
            return { status: "COMPLETED_WITH_FAILURES", findings, telemetry: res };
        }

        // 4. Run Fuzzer
        const fuzzerTimeout = aflOptions.timeout || 5;
        console.log(`[AFL++] Running afl-fuzz for ${fuzzerTimeout} seconds...`);
        const inDir = path.join(absOutputDir, 'inputs');
        const outDir = path.join(absOutputDir, 'fuzz_out');
        fs.mkdirSync(inDir, { recursive: true });
        fs.writeFileSync(path.join(inDir, 'seed.bin'), '\x00\x00\x00', 'binary');

        const wslInDir = this._translatePath(inDir);
        const wslOutDir = this._translatePath(outDir);
        let dictArg = "";
        if (aflOptions.dict_path && fs.existsSync(aflOptions.dict_path)) {
            dictArg = `-x ${this._translatePath(aflOptions.dict_path)} `;
        }

        const fuzzCmd = `afl-fuzz -i ${wslInDir} -o ${wslOutDir} ${dictArg}-V ${fuzzerTimeout} -- ${wslOutExe}`;
        const fCommand = process.platform === 'win32' ? 'wsl' : 'bash';
        const fArgs = process.platform === 'win32' ? ['bash', '-c', fuzzCmd] : ['-c', fuzzCmd];
        
        const telemetry = await runCommand(fCommand, fArgs, { timeout: (fuzzerTimeout + 15) * 1000 }); 
        
        const telemetryPath = path.join(absOutputDir, 'afl_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');

        // Check if crashes were found
        const crashesDir = path.join(outDir, 'default', 'crashes');
        let crashesFound = 0;
        if (fs.existsSync(crashesDir)) {
            const files = fs.readdirSync(crashesDir);
            crashesFound = files.filter(f => !f.startsWith('README')).length;
        }

        if (crashesFound > 0) {
            findings.push(createFinding({
                id: `AFL-${crypto.randomBytes(4).toString('hex')}`,
                title: `AFL++ Discovered ${crashesFound} Crashes`,
                description: `Fuzzer discovered crashing inputs in the RTL simulation.`,
                severity: Severity.CRITICAL,
                source_tool: this.name,
                evidence: [{
                    id: crypto.randomBytes(4).toString('hex'),
                    tool_name: this.name,
                    artifact_path: telemetryPath,
                    description: `Crash count: ${crashesFound}`
                }],
                verification_state: "PROPOSED"
            }));
        }

        return {
            status: telemetry.exitCode === 0 || telemetry.exitCode === 2 ? "SUCCESS" : "COMPLETED_WITH_FAILURES",
            findings,
            telemetry
        };
    }
}
