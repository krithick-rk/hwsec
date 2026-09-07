import path from 'path';
import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand } from '../../../core/execUtils.js';
import { createFinding, Severity } from '../../../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';

export class AflTool extends ToolAdapter {
    get name() {
        return "afl++";
    }

    get id() {
        return "afl++";
    }

    get capabilities() {
        return ["rtl_fuzz"];
    }

    get supportedLanguages() {
        return ["verilog"];
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

    async run(params, legacyOutputDir, legacyOptions = {}) {
        let rtlFiles = [];
        let outputDir = '';
        let aflOptions = {};

        if (Array.isArray(params)) {
            rtlFiles = params;
            outputDir = legacyOutputDir;
            aflOptions = legacyOptions || {};
        } else if (params && typeof params === 'object') {
            rtlFiles = params.files || [];
            outputDir = params.outputDir || 'hwsec-output/tools';
            aflOptions = params.config || params;
        }

        const findings = [];
        if (!rtlFiles || rtlFiles.length === 0) {
            return { status: "SKIPPED", findings, telemetry: { reason: "No RTL files provided" } };
        }

        const topModuleFile = path.resolve(rtlFiles[0]);
        const absOutputDir = path.resolve(outputDir);
        const objDir = path.join(absOutputDir, 'obj_dir');
        
        if (fs.existsSync(objDir)) fs.rmSync(objDir, { recursive: true, force: true });

        let command = this.config.tool_paths?.verilator || "verilator";
        let baseArgs = ["--cc", "-Wno-fatal", "--Mdir", objDir, topModuleFile];
        for (let i = 1; i < rtlFiles.length; i++) {
            baseArgs.push(path.resolve(rtlFiles[i]));
        }
        
        let args = [...baseArgs];
        const env = { ...process.env };
        let rootDir = "";
        if (process.platform === 'win32') {
            const binDir = path.dirname(command);
            rootDir = path.dirname(binDir);
            const verilatorBin = path.join(binDir, 'verilator_bin.exe');
            if (fs.existsSync(verilatorBin)) {
                command = verilatorBin;
                env.VERILATOR_ROOT = path.join(rootDir, 'share', 'verilator');
                env.PATH = `${binDir};${path.join(rootDir, 'lib')};${env.PATH || ''}`;
            }
        }
        
        console.log(`[AFL++] Generating C++ model via Verilator...`);
        let res = await runCommand(command, args, { timeout: 30000, env, shell: false });
        if (res.exitCode !== 0) {
            return { status: "COMPLETED_WITH_FAILURES", findings, telemetry: res };
        }

        console.log(`[AFL++] Generating fuzz.cpp harness...`);
        const headerFile = path.join(objDir, `Vtop.h`);
        const harnessPath = path.join(absOutputDir, 'fuzz.cpp');
        
        let harnessContent = "";
        try {
            const { generateHarness } = await import('../../../tools/harnessGen.js');
            harnessContent = generateHarness(headerFile);
        } catch (e) {
            console.error(`[-] Harness generation failed: ${e.message}`);
        }
        
        if (!harnessContent) {
            harnessContent = `#include "Vtop.h"\n#include "verilated.h"\n#include <stdint.h>\n#include <stddef.h>\nextern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n    if (size < 1) return 0;\n    Verilated::commandArgs(0, (const char**)nullptr);\n    Vtop* top = new Vtop;\n    top->eval();\n    delete top;\n    return 0;\n}`;
        }
        fs.writeFileSync(harnessPath, harnessContent, 'utf-8');

        console.log(`[AFL++] Compiling harness with afl-c++...`);
        const wslObjDir = this._translatePath(objDir);
        const wslHarness = this._translatePath(harnessPath);
        const wslVerilatorInc = this._translatePath(path.join(rootDir, 'share', 'verilator', 'include'));
        const wslOutExe = this._translatePath(path.join(absOutputDir, 'fuzz_exe'));

        // Write safe compilation script with properly escaped arguments
        const escapeBash = (str) => `'${String(str).replace(/'/g, "'\\''")}'`;
        const compileSh = path.join(absOutputDir, 'compile_afl.sh');
        const compileShContent = `#!/usr/bin/env bash\nset -euo pipefail\ncd ${escapeBash(wslObjDir)}\nafl-c++ -fsanitize=fuzzer -DVL_USER_FATAL ${escapeBash(wslHarness)} *.cpp "${wslVerilatorInc}/verilated.cpp" "${wslVerilatorInc}/verilated_threads.cpp" -I${escapeBash(wslVerilatorInc)} -I${escapeBash(wslVerilatorInc + '/vltstd')} -I. -o ${escapeBash(wslOutExe)}\n`;
        fs.writeFileSync(compileSh, compileShContent.replace(/\r\n/g, '\n'), 'utf-8');
        const wslCompileSh = this._translatePath(compileSh);

        res = process.platform === 'win32'
            ? await runWslCommand('bash', [wslCompileSh], { timeout: 60000 })
            : await runCommand('bash', [compileSh], { timeout: 60000, shell: false });

        if (res.exitCode !== 0) {
            findings.push(createFinding({
                id: `AFL-${crypto.randomBytes(4).toString('hex')}`,
                title: `AFL Compilation Failed`,
                description: res.stderr,
                severity: Severity.HIGH,
                source_tool: this.name,
                source_locations: [],
                evidence: [],
                verification_state: "PROPOSED"
            }));
            return { status: "COMPLETED_WITH_FAILURES", findings, telemetry: res };
        }

        const fuzzerTimeout = aflOptions.timeout || 5;
        console.log(`[AFL++] Running afl-fuzz for ${fuzzerTimeout} seconds...`);
        const inDir = path.join(absOutputDir, 'inputs');
        const outDir = path.join(absOutputDir, 'fuzz_out');
        fs.mkdirSync(inDir, { recursive: true });
        fs.writeFileSync(path.join(inDir, 'seed.bin'), '\x00\x00\x00', 'binary');

        const wslInDir = this._translatePath(inDir);
        const wslOutDir = this._translatePath(outDir);

        const fuzzArgs = ['-i', wslInDir, '-o', wslOutDir];
        if (aflOptions.dict_path && fs.existsSync(aflOptions.dict_path)) {
            fuzzArgs.push('-x', this._translatePath(aflOptions.dict_path));
        }
        fuzzArgs.push('-V', String(fuzzerTimeout), '--', wslOutExe);

        const telemetry = process.platform === 'win32'
            ? await runWslCommand('afl-fuzz', fuzzArgs, { timeout: (fuzzerTimeout + 15) * 1000 })
            : await runCommand('afl-fuzz', fuzzArgs, { timeout: (fuzzerTimeout + 15) * 1000, shell: false });
        
        const telemetryPath = path.join(absOutputDir, 'afl_telemetry.json');
        fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');

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
                source_locations: [],
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
