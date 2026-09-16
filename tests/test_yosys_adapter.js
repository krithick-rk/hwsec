import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { YosysTool } from '../src/domains/hardware/tools/yosys.js';
import { loadConfig } from '../src/core/config.js';

console.log("=== Running Yosys Real Adapter Integration Tests ===");

const config = loadConfig('config.json');
const yosys = new YosysTool(config);

// 1. Test checkInstalled with config
console.log("[Test 1] Testing Yosys checkInstalled()...");
const install = await yosys.checkInstalled();
console.log(`  -> Installed: ${install.installed}, Version: ${install.version}`);
if (!install.installed) {
    console.log("  [*] Yosys binary not present on host environment. Skipping live execution tests.");
    console.log("\n[PASS] Yosys adapter detection test completed (binary optional).\n");
    process.exit(0);
}
assert.strictEqual(install.installed, true, "Yosys should be detected on this system");

// 2. Test checkInstalled without config (fallback discovery)
console.log("[Test 2] Testing Yosys fallback discovery without config...");
const bareYosys = new YosysTool();
const bareInstall = await bareYosys.checkInstalled();
assert.strictEqual(bareInstall.installed, true, "Yosys fallback discovery should detect binary");
console.log(`  -> Bare Installed: ${bareInstall.installed}, Path: ${bareInstall.cmd}`);

// 3. Test Yosys script generation (.v and .sv support, plus injection defense)
console.log("[Test 3] Testing .ys script generator (Verilog + SystemVerilog)...");
const script = yosys._generateScript(['module_a.v', 'module_b.sv']);
assert.ok(script.includes('read_verilog "module_a.v"'), "Script must contain read_verilog for .v");
assert.ok(script.includes('read_verilog -sv "module_b.sv"'), "Script must contain read_verilog -sv for .sv");
assert.ok(script.includes('hierarchy -check'), "Script must check hierarchy");
assert.ok(script.includes('prep'), "Script must include prep command");

// Verify injection defense
assert.throws(() => {
    yosys._generateScript(['malicious;calc.exe.v']);
}, /Potentially malicious characters/, "Must throw on semicolon in filename");

assert.throws(() => {
    yosys._generateScript(['malicious\nrm -rf /.v']);
}, /Potentially malicious characters/, "Must throw on newline in filename");
console.log("  -> Generated .ys script and input sanitization verified.");

// 4. Test real Yosys run on counter.v
console.log("[Test 4] Testing real Yosys execution on counter.v...");
const fixturePath = path.resolve('tests/fixtures/multilang_project/counter.v');
assert.ok(fs.existsSync(fixturePath), "counter.v fixture must exist");

const outDir = path.resolve('hwsec-output/test-yosys');
if (fs.existsSync(outDir)) {
    fs.rmSync(outDir, { recursive: true, force: true });
}

const result = await yosys.run({
    files: [fixturePath],
    outputDir: outDir
});

console.log(`  -> Status: ${result.status}`);
console.log(`  -> Findings count: ${result.findings.length}`);
console.log(`  -> Telemetry exitCode: ${result.telemetry.exitCode}`);

assert.strictEqual(result.status, "SUCCESS", "Yosys execution on counter.v should succeed");
assert.strictEqual(result.telemetry.exitCode, 0, "Yosys should exit with code 0");

const scriptOnDisk = path.join(outDir, 'yosys_check.ys');
assert.ok(fs.existsSync(scriptOnDisk), "yosys_check.ys must exist on disk");

const telemetryOnDisk = path.join(outDir, 'yosys_telemetry.json');
assert.ok(fs.existsSync(telemetryOnDisk), "yosys_telemetry.json must exist on disk");

// 5. Test clean SKIP on non-Verilog files
console.log("[Test 5] Testing Yosys clean SKIP on non-Verilog files...");
const skipRes = await yosys.run({
    files: ['main.py', 'test.c'],
    outputDir: outDir
});
assert.strictEqual(skipRes.status, "SKIPPED", "Non-Verilog files should produce SKIPPED");
console.log("  -> Non-Verilog files cleanly SKIPPED.");

console.log("\n[PASS] All Yosys Adapter tests passed successfully!\n");
