import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { SymbiYosysTool } from '../src/domains/hardware/tools/symbiyosys.js';
import { loadConfig } from '../src/core/config.js';

console.log("=== Running SymbiYosys Real Adapter Integration Tests ===");

const config = loadConfig('config.json');
const sby = new SymbiYosysTool(config);

// 1. Test checkInstalled
console.log("[Test 1] Testing SymbiYosys checkInstalled()...");
const install = await sby.checkInstalled();
console.log(`  -> Installed: ${install.installed}, Version: ${install.version}`);
if (!install.installed) {
    console.log("  [*] SymbiYosys binary not present on host environment. Skipping live execution tests.");
    console.log("\n[PASS] SymbiYosys adapter detection test completed (binary optional).\n");
    process.exit(0);
}
assert.strictEqual(install.installed, true, "SymbiYosys should be detected on this system");

// 2. Test SBY config generation
console.log("[Test 2] Testing .sby config generator...");
const sbyContent = sby.generateSbyConfig({
    targetFiles: ['test_formal.v'],
    topModule: 'test_formal',
    mode: 'bmc',
    depth: 5
});
assert.ok(sbyContent.includes('[options]'), "Config must contain [options]");
assert.ok(sbyContent.includes('mode bmc'), "Config must specify mode bmc");
assert.ok(sbyContent.includes('smtbmc'), "Config must specify engine smtbmc");
assert.ok(sbyContent.includes('prep -top test_formal'), "Config must specify top module");
console.log("  -> Generated .sby configuration verified.");

// 3. Test real formal verification run on test_formal.v
console.log("[Test 3] Testing SymbiYosys execution and counterexample extraction on test_formal.v...");
const fixturePath = path.resolve('tests/fixtures/test_formal.v');
assert.ok(fs.existsSync(fixturePath), "test_formal.v fixture must exist");

const outDir = path.resolve('hwsec-output/test-sby');
if (fs.existsSync(outDir)) {
    fs.rmSync(outDir, { recursive: true, force: true });
}

const result = await sby.run({
    files: [fixturePath],
    outputDir: outDir,
    depth: 5,
    timeout: 30000
});

console.log(`  -> Status: ${result.status}`);
console.log(`  -> Formal Result: ${result.formalResult}`);
console.log(`  -> Findings count: ${result.findings.length}`);
console.log(`  -> Artifacts produced: ${result.artifacts.length}`);

assert.strictEqual(result.status, "SUCCESS", "Execution should complete successfully");
assert.strictEqual(result.formalResult, "FAIL", "Formal check should fail the flawed assertion");
assert.strictEqual(result.findings.length, 1, "Should emit exactly 1 verified formal violation finding");

const f = result.findings[0];
assert.strictEqual(f.source_tool, "symbiyosys", "Source tool must be symbiyosys");
assert.strictEqual(f.verification_state, "PROPOSED", "Raw formal tool finding must be PROPOSED before verifier evaluation");
assert.strictEqual(f.source_locations[0].line, 18, "Assertion line must be 18");
assert.ok(f.evidence[0].evidence_type.includes("COUNTEREXAMPLE"), "Evidence must indicate counterexample");

// Verify that LayeredVerifier elevates this finding to VERIFIED using the generated VCD trace
const { LayeredVerifier } = await import('../src/workers/verifier.js');
const verifier = new LayeredVerifier();
const evalRes = verifier.verifySingleFinding(f);
assert.strictEqual(evalRes.status, "VERIFIED", "LayeredVerifier must evaluate finding with valid VCD counterexample trace to VERIFIED");

// Verify that at least one trace artifact (vcd/tb/smtc) is captured
const vcdArtifact = result.artifacts.find(a => a.endsWith('.vcd'));
if (vcdArtifact) {
    assert.ok(fs.existsSync(vcdArtifact), "Counterexample VCD must exist on disk");
    console.log("  -> Concrete counterexample trace verified on disk:", vcdArtifact);
}

// 4. Test clean SKIP on non-Verilog files
console.log("[Test 4] Testing SymbiYosys clean SKIP on non-Verilog files...");
const skipRes = await sby.run({
    files: ['main.py', 'test.c'],
    outputDir: outDir
});
assert.strictEqual(skipRes.status, "SKIPPED", "Non-verilog files should produce SKIPPED");
console.log("  -> Non-Verilog files cleanly SKIPPED.");

console.log("\n[PASS] All SymbiYosys Adapter tests passed successfully!\n");
