import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { JoernTool } from '../src/domains/software/tools/joern.js';
import { loadConfig } from '../src/core/config.js';

console.log("=== Running Joern Real Adapter Integration Tests ===");

const config = loadConfig('config.json');
const joern = new JoernTool(config);

// 1. Test checkInstalled
console.log("[Test 1] Testing JoernTool.checkInstalled()...");
const install = await joern.checkInstalled();
console.log(`  -> Installed: ${install.installed}, Version: ${install.version}, Mode: ${install.isWsl ? 'WSL' : 'Native'}`);
assert.strictEqual(install.installed, true, "Joern should be detected on this system");

// 2. Test run on real C fixture (test_vuln.c)
console.log("[Test 2] Testing JoernTool.run() on test_vuln.c fixture...");
const fixturePath = path.resolve('tests/fixtures/test_vuln.c');
assert.ok(fs.existsSync(fixturePath), "test_vuln.c must exist");

const outDir = path.resolve('hwsec-output/test-joern');
if (fs.existsSync(outDir)) {
    fs.rmSync(outDir, { recursive: true, force: true });
}

const result = await joern.run({
    files: [fixturePath],
    language: 'c',
    outputDir: outDir,
    timeout: 60000
});

console.log(`  -> Status: ${result.status}`);
console.log(`  -> Findings count: ${result.findings.length}`);
console.log(`  -> CPG generated: ${result.telemetry?.cpgGenerated} (${result.telemetry?.cpgSizeBytes} bytes)`);

assert.strictEqual(result.status, "SUCCESS", "Joern execution should succeed");
assert.ok(result.findings.length >= 2, "Joern should find at least 2 vulnerabilities in test_vuln.c");

const strcpyFinding = result.findings.find(f => f.title.includes('strcpy') || f.cwe_id === 'CWE-120');
assert.ok(strcpyFinding, "Should detect strcpy (CWE-120)");
assert.strictEqual(strcpyFinding.source_locations[0].line, 8, "strcpy line should be 8");

const systemFinding = result.findings.find(f => f.title.includes('system') || f.cwe_id === 'CWE-78');
assert.ok(systemFinding, "Should detect system (CWE-78)");
assert.strictEqual(systemFinding.source_locations[0].line, 13, "system line should be 13");

// Verify evidence artifact exists
assert.ok(fs.existsSync(result.artifacts[0]), "CPG binary must exist on disk");
console.log("  -> Evidence artifact verified on disk:", result.artifacts[0]);

// 3. Test clean SKIP on unsupported file types
console.log("[Test 3] Testing JoernTool.run() with unsupported files...");
const skipRes = await joern.run({
    files: ['dummy.xyz', 'test.v'],
    outputDir: outDir
});
assert.strictEqual(skipRes.status, "SKIPPED", "Unsupported files should produce SKIPPED status");
console.log("  -> Unsupported files cleanly SKIPPED.");

console.log("\n[PASS] All Joern Adapter tests passed successfully!\n");
