import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ToolRegistry, AnalysisBroker } from '../src/core/broker.js';
import { SemgrepTool } from '../src/domains/software/tools/semgrep.js';

console.log('=== Running WP4 & WP5: Analysis Broker & Multi-Language Tools Tests ===');

// Test 1: Tool Registry & Capability Matching
console.log('[Test 1] Testing Tool Registry & Capability Resolution...');
const registry = new ToolRegistry({});
const allTools = registry.getAllTools();
assert.ok(allTools.length >= 8, 'Must register at least 8 default tools');

// Test capability resolution
const lintTools = registry.findToolsForCapability({ capability: 'rtl_lint', languages: ['verilog'] });
assert.strictEqual(lintTools.length, 1);
assert.strictEqual(lintTools[0].name, 'verilator');

const sastTools = registry.findToolsForCapability({ capability: 'sast_pattern_scan', languages: ['python'] });
assert.strictEqual(sastTools.length, 1);
assert.strictEqual(sastTools[0].name, 'semgrep');

const formalTools = registry.findToolsForCapability({ capability: 'rtl_formal', languages: ['verilog'] });
assert.ok(formalTools.some(t => t.name === 'yosys'));

console.log('  -> Capability dispatch mapping verified.');

// Test 2: Software Multi-Language Analysis (Semgrep)
console.log('[Test 2] Testing Software Multi-Language SAST Engine (Python, Java, C, Go)...');
const tempDir = path.resolve('./hwsec-output/test_multilang');
fs.mkdirSync(tempDir, { recursive: true });

// Create test files in C, Python, Java, Go
const cFile = path.join(tempDir, 'vuln.c');
fs.writeFileSync(cFile, '#include <string.h>\nvoid test(char *src) { char dest[10]; strcpy(dest, src); }\n', 'utf-8');

const pyFile = path.join(tempDir, 'app.py');
fs.writeFileSync(pyFile, 'import os\ndef run_cmd(cmd): os.system(cmd)\n', 'utf-8');

const javaFile = path.join(tempDir, 'Test.java');
fs.writeFileSync(javaFile, 'import java.io.*;\npublic class Test { void load(InputStream is) throws Exception { ObjectInputStream ois = new ObjectInputStream(is); ois.readObject(); } }\n', 'utf-8');

const goFile = path.join(tempDir, 'auth.go');
fs.writeFileSync(goFile, 'package main\nconst API_KEY = "my_secret_token_12345"\n', 'utf-8');

const semgrep = new SemgrepTool({});
const result = await semgrep.run({
    files: [cFile, pyFile, javaFile, goFile],
    outputDir: path.join(tempDir, 'semgrep_out')
});

assert.strictEqual(result.status, 'SUCCESS');
assert.ok(result.findings.length >= 4, `Expected at least 4 findings, got ${result.findings.length}`);

// Verify findings have generalized source_locations
for (const f of result.findings) {
    assert.ok(f.source_locations && f.source_locations.length > 0);
    assert.ok(f.source_locations[0].path);
    assert.ok(f.source_locations[0].startLine > 0);
    assert.strictEqual(f.source_tool, 'semgrep');
}
console.log(`  -> Successfully scanned 4 languages. Discovered ${result.findings.length} grounded findings.`);

// Test 3: Structured Action Security & Path Traversal Protection
console.log('[Test 3] Testing Structured Action Validation & Security Guardrails...');
const broker = new AnalysisBroker({});

// Malicious path traversal
await assert.rejects(async () => {
    await broker.executeStructuredAction({
        action: 'run_tool',
        tool: 'semgrep',
        target: '../../../../windows/system32'
    }, tempDir);
}, /Path traversal attempt blocked/);

// Unauthorized action
await assert.rejects(async () => {
    await broker.executeStructuredAction({
        action: 'execute_shell',
        tool: 'semgrep',
        target: '.'
    }, tempDir);
}, /Only 'run_tool' is authorized/);

// Unregistered tool
await assert.rejects(async () => {
    await broker.executeStructuredAction({
        action: 'run_tool',
        tool: 'arbitrary_exploit_tool',
        target: '.'
    }, tempDir);
}, /is not registered/);

console.log('  -> Security guardrails passed (traversal, unauthorized action, unregistered tools blocked).');

console.log('\n[PASS] All WP4 & WP5 Analysis Broker tests passed successfully!\n');
