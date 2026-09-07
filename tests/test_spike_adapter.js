import assert from 'assert';
import path from 'path';
import { SpikeTool } from '../src/domains/hardware/tools/spike.js';

console.log("=== Running Spike Adapter Integration & Divergence Tests ===");

const spike = new SpikeTool({});

// 1. Test checkInstalled
console.log("[Test 1] Testing Spike checkInstalled()...");
const install = await spike.checkInstalled();
console.log(`  -> Installed: ${install.installed}, Error: ${install.error || 'None'}`);
if (!install.installed) {
    assert.strictEqual(install.installed, false);
    assert.ok(install.error.includes('Spike RISC-V ISA Simulator not found'), "Error should report missing simulator");
    console.log("  -> Explicit unavailable state confirmed.");
}

// 2. Test run() when unavailable returns clean UNAVAILABLE status
console.log("[Test 2] Testing run() behavior when Spike is unavailable...");
const runRes = await spike.run({
    files: ['firmware.elf'],
    outputDir: path.resolve('hwsec-output/test-spike')
});
if (!install.installed) {
    assert.strictEqual(runRes.status, "UNAVAILABLE", "Must return explicit UNAVAILABLE status");
    assert.strictEqual(runRes.findings.length, 0, "No fake findings allowed");
    assert.ok(runRes.reason, "Must provide explicit reason");
    console.log("  -> Verified clean UNAVAILABLE return without fake findings.");
}

// 3. Test Commit Log Parser
console.log("[Test 3] Testing Spike Commit Log Parser...");
const sampleTrace = `
core   0: 3 0x0000000080000000 (0x00000297) x05 0x0000000080000000
core   0: 3 0x0000000080000004 (0x02028593) x11 0x0000000080000020
core   0: 3 0x0000000080000008 (0x0000006f)
`;
const steps = spike.parseCommitLog(sampleTrace);
assert.strictEqual(steps.length, 3, "Should parse 3 instruction commit steps");
assert.strictEqual(steps[0].pc, '0x0000000080000000');
assert.strictEqual(steps[0].rd, 'x05');
assert.strictEqual(steps[0].val, '0x0000000080000000');
assert.strictEqual(steps[1].rd, 'x11');
assert.strictEqual(steps[1].val, '0x0000000080000020');
console.log("  -> Commit log parser verified.");

// 4. Test Trace Comparison & Divergence Detection
console.log("[Test 4] Testing Trace Comparison & Divergence Detection...");
const rtlTraceDivergent = `
core   0: 3 0x0000000080000000 (0x00000297) x05 0x0000000080000000
core   0: 3 0x0000000080000004 (0x02028593) x11 0x00000000DEADBEEF
`;
const rtlSteps = spike.parseCommitLog(rtlTraceDivergent);
const divergences = spike.compareTraces(steps, rtlSteps);

assert.strictEqual(divergences.length, 1, "Should detect exactly 1 divergence");
assert.strictEqual(divergences[0].type, 'REGISTER_MISMATCH', "Type should be REGISTER_MISMATCH");
assert.strictEqual(divergences[0].step, 1, "Divergence step should be 1");
assert.strictEqual(divergences[0].spike.val, '0x0000000080000020');
assert.strictEqual(divergences[0].rtl.val, '0x00000000DEADBEEF');
console.log("  -> Trace comparison verified with precise mismatch detection:", divergences[0].description);

console.log("\n[PASS] All Spike Adapter tests passed successfully!\n");
