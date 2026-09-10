import assert from 'assert';
import path from 'path';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';
import { EntryPointInventory } from '../src/core/inventory/entryPointInventory.js';

console.log("============================================================");
console.log("    HWSEC PHASE P2: VULNERABILITY HYPOTHESIS & INVENTORY");
console.log("============================================================\n");

// Test 1: VulnerabilityHypothesis Creation and Signal Consensus
console.log("[P2-Test 1] Testing VulnerabilityHypothesis from Finding & Consensus...");
const rawFinding = {
    id: 'FIND-001',
    cwe: 'CWE-89',
    analyzer: 'semgrep',
    rule_id: 'java.sql.injection',
    file: 'src/main/java/com/example/SearchService.java',
    line: 55,
    source: 'req.getParameter("id")',
    sink: 'stmt.executeQuery(sql)',
    confidence: 0.8
};

const hyp = VulnerabilityHypothesis.fromFinding(rawFinding, { repository_id: 'sample_repo' });
assert.strictEqual(hyp.cwe, 'CWE-89');
assert.strictEqual(hyp.security_condition, 'SQLiOracle');
assert.strictEqual(hyp.discovery_signals.length, 1);
assert.strictEqual(hyp.priority, 0.5);

// Add second agreeing signal from CodeQL
hyp.addDiscoverySignal({
    analyzer: 'codeql',
    rule_id: 'java/sql-injection',
    file: 'src/main/java/com/example/SearchService.java',
    line: 55,
    confidence: 0.95
});
assert.strictEqual(hyp.discovery_signals.length, 2);
assert.strictEqual(hyp.priority, 0.7, "Multi-analyzer consensus must boost hypothesis priority");
console.log("  -> [PASS] Hypothesis formulated and priority consensus calculated.");

// Test 2: EntryPointInventory Discovery on example project
console.log("\n[P2-Test 2] Testing EntryPointInventory multi-language discovery...");
const inventory = new EntryPointInventory();
const exampleProjDir = path.resolve('example-project');
const discovered = inventory.discover(exampleProjDir);

assert.ok(discovered.length > 0, "Inventory must discover entry points in example-project");
const hasMain = discovered.some(ep => ep.type === 'CLI_MAIN');
console.log(`  -> [PASS] Discovered ${discovered.length} entry points across codebase (CLI/HTTP).`);

// Test 3: Resolving Entry Points for Hypotheses
console.log("\n[P2-Test 3] Testing Hypothesis Entry-Point Resolution...");
// Direct match test
const resolvedHyp = new VulnerabilityHypothesis({
    cwe: 'CWE-78',
    security_condition: 'CommandInjectionOracle',
    candidate_path: [discovered[0].file + ':10']
});
const resolvedEp = inventory.resolveForHypothesis(resolvedHyp);
assert.strictEqual(resolvedEp.status, 'RESOLVED');
resolvedHyp.setEntryPoint(resolvedEp);
assert.strictEqual(resolvedHyp.uncertainty.entry_point_unresolved, false);
console.log("  -> [PASS] Matching path resolved to active entry point.");

// Unresolved test
const unresolvedHyp = new VulnerabilityHypothesis({
    cwe: 'CWE-22',
    security_condition: 'PathTraversalOracle',
    candidate_path: ['non_existent/DeepLibrary.java:100']
});
const unresolvedEp = inventory.resolveForHypothesis(unresolvedHyp);
assert.strictEqual(unresolvedEp.status, 'UNRESOLVED');
unresolvedHyp.setEntryPoint(unresolvedEp);
assert.strictEqual(unresolvedHyp.uncertainty.entry_point_unresolved, true);
console.log("  -> [PASS] Unmatched path explicitly classified as ENTRYPOINT_UNRESOLVED.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P2 HYPOTHESIS & INVENTORY TESTS PASSED");
console.log("============================================================\n");
