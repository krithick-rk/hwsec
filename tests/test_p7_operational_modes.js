import assert from 'assert';
import { OperatingMode, SemanticLifecycleState, AnalysisStatus, isValidTransition } from '../src/core/state.js';
import { BrokerCapability } from '../src/core/broker.js';
import { AnalystDossier } from '../src/core/analyst/analystDossier.js';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';

console.log("============================================================");
console.log("    HWSEC PHASE P7: OPERATIONAL MODES & UX TEST SUITE");
console.log("============================================================\n");

// Test 1: Operating Modes & Lifecycle States
console.log("[P7-Test 1] Testing Operating Modes & 5-State Semantic Lifecycle...");
assert.strictEqual(OperatingMode.FAST, 'FAST');
assert.strictEqual(OperatingMode.STANDARD, 'STANDARD');
assert.strictEqual(OperatingMode.DEEP, 'DEEP');
assert.strictEqual(OperatingMode.FORENSIC, 'FORENSIC');

assert.strictEqual(SemanticLifecycleState.DISCOVERED, 'DISCOVERED');
assert.strictEqual(SemanticLifecycleState.HYPOTHESIS_READY, 'HYPOTHESIS_READY');
assert.strictEqual(SemanticLifecycleState.EXECUTING, 'EXECUTING');
assert.strictEqual(SemanticLifecycleState.EVIDENCE_READY, 'EVIDENCE_READY');
assert.strictEqual(SemanticLifecycleState.VERDICTED, 'VERDICTED');

assert.strictEqual(isValidTransition(AnalysisStatus.PLANNED, AnalysisStatus.APPROVED), true);
assert.strictEqual(isValidTransition(AnalysisStatus.APPROVED, AnalysisStatus.RUNNING), true);
console.log("  -> [PASS] Operating modes and simplified state lifecycle verified.");

// Test 2: 9 Core Broker Capabilities
console.log("\n[P7-Test 2] Testing 9 Core Broker Capabilities...");
const requiredCaps = [
    'DISCOVERY', 'SLICE', 'HYPOTHESIS', 'WITNESS_SEARCH',
    'CONSTRAINT_REFINEMENT', 'RUNTIME_OBSERVATION', 'CONTROL_EXECUTION',
    'EVIDENCE_ASSEMBLY', 'VERDICT_REDUCTION'
];

for (const cap of requiredCaps) {
    assert.strictEqual(BrokerCapability[cap], cap, `BrokerCapability.${cap} must exist`);
}
console.log("  -> [PASS] All 9 core broker operational capabilities registered.");

// Test 3: Analyst Experience Dossier Generation
console.log("\n[P7-Test 3] Testing Analyst Dossier Generation (10 Core Questions)...");
const hyp = new VulnerabilityHypothesis({
    cwe: 'CWE-89',
    security_condition: 'SQLiOracle',
    attack_surface: 'HTTP_PARAM',
    source: 'id',
    sink: 'stmt.executeQuery',
    entry_point: { status: 'RESOLVED', route: '/api/v1/search', method: 'GET' }
});

const mockVerdict = {
    verdict: 'DETECTED',
    reason_code: 'VERIFIED_EXPLOIT_WITNESS',
    dag_hash: 'dag_abc123456',
    witness_input: { parameter: 'id', value: "' OR '1'='1" },
    obligations: {
        concrete_execution_succeeded: true,
        security_oracle_fired: true,
        negative_control_passed: true,
        provenance_manifest_verified: true
    }
};

const dossier = AnalystDossier.generateCaseSummary(hyp, {}, mockVerdict);
assert.ok(dossier.summary.q1_suspected_vulnerability.includes('CWE-89'));
assert.strictEqual(dossier.summary.q2_attack_surface_and_entry_point.resolved, true);
assert.strictEqual(dossier.summary.q7_security_effect_observed, true);
assert.strictEqual(dossier.summary.q9_replayable, true);
assert.strictEqual(dossier.summary.q10_verdict_decision.verdict, 'DETECTED');
assert.ok(dossier.markdown_dossier.includes('HWSEC Security Operations Case Dossier'));
console.log("  -> [PASS] Analyst dossier generated with structured Q&A and Markdown representation.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P7 OPERATIONAL MODES & UX TESTS PASSED");
console.log("============================================================\n");
