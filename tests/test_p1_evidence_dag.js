import assert from 'assert';
import { EvidenceDag, EvidenceAuthority, EvidenceNodeType, EvidenceEdgeRelation, VerdictType, InconclusiveReason } from '../src/core/bep/evidenceDag.js';

console.log("============================================================");
console.log("    HWSEC PHASE P1: TYPED EVIDENCE DAG & REDUCER TESTS");
console.log("============================================================\n");

// Test 1: Node & Edge Content-Addressing
console.log("[P1-Test 1] Testing Evidence DAG Content-Addressing & Integrity...");
const dag = new EvidenceDag({ run_id: 'RUN-TEST-001' });

const hypNode = dag.addNode(EvidenceNodeType.HYPOTHESIS, {
    cwe: 'CWE-89',
    claim: 'Attacker input reaches Statement.executeQuery',
    security_condition: 'SQLiOracle'
});

const entryNode = dag.addNode(EvidenceNodeType.ENTRY_POINT, {
    type: 'HTTP_ENDPOINT',
    route: '/api/v1/search',
    method: 'POST',
    status: 'RESOLVED'
});

const findingNode = dag.addNode(EvidenceNodeType.FINDING, {
    analyzer: 'semgrep',
    rule_id: 'java.sql.injection',
    file: 'SearchController.java',
    line: 42
});

const witnessNode = dag.addNode(EvidenceNodeType.WITNESS_INPUT, {
    vector: 'HTTP_PARAM',
    param_name: 'query',
    payload: "' OR '1'='1"
});

const traceNode = dag.addNode(EvidenceNodeType.RUNTIME_TRACE, {
    exit_code: 0,
    timeout: false,
    duration_ms: 120
});

const oracleNode = dag.addNode(EvidenceNodeType.SECURITY_ORACLE_RESULT, {
    oracle: 'SQLiOracle',
    condition_satisfied: true,
    ast_modified: true
});

const controlNode = dag.addNode(EvidenceNodeType.NEGATIVE_CONTROL, {
    type: 'BENIGN_INPUT',
    payload: 'clean_search',
    passed: true
});

const provNode = dag.addNode(EvidenceNodeType.PROVENANCE_MANIFEST, {
    tool_version: '2.0.0',
    environment: 'WSL-Ubuntu-24.04',
    verified: true
});

// Add Edges
dag.addEdge(hypNode.id, entryNode.id, EvidenceEdgeRelation.DERIVED_FROM);
dag.addEdge(findingNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
dag.addEdge(witnessNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
dag.addEdge(traceNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
dag.addEdge(oracleNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
dag.addEdge(controlNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);

const integrity = dag.verifyIntegrity();
assert.strictEqual(integrity.valid, true, "DAG integrity must be valid");
console.log("  -> [PASS] DAG constructed and cryptographic integrity verified.");

// Test 2: Full Evidence -> DETECTED
console.log("\n[P1-Test 2] Testing EvidenceAuthority Reduction -> DETECTED...");
const verdictDetected = EvidenceAuthority.reduce(dag, hypNode.id);
assert.strictEqual(verdictDetected.verdict, VerdictType.DETECTED);
assert.strictEqual(verdictDetected.reason_code, 'VERIFIED_EXPLOIT_WITNESS');
assert.ok(verdictDetected.dag_hash);
console.log("  -> [PASS] Complete evidence bundle cleanly reduces to DETECTED.");

// Test 3: Missing / Failed Negative Control -> INCONCLUSIVE with CONTROL_INVALID
console.log("\n[P1-Test 3] Testing Missing Negative Control -> INCONCLUSIVE...");
const dagNoControl = new EvidenceDag({ run_id: 'RUN-TEST-002' });
const hNode = dagNoControl.addNode(EvidenceNodeType.HYPOTHESIS, { cwe: 'CWE-89' });
const eNode = dagNoControl.addNode(EvidenceNodeType.ENTRY_POINT, { status: 'RESOLVED' });
const wNode = dagNoControl.addNode(EvidenceNodeType.WITNESS_INPUT, { payload: "' OR 1=1" });
const tNode = dagNoControl.addNode(EvidenceNodeType.RUNTIME_TRACE, { exit_code: 0 });
const oNode = dagNoControl.addNode(EvidenceNodeType.SECURITY_ORACLE_RESULT, { condition_satisfied: true });
const badCtrl = dagNoControl.addNode(EvidenceNodeType.NEGATIVE_CONTROL, { passed: false });
const pNode = dagNoControl.addNode(EvidenceNodeType.PROVENANCE_MANIFEST, { verified: true });

dagNoControl.addEdge(hNode.id, eNode.id, EvidenceEdgeRelation.DERIVED_FROM);
dagNoControl.addEdge(wNode.id, hNode.id, EvidenceEdgeRelation.SUPPORTS);
dagNoControl.addEdge(tNode.id, hNode.id, EvidenceEdgeRelation.SUPPORTS);
dagNoControl.addEdge(oNode.id, hNode.id, EvidenceEdgeRelation.SUPPORTS);
dagNoControl.addEdge(badCtrl.id, hNode.id, EvidenceEdgeRelation.SUPPORTS);

const verdictNoCtrl = EvidenceAuthority.reduce(dagNoControl, hNode.id);
assert.strictEqual(verdictNoCtrl.verdict, VerdictType.INCONCLUSIVE);
assert.strictEqual(verdictNoCtrl.reason_code, InconclusiveReason.CONTROL_INVALID);
console.log("  -> [PASS] Invalidation of negative control fails closed to INCONCLUSIVE.");

// Test 4: Unresolved Entry Point -> INCONCLUSIVE with ENTRYPOINT_UNRESOLVED
console.log("\n[P1-Test 4] Testing Unresolved Entry Point -> ENTRYPOINT_UNRESOLVED...");
const dagUnresolved = new EvidenceDag();
const hyp2 = dagUnresolved.addNode(EvidenceNodeType.HYPOTHESIS, { cwe: 'CWE-22' });
const unresEntry = dagUnresolved.addNode(EvidenceNodeType.ENTRY_POINT, { status: 'UNRESOLVED' });
dagUnresolved.addEdge(hyp2.id, unresEntry.id, EvidenceEdgeRelation.DERIVED_FROM);

const verdictUnres = EvidenceAuthority.reduce(dagUnresolved, hyp2.id);
assert.strictEqual(verdictUnres.verdict, VerdictType.INCONCLUSIVE);
assert.strictEqual(verdictUnres.reason_code, InconclusiveReason.ENTRYPOINT_UNRESOLVED);
console.log("  -> [PASS] Unresolved entry point yields ENTRYPOINT_UNRESOLVED.");

// Test 5: Explicit Refutation -> NOT_DETECTED
console.log("\n[P1-Test 5] Testing Explicit Refutation -> NOT_DETECTED...");
const dagRefuted = new EvidenceDag();
const hyp3 = dagRefuted.addNode(EvidenceNodeType.HYPOTHESIS, { cwe: 'CWE-78' });
const refNode = dagRefuted.addNode(EvidenceNodeType.PATCH_RESULT, { refuted: true, patch_verified: true });
dagRefuted.addEdge(refNode.id, hyp3.id, EvidenceEdgeRelation.REFUTES);

const verdictRefuted = EvidenceAuthority.reduce(dagRefuted, hyp3.id);
assert.strictEqual(verdictRefuted.verdict, VerdictType.NOT_DETECTED);
console.log("  -> [PASS] Explicit refutation yields NOT_DETECTED.");

// Test 6: DAG Serialization & Rehydration
console.log("\n[P1-Test 6] Testing DAG Serialization & Roundtrip Integrity...");
const serialized = dag.toJSON();
const rehydrated = EvidenceDag.fromJSON(serialized);
assert.strictEqual(rehydrated.computeDagHash(), dag.computeDagHash(), "DAG hashes must match perfectly");
console.log("  -> [PASS] DAG JSON serialization roundtrip verified.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P1 EVIDENCE DAG TESTS PASSED");
console.log("============================================================\n");
