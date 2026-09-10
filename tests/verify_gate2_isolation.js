import assert from 'assert';
import { BEPPackager } from '../prototype/workers/evidence/bepPackager.js';
import { EvidenceContract } from '../prototype/workers/evidence/evidenceContract.js';

console.log("============================================================");
console.log("    GATE 2: ADVERSARIAL GROUND-TRUTH ISOLATION TEST");
console.log("============================================================\n");

const packager = new BEPPackager({ artifactsDir: 'prototype/artifacts' });
const testCaseId = 'BenchmarkTest00001';

// 1. Condition A: Mock registry with VULNERABLE
packager.caseAdapter.cases = [{
    case_id: testCaseId,
    cwe: 'CWE-22',
    target_class: 'org.owasp.benchmark.testcode.BenchmarkTest00001',
    entrypoint_method: 'doPost',
    input_vector_type: 'HEADER',
    input_param_name: 'vector',
    sink_type: 'java.io.File',
    expected_label: 'VULNERABLE'
}];
const packetA = packager.packageCase(testCaseId);

// 2. Condition B: Mock registry with SAFE / NOT_VULNERABLE
packager.caseAdapter.cases = [{
    case_id: testCaseId,
    cwe: 'CWE-22',
    target_class: 'org.owasp.benchmark.testcode.BenchmarkTest00001',
    entrypoint_method: 'doPost',
    input_vector_type: 'HEADER',
    input_param_name: 'vector',
    sink_type: 'java.io.File',
    expected_label: 'NOT_VULNERABLE'
}];
const packetB = packager.packageCase(testCaseId);

// 3. Condition C: Mock registry with expected_label completely stripped
packager.caseAdapter.cases = [{
    case_id: testCaseId,
    cwe: 'CWE-22',
    target_class: 'org.owasp.benchmark.testcode.BenchmarkTest00001',
    entrypoint_method: 'doPost',
    input_vector_type: 'HEADER',
    input_param_name: 'vector',
    sink_type: 'java.io.File'
}];
const packetC = packager.packageCase(testCaseId);

console.log(`Condition A Verdict: ${packetA.verdict.verdict}, Reason: ${packetA.verdict.reason_code}`);
console.log(`Condition B Verdict: ${packetB.verdict.verdict}, Reason: ${packetB.verdict.reason_code}`);
console.log(`Condition C Verdict: ${packetC.verdict.verdict}, Reason: ${packetC.verdict.reason_code}`);

// Check that packets are 100% invariant across all three conditions
assert.strictEqual(packetA.verdict.verdict, packetB.verdict.verdict, "Verdict must not change when expected_label is flipped to SAFE");
assert.strictEqual(packetA.verdict.verdict, packetC.verdict.verdict, "Verdict must not change when expected_label is removed");
assert.strictEqual(packetA.verdict.reason_code, packetB.verdict.reason_code, "Reason code must be identical");
assert.strictEqual(packetA.verdict.reason_code, packetC.verdict.reason_code, "Reason code must be identical");

// Compare packets ignoring runtime timestamp
delete packetA.evidence.provenance.timestamp;
delete packetB.evidence.provenance.timestamp;
delete packetC.evidence.provenance.timestamp;

const jsonA = JSON.stringify(packetA.evidence);
const jsonB = JSON.stringify(packetB.evidence);
const jsonC = JSON.stringify(packetC.evidence);

assert.strictEqual(jsonA, jsonB, "Evidence packet under Condition A and B must match bit-for-bit");
assert.strictEqual(jsonA, jsonC, "Evidence packet under Condition A and C must match bit-for-bit");

console.log("\n[GATE 2 VERIFICATION RESULT]: PASS");
console.log("  -> Evidence generation and verdict derivation have ZERO access or sensitivity to expected_label.");
