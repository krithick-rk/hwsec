import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { spawnSync } from 'child_process';
import { BEPManager } from '../src/core/bep/bepManager.js';
import { BEPIntegrityChecker } from '../src/core/bep/integrityChecker.js';
import { TransitionLedger } from '../src/core/bep/transitionLedger.js';
import { FPReductionAuditEngine } from '../src/core/bep/fpReductionAudit.js';
import { HardwareAssertionTracker } from '../src/core/bep/hardwareAssertionTracker.js';
import { AblationSuite } from '../src/core/bep/ablationSuite.js';
import { DossierGenerator } from '../src/core/bep/dossierGenerator.js';
import {
    createGroundTruthRecord,
    createRawFindingRecord,
    createNormalizedFindingRecord,
    createCandidateRecord,
    createVerifierDecisionRecord,
    createProofArtifactRecord,
    createCaseResultRecord,
    GroundTruthLabel,
    CaseClassification,
    TriggerType,
    EvidenceBasis
} from '../src/core/bep/bepSchema.js';

console.log('============================================================');
console.log('   HWSEC BENCHMARK EVIDENCE PACKAGE (BEP) TEST SUITE');
console.log('============================================================\n');

const testEvidenceDir = path.resolve('quality-benchmark/evidence/runs/test_bep_suite');

// Clean up previous test output if any
if (fs.existsSync(testEvidenceDir)) {
    fs.rmSync(testEvidenceDir, { recursive: true, force: true });
}

// 1. BEP Bundle Creation
console.log('[Test 1] BEP Bundle Creation & Manifest Generator...');
const manager = new BEPManager('quality-benchmark/evidence/runs');
const writer = manager.createBundle('owasp-benchmark-java', 'test_run_001', {
    case_count: 10,
    languages: ['Java']
});
assert(fs.existsSync(writer.bundlePath), 'Bundle directory must be created');
assert(fs.existsSync(path.join(writer.bundlePath, 'manifest.json')), 'manifest.json must exist');
console.log('  ok Bundle initialized cleanly');

// 2. Case & Ground Truth Record Writing
console.log('[Test 2] Per-Case Ground Truth & Raw Finding Capture...');
const gt1 = createGroundTruthRecord({
    case_id: 'CASE-001',
    source_file: 'BenchmarkTest001.java',
    cwe: 'CWE-89',
    ground_truth_label: GroundTruthLabel.VULNERABLE
});
const gt2 = createGroundTruthRecord({
    case_id: 'CASE-002',
    source_file: 'BenchmarkTest002.java',
    cwe: 'CWE-78',
    ground_truth_label: GroundTruthLabel.NOT_VULNERABLE
});

writer.writeRecord('ground_truth.jsonl', gt1);
writer.writeRecord('ground_truth.jsonl', gt2);

const raw1 = createRawFindingRecord({
    finding_id: 'RAW-001',
    analyzer: 'semgrep',
    rule_id: 'java.sql.injection',
    file: 'BenchmarkTest001.java'
});
writer.writeRecord('raw_findings.jsonl', raw1);
console.log('  ok Ground truth & raw findings written');

// 3. Finding Normalization & Candidate Triggers
console.log('[Test 3] Finding Normalization & Candidate Trigger Categories...');
const norm1 = createNormalizedFindingRecord({
    finding_id: 'NORM-001',
    linked_raw_ids: ['RAW-001'],
    cwe: 'CWE-89',
    file: 'BenchmarkTest001.java'
});
const cand1 = createCandidateRecord({
    candidate_id: 'CAND-001',
    case_id: 'CASE-001',
    trigger_types: [TriggerType.STATIC_FINDING, TriggerType.GRAPH_PATH],
    source_finding_ids: ['NORM-001']
});
writer.writeRecord('normalized_findings.jsonl', norm1);
writer.writeRecord('candidates.jsonl', cand1);
console.log('  ok Normalized findings and candidate records persisted');

// 4. Transition Ledger Append-Only Behavior
console.log('[Test 4] Transition Ledger Append-Only & Taxonomy Categorization...');
const ledger = new TransitionLedger();
const tr1 = ledger.recordTransition({
    case_id: 'CASE-001',
    from_state: 'NOT_EVALUATED',
    to_state: 'CANDIDATE',
    stage: 'CANDIDATE_GENERATOR'
});
const tr2 = ledger.recordTransition({
    case_id: 'CASE-002',
    from_state: 'FP',
    to_state: 'TN',
    stage: 'PROOF_VERIFIER',
    proof_ref: 'PROOF-001',
    evidence_refs: ['ASAN-001']
});
assert.strictEqual(ledger.getTransitionsForCase('CASE-001').length, 1);
assert.strictEqual(tr2.transition_type, 'EVIDENCE_BACKED');
writer.writeRecord('classification_transitions.jsonl', tr1);
writer.writeRecord('classification_transitions.jsonl', tr2);
console.log('  ok Transition ledger correctly tracked evidence-backed transition');

// 5. Verifier Decision Logging & Evidence Basis
console.log('[Test 5] Verifier Decision Records & Evidence Basis...');
const vd1 = createVerifierDecisionRecord({
    decision_id: 'VD-001',
    case_id: 'CASE-002',
    candidate_id: 'CAND-002',
    decision: 'REJECT',
    evidence_basis: EvidenceBasis.SUPPORTED_BY_DETERMINISTIC
});
writer.writeRecord('verifier_decisions.jsonl', vd1);
console.log('  ok Verifier decision recorded with deterministic evidence basis');

// 6. Proof Artifact Storage & Cryptographic Provenance
console.log('[Test 6] Proof Artifact Storage & SHA-256 Provenance...');
const proofArt = writer.saveProofArtifact('PROOF-001', 'test_regression.c', '#include <stdio.h>\nint main() { return 0; }\n');
const proofRec = createProofArtifactRecord({
    proof_id: 'PROOF-001',
    case_id: 'CASE-002',
    verdict: 'REPRODUCED',
    repetition_count: '3/3',
    stdout_hash: proofArt.sha256
});
writer.writeRecord('proof_artifacts.jsonl', proofRec);
assert.strictEqual(proofArt.sha256.length, 64);
console.log('  ok Proof artifact saved and SHA-256 digest computed');

// 7. Case Results & Aggregate Recomputation
console.log('[Test 7] Case Results & Derived Aggregate Metrics...');
const cr1 = createCaseResultRecord({
    case_id: 'CASE-001',
    ground_truth: GroundTruthLabel.VULNERABLE,
    classification: CaseClassification.TP,
    source_finding_ids: ['NORM-001']
});
const cr2 = createCaseResultRecord({
    case_id: 'CASE-002',
    ground_truth: GroundTruthLabel.NOT_VULNERABLE,
    classification: CaseClassification.TN,
    transition_ids: ['TR-002']
});
writer.writeRecord('case_results.jsonl', cr1);
writer.writeRecord('case_results.jsonl', cr2);

const agg = { tp: 1, fp: 0, fn: 0, tn: 1, unknown: 0, total_cases: 2, precision: 1.0, recall: 1.0, f1: 1.0 };
const cm = { tp: 1, fp: 0, fn: 0, tn: 1, unknown: 0 };
await writer.finalize(agg, cm, {});
console.log('  ok Bundle finalized and checksums.sha256 written');

// 8. Evidence Integrity Checker Pass Case
console.log('[Test 8] Fail-Closed Evidence Integrity Checker (Pass Case)...');
const reader = manager.loadBundle(writer.bundlePath);
const checker = new BEPIntegrityChecker();
const passRes = checker.verifyBundle(reader);
assert.strictEqual(passRes.passed, true, 'Valid bundle must pass integrity check');
console.log('  ok Integrity check passed');

// 9. Fail-Closed Integrity Checker (Tamper Detection)
console.log('[Test 9] Integrity Checker Tamper Detection (SHA-256 Mismatch)...');
const manifestPath = path.join(writer.bundlePath, 'manifest.json');
const manifestContent = fs.readFileSync(manifestPath, 'utf8');
fs.writeFileSync(manifestPath, manifestContent + '\n// tampered', 'utf8');
const tamperRes = checker.verifyBundle(reader);
assert.strictEqual(tamperRes.passed, false, 'Tampered file must fail integrity check');
assert(tamperRes.errors.some(e => e.includes('SHA-256 mismatch')), 'Must report SHA-256 mismatch');
// Restore manifest
fs.writeFileSync(manifestPath, manifestContent, 'utf8');
console.log('  ok Tamper detection verified (failed closed)');

// 10. OWASP FP-Reduction Audit Engine
console.log('[Test 10] OWASP FP-Reduction Audit Engine (194 FP->TN Cases)...');
const fpAuditEngine = new FPReductionAuditEngine();
const mockTransitions = [];
const mockDecisions = [];
const mockProofs = [];
const mockCases = [];

for (let i = 1; i <= 194; i++) {
    const cId = `CASE-FP-${i}`;
    const dId = `VD-FP-${i}`;
    const pId = `PROOF-FP-${i}`;
    mockCases.push(createCaseResultRecord({ case_id: cId, classification: 'TN' }));
    mockTransitions.push({ case_id: cId, from_state: 'FP', to_state: 'TN', verifier_decision_id: dId, proof_ref: pId, timestamp: new Date().toISOString() });
    mockDecisions.push(createVerifierDecisionRecord({ decision_id: dId, case_id: cId, evidence_basis: EvidenceBasis.SUPPORTED_BY_DETERMINISTIC }));
    mockProofs.push(createProofArtifactRecord({ proof_id: pId, case_id: cId, verdict: 'REPRODUCED', repetition_count: '3/3' }));
}

const auditRes = fpAuditEngine.auditRun(mockCases, mockTransitions, mockDecisions, mockProofs);
assert.strictEqual(auditRes.summary.actual_fp_to_tn_transitions, 194);
assert.strictEqual(auditRes.summary.breakdown.PROOF_CONFIRMED, 194);
assert.strictEqual(auditRes.summary.is_valid_claim, true);
console.log('  ok FP-reduction audit engine verified 194 proof-confirmed transitions');

// 11. Hardware SVA Assertion Evidence Tracker
console.log('[Test 11] Hardware SVA Assertion Evidence Tracker...');
const hwTracker = new HardwareAssertionTracker();
hwTracker.recordAssertion({
    assertion_id: 'SVA-001',
    case_id: 'CASE-RTL-01',
    compile_result: 'PASSED',
    vacuity_status: 'NON_VACUOUS',
    proof_result: 'PASS'
});
hwTracker.recordAssertion({
    assertion_id: 'SVA-002',
    case_id: 'CASE-RTL-02',
    compile_result: 'PASSED',
    vacuity_status: 'NON_VACUOUS',
    proof_result: 'FAIL'
});
const hwMetrics = hwTracker.getMetrics();
assert.strictEqual(hwMetrics.total_assertions, 2);
assert.strictEqual(hwMetrics.syntax_compile_success_rate, 1.0);
assert.strictEqual(hwMetrics.confirmed_proof_rate, 0.5);
console.log('  ok Hardware assertion metrics calculated cleanly');

// 12. Ablation & Control Experiment Suite
console.log('[Test 12] Ablation Suite (Configurations A through H)...');
const ablation = new AblationSuite();
ablation.recordConfigResult('A', [
    createCaseResultRecord({ case_id: 'C1', classification: 'FP' }),
    createCaseResultRecord({ case_id: 'C2', classification: 'FN' })
]);
ablation.recordConfigResult('G', [
    createCaseResultRecord({ case_id: 'C1', classification: 'TN', reclassification_taxonomy: 'EVIDENCE_BACKED' }),
    createCaseResultRecord({ case_id: 'C2', classification: 'TP', reclassification_taxonomy: 'EVIDENCE_BACKED' })
]);
const diffAG = ablation.computeDiff('A', 'G');
assert.strictEqual(diffAG.total_changed_cases, 2);
assert.strictEqual(diffAG.fp_to_tn_count, 1);
assert.strictEqual(diffAG.fn_to_tp_count, 1);
console.log('  ok Ablation diff calculated 2 reclassified cases');

// 13. Single-Case Human Review Dossier Generator
console.log('[Test 13] Single-Case Human Review Dossier Generator...');
const dossierGen = new DossierGenerator();
const { markdown } = dossierGen.generateDossier(reader, 'CASE-001');
assert(markdown.includes('CASE-001'), 'Dossier markdown must include case ID');
assert(markdown.includes('BenchmarkTest001.java'), 'Dossier markdown must include source file');
console.log('  ok Single-case dossier generated');

// 14. CLI Command Integration Test: verify-evidence
console.log('[Test 14] CLI Integration Test (hwsec benchmark verify-evidence)...');
const cliRes = spawnSync(process.execPath, [
    'src/index.js', 'benchmark', 'verify-evidence', writer.bundlePath
], { encoding: 'utf-8', env: process.env });
assert.strictEqual(cliRes.status, 0, `verify-evidence should exit 0. Stderr: ${cliRes.stderr}`);
assert(cliRes.stdout.includes('Integrity Gate:  ✅ PASS'), 'CLI output must report PASS');
console.log('  ok CLI benchmark verify-evidence command passed');

// Clean up temporary test evidence directory
if (fs.existsSync(writer.bundlePath)) {
    fs.rmSync(writer.bundlePath, { recursive: true, force: true });
}

console.log('\n============================================================');
console.log('  BEP TEST SUITE SUMMARY: ALL 14 TEST POINTS PASSED ✅');
console.log('============================================================\n');
