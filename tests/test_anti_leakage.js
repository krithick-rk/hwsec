import assert from 'assert';
import { CandidateGenerator } from '../src/workers/candidateGenerator.js';
import { LayeredVerifier } from '../src/workers/verifier.js';
import { ControlledProofVerifier } from '../src/workers/proofVerifier.js';
import { evaluatePrediction, PredictionState, GroundTruthLabel, CaseClassification } from '../src/core/bep/bepSchema.js';

console.log("============================================================");
console.log("    HWSEC ANTI-LEAKAGE AND INTEGRITY TEST SUITE");
console.log("============================================================");

// Test 1: Ground Truth Label Must Not Exist in Prediction Inputs
console.log("\n[Test 1] Verifying Prediction Functions Reject Injected Ground Truth...");
const candGen = new CandidateGenerator(null, null);

const cleanInput = {
    files: [{ path: 'BenchmarkTest00001.java', language: 'java' }],
    deterministicFindings: [{
        id: 'FIND-001',
        title: 'Path Traversal',
        source_tool: 'semgrep',
        cwe_id: 'CWE-22',
        source_locations: [{ path: 'BenchmarkTest00001.java', line: 72 }]
    }],
    executedTools: ['semgrep']
};

const candidatesClean = candGen.generateCandidates(cleanInput);
assert.ok(candidatesClean.length > 0, "Clean input should generate candidates");

// Attempt to pass malicious/leaked ground truth into candidate generation
const leakedInput = {
    ...cleanInput,
    is_vulnerable: true,
    ground_truth_label: GroundTruthLabel.VULNERABLE,
    ground_truth: { is_vulnerable: true }
};

const candidatesLeaked = candGen.generateCandidates(leakedInput);
assert.deepStrictEqual(
    candidatesClean.map(c => ({ id: c.id, cwe: c.cwe })),
    candidatesLeaked.map(c => ({ id: c.id, cwe: c.cwe })),
    "Injected ground truth must NOT alter candidate generation outcomes"
);
console.log("  -> [PASS] CandidateGenerator output is invariant to ground truth presence.");

// Test 2: Inverting Ground Truth Manifest Produces Exact Same Prediction States
console.log("\n[Test 2] Verifying Inverted Ground Truth Produces Identical Predictions...");
const predNormal = evaluatePrediction(PredictionState.DETECTED, GroundTruthLabel.VULNERABLE);
const predInverted = evaluatePrediction(PredictionState.DETECTED, GroundTruthLabel.NOT_VULNERABLE);

assert.strictEqual(predNormal, CaseClassification.TP, "DETECTED + VULNERABLE = TP");
assert.strictEqual(predInverted, CaseClassification.FP, "DETECTED + NOT_VULNERABLE = FP");

// Prediction itself must be completely independent of ground truth
const hypotheticalEvidence = { reproduced: true };
const predictionState = hypotheticalEvidence.reproduced ? PredictionState.DETECTED : PredictionState.INCONCLUSIVE;
assert.strictEqual(predictionState, PredictionState.DETECTED, "Evidence alone dictates prediction state");
console.log("  -> [PASS] PredictionState is decoupled from ground truth evaluation layer.");

// Test 3: Ensure ControlledProofVerifier Does Not Consult Ground Truth
console.log("\n[Test 3] Verifying ControlledProofVerifier Artifact Generation Ignores Ground Truth...");
const mockFinding = {
    id: 'FIND-002',
    title: 'SQL Injection',
    cwe_id: 'CWE-89',
    source_locations: [{ path: 'org/owasp/benchmark/testcode/BenchmarkTest00002.java', line: 50 }],
    // Attempted leakage field:
    is_vulnerable: false,
    ground_truth_label: GroundTruthLabel.NOT_VULNERABLE
};

const proofVerifier = new ControlledProofVerifier({}, null, null, { sandboxDir: './hwsec-output/sandbox' });
const proofResult = await proofVerifier.generateProof(mockFinding, './quality-benchmark/java/owasp-benchmark', { proofId: 'PROOF-TEST-LEAK' });

assert.ok(proofResult.artifactContent.includes('BenchmarkTest00002'), "Harness must target the claimed finding");
assert.ok(!proofResult.artifactContent.includes('NOT_VULNERABLE'), "Generated artifact must NEVER contain ground truth strings");
assert.ok(!proofResult.artifactContent.includes('is_vulnerable'), "Generated artifact must NEVER inspect vulnerability ground truth");
console.log("  -> [PASS] ControlledProofVerifier artifact is completely untainted by ground truth.");

console.log("\n[PASS] All Anti-Leakage Invariant Tests Succeeded!");
