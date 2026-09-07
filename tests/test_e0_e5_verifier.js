import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { LayeredVerifier, VerificationLevel } from '../src/workers/verifier.js';
import { createFinding, createEvidence, Severity, VerificationState } from '../src/core/schema.js';

console.log("=== Running Complete E0–E5 Layered Verifier Tests ===");

const testDir = path.resolve('hwsec-output/test_verifier_e0_e5');
if (!fs.existsSync(testDir)) fs.mkdirSync(testDir, { recursive: true });

// Create artifacts
const staticFile = path.join(testDir, 'static.txt');
fs.writeFileSync(staticFile, 'Warning: potential flaw', 'utf-8');

const artifactFile = path.join(testDir, 'target.bin');
fs.writeFileSync(artifactFile, 'DUMMY BINARY ARTIFACT', 'utf-8');

const crashFile = path.join(testDir, 'crash.vcd');
fs.writeFileSync(crashFile, '$timescale 1ps $end\nAssert failed in top: violation at step 4\ncounterexample trace', 'utf-8');

const verifier = new LayeredVerifier();

// 1. Test E0 (Claim only -> Refuted)
console.log("[Test 1] Testing E0 Claim Only -> REFUTED...");
const hypE0 = {
    hypothesis_id: 'HYP-E0',
    title: 'Unsubstantiated Claim',
    claim: 'Unproven backdoor in module',
    affected_assets: ['core.v']
};
const resE0 = await verifier.verify([hypE0], [], {});
const sE0 = resE0.verificationSummaries[0];
assert.strictEqual(sE0.level, VerificationLevel.E0_CLAIM_ONLY);
assert.strictEqual(sE0.status, VerificationState.REFUTED);
console.log("  -> E0 correctly evaluated as REFUTED.");

// 2. Test E1 (Tool observation -> Candidate)
console.log("[Test 2] Testing E1 Tool Observation -> CANDIDATE...");
const hypE1 = {
    hypothesis_id: 'HYP-E1',
    title: 'Lint Warning',
    claim: 'Unused wire causes potential logic fault',
    affected_assets: ['core.v']
};
const fE1 = createFinding({
    id: 'FIND-E1',
    title: 'Lint Warning',
    source_tool: 'verilator',
    source_locations: [{ path: 'core.v', line: 10 }],
    evidence: [createEvidence({ tool: 'verilator', observation: 'unused wire' })]
});
const resE1 = await verifier.verify([hypE1], [fE1], {});
const sE1 = resE1.verificationSummaries[0];
assert.strictEqual(sE1.level, VerificationLevel.E1_TOOL_OBSERVATION);
assert.strictEqual(sE1.status, VerificationState.CANDIDATE);
console.log("  -> E1 correctly evaluated as CANDIDATE.");

// 3. Test E2 (Reproducible artifact without violation -> Candidate)
console.log("[Test 3] Testing E2 Reproducible Artifact -> CANDIDATE...");
const hypE2 = {
    hypothesis_id: 'HYP-E2',
    title: 'Compiled Model Target',
    claim: 'Model has logic discrepancy',
    affected_assets: ['core.v']
};
const fE2 = createFinding({
    id: 'FIND-E2',
    title: 'Model Object Generated',
    source_tool: 'verilator',
    has_reproducible_artifact: true,
    source_locations: [{ path: 'core.v', line: 10 }],
    evidence: [createEvidence({
        tool: 'verilator',
        evidence_type: 'REPRODUCIBLE_ARTIFACT',
        artifact_path: artifactFile,
        observation: 'Object file produced on disk'
    })]
});
const resE2 = await verifier.verify([hypE2], [fE2], {});
const sE2 = resE2.verificationSummaries[0];
assert.strictEqual(sE2.level, VerificationLevel.E2_REPRODUCIBLE_ARTIFACT);
assert.strictEqual(sE2.status, VerificationState.CANDIDATE);
console.log("  -> E2 correctly evaluated as CANDIDATE with artifact.");

// 4. Test E3 (Semantic match / concrete reproduction -> Verified)
console.log("[Test 4] Testing E3 Semantic Match -> VERIFIED...");
const hypE3 = {
    hypothesis_id: 'HYP-E3',
    title: 'Assert Failure',
    claim: 'Assertion violation occurs during BMC',
    affected_assets: ['core.v']
};
const fE3 = createFinding({
    id: 'FIND-E3',
    title: 'Assertion Violated',
    source_tool: 'symbiyosys',
    source_locations: [{ path: 'core.v', line: 15 }],
    evidence: [createEvidence({
        tool: 'symbiyosys',
        artifact_path: crashFile,
        observation: 'Assert failed in top: violation at step 4'
    })]
});
const resE3 = await verifier.verify([hypE3], [fE3], {});
const sE3 = resE3.verificationSummaries[0];
assert.strictEqual(sE3.level, VerificationLevel.E3_SEMANTIC_MATCH);
assert.strictEqual(sE3.status, VerificationState.VERIFIED);
console.log("  -> E3 correctly evaluated as VERIFIED (semantic reproduction).");

// 5. Test E4 (Security relevance -> Verified security issue)
console.log("[Test 5] Testing E4 Security Relevance -> VERIFIED (Level E4)...");
const hypE4 = {
    hypothesis_id: 'HYP-E4',
    title: 'Security Boundary Breach',
    claim: 'Memory write bypasses privilege check',
    affected_assets: ['core.v'],
    security_boundary: 'Kernel Memory Boundary',
    security_property: 'SECURITY_BOUNDARY'
};
const resE4 = await verifier.verify([hypE4], [fE3], {});
const sE4 = resE4.verificationSummaries[0];
assert.strictEqual(sE4.level, VerificationLevel.E4_SECURITY_RELEVANCE);
assert.strictEqual(sE4.status, VerificationState.VERIFIED);
console.log("  -> E4 correctly evaluated as VERIFIED (security boundary relevance).");

// 6. Test E5 (Attacker reachability -> High confidence exploitable issue)
console.log("[Test 6] Testing E5 Attacker Reachability -> VERIFIED (Level E5)...");
const fE5 = createFinding({
    id: 'FIND-E5',
    title: 'Exploitable Buffer Injection',
    source_tool: 'joern',
    dataflow_reachable: true,
    source_locations: [{ path: 'core.v', line: 15 }],
    evidence: [createEvidence({
        tool: 'joern',
        artifact_path: crashFile,
        raw_evidence: { dataflow_reachable: true },
        observation: 'Source to sink dataflow path proven'
    })]
});
const resE5 = await verifier.verify([hypE4], [fE5], {});
const sE5 = resE5.verificationSummaries[0];
assert.strictEqual(sE5.level, VerificationLevel.E5_ATTACKER_REACHABILITY);
assert.strictEqual(sE5.status, VerificationState.VERIFIED);
assert.strictEqual(sE5.confidence, 0.99);
console.log("  -> E5 correctly evaluated as VERIFIED (attacker reachability verified).");

console.log("\n[PASS] All E0–E5 Layered Verifier tests passed successfully!\n");
