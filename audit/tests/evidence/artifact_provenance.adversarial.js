import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { LayeredVerifier, VerificationLevel } from '../../../src/workers/verifier.js';
import { createFinding, createEvidence, Severity as FindingSeverity, VerificationState } from '../../../src/core/schema.js';

export async function runSuite() {
    const ctx = new AuditContext('Artifact Cryptographic Provenance & Tamper-Detection Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-prov-audit-');
    const verifier = new LayeredVerifier();

    // Create authentic artifact
    const artifactPath = path.join(tempDir, 'tool_counterexample.vcd');
    const validVcdHeader = "$date 2026-09-07 $end\n$version SBY $end\n$timescale 1ns $end\n$scope module test $end\n$var wire 1 ! clk $end\n$upscope $end\n$enddefinitions $end\n#0\n0!\n#10\n1!\n";
    fs.writeFileSync(artifactPath, validVcdHeader, 'utf-8');
    const validHash = crypto.createHash('sha256').update(fs.readFileSync(artifactPath)).digest('hex');

    // 1. Authentic Artifact with Matching Hash
    const authenticEvidence = createEvidence({
        id: 'EV-AUTH-001',
        tool_name: 'symbiyosys',
        artifact_path: artifactPath,
        artifact_hash: validHash,
        description: 'Authentic bounded model counterexample'
    });
    const authenticFinding = createFinding({
        id: 'FINDING-AUTH-001',
        title: 'Authentic Property Violation',
        description: 'Violation with cryptographically signed hash',
        severity: FindingSeverity.HIGH,
        source_tool: 'symbiyosys',
        evidence: [authenticEvidence],
        verification_state: 'PROPOSED'
    });

    // 2. Tampered Artifact Test (file on disk modified after execution)
    const tamperedArtifactPath = path.join(tempDir, 'tampered_trace.vcd');
    fs.writeFileSync(tamperedArtifactPath, validVcdHeader + "\n// INJECTED ATTACKER BYTES", 'utf-8');

    const tamperedEvidence = createEvidence({
        id: 'EV-TAMP-001',
        tool_name: 'symbiyosys',
        artifact_path: tamperedArtifactPath,
        artifact_hash: validHash, // Stored hash does NOT match actual file on disk!
        description: 'Tampered counterexample trace'
    });
    const tamperedFinding = createFinding({
        id: 'FINDING-TAMP-001',
        title: 'Tampered Property Violation',
        description: 'Artifact was altered after tool recorded hash',
        severity: FindingSeverity.HIGH,
        source_tool: 'symbiyosys',
        evidence: [tamperedEvidence],
        verification_state: 'PROPOSED'
    });

    // Verify how verifier handles tampered artifact
    let tamperedRejected = false;
    try {
        const tampRes = verifier.verifySingleFinding(tamperedFinding, [tamperedFinding]);
        // If hash verification is implemented, status must be REFUTED or INCONCLUSIVE, not VERIFIED
        if (tampRes.status !== VerificationState.VERIFIED) {
            tamperedRejected = true;
        }
    } catch (e) {
        tamperedRejected = true;
    }

    ctx.recordResult({
        testName: 'Artifact Provenance: SHA-256 Hash Tamper Detection',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: tamperedRejected,
        expected: 'Immediate rejection (REFUTED/INCONCLUSIVE) when disk artifact SHA-256 does not match recorded hash',
        actual: tamperedRejected ? 'Tampered artifact successfully rejected' : 'VULNERABLE: Tampered artifact accepted without cryptographic verification',
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 3. Replay from Different Run / Cross-Project Replay Test
    const replayEvidence = createEvidence({
        id: 'EV-REPLAY-001',
        tool_name: 'symbiyosys',
        artifact_path: artifactPath,
        artifact_hash: validHash,
        run_id: 'RUN-DIFFERENT-PROJECT-XYZ', // Belongs to different project
        description: 'Replayed counterexample from Project B'
    });
    const replayFinding = createFinding({
        id: 'FINDING-REPLAY-001',
        run_id: 'RUN-CURRENT-PROJECT-ABC',
        title: 'Cross-Project Replayed Finding',
        description: 'Replay attack across workspace boundaries',
        severity: FindingSeverity.HIGH,
        source_tool: 'symbiyosys',
        evidence: [replayEvidence],
        verification_state: 'PROPOSED'
    });

    let replayRejected = false;
    try {
        const replayRes = verifier.verifySingleFinding(replayFinding, [replayFinding]);
        if (replayRes.status !== VerificationState.VERIFIED) {
            replayRejected = true;
        }
    } catch (e) {
        replayRejected = true;
    }

    ctx.recordResult({
        testName: 'Artifact Provenance: Cross-Project / Cross-Run Replay Defense',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: replayRejected,
        expected: 'Replayed artifact from another analysis or project must be rejected',
        actual: replayRejected ? 'Replay rejected' : 'VULNERABLE: Cross-run artifact replayed without check',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
