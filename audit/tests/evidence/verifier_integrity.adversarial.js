import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { LayeredVerifier, VerificationLevel } from '../../../src/workers/verifier.js';
import { createFinding, createEvidence, Severity as FindingSeverity, VerificationState } from '../../../src/core/schema.js';

export async function runSuite() {
    const ctx = new AuditContext('LayeredVerifier Evidence-Integrity & Substring-Bypass Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-verif-audit-');
    const verifier = new LayeredVerifier();

    // 1. Adversarial Test: Benign zero-crash telemetry artifact
    // Telemetry says: {"crashes": 0, "message": "No crash found"}
    const benignZeroCrashesPath = path.join(tempDir, 'benign_zero_crashes.json');
    fs.writeFileSync(benignZeroCrashesPath, JSON.stringify({
        crashes: 0,
        message: "No crash found during 10 hours of fuzzing"
    }, null, 2), 'utf-8');

    const fakeFinding1 = createFinding({
        id: 'FINDING-FAKE-001',
        title: 'Fabricated Critical Buffer Overflow',
        description: 'Attacker crafted finding pointing to benign zero-crash log',
        severity: FindingSeverity.CRITICAL,
        source_tool: 'afl',
        source_locations: [{ path: 'clean.c', startLine: 10, endLine: 10 }],
        evidence: [createEvidence({
            id: 'EV-001',
            tool_name: 'afl',
            artifact_path: benignZeroCrashesPath,
            description: 'Benign telemetry containing word crash: 0'
        })],
        verification_state: 'PROPOSED',
        dataflow_reachable: true
    });

    const result1 = verifier.verifySingleFinding(fakeFinding1, [fakeFinding1]);
    const falselyPromotedToE5 = result1.level === VerificationLevel.E5_ATTACKER_REACHABILITY || result1.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Verifier: Benign Zero-Crash Telemetry Substring Rejection',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !falselyPromotedToE5,
        expected: 'Level E1/E2 or REFUTED/INCONCLUSIVE (crashes == 0 must NEVER yield E5/VERIFIED)',
        actual: `level: ${result1.level}, status: ${result1.status}, confidence: ${result1.confidence}`,
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED,
        details: falselyPromotedToE5 ? 'CRITICAL: verifier.js substring match promoted "crashes: 0" to Level E5 VERIFIED' : 'Correctly rejected'
    });

    // 2. Adversarial Test: Historical FAIL in passing log
    const passedLogPath = path.join(tempDir, 'passed_with_historical_fail.txt');
    fs.writeFileSync(passedLogPath, "previous run: FAIL (counterexample)\ncurrent run: PASS\nAll tests passed!\n", 'utf-8');

    const fakeFinding2 = createFinding({
        id: 'FINDING-FAKE-002',
        title: 'Fixed Assertion Failure',
        description: 'Log mentions historical FAIL but current run passed',
        severity: FindingSeverity.HIGH,
        source_tool: 'symbiyosys',
        source_locations: [{ path: 'module.v', startLine: 5, endLine: 5 }],
        evidence: [createEvidence({
            id: 'EV-002',
            tool_name: 'symbiyosys',
            artifact_path: passedLogPath,
            description: 'Historical log'
        })],
        verification_state: 'PROPOSED'
    });

    const result2 = verifier.verifySingleFinding(fakeFinding2, [fakeFinding2]);
    const falsePassPromoted = result2.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Verifier: Historical FAIL in Passing Log Rejection',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !falsePassPromoted,
        expected: 'Refusal to verify based on historical FAIL substring when current run passed',
        actual: `status: ${result2.status}, level: ${result2.level}`,
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 3. Adversarial Test: Arbitrary documentation claiming VERIFIED
    const docClaimsPath = path.join(tempDir, 'documentation_claims.md');
    fs.writeFileSync(docClaimsPath, "# Status: VERIFIED\nCounterexample: None. Formally proven.\n", 'utf-8');

    const fakeFinding3 = createFinding({
        id: 'FINDING-FAKE-003',
        title: 'Documentation Claim As Evidence',
        description: 'Attacker pointing to doc markdown file',
        severity: FindingSeverity.MEDIUM,
        source_tool: 'custom',
        source_locations: [{ path: 'doc.md', startLine: 1, endLine: 1 }],
        evidence: [createEvidence({
            id: 'EV-003',
            tool_name: 'custom',
            artifact_path: docClaimsPath,
            description: 'Arbitrary doc claiming verified'
        })],
        verification_state: 'PROPOSED'
    });

    const result3 = verifier.verifySingleFinding(fakeFinding3, [fakeFinding3]);
    const docClaimPromoted = result3.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Verifier: Arbitrary Markdown Documentation Claim Rejection',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !docClaimPromoted,
        expected: 'Unstructured markdown text cannot verify finding',
        actual: `status: ${result3.status}, level: ${result3.level}`,
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 4. Adversarial Test: Global CodeGraph attack-path leak to unrelated finding
    const fakeFindingUnrelated = createFinding({
        id: 'FINDING-UNRELATED',
        title: 'Unrelated Software Buffer Observation',
        description: 'Harmless software finding with no attack path',
        severity: FindingSeverity.LOW,
        source_tool: 'semgrep',
        source_locations: [{ path: 'clean_software.c', startLine: 10, endLine: 10 }],
        evidence: [createEvidence({
            id: 'EV-004',
            tool_name: 'semgrep',
            artifact_path: passedLogPath, // mentions FAIL
            description: 'Observation'
        })],
        verification_state: 'PROPOSED',
        dataflow_reachable: false
    });

    // Mock CodeGraph that has an attack path in HARDWARE top.v
    const mockGraphWithOtherPath = {
        findAttackPaths: () => [{
            path: ['SourceSignal:top.v', 'SinkSignal:top.v'],
            sink: 'SinkSignal:top.v'
        }]
    };
    const verifierWithGraph = new LayeredVerifier(mockGraphWithOtherPath);
    const result4 = verifierWithGraph.verifySingleFinding(fakeFindingUnrelated, [fakeFindingUnrelated]);
    // The unrelated finding in clean_software.c should NOT be marked E5 Attacker Reachable just because top.v has a path!
    const globalGraphLeakedToFinding = result4.level === VerificationLevel.E5_ATTACKER_REACHABILITY;

    ctx.recordResult({
        testName: 'Verifier: Global Attack-Path Reachability Isolation',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !globalGraphLeakedToFinding,
        expected: 'Only findings whose specific locations/variables participate in an attack path get reachability',
        actual: `level: ${result4.level}, justified: ${result4.justification}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
