import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { LayeredVerifier, VerificationLevel } from '../../../src/workers/verifier.js';
import { createFinding, createEvidence, Severity as FindingSeverity, VerificationState } from '../../../src/core/schema.js';

export async function runSuite() {
    const ctx = new AuditContext('Telemetry & Tool Output Poisoning Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-poison-audit-');
    const verifier = new LayeredVerifier();

    // 1. Malformed VCD file masquerading with keyword 'FAIL'
    const malformedVcd = path.join(tempDir, 'corrupt.vcd');
    fs.writeFileSync(malformedVcd, "RANDOM CORRUPT TEXT FAIL CRASH BMC FAILED\nNo VCD header at all\n", 'utf-8');

    const poisonedFinding = createFinding({
        id: 'FINDING-POISON-001',
        title: 'Poisoned Artifact Test',
        description: 'Testing if parser validates real VCD structure',
        severity: FindingSeverity.HIGH,
        source_tool: 'symbiyosys',
        evidence: [createEvidence({
            id: 'EV-P-001',
            tool_name: 'symbiyosys',
            artifact_path: malformedVcd,
            description: 'Corrupted VCD'
        })],
        verification_state: 'PROPOSED'
    });

    const res1 = verifier.verifySingleFinding(poisonedFinding, [poisonedFinding]);
    const malformedPromoted = res1.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Telemetry Poisoning: Malformed VCD Header Validation',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !malformedPromoted,
        expected: 'Malformed .vcd missing $date/$version/$enddefinitions must fail validation',
        actual: malformedPromoted ? 'VULNERABLE: Corrupted text promoted due to FAIL keyword' : 'Rejected correctly',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 2. Corrupt JSON Telemetry File
    const corruptJsonPath = path.join(tempDir, 'corrupt_telemetry.json');
    fs.writeFileSync(corruptJsonPath, "{ crashes: 5, syntax_error_here ", 'utf-8');

    const corruptJsonFinding = createFinding({
        id: 'FINDING-POISON-002',
        title: 'Corrupt JSON Telemetry',
        description: 'Telemetry file is malformed JSON',
        severity: FindingSeverity.MEDIUM,
        source_tool: 'afl',
        evidence: [createEvidence({
            id: 'EV-P-002',
            tool_name: 'afl',
            artifact_path: corruptJsonPath,
            description: 'Corrupt JSON'
        })],
        verification_state: 'PROPOSED'
    });

    let handledCleanly = true;
    try {
        const res2 = verifier.verifySingleFinding(corruptJsonFinding, [corruptJsonFinding]);
        if (res2.status === VerificationState.VERIFIED) {
            handledCleanly = false;
        }
    } catch (e) {
        // Must fail closed without unhandled exception crashing the process
        handledCleanly = false;
    }

    ctx.recordResult({
        testName: 'Telemetry Poisoning: Malformed JSON Telemetry Fail-Closed',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: handledCleanly,
        expected: 'Fail-closed gracefully without promoting finding or crashing',
        actual: handledCleanly ? 'Handled cleanly' : 'Failed or crashed',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
