import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { LayeredVerifier, VerificationLevel } from '../../../src/workers/verifier.js';
import { createFinding, createEvidence, Severity as FindingSeverity, VerificationState } from '../../../src/core/schema.js';

export async function runSuite() {
    const ctx = new AuditContext('Cross-Domain Evidence Semantic Compatibility Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-cross-domain-');
    const verifier = new LayeredVerifier();

    // Create a real hardware VCD waveform
    const vcdPath = path.join(tempDir, 'hardware_trace.vcd');
    fs.writeFileSync(vcdPath, "$date 2026-09-07 $end\n$version SBY $end\n$timescale 1ns $end\n$scope module counter $end\n$var wire 1 ! clk $end\n$upscope $end\n$enddefinitions $end\n#0\n0!\n#10\n1!\n", 'utf-8');

    // 1. Incompatible Hardware Trace attached to Software Python Finding
    const pythonSoftwareFinding = createFinding({
        id: 'FINDING-PY-001',
        title: 'Python Remote Code Injection via eval()',
        description: 'Unsanitized input passed to eval in server.py',
        severity: FindingSeverity.CRITICAL,
        source_tool: 'semgrep',
        source_locations: [{ path: 'server.py', startLine: 45, endLine: 45 }],
        evidence: [createEvidence({
            id: 'EV-CROSS-001',
            tool_name: 'symbiyosys', // Incompatible tool for Python!
            artifact_path: vcdPath,
            description: 'VCD trace attached to software finding'
        })],
        verification_state: 'PROPOSED'
    });

    const res1 = verifier.verifySingleFinding(pythonSoftwareFinding, [pythonSoftwareFinding]);
    const crossDomainAccepted = res1.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Cross-Domain Integrity: Reject Hardware VCD Trace on Software Finding',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !crossDomainAccepted,
        expected: 'Incompatible domain evidence rejected (must not verify Python finding with Verilog VCD trace)',
        actual: crossDomainAccepted ? 'VULNERABLE: Python finding verified using hardware .vcd trace' : 'Cross-domain evidence rejected',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 2. Incompatible Software Stacktrace attached to Verilog RTL Finding
    const fakeLog = path.join(tempDir, 'python_traceback.log');
    fs.writeFileSync(fakeLog, "Traceback (most recent call last):\n  File 'server.py', line 10, in <module>\nTypeError: unsupported operand\n", 'utf-8');

    const verilogFinding = createFinding({
        id: 'FINDING-V-001',
        title: 'Verilog Invariant Failure: Grant Never Asserted',
        description: 'Arbiter fails grant assertion in arbiter.v',
        severity: FindingSeverity.HIGH,
        source_tool: 'verilator',
        source_locations: [{ path: 'arbiter.v', startLine: 20, endLine: 20 }],
        evidence: [createEvidence({
            id: 'EV-CROSS-002',
            tool_name: 'semgrep',
            artifact_path: fakeLog,
            description: 'Python traceback attached to Verilog finding'
        })],
        verification_state: 'PROPOSED'
    });

    const res2 = verifier.verifySingleFinding(verilogFinding, [verilogFinding]);
    const rtlCrossAccepted = res2.status === VerificationState.VERIFIED;

    ctx.recordResult({
        testName: 'Cross-Domain Integrity: Reject Software Traceback on RTL Finding',
        category: 'EVIDENCE_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !rtlCrossAccepted,
        expected: 'Software traceback cannot verify hardware invariant finding',
        actual: rtlCrossAccepted ? 'VULNERABLE: RTL finding verified using Python traceback' : 'Rejected cleanly',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
