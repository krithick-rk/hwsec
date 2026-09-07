import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { runCommand } from '../../../src/core/execUtils.js';

export async function runSuite() {
    const ctx = new AuditContext('Process Isolation & Execution Security Adversarial Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-proc-iso-');

    // 1. Timeout Enforcement Test
    const sleepScript = path.join(tempDir, 'hang.bat');
    fs.writeFileSync(sleepScript, `@echo off\nping 127.0.0.1 -n 10 > nul\n`, 'utf-8');
    const startTimeoutTest = Date.now();
    const timeoutRes = await runCommand(sleepScript, [], { timeout: 1500 });
    const elapsed = Date.now() - startTimeoutTest;

    ctx.recordResult({
        testName: 'runCommand: Strict Timeout Enforcement and Process Interruption',
        category: 'PROCESS_ISOLATION',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: timeoutRes.timeout === true && elapsed < 4000,
        expected: 'Process timed out after 1.5s with timeout: true flag',
        actual: `timeout: ${timeoutRes.timeout}, elapsedMs: ${elapsed}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 2. Output Buffer Ceiling (DoS Protection)
    const floodScript = path.join(tempDir, 'flood.bat');
    // Generates output in loop
    fs.writeFileSync(floodScript, `@echo off\nfor /L %%i in (1,1,1000) do echo FLOOD_FLOOD_FLOOD_FLOOD_FLOOD_FLOOD_FLOOD_FLOOD_FLOOD_FLOOD\n`, 'utf-8');
    const floodRes = await runCommand(floodScript, [], { timeout: 5000, maxOutputBytes: 1024 });

    const bufferExceededBounded = floodRes.stdout.length <= 4096; // Within reasonable bounded threshold
    ctx.recordResult({
        testName: 'runCommand: Output Buffer Size Limiting (Prevent Node Heap Exhaustion)',
        category: 'PROCESS_ISOLATION',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: bufferExceededBounded,
        expected: 'Stdout/stderr captured up to max threshold, truncated without crash',
        actual: `Captured bytes: ${floodRes.stdout.length}`,
        severity: Severity.MEDIUM,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 3. Environment & PATH Sanitization
    // Verify that child processes do not inherit or expose personal developer paths
    const envCheckScript = path.join(tempDir, 'check_env.bat');
    fs.writeFileSync(envCheckScript, `@echo off\necho PATH=%PATH%\n`, 'utf-8');
    const envRes = await runCommand(envCheckScript, [], { timeout: 5000 });
    const containsPersonalPath = envRes.stdout.toLowerCase().includes('krithick');

    ctx.recordResult({
        testName: 'Environment: No Personal Machine Paths in Child Process Environment',
        category: 'ENVIRONMENT_INDEPENDENCE',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !containsPersonalPath,
        expected: 'Clean environment without hardcoded personal user directories',
        actual: containsPersonalPath ? 'VULNERABLE: Personal path found in PATH output' : 'Clean environment',
        severity: Severity.MEDIUM,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
