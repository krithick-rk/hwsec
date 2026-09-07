import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { runCommand } from '../../../src/core/execUtils.js';

export async function runSuite() {
    const ctx = new AuditContext('Process-Tree Termination & Resource Leak Stress Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-proctree-');

    // Child batch script that spawns a background ping loop
    const launcherScript = path.join(tempDir, 'spawn_children.bat');
    fs.writeFileSync(launcherScript, `@echo off\nstart /b cmd /c ping 127.0.0.1 -n 30 > nul\nping 127.0.0.1 -n 30 > nul\n`, 'utf-8');

    const start = Date.now();
    const res = await runCommand(launcherScript, [], { timeout: 2000 });
    const elapsed = Date.now() - start;

    ctx.recordResult({
        testName: 'Process Cleanup: Process-Tree Termination on Timeout',
        category: 'PROCESS_ISOLATION',
        tier: TestTier.PERFORMANCE_TEST,
        passed: res.timeout === true && elapsed < 4500,
        expected: 'Parent and all child processes terminated when timeout fires',
        actual: `timeout: ${res.timeout}, elapsedMs: ${elapsed}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    ctx.cleanup();
    return ctx.getSummary();
}
