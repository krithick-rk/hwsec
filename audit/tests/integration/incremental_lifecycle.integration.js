import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { Database } from '../../../src/core/db.js';

export async function runSuite() {
    const ctx = new AuditContext('Incremental Analysis Lifecycle & Stale Data Invalidation Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-inc-audit-');
    const dbPath = path.join(tempDir, 'incremental_lifecycle.sqlite');
    const db = new Database(dbPath);

    const fileA = path.join(tempDir, 'module_a.c');
    const fileB = path.join(tempDir, 'module_b.c');

    fs.writeFileSync(fileA, 'int funcA() { return 1; }\n', 'utf-8');
    fs.writeFileSync(fileB, 'int funcB() { return 2; }\n', 'utf-8');

    // Run 1: Initial Run
    const run1Id = 'RUN-01-INITIAL';
    db.saveAnalysisRun({ id: run1Id, status: 'RUNNING' });
    const hashA1 = Database.computeFileHash(fileA);
    const hashB1 = Database.computeFileHash(fileB);

    db.saveFile({ id: 'F1', runId: run1Id, path: fileA, language: 'c', sha256Hash: hashA1 });
    db.saveFile({ id: 'F2', runId: run1Id, path: fileB, language: 'c', sha256Hash: hashB1 });
    db.saveFinding({ id: 'FIND-A1', runId: run1Id, title: 'Issue in A', type: 'STATIC', severity: 'MEDIUM', verificationState: 'CANDIDATE', location: fileA });
    db.saveFinding({ id: 'FIND-B1', runId: run1Id, title: 'Issue in B', type: 'STATIC', severity: 'LOW', verificationState: 'CANDIDATE', location: fileB });

    // Run 2: Unchanged Files -> Must detect reuse
    const run2Id = 'RUN-02-UNCHANGED';
    const incA2 = db.checkIncrementalReuse(fileA, hashA1);
    const incB2 = db.checkIncrementalReuse(fileB, hashB1);

    const reusableDetected = incA2.reusable && incB2.reusable;
    ctx.recordResult({
        testName: 'Incremental Lifecycle: Unchanged File Reuse Detection',
        category: 'INCREMENTAL_ANALYSIS',
        tier: TestTier.INTEGRATION_TEST,
        passed: reusableDetected,
        expected: 'checkIncrementalReuse returns reusable: true for unchanged hash',
        actual: `A reusable: ${incA2.reusable}, B reusable: ${incB2.reusable}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // Run 3: Modify File A
    fs.writeFileSync(fileA, 'int funcA() { return 999; /* modified */ }\n', 'utf-8');
    const hashA3 = Database.computeFileHash(fileA);
    const incA3 = db.checkIncrementalReuse(fileA, hashA3);
    const incB3 = db.checkIncrementalReuse(fileB, hashB1);

    const modificationDetected = !incA3.reusable && incB3.reusable;
    ctx.recordResult({
        testName: 'Incremental Lifecycle: Selective Re-Analysis on Modified File',
        category: 'INCREMENTAL_ANALYSIS',
        tier: TestTier.INTEGRATION_TEST,
        passed: modificationDetected,
        expected: 'Modified file A marked reusable: false; untouched file B marked reusable: true',
        actual: `A reusable: ${incA3.reusable}, B reusable: ${incB3.reusable}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // Run 4: Invalidate Stale Findings upon File Deletion
    fs.unlinkSync(fileB);
    // Method to prune stale findings for files no longer present
    let stalePruned = false;
    if (typeof db.pruneStaleFiles === 'function') {
        db.pruneStaleFiles([fileA]); // Only fileA exists now
        const findingsB = db.db.prepare(`SELECT * FROM findings WHERE location = ?`).all(fileB);
        stalePruned = findingsB.length === 0;
    }

    ctx.recordResult({
        testName: 'Incremental Lifecycle: Stale Finding Invalidation on File Deletion',
        category: 'INCREMENTAL_ANALYSIS',
        tier: TestTier.INTEGRATION_TEST,
        passed: stalePruned,
        expected: 'Deleted file findings are pruned or marked stale in database',
        actual: stalePruned ? 'Stale records successfully pruned' : 'NOT IMPLEMENTED / Stale records persist indefinitely',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    db.close();
    ctx.cleanup();
    return ctx.getSummary();
}
