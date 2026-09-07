import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { Database } from '../../../src/core/db.js';
import { LLMGateway } from '../../../src/core/llm/gateway.js';

export async function runSuite() {
    const ctx = new AuditContext('LLM Gateway Telemetry & Audit Persistence Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-gateway-audit-');
    const dbPath = path.join(tempDir, 'test_telemetry.sqlite');
    const db = new Database(dbPath);

    const gateway = new LLMGateway({}, db, 'planner');

    // Attempt to log audit telemetry
    const telemetryRecord = {
        timestamp: new Date().toISOString(),
        provider: 'mock-provider',
        model: 'mock-model',
        taskType: 'security_planning',
        analysisId: 'AUDIT-RUN-TEST-001',
        promptTokens: 100,
        completionTokens: 50,
        totalTokens: 150,
        estimatedCostUsd: 0.002,
        latencyMs: 350
    };

    gateway._logAudit(telemetryRecord);

    // Query SQLite audit_events table directly to see if it persisted
    const rows = db.db.prepare(`SELECT * FROM audit_events WHERE run_id = ? OR event_type = ?`).all('AUDIT-RUN-TEST-001', 'LLM_GATEWAY');
    const persisted = rows.length > 0;

    ctx.recordResult({
        testName: 'LLM Gateway: Audit Telemetry Persisted to SQLite Without Swallowed Errors',
        category: 'DATABASE_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: persisted,
        expected: 'Audit record successfully inserted into SQLite audit_events table',
        actual: persisted ? `Successfully saved ${rows.length} row(s)` : 'VULNERABLE: Record missing from SQLite (schema mismatch swallowed in catch block)',
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    db.close();
    ctx.cleanup();
    return ctx.getSummary();
}
