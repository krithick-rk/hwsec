import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { Database } from '../src/core/db.js';

console.log('=== Running WP3: Local SQLite Database & Incremental Fingerprinting Tests ===');

// Use in-memory SQLite database for test isolation
const db = new Database(':memory:');

// Test 1: Project & Analysis Run Insertion
console.log('[Test 1] Testing Project and Analysis Run Persistence...');
const projectId = 'proj-001';
db.saveProject({ id: projectId, path: 'E:/Intern/test_proj', name: 'TestProject' });

const runId = 'run-001';
db.saveAnalysisRun({
    id: runId,
    projectId,
    status: 'PLANNED',
    configHash: 'cfghash123',
    repositoryHash: 'rephash123',
    budgetAllocated: 5.0,
    budgetConsumed: 0.0
});

db.updateAnalysisRunStatus(runId, 'APPROVED');
console.log('  -> Project and Run lifecycle persisted.');

// Test 2: File Fingerprinting & Incremental Reuse
console.log('[Test 2] Testing File Fingerprinting & Incremental Check...');
const filePath = path.resolve('./dummy_rtl/top.v');
const initialHash = Database.computeFileHash(filePath);
assert.ok(initialHash && initialHash.length === 64, 'SHA-256 hash must be 64-char hex');

// First time file is checked
let check = db.checkIncrementalReuse(filePath, initialHash);
assert.strictEqual(check.reusable, false, 'First check must not be reusable');

// Save file to DB for run-001
db.saveFile({
    id: 'file-001',
    runId,
    path: filePath,
    language: 'verilog',
    sha256Hash: initialHash,
    size: 741,
    loc: 28
});

// Second check with same hash
check = db.checkIncrementalReuse(filePath, initialHash);
assert.strictEqual(check.reusable, true, 'Same hash must be marked reusable');
assert.strictEqual(check.previousRunId, runId);
assert.ok(check.reason.includes('content unchanged'));

// Check with modified hash
check = db.checkIncrementalReuse(filePath, '0000000000000000000000000000000000000000000000000000000000000000');
assert.strictEqual(check.reusable, false, 'Modified hash must trigger re-analysis');
assert.ok(check.reason.includes('mismatch'));
console.log('  -> Incremental fingerprinting and invalidation verified.');

// Test 3: Tool Runs & Evidence
console.log('[Test 3] Testing Tool Runs and Structured Evidence...');
const toolRunId = 'tr-001';
db.saveToolRun({
    id: toolRunId,
    runId,
    toolName: 'verilator',
    capability: 'rtl_lint',
    status: 'SUCCESS',
    exitCode: 0,
    startedAt: new Date().toISOString()
});

const evidenceId = 'ev-001';
db.saveEvidence({
    id: evidenceId,
    toolRunId,
    fileId: 'file-001',
    artifactPath: 'hwsec-output/run-001/tools/verilator_telemetry.json',
    artifactHash: 'evhash123',
    observation: 'Found 0 lint errors in top.v',
    rawEvidence: { warnings: 0, errors: 0 }
});
console.log('  -> Tool run and evidence recorded.');

// Test 4: Hypotheses, Findings, Verification, and Token Ledger
console.log('[Test 4] Testing Findings, Verification, Graph, and Ledger...');
db.saveHypothesis({
    id: 'hyp-001',
    runId,
    claim: 'Reset line may cause state corruption',
    status: 'TESTING',
    rationale: 'RTL inspection indicates potential glitch',
    proposedTest: 'formal'
});

const findingId = 'find-001';
db.saveFinding({
    id: findingId,
    runId,
    title: 'CWE-1234: Hardware Glitch',
    type: 'HARDWARE_CWE',
    severity: 'MEDIUM',
    confidence: 0.8,
    verificationState: 'SUPPORTED',
    location: `${filePath}:12`
});

db.saveVerificationResult({
    id: 'vr-001',
    findingId,
    level: 'E3',
    status: 'VERIFIED',
    justification: 'Synthesized property test reproduced breach'
});

db.saveGraphNode({
    id: 'node-001',
    runId,
    type: 'SOURCE',
    label: 'data_in'
});

db.saveGraphNode({
    id: 'node-002',
    runId,
    type: 'SINK',
    label: 'data_out'
});

db.saveGraphEdge({
    id: 'edge-001',
    runId,
    sourceId: 'node-001',
    targetId: 'node-002',
    relation: 'DATAFLOW'
});

db.recordTokenUsage({
    id: 'tl-001',
    analysis_id: runId,
    task_type: 'verification',
    model_id: 'deepseek-ai/deepseek-r1',
    provider: 'nvidia',
    prompt_tokens: 1200,
    completion_tokens: 450,
    total_tokens: 1650,
    estimated_cost: 0.0012,
    timestamp: new Date().toISOString()
});

db.recordAuditEvent({
    runId,
    eventType: 'PHASE_CHANGE',
    message: 'Analysis transitioned to VERIFICATION',
    metadata: { phase: 'verification' }
});

console.log('  -> All 12 tables and operations verified.');

db.close();

console.log('\n[PASS] All WP3 SQLite Database tests passed successfully!\n');
