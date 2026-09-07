import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { Planner } from '../src/core/planner.js';
import { Workspace } from '../src/core/workspace.js';
import { AnalysisStatus, isValidTransition, assertTransition } from '../src/core/state.js';

console.log('=== Running WP1: Planning Gate & State Transition Tests ===');

// Test 1: State Machine Transitions
console.log('[Test 1] Testing State Transition Rules...');
assert.strictEqual(isValidTransition(AnalysisStatus.CREATED, AnalysisStatus.PLANNING), true);
assert.strictEqual(isValidTransition(AnalysisStatus.PLANNING, AnalysisStatus.PLANNED), true);
assert.strictEqual(isValidTransition(AnalysisStatus.PLANNED, AnalysisStatus.APPROVED), true);
assert.strictEqual(isValidTransition(AnalysisStatus.APPROVED, AnalysisStatus.RUNNING), true);
assert.strictEqual(isValidTransition(AnalysisStatus.RUNNING, AnalysisStatus.COMPLETED), true);

// Invalid Transitions
assert.strictEqual(isValidTransition(AnalysisStatus.PLANNED, AnalysisStatus.RUNNING), false); // Must go through APPROVED
assert.strictEqual(isValidTransition(AnalysisStatus.PLANNED, AnalysisStatus.COMPLETED), false);
assert.strictEqual(isValidTransition(AnalysisStatus.COMPLETED, AnalysisStatus.APPROVED), false); // Cannot proceed twice
assert.strictEqual(isValidTransition(AnalysisStatus.RUNNING, AnalysisStatus.APPROVED), false);

assert.throws(() => {
    assertTransition(AnalysisStatus.COMPLETED, AnalysisStatus.APPROVED, 'proceed');
}, /Illegal state transition/);

console.log('  -> State transition logic passed.');

// Test 2: Planner execution does not run expensive tools or call LLM
console.log('[Test 2] Testing Planner isolation (No LLM, No Expensive Analysis)...');
const testWs = new Workspace('hwsec-output');
const planner = new Planner('./dummy_rtl', {}, null, 'standard');

const startTime = Date.now();
const planRes = await planner.plan(testWs);
const durationMs = Date.now() - startTime;

assert.strictEqual(planRes.status, AnalysisStatus.PLANNED);
assert.strictEqual(planRes.approval_required, true);
assert.strictEqual(planRes.execution_started, false);
assert.ok(planRes.inventory.total_files > 0);
assert.ok(Array.isArray(planRes.execution_graph));
assert.ok(planRes.budget_estimate.estimated_tokens > 0);

// Verify artifacts were created on disk
const analysisJson = testWs.loadJson('analysis.json');
assert.strictEqual(analysisJson.status, 'PLANNED');
assert.strictEqual(analysisJson.approval_required, true);
assert.strictEqual(analysisJson.execution_started, false);

const planMdPath = path.join(testWs.outputDir, 'plan.md');
assert.ok(fs.existsSync(planMdPath));
const planMdContent = fs.readFileSync(planMdPath, 'utf-8');
assert.ok(planMdContent.includes('ANALYSIS HAS NOT STARTED'));
assert.ok(planMdContent.includes('WAITING FOR APPROVAL'));
assert.ok(planMdContent.includes(testWs.analysisId));

// Ensure no finding or hypothesis files were created yet
const hypothesesPath = path.join(testWs.outputDir, 'hypotheses', 'hypotheses.json');
assert.strictEqual(fs.existsSync(hypothesesPath), false, 'Hypotheses must NOT be generated during planning');

const findingsPath = path.join(testWs.outputDir, 'findings', 'linting.json');
assert.strictEqual(fs.existsSync(findingsPath), false, 'Tool execution must NOT run during planning');

console.log(`  -> Planning completed cleanly in ${durationMs}ms with human approval gate intact.`);

// Test 3: Rejection of invalid directory
console.log('[Test 3] Testing non-existent directory rejection...');
const badPlanner = new Planner('./non_existent_dir_12345', {});
await assert.rejects(async () => {
    await badPlanner.plan(new Workspace('hwsec-output'));
}, /not found/);
console.log('  -> Non-existent directory cleanly rejected.');

console.log('\n[PASS] All WP1 Planning Gate tests passed successfully!\n');
