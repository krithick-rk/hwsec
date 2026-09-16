import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { ConsoleApp } from '../src/core/console/consoleApp.js';
import { SessionPhase } from '../src/core/console/consoleSession.js';

console.log("=== Running Interactive Console Workflow & State Invariants Test ===");

const fixturesDir = path.resolve('tests/fixtures');
const testOutputDir = path.resolve('hwsec-output/test-console-workflow');

if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

const app = new ConsoleApp({
    outputDir: testOutputDir,
    skipOnboarding: true
});

// 1. Configure options
console.log("[Test 1] Setting configuration options...");
await app.executeCommand(`set target "${fixturesDir}"`);
await app.executeCommand('set mode STANDARD');
await app.executeCommand('set llm ADAPTIVE');
await app.executeCommand('set pov ON-DETECTED');
await app.executeCommand('set approval REQUIRED');
await app.executeCommand('set budget 20');

assert.strictEqual(app.session.targetDir, fixturesDir);
assert.strictEqual(app.session.mode, 'STANDARD');
assert.strictEqual(app.session.approvalPolicy, 'REQUIRED');
assert.strictEqual(app.session.budget, 20);

// 2. Planning phase ('run')
console.log("[Test 2] Executing 'run' command (planning)...");
await app.executeCommand('run');

assert.strictEqual(app.session.status, SessionPhase.PLANNED, "Session phase must be PLANNED after run");
assert(app.session.analysisId, "Must have an analysisId assigned");
assert(app.workspace, "Workspace must be initialized");

const analysisPath = path.join(app.workspace.outputDir, 'analysis.json');
assert(fs.existsSync(analysisPath), "analysis.json must be written");
const analysis = JSON.parse(fs.readFileSync(analysisPath, 'utf-8'));
assert.strictEqual(analysis.status, 'PLANNED', "Authoritative analysis state must be PLANNED");

// 3. Inspection of planned state
console.log("[Test 3] Inspecting planned state...");
await app.executeCommand('plan');
await app.executeCommand('inspect plan');
await app.executeCommand('inspect target');
await app.executeCommand('status');

// 4. Approval boundary enforcement
console.log("[Test 4] Approval boundary enforcement: proceed before approve must be rejected...");
let proceedRejected = false;
try {
    await app.executeCommand('proceed');
} catch {
    proceedRejected = true;
}
assert.notStrictEqual(app.session.status, SessionPhase.RUNNING, "Must not transition to RUNNING without approval");
assert.notStrictEqual(app.session.status, SessionPhase.COMPLETED, "Must not execute without approval");

// 5. Plan Approval
console.log("[Test 5] Approving plan...");
// Simulate operator answering 'y'
app.ask = async () => 'y';
await app.executeCommand('approve');
assert.strictEqual(app.session.status, SessionPhase.APPROVED, "Session phase must transition to APPROVED");

// 6. Plan Execution ('proceed')
console.log("[Test 6] Executing approved plan ('proceed')...");
await app.executeCommand('proceed');
assert.strictEqual(app.session.status, SessionPhase.COMPLETED, "Session phase must be COMPLETED after proceed");

const updatedAnalysis = JSON.parse(fs.readFileSync(analysisPath, 'utf-8'));
assert.strictEqual(updatedAnalysis.status, 'COMPLETED', "Underlying analysis state must be COMPLETED");
assert(updatedAnalysis.results, "Must contain analysis results");

// 7. Rich Inspection after execution
console.log("[Test 7] Inspecting completed artifacts and state...");
await app.executeCommand('status');
await app.executeCommand('inspect hypothesis');
await app.executeCommand('inspect evidence');
await app.executeCommand('inspect pov');
await app.executeCommand('inspect execution');
await app.executeCommand('inspect llm');
await app.executeCommand('report');
await app.executeCommand('dossier');

// 8. Diagnostics & Doctor checks
console.log("[Test 8] Running diagnostics & doctor checks...");
await app.executeCommand('doctor');
await app.executeCommand('doctor execution');
await app.executeCommand('doctor sandbox');
await app.executeCommand('doctor database');
await app.executeCommand('doctor security');
await app.executeCommand('providers');
await app.executeCommand('modules');

// 9. Sessions and History
console.log("[Test 9] Inspecting session list and command history...");
await app.executeCommand('sessions');
await app.executeCommand('history');

const history = app.sessionManager.getHistory();
assert(history.length >= 5, "Must have recorded multiple commands in history");

// 10. Safe Reset
console.log("[Test 10] Testing safe session reset...");
await app.executeCommand('reset');
assert.strictEqual(app.session.targetDir, null, "Target must be cleared after reset");
assert.strictEqual(app.session.status, SessionPhase.INITIALIZED, "Status must be INITIALIZED after reset");

app.close();

// Cleanup
try {
    if (fs.existsSync(testOutputDir)) {
        fs.rmSync(testOutputDir, { recursive: true, force: true });
    }
} catch {}

console.log("\n>>> ALL CONSOLE WORKFLOW TESTS PASSED! <<<\n");
