import assert from 'assert';
import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

console.log("=== Running Comprehensive CLI Commands End-to-End Test ===");

const cliPath = path.resolve('src/index.js');
const testOutputDir = path.resolve('hwsec-cli-test-output');
const fixturesDir = path.resolve('tests/fixtures');

// Clean up any existing test output
if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

// 1. Test 'analyze' command
console.log("[Test 1] Testing 'analyze' command with approval boundary...");
const analyzeRes = spawnSync(process.execPath, [
    cliPath, 'analyze', fixturesDir,
    '--output-dir', testOutputDir,
    '--novelty', 'off'
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(analyzeRes.status, 0, `analyze should exit with 0. Stderr: ${analyzeRes.stderr}`);
const match = analyzeRes.stdout.match(/Analysis ID:\s+([a-f0-9-]+)/i);
assert(match && match[1], "Must output an Analysis ID");
const analysisId = match[1].trim();
console.log(`  -> Planned Analysis ID: ${analysisId}`);

const runDir = path.join(testOutputDir, analysisId);
assert(fs.existsSync(runDir), "Run workspace directory must exist");
const analysisJsonPath = path.join(runDir, 'analysis.json');
assert(fs.existsSync(analysisJsonPath), "analysis.json must exist");
const planMdPath = path.join(runDir, 'plan.md');
assert(fs.existsSync(planMdPath), "plan.md must exist");

const analysisData = JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8'));
assert.strictEqual(analysisData.status, 'PLANNED', "Analysis must be in PLANNED status");
assert.strictEqual(analysisData.execution_started, false, "Execution must not have started before approval");
assert.strictEqual(analysisData.approval_required, true, "Approval must be required");
console.log("  -> 'analyze' command passed.");

// 2. Test 'status' command on planned analysis
console.log("[Test 2] Testing 'status' command on PLANNED run...");
const statusRes = spawnSync(process.execPath, [
    cliPath, 'status', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(statusRes.status, 0, `status should exit with 0. Stderr: ${statusRes.stderr}`);
assert(statusRes.stdout.includes('PLANNED'), "Status output must display PLANNED");
console.log("  -> 'status' command on PLANNED passed.");

// 3. Test 'proceed' command
console.log("[Test 3] Testing 'proceed' command to approve and execute analysis...");
const proceedRes = spawnSync(process.execPath, [
    cliPath, 'proceed', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(proceedRes.status, 0, `proceed should exit with 0. Stderr: ${proceedRes.stderr}`);
assert(proceedRes.stdout.includes('COMPLETED'), "Proceed output must indicate COMPLETED status");

// Verify artifacts generated
const updatedAnalysis = JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8'));
assert.strictEqual(updatedAnalysis.status, 'COMPLETED', "Analysis status must be COMPLETED");
assert.strictEqual(updatedAnalysis.execution_started, true, "Execution must have started");

const reportPath = path.join(runDir, 'report', 'final.md');
assert(fs.existsSync(reportPath), "Final report markdown must be generated");

const verifiedPath = path.join(runDir, 'findings', 'verified_findings.json');
const candidatePath = path.join(runDir, 'findings', 'candidate_findings.json');
assert(fs.existsSync(verifiedPath), "verified_findings.json must exist");
assert(fs.existsSync(candidatePath), "candidate_findings.json must exist");
console.log("  -> 'proceed' execution passed.");

// 4. Test 'status' command on completed analysis
console.log("[Test 4] Testing 'status' command on COMPLETED run...");
const statusCompRes = spawnSync(process.execPath, [
    cliPath, 'status', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(statusCompRes.status, 0, `status should exit with 0. Stderr: ${statusCompRes.stderr}`);
assert(statusCompRes.stdout.includes('COMPLETED'), "Status output must display COMPLETED");
console.log("  -> 'status' on COMPLETED passed.");

// 5. Test 'findings' command
console.log("[Test 5] Testing 'findings' command...");
const findingsRes = spawnSync(process.execPath, [
    cliPath, 'findings', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(findingsRes.status, 0, `findings should exit with 0. Stderr: ${findingsRes.stderr}`);
assert(findingsRes.stdout.includes('HWSEC Findings for'), "Findings output must display heading");
console.log("  -> 'findings' command passed.");

// 6. Test 'report' command
console.log("[Test 6] Testing 'report' command...");
const reportRes = spawnSync(process.execPath, [
    cliPath, 'report', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(reportRes.status, 0, `report should exit with 0. Stderr: ${reportRes.stderr}`);
assert(reportRes.stdout.includes('HWSEC Security Analysis Final Report'), "Report must output markdown report");
console.log("  -> 'report' command passed.");

// 7. Test 'verify' command
console.log("[Test 7] Testing 'verify' command on a finding...");
const candidates = JSON.parse(fs.readFileSync(candidatePath, 'utf-8'));
const verified = JSON.parse(fs.readFileSync(verifiedPath, 'utf-8'));
const sampleFinding = verified[0] || candidates[0];

if (sampleFinding) {
    const verifyRes = spawnSync(process.execPath, [
        cliPath, 'verify', sampleFinding.id,
        '--output-dir', testOutputDir
    ], { encoding: 'utf-8', env: process.env });

    assert.strictEqual(verifyRes.status, 0, `verify should exit with 0. Stderr: ${verifyRes.stderr}`);
    assert(verifyRes.stdout.includes(sampleFinding.id), "Verify command must output finding details");
    console.log(`  -> 'verify' on finding ${sampleFinding.id} passed.`);
} else {
    console.log("  -> No findings to verify, skipping lookup.");
}

// 8. Test 'reset' command (soft reset)
console.log("[Test 8] Testing 'reset' command (soft reset without deleting files)...");
const resetRes = spawnSync(process.execPath, [
    cliPath, 'reset', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(resetRes.status, 0, `reset should exit with 0. Stderr: ${resetRes.stderr}`);
const resetAnalysis = JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8'));
assert.strictEqual(resetAnalysis.status, 'PLANNED', "Analysis must be reset to PLANNED");
assert.strictEqual(resetAnalysis.execution_started, false, "Execution flag must be false");
console.log("  -> 'reset' soft reset passed.");

// 9. Test 'reset' command with --delete-files
console.log("[Test 9] Testing 'reset' command with --delete-files...");
const resetDelRes = spawnSync(process.execPath, [
    cliPath, 'reset', analysisId,
    '--output-dir', testOutputDir,
    '--delete-files'
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(resetDelRes.status, 0, `reset --delete-files should exit with 0. Stderr: ${resetDelRes.stderr}`);
assert(!fs.existsSync(runDir), "Workspace directory must be deleted");
console.log("  -> 'reset --delete-files' passed.");

// Clean up test output directory
if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

console.log("\n>>> ALL CLI COMMAND TESTS PASSED SUCCESSFULLY! <<<\n");
