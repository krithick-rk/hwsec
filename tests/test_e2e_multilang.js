import assert from 'assert';
import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';
import { Database } from '../src/core/db.js';

console.log("=== Running End-to-End Multi-Language Analysis Smoke Test ===");

const cliPath = path.resolve('src/index.js');
const targetProjectDir = path.resolve('tests/fixtures/multilang_project');
const testOutputDir = path.resolve('hwsec-e2e-multilang-output');

// Clean up previous runs if any
if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

// 1. Run 'analyze' on multi-language target (C, Python, Verilog)
console.log("[Test 1] Running 'hwsec analyze' on multi-language repository...");
const analyzeRes = spawnSync(process.execPath, [
    cliPath, 'analyze', targetProjectDir,
    '--output-dir', testOutputDir,
    '--novelty', 'off'
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(analyzeRes.status, 0, `analyze failed with stderr: ${analyzeRes.stderr}`);
const match = analyzeRes.stdout.match(/Analysis ID:\s+([a-f0-9-]+)/i);
assert(match && match[1], "Must output an Analysis ID");
const analysisId = match[1].trim();
console.log(`  -> Analysis ID: ${analysisId}`);

const runDir = path.join(testOutputDir, analysisId);
const analysisJsonPath = path.join(runDir, 'analysis.json');
const planMdPath = path.join(runDir, 'plan.md');

assert(fs.existsSync(analysisJsonPath), "analysis.json must exist");
assert(fs.existsSync(planMdPath), "plan.md must exist");

const analysisData = JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8'));
assert.strictEqual(analysisData.status, 'PLANNED', "Initial status must be PLANNED");
assert.strictEqual(analysisData.execution_started, false, "Execution must not be started");

// Verify multi-language discovery
const languages = analysisData.inventory.languages;
assert(languages.c && languages.c.length > 0, "C files must be detected");
assert(languages.python && languages.python.length > 0, "Python files must be detected");
assert(languages.verilog && languages.verilog.length > 0, "Verilog files must be detected");
console.log(`  -> Detected languages: ${Object.keys(languages).join(', ')}`);
console.log("  -> Multi-language planning passed.");

// 2. Run 'proceed' to execute pipeline
console.log("[Test 2] Running 'hwsec proceed' to execute multi-language pipeline...");
const proceedRes = spawnSync(process.execPath, [
    cliPath, 'proceed', analysisId,
    '--output-dir', testOutputDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(proceedRes.status, 0, `proceed failed with stderr: ${proceedRes.stderr}`);
console.log(proceedRes.stdout.split('\n').filter(l => l.includes('->') || l.includes('[+]')).join('\n'));

// 3. Validate completed analysis artifacts
console.log("[Test 3] Validating artifacts and final report...");
const completedAnalysis = JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8'));
assert.strictEqual(completedAnalysis.status, 'COMPLETED', "Status must transition to COMPLETED");
assert.strictEqual(completedAnalysis.execution_started, true, "Execution flag must be true");

const finalReportPath = path.join(runDir, 'report', 'final.md');
assert(fs.existsSync(finalReportPath), "report/final.md must exist");
const reportContent = fs.readFileSync(finalReportPath, 'utf-8');
assert(reportContent.includes('# HWSEC Security Analysis Final Report'), "Report must have valid header");
assert(reportContent.includes('Total Files Scanned'), "Report must have executive summary");

const statusMdPath = path.join(runDir, 'status.md');
assert(fs.existsSync(statusMdPath), "status.md must exist");
const statusContent = fs.readFileSync(statusMdPath, 'utf-8');
assert(statusContent.includes('COMPLETED'), "status.md must reflect COMPLETED");

const verifiedFindingsPath = path.join(runDir, 'findings', 'verified_findings.json');
const candidateFindingsPath = path.join(runDir, 'findings', 'candidate_findings.json');
assert(fs.existsSync(verifiedFindingsPath), "verified_findings.json must exist");
assert(fs.existsSync(candidateFindingsPath), "candidate_findings.json must exist");

const verifiedFindings = JSON.parse(fs.readFileSync(verifiedFindingsPath, 'utf-8'));
const candidateFindings = JSON.parse(fs.readFileSync(candidateFindingsPath, 'utf-8'));
const totalFindings = verifiedFindings.length + candidateFindings.length;
console.log(`  -> Findings generated: ${verifiedFindings.length} verified, ${candidateFindings.length} candidate (Total: ${totalFindings})`);
assert(totalFindings > 0, "Multi-language project must yield at least one finding (Semgrep / Joern / SymbiYosys)");
console.log("  -> Artifact and report validation passed.");

// 4. Validate SQLite Persistence
console.log("[Test 4] Validating SQLite database persistence...");
const dbPath = path.join(testOutputDir, 'hwsec.db');
assert(fs.existsSync(dbPath), "hwsec.db must exist in output directory");

const db = new Database(dbPath);
const runRow = db.db.prepare(`SELECT * FROM analysis_runs WHERE id = ?`).get(analysisId);
assert(runRow, "Analysis run record must exist in DB");
assert.strictEqual(runRow.status, 'COMPLETED', "DB status must be COMPLETED");

const filesInDb = db.db.prepare(`SELECT path, language FROM files WHERE run_id = ?`).all(analysisId);
assert(filesInDb.length >= 3, "All 3 target files must be recorded in DB");
console.log(`  -> Files recorded in DB: ${filesInDb.map(f => `${path.basename(f.path)} (${f.language})`).join(', ')}`);

const toolRuns = db.db.prepare(`SELECT tool_name, capability, status FROM tool_runs WHERE run_id = ?`).all(analysisId);
console.log(`  -> Tool runs recorded in DB (${toolRuns.length}): ${toolRuns.map(t => t.tool_name).join(', ')}`);

const findingsInDb = db.db.prepare(`SELECT id, title, severity, verification_state FROM findings WHERE run_id = ?`).all(analysisId);
console.log(`  -> Findings recorded in DB: ${findingsInDb.length}`);

db.close();
console.log("  -> SQLite persistence passed.");

// 5. Clean up test directory
if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

console.log("\n>>> END-TO-END MULTI-LANGUAGE SMOKE TEST PASSED! <<<\n");
