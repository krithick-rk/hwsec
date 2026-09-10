import assert from 'assert';
import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

console.log("============================================================");
console.log("   HWSEC REAL CLI END-TO-END OPERATIONAL INTEGRATION TEST   ");
console.log("   Testing real CLI -> Broker -> P0-P7 -> EvidenceAuthority ");
console.log("============================================================\n");

const cliPath = path.resolve('src/index.js');
const testWorkspaceDir = path.resolve('hwsec-cli-e2e-operational-output');
const fixtureDir = path.resolve('hwsec-cli-e2e-fixture');

// 0. Clean workspace & fixture directories
if (fs.existsSync(testWorkspaceDir)) {
    fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
}
if (fs.existsSync(fixtureDir)) {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
}
fs.mkdirSync(fixtureDir, { recursive: true });

// Create real vulnerable Python fixture (CWE-78 Command Injection)
const vulnAppPath = path.join(fixtureDir, 'vulnerable_service.py');
fs.writeFileSync(vulnAppPath, `
import sys
import os

def handle_cli_request(user_input):
    # Real command injection sink
    cmd = "echo Processing: " + user_input
    print("[APP_EXEC] Executing command: " + cmd)
    res = os.system(cmd)
    return res

if __name__ == '__main__':
    if len(sys.argv) > 1:
        out = handle_cli_request(sys.argv[1])
        print("[APP_OUTPUT] " + str(out))
`, 'utf-8');

// 1. Run 'hwsec analyze' via CLI
console.log("[Test 1] Executing real CLI: 'hwsec analyze'...");
const analyzeRes = spawnSync(process.execPath, [
    cliPath, 'analyze', fixtureDir,
    '--output-dir', testWorkspaceDir,
    '--novelty', 'off',
    '--proof', 'standard'
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(analyzeRes.status, 0, `analyze should exit 0. Stderr: ${analyzeRes.stderr}`);
const match = analyzeRes.stdout.match(/Analysis ID:\s+([a-f0-9-]+)/i);
assert(match && match[1], "analyze must output an Analysis ID");
const analysisId = match[1].trim();
console.log(`  -> Planned Analysis ID: ${analysisId}`);

const runDir = path.join(testWorkspaceDir, analysisId);
assert(fs.existsSync(runDir), "Workspace directory must exist");
const entryPointsJsonPath = path.join(runDir, 'inventory', 'entry_points.json');
assert(fs.existsSync(entryPointsJsonPath), "EntryPointInventory must generate inventory/entry_points.json during planning");
const entryPoints = JSON.parse(fs.readFileSync(entryPointsJsonPath, 'utf-8'));
assert.ok(entryPoints.length > 0, "Must discover at least 1 entry point in fixture");
console.log(`  -> [PASS] 'analyze' discovered ${entryPoints.length} entry points.`);

// 2. Run 'hwsec proceed' via CLI (The real production execution path!)
console.log("\n[Test 2] Executing real CLI: 'hwsec proceed' to run operational evidence pipeline...");
const proceedRes = spawnSync(process.execPath, [
    cliPath, 'proceed', analysisId,
    '--output-dir', testWorkspaceDir,
    '--mode', 'standard'
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(proceedRes.status, 0, `proceed should exit 0. Stderr: ${proceedRes.stderr}`);
assert(proceedRes.stdout.includes('COMPLETED'), "Proceed output must indicate COMPLETED status");
assert(proceedRes.stdout.includes('VulnerabilityHypothesis core work unit'), "Must formulate VulnerabilityHypotheses");
assert(proceedRes.stdout.includes('Witness SEARCH') || proceedRes.stdout.includes('Witness FOUND') || proceedRes.stdout.includes('Processing Hypothesis'), "Must execute WitnessSearchEngine");
console.log("  -> [PASS] 'proceed' completed operational execution.");

// 3. Verify Generated Operational Artifacts
console.log("\n[Test 3] Verifying Generated Content-Addressed Evidence DAG and Dossiers...");
const hypothesesJsonPath = path.join(runDir, 'hypotheses', 'hypotheses.json');
assert(fs.existsSync(hypothesesJsonPath), "hypotheses/hypotheses.json must exist");
const hypotheses = JSON.parse(fs.readFileSync(hypothesesJsonPath, 'utf-8'));
assert.ok(hypotheses.length > 0, "Must formulate at least 1 hypothesis");
const hyp = hypotheses[0];
console.log(`  -> Hypothesis: ${hyp.id} (${hyp.cwe} at ${hyp.sink})`);
assert.strictEqual(hyp.entry_point?.status, 'RESOLVED', "Hypothesis must resolve real entry point");

const evidenceDir = path.join(runDir, 'evidence');
assert(fs.existsSync(evidenceDir), "evidence/ directory must exist");
const dagFiles = fs.readdirSync(evidenceDir).filter(f => f.startsWith('dag_') && f.endsWith('.json'));
assert.ok(dagFiles.length > 0, "Must generate at least one Evidence DAG file");
const dagPath = path.join(evidenceDir, dagFiles[0]);
const dagData = JSON.parse(fs.readFileSync(dagPath, 'utf-8'));
assert.ok(dagData.nodes && dagData.edges, "Evidence DAG must contain nodes and edges");
assert.ok(dagData.root_hash, "Evidence DAG must have cryptographic root_hash");
console.log(`  -> Evidence DAG Root Hash: ${dagData.root_hash}`);

const dossierFiles = fs.readdirSync(evidenceDir).filter(f => f.startsWith('dossier_') && f.endsWith('.md'));
assert.ok(dossierFiles.length > 0, "Must generate at least one Analyst Dossier markdown");
const dossierMd = fs.readFileSync(path.join(evidenceDir, dossierFiles[0]), 'utf-8');
assert(dossierMd.includes('HWSEC Security Operations Case Dossier'), "Dossier must contain heading");
assert(dossierMd.includes('Suspected Vulnerability'), "Dossier must answer Q1");
assert(dossierMd.includes('Attack Surface & Entry Point'), "Dossier must answer Q2");
assert(dossierMd.includes('Operational Verdict & Evidence'), "Dossier must answer Q4");
assert(dossierMd.includes('Analyst Recommendation'), "Dossier must include recommendation");
console.log("  -> [PASS] 10-Question Analyst Dossier generated and validated.");

// 4. Verify Final Report & Findings
console.log("\n[Test 4] Verifying Final Report and Database State...");
const finalReportPath = path.join(runDir, 'report', 'final.md');
assert(fs.existsSync(finalReportPath), "Final report must exist");
const finalReportMd = fs.readFileSync(finalReportPath, 'utf-8');
assert(finalReportMd.includes('Executive Operational Verdict Summary'), "Report must include Operational Verdict Summary");
assert(finalReportMd.includes('**DETECTED (Verified Exploit Witness)**:'), "Report must include DETECTED summary");
assert(/- \*\*DETECTED \(Verified Exploit Witness\)\*\*:\s+[1-9]/.test(finalReportMd), "Report must have positive DETECTED count");
assert(finalReportMd.includes('Evidence DAG Hash'), "Report must include Evidence DAG Hash");

const verifiedFindingsPath = path.join(runDir, 'findings', 'verified_findings.json');
assert(fs.existsSync(verifiedFindingsPath), "verified_findings.json must exist");
const verifiedFindings = JSON.parse(fs.readFileSync(verifiedFindingsPath, 'utf-8'));
assert.ok(verifiedFindings.length > 0, "Must have verified findings");
const verifiedFinding = verifiedFindings[0];
assert.strictEqual(verifiedFinding.operational_verdict, 'DETECTED', "Finding must have operational_verdict = DETECTED");
assert.strictEqual(verifiedFinding.verification_level, 'E5', "Level must be E5");
assert.ok(verifiedFinding.evidence_dag_hash, "Finding must have evidence_dag_hash");
console.log(`  -> [PASS] Final report and verified findings contain genuine operational proof.`);

// 5. Test 'hwsec verify' command
console.log("\n[Test 5] Testing 'hwsec verify' on the verified finding...");
const verifyRes = spawnSync(process.execPath, [
    cliPath, 'verify', verifiedFinding.id,
    '--output-dir', testWorkspaceDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(verifyRes.status, 0, `verify command should exit 0. Stderr: ${verifyRes.stderr}`);
assert(verifyRes.stdout.includes('Operational Verdict: DETECTED') || verifyRes.stdout.includes('DETECTED'), "Must display DETECTED operational verdict");
assert(verifyRes.stdout.includes('Evidence DAG Hash'), "Must display Evidence DAG Hash");
console.log("  -> [PASS] 'hwsec verify' successfully inspected operational DAG.");

// 6. Test 'hwsec dossier' command
console.log("\n[Test 6] Testing 'hwsec dossier' CLI command...");
const dossierRes = spawnSync(process.execPath, [
    cliPath, 'dossier', analysisId,
    '--output-dir', testWorkspaceDir
], { encoding: 'utf-8', env: process.env });

assert.strictEqual(dossierRes.status, 0, `dossier command should exit 0. Stderr: ${dossierRes.stderr}`);
assert(dossierRes.stdout.includes('HWSEC Security Operations Case Dossier'), "Dossier CLI must output formatted dossier");
console.log("  -> [PASS] 'hwsec dossier' command successfully displayed case dossier.");

// Clean up test workspace
if (fs.existsSync(testWorkspaceDir)) {
    fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
}
if (fs.existsSync(fixtureDir)) {
    fs.rmSync(fixtureDir, { recursive: true, force: true });
}

console.log("\n============================================================");
console.log("   [SUCCESS] ALL REAL CLI OPERATIONAL E2E TESTS PASSED      ");
console.log("============================================================\n");
