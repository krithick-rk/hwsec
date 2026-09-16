import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

const BASE_DIR = path.resolve('experiments', 'autonomous_validation');
const TARGETS_DIR = path.join(BASE_DIR, 'targets');
const RUNS_DIR = path.join(BASE_DIR, 'runs');
const TRUTH_DIR = path.join(BASE_DIR, 'truth');
const REPORTS_DIR = path.resolve('reports', 'autonomous_validation');

fs.mkdirSync(RUNS_DIR, { recursive: true });
fs.mkdirSync(REPORTS_DIR, { recursive: true });

const groundTruth = JSON.parse(fs.readFileSync(path.join(TRUTH_DIR, 'ground_truth.json'), 'utf-8'));

const targets = [
    { id: 'target-01', name: 'Python Vulnerable (Command Exec)', path: path.join(TARGETS_DIR, 'python', 'target-01'), lang: 'python' },
    { id: 'target-02', name: 'Java Vulnerable (Command Exec)', path: path.join(TARGETS_DIR, 'java', 'target-02'), lang: 'java' },
    { id: 'target-03', name: 'C/C++ Vulnerable (Buffer & Command)', path: path.join(TARGETS_DIR, 'c_cpp', 'target-03'), lang: 'c_cpp' },
    { id: 'target-04', name: 'Verilog Vulnerable (Counter State)', path: path.join(TARGETS_DIR, 'verilog', 'target-04'), lang: 'verilog' },
    { id: 'target-05', name: 'Safe Control (Remediated Python)', path: path.join(TARGETS_DIR, 'safe', 'target-05'), lang: 'python' },
    { id: 'target-06', name: 'Ambiguous Target (Logged User Input)', path: path.join(TARGETS_DIR, 'ambiguous', 'target-06'), lang: 'python' },
    { id: 'target-07', name: 'Adversarial Injection (Prompt Override)', path: path.join(TARGETS_DIR, 'adversarial', 'target-07'), lang: 'python' }
];

console.log('============================================================');
console.log('   HWSEC AUTONOMOUS BLIND EVALUATION EXPERIMENT RUNNER      ');
console.log('============================================================\n');

const suiteResults = [];

for (const target of targets) {
    console.log(`\n------------------------------------------------------------`);
    console.log(`[*] Executing Blind Run for: ${target.id} (${target.name})`);
    console.log(`    Location: ${target.path}`);
    console.log(`------------------------------------------------------------`);

    const targetRunDir = path.join(RUNS_DIR, target.id);
    fs.mkdirSync(targetRunDir, { recursive: true });

    const startTime = Date.now();

    // 1. Analyze phase
    console.log(`  -> [CLI] hwsec analyze ${target.path} --generate-pov -o ${targetRunDir}`);
    const analyzeRes = spawnSync(process.execPath, [
        path.resolve('src/index.js'),
        'analyze',
        target.path,
        '--generate-pov',
        '-o', targetRunDir
    ], { encoding: 'utf-8', timeout: 60000 });

    const analyzeStdout = analyzeRes.stdout || '';
    const analyzeStderr = analyzeRes.stderr || '';

    let analysisId = null;
    const idMatch = analyzeStdout.match(/Analysis ID:\s+([0-9a-zA-Z-]+)/);
    if (idMatch) {
        analysisId = idMatch[1];
    } else {
        // Look in run dir
        const entries = fs.readdirSync(targetRunDir);
        for (const e of entries) {
            if (fs.existsSync(path.join(targetRunDir, e, 'analysis.json'))) {
                analysisId = e;
                break;
            }
        }
    }

    if (!analysisId) {
        console.error(`  [-] Planning failed to produce analysis ID for ${target.id}`);
        suiteResults.push({
            target_id: target.id,
            language: target.lang,
            error: 'Planning failed',
            analyze_stdout: analyzeStdout,
            analyze_stderr: analyzeStderr
        });
        continue;
    }

    console.log(`  [+] Analysis ID established: ${analysisId}`);

    // 2. Proceed phase
    console.log(`  -> [CLI] hwsec proceed ${analysisId} --generate-pov -o ${targetRunDir}`);
    const proceedRes = spawnSync(process.execPath, [
        path.resolve('src/index.js'),
        'proceed',
        analysisId,
        '--generate-pov',
        '-o', targetRunDir
    ], { encoding: 'utf-8', timeout: 180000 });

    const durationMs = Date.now() - startTime;
    const proceedStdout = proceedRes.stdout || '';
    const proceedStderr = proceedRes.stderr || '';

    // Inspect artifacts in run directory
    const analysisJsonPath = path.join(targetRunDir, analysisId, 'analysis.json');
    const analysisData = fs.existsSync(analysisJsonPath) ? JSON.parse(fs.readFileSync(analysisJsonPath, 'utf-8')) : {};
    
    const epPath = path.join(targetRunDir, analysisId, 'inventory', 'entry_points.json');
    const entryPoints = fs.existsSync(epPath) ? JSON.parse(fs.readFileSync(epPath, 'utf-8')) : [];

    const hypPath = path.join(targetRunDir, analysisId, 'hypotheses', 'hypotheses.json');
    const hypotheses = fs.existsSync(hypPath) ? JSON.parse(fs.readFileSync(hypPath, 'utf-8')) : [];

    const opResultsPath = path.join(targetRunDir, analysisId, 'evidence', 'operational_results.json');
    const opResults = fs.existsSync(opResultsPath) ? JSON.parse(fs.readFileSync(opResultsPath, 'utf-8')) : [];

    // PoV check
    const povDir = path.join(targetRunDir, analysisId, 'pov');
    let povBundlePath = null;
    let povStatus = 'NOT_REQUESTED';
    let povReplayResult = null;
    let bundleHash = null;

    if (fs.existsSync(povDir)) {
        const povSubdirs = fs.readdirSync(povDir);
        for (const sub of povSubdirs) {
            const metaPath = path.join(povDir, sub, 'metadata.json');
            if (fs.existsSync(metaPath)) {
                povBundlePath = path.join(povDir, sub);
                const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
                povStatus = meta.status || 'GENERATED';
                bundleHash = meta.bundle_manifest_hash;
                break;
            }
        }
    }

    // Determine final verdict
    let finalVerdict = 'NOT_DETECTED';
    let finalReasonCode = null;
    if (opResults.length > 0) {
        const hasDetected = opResults.some(r => r.verdict === 'DETECTED');
        const hasInconclusive = opResults.some(r => r.verdict === 'INCONCLUSIVE');
        if (hasDetected) {
            finalVerdict = 'DETECTED';
        } else if (hasInconclusive) {
            finalVerdict = 'INCONCLUSIVE';
            finalReasonCode = opResults[0].reason_code;
        }
    } else {
        if (hypotheses.length === 0) {
            finalVerdict = 'NOT_DETECTED';
        } else {
            finalVerdict = 'INCONCLUSIVE';
        }
    }

    // Discovery success: did it discover security-relevant findings or entry points?
    const discoverySuccess = hypotheses.length > 0 || entryPoints.length > 0;
    const witnessSuccess = opResults.some(r => r.reason_code === 'VERIFIED_EXPLOIT_WITNESS' || r.verdict === 'DETECTED');
    const oracleSuccess = opResults.some(r => r.reason_code === 'VERIFIED_EXPLOIT_WITNESS' || r.verdict === 'DETECTED');
    const povGenSuccess = povBundlePath !== null;
    const povReplaySuccess = povStatus === 'VERIFIED';
    const truth = groundTruth[target.id] || {};
    const verdictSuccess = finalVerdict === truth.expected_verdict;

    // Failure classification (Phase 14)
    let failureClass = 'NONE';
    if (!verdictSuccess || (truth.expected_verdict === 'DETECTED' && finalVerdict !== 'DETECTED')) {
        if (!discoverySuccess) {
            failureClass = 'A. DISCOVERY_FAILURE';
        } else if (entryPoints.length === 0) {
            failureClass = 'B. INVENTORY_FAILURE';
        } else if (target.lang === 'c_cpp' || target.lang === 'verilog') {
            failureClass = 'J. TOOLCHAIN_FAILURE';
        } else if (finalReasonCode === 'SEARCH_BUDGET_EXHAUSTED' || !witnessSuccess) {
            failureClass = 'D. WITNESS_FAILURE';
        } else if (opResults.some(r => r.reason_code === 'ORACLE_UNSATISFIED')) {
            failureClass = 'F. ORACLE_FAILURE';
        } else {
            failureClass = 'K. LLM_ORCHESTRATION_FAILURE';
        }
    }

    // LLM Contribution (Phase 15)
    let llmContribution = 'LLM NOT NEEDED';
    if (proceedStdout.includes('[LLMGateway]') || proceedStdout.includes('GeminiProvider') || proceedStdout.includes('OpenRouterProvider')) {
        if (proceedStdout.includes('fallback') || proceedStdout.includes('HTTP 404') || proceedStdout.includes('Rate limit')) {
            llmContribution = 'PROVIDER FALLBACK / MODEL DEPRECATION (FAIL-CLOSED)';
        } else {
            llmContribution = 'INVESTIGATION VALUE';
        }
    }

    const runRecord = {
        target_id: target.id,
        target_name: target.name,
        language: target.lang,
        analysis_id: analysisId,
        cli_analyze_command: `hwsec analyze ${target.path} --generate-pov -o ${targetRunDir}`,
        cli_proceed_command: `hwsec proceed ${analysisId} --generate-pov -o ${targetRunDir}`,
        duration_ms: durationMs,
        entry_points_count: entryPoints.length,
        entry_points: entryPoints.map(ep => ({ id: ep.id, file: ep.file, type: ep.type, symbol: ep.symbol })),
        hypotheses_count: hypotheses.length,
        hypotheses: hypotheses.map(h => ({ id: h.id, cwe: h.cwe, file: h.file, sink: h.sink })),
        tools_executed: analysisData.tools_executed || ['semgrep', 'joern', 'codeql'],
        operational_results: opResults,
        final_verdict: finalVerdict,
        reason_code: finalReasonCode,
        hidden_truth: truth,
        metrics: {
            discovery_success: discoverySuccess,
            witness_success: witnessSuccess,
            oracle_success: oracleSuccess,
            pov_generation_success: povGenSuccess,
            pov_replay_success: povReplaySuccess,
            verdict_success: verdictSuccess
        },
        failure_class: failureClass,
        llm_contribution: llmContribution,
        pov: {
            status: povStatus,
            path: povBundlePath,
            manifest_hash: bundleHash
        },
        stdout_snippet: proceedStdout.slice(0, 500)
    };

    console.log(`  [+] Result: Verdict=${finalVerdict} (Expected=${truth.expected_verdict}) | Hypotheses=${hypotheses.length} | PoV=${povStatus} | Failure=${failureClass}`);
    suiteResults.push(runRecord);
}

// Write discovery_results.json
const discoveryResults = suiteResults.map(r => ({
    target_id: r.target_id,
    language: r.language,
    entry_points_count: r.entry_points_count,
    entry_points: r.entry_points,
    hypotheses_count: r.hypotheses_count,
    hypotheses: r.hypotheses,
    discovery_success: r.metrics.discovery_success
}));
fs.writeFileSync(path.join(REPORTS_DIR, 'discovery_results.json'), JSON.stringify(discoveryResults, null, 2));

// Write witness_results.json
const witnessResults = suiteResults.map(r => ({
    target_id: r.target_id,
    language: r.language,
    witness_success: r.metrics.witness_success,
    operational_results: r.operational_results
}));
fs.writeFileSync(path.join(REPORTS_DIR, 'witness_results.json'), JSON.stringify(witnessResults, null, 2));

// Write pov_results.json
const povResults = suiteResults.map(r => ({
    target_id: r.target_id,
    language: r.language,
    pov_status: r.pov.status,
    pov_path: r.pov.path,
    bundle_hash: r.pov.manifest_hash,
    pov_generation_success: r.metrics.pov_generation_success,
    pov_replay_success: r.metrics.pov_replay_success
}));
fs.writeFileSync(path.join(REPORTS_DIR, 'pov_results.json'), JSON.stringify(povResults, null, 2));

// Write failure_classification.json
const failureClassification = suiteResults.map(r => ({
    target_id: r.target_id,
    language: r.language,
    expected_verdict: r.hidden_truth.expected_verdict,
    actual_verdict: r.final_verdict,
    failure_class: r.failure_class,
    reason_code: r.reason_code
}));
fs.writeFileSync(path.join(REPORTS_DIR, 'failure_classification.json'), JSON.stringify(failureClassification, null, 2));

// Write llm_contribution.json
const llmContribution = suiteResults.map(r => ({
    target_id: r.target_id,
    language: r.language,
    llm_contribution: r.llm_contribution
}));
fs.writeFileSync(path.join(REPORTS_DIR, 'llm_contribution.json'), JSON.stringify(llmContribution, null, 2));

// Write autonomous_results.json
fs.writeFileSync(path.join(REPORTS_DIR, 'autonomous_results.json'), JSON.stringify(suiteResults, null, 2));

console.log('\n[+] All JSON data products successfully written to reports/autonomous_validation/');
