#!/usr/bin/env node

import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { loadConfig } from './core/config.js';
import { Workspace } from './core/workspace.js';
import { Planner } from './core/planner.js';
import { Database } from './core/db.js';
import { AnalysisStatus, assertTransition } from './core/state.js';
import { AnalysisBroker } from './core/broker.js';
import { ModelRouter } from './core/llm/modelRouter.js';
import { LLMGateway } from './core/llm/gateway.js';
import { SuspicionEngine } from './core/suspicion/engine.js';
import { LayeredVerifier } from './workers/verifier.js';
import { EvidenceCorrelationEngine } from './workers/evidenceCorrelation.js';
import { HypothesisGenerator } from './workers/hypothesisGenerator.js';
import { InvariantSynthesizer } from './workers/invariantSynthesizer.js';
import { createFinding, Severity, VerificationState } from './core/schema.js';
import { CodeGraph, NodeTypes, EdgeRelations } from './core/graph/codeGraph.js';
import { RAGEngine } from './core/knowledge/rag.js';

const program = new Command();

program
  .name('hwsec')
  .description('HWSEC - Multi-Language Evidence-Driven Security Analysis Framework')
  .version('2.0.0');

// ==========================================
// Command: analyze
// ==========================================
program.command('analyze')
  .description('Discover repository and plan analysis without executing expensive work')
  .argument('<directory>', 'Directory containing source files (Python, Java, C/C++, Go, Verilog)')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-s, --spec <path>', 'Path to specification file')
  .option('-n, --novelty <mode>', 'Novelty mode (off, minimal, standard, deep)', 'standard')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (directory, options) => {
    console.log(`[*] Discovering and planning analysis for: ${directory}`);
    console.log(`[*] Novelty mode: ${options.novelty.toUpperCase()}`);

    const configPath = path.resolve(options.config);
    const config = loadConfig(configPath);
    const workspace = new Workspace(options.outputDir);

    const planner = new Planner(
        directory,
        config,
        options.spec ? path.resolve(options.spec) : null,
        options.novelty
    );

    try {
        const plan = await planner.plan(workspace);

        console.log(`\n[+] Planning complete! Analysis ID: ${workspace.analysisId}`);
        console.log(`    Files detected:    ${plan.inventory.total_files}`);
        console.log(`    Estimated LOC:     ${plan.inventory.total_loc}`);
        console.log(`    Tools detected:    ${plan.tools_detected.join(', ') || 'None'}`);
        console.log(`    Planned pipeline:  ${plan.execution_graph.join(' -> ')}`);
        console.log(`\n> [!IMPORTANT]`);
        console.log(`> **ANALYSIS HAS NOT STARTED. WAITING FOR APPROVAL.**`);
        console.log(`> Review plan at: ${path.join(workspace.outputDir, 'plan.md')}`);
        console.log(`> Run \`hwsec proceed ${workspace.analysisId}\` to approve and begin execution.\n`);
    } catch (e) {
        console.error(`[-] Planning failed: ${e.message}`);
        process.exit(1);
    }
  });

// ==========================================
// Command: proceed
// ==========================================
program.command('proceed')
  .description('Execute an approved analysis plan')
  .argument('<analysis-id>', 'ID of the planned analysis to approve and run')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (analysisId, options) => {
    console.log(`[*] Validating approval for analysis ID: ${analysisId}...`);

    try {
        const configPath = path.resolve(options.config);
        const config = loadConfig(configPath);
        const workspace = Workspace.load(options.outputDir, analysisId);
        const analysis = workspace.loadJson('analysis.json');

        if (!analysis) {
            console.error(`[-] Analysis record not found for ID: ${analysisId}`);
            process.exit(1);
        }

        // Enforce Human Approval State Boundary
        assertTransition(analysis.status, AnalysisStatus.APPROVED, 'proceed');
        analysis.status = AnalysisStatus.APPROVED;
        analysis.approved_at = new Date().toISOString();
        workspace.saveJson('analysis.json', analysis);

        assertTransition(analysis.status, AnalysisStatus.RUNNING, 'proceed');
        analysis.status = AnalysisStatus.RUNNING;
        analysis.execution_started = true;
        analysis.started_at = new Date().toISOString();
        workspace.saveJson('analysis.json', analysis);

        console.log(`[+] Plan APPROVED. Transitioned status to RUNNING.`);
        workspace.saveMarkdown('status.md', `# Status\n\nPhase: RUNNING\nStarted: ${analysis.started_at}\n`);

        // Initialize SQLite Database
        const dbPath = path.join(options.outputDir, 'hwsec.db');
        const db = new Database(dbPath);
        const projectId = `PROJ-${Buffer.from(analysis.target_dir).toString('hex').slice(0, 8)}`;
        db.saveProject({ id: projectId, path: analysis.target_dir, name: path.basename(analysis.target_dir) });
        db.saveAnalysisRun({
            id: analysisId,
            projectId,
            status: AnalysisStatus.RUNNING,
            budgetAllocated: analysis.budget_estimate?.max_budget_usd || 10.0,
            budgetConsumed: 0.0
        });

        // Initialize Broker & LLM Gateway
        const broker = new AnalysisBroker(config, null, db);
        const llmGateway = new LLMGateway(config, db);
        const modelRouter = llmGateway.router;
        const suspicionEngine = new SuspicionEngine(config);
        const ragEngine = new RAGEngine(db, config);
        const codeGraph = new CodeGraph();
        const verifier = new LayeredVerifier(modelRouter, db, analysisId, codeGraph);

        // 1. File Fingerprinting & Incremental Check
        console.log(`[*] Fingerprinting source files and checking incremental cache...`);
        const allFiles = [];
        const filesByLang = analysis.inventory?.languages || {};
        for (const [lang, files] of Object.entries(filesByLang)) {
            for (const f of files) {
                const absPath = path.resolve(analysis.target_dir, f);
                allFiles.push({ path: absPath, language: lang });
                codeGraph.addNode(absPath, NodeTypes.FILE, path.basename(absPath), { language: lang, path: absPath });
                if (fs.existsSync(absPath)) {
                    const hash = Database.computeFileHash(absPath);
                    const incCheck = db.checkIncrementalReuse(absPath, hash);
                    db.saveFile({
                        id: `FILE-${crypto.randomBytes(6).toString('hex')}`,
                        runId: analysisId,
                        path: absPath,
                        language: lang,
                        sha256Hash: hash
                    });
                }
            }
        }

        // 2. Deterministic Analysis Dispatch via AnalysisBroker
        console.log(`[*] [Deterministic Phase] Executing analyzers via AnalysisBroker...`);
        const allRawFindings = [];
        const executedTools = [];
        const toolsOutputDir = path.join(workspace.outputDir, 'tools');
        const plannedCaps = analysis.planned_capabilities || [];

        // RTL Linting (Verilator)
        if (plannedCaps.includes('rtl_lint')) {
            console.log(`  -> Running RTL Linting (Verilator)...`);
            const rtlFiles = (filesByLang.verilog || []).map(f => path.resolve(analysis.target_dir, f));
            const res = await broker.dispatch({
                capability: 'rtl_lint',
                languages: ['verilog'],
                files: rtlFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('verilator');
            workspace.saveJson('findings/linting.json', res.findings || []);
        }

        // RTL Formal (Yosys)
        if (plannedCaps.includes('rtl_formal')) {
            console.log(`  -> Running RTL Formal (Yosys)...`);
            const rtlFiles = (filesByLang.verilog || []).map(f => path.resolve(analysis.target_dir, f));
            const res = await broker.dispatch({
                capability: 'rtl_formal',
                languages: ['verilog'],
                files: rtlFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('yosys');
            workspace.saveJson('findings/formal.json', res.findings || []);
        }

        // Formal Invariant Verification (SymbiYosys)
        if (plannedCaps.includes('formal_invariant_verification')) {
            console.log(`  -> Running Formal Invariant Verification (SymbiYosys)...`);
            const rtlFiles = (filesByLang.verilog || []).map(f => path.resolve(analysis.target_dir, f));
            const res = await broker.dispatch({
                capability: 'formal_invariant_verification',
                languages: ['verilog'],
                files: rtlFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('symbiyosys');
            workspace.saveJson('findings/symbiyosys.json', res.findings || []);
        }

        // RTL Fuzzing (AFL++)
        if (plannedCaps.includes('rtl_fuzz')) {
            console.log(`  -> Running RTL Fuzzing (AFL++)...`);
            const rtlFiles = (filesByLang.verilog || []).map(f => path.resolve(analysis.target_dir, f));
            const res = await broker.dispatch({
                capability: 'rtl_fuzz',
                languages: ['verilog'],
                files: rtlFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('afl++');
            workspace.saveJson('findings/fuzzing.json', res.findings || []);
        }

        // Reference Model (Spike)
        if (plannedCaps.includes('reference_model')) {
            console.log(`  -> Running Reference Model Simulation (Spike)...`);
            const res = await broker.dispatch({
                capability: 'reference_model',
                languages: ['verilog', 'c', 'riscv'],
                files: allFiles.map(f => f.path),
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('spike');
            workspace.saveJson('findings/spike.json', res.findings || []);
        }

        // Software SAST (Semgrep)
        const softwareLangs = ['python', 'java', 'c', 'cpp', 'go'];
        const softwareFiles = allFiles.filter(f => softwareLangs.includes(f.language)).map(f => f.path);
        if (softwareFiles.length > 0 && (plannedCaps.includes('sast_pattern_scan') || plannedCaps.length === 0)) {
            console.log(`  -> Running Software SAST Pattern Analysis (Semgrep)...`);
            const res = await broker.dispatch({
                capability: 'sast_pattern_scan',
                languages: softwareLangs,
                files: softwareFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('semgrep');
            workspace.saveJson('findings/software_sast.json', res.findings || []);
        }

        // Code Property Graph / Dataflow (Joern)
        if (softwareFiles.length > 0 && plannedCaps.includes('graph_dataflow')) {
            console.log(`  -> Running Code Property Graph Dataflow (Joern)...`);
            const res = await broker.dispatch({
                capability: 'graph_dataflow',
                languages: softwareLangs,
                files: softwareFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('joern');
            workspace.saveJson('findings/joern.json', res.findings || []);
        }

        // Deep Dataflow (CodeQL)
        if (softwareFiles.length > 0 && plannedCaps.includes('deep_dataflow')) {
            console.log(`  -> Running Deep Dataflow & Taint Tracking (CodeQL)...`);
            const res = await broker.dispatch({
                capability: 'deep_dataflow',
                languages: softwareLangs,
                files: softwareFiles,
                outputDir: toolsOutputDir,
                runId: analysisId
            });
            if (res.findings) allRawFindings.push(...res.findings);
            executedTools.push('codeql');
            workspace.saveJson('findings/codeql.json', res.findings || []);
        }

        console.log(`[+] Deterministic tools collected ${allRawFindings.length} raw finding(s).`);

        // Persist raw findings and link to graph
        for (const f of allRawFindings) {
            db.saveFinding({
                id: f.id,
                runId: analysisId,
                title: f.title,
                type: f.cwe_id || 'SECURITY_FINDING',
                severity: f.severity || 'MEDIUM',
                confidence: f.confidence || 0.5,
                verificationState: f.verification_state || 'PROPOSED',
                location: f.source_locations?.[0]?.path || f.rtl_location || null
            });
            codeGraph.addNode(f.id, NodeTypes.FINDING, f.title, { severity: f.severity, tool: f.source_tool });
            const loc = f.source_locations?.[0]?.path || f.rtl_location;
            if (loc && codeGraph.getNode(loc)) {
                codeGraph.addEdge(loc, f.id, EdgeRelations.EVIDENCES);
            }
        }

        // 3. Suspicion Scoring & Prioritization
        console.log(`[*] [Intelligent Phase] Computing suspicion scores and analyzer disagreement...`);
        const scoredTargets = allFiles.map(f => {
            return suspicionEngine.scoreTarget({
                path: f.path,
                findings: allRawFindings,
                executedTools,
                noveltyMode: analysis.novelty_mode
            });
        });
        const ranking = suspicionEngine.rankTargets(allFiles.map(f => ({
            path: f.path,
            findings: allRawFindings,
            executedTools,
            noveltyMode: analysis.novelty_mode
        })), 0.25);

        workspace.saveJson('report/suspicion_scores.json', ranking);
        console.log(`[+] Prioritized top ${ranking.prioritizedTargets.length} suspicious target(s) for targeted reasoning.`);

        // 4. Hypothesis & Invariant Engine (Execution Phase)
        let hypotheses = [];
        if (analysis.novelty_mode !== 'off') {
            console.log(`[*] [Reasoning Phase] Formulating security hypotheses (Mode: ${analysis.novelty_mode})...`);
            const hypGen = new HypothesisGenerator(modelRouter, ragEngine);
            hypotheses = await hypGen.generateHypotheses({
                deterministicFindings: allRawFindings,
                suspiciousTargets: ranking.prioritizedTargets,
                availableTools: executedTools,
                analysisId,
                noveltyMode: analysis.novelty_mode
            });

            for (const h of hypotheses) {
                db.saveHypothesis({
                    id: h.hypothesis_id,
                    runId: analysisId,
                    claim: h.claim,
                    status: 'PLANNED',
                    proposedTest: h.proposed_test
                });
                codeGraph.addNode(h.hypothesis_id, NodeTypes.HYPOTHESIS, h.title, { claim: h.claim });
            }
            workspace.saveJson('hypotheses/hypotheses.json', hypotheses);
            console.log(`[+] Generated ${hypotheses.length} grounded security hypothesis(es).`);
        }

        // 5. Layered Verification Engine
        console.log(`[*] [Verification Phase] Running Layered Technical Verifier...`);
        const verificationResult = await verifier.verify(hypotheses, allRawFindings, {});
        const verifiedFindings = verificationResult.verifiedFindings;
        const candidateFindings = verificationResult.candidateFindings;

        // Update database with final verified/candidate states
        for (const f of [...verifiedFindings, ...candidateFindings]) {
            db.saveFinding({
                id: f.id,
                runId: analysisId,
                title: f.title,
                type: f.cwe_id || 'SECURITY_FINDING',
                severity: f.severity || 'MEDIUM',
                confidence: f.confidence || 0.5,
                verificationState: f.verification_state,
                location: f.source_locations?.[0]?.path || f.rtl_location || null
            });
        }

        workspace.saveJson('findings/verified_findings.json', verifiedFindings);
        workspace.saveJson('findings/candidate_findings.json', candidateFindings);
        workspace.saveJson('verification/summaries.json', verificationResult.verificationSummaries);
        console.log(`[+] Verification complete: ${verifiedFindings.length} VERIFIED, ${candidateFindings.length} CANDIDATE.`);

        // 6. Evidence Correlation & Graph
        console.log(`[*] [Correlation Phase] Building evidence graph and attack paths...`);
        const correlator = new EvidenceCorrelationEngine(llmGateway);
        const correlationRes = await correlator.correlate([...verifiedFindings, ...candidateFindings], hypotheses, {});
        codeGraph.syncToDatabase(db, analysisId);

        workspace.saveJson('report/evidence_graph.json', correlationRes.graph);
        workspace.saveJson('report/correlated_clusters.json', correlationRes.correlatedClusters);
        workspace.saveJson('report/attack_paths.json', correlationRes.attackPaths);

        // 7. Generate Final Human-Readable Security Report
        const allFindings = [...verifiedFindings, ...candidateFindings];
        const finalReportMd = `# HWSEC Security Analysis Final Report

**Analysis ID**: \`${analysisId}\`  
**Target Repository**: \`${analysis.target_dir}\`  
**Novelty Mode**: \`${analysis.novelty_mode.toUpperCase()}\`  
**Completion Date**: ${new Date().toISOString()}  

---

## Executive Summary
- **Total Files Scanned**: ${analysis.inventory.total_files}
- **Verified Findings (E3+)**: ${verifiedFindings.length}
- **Candidate Findings (E1-E2)**: ${candidateFindings.length}
- **Correlated Clusters**: ${correlationRes.correlatedClusters.length}
- **Synthesized Attack Paths**: ${correlationRes.attackPaths.length}
- **Tokens Consumed**: ${modelRouter.budgetController.totalTokensConsumed}
- **Total LLM Cost**: $${modelRouter.budgetController.totalCostUsd} USD

---

## 1. Verified Findings (High-Confidence Concrete Evidence)
${verifiedFindings.length > 0 
    ? verifiedFindings.map((f, i) => `### [${f.severity}] ${f.title}\n- **ID**: \`${f.id}\`\n- **Verification State**: \`${f.verification_state}\`\n- **Location**: \`${f.source_locations?.[0]?.path || f.rtl_location || 'Unknown'}\`\n- **Description**: ${f.description}\n- **Evidence**: ${f.evidence?.map(e => e.description || e.artifact_path).join('; ') || 'Verified trace'}\n`).join('\n')
    : '_No verified findings identified with dynamic reproducing evidence._'}

---

## 2. Candidate Findings (Static Tool Observations)
${candidateFindings.length > 0
    ? candidateFindings.map((f, i) => `### [${f.severity}] ${f.title}\n- **ID**: \`${f.id}\`\n- **Verification State**: \`${f.verification_state}\`\n- **Location**: \`${f.source_locations?.[0]?.path || f.rtl_location || 'Unknown'}\`\n- **Description**: ${f.description}\n`).join('\n')
    : '_No unverified candidate findings._'}

---

## 3. Evidence Clusters & Attack Paths
${correlationRes.attackPaths.length > 0
    ? correlationRes.attackPaths.map(p => `### ${p.title}\n- **Evidence Strength**: ${p.evidence_strength}\n- ${p.description}\n`).join('\n')
    : '_No multi-stage attack paths identified._'}

---

## 4. Verification Methodology & Grounding
All findings in this report strictly adhere to technical artifact grounding. Pure string/substring matches and unsupported LLM assertions were rejected or held at Candidate (E1) level according to HWSEC Verification Policy.
`;

        workspace.saveMarkdown('report/final.md', finalReportMd);
        workspace.saveMarkdown('report/report.md', finalReportMd);

        // 8. Finalize State
        analysis.status = AnalysisStatus.COMPLETED;
        analysis.completed_at = new Date().toISOString();
        analysis.results = {
            verified_count: verifiedFindings.length,
            candidate_count: candidateFindings.length,
            tokens_consumed: modelRouter.budgetController.totalTokensConsumed,
            cost_usd: modelRouter.budgetController.totalCostUsd
        };
        workspace.saveJson('analysis.json', analysis);

        // Final status.md
        const statusMd = `# HWSEC Analysis Status

**Analysis ID**: \`${analysisId}\`  
**Phase**: \`COMPLETED\`  
**Execution Started**: \`true\`  
**Completed At**: ${analysis.completed_at}  

### Summary Results
- **Verified Findings**: ${verifiedFindings.length}
- **Candidate Findings**: ${candidateFindings.length}
- **Tokens Consumed**: ${analysis.results.tokens_consumed}
- **Budget Remaining**: $${(analysis.budget_estimate?.max_budget_usd - analysis.results.cost_usd).toFixed(4)} USD

> [!TIP]
> View final security report at: \`hwsec-output/${analysisId}/report/final.md\`
`;
        workspace.saveMarkdown('status.md', statusMd);
        db.updateAnalysisRunStatus(analysisId, AnalysisStatus.COMPLETED, modelRouter.budgetController.totalCostUsd);

        console.log(`\n[+] Analysis execution COMPLETED successfully!`);
        console.log(`    Verified findings:  ${verifiedFindings.length}`);
        console.log(`    Candidate findings: ${candidateFindings.length}`);
        console.log(`    Final report saved: ${path.join(workspace.outputDir, 'report/final.md')}\n`);

    } catch (e) {
        console.error(`[-] Execution failed: ${e.message}`);
        process.exit(1);
    }
  });

// ==========================================
// Command: status
// ==========================================
program.command('status')
  .description('Check live progress and status of an analysis')
  .argument('<analysis-id>', 'ID of the analysis')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((analysisId, options) => {
    try {
        const workspace = Workspace.load(options.outputDir, analysisId);
        const analysis = workspace.loadJson('analysis.json');
        if (!analysis) {
            console.error(`[-] No analysis metadata found for ID: ${analysisId}`);
            process.exit(1);
        }

        console.log(`\n[*] === HWSEC Analysis Status: ${analysis.analysis_id} ===`);
        console.log(`  Phase / Status:     ${analysis.status}`);
        console.log(`  Target Directory:   ${analysis.target_dir}`);
        console.log(`  Novelty Mode:       ${analysis.novelty_mode || 'standard'}`);
        console.log(`  Files Discovered:   ${analysis.inventory?.total_files ?? 0}`);
        console.log(`  Tools Detected:     ${analysis.tools_detected?.join(', ') || 'None'}`);
        console.log(`  Planned Pipeline:   ${analysis.execution_graph?.join(' -> ') || 'None'}`);
        if (analysis.results) {
            console.log(`  Verified Findings:  ${analysis.results.verified_count}`);
            console.log(`  Candidate Findings: ${analysis.results.candidate_count}`);
            console.log(`  Tokens Consumed:    ${analysis.results.tokens_consumed}`);
            console.log(`  LLM Cost (USD):     $${analysis.results.cost_usd}`);
        }
        console.log(`  Status File:        ${path.join(workspace.outputDir, 'status.md')}\n`);
    } catch (e) {
        console.error(`[-] Failed to retrieve status: ${e.message}`);
    }
  });

// ==========================================
// Command: findings
// ==========================================
program.command('findings')
  .description('Display structured findings from an analysis')
  .argument('<analysis-id>', 'ID of the analysis')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((analysisId, options) => {
    try {
        const workspace = Workspace.load(options.outputDir, analysisId);
        const verified = workspace.loadJson('findings/verified_findings.json') || [];
        const candidates = workspace.loadJson('findings/candidate_findings.json') || [];

        console.log(`\n=== HWSEC Findings for ${analysisId} ===\n`);
        console.log(`[+] VERIFIED FINDINGS (${verified.length}):`);
        if (verified.length === 0) console.log('    (None)');
        for (const f of verified) {
            console.log(`  * [${f.severity}] ${f.title} (Location: ${f.source_locations?.[0]?.path || f.rtl_location || 'N/A'})`);
            console.log(`    ID: ${f.id} | Confidence: ${(f.confidence * 100).toFixed(0)}%`);
        }

        console.log(`\n[+] CANDIDATE FINDINGS (${candidates.length}):`);
        if (candidates.length === 0) console.log('    (None)');
        for (const f of candidates) {
            console.log(`  * [${f.severity}] ${f.title} (Location: ${f.source_locations?.[0]?.path || f.rtl_location || 'N/A'})`);
            console.log(`    ID: ${f.id} | Status: ${f.verification_state}`);
        }
        console.log();
    } catch (e) {
        console.error(`[-] Failed to retrieve findings: ${e.message}`);
    }
  });

// ==========================================
// Command: verify
// ==========================================
program.command('verify')
  .description('Inspect or re-evaluate verification evidence for a specific finding')
  .argument('<finding-id>', 'ID of the finding to verify')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((findingId, options) => {
    try {
        // Search through all analyses in output dir
        const baseDir = path.resolve(options.outputDir);
        if (!fs.existsSync(baseDir)) {
            console.error(`[-] Output directory ${baseDir} does not exist.`);
            return;
        }

        let found = null;
        let foundWs = null;
        const runs = fs.readdirSync(baseDir);
        for (const run of runs) {
            const runDir = path.join(baseDir, run);
            if (fs.statSync(runDir).isDirectory()) {
                for (const file of [
                    'findings/verified_findings.json',
                    'findings/candidate_findings.json',
                    'findings/software_sast.json',
                    'findings/joern.json',
                    'findings/codeql.json',
                    'findings/linting.json',
                    'findings/formal.json',
                    'findings/symbiyosys.json',
                    'findings/spike.json'
                ]) {
                    const fp = path.join(runDir, file);
                    if (fs.existsSync(fp)) {
                        try {
                            const list = JSON.parse(fs.readFileSync(fp, 'utf-8'));
                            const item = list.find(x => x.id === findingId);
                            if (item) {
                                found = item;
                                foundWs = run;
                                break;
                            }
                        } catch {}
                    }
                }
            }
            if (found) break;
        }

        if (!found) {
            console.error(`[-] Finding ID '${findingId}' not found in any analysis run.`);
            return;
        }

        console.log(`\n=== Verification Details for Finding: ${findingId} ===`);
        console.log(`Analysis Run:       ${foundWs}`);
        console.log(`Title:              ${found.title}`);
        console.log(`Severity:           ${found.severity}`);
        console.log(`Verification State: ${found.verification_state}`);
        console.log(`Confidence:         ${(found.confidence * 100).toFixed(0)}%`);
        console.log(`Location:           ${found.source_locations?.[0]?.path || found.rtl_location || 'N/A'}`);
        console.log(`Evidence Count:     ${(found.evidence || []).length}`);
        for (const ev of (found.evidence || [])) {
            console.log(`  - Tool: ${ev.tool_name || ev.tool} | Path: ${ev.artifact_path || 'None'}`);
            console.log(`    Observation: ${ev.description || ev.observation}`);
        }
        console.log();
    } catch (e) {
        console.error(`[-] Verification lookup failed: ${e.message}`);
    }
  });

// ==========================================
// Command: report
// ==========================================
program.command('report')
  .description('Display the final human-readable report for an analysis')
  .argument('<analysis-id>', 'ID of the analysis')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((analysisId, options) => {
    try {
        const workspace = Workspace.load(options.outputDir, analysisId);
        const reportPath = path.join(workspace.outputDir, 'report', 'final.md');
        if (fs.existsSync(reportPath)) {
            console.log(fs.readFileSync(reportPath, 'utf-8'));
        } else {
            console.log(`[!] Final report not yet generated for ${analysisId}. Current status: ${workspace.loadJson('analysis.json')?.status || 'UNKNOWN'}`);
        }
    } catch (e) {
        console.error(`[-] Failed to display report: ${e.message}`);
    }
  });

// ==========================================
// Command: reset
// ==========================================
program.command('reset')
  .description('Reset an analysis run or purge database records and workspaces')
  .argument('<analysis-id>', 'ID of the analysis to reset')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .option('--delete-files', 'Delete workspace directory and files on disk', false)
  .action((analysisId, options) => {
    try {
        const dbPath = path.join(options.outputDir, 'hwsec.db');
        if (fs.existsSync(dbPath)) {
            const db = new Database(dbPath);
            db.deleteAnalysisRun(analysisId);
            db.close();
            console.log(`[+] Database records for analysis ${analysisId} purged.`);
        }

        const runDir = path.join(options.outputDir, analysisId);
        if (fs.existsSync(runDir)) {
            if (options.deleteFiles) {
                fs.rmSync(runDir, { recursive: true, force: true });
                console.log(`[+] Workspace files deleted for analysis ${analysisId} at: ${runDir}`);
            } else {
                const analysisPath = path.join(runDir, 'analysis.json');
                if (fs.existsSync(analysisPath)) {
                    const analysis = JSON.parse(fs.readFileSync(analysisPath, 'utf-8'));
                    analysis.status = AnalysisStatus.PLANNED;
                    analysis.execution_started = false;
                    delete analysis.started_at;
                    delete analysis.completed_at;
                    delete analysis.approved_at;
                    delete analysis.results;
                    fs.writeFileSync(analysisPath, JSON.stringify(analysis, null, 2), 'utf-8');
                }
                const statusPath = path.join(runDir, 'status.md');
                if (fs.existsSync(statusPath)) {
                    fs.writeFileSync(statusPath, `# Status\n\nPhase: PLANNED\nExecution: Reset to initial plan\n`, 'utf-8');
                }
                console.log(`[+] Workspace ${analysisId} reset to PLANNED state.`);
            }
        } else {
            console.log(`[*] Workspace directory ${runDir} does not exist.`);
        }
    } catch (e) {
        console.error(`[-] Failed to reset analysis: ${e.message}`);
        process.exit(1);
    }
  });

// ==========================================
// Command: refine
// ==========================================
program.command('refine')
  .description('Refine analysis (fuzzer dictionary generation)')
  .argument('<analysis-id>', 'ID of the analysis to refine')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (analysisId, options) => {
    try {
        const configPath = path.resolve(options.config);
        const config = loadConfig(configPath);
        const workspace = Workspace.load(options.outputDir, analysisId);
        const analysis = workspace.loadJson('analysis.json');
        if (!analysis) {
            console.error(`[-] Analysis ${analysisId} not found.`);
            return;
        }

        const hypotheses = workspace.loadJson('hypotheses/hypotheses.json') || [];
        const verified = workspace.loadJson('findings/verified_findings.json') || [];
        const verifiedIds = verified.map(v => v.hypothesis_id);
        const refuted = hypotheses.filter(h => !verifiedIds.includes(h.hypothesis_id));

        if (refuted.length === 0) {
            console.log(`[*] No refuted hypotheses to refine.`);
            return;
        }

        console.log(`[*] Found ${refuted.length} refuted hypotheses. Initiating Refinement...`);
        const { LLMGateway } = await import('./core/llm/gateway.js');
        const { RefinerWorker } = await import('./workers/refiner.js');
        const llmGateway = new LLMGateway(config, null, 'refiner');
        const refiner = new RefinerWorker(llmGateway);

        const rtlFiles = analysis.inventory?.languages?.verilog || [];
        const result = await refiner.generateFuzzerDictionary(rtlFiles, refuted);

        const dictPath = path.join(workspace.outputDir, 'tools', 'fuzz_dict.txt');
        fs.writeFileSync(dictPath, result.dictionary_content, 'utf-8');
        analysis.refined = true;
        analysis.dict_path = dictPath;
        workspace.saveJson('analysis.json', analysis);
        console.log(`[+] Dictionary generated at ${dictPath}`);
    } catch (e) {
        console.error(`[-] Refinement failed: ${e.message}`);
    }
  });

program.parse(process.argv);
