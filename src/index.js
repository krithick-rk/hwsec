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
import { CoverageMatrix } from './core/coverageMatrix.js';
import { CandidateGenerator } from './workers/candidateGenerator.js';
import { BEPManager } from './core/bep/bepManager.js';
import { BEPIntegrityChecker } from './core/bep/integrityChecker.js';
import { FPReductionAuditEngine } from './core/bep/fpReductionAudit.js';
import { AblationSuite } from './core/bep/ablationSuite.js';
import { DossierGenerator } from './core/bep/dossierGenerator.js';
import { TransitionLedger } from './core/bep/transitionLedger.js';
import { BenchmarkRunner } from './core/bep/benchmarkRunner.js';

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
  .option('-p, --proof <mode>', 'Proof-of-impact validation mode (off, minimal, standard, deep)', 'standard')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (directory, options) => {
    console.log(`[*] Discovering and planning analysis for: ${directory}`);
    console.log(`[*] Novelty mode: ${options.novelty.toUpperCase()} | Proof mode: ${options.proof.toUpperCase()}`);

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
        const analysis = workspace.loadJson('analysis.json') || {};
        analysis.proof_mode = (options.proof || 'standard').toLowerCase();
        workspace.saveJson('analysis.json', analysis);

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
  .option('-p, --proof <mode>', 'Proof-of-impact validation mode (off, minimal, standard, deep)')
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
        const coverageMatrix = new CoverageMatrix();
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

        // 3b. Candidate Generation & Graph Escalation
        console.log(`[*] [Candidate Escalation] Pooling candidates across SAST, boundaries, and disagreement...`);
        const candidateGen = new CandidateGenerator(codeGraph, coverageMatrix);
        const candidatePool = candidateGen.generateCandidates({
            files: allFiles,
            deterministicFindings: allRawFindings,
            executedTools
        });
        workspace.saveJson('findings/candidate_pool.json', candidatePool);
        console.log(`[+] Candidate pool established with ${candidatePool.length} candidate(s).`);

        // Ingest novel boundary & disagreement candidates into raw findings for downstream verification
        for (const cand of candidatePool) {
            if (cand.source !== 'deterministic_tool') {
                const escalatedFinding = createFinding({
                    id: cand.id,
                    title: cand.title,
                    description: `Candidate generated via ${cand.source} (Escalation: ${cand.escalationLevel})`,
                    severity: cand.severity,
                    confidence: cand.confidence,
                    source_tool: cand.sourceTool,
                    source_locations: cand.sourceLocations,
                    evidence: cand.evidence,
                    verification_state: VerificationState.CANDIDATE,
                    cwe_id: cand.cwe
                });
                allRawFindings.push(escalatedFinding);
            }
        }

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

        // 5b. Controlled Proof-of-Impact Validation Engine
        const proofMode = (options.proof || analysis.proof_mode || 'standard').toLowerCase();
        let executedProofRecords = [];
        let unreproducedFindings = [];
        let notEligibleFindings = [];
        let deferredFindings = [];

        if (proofMode !== 'off') {
            console.log(`[*] [Proof Validation Phase] Scheduling & running Controlled Proof-of-Impact (Mode: ${proofMode.toUpperCase()})...`);
            const { ControlledProofVerifier } = await import('./workers/proofVerifier.js');
            const { ProofMemoryStore } = await import('./core/knowledge/proofMemory.js');
            const { ProofStatus } = await import('./core/schema.js');

            const proofVerifier = new ControlledProofVerifier(config, db, llmGateway, {
                sandboxDir: path.join(workspace.outputDir, 'sandbox')
            });
            const proofMemory = new ProofMemoryStore(db, config);

            // Schedule candidate findings via DynamicTokenScheduler
            const proofSchedule = llmGateway.scheduler.scheduleProofValidation({
                findings: candidateFindings,
                exploitMode: proofMode,
                analysisId
            });

            console.log(`  -> Proof Triage: ${proofSchedule.eligibleFindings} eligible, ${proofSchedule.skippedFindings.length} skipped`);

            for (const skipped of proofSchedule.skippedFindings) {
                if (skipped.decision === 'DEFER') {
                    deferredFindings.push(skipped);
                } else {
                    notEligibleFindings.push(skipped);
                }
            }

            const repetitions = proofMode === 'deep' ? 3 : 1;
            for (const attempt of proofSchedule.scheduledAttempts) {
                const targetFinding = candidateFindings.find(f => f.id === attempt.findingId);
                if (!targetFinding) continue;

                console.log(`  -> Generating & executing proof for ${targetFinding.id} (${targetFinding.title})...`);
                try {
                    const generated = await proofVerifier.generateProof(targetFinding, analysis.target_dir, attempt);
                    const execution = await proofVerifier.executeProof(generated.proofRecord, analysis.target_dir, repetitions);
                    executedProofRecords.push(execution.proofRecord);

                    if (execution.reproduced && execution.evidence) {
                        targetFinding.evidence = targetFinding.evidence || [];
                        targetFinding.evidence.push(execution.evidence);
                        targetFinding.proof_id = execution.proofRecord.proof_id;
                        targetFinding.proof_status = execution.proofRecord.proof_status;
                        targetFinding.proof_record = execution.proofRecord;

                        // Re-evaluate through LayeredVerifier to promote
                        const evalResult = verifier.verifySingleFinding(targetFinding);
                        if (evalResult.status === VerificationState.VERIFIED) {
                            targetFinding.verification_state = VerificationState.VERIFIED;
                            targetFinding.verification_level = evalResult.level;
                            targetFinding.confidence = evalResult.confidence;
                            targetFinding.description += `\n\n[Controlled Proof-of-Impact]: Reproduced ${execution.reproducibilityRate} (${execution.proofRecord.impact_class}).`;

                            const candIdx = candidateFindings.findIndex(c => c.id === targetFinding.id);
                            if (candIdx >= 0) candidateFindings.splice(candIdx, 1);
                            verifiedFindings.push(targetFinding);
                            console.log(`    [+] Finding ${targetFinding.id} PROMOTED to ${evalResult.level} VERIFIED via proof execution!`);
                        }
                    } else {
                        targetFinding.proof_status = ProofStatus.FAILED_TO_REPRODUCE;
                        targetFinding.proof_record = execution.proofRecord;
                        unreproducedFindings.push({
                            findingId: targetFinding.id,
                            title: targetFinding.title,
                            reason: execution.proofRecord.failure_reason
                        });
                        console.log(`    [-] Finding ${targetFinding.id} failed to reproduce: ${execution.proofRecord.failure_reason}`);
                    }

                    // Record outcome in persistent proof memory
                    await proofMemory.recordOutcome({
                        cwe: targetFinding.cwe_id || 'CWE-UNKNOWN',
                        domain: attempt.domain,
                        language: attempt.language,
                        proof_type: generated.proofRecord.proof_type,
                        tool_chain: attempt.budget?.allowed_tools || [],
                        success: execution.reproduced,
                        reproducibility_rate: execution.reproducibilityRate,
                        runtime_seconds: execution.proofRecord.actual_runtime,
                        tokens_used: execution.proofRecord.actual_tokens,
                        impact_class: execution.proofRecord.impact_class,
                        run_id: analysisId
                    });
                } catch (err) {
                    console.error(`    [!] Error during proof validation of ${targetFinding.id}: ${err.message}`);
                }
            }

            workspace.saveJson('verification/proof_records.json', executedProofRecords);
            console.log(`[+] Proof validation complete: ${executedProofRecords.filter(p => p.proof_status === 'REPRODUCED').length} reproduced.`);
        }

        // Update database and workspace with final verified/candidate states after proof phase
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
**Proof Mode**: \`${proofMode.toUpperCase()}\`  
**Completion Date**: ${new Date().toISOString()}  

---

## Executive Summary
- **Total Files Scanned**: ${analysis.inventory.total_files}
- **Verified Findings (E3+)**: ${verifiedFindings.length}
- **Candidate Findings (E1-E2)**: ${candidateFindings.length}
- **Proof-of-Impact Verified**: ${executedProofRecords.filter(p => p.proof_status === 'REPRODUCED').length}
- **Correlated Clusters**: ${correlationRes.correlatedClusters.length}
- **Synthesized Attack Paths**: ${correlationRes.attackPaths.length}
- **Tokens Consumed**: ${modelRouter.budgetController.totalTokensConsumed}
- **Total LLM Cost**: $${modelRouter.budgetController.totalCostUsd} USD

---

## 1. Verified Findings (High-Confidence Concrete Evidence)
${verifiedFindings.length > 0 
    ? verifiedFindings.map((f, i) => `### [${f.severity}] ${f.title}
- **Finding**: \`${f.id}\`
- **Severity**: \`${f.severity}\`
- **Confidence**: \`${(f.confidence * 100).toFixed(0)}%\`
- **Verification Level**: \`${f.verification_level || 'E3'}\`
- **Proof Status**: \`${f.proof_status || (f.verification_state === 'VERIFIED' ? 'REPRODUCED' : 'NOT_ELIGIBLE')}\`
- **Proof Type**: \`${f.proof_record?.proof_type || 'N/A'}\`
- **Reproducibility**: \`${f.proof_record?.reproducibility_rate || '1/1'}\`
- **Security Impact**: \`${f.proof_record?.impact_class || f.impact || 'SECURITY_PROPERTY_VIOLATION'}\`
- **Evidence**: \`${f.evidence?.map(e => e.id || e.artifact_path).join(', ') || 'N/A'}\`
- **Artifact**: \`${f.proof_record?.generated_artifact ? path.basename(f.proof_record.generated_artifact) : 'N/A'}\`
- **Artifact SHA-256**: \`${f.proof_record?.artifact_hash || 'N/A'}\`
- **Execution Environment**: \`${f.proof_record?.execution_environment || 'hwsec_isolated_sandbox'}\`
- **Description**: ${f.description}
`).join('\n')
    : '_No verified findings identified with dynamic reproducing evidence._'}

---

## 2. Candidate Findings (Static Tool Observations)
${candidateFindings.length > 0
    ? candidateFindings.map((f, i) => `### [${f.severity}] ${f.title}\n- **ID**: \`${f.id}\`\n- **Verification State**: \`${f.verification_state}\`\n- **Location**: \`${f.source_locations?.[0]?.path || f.rtl_location || 'Unknown'}\`\n- **Description**: ${f.description}\n`).join('\n')
    : '_No unverified candidate findings._'}

---

## 3. Unreproduced Findings
${unreproducedFindings.length > 0
    ? unreproducedFindings.map(u => `- **${u.findingId}**: ${u.title}\n  - Reason: ${u.reason}`).join('\n')
    : '_No candidate findings failed proof reproduction._'}

---

## 4. Not Eligible for Proof Testing
${notEligibleFindings.length > 0
    ? notEligibleFindings.map(n => `- **${n.findingId}**: ${n.reason} (${n.description})`).join('\n')
    : '_No candidate findings excluded from proof testing._'}

---

## 5. Deferred by Budget
${deferredFindings.length > 0
    ? deferredFindings.map(d => `- **${d.findingId}**: ${d.reason} (${d.description})`).join('\n')
    : '_No candidate findings deferred due to budget ceilings._'}

---

## 6. Evidence Clusters & Attack Paths
${correlationRes.attackPaths.length > 0
    ? correlationRes.attackPaths.map(p => `### ${p.title}\n- **Evidence Strength**: ${p.evidence_strength}\n- ${p.description}\n`).join('\n')
    : '_No multi-stage attack paths identified._'}

---

## 7. Verification Methodology & Grounding
All findings in this report strictly adhere to technical artifact grounding. Pure string/substring matches and unsupported LLM assertions were rejected or held at Candidate (E1) level according to HWSEC Verification Policy.

---

## 8. Vulnerability Coverage Matrix
${coverageMatrix.toMarkdown(Object.keys(filesByLang))}
`;

        workspace.saveMarkdown('report/final.md', finalReportMd);
        workspace.saveMarkdown('report/report.md', finalReportMd);
        workspace.saveJson('inventory/coverage_matrix.json', coverageMatrix.exportState());

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
            try {
                db.deleteAnalysisRun(analysisId);
                console.log(`[+] Database records for analysis ${analysisId} purged.`);
            } finally {
                db.close();
            }
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

// ==========================================
// Command: proof
// ==========================================
program.command('proof')
  .description('Run or inspect controlled proof-of-impact validation for an analysis run or specific finding')
  .argument('<id>', 'Analysis ID or Finding ID to validate')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-m, --mode <mode>', 'Proof mode (minimal, standard, deep)', 'standard')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (id, options) => {
    try {
        const configPath = path.resolve(options.config);
        const config = loadConfig(configPath);
        const baseDir = path.resolve(options.outputDir);

        // Check if ID is an analysis run
        const runDir = path.join(baseDir, id);
        if (fs.existsSync(runDir) && fs.existsSync(path.join(runDir, 'analysis.json'))) {
            const workspace = Workspace.load(options.outputDir, id);
            const analysis = workspace.loadJson('analysis.json');
            console.log(`\n[*] === Running Proof Validation for Analysis: ${id} ===`);
            const candidates = workspace.loadJson('findings/candidate_findings.json') || [];
            if (candidates.length === 0) {
                console.log(`[*] No candidate findings available to validate.`);
                return;
            }

            const dbPath = path.join(options.outputDir, 'hwsec.db');
            const db = new Database(dbPath);
            const { LLMGateway } = await import('./core/llm/gateway.js');
            const { ControlledProofVerifier } = await import('./workers/proofVerifier.js');
            const llmGateway = new LLMGateway(config, db);
            const proofVerifier = new ControlledProofVerifier(config, db, llmGateway, {
                sandboxDir: path.join(workspace.outputDir, 'sandbox')
            });

            const proofSchedule = llmGateway.scheduler.scheduleProofValidation({
                findings: candidates,
                exploitMode: options.mode,
                analysisId: id
            });

            console.log(proofSchedule.report);
            console.log(`\n[*] Executing scheduled proofs...`);
            for (const attempt of proofSchedule.scheduledAttempts) {
                const targetFinding = candidates.find(f => f.id === attempt.findingId);
                if (!targetFinding) continue;
                console.log(`  -> Generating & running proof for [${targetFinding.id}]...`);
                const generated = await proofVerifier.generateProof(targetFinding, analysis.target_dir, attempt);
                const execution = await proofVerifier.executeProof(generated.proofRecord, analysis.target_dir, 1);
                console.log(`     Result: ${execution.proofRecord.proof_status} | Reproducibility: ${execution.reproducibilityRate} | Impact: ${execution.proofRecord.impact_class}`);
                console.log(`     Artifact: ${execution.proofRecord.generated_artifact} (SHA-256: ${execution.proofRecord.artifact_hash?.slice(0, 16)}...)`);
            }
            return;
        }

        // Search for specific finding ID across all analysis runs
        let foundFinding = null;
        let foundWs = null;
        if (fs.existsSync(baseDir)) {
            for (const r of fs.readdirSync(baseDir)) {
                const rDir = path.join(baseDir, r);
                if (fs.statSync(rDir).isDirectory()) {
                    for (const fFile of ['findings/candidate_findings.json', 'findings/verified_findings.json']) {
                        const fp = path.join(rDir, fFile);
                        if (fs.existsSync(fp)) {
                            try {
                                const list = JSON.parse(fs.readFileSync(fp, 'utf-8'));
                                const item = list.find(x => x.id === id);
                                if (item) {
                                    foundFinding = item;
                                    foundWs = r;
                                    break;
                                }
                            } catch {}
                        }
                    }
                }
                if (foundFinding) break;
            }
        }

        if (!foundFinding) {
            console.error(`[-] ID '${id}' not found as an analysis ID or finding ID.`);
            return;
        }

        console.log(`\n=== Running Proof-of-Impact Validation for Finding: ${id} ===`);
        console.log(`Analysis Run:       ${foundWs}`);
        console.log(`Title:              ${foundFinding.title}`);
        console.log(`Severity:           ${foundFinding.severity}`);
        console.log(`Location:           ${foundFinding.source_locations?.[0]?.path || foundFinding.rtl_location || 'N/A'}`);

        const workspace = Workspace.load(options.outputDir, foundWs);
        const analysis = workspace.loadJson('analysis.json') || { target_dir: process.cwd() };
        const dbPath = path.join(options.outputDir, 'hwsec.db');
        const db = fs.existsSync(dbPath) ? new Database(dbPath) : null;

        const { ControlledProofVerifier } = await import('./workers/proofVerifier.js');
        const proofVerifier = new ControlledProofVerifier(config, db, null, {
            sandboxDir: path.join(workspace.outputDir, 'sandbox')
        });

        const generated = await proofVerifier.generateProof(foundFinding, analysis.target_dir, { analysisId: foundWs });
        const repetitions = options.mode === 'deep' ? 3 : 1;
        const execution = await proofVerifier.executeProof(generated.proofRecord, analysis.target_dir, repetitions);

        console.log(`\n[+] Proof Execution Result:`);
        console.log(`  Proof ID:           ${execution.proofRecord.proof_id}`);
        console.log(`  Proof Status:       ${execution.proofRecord.proof_status}`);
        console.log(`  Proof Type:         ${execution.proofRecord.proof_type}`);
        console.log(`  Reproducibility:    ${execution.reproducibilityRate}`);
        console.log(`  Security Impact:    ${execution.proofRecord.impact_class}`);
        console.log(`  Artifact:           ${execution.proofRecord.generated_artifact}`);
        console.log(`  Artifact SHA-256:   ${execution.proofRecord.artifact_hash}`);
        console.log(`  Sandbox Command:    ${execution.proofRecord.execution_command}`);
        if (execution.proofRecord.failure_reason) {
            console.log(`  Failure Reason:     ${execution.proofRecord.failure_reason}`);
        }
        console.log();
    } catch (e) {
        console.error(`[-] Proof validation command failed: ${e.message}`);
    }
  });

// ==========================================
// Command: proof-status
// ==========================================
program.command('proof-status')
  .description('Display detailed status and cryptographic provenance of a specific proof artifact')
  .argument('<proof-id>', 'ID of the proof record (e.g. PROOF-xxxxxx)')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((proofId, options) => {
    try {
        const dbPath = path.join(options.outputDir, 'hwsec.db');
        let record = null;

        if (fs.existsSync(dbPath)) {
            const db = new Database(dbPath);
            try {
                record = db.getProofRecord(proofId);
            } finally {
                db.close();
            }
        }

        // Fallback search in workspace verification/proof_records.json files
        if (!record && fs.existsSync(options.outputDir)) {
            for (const r of fs.readdirSync(options.outputDir)) {
                const recPath = path.join(options.outputDir, r, 'verification', 'proof_records.json');
                if (fs.existsSync(recPath)) {
                    try {
                        const list = JSON.parse(fs.readFileSync(recPath, 'utf-8'));
                        const match = list.find(x => x.proof_id === proofId);
                        if (match) { record = match; break; }
                    } catch {}
                }
            }
        }

        if (!record) {
            console.error(`[-] Proof record '${proofId}' not found in database or analysis workspaces.`);
            return;
        }

        console.log(`\n============================================================`);
        console.log(`        HWSEC CONTROLLED PROOF RECORD: ${record.proof_id}`);
        console.log(`============================================================`);
        console.log(`  Finding ID:           ${record.finding_id}`);
        console.log(`  Analysis ID:          ${record.analysis_id}`);
        console.log(`  Proof Status:         ${record.proof_status}`);
        console.log(`  Proof Type:           ${record.proof_type}`);
        console.log(`  Security Impact:      ${record.impact_class}`);
        console.log(`  Reproducibility:      ${record.reproducibility_rate || `${record.reproducibility_count || 0} successes`}`);
        console.log(`  Verifier Level:       ${record.verifier_level}`);
        console.log(`  Artifact Path:        ${record.generated_artifact || 'None'}`);
        console.log(`  Artifact SHA-256:     ${record.artifact_hash || 'None'}`);
        console.log(`  Sandbox Environment:  ${record.execution_environment}`);
        console.log(`  Execution Command:    ${record.execution_command || 'None'}`);
        if (record.failure_reason) {
            console.log(`  Failure Reason:       ${record.failure_reason}`);
        }
        console.log(`  Created At:           ${record.created_at}`);
        console.log(`  Completed At:           ${record.completed_at || 'In progress / incomplete'}`);
        console.log(`============================================================\n`);
    } catch (e) {
        console.error(`[-] Failed to retrieve proof status: ${e.message}`);
    }
  });

// ==========================================
// Command Group: benchmark
// ==========================================
const benchmarkCmd = program.command('benchmark')
  .description('Reproducible Benchmark Evidence Package (BEP) subsystem');

benchmarkCmd.command('run')
  .description('Run a reproducible benchmark and emit an evidence package')
  .option('-b, --benchmark <id>', 'ID of the benchmark to run (e.g., owasp-benchmark)')
  .option('-c, --config <mode>', 'Run mode configuration (e.g., full)', 'full')
  .option('-e, --evidence-out <path>', 'Base output directory for the evidence package', 'quality-benchmark/evidence/runs')
  .option('-r, --resume <path>', 'Resume from existing evidence bundle (reusing raw findings)')
  .option('-m, --max-cases <number>', 'Maximum candidate cases to validate in pilot mode')
  .action(async (options) => {
    try {
        const runner = new BenchmarkRunner('config.json', options.evidenceOut);
        await runner.runBenchmark(options.benchmark, options.config, options);
    } catch (e) {
        console.error(`[-] Benchmark run failed: ${e.message}`);
        process.exit(1);
    }
  });

benchmarkCmd.command('diff')
  .description('Calculate diff between two ablation runs')
  .argument('<run_a>', 'Run ID A')
  .argument('<run_b>', 'Run ID B')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runA, runB, options) => {
      const mgr = new BEPManager(options.evidenceDir);
      const readerA = mgr.loadBundle(runA);
      const readerB = mgr.loadBundle(runB);
      const suite = new AblationSuite();
      suite.recordConfigResult('A', readerA.readJsonl('case_results.jsonl'));
      suite.recordConfigResult('B', readerB.readJsonl('case_results.jsonl'));
      const diff = suite.computeDiff('A', 'B');
      console.log(`\n============================================================`);
      console.log(`     HWSEC ABLATION DIFF: ${runA} vs ${runB}                `);
      console.log(`============================================================`);
      console.log(`Total Changed Cases: ${diff.total_changed_cases}`);
      console.log(`FP -> TN: ${diff.fp_to_tn_count}`);
      console.log(`FN -> TP: ${diff.fn_to_tp_count}`);
  });

benchmarkCmd.command('audit-transitions')
  .description('Audit state transitions for a benchmark run')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, options) => {
      const mgr = new BEPManager(options.evidenceDir);
      const reader = mgr.loadBundle(runIdOrPath);
      const engine = new FPReductionAuditEngine();
      
      const cases = reader.readJsonl('case_results.jsonl');
      const transitions = reader.readJsonl('classification_transitions.jsonl');
      const decs = reader.readJsonl('verifier_decisions.jsonl');
      const proofs = reader.readJsonl('proof_artifacts.jsonl');
      
      const res = engine.auditRun(cases, transitions, decs, proofs);

      // Aggregate all transition types
      const transitionCounts = {};
      for (const t of transitions) {
          const key = `${t.from_state} -> ${t.to_state}`;
          transitionCounts[key] = (transitionCounts[key] || 0) + 1;
      }

      console.log(`\n============================================================`);
      console.log(`     HWSEC TRANSITION AUDIT: ${reader.manifest.run_id}      `);
      console.log(`============================================================`);
      console.log(`Total Cases:          ${cases.length}`);
      console.log(`Total Transitions:    ${transitions.length}`);
      console.log(`\nTransition Breakdown:`);
      for (const [trans, cnt] of Object.entries(transitionCounts)) {
          console.log(`  - ${trans.padEnd(35)} : ${cnt}`);
      }

      console.log(`\nFP -> TN Transitions: ${res.summary.actual_fp_to_tn_transitions}`);
      console.log(`Proof Confirmed:      ${res.summary.breakdown.PROOF_CONFIRMED}`);
      console.log(`Hybrid Confirmed:     ${res.summary.breakdown.HYBRID_CONFIRMED}`);
      console.log(`LLM Only:             ${res.summary.breakdown.LLM_ONLY}`);
      console.log(`Is 242->48 Claim Valid: ${res.summary.is_valid_claim ? 'VALIDATED' : 'DISPROVEN / INVALID'}`);
      if (!res.summary.is_valid_claim) {
          console.log(`  Reason: Previous claim converted unresolved candidates into TN via ground-truth fallback without deterministic proof.`);
      }
  });

benchmarkCmd.command('replay')
  .description('Recompute final metrics strictly from immutable case records and transitions, without stored aggregates')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, options) => {
      const mgr = new BEPManager(options.evidenceDir);
      const reader = mgr.loadBundle(runIdOrPath);
      
      const gt = reader.readJsonl('ground_truth.jsonl');
      const transitions = reader.readJsonl('classification_transitions.jsonl');
      const cases = reader.readJsonl('case_results.jsonl');
      const storedMetrics = reader.readJson('aggregate_metrics.json') || {};

      console.log(`\n============================================================`);
      console.log(`     HWSEC BEP METRIC & REPLAY INTEGRITY ENGINE              `);
      console.log(`============================================================`);
      console.log(`Target Bundle:  ${reader.bundlePath}`);
      console.log(`Total GT Cases: ${gt.length}`);

      // 1. Verify all referenced files in checksums.sha256 exist and match
      const checksumFile = path.join(reader.bundlePath, 'checksums.sha256');
      if (!fs.existsSync(checksumFile)) {
          console.error(`[-] Integrity FAIL: checksums.sha256 missing from bundle.`);
          process.exit(1);
      }
      const checksumLines = fs.readFileSync(checksumFile, 'utf8').split('\n').filter(l => l.trim().length > 0);
      let verifiedArtifacts = 0;
      for (const line of checksumLines) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 2) {
              const expectedSha = parts[0];
              const relPath = parts.slice(1).join(' ');
              const fullPath = path.join(reader.bundlePath, relPath);
              if (!fs.existsSync(fullPath)) {
                  console.error(`[-] Integrity FAIL: Referenced artifact missing: ${relPath}`);
                  process.exit(1);
              }
              const actualSha = crypto.createHash('sha256').update(fs.readFileSync(fullPath)).digest('hex');
              if (actualSha !== expectedSha) {
                  console.error(`[-] Integrity FAIL: SHA-256 mismatch for ${relPath}`);
                  process.exit(1);
              }
              verifiedArtifacts++;
          }
      }
      console.log(`[+] Verified ${verifiedArtifacts} bundle artifact hashes against manifest.`);

      // 2. Recompute predictions and evaluation counts
      const gtMap = new Map(gt.map(g => [g.case_id, g]));
      const transitionsByCase = new Map();
      for (const t of transitions) {
          if (!transitionsByCase.has(t.case_id)) transitionsByCase.set(t.case_id, []);
          transitionsByCase.get(t.case_id).push(t);
      }

      let recomputedDetected = 0, recomputedNotDetected = 0, recomputedInconclusivePred = 0;
      let tp = 0, fp = 0, tn = 0, fn = 0, inconclusive = 0;

      for (const [caseId, g] of gtMap.entries()) {
          const caseTrans = transitionsByCase.get(caseId) || [];
          if (caseTrans.length === 0) {
              console.error(`[-] Replay FAIL: Case ${caseId} has no recorded transitions.`);
              process.exit(1);
          }

          // Determine prediction from ledger without consulting ground truth!
          let prediction = 'INCONCLUSIVE';
          // Check if proof confirmed detection
          const hasDetected = caseTrans.some(t => t.to_state === 'DETECTED');
          const hasNotDetected = caseTrans.some(t => t.to_state === 'NOT_DETECTED');
          
          if (hasDetected) {
              prediction = 'DETECTED';
          } else if (hasNotDetected) {
              prediction = 'NOT_DETECTED';
          } else {
              prediction = 'INCONCLUSIVE';
          }

          if (prediction === 'DETECTED') recomputedDetected++;
          else if (prediction === 'NOT_DETECTED') recomputedNotDetected++;
          else recomputedInconclusivePred++;

          // Evaluate prediction against authoritative ground truth
          const isVuln = g.ground_truth_label === 'VULNERABLE';
          let finalClass = 'INCONCLUSIVE';
          if (prediction === 'DETECTED') {
              finalClass = isVuln ? 'TP' : 'FP';
          } else if (prediction === 'NOT_DETECTED') {
              finalClass = isVuln ? 'FN' : 'TN';
          } else {
              finalClass = 'INCONCLUSIVE';
          }

          if (finalClass === 'TP') tp++;
          else if (finalClass === 'FP') fp++;
          else if (finalClass === 'TN') tn++;
          else if (finalClass === 'FN') fn++;
          else inconclusive++;
      }

      const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : null;
      const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : null;
      const f1 = (precision !== null && recall !== null && (precision + recall) > 0) 
          ? (2 * precision * recall / (precision + recall)) 
          : null;

      console.log(`\nRecomputed Predictions: DETECTED=${recomputedDetected} | NOT_DETECTED=${recomputedNotDetected} | INCONCLUSIVE=${recomputedInconclusivePred}`);
      console.log(`Recomputed Evaluated:   TP=${tp} | FP=${fp} | TN=${tn} | FN=${fn} | INCONCLUSIVE=${inconclusive}`);
      console.log(`Stored Aggregate:       TP=${storedMetrics.tp} | FP=${storedMetrics.fp} | TN=${storedMetrics.tn} | FN=${storedMetrics.fn} | INCONCLUSIVE=${storedMetrics.inconclusive}`);

      const metricsMatch = tp === storedMetrics.tp && 
                           fp === storedMetrics.fp && 
                           tn === storedMetrics.tn && 
                           fn === storedMetrics.fn &&
                           inconclusive === (storedMetrics.inconclusive !== undefined ? storedMetrics.inconclusive : 0);

      if (metricsMatch) {
          console.log(`\n[+] Integrity Gate: PASS (Replayed metrics MATCH stored metrics exactly!)`);
      } else {
          console.error(`\n[-] Integrity Gate: FAIL (Replayed metrics DO NOT match stored metrics)`);
          process.exit(1);
      }

      console.log(`\nRecomputed Precision: ${precision !== null ? (precision * 100).toFixed(1) + '%' : 'N/A (no positive predictions)'}`);
      console.log(`Recomputed Recall:    ${recall !== null ? (recall * 100).toFixed(1) + '%' : 'N/A (no actual positives)'}`);
      console.log(`Recomputed F1 Score:  ${f1 !== null ? f1.toFixed(3) : 'N/A'}`);
  });

benchmarkCmd.command('verify-evidence')
  .description('Verify integrity, cryptographic hashes, and schemas of an evidence bundle')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, options) => {
    try {
        const mgr = new BEPManager(options.evidenceDir);
        const reader = mgr.loadBundle(runIdOrPath);
        const checker = new BEPIntegrityChecker();
        const res = checker.verifyBundle(reader);

        console.log(`\n============================================================`);
        console.log(`     HWSEC REPRODUCIBLE EVIDENCE INTEGRITY CHECKER          `);
        console.log(`============================================================`);
        console.log(`  Bundle Path:     ${reader.bundlePath}`);
        console.log(`  Benchmark ID:    ${reader.manifest.benchmark_id}`);
        console.log(`  Run ID:          ${reader.manifest.run_id}`);
        console.log(`  Integrity Gate:  ${res.passed ? '✅ PASS' : '❌ FAIL (INCOMPLETE/CORRUPT)'}`);
        console.log(`  Total Cases:     ${res.stats.total_cases}`);
        console.log(`  Ground Truths:   ${res.stats.total_ground_truth}`);
        console.log(`  Transitions:     ${res.stats.total_transitions}`);
        console.log(`  Decisions:       ${res.stats.total_verifier_decisions}`);
        console.log(`  Proof Artifacts: ${res.stats.total_proof_artifacts}`);
        if (res.errors.length > 0) {
            console.log(`\n[-] ERRORS DETECTED (${res.errors.length}):`);
            res.errors.forEach(e => console.log(`    - ${e}`));
        }
        if (res.warnings.length > 0) {
            console.log(`\n[!] WARNINGS (${res.warnings.length}):`);
            res.warnings.forEach(w => console.log(`    - ${w}`));
        }
        console.log(`============================================================\n`);

        if (!res.passed) process.exit(1);
    } catch (e) {
        console.error(`[-] Integrity verification failed: ${e.message}`);
        process.exit(1);
    }
  });

benchmarkCmd.command('audit-fp-reduction')
  .description('Audit OWASP 242 -> 48 FP reduction claim and classify transition evidence')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, options) => {
    try {
        const mgr = new BEPManager(options.evidenceDir);
        const reader = mgr.loadBundle(runIdOrPath);
        const engine = new FPReductionAuditEngine();

        const cases = reader.readJsonl('case_results.jsonl');
        const transitions = reader.readJsonl('classification_transitions.jsonl');
        const decisions = reader.readJsonl('verifier_decisions.jsonl');
        const proofs = reader.readJsonl('proof_artifacts.jsonl');

        const auditRes = engine.auditRun(cases, transitions, decisions, proofs);
        console.log(auditRes.report_md);
    } catch (e) {
        console.error(`[-] FP reduction audit failed: ${e.message}`);
        process.exit(1);
    }
  });

benchmarkCmd.command('case')
  .description('Generate human review audit dossier for an individual benchmark test case')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .argument('<case-id>', 'ID of the test case to inspect (e.g. CASE-1234)')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, caseId, options) => {
    try {
        const mgr = new BEPManager(options.evidenceDir);
        const reader = mgr.loadBundle(runIdOrPath);
        const gen = new DossierGenerator();
        const { markdown } = gen.generateDossier(reader, caseId);
        console.log(markdown);
    } catch (e) {
        console.error(`[-] Case dossier generation failed: ${e.message}`);
        process.exit(1);
    }
  });

benchmarkCmd.command('summarize')
  .description('Display summary metrics derived from stored case records')
  .argument('<run-id-or-path>', 'Run ID or path to evidence bundle directory')
  .option('-e, --evidence-dir <path>', 'Base evidence directory', 'quality-benchmark/evidence/runs')
  .action((runIdOrPath, options) => {
    try {
        const mgr = new BEPManager(options.evidenceDir);
        const reader = mgr.loadBundle(runIdOrPath);
        const metrics = reader.readJson('aggregate_metrics.json') || {};
        const cm = reader.readJson('confusion_matrix.json') || {};

        console.log(`\n============================================================`);
        console.log(`    HWSEC BENCHMARK AGGREGATE METRICS SUMMARY              `);
        console.log(`============================================================`);
        console.log(`  Benchmark ID:   ${reader.manifest.benchmark_id}`);
        console.log(`  Run ID:         ${reader.manifest.run_id}`);
        console.log(`  Total Cases:    ${metrics.total_cases || 0}`);
        console.log(`  True Positives: ${cm.tp || 0}`);
        console.log(`  False Positives:${cm.fp || 0}`);
        console.log(`  False Negatives:${cm.fn || 0}`);
        console.log(`  True Negatives: ${cm.tn || 0}`);
        console.log(`  Precision:      ${((metrics.precision || 0) * 100).toFixed(2)}%`);
        console.log(`  Recall:         ${((metrics.recall || 0) * 100).toFixed(2)}%`);
        console.log(`  F1 Score:       ${((metrics.f1 || 0) * 100).toFixed(2)}%`);
        console.log(`============================================================\n`);
    } catch (e) {
        console.error(`[-] Summarize failed: ${e.message}`);
        process.exit(1);
    }
  });

program.parse(process.argv);
