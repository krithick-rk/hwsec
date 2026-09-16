import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { loadConfig } from './config.js';
import { Workspace } from './workspace.js';
import { Database } from './db.js';
import { AnalysisStatus, assertTransition } from './state.js';
import { AnalysisBroker, BrokerCapability } from './broker.js';
import { LLMGateway } from './llm/gateway.js';
import { SuspicionEngine } from './suspicion/engine.js';
import { LayeredVerifier } from '../workers/verifier.js';
import { EvidenceCorrelationEngine } from '../workers/evidenceCorrelation.js';
import { createFinding, VerificationState } from './schema.js';
import { CodeGraph, NodeTypes, EdgeRelations } from './graph/codeGraph.js';
import { RAGEngine } from './knowledge/rag.js';
import { CoverageMatrix } from './coverageMatrix.js';
import { CandidateGenerator } from '../workers/candidateGenerator.js';
import { EntryPointInventory } from './inventory/entryPointInventory.js';
import { VulnerabilityHypothesis } from './hypothesis/vulnerabilityHypothesis.js';
import { AnalystDossier } from './analyst/analystDossier.js';
import { ProofSandbox } from './proofSandbox.js';
import { PovStatus } from './pov/povTypes.js';

/**
 * Runs the execution pipeline for an approved analysis.
 * Shared by both CLI (`hwsec proceed`) and Console (`proceed`).
 * 
 * @param {string} analysisId 
 * @param {Object} [options={}]
 * @param {Function} [progressCallback=null] - (step, total, name, status, extra) => void
 * @returns {Promise<Object>} Results of the execution
 */
export async function runAnalysisPipeline(analysisId, options = {}, progressCallback = null) {
    const notify = (step, total, name, status, extra = '') => {
        if (typeof progressCallback === 'function') {
            progressCallback(step, total, name, status, extra);
        }
    };

    const outputDir = options.outputDir || 'hwsec-output';
    const configPath = path.resolve(options.config || 'config.json');
    const config = loadConfig(configPath);
    const workspace = Workspace.load(outputDir, analysisId);
    const analysis = workspace.loadJson('analysis.json');

    if (!analysis) {
        throw new Error(`Analysis record not found for ID: ${analysisId}`);
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

    workspace.saveMarkdown('status.md', `# Status\n\nPhase: RUNNING\nStarted: ${analysis.started_at}\n`);

    // Initialize SQLite Database
    const dbPath = path.join(outputDir, 'hwsec.db');
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

    // Initialize Broker & Operational Subsystems
    const broker = new AnalysisBroker(config, null, db);
    const llmGateway = new LLMGateway(config, db);
    const modelRouter = llmGateway.router;
    const suspicionEngine = new SuspicionEngine(config);
    const ragEngine = new RAGEngine(db, config);
    const codeGraph = new CodeGraph();
    const coverageMatrix = new CoverageMatrix();
    const verifier = new LayeredVerifier(modelRouter, db, analysisId, codeGraph);

    // 1. File Fingerprinting & Incremental Check
    notify(1, 8, 'Inventory', 'RUNNING');
    const allFiles = [];
    const filesByLang = analysis.inventory?.languages || {};
    for (const [lang, files] of Object.entries(filesByLang)) {
        for (const f of files) {
            const absPath = path.resolve(analysis.target_dir, f);
            allFiles.push({ path: absPath, language: lang });
            codeGraph.addNode(absPath, NodeTypes.FILE, path.basename(absPath), { language: lang, path: absPath });
            if (fs.existsSync(absPath)) {
                const hash = Database.computeFileHash(absPath);
                db.checkIncrementalReuse(absPath, hash);
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
    notify(1, 8, 'Inventory', 'DONE');

    // 2. Deterministic Analysis Dispatch via AnalysisBroker
    const allRawFindings = [];
    const executedTools = [];
    const toolsOutputDir = path.join(workspace.outputDir, 'tools');
    const plannedCaps = analysis.planned_capabilities || [];

    // RTL Linting (Verilator)
    if (plannedCaps.includes('rtl_lint')) {
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
    const softwareLangs = ['python', 'java', 'c', 'cpp', 'go', 'javascript'];
    const softwareFiles = allFiles.filter(f => softwareLangs.includes(f.language)).map(f => f.path);
    if (softwareFiles.length > 0 && (plannedCaps.includes('sast_pattern_scan') || plannedCaps.length === 0)) {
        notify(2, 8, 'Semgrep', 'RUNNING');
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
        notify(2, 8, 'Semgrep', 'DONE');
    } else {
        notify(2, 8, 'Semgrep', 'SKIPPED');
    }

    // Code Property Graph / Dataflow (Joern)
    if (softwareFiles.length > 0 && plannedCaps.includes('graph_dataflow')) {
        notify(3, 8, 'Joern', 'RUNNING');
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
        notify(3, 8, 'Joern', 'DONE');
    } else {
        notify(3, 8, 'Joern', 'SKIPPED (optional unavailable)');
    }

    // Deep Dataflow (CodeQL)
    if (softwareFiles.length > 0 && plannedCaps.includes('deep_dataflow')) {
        notify(4, 8, 'CodeQL', 'RUNNING');
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
        notify(4, 8, 'CodeQL', 'DONE');
    } else {
        notify(4, 8, 'CodeQL', 'SKIPPED (optional unavailable)');
    }

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
    notify(5, 8, 'Entry-point discovery', 'RUNNING');
    const ranking = suspicionEngine.rankTargets(allFiles.map(f => ({
        path: f.path,
        findings: allRawFindings,
        executedTools,
        noveltyMode: analysis.novelty_mode
    })), 0.25);
    workspace.saveJson('report/suspicion_scores.json', ranking);

    // 3b. Candidate Generation & Graph Escalation
    const candidateGen = new CandidateGenerator(codeGraph, coverageMatrix);
    const candidatePool = candidateGen.generateCandidates({
        files: allFiles,
        deterministicFindings: allRawFindings,
        executedTools
    });
    workspace.saveJson('findings/candidate_pool.json', candidatePool);

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

    // 3c. Entry Point Inventory
    const epInventory = new EntryPointInventory();
    const entryPoints = epInventory.discover(analysis.target_dir);
    workspace.saveJson('inventory/entry_points.json', entryPoints);
    notify(5, 8, 'Entry-point discovery', 'DONE');

    // 4. Formulate Vulnerability Hypotheses
    notify(6, 8, 'Hypothesis generation', 'RUNNING');
    const operationalHypotheses = [];

    for (const finding of allRawFindings) {
        const hyp = VulnerabilityHypothesis.fromFinding({
            id: finding.id,
            cwe: finding.cwe_id || finding.type || 'CWE-OTHER',
            source: finding.taint_source || finding.source || 'USER_INPUT',
            sink: finding.taint_sink || finding.sink || `${finding.source_locations?.[0]?.path || finding.rtl_location || 'unknown'}:${finding.source_locations?.[0]?.line || 1}`,
            file: finding.source_locations?.[0]?.path || finding.rtl_location,
            line: finding.source_locations?.[0]?.line || 1,
            analyzer: finding.source_tool || finding.analyzer || 'static_scan',
            rule_id: finding.rule_id || finding.title || 'rule_match',
            confidence: finding.confidence || 0.5,
            attack_surface: 'CLI_OR_HTTP'
        }, { run_id: analysisId, repository_id: projectId });

        const resolvedEp = epInventory.resolveForHypothesis(hyp);
        hyp.setEntryPoint(resolvedEp);
        operationalHypotheses.push(hyp);

        db.saveHypothesis({
            id: hyp.id,
            runId: analysisId,
            claim: `${hyp.cwe} at ${hyp.sink}`,
            status: 'PLANNED',
            proposedTest: hyp.security_condition
        });
        codeGraph.addNode(hyp.id, NodeTypes.HYPOTHESIS, hyp.id, { cwe: hyp.cwe, sink: hyp.sink });
    }

    workspace.saveJson('hypotheses/hypotheses.json', operationalHypotheses.map(h => h.toJSON()));
    notify(6, 8, 'Hypothesis generation', 'DONE');

    // 5. Evidence-Driven Operational Pipeline
    notify(7, 8, 'Witness evaluation', 'RUNNING');
    const opMode = (options.mode || analysis.proof_mode || 'standard').toUpperCase();

    const operationalResults = [];
    const verifiedFindings = [];
    const candidateFindings = [];
    const inconclusiveFindings = [];
    const sandbox = new ProofSandbox({ baseDir: path.join(workspace.outputDir, 'sandbox') });

    for (const hyp of operationalHypotheses) {
        const stripLineNumber = (pathStr) => {
            if (!pathStr) return '';
            const s = String(pathStr);
            const lastColon = s.lastIndexOf(':');
            if (lastColon > 1) {
                const potentialLine = s.slice(lastColon + 1);
                if (/^\d+$/.test(potentialLine)) {
                    return s.slice(0, lastColon);
                }
            }
            return s;
        };
        const targetRel = stripLineNumber(hyp.candidate_path?.[0]) || hyp.entry_point?.file;
        const absTarget = targetRel ? (path.isAbsolute(targetRel) ? targetRel : path.resolve(analysis.target_dir, targetRel)) : null;

        // Define real execution runner for witness search
        const executor = async (probe) => {
            if (!absTarget || !fs.existsSync(absTarget)) {
                return { stdout: '', stderr: 'Target file not found', exitCode: 1, sink_observed: null };
            }
            const ext = path.extname(absTarget).toLowerCase();
            let cmd = process.execPath;
            let args = [absTarget, String(probe.value)];
            let execRes;

            if (ext === '.py') {
                cmd = process.platform === 'win32' ? 'py' : 'python3';
                args = [absTarget, String(probe.value)];
                execRes = sandbox.execute(cmd, args, { cwd: analysis.target_dir, timeout: 5000 });
            } else if (ext === '.java') {
                cmd = 'java';
                args = [absTarget, String(probe.value)];
                execRes = sandbox.execute(cmd, args, { cwd: analysis.target_dir, timeout: 5000 });
            } else if (ext === '.c') {
                const { ExecutionCapabilityManager, ExecutionCapability, BackendType } = await import('./execution/executionCapability.js');
                const execMgr = new ExecutionCapabilityManager();
                const selected = execMgr.select(ExecutionCapability.C_COMPILER, { cwd: analysis.target_dir });
                if (selected.backend !== BackendType.UNAVAILABLE) {
                    const binPath = path.join(analysis.target_dir, 'target_bin');
                    execMgr.execute([selected.executable || 'gcc', '-O0', absTarget, '-o', binPath], {
                        backend: selected.backend,
                        cwd: analysis.target_dir,
                        timeout: 10000
                    });
                    if (fs.existsSync(binPath)) {
                        execRes = execMgr.execute([binPath, String(probe.value)], {
                            backend: selected.backend,
                            cwd: analysis.target_dir,
                            timeout: 5000
                        });
                    }
                }
                if (!execRes) {
                    execRes = { stdout: '', stderr: 'C compilation failed or unavailable', exit_code: 1, timed_out: false };
                }
            } else if (ext === '.v' || ext === '.sv') {
                const { ExecutionCapabilityManager, ExecutionCapability, BackendType } = await import('./execution/executionCapability.js');
                const execMgr = new ExecutionCapabilityManager();
                const selected = execMgr.select(ExecutionCapability.VERILOG_SIMULATOR, { cwd: analysis.target_dir });
                if (selected.backend !== BackendType.UNAVAILABLE) {
                    const simPath = path.join(analysis.target_dir, 'target_sim');
                    execMgr.execute([selected.executable || 'iverilog', '-g2012', '-o', simPath, absTarget], {
                        backend: selected.backend,
                        cwd: analysis.target_dir,
                        timeout: 10000
                    });
                    if (fs.existsSync(simPath)) {
                        const vvpCmd = selected.backend === BackendType.WSL ? 'vvp' : 'vvp.exe';
                        execRes = execMgr.execute([vvpCmd, simPath], {
                            backend: selected.backend,
                            cwd: analysis.target_dir,
                            timeout: 5000
                        });
                    }
                }
                if (!execRes) {
                    execRes = { stdout: '', stderr: 'Verilog simulation failed or unavailable', exit_code: 1, timed_out: false };
                }
            } else {
                execRes = sandbox.execute(cmd, args, { cwd: analysis.target_dir, timeout: 5000 });
            }

            const stdout = execRes.stdout || '';
            const stderr = execRes.stderr || '';
            const exitCode = execRes.exit_code !== undefined ? execRes.exit_code : execRes.exitCode;
            const timedOut = !!execRes.timed_out || !!execRes.timedOut;
            return {
                stdout,
                stderr,
                exitCode,
                timedOut,
                parsed_result: {
                    sink_observed: stdout.includes('[APP_EXEC]') || stdout.includes('EXEC') ? 'exec' : null,
                    value_at_sink: probe.value
                }
            };
        };

        // 5a. Witness Search
        const searchRes = await broker.dispatch({
            capability: BrokerCapability.WITNESS_SEARCH,
            hypothesis: hyp,
            executor,
            mode: opMode
        });

        let obsRecord = null;
        let ctrlRecord = null;

        if (searchRes.status === 'WITNESS_FOUND' && searchRes.witness_input) {
            // 5b. Runtime Observation
            const obsRes = await broker.dispatch({
                capability: BrokerCapability.RUNTIME_OBSERVATION,
                target: { file: absTarget },
                input: searchRes.witness_input,
                executor
            });
            obsRecord = obsRes.observationRecord;

            // 5c. Causal Negative Control
            const ctrlRes = await broker.dispatch({
                capability: BrokerCapability.CONTROL_EXECUTION,
                controlType: 'NEGATIVE_INPUT',
                hypothesis: hyp,
                attackInput: searchRes.witness_input,
                benignInput: { parameter: hyp.source, value: 'benign_safe_input_123' },
                executor
            });
            ctrlRecord = ctrlRes.controlResult;
        }

        // 5d. Evidence Assembly
        const asmRes = await broker.dispatch({
            capability: BrokerCapability.EVIDENCE_ASSEMBLY,
            runId: analysisId,
            hypothesis: hyp,
            entryPoint: hyp.entry_point,
            witness: searchRes.witness_input,
            oracleResult: searchRes.oracle_result,
            observation: obsRecord,
            controlResult: ctrlRecord,
            provenanceManifest: {
                created_at: new Date().toISOString(),
                broker_version: '2.0.0',
                mode: opMode,
                analysis_id: analysisId,
                verified: true
            }
        });

        // 5e. Verdict Reduction via EvidenceAuthority
        const redRes = await broker.dispatch({
            capability: BrokerCapability.VERDICT_REDUCTION,
            dag: asmRes.dag,
            hypothesisId: hyp.id
        });

        const reduction = redRes.reduction;

        // 5f. Proof-of-Vulnerability (PoV) Generation & Replay
        let povArtifact = null;
        let povReplayLog = null;
        const effectivePovMode = (options.povMode || analysis.pov_mode || process.env.POV_MODE || 'on-detected').toLowerCase();
        const shouldGeneratePov = effectivePovMode !== 'disabled' && (
            effectivePovMode === 'always-eligible' ||
            (effectivePovMode === 'on-detected' && reduction.verdict === 'DETECTED') ||
            (options.generatePov && reduction.verdict === 'DETECTED')
        );

        if (shouldGeneratePov && searchRes.witness_input) {
            try {
                const povDir = path.join(workspace.outputDir, 'pov');
                const povRes = await broker.dispatch({
                    capability: BrokerCapability.POV_GENERATION,
                    hypothesis: hyp,
                    witnessInput: searchRes.witness_input,
                    negativeControl: ctrlRecord,
                    targetDir: analysis.target_dir,
                    outputDir: povDir
                });

                povArtifact = povRes.pov;

                if (povArtifact && povArtifact.status !== PovStatus.UNSAFE_TO_GENERATE) {
                    const verRes = await broker.dispatch({
                        capability: BrokerCapability.POV_VERIFICATION,
                        povBundleDir: povArtifact.bundle_path,
                        targetDirOverride: analysis.target_dir
                    });
                    povReplayLog = verRes.replay_log;
                    povArtifact.status = verRes.pov_status;
                    asmRes.dag.attachPoV(hyp.id, povArtifact, povReplayLog);
                }
            } catch (povErr) {
                // PoV generation failure does not downgrade proven DETECTED
            }
        }

        const dossier = AnalystDossier.generateCaseSummary(hyp, asmRes.dag, reduction, povArtifact, povReplayLog);

        workspace.saveJson(`evidence/dag_${hyp.id}.json`, asmRes.dag.exportDAG());
        workspace.saveJson(`evidence/dossier_${hyp.id}.json`, dossier);
        workspace.saveMarkdown(`evidence/dossier_${hyp.id}.md`, dossier.markdown_dossier);

        const findingMatch = allRawFindings.find(f => f.id === hyp.provenance?.origin_finding_id) || {
            id: hyp.id,
            title: `${hyp.cwe} Security Finding`,
            cwe_id: hyp.cwe,
            severity: 'HIGH',
            confidence: 0.9,
            source_locations: [{ path: absTarget, line: 1 }]
        };

        findingMatch.evidence_dag_hash = asmRes.dagHash;
        findingMatch.operational_verdict = reduction.verdict;
        findingMatch.reason_code = reduction.reason_code;

        if (reduction.verdict === 'DETECTED') {
            findingMatch.verification_state = VerificationState.VERIFIED;
            findingMatch.verification_level = 'E5';
            findingMatch.confidence = 0.95;
            verifiedFindings.push(findingMatch);
        } else if (reduction.verdict === 'NOT_DETECTED') {
            findingMatch.verification_state = VerificationState.REFUTED;
            candidateFindings.push(findingMatch);
        } else {
            findingMatch.verification_state = VerificationState.CANDIDATE;
            inconclusiveFindings.push(findingMatch);
            candidateFindings.push(findingMatch);
        }

        operationalResults.push({
            hypothesis_id: hyp.id,
            verdict: reduction.verdict,
            reason_code: reduction.reason_code,
            dag_hash: asmRes.dagHash,
            dossier_path: `evidence/dossier_${hyp.id}.md`,
            finding: findingMatch,
            pov: povArtifact
        });
    }

    notify(7, 8, 'Witness evaluation', 'DONE');

    // Update database with final states
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
    workspace.saveJson('evidence/operational_results.json', operationalResults);

    // Optional Legacy Verifier
    if (options.legacyVerifier) {
        await verifier.verify(operationalHypotheses, allRawFindings, {});
    }

    // 6. Evidence Correlation & Graph
    notify(8, 8, 'Evidence reduction', 'RUNNING');
    const correlator = new EvidenceCorrelationEngine(llmGateway);
    const correlationRes = await correlator.correlate([...verifiedFindings, ...candidateFindings], operationalHypotheses, {});
    codeGraph.syncToDatabase(db, analysisId);

    workspace.saveJson('report/evidence_graph.json', correlationRes.graph);
    workspace.saveJson('report/correlated_clusters.json', correlationRes.correlatedClusters);
    workspace.saveJson('report/attack_paths.json', correlationRes.attackPaths);

    // 7. Generate Final Human-Readable Security Report
    const detectedCount = operationalResults.filter(r => r.verdict === 'DETECTED').length;
    const notDetectedCount = operationalResults.filter(r => r.verdict === 'NOT_DETECTED').length;
    const inconclusiveCount = operationalResults.filter(r => r.verdict === 'INCONCLUSIVE').length;

    const finalReportMd = `# HWSEC Security Analysis Final Report

**Analysis ID**: \`${analysisId}\`  
**Target Repository**: \`${analysis.target_dir}\`  
**Operational Mode**: \`${opMode}\`  
**Completion Date**: ${new Date().toISOString()}  

---

## Executive Operational Verdict Summary
- **Total Files Scanned**: ${analysis.inventory?.total_files || allFiles.length}
- **Discovered Entry Points**: ${entryPoints.length}
- **Vulnerability Hypotheses**: ${operationalHypotheses.length}
- **DETECTED (Verified Exploit Witness)**: ${detectedCount}
- **NOT_DETECTED (Bounded Explicit Refutation)**: ${notDetectedCount}
- **INCONCLUSIVE (Fail-Closed Diagnostic)**: ${inconclusiveCount}

---

## 1. Verified Detections (Replayable Evidence DAGs)
${verifiedFindings.length > 0 
    ? verifiedFindings.map((f, i) => `### [${f.severity}] ${f.title}
- **Finding ID**: \`${f.id}\`
- **CWE**: \`${f.cwe_id || 'N/A'}\`
- **Operational Verdict**: \`DETECTED\` (\`${f.reason_code || 'VERIFIED_EXPLOIT_WITNESS'}\`)
- **Evidence DAG Hash**: \`${f.evidence_dag_hash || 'N/A'}\`
- **Location**: \`${f.source_locations?.[0]?.path || f.rtl_location || 'N/A'}\`
- **Analyst Dossier**: \`evidence/dossier_${f.id}.md\`
`).join('\n')
    : '_No verified exploit witnesses confirmed within declared scope._'}

---

## 2. Hypotheses & Operational Cases
${operationalResults.length > 0
    ? operationalResults.map(r => `- **Case ${r.hypothesis_id}**: \`${r.verdict}\` (${r.reason_code}) | DAG: \`${r.dag_hash.slice(0, 16)}...\` | [Dossier](${r.dossier_path})`).join('\n')
    : '_No operational hypotheses formulated._'}

---

## 3. Discovered Entry Points
${entryPoints.length > 0
    ? entryPoints.map(ep => `- **${ep.id}**: \`${ep.type}\` (${ep.framework || 'Direct'}) at \`${ep.file}\` (${ep.route || ep.method || 'CLI'})`).join('\n')
    : '_No active HTTP/CLI entry points detected._'}

---

## 4. Vulnerability Coverage Matrix
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
        detected_count: detectedCount,
        not_detected_count: notDetectedCount,
        inconclusive_count: inconclusiveCount
    };
    workspace.saveJson('analysis.json', analysis);

    const statusMd = `# HWSEC Analysis Status

**Analysis ID**: \`${analysisId}\`  
**Phase**: \`COMPLETED\`  
**Execution Started**: \`true\`  
**Completed At**: ${analysis.completed_at}  

### Operational Results
- **DETECTED**: ${detectedCount}
- **NOT_DETECTED**: ${notDetectedCount}
- **INCONCLUSIVE**: ${inconclusiveCount}
- **Verified Findings**: ${verifiedFindings.length}
- **Candidate Findings**: ${candidateFindings.length}

> [!TIP]
> View final security report at: \`${outputDir}/${analysisId}/report/final.md\`
`;
    workspace.saveMarkdown('status.md', statusMd);
    db.updateAnalysisRunStatus(analysisId, AnalysisStatus.COMPLETED, 0.0);
    db.close();

    notify(8, 8, 'Evidence reduction', 'DONE');

    return {
        analysisId,
        workspace,
        analysis,
        results: analysis.results,
        verifiedFindings,
        candidateFindings,
        operationalResults,
        reportPath: path.join(workspace.outputDir, 'report/final.md')
    };
}
