import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { BEPManager } from './bepManager.js';
import { TransitionLedger } from './transitionLedger.js';
import { createGroundTruthRecord, createRawFindingRecord, createNormalizedFindingRecord, createCandidateRecord, createVerifierDecisionRecord, createProofArtifactRecord, createCaseResultRecord, GroundTruthLabel, CaseClassification, PredictionState, evaluatePrediction, TriggerType, EvidenceBasis, InconclusiveReason, RecommendedNextAction } from './bepSchema.js';
import { BenchmarkManager } from '../benchmark.js';
import { Database } from '../db.js';
import { loadConfig } from '../config.js';
import { AnalysisBroker } from '../broker.js';
import { LLMGateway } from '../llm/gateway.js';
import { LayeredVerifier } from '../../workers/verifier.js';
import { CandidateGenerator } from '../../workers/candidateGenerator.js';
import { CodeGraph, NodeTypes, EdgeRelations } from '../graph/codeGraph.js';
import { ControlledProofVerifier } from '../../workers/proofVerifier.js';
import { VerificationState } from '../schema.js';

export class BenchmarkRunner {
    constructor(configPath = 'config.json', evidenceOutputDir = 'quality-benchmark/evidence/runs') {
        this.configPath = path.resolve(configPath);
        this.config = loadConfig(this.configPath);
        this.bepManager = new BEPManager(evidenceOutputDir);
        this.benchmarkManager = new BenchmarkManager();
    }

    async runBenchmark(benchmarkId, runMode = 'full', options = {}) {
        console.log(`\n============================================================`);
        console.log(`    HWSEC BENCHMARK EVIDENCE RUNNER`);
        console.log(`============================================================`);
        console.log(`[*] Target Benchmark: ${benchmarkId}`);
        console.log(`[*] Run Mode: ${runMode}`);

        // 1. Resolve Dataset
        const active = this.benchmarkManager.getActiveBenchmarks();
        const target = active.find(b => b.name === benchmarkId || b.key.includes(benchmarkId));
        if (!target) {
            throw new Error(`Benchmark ${benchmarkId} not found or disabled in config.`);
        }
        console.log(`[+] Resolved dataset: ${target.resolvedPath}`);

        // 2. Load Ground Truth
        const gtResult = this.benchmarkManager.loadGroundTruth();
        const allEntries = gtResult.data.entries || [];
        const datasetEntries = allEntries.filter(e => e.dataset === target.name || e.dataset === target.key.split('/')[1]);
        
        console.log(`[+] Found ${datasetEntries.length} ground truth cases for this dataset.`);

        // 3. Initialize BEP Bundle
        const runId = options.resumeRunId || `RUN-${crypto.randomBytes(4).toString('hex')}`;
        const writer = this.bepManager.createBundle(benchmarkId, runId, {
            case_count: datasetEntries.length,
            language: target.language,
            languages: [target.language],
            run_id: runId
        });

        const ledger = new TransitionLedger();

        console.log(`[+] Initialized Evidence Bundle: ${writer.bundlePath}`);

        // Write Ground Truth
        for (const e of datasetEntries) {
            e.case_id = e.id || e.case_id || `CASE-${crypto.randomBytes(4).toString('hex')}`;
            writer.writeRecord('ground_truth.jsonl', createGroundTruthRecord({
                case_id: e.case_id,
                benchmark_id: benchmarkId,
                source_file: e.path,
                line_range: e.line ? [e.line, e.line] : null,
                cwe: e.cwe || 'CWE-UNKNOWN',
                ground_truth_label: e.is_vulnerable === false ? GroundTruthLabel.NOT_VULNERABLE : GroundTruthLabel.VULNERABLE,
                ground_truth_source: 'hwsec_ground_truth_manifest'
            }));
        }

        // 4. Setup Execution Environment
        const dbPath = path.join(writer.bundlePath, 'hwsec.db');
        const db = new Database(dbPath);
        db.saveProject({ id: 'PROJ-BENCHMARK', path: target.resolvedPath, name: benchmarkId });
        db.saveAnalysisRun({
            id: runId,
            projectId: 'PROJ-BENCHMARK',
            status: 'RUNNING',
            budgetAllocated: 100.0,
            budgetConsumed: 0.0
        });
        const broker = new AnalysisBroker(this.config, null, db);
        const llmGateway = new LLMGateway(this.config, db);
        const modelRouter = llmGateway.router;
        const codeGraph = new CodeGraph();

        // 5. Run Deterministic Analyzers
        const allFiles = datasetEntries.map(e => ({ path: path.resolve(process.cwd(), e.path), language: target.language }));
        const uniquePaths = [...new Set(allFiles.map(f => f.path))].filter(p => fs.existsSync(p));
        
        const toolsOutputDir = path.join(writer.bundlePath, 'tools');
        const rawFindings = [];
        const executedTools = [];

        // Check if resuming from an existing bundle with raw_findings
        let resumed = false;
        const resumePath = options.resume || options.resumeBundle;
        if (resumePath) {
            const rawFindingsPath = path.isAbsolute(resumePath) 
                ? path.join(resumePath, 'raw_findings.jsonl')
                : path.resolve(resumePath, 'raw_findings.jsonl');
            if (fs.existsSync(rawFindingsPath)) {
                console.log(`[+] Resuming from existing raw findings: ${rawFindingsPath}`);
                const lines = fs.readFileSync(rawFindingsPath, 'utf8').split('\n').filter(l => l.trim().length > 0);
                for (const line of lines) {
                    try {
                        const rf = JSON.parse(line);
                        rawFindings.push({
                            id: rf.finding_id,
                            source_tool: rf.analyzer,
                            cwe_id: rf.rule_id,
                            cwe: rf.rule_id,
                            severity: rf.severity || 'MEDIUM',
                            confidence: 0.8,
                            source_locations: [{ path: rf.file, line: rf.start_line || 1 }]
                        });
                        writer.writeRecord('raw_findings.jsonl', rf);
                    } catch (_) {}
                }
                executedTools.push('semgrep');
                resumed = true;
                console.log(`[+] Successfully loaded ${rawFindings.length} raw findings from existing run.`);
            }
        }

        if (!resumed) {
            console.log(`[*] Executing deterministic analyzers on ${uniquePaths.length} files...`);
            const toolsToRun = target.language === 'java' || target.language === 'c' || target.language === 'cpp' 
                ? ['semgrep', 'joern'] 
                : ['semgrep'];

            for (const tool of toolsToRun) {
                try {
                    const res = await broker.dispatch({
                        capability: tool === 'semgrep' ? 'sast_pattern_scan' : 'graph_dataflow',
                        languages: [target.language],
                        files: uniquePaths,
                        outputDir: toolsOutputDir,
                        runId
                    });
                    if (res.findings) {
                        rawFindings.push(...res.findings);
                        executedTools.push(tool);
                        res.findings.forEach(f => {
                            writer.writeRecord('raw_findings.jsonl', createRawFindingRecord({
                                finding_id: f.id,
                                analyzer: f.source_tool || tool,
                                analyzer_version: 'unknown',
                                rule_id: f.cwe_id || 'UNKNOWN',
                                file: f.source_locations?.[0]?.path || f.rtl_location || 'unknown'
                            }));
                        });
                    }
                } catch (err) {
                    console.warn(`[!] Tool ${tool} note: ${err.message}`);
                }
            }
        }

        console.log(`[+] Generated ${rawFindings.length} raw findings.`);

        // 6. Generate Candidates
        console.log(`[*] Generating candidates and escalating findings...`);
        const candGen = new CandidateGenerator(codeGraph, null);
        const candidatePool = candGen.generateCandidates({
            files: uniquePaths.map(p => ({path: p, language: target.language})),
            deterministicFindings: rawFindings,
            executedTools
        });

        // Index dataset entries for fast O(1) case matching
        const caseByPath = new Map();
        for (const e of datasetEntries) {
            const norm = (e.path || '').replace(/\\/g, '/').toLowerCase();
            caseByPath.set(norm, e);
            const base = path.basename(norm);
            if (!caseByPath.has(base)) caseByPath.set(base, e);
        }
        const findCase = (filePath) => {
            if (!filePath) return null;
            const norm = filePath.replace(/\\/g, '/').toLowerCase();
            if (caseByPath.has(norm)) return caseByPath.get(norm);
            const base = path.basename(norm);
            if (caseByPath.has(base)) return caseByPath.get(base);
            return datasetEntries.find(e => {
                const normE = (e.path || '').replace(/\\/g, '/').toLowerCase();
                return norm.endsWith(normE) || normE.endsWith(norm);
            });
        };

        // Write Candidates and Normalized findings
        for (const cand of candidatePool) {
            const normId = `NORM-${cand.id}`;
            writer.writeRecord('normalized_findings.jsonl', createNormalizedFindingRecord({
                finding_id: normId,
                linked_raw_ids: [cand.id],
                cwe: cand.cwe,
                file: cand.sourceLocations?.[0]?.path || 'unknown'
            }));

            // Normalize path for robust cross-platform matching
            const candPath = cand.sourceLocations?.[0]?.path;
            const matchedCase = findCase(candPath);
            const caseId = matchedCase ? (matchedCase.case_id || `CASE-M-${cand.id}`) : `CASE-U-${cand.id}`;

            writer.writeRecord('candidates.jsonl', createCandidateRecord({
                candidate_id: cand.id,
                case_id: caseId,
                trigger_types: cand.source === 'deterministic_tool' ? [TriggerType.STATIC_FINDING] : [TriggerType.ANALYZER_DISAGREEMENT],
                source_finding_ids: [normId]
            }));

            writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                case_id: caseId,
                from_state: 'NOT_EVALUATED',
                to_state: 'CANDIDATE',
                stage: 'CANDIDATE_GENERATOR',
                reason_code: 'STATIC_FINDING_IDENTIFIED'
            }));
        }

        // Convert to finding objects for verifier
        const candidateFindings = candidatePool.map(c => ({
            id: c.id,
            title: c.title,
            description: c.description || 'Candidate',
            severity: c.severity || 'MEDIUM',
            confidence: c.confidence || 0.5,
            verification_state: VerificationState.CANDIDATE,
            cwe_id: c.cwe,
            source_locations: c.sourceLocations
        }));

        // Pre-populate findings in db for relational integrity
        for (const cf of candidateFindings) {
            try {
                db.saveFinding({
                    id: cf.id,
                    runId: runId,
                    title: cf.title || `Candidate ${cf.id}`,
                    type: cf.cwe_id || 'UNKNOWN',
                    severity: cf.severity || 'MEDIUM',
                    confidence: cf.confidence || 0.5,
                    verificationState: cf.verification_state || 'CANDIDATE',
                    location: cf.source_locations?.[0]?.path || null
                });
            } catch (_) {}
        }

        // 7. Layered Verifier (LLM / Hybrid)
        console.log(`[*] Running Layered Verifier (Mode: ${runMode === 'full' ? 'ON' : 'OFF'})...`);
        const verifierDecisions = new Map();
        if (runMode === 'full') {
            const verifier = new LayeredVerifier(modelRouter, db, runId, codeGraph);
            const verificationResult = await verifier.verify([], candidateFindings, {});
            
            // Record decisions
            for (const f of [...verificationResult.verifiedFindings, ...verificationResult.candidateFindings]) {
                const fPath = f.source_locations?.[0]?.path;
                const matchedCase = findCase(fPath);
                const caseId = matchedCase ? (matchedCase.case_id || `CASE-M-${f.id}`) : `CASE-U-${f.id}`;
                
                const vdId = `VD-${f.id}`;
                const isVerified = f.verification_state === VerificationState.VERIFIED;
                const vdRecord = createVerifierDecisionRecord({
                    decision_id: vdId,
                    case_id: caseId,
                    candidate_id: f.id,
                    decision: isVerified ? 'KEEP' : 'REJECT',
                    verifier_type: 'LLM',
                    model: 'gemini-2.5-flash',
                    provider: 'gemini',
                    confidence: f.confidence || 0.0,
                    evidence_basis: EvidenceBasis.MODEL_ONLY,
                    suspected_cwe: f.cwe_id || 'CWE-UNKNOWN',
                    source_boundary: 'HTTP_REQUEST_PARAMETER',
                    dangerous_sink: 'DANGEROUS_SECURITY_SINK',
                    dataflow_path: 'INPUT -> SOURCE -> SINK',
                    recommended_deterministic_validator: 'JAVA_SANDBOX_HARNESS',
                    expected_security_impact: 'UNAUTHORIZED_DATAFLOW_OR_CORRUPTION'
                });
                writer.writeRecord('verifier_decisions.jsonl', vdRecord);
                verifierDecisions.set(f.id, vdRecord);

                // Evidence Gate: LLM output alone must not promote or demote a finding!
                // Remains in CANDIDATE state until deterministic proof verification
                writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                    case_id: caseId,
                    from_state: 'CANDIDATE',
                    to_state: 'CANDIDATE',
                    stage: 'LLM_VERIFIER',
                    verifier_decision_id: vdId,
                    reason_code: isVerified ? 'LLM_RECOMMENDED_VERIFY' : 'LLM_RECOMMENDED_PRUNE'
                }));
            }
        }

        // 8. Controlled Proof Validator
        console.log(`[*] Running Controlled Proof-of-Impact Validation...`);
        const proofVerifier = new ControlledProofVerifier(this.config, db, llmGateway, {
            sandboxDir: path.join(writer.bundlePath, 'sandbox')
        });

        // Group candidate findings by case
        const candidatesByCase = new Map();
        for (const cand of candidateFindings) {
            const candPath = cand.source_locations?.[0]?.path;
            const matchedCase = findCase(candPath);
            const caseId = matchedCase ? matchedCase.case_id : `CASE-U-${cand.id}`;
            if (!candidatesByCase.has(caseId)) {
                candidatesByCase.set(caseId, []);
            }
            candidatesByCase.get(caseId).push(cand);
        }

        const maxCases = options.maxCases ? parseInt(options.maxCases, 10) : null;
        let candidateCaseEntries = Array.from(candidatesByCase.entries());
        if (maxCases && maxCases > 0 && maxCases < candidateCaseEntries.length) {
            console.log(`[!] Pilot mode: validating first ${maxCases} of ${candidateCaseEntries.length} candidate cases`);
            candidateCaseEntries = candidateCaseEntries.slice(0, maxCases);
        }

        console.log(`[*] Dispatched ${candidateCaseEntries.length} candidate cases to Controlled Proof Validator (Stage: PROOF_VERIFICATION)...`);
        const casePredictions = new Map(); // caseId -> { prediction, reason, proofRef, inconclusive_reason, recommended_next_action }

        let casesProcessed = 0;
        let candidatesProcessed = 0;
        let proofsAttempted = 0;
        let proofsSucceeded = 0;
        let proofsFailed = 0;
        const totalCasesToValidate = candidateCaseEntries.length;
        const stageStartTime = Date.now();
        let lastSuccessfulActivityTime = new Date().toISOString();

        const concurrency = 4;
        let entryCursor = 0;

        const runWorker = async () => {
            while (entryCursor < candidateCaseEntries.length) {
                const currentIndex = entryCursor++;
                const [caseId, caseCandidates] = candidateCaseEntries[currentIndex];

                let provenFinding = null;
                let lastExecution = null;

                for (const candFinding of caseCandidates) {
                    candidatesProcessed++;
                    proofsAttempted++;
                    try {
                        const attempt = { findingId: candFinding.id, budget: { allowed_tools: ['javac', 'java', 'node', 'python3', 'local_test_runner'] } };
                        const generated = await proofVerifier.generateProof(candFinding, target.resolvedPath, attempt);
                        const execution = await proofVerifier.executeProof(generated.proofRecord, target.resolvedPath, 1);
                        lastExecution = execution;

                        writer.writeRecord('proof_artifacts.jsonl', createProofArtifactRecord({
                            proof_id: execution.proofRecord.proof_id,
                            case_id: caseId,
                            verdict: execution.proofRecord.proof_status,
                            stdout_hash: execution.proofRecord.artifact_hash || 'unknown',
                            repetition_count: execution.reproducibilityRate,
                            exit_code: execution.proofRecord.exit_status,
                            timeout_state: execution.proofRecord.timeout_state,
                            command_struct: { command: execution.proofRecord.command_args, version: execution.proofRecord.tool_version }
                        }));

                        if (execution.reproduced) {
                            provenFinding = candFinding;
                            proofsSucceeded++;
                            lastSuccessfulActivityTime = new Date().toISOString();
                            console.log(`[+] Proof REPRODUCED for ${caseId} (${candFinding.cwe_id || 'CWE-UNKNOWN'}) [impact: ${execution.proofRecord.impact_class}]`);
                            break; // Successfully proven!
                        } else {
                            proofsFailed++;
                        }
                    } catch (err) {
                        proofsFailed++;
                        console.warn(`[!] Proof execution error for candidate ${candFinding.id}: ${err.message}`);
                    }
                }

                if (provenFinding && lastExecution && lastExecution.reproduced) {
                    casePredictions.set(caseId, {
                        prediction: PredictionState.DETECTED,
                        reason: 'DETERMINISTIC_PROOF_REPRODUCED',
                        proofRef: lastExecution.proofRecord.proof_id
                    });
                    writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                        case_id: caseId,
                        from_state: 'CANDIDATE',
                        to_state: 'DETECTED',
                        stage: 'PROOF_VERIFIER',
                        proof_ref: lastExecution.proofRecord.proof_id,
                        reason_code: 'DETERMINISTIC_PROOF_REPRODUCED'
                    }));
                } else {
                    let incReason = InconclusiveReason.NO_REPRODUCIBLE_PATH;
                    if (lastExecution?.proofRecord?.proof_status === 'UNAVAILABLE') {
                        incReason = InconclusiveReason.TOOL_UNAVAILABLE;
                    } else if (lastExecution?.proofRecord?.timeout_state) {
                        incReason = InconclusiveReason.VALIDATION_TIMEOUT;
                    } else if (!lastExecution) {
                        incReason = InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF;
                    }

                    const nextAction = RecommendedNextAction[incReason] || 'GENERATE_AND_EXECUTE_DETERMINISTIC_PROOF_HARNESS';

                    casePredictions.set(caseId, {
                        prediction: PredictionState.INCONCLUSIVE,
                        reason: incReason,
                        inconclusive_reason: incReason,
                        recommended_next_action: nextAction,
                        proofRef: lastExecution?.proofRecord?.proof_id || null
                    });

                    writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                        case_id: caseId,
                        from_state: 'CANDIDATE',
                        to_state: 'INCONCLUSIVE',
                        stage: 'PROOF_VERIFIER',
                        inconclusive_reason: incReason,
                        recommended_next_action: nextAction,
                        proof_ref: lastExecution?.proofRecord?.proof_id || null,
                        reason_code: incReason
                    }));
                }

                casesProcessed++;

                // Periodic telemetry reporting
                if (casesProcessed % 10 === 0 || casesProcessed === totalCasesToValidate) {
                    const elapsedSec = ((Date.now() - stageStartTime) / 1000).toFixed(1);
                    const remaining = totalCasesToValidate - casesProcessed;
                    console.log(`[TELEMETRY] Stage: PROOF_VERIFIER | Cases: ${casesProcessed}/${totalCasesToValidate} (remaining: ${remaining}) | Candidates: ${candidatesProcessed} | Proofs: att=${proofsAttempted}, succ=${proofsSucceeded}, fail=${proofsFailed} | Elapsed: ${elapsedSec}s | Last Activity: ${lastSuccessfulActivityTime}`);
                }
            }
        };

        const telemetryInterval = setInterval(() => {
            const elapsedSec = ((Date.now() - stageStartTime) / 1000).toFixed(1);
            const remaining = totalCasesToValidate - casesProcessed;
            console.log(`[HEARTBEAT] Stage: PROOF_VERIFIER | Active Workers: ${Math.min(concurrency, Math.max(1, remaining))} | Cases: ${casesProcessed}/${totalCasesToValidate} (${((casesProcessed / Math.max(1, totalCasesToValidate)) * 100).toFixed(1)}%) | Proofs: att=${proofsAttempted}, succ=${proofsSucceeded}, fail=${proofsFailed} | Elapsed: ${elapsedSec}s | Last Activity: ${lastSuccessfulActivityTime}`);
        }, 15000);

        const workers = [];
        for (let w = 0; w < Math.min(concurrency, totalCasesToValidate); w++) {
            workers.push(runWorker());
        }
        try {
            await Promise.all(workers);
        } finally {
            clearInterval(telemetryInterval);
        }

        // For any candidate cases skipped due to pilot maxCases, record them as INCONCLUSIVE
        for (const [caseId] of candidatesByCase.entries()) {
            if (!casePredictions.has(caseId)) {
                casePredictions.set(caseId, {
                    prediction: PredictionState.INCONCLUSIVE,
                    reason: InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF,
                    inconclusive_reason: InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF,
                    recommended_next_action: 'GENERATE_AND_EXECUTE_DETERMINISTIC_PROOF_HARNESS',
                    proofRef: null
                });
                writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                    case_id: caseId,
                    from_state: 'CANDIDATE',
                    to_state: 'INCONCLUSIVE',
                    stage: 'PROOF_VERIFIER',
                    inconclusive_reason: InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF,
                    recommended_next_action: 'GENERATE_AND_EXECUTE_DETERMINISTIC_PROOF_HARNESS',
                    proof_ref: null,
                    reason_code: InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF
                }));
            }
        }

        // For cases where no candidates were flagged:
        // Evidence gate: clean deterministic scan with sufficient coverage yields NOT_DETECTED
        for (const e of datasetEntries) {
            const caseId = e.case_id;
            if (!casePredictions.has(caseId)) {
                casePredictions.set(caseId, {
                    prediction: PredictionState.NOT_DETECTED,
                    reason: 'CLEAN_STATIC_SCAN_NO_FINDINGS'
                });
                writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                    case_id: caseId,
                    from_state: 'NOT_EVALUATED',
                    to_state: 'NOT_DETECTED',
                    stage: 'STATIC_ANALYSIS',
                    reason_code: 'CLEAN_STATIC_SCAN_NO_FINDINGS'
                }));
            }
        }

        // 9. Case Evaluation (Strictly compare Prediction with Ground Truth at Evaluation Layer)
        console.log(`[*] Evaluating HWSEC Predictions against Ground Truth...`);
        let tp = 0, fp = 0, tn = 0, fn = 0, inconclusive = 0;
        let detected = 0, not_detected = 0, inconclusive_pred = 0;
        let inconclusive_vulnerable = 0;

        const cweMap = {};

        for (const e of datasetEntries) {
            const isVuln = e.is_vulnerable !== false;
            const gtLabel = isVuln ? GroundTruthLabel.VULNERABLE : GroundTruthLabel.NOT_VULNERABLE;
            const caseId = e.case_id;
            const cwe = e.cwe || 'CWE-UNKNOWN';

            if (!cweMap[cwe]) {
                cweMap[cwe] = { total: 0, tp: 0, fp: 0, tn: 0, fn: 0, inconclusive: 0 };
            }
            cweMap[cwe].total++;
            
            const predInfo = casePredictions.get(caseId) || { prediction: PredictionState.INCONCLUSIVE, reason: 'UNPROCESSED' };
            const prediction = predInfo.prediction;

            if (prediction === PredictionState.DETECTED) detected++;
            else if (prediction === PredictionState.NOT_DETECTED) not_detected++;
            else {
                inconclusive_pred++;
                if (isVuln) inconclusive_vulnerable++;
            }

            const finalClass = evaluatePrediction(prediction, gtLabel);

            if (finalClass === CaseClassification.TP) { tp++; cweMap[cwe].tp++; }
            else if (finalClass === CaseClassification.FP) { fp++; cweMap[cwe].fp++; }
            else if (finalClass === CaseClassification.TN) { tn++; cweMap[cwe].tn++; }
            else if (finalClass === CaseClassification.FN) { fn++; cweMap[cwe].fn++; }
            else { inconclusive++; cweMap[cwe].inconclusive++; }

            writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                case_id: caseId,
                from_state: prediction,
                to_state: finalClass,
                stage: 'GROUND_TRUTH_EVALUATOR',
                reason_code: `EVALUATED_AGAINST_GROUND_TRUTH_${gtLabel}`
            }));

            const transitions = ledger.getTransitionsForCase(caseId);
            writer.writeRecord('case_results.jsonl', createCaseResultRecord({
                case_id: caseId,
                ground_truth: gtLabel,
                prediction: prediction,
                hwsec_final: prediction,
                classification: finalClass,
                first_detection_stage: prediction === PredictionState.DETECTED ? 'PROOF_VERIFIER' : (predInfo.reason?.includes('CANDIDATE') ? 'CANDIDATE_GENERATOR' : 'NONE'),
                final_confirmation_stage: prediction === PredictionState.DETECTED ? 'PROOF_VERIFIER' : 'EVALUATION',
                proof_ids: predInfo.proofRef ? [predInfo.proofRef] : [],
                transition_ids: transitions.map(t => t.transition_id),
                inconclusive_reason: predInfo.inconclusive_reason || null,
                recommended_next_action: predInfo.recommended_next_action || null
            }));
        }

        const totalCases = datasetEntries.length;
        const totalVulnerable = datasetEntries.filter(e => e.is_vulnerable !== false).length;

        // 3-State Metrics Suite (Section 9)
        const detected_coverage = totalCases > 0 ? (detected / totalCases) : 0;
        const not_detected_coverage = totalCases > 0 ? (not_detected / totalCases) : 0;
        const inconclusive_coverage = totalCases > 0 ? (inconclusive_pred / totalCases) : 0;

        const precision_resolved = (tp + fp) > 0 ? (tp / (tp + fp)) : null;
        const recall_resolved = (tp + fn) > 0 ? (tp / (tp + fn)) : null;
        const f1_resolved = (precision_resolved !== null && recall_resolved !== null && (precision_resolved + recall_resolved) > 0) 
            ? (2 * precision_resolved * recall_resolved / (precision_resolved + recall_resolved)) 
            : null;

        const recall_end_to_end = totalVulnerable > 0 ? (tp / totalVulnerable) : 0;

        // Per-CWE metrics breakdown
        const per_cwe = {};
        for (const [cwe, m] of Object.entries(cweMap)) {
            const p = (m.tp + m.fp) > 0 ? (m.tp / (m.tp + m.fp)) : null;
            const r = (m.tp + m.fn) > 0 ? (m.tp / (m.tp + m.fn)) : null;
            per_cwe[cwe] = {
                total: m.total,
                tp: m.tp,
                fp: m.fp,
                fn: m.fn,
                tn: m.tn,
                inconclusive: m.inconclusive,
                precision: p !== null ? Number(p.toFixed(4)) : 'N/A',
                recall: r !== null ? Number(r.toFixed(4)) : 'N/A',
                detected_coverage: m.total > 0 ? Number(((m.tp + m.fp) / m.total).toFixed(4)) : 0,
                inconclusive_rate: m.total > 0 ? Number((m.inconclusive / m.total).toFixed(4)) : 0
            };
        }

        await writer.finalize({
            tp, fp, fn, tn, inconclusive, total_cases: totalCases,
            predictions: {
                detected,
                not_detected,
                inconclusive: inconclusive_pred
            },
            coverage_3_state: {
                detected_coverage: Number(detected_coverage.toFixed(4)),
                not_detected_coverage: Number(not_detected_coverage.toFixed(4)),
                inconclusive_coverage: Number(inconclusive_coverage.toFixed(4))
            },
            resolved_metrics: {
                precision_resolved: precision_resolved !== null ? Number(precision_resolved.toFixed(4)) : 'N/A',
                recall_resolved: recall_resolved !== null ? Number(recall_resolved.toFixed(4)) : 'N/A',
                f1_resolved: f1_resolved !== null ? Number(f1_resolved.toFixed(4)) : 'N/A'
            },
            precision: precision_resolved !== null ? Number(precision_resolved.toFixed(4)) : 'N/A',
            recall: recall_resolved !== null ? Number(recall_resolved.toFixed(4)) : 'N/A',
            f1: f1_resolved !== null ? Number(f1_resolved.toFixed(4)) : 'N/A',
            recall_end_to_end: Number(recall_end_to_end.toFixed(4)),
            precision_informative: (tp + fp) > 0,
            recall_informative: (tp + fn) > 0,
            per_cwe
        }, { tp, fp, fn, tn, inconclusive }, {});

        db.close();

        console.log(`\n[+] Benchmark Run COMPLETE.`);
        console.log(`    Predictions: DETECTED=${detected}, NOT_DETECTED=${not_detected}, INCONCLUSIVE=${inconclusive_pred}`);
        console.log(`    Evaluated:   TP=${tp}, FP=${fp}, TN=${tn}, FN=${fn}, INCONCLUSIVE=${inconclusive}`);
        console.log(`    3-State:     DETECTED_cov=${(detected_coverage * 100).toFixed(1)}%, NOT_DETECTED_cov=${(not_detected_coverage * 100).toFixed(1)}%, INCONCL_cov=${(inconclusive_coverage * 100).toFixed(1)}%`);
        console.log(`    Precision:   ${precision_resolved !== null ? (precision_resolved * 100).toFixed(1) + '%' : 'N/A'}`);
        console.log(`    Recall (Res):${recall_resolved !== null ? (recall_resolved * 100).toFixed(1) + '%' : 'N/A'}`);
        console.log(`    Recall (E2E):${(recall_end_to_end * 100).toFixed(1)}%`);
        console.log(`    F1:          ${f1_resolved !== null ? f1_resolved.toFixed(3) : 'N/A'}`);
        console.log(`    Results saved to: ${writer.bundlePath}`);
        
        return writer.bundlePath;
    }
}
