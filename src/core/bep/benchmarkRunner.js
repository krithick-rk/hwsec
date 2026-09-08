import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { BEPManager } from './bepManager.js';
import { TransitionLedger } from './transitionLedger.js';
import { createGroundTruthRecord, createRawFindingRecord, createNormalizedFindingRecord, createCandidateRecord, createVerifierDecisionRecord, createProofArtifactRecord, createCaseResultRecord, GroundTruthLabel, CaseClassification, PredictionState, evaluatePrediction, TriggerType, EvidenceBasis } from './bepSchema.js';
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

    async runBenchmark(benchmarkId, runMode = 'full') {
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
        const runId = `RUN-${crypto.randomBytes(4).toString('hex')}`;
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
        
        console.log(`[*] Executing deterministic analyzers on ${uniquePaths.length} files...`);
        const toolsOutputDir = path.join(writer.bundlePath, 'tools');
        
        const rawFindings = [];
        const executedTools = [];
        
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
                console.warn(`[!] Tool ${tool} failed: ${err.message}`);
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
            const normCandPath = (candPath || '').replace(/\\/g, '/').toLowerCase();
            const matchedCase = datasetEntries.find(e => {
                const normE = (e.path || '').replace(/\\/g, '/').toLowerCase();
                return normCandPath.endsWith(normE) || normE.endsWith(normCandPath);
            });
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

        // 7. Layered Verifier (LLM / Hybrid)
        console.log(`[*] Running Layered Verifier (Mode: ${runMode === 'full' ? 'ON' : 'OFF'})...`);
        const verifiedFindings = [];
        if (runMode === 'full') {
            const verifier = new LayeredVerifier(modelRouter, db, runId, codeGraph);
            const verificationResult = await verifier.verify([], candidateFindings, {});
            verifiedFindings.push(...verificationResult.verifiedFindings);
            
            // Record decisions
            for (const f of [...verifiedFindings, ...verificationResult.candidateFindings]) {
                const fPath = f.source_locations?.[0]?.path;
                const normFPath = (fPath || '').replace(/\\/g, '/').toLowerCase();
                const matchedCase = datasetEntries.find(e => {
                    const normE = (e.path || '').replace(/\\/g, '/').toLowerCase();
                    return normFPath.endsWith(normE) || normE.endsWith(normFPath);
                });
                const caseId = matchedCase ? (matchedCase.case_id || `CASE-M-${f.id}`) : `CASE-U-${f.id}`;
                
                const vdId = `VD-${f.id}`;
                const isVerified = f.verification_state === VerificationState.VERIFIED;
                writer.writeRecord('verifier_decisions.jsonl', createVerifierDecisionRecord({
                    decision_id: vdId,
                    case_id: caseId,
                    candidate_id: f.id,
                    decision: isVerified ? 'KEEP' : 'REJECT',
                    verifier_type: 'LLM',
                    model: 'gemini-2.5-flash',
                    provider: 'gemini',
                    confidence: f.confidence || 0.0,
                    evidence_basis: EvidenceBasis.MODEL_ONLY
                }));

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
        } else {
            // Treat all candidates as verified if LLM is off
            verifiedFindings.push(...candidateFindings);
        }

        // 8. Controlled Proof Validator
        console.log(`[*] Running Controlled Proof-of-Impact Validation...`);
        const proofVerifier = new ControlledProofVerifier(this.config, db, llmGateway, {
            sandboxDir: path.join(writer.bundlePath, 'sandbox')
        });

        // Track case predictions strictly from evidence (independent of ground truth!)
        const casePredictions = new Map(); // caseId -> { prediction, reason, proofRef }

        for (const f of verifiedFindings) {
            const fPath = f.source_locations?.[0]?.path;
            const normFPath = (fPath || '').replace(/\\/g, '/').toLowerCase();
            const matchedCase = datasetEntries.find(e => {
                const normE = (e.path || '').replace(/\\/g, '/').toLowerCase();
                return normFPath.endsWith(normE) || normE.endsWith(normFPath);
            });
            const caseId = matchedCase ? (matchedCase.case_id || `CASE-M-${f.id}`) : `CASE-U-${f.id}`;

            try {
                // Generate and execute proof
                const attempt = { findingId: f.id, budget: { allowed_tools: ['javac', 'java', 'node', 'python3', 'local_test_runner'] } };
                const generated = await proofVerifier.generateProof(f, target.resolvedPath, attempt);
                const execution = await proofVerifier.executeProof(generated.proofRecord, target.resolvedPath, 1);
                
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
                    casePredictions.set(caseId, {
                        prediction: PredictionState.DETECTED,
                        reason: 'DETERMINISTIC_PROOF_REPRODUCED',
                        proofRef: execution.proofRecord.proof_id
                    });
                    writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                        case_id: caseId,
                        from_state: 'CANDIDATE',
                        to_state: 'DETECTED',
                        stage: 'PROOF_VERIFIER',
                        proof_ref: execution.proofRecord.proof_id,
                        reason_code: 'DETERMINISTIC_PROOF_REPRODUCED'
                    }));
                } else if (execution.proofRecord.proof_status === 'UNAVAILABLE') {
                    casePredictions.set(caseId, {
                        prediction: PredictionState.INCONCLUSIVE,
                        reason: 'PROOF_VALIDATION_UNAVAILABLE',
                        proofRef: execution.proofRecord.proof_id
                    });
                    writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                        case_id: caseId,
                        from_state: 'CANDIDATE',
                        to_state: 'INCONCLUSIVE',
                        stage: 'PROOF_VERIFIER',
                        proof_ref: execution.proofRecord.proof_id,
                        reason_code: 'PROOF_VALIDATION_UNAVAILABLE'
                    }));
                } else {
                    casePredictions.set(caseId, {
                        prediction: PredictionState.INCONCLUSIVE,
                        reason: 'PROOF_REPRODUCTION_FAILED',
                        proofRef: execution.proofRecord.proof_id
                    });
                    writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                        case_id: caseId,
                        from_state: 'CANDIDATE',
                        to_state: 'INCONCLUSIVE',
                        stage: 'PROOF_VERIFIER',
                        proof_ref: execution.proofRecord.proof_id,
                        reason_code: 'PROOF_REPRODUCTION_FAILED'
                    }));
                }
            } catch (err) {
                casePredictions.set(caseId, {
                    prediction: PredictionState.INCONCLUSIVE,
                    reason: `PROOF_VERIFICATION_ERROR: ${err.message}`
                });
                writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                    case_id: caseId,
                    from_state: 'CANDIDATE',
                    to_state: 'INCONCLUSIVE',
                    stage: 'PROOF_VERIFIER',
                    reason_code: 'PROOF_VERIFICATION_ERROR'
                }));
            }
        }

        // For any candidate that was not verified or lacked proof:
        // Evidence gate: candidate cannot be demoted to NOT_DETECTED without proof!
        for (const cand of candidatePool) {
            const candPath = cand.sourceLocations?.[0]?.path;
            const normCandPath = (candPath || '').replace(/\\/g, '/').toLowerCase();
            const matchedCase = datasetEntries.find(e => {
                const normE = (e.path || '').replace(/\\/g, '/').toLowerCase();
                return normCandPath.endsWith(normE) || normE.endsWith(normCandPath);
            });
            const caseId = matchedCase ? matchedCase.case_id : `CASE-U-${cand.id}`;
            if (!casePredictions.has(caseId)) {
                casePredictions.set(caseId, {
                    prediction: PredictionState.INCONCLUSIVE,
                    reason: 'UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF'
                });
                writer.writeRecord('classification_transitions.jsonl', ledger.recordTransition({
                    case_id: caseId,
                    from_state: 'CANDIDATE',
                    to_state: 'INCONCLUSIVE',
                    stage: 'EVIDENCE_GATE',
                    reason_code: 'UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF'
                }));
            }
        }

        // For cases where no candidates were flagged:
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

        for (const e of datasetEntries) {
            const isVuln = e.is_vulnerable !== false;
            const gtLabel = isVuln ? GroundTruthLabel.VULNERABLE : GroundTruthLabel.NOT_VULNERABLE;
            const caseId = e.case_id;
            
            const predInfo = casePredictions.get(caseId) || { prediction: PredictionState.INCONCLUSIVE, reason: 'UNPROCESSED' };
            const prediction = predInfo.prediction;

            if (prediction === PredictionState.DETECTED) detected++;
            else if (prediction === PredictionState.NOT_DETECTED) not_detected++;
            else inconclusive_pred++;

            const finalClass = evaluatePrediction(prediction, gtLabel);

            if (finalClass === CaseClassification.TP) tp++;
            else if (finalClass === CaseClassification.FP) fp++;
            else if (finalClass === CaseClassification.TN) tn++;
            else if (finalClass === CaseClassification.FN) fn++;
            else inconclusive++;

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
                first_detection_stage: prediction === PredictionState.DETECTED ? 'PROOF_VERIFIER' : (predInfo.reason.includes('CANDIDATE') ? 'CANDIDATE_GENERATOR' : 'NONE'),
                final_confirmation_stage: prediction === PredictionState.DETECTED ? 'PROOF_VERIFIER' : 'EVALUATION',
                proof_ids: predInfo.proofRef ? [predInfo.proofRef] : [],
                transition_ids: transitions.map(t => t.transition_id)
            }));
        }

        const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : null;
        const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : null;
        const f1 = (precision !== null && recall !== null && (precision + recall) > 0) 
            ? (2 * precision * recall / (precision + recall)) 
            : null;

        await writer.finalize({
            tp, fp, fn, tn, inconclusive, total_cases: datasetEntries.length,
            predictions: {
                detected,
                not_detected,
                inconclusive: inconclusive_pred
            },
            precision: precision !== null ? precision : 'N/A',
            recall: recall !== null ? recall : 'N/A',
            f1: f1 !== null ? f1 : 'N/A',
            precision_informative: (tp + fp) > 0,
            recall_informative: (tp + fn) > 0
        }, { tp, fp, fn, tn, inconclusive }, {});

        db.close();

        console.log(`\n[+] Benchmark Run COMPLETE.`);
        console.log(`    Predictions: DETECTED=${detected}, NOT_DETECTED=${not_detected}, INCONCLUSIVE=${inconclusive_pred}`);
        console.log(`    Evaluated:   TP=${tp}, FP=${fp}, TN=${tn}, FN=${fn}, INCONCLUSIVE=${inconclusive}`);
        console.log(`    Precision:   ${precision !== null ? (precision * 100).toFixed(1) + '%' : 'N/A'}`);
        console.log(`    Recall:      ${recall !== null ? (recall * 100).toFixed(1) + '%' : 'N/A'}`);
        console.log(`    F1:          ${f1 !== null ? f1.toFixed(3) : 'N/A'}`);
        console.log(`    Results saved to: ${writer.bundlePath}`);
        
        return writer.bundlePath;
    }
}
