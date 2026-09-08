import { createFinding, Severity, VerificationState, createSourceLocation } from '../core/schema.js';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export const VerificationLevel = {
    E0_CLAIM_ONLY: "E0",
    E1_TOOL_OBSERVATION: "E1",
    E2_REPRODUCIBLE_ARTIFACT: "E2",
    E3_SEMANTIC_MATCH: "E3",
    E4_SECURITY_RELEVANCE: "E4",
    E5_ATTACKER_REACHABILITY: "E5"
};

export class LayeredVerifier {
    /**
     * @param {Object} [modelRouter] Optional model router for semantic reasoning
     * @param {Object} [db]
     * @param {string} [runId='global']
     * @param {Object} [codeGraph=null]
     */
    constructor(modelRouter = null, db = null, runId = 'global', codeGraph = null) {
        if (modelRouter && typeof modelRouter.findAttackPaths === 'function') {
            this.codeGraph = modelRouter;
            this.modelRouter = null;
        } else {
            this.modelRouter = modelRouter;
            this.codeGraph = codeGraph;
        }
        this.db = db;
        this.runId = runId;
    }

    /**
     * Skeptically evaluates hypotheses and findings against concrete technical artifacts.
     */
    async verify(hypotheses = [], toolFindings = [], telemetries = {}) {
        const verifiedFindings = [];
        const candidateFindings = [];
        const verificationSummaries = [];
        const processedFindingIds = new Set();

        // 1. Evaluate Hypotheses against Technical Evidence
        for (const hyp of hypotheses) {
            const evaluation = await this._evaluateHypothesis(hyp, toolFindings, telemetries);
            verificationSummaries.push(evaluation);

            for (const mf of evaluation.matched_finding_ids) {
                processedFindingIds.add(mf);
            }

            if (evaluation.status === VerificationState.VERIFIED) {
                const verifiedFinding = createFinding({
                    id: `VERIFIED-${crypto.randomBytes(4).toString('hex')}`,
                    title: `[${hyp.cwe_id || 'VERIFIED'}] ${hyp.title}`,
                    description: `${hyp.claim}\n\nVerification Analysis: ${evaluation.justification}\nVerification Level: ${evaluation.level}`,
                    severity: evaluation.severity,
                    confidence: evaluation.confidence,
                    source_tool: "layered-verifier",
                    source_locations: evaluation.source_locations,
                    evidence: evaluation.supporting_evidence,
                    verification_state: VerificationState.VERIFIED,
                    security_property: hyp.security_property || null,
                    cwe_id: hyp.cwe_id || null
                });
                verifiedFinding.verification_level = evaluation.level;
                verifiedFindings.push(verifiedFinding);
                this._persistFinding(verifiedFinding);
                this._persistVerification(verifiedFinding.id, evaluation);
            } else if (evaluation.status === VerificationState.CANDIDATE || evaluation.status === VerificationState.SUPPORTED) {
                const candFinding = createFinding({
                    id: `CAND-${crypto.randomBytes(4).toString('hex')}`,
                    title: `[${hyp.cwe_id || 'CANDIDATE'}] ${hyp.title}`,
                    description: `${hyp.claim}\n\nCandidate Analysis: ${evaluation.justification}\nVerification Level: ${evaluation.level}`,
                    severity: evaluation.severity,
                    confidence: evaluation.confidence,
                    source_tool: "layered-verifier",
                    source_locations: evaluation.source_locations,
                    evidence: evaluation.supporting_evidence,
                    verification_state: VerificationState.CANDIDATE,
                    cwe_id: hyp.cwe_id || null
                });
                candFinding.verification_level = evaluation.level;
                candidateFindings.push(candFinding);
                this._persistFinding(candFinding);
                this._persistVerification(candFinding.id, evaluation);
            }
        }

        // 2. Evaluate Unmatched Raw Tool Findings
        for (const finding of toolFindings) {
            if (processedFindingIds.has(finding.id)) {
                continue;
            }

            const evaluation = this._evaluateRawFinding(finding);
            if (evaluation.status === VerificationState.VERIFIED) {
                finding.verification_state = VerificationState.VERIFIED;
                finding.confidence = evaluation.confidence;
                finding.verification_level = evaluation.level;
                finding.description += `\n\nVerified at Level ${evaluation.level}: ${evaluation.justification}`;
                verifiedFindings.push(finding);
                this._persistFinding(finding);
                this._persistVerification(finding.id, evaluation);
            } else {
                finding.verification_state = VerificationState.CANDIDATE;
                finding.confidence = evaluation.confidence;
                finding.verification_level = evaluation.level;
                candidateFindings.push(finding);
                this._persistFinding(finding);
                this._persistVerification(finding.id, evaluation);
            }
        }

        const reportMarkdown = this._generateReportMarkdown(verificationSummaries, verifiedFindings, candidateFindings);

        return {
            verifiedFindings,
            candidateFindings,
            verificationSummaries,
            reportMarkdown
        };
    }

    verifySingleFinding(finding, allFindings = [finding]) {
        return this._evaluateRawFinding(finding);
    }

    _inspectArtifact(ev, finding) {
        if (!ev || !ev.artifact_path) {
            return { exists: false, valid: false, hasCounterexample: false, reason: 'No artifact path specified' };
        }

        const artifactPath = ev.artifact_path;
        if (!fs.existsSync(artifactPath)) {
            return { exists: false, valid: false, hasCounterexample: false, reason: `Artifact does not exist on disk: ${artifactPath}` };
        }

        let rawBuffer;
        try {
            rawBuffer = fs.readFileSync(artifactPath);
        } catch (err) {
            return { exists: true, valid: false, hasCounterexample: false, malformed: true, reason: `Failed to read artifact: ${err.message}` };
        }

        // 1. Cryptographic Hash Validation
        if (ev.artifact_hash) {
            const actualHash = crypto.createHash('sha256').update(rawBuffer).digest('hex');
            if (actualHash.toLowerCase() !== ev.artifact_hash.toLowerCase()) {
                return {
                    exists: true,
                    valid: false,
                    tampered: true,
                    hasCounterexample: false,
                    reason: `Cryptographic SHA-256 hash mismatch! Stored: ${ev.artifact_hash}, computed: ${actualHash}`
                };
            }
        }

        // 2. Cross-Run / Cross-Project Replay Defense
        if (ev.run_id && finding.run_id && ev.run_id !== finding.run_id) {
            return {
                exists: true,
                valid: false,
                replayed: true,
                hasCounterexample: false,
                reason: `Cross-run replay attack: evidence run '${ev.run_id}' does not match finding run '${finding.run_id}'`
            };
        }

        const ext = path.extname(artifactPath).toLowerCase();
        const toolName = (ev.tool_name || ev.tool || finding.source_tool || '').toLowerCase();

        // 3. Domain Compatibility Check
        const locations = (finding.source_locations || []).map(l => (typeof l === 'string' ? l : l.path || '')).filter(Boolean);
        if (finding.location) locations.push(finding.location);
        if (finding.rtl_location) locations.push(finding.rtl_location);

        const isSoftwareLocation = locations.some(loc => /\.(c|cpp|cc|cxx|h|hpp|py|js|ts|java|rs|go)$/i.test(loc));
        const isHardwareLocation = locations.some(loc => /\.(v|sv|vh|svh|vhd|vhdl)$/i.test(loc));

        // Incompatible domain: Hardware VCD attached to software finding
        if (ext === '.vcd' || toolName === 'symbiyosys' || toolName === 'yosys') {
            if (isSoftwareLocation && !isHardwareLocation) {
                return {
                    exists: true,
                    valid: false,
                    domainMismatch: true,
                    hasCounterexample: false,
                    reason: `Cross-domain mismatch: Hardware verification artifact (${path.basename(artifactPath)}) cannot verify software finding in ${locations.join(', ')}`
                };
            }
        }

        // Incompatible domain: Software traceback / semgrep attached to hardware finding
        const contentStr = rawBuffer.toString('utf-8');
        const isSoftwareTraceback = contentStr.includes('Traceback (most recent call last)');
        if (isSoftwareTraceback || (toolName === 'semgrep' && isHardwareLocation && !isSoftwareLocation)) {
            if (isHardwareLocation && !isSoftwareLocation) {
                return {
                    exists: true,
                    valid: false,
                    domainMismatch: true,
                    hasCounterexample: false,
                    reason: `Cross-domain mismatch: Software traceback cannot verify hardware RTL finding in ${locations.join(', ')}`
                };
            }
        }

        // 4. Dynamic Proof Reproduction Evidence
        if (ev.evidence_type === 'DYNAMIC_PROOF_REPRODUCTION' || ev.tool === 'controlled_proof_verifier') {
            const hasCounterexample = !!(ev.raw_evidence?.hasCounterexample);
            const rate = ev.raw_evidence?.reproducibility_rate || '1/1';
            const impact = ev.raw_evidence?.impact_class || 'UNKNOWN';
            return {
                exists: true,
                valid: true,
                hasCounterexample,
                reason: hasCounterexample 
                    ? `Controlled proof reproduced: ${impact} (${rate} reproductions)` 
                    : `Controlled proof executed but failed to reproduce under tested conditions`
            };
        }

        // 5. File-type specific validation
        // Markdown / Documentation claims
        if (ext === '.md' || ext === '.markdown') {
            return {
                exists: true,
                valid: true,
                hasCounterexample: false,
                reason: 'Documentation artifact is claim/reference only, not a concrete dynamic counterexample'
            };
        }

        // VCD waveform validation
        if (ext === '.vcd') {
            const hasHeader = (contentStr.includes('$date') || contentStr.includes('$version') || contentStr.includes('$timescale')) &&
                              (contentStr.includes('$enddefinitions') || contentStr.includes('$timescale'));
            if (!hasHeader) {
                return {
                    exists: true,
                    valid: false,
                    malformed: true,
                    hasCounterexample: false,
                    reason: 'Malformed VCD: Missing standard header directives ($date, $version, $enddefinitions, $timescale)'
                };
            }
            const hasWaveformTrace = /#\d+/.test(contentStr) ||
                                     contentStr.includes('Assert failed') ||
                                     contentStr.includes('violation');
            return {
                exists: true,
                valid: true,
                hasCounterexample: hasWaveformTrace,
                reason: hasWaveformTrace ? 'Valid VCD waveform counterexample trace present' : 'Valid VCD waveform present without assertion violation'
            };
        }

        // JSON telemetry validation
        if (ext === '.json') {
            let parsed;
            try {
                parsed = JSON.parse(contentStr);
            } catch (err) {
                return {
                    exists: true,
                    valid: false,
                    malformed: true,
                    hasCounterexample: false,
                    reason: `Malformed JSON telemetry: ${err.message}`
                };
            }

            if (parsed.crashes !== undefined) {
                const count = Number(parsed.crashes);
                const hasCrash = !isNaN(count) && count > 0;
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: hasCrash,
                    reason: hasCrash ? `Telemetry records ${count} crashes` : `Telemetry indicates 0 crashes (benign execution)`
                };
            }

            if (parsed.crashesFound !== undefined) {
                const count = Number(parsed.crashesFound);
                const hasCrash = !isNaN(count) && count > 0;
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: hasCrash,
                    reason: hasCrash ? `Telemetry records ${count} crashes found` : `Telemetry indicates 0 crashes found`
                };
            }

            if (parsed.crash_count !== undefined) {
                const count = Number(parsed.crash_count);
                const hasCrash = !isNaN(count) && count > 0;
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: hasCrash,
                    reason: hasCrash ? `Crash count: ${count}` : `Zero crash count recorded`
                };
            }

            if (parsed.violations !== undefined) {
                const count = Number(parsed.violations);
                const hasViolation = !isNaN(count) && count > 0;
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: hasViolation,
                    reason: hasViolation ? `Telemetry records ${count} invariant violations` : `Zero invariant violations recorded`
                };
            }

            if (parsed.counterexample === true || parsed.hasCounterexample === true) {
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: true,
                    reason: `Telemetry explicitly confirms counterexample trace: ${parsed.reason || 'reproduced'}`
                };
            }

            if (parsed.findings && Array.isArray(parsed.findings) && parsed.findings.length > 0) {
                // Static findings array in telemetry is an observation, not a dynamic reproducing counterexample
                return {
                    exists: true,
                    valid: true,
                    hasCounterexample: false,
                    reason: `Telemetry contains ${parsed.findings.length} static findings (observation only, dynamic counterexample required for full verification)`
                };
            }

            return {
                exists: true,
                valid: true,
                hasCounterexample: false,
                reason: 'JSON telemetry contains no crash or counterexample indicators'
            };
        }

        // Text / Log files
        const isPassedLog = /current run:\s*PASS/i.test(contentStr) ||
                            /\bAll tests passed\b/i.test(contentStr) ||
                            /\bstatus:\s*PASS\b/i.test(contentStr);
        if (isPassedLog) {
            return {
                exists: true,
                valid: true,
                hasCounterexample: false,
                reason: 'Log indicates test run passed successfully'
            };
        }

        // Strict affirmative execution failure traces (avoiding generic "crash", "FAIL", or "verified" substring matches)
        const hasFailurePattern = /\bAssert(ion)? failed\b/i.test(contentStr) ||
                                 /\bBMC failed at step\b/i.test(contentStr) ||
                                 /\bFATAL: assertion violation\b/i.test(contentStr) ||
                                 /\bcounterexample trace found\b/i.test(contentStr) ||
                                 /\bSegmentation fault \(core dumped\)\b/i.test(contentStr) ||
                                 /\bAddressSanitizer:\s*([A-Za-z-]+)\b/i.test(contentStr) ||
                                 /\bUndefinedBehaviorSanitizer:\s*([A-Za-z-]+)\b/i.test(contentStr) ||
                                 /\bFatal error: Core dumped\b/i.test(contentStr);

        return {
            exists: true,
            valid: true,
            hasCounterexample: hasFailurePattern,
            reason: hasFailurePattern ? 'Execution log contains affirmative assertion failure trace' : 'Log file contains no counterexample trace'
        };
    }

    _checkDataflowReachability(finding) {
        if (finding.dataflow_reachable) return true;
        for (const ev of (finding.evidence || [])) {
            if (ev?.raw_evidence?.dataflow_reachable) return true;
        }

        if (this.codeGraph && typeof this.codeGraph.findAttackPaths === 'function') {
            const attackPaths = this.codeGraph.findAttackPaths();
            if (attackPaths.length === 0) return false;

            const locations = (finding.source_locations || []).map(l => (typeof l === 'string' ? l : l.path || '')).filter(Boolean);
            if (finding.location) locations.push(finding.location);
            if (finding.rtl_location) locations.push(finding.rtl_location);

            const fileNames = locations.map(l => path.basename(l));

            for (const ap of attackPaths) {
                const pathElements = (Array.isArray(ap.path) ? ap.path : []).concat(ap.sink ? (typeof ap.sink === 'string' ? [ap.sink] : [ap.sink.id, ap.sink.label]) : []);
                const touchesFinding = pathElements.some(elem => {
                    const elemStr = String(elem);
                    return fileNames.some(fn => fn && elemStr.includes(fn)) || locations.some(loc => loc && elemStr.includes(loc));
                });
                if (touchesFinding) {
                    return true;
                }
            }
        }
        return false;
    }

    _checkHypothesisReachability(hyp, matchingFindings) {
        for (const f of matchingFindings) {
            if (f.dataflow_reachable) return true;
            for (const ev of (f.evidence || [])) {
                if (ev?.raw_evidence?.dataflow_reachable) return true;
            }
        }

        if (this.codeGraph && typeof this.codeGraph.findAttackPaths === 'function') {
            const attackPaths = this.codeGraph.findAttackPaths();
            if (attackPaths.length === 0) return false;

            const hypAssets = (hyp.affected_assets || []).map(a => path.basename(a));

            for (const ap of attackPaths) {
                const pathElements = (Array.isArray(ap.path) ? ap.path : []).concat(ap.sink ? (typeof ap.sink === 'string' ? [ap.sink] : [ap.sink.id, ap.sink.label]) : []);
                const touchesHyp = pathElements.some(elem => {
                    const elemStr = String(elem);
                    return hypAssets.some(ha => ha && elemStr.includes(ha));
                });
                if (touchesHyp) {
                    return true;
                }
            }
        }
        return false;
    }

    _evaluateRawFinding(finding) {
        const evidences = finding.evidence || [];
        if (evidences.length === 0) {
            return {
                level: VerificationLevel.E1_TOOL_OBSERVATION,
                status: VerificationState.CANDIDATE,
                confidence: 0.60,
                justification: `E1 Tool Observation: Static observation without dedicated reproducible artifact.`
            };
        }

        let anyArtifactExists = false;
        let anyCounterexample = false;
        let lastReason = '';

        for (const ev of evidences) {
            const insp = this._inspectArtifact(ev, finding);
            if (insp.exists) anyArtifactExists = true;
            lastReason = insp.reason;

            if (insp.tampered) {
                return {
                    level: VerificationLevel.E0_CLAIM_ONLY,
                    status: VerificationState.REFUTED,
                    confidence: 0.1,
                    justification: `E0 Refuted: Artifact integrity failure - ${insp.reason}`
                };
            }

            if (insp.replayed) {
                return {
                    level: VerificationLevel.E0_CLAIM_ONLY,
                    status: VerificationState.REFUTED,
                    confidence: 0.1,
                    justification: `E0 Refuted: Evidence provenance violation - ${insp.reason}`
                };
            }

            if (insp.domainMismatch) {
                return {
                    level: VerificationLevel.E1_TOOL_OBSERVATION,
                    status: VerificationState.CANDIDATE,
                    confidence: 0.4,
                    justification: `E1 Candidate: Cross-domain evidence rejected - ${insp.reason}`
                };
            }

            if (insp.malformed) {
                return {
                    level: VerificationLevel.E1_TOOL_OBSERVATION,
                    status: VerificationState.CANDIDATE,
                    confidence: 0.4,
                    justification: `E1 Candidate: Corrupt evidence rejected - ${insp.reason}`
                };
            }

            if (insp.hasCounterexample) {
                anyCounterexample = true;
                lastReason = insp.reason;
                break;
            }
        }

        // LLM self-certification rejection: LLM claims cannot verify without concrete counterexample
        const isLLMClaim = finding.llm_certified || 
                           finding.source_tool === 'llm' || 
                           finding.source_tool === 'deep_reasoning' ||
                           finding.source_tool === 'hypothesis_generator';
        if (isLLMClaim && !anyCounterexample) {
            return {
                level: VerificationLevel.E1_TOOL_OBSERVATION,
                status: VerificationState.CANDIDATE,
                confidence: 0.50,
                justification: `E1 Candidate: LLM/reasoning claim cannot self-certify without concrete dynamic execution counterexample or formal proof.`
            };
        }

        const isDataflowReachable = this._checkDataflowReachability(finding);
        const hasSecurityProperty = !!(finding.security_property || finding.cwe_id);

        if (anyCounterexample) {
            if (isDataflowReachable) {
                return {
                    level: VerificationLevel.E5_ATTACKER_REACHABILITY,
                    status: VerificationState.VERIFIED,
                    confidence: 0.99,
                    justification: `E5 Attacker Reachability confirmed: violation reproduces with external dataflow path to sink (${lastReason}).`
                };
            }
            if (hasSecurityProperty) {
                return {
                    level: VerificationLevel.E4_SECURITY_RELEVANCE,
                    status: VerificationState.VERIFIED,
                    confidence: 0.95,
                    justification: `E4 Security Relevance verified: violation reproduces on security property '${finding.security_property || finding.cwe_id}' (${lastReason}).`
                };
            }
            return {
                level: VerificationLevel.E3_SEMANTIC_MATCH,
                status: VerificationState.VERIFIED,
                confidence: 0.90,
                justification: `E3 Semantic Match verified: reproducible violation artifact on disk (${lastReason}).`
            };
        }

        if (finding.proof_status === 'FAILED_TO_REPRODUCE') {
            return {
                level: anyArtifactExists ? VerificationLevel.E2_REPRODUCIBLE_ARTIFACT : VerificationLevel.E1_TOOL_OBSERVATION,
                status: VerificationState.CANDIDATE,
                confidence: 0.55,
                justification: `Retained as Candidate: Proof not reproduced under tested conditions (${finding.proof_record?.failure_reason || lastReason || 'unreproduced'}).`
            };
        }

        if (anyArtifactExists) {
            return {
                level: VerificationLevel.E2_REPRODUCIBLE_ARTIFACT,
                status: VerificationState.CANDIDATE,
                confidence: 0.75,
                justification: `E2 Reproducible Artifact present, but dynamic counterexample/crash not triggered (${lastReason}).`
            };
        }

        return {
            level: VerificationLevel.E1_TOOL_OBSERVATION,
            status: VerificationState.CANDIDATE,
            confidence: 0.60,
            justification: `E1 Tool Observation: Static observation without dedicated reproducible artifact.`
        };
    }

    async _evaluateHypothesis(hyp, toolFindings, telemetries) {
        // Match findings grounded in locations or affected assets
        const matchingFindings = toolFindings.filter(f => {
            const fLocations = (f.source_locations || []).map(loc => (typeof loc === 'string' ? loc : loc.path || '')).filter(Boolean);
            if (f.location) fLocations.push(f.location);
            if (f.rtl_location) fLocations.push(f.rtl_location);
            const hypAssets = (hyp.affected_assets || []);

            const assetMatch = hypAssets.some(asset => 
                fLocations.some(l => l.includes(asset) || path.basename(l) === path.basename(asset))
            );

            return assetMatch;
        });

        // Examine concrete artifacts
        const artifactsExamined = [];
        let hasReproducibleArtifact = false;
        let hasViolationDemonstrated = false;
        let hasToolObservation = matchingFindings.length > 0;
        let integrityViolated = false;
        let integrityReason = '';

        for (const f of matchingFindings) {
            for (const ev of (f.evidence || [])) {
                if (ev.artifact_path) {
                    const insp = this._inspectArtifact(ev, f);
                    if (insp.exists) {
                        artifactsExamined.push(ev.artifact_path);
                        hasReproducibleArtifact = true;
                    }
                    if (insp.tampered || insp.replayed) {
                        integrityViolated = true;
                        integrityReason = insp.reason;
                    } else if (insp.hasCounterexample) {
                        hasViolationDemonstrated = true;
                    }
                }
            }
        }

        if (integrityViolated) {
            return {
                hypothesis_id: hyp.hypothesis_id,
                cwe_id: hyp.cwe_id,
                title: hyp.title,
                claimed: hyp.claim,
                evidence_examined: artifactsExamined,
                level: VerificationLevel.E0_CLAIM_ONLY,
                status: VerificationState.REFUTED,
                confidence: 0.1,
                severity: Severity.LOW,
                justification: `E0 Refuted: Evidence integrity violation: ${integrityReason}`,
                matched_finding_ids: matchingFindings.map(m => m.id),
                source_locations: matchingFindings.flatMap(m => m.source_locations || []),
                supporting_evidence: matchingFindings.flatMap(m => m.evidence || [])
            };
        }

        const isDataflowReachable = this._checkHypothesisReachability(hyp, matchingFindings);

        let level = VerificationLevel.E0_CLAIM_ONLY;
        let status = VerificationState.INCONCLUSIVE;
        let justification = "No matching concrete tool execution evidence found.";
        let confidence = 0.2;
        let severity = Severity.MEDIUM;

        if (hasViolationDemonstrated) {
            if (isDataflowReachable) {
                level = VerificationLevel.E5_ATTACKER_REACHABILITY;
                status = VerificationState.VERIFIED;
                confidence = 0.99;
                severity = matchingFindings[0]?.severity || Severity.CRITICAL;
                justification = `E5 Attacker Reachability verified: concrete counterexample trace reproduces violation with attacker-controlled path.`;
            } else if (hyp.security_boundary || hyp.security_property === 'SECURITY_BOUNDARY' || hyp.has_security_impact) {
                level = VerificationLevel.E4_SECURITY_RELEVANCE;
                status = VerificationState.VERIFIED;
                confidence = 0.95;
                severity = matchingFindings[0]?.severity || Severity.HIGH;
                justification = `E4 Security Relevance verified: concrete artifact violates security invariant '${hyp.security_property || hyp.security_boundary}'.`;
            } else {
                level = VerificationLevel.E3_SEMANTIC_MATCH;
                status = VerificationState.VERIFIED;
                confidence = 0.95;
                severity = matchingFindings[0]?.severity || Severity.HIGH;
                justification = `Reproducible violation artifact verified in execution trace: ${artifactsExamined.join(', ')}`;
            }
        } else if (hasReproducibleArtifact && (matchingFindings.some(f => f.has_reproducible_artifact || f.evidence?.some(e => e.evidence_type === 'REPRODUCIBLE_ARTIFACT')))) {
            level = VerificationLevel.E2_REPRODUCIBLE_ARTIFACT;
            status = VerificationState.CANDIDATE;
            confidence = 0.75;
            severity = matchingFindings[0]?.severity || Severity.MEDIUM;
            justification = `E2 Reproducible Artifact present (${artifactsExamined.join(', ')}), but specific invariant violation not triggered.`;
        } else if (hasToolObservation) {
            level = VerificationLevel.E1_TOOL_OBSERVATION;
            status = VerificationState.CANDIDATE;
            confidence = 0.65;
            severity = matchingFindings[0]?.severity || Severity.MEDIUM;
            justification = `Observation supported by static inspection (${matchingFindings.map(m => m.title).join('; ')}), but lacks dynamic reproducing counterexample trace.`;
        } else {
            status = VerificationState.REFUTED;
            level = VerificationLevel.E0_CLAIM_ONLY;
            justification = `Tools executed cleanly. No supporting technical evidence found for claim: "${hyp.claim}".`;
        }

        return {
            hypothesis_id: hyp.hypothesis_id,
            cwe_id: hyp.cwe_id,
            title: hyp.title,
            claimed: hyp.claim,
            evidence_examined: artifactsExamined,
            level,
            status,
            confidence,
            severity,
            justification,
            matched_finding_ids: matchingFindings.map(m => m.id),
            source_locations: matchingFindings.flatMap(m => m.source_locations || []),
            supporting_evidence: matchingFindings.flatMap(m => m.evidence || [])
        };
    }

    _persistFinding(finding) {
        if (this.db && typeof this.db.saveFinding === 'function') {
            try {
                this.db.saveFinding({
                    id: finding.id,
                    runId: this.runId || 'global',
                    title: finding.title,
                    type: finding.cwe_id || 'SECURITY_FINDING',
                    severity: finding.severity || Severity.MEDIUM,
                    confidence: finding.confidence || 0.5,
                    verificationState: finding.verification_state,
                    location: finding.source_locations?.[0]?.path || finding.rtl_location || null
                });
            } catch (err) {
                console.error(`[-] Failed to persist finding to DB: ${err.message}`);
            }
        }
    }

    _persistVerification(findingId, evalResult) {
        if (this.db && typeof this.db.saveVerificationResult === 'function') {
            try {
                this.db.saveVerificationResult({
                    id: `VR-${crypto.randomBytes(4).toString('hex')}`,
                    findingId,
                    level: evalResult.level,
                    status: evalResult.status,
                    justification: evalResult.justification,
                    runId: this.runId || 'global'
                });
            } catch (err) {
                console.error(`[-] Failed to persist verification result to DB: ${err.message}`);
            }
        }
    }

    _generateReportMarkdown(summaries, verified, candidates) {
        let md = `# HWSEC Layered Verification Report\n\n`;
        md += `### Executive Summary\n`;
        md += `- **Hypotheses Evaluated**: ${summaries.length}\n`;
        md += `- **Verified Findings (E3–E5)**: ${verified.length}\n`;
        md += `- **Candidate Findings (E1–E2)**: ${candidates.length}\n`;
        md += `- **Refuted Claims (E0)**: ${summaries.filter(s => s.status === 'REFUTED').length}\n\n`;

        md += `### Verification Status by Hypothesis\n\n`;
        for (const s of summaries) {
            md += `#### [${s.status}] (${s.level}) ${s.hypothesis_id}: ${s.title}\n`;
            md += `- **Claim**: ${s.claimed}\n`;
            md += `- **Evidence Level**: \`${s.level}\`\n`;
            md += `- **Confidence**: ${(s.confidence * 100).toFixed(0)}%\n`;
            md += `- **Artifacts Examined**: ${s.evidence_examined.length > 0 ? s.evidence_examined.join(', ') : 'None'}\n`;
            md += `- **Justification**: ${s.justification}\n\n`;
        }
        return md;
    }
}

export { LayeredVerifier as ArtifactGatedVerifier };
