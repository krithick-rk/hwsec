import crypto from 'crypto';

/**
 * HWSEC Benchmark Evidence Package (BEP) Data Model & Schema Definitions
 */

export const GroundTruthLabel = Object.freeze({
    VULNERABLE: 'VULNERABLE',
    NOT_VULNERABLE: 'NOT_VULNERABLE',
    UNKNOWN: 'UNKNOWN',
    EXCLUDED: 'EXCLUDED'
});

export const PredictionState = Object.freeze({
    DETECTED: 'DETECTED',
    NOT_DETECTED: 'NOT_DETECTED',
    INCONCLUSIVE: 'INCONCLUSIVE'
});

export const CaseClassification = Object.freeze({
    TP: 'TP',
    FP: 'FP',
    FN: 'FN',
    TN: 'TN',
    INCONCLUSIVE: 'INCONCLUSIVE',
    UNKNOWN: 'UNKNOWN'
});

export const InconclusiveReason = Object.freeze({
    MISSING_BUILD_CONTEXT: 'MISSING_BUILD_CONTEXT',
    MISSING_DEPENDENCY: 'MISSING_DEPENDENCY',
    VALIDATION_TIMEOUT: 'VALIDATION_TIMEOUT',
    NO_REPRODUCIBLE_PATH: 'NO_REPRODUCIBLE_PATH',
    AMBIGUOUS_DATAFLOW: 'AMBIGUOUS_DATAFLOW',
    TOOL_UNAVAILABLE: 'TOOL_UNAVAILABLE',
    UNSUPPORTED_VULNERABILITY_CLASS: 'UNSUPPORTED_VULNERABILITY_CLASS',
    SAFETY_GATE_REJECTED: 'SAFETY_GATE_REJECTED',
    UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF: 'UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF'
});

export const RecommendedNextAction = Object.freeze({
    [InconclusiveReason.MISSING_BUILD_CONTEXT]: 'SUPPLY_MAVEN_BUILD_METADATA',
    [InconclusiveReason.MISSING_DEPENDENCY]: 'PROVIDE_LOCAL_JAR_DEPENDENCIES',
    [InconclusiveReason.VALIDATION_TIMEOUT]: 'INCREASE_SANDBOX_TIMEOUT_BUDGET',
    [InconclusiveReason.NO_REPRODUCIBLE_PATH]: 'SYNTHESIZE_TAINTED_INPUT_FIXTURE',
    [InconclusiveReason.AMBIGUOUS_DATAFLOW]: 'EXTRACT_METHOD_LEVEL_CPG_SLICE',
    [InconclusiveReason.TOOL_UNAVAILABLE]: 'INITIALIZE_TARGET_TOOL_RUNTIME',
    [InconclusiveReason.UNSUPPORTED_VULNERABILITY_CLASS]: 'IMPLEMENT_CUSTOM_DETERMINISTIC_VALIDATOR',
    [InconclusiveReason.SAFETY_GATE_REJECTED]: 'REVIEW_SAFETY_BOUNDS_AND_SANDBOX_PERMISSIONS',
    [InconclusiveReason.UNRESOLVED_CANDIDATE_NO_DETERMINISTIC_PROOF]: 'GENERATE_AND_EXECUTE_DETERMINISTIC_PROOF_HARNESS'
});

export const NotDetectedThreshold = Object.freeze({
    MIN_ANALYZERS_EXECUTED: 1,
    MAX_UNPARSED_FILES: 0,
    ALLOW_TIMEOUTS: false,
    DESCRIPTION: 'Clean deterministic analysis with full file coverage and zero qualifying findings'
});

export function evaluatePrediction(prediction, groundTruthLabel) {
    if (prediction === PredictionState.INCONCLUSIVE) {
        return CaseClassification.INCONCLUSIVE;
    }
    if (prediction === PredictionState.DETECTED) {
        if (groundTruthLabel === GroundTruthLabel.VULNERABLE) return CaseClassification.TP;
        if (groundTruthLabel === GroundTruthLabel.NOT_VULNERABLE) return CaseClassification.FP;
        return CaseClassification.INCONCLUSIVE;
    }
    if (prediction === PredictionState.NOT_DETECTED) {
        if (groundTruthLabel === GroundTruthLabel.VULNERABLE) return CaseClassification.FN;
        if (groundTruthLabel === GroundTruthLabel.NOT_VULNERABLE) return CaseClassification.TN;
        return CaseClassification.INCONCLUSIVE;
    }
    return CaseClassification.INCONCLUSIVE;
}

export const TriggerType = Object.freeze({
    STATIC_FINDING: 'STATIC_FINDING',
    ANALYZER_DISAGREEMENT: 'ANALYZER_DISAGREEMENT',
    BOUNDARY_CROSSING: 'BOUNDARY_CROSSING',
    DANGEROUS_SINK: 'DANGEROUS_SINK',
    GRAPH_PATH: 'GRAPH_PATH',
    SPEC_DIVERGENCE: 'SPEC_DIVERGENCE',
    SECURITY_INVARIANT: 'SECURITY_INVARIANT',
    HEURISTIC_SUSPICION: 'HEURISTIC_SUSPICION',
    PRIOR_EVIDENCE: 'PRIOR_EVIDENCE',
    NOVELTY_HYPOTHESIS: 'NOVELTY_HYPOTHESIS'
});

export const EvidenceBasis = Object.freeze({
    SUPPORTED_BY_DETERMINISTIC: 'SUPPORTED_BY_DETERMINISTIC',
    CONTRADICTED_BY_DETERMINISTIC: 'CONTRADICTED_BY_DETERMINISTIC',
    UNRESOLVED: 'UNRESOLVED',
    MODEL_ONLY: 'MODEL_ONLY'
});

export const ReclassificationType = Object.freeze({
    EVIDENCE_BACKED: 'EVIDENCE_BACKED',
    MODEL_ASSISTED: 'MODEL_ASSISTED',
    MODEL_ONLY: 'MODEL_ONLY',
    NONE: 'NONE'
});

export const FPTransitionCategory = Object.freeze({
    DETERMINISTICALLY_CONFIRMED: 'DETERMINISTICALLY_CONFIRMED',
    PROOF_CONFIRMED: 'PROOF_CONFIRMED',
    HYBRID_CONFIRMED: 'HYBRID_CONFIRMED',
    LLM_ONLY: 'LLM_ONLY',
    UNRESOLVED: 'UNRESOLVED'
});

export function computeSha256(data) {
    const content = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHash('sha256').update(content).digest('hex');
}

export function createBenchmarkManifest(params = {}) {
    return {
        benchmark_id: params.benchmark_id || 'unknown-benchmark',
        benchmark_version: params.benchmark_version || '1.0.0',
        benchmark_revision: params.benchmark_revision || 'HEAD',
        source_repository: params.source_repository || 'local',
        source_commit: params.source_commit || 'HEAD',
        dataset_root: params.dataset_root || './',
        dataset_sha256: params.dataset_sha256 || '',
        ground_truth_source: params.ground_truth_source || 'manifests/ground_truth.json',
        ground_truth_version: params.ground_truth_version || '1.0.0',
        case_count: params.case_count || 0,
        language: params.language || 'multi',
        languages: params.languages || ['multi'],
        toolchain: params.toolchain || {},
        hwsec_revision: params.hwsec_revision || 'v3.0.0',
        config_hash: params.config_hash || '',
        run_id: params.run_id || `run_${Date.now()}`,
        created_at: params.created_at || new Date().toISOString(),
        enabled_analyzers: params.enabled_analyzers || [],
        disabled_analyzers: params.disabled_analyzers || [],
        analyzer_versions: params.analyzer_versions || {},
        timeouts: params.timeouts || { analyzer_ms: 120000, sandbox_ms: 30000 },
        proof_mode: params.proof_mode || 'standard',
        rag_enabled: params.rag_enabled !== undefined ? params.rag_enabled : true,
        graph_enabled: params.graph_enabled !== undefined ? params.graph_enabled : true,
        candidate_mode: params.candidate_mode || 'standard',
        novelty_mode: params.novelty_mode || 'standard',
        model_routing: params.model_routing || {},
        providers_used: params.providers_used || [],
        scheduler_config: params.scheduler_config || {},
        seeds: params.seeds || { random: 42 },
        environment: params.environment || {}
    };
}

export function createGroundTruthRecord(params = {}) {
    return {
        case_id: params.case_id || `CASE-${crypto.randomBytes(4).toString('hex')}`,
        benchmark_id: params.benchmark_id || 'unknown-benchmark',
        source_file: params.source_file || '',
        source_revision: params.source_revision || 'HEAD',
        function_or_method: params.function_or_method || '',
        line_range: params.line_range || [1, 1],
        cwe: params.cwe || 'CWE-000',
        ground_truth_label: params.ground_truth_label || GroundTruthLabel.UNKNOWN,
        ground_truth_source: params.ground_truth_source || 'benchmark_manifest',
        ground_truth_confidence: params.ground_truth_confidence || 'authoritative',
        ground_truth_reference: params.ground_truth_reference || ''
    };
}

export function createRawFindingRecord(params = {}) {
    return {
        finding_id: params.finding_id || `RAW-${crypto.randomBytes(4).toString('hex')}`,
        analyzer: params.analyzer || 'unknown',
        analyzer_version: params.analyzer_version || '1.0.0',
        raw_artifact: params.raw_artifact || '',
        raw_sha256: params.raw_sha256 || '',
        rule_id: params.rule_id || '',
        file: params.file || '',
        start_line: params.start_line || 1,
        end_line: params.end_line || 1,
        severity: params.severity || 'MEDIUM',
        message: params.message || '',
        execution_id: params.execution_id || '',
        timestamp: params.timestamp || new Date().toISOString()
    };
}

export function createNormalizedFindingRecord(params = {}) {
    return {
        finding_id: params.finding_id || `NORM-${crypto.randomBytes(4).toString('hex')}`,
        linked_raw_ids: params.linked_raw_ids || [],
        cwe: params.cwe || 'CWE-000',
        cwe_family: params.cwe_family || 'UNKNOWN',
        file: params.file || '',
        start_line: params.start_line || 1,
        end_line: params.end_line || 1,
        source_sink_info: params.source_sink_info || null,
        reachability: params.reachability || 'UNKNOWN',
        confidence: params.confidence || 0.5,
        severity: params.severity || 'MEDIUM',
        evidence_refs: params.evidence_refs || [],
        correlations: params.correlations || []
    };
}

export function createCandidateRecord(params = {}) {
    return {
        candidate_id: params.candidate_id || `CAND-${crypto.randomBytes(4).toString('hex')}`,
        case_id: params.case_id || '',
        trigger_types: params.trigger_types || [TriggerType.STATIC_FINDING],
        source_finding_ids: params.source_finding_ids || [],
        hypothesis: params.hypothesis || '',
        suspected_cwe: params.suspected_cwe || 'CWE-000',
        source_location: params.source_location || null,
        source_boundary: params.source_boundary || 'unspecified_boundary',
        dataflow_path: params.dataflow_path || [],
        dangerous_sink: params.dangerous_sink || 'unspecified_sink',
        required_preconditions: params.required_preconditions || [],
        expected_security_impact: params.expected_security_impact || 'unspecified_impact',
        recommended_validator: params.recommended_validator || 'targeted_sandbox_validator',
        confidence_metadata: params.confidence_metadata || {},
        evidence_refs: params.evidence_refs || [],
        created_by: params.created_by || 'candidateGenerator',
        created_at: params.created_at || new Date().toISOString()
    };
}

export function createTransitionRecord(params = {}) {
    return {
        transition_id: params.transition_id || `TR-${crypto.randomBytes(4).toString('hex')}`,
        case_id: params.case_id || '',
        from_state: params.from_state || 'NOT_EVALUATED',
        to_state: params.to_state || 'UNVERIFIED',
        stage: params.stage || 'STATIC_ANALYSIS',
        reason_code: params.reason_code || 'INITIAL_SCAN',
        inconclusive_reason: params.inconclusive_reason || null,
        recommended_next_action: params.recommended_next_action || null,
        evidence_refs: params.evidence_refs || [],
        verifier_decision_id: params.verifier_decision_id || null,
        proof_ref: params.proof_ref || null,
        transition_type: params.transition_type || ReclassificationType.NONE,
        timestamp: params.timestamp || new Date().toISOString()
    };
}

export function createVerifierDecisionRecord(params = {}) {
    return {
        decision_id: params.decision_id || `VD-${crypto.randomBytes(4).toString('hex')}`,
        case_id: params.case_id || '',
        candidate_id: params.candidate_id || '',
        verifier_type: params.verifier_type || 'HYBRID',
        provider: params.provider || 'gemini',
        model: params.model || 'gemini-2.5-pro',
        model_revision: params.model_revision || 'latest',
        prompt_template_hash: params.prompt_template_hash || '',
        input_evidence_refs: params.input_evidence_refs || [],
        decision: params.decision || 'KEEP',
        confidence: params.confidence || 0.8,
        reason_codes: params.reason_codes || [],
        evidence_basis: params.evidence_basis || EvidenceBasis.SUPPORTED_BY_DETERMINISTIC,
        suspected_cwe: params.suspected_cwe || null,
        source_boundary: params.source_boundary || null,
        dataflow_path: params.dataflow_path || null,
        dangerous_sink: params.dangerous_sink || null,
        required_preconditions: params.required_preconditions || null,
        expected_security_impact: params.expected_security_impact || null,
        recommended_deterministic_validator: params.recommended_deterministic_validator || null,
        confidence_reasoning_metadata: params.confidence_reasoning_metadata || null,
        output_artifact: params.output_artifact || '',
        output_sha256: params.output_sha256 || '',
        deterministic_validation_refs: params.deterministic_validation_refs || [],
        human_review: params.human_review || null,
        timestamp: params.timestamp || new Date().toISOString()
    };
}

export function createProofArtifactRecord(params = {}) {
    return {
        proof_id: params.proof_id || `PROOF-${crypto.randomBytes(4).toString('hex')}`,
        case_id: params.case_id || '',
        hypothesis_id: params.hypothesis_id || '',
        proof_mode: params.proof_mode || 'standard',
        sandbox_id: params.sandbox_id || '',
        generated_test_id: params.generated_test_id || '',
        command_struct: params.command_struct || {},
        exit_code: params.exit_code !== undefined ? params.exit_code : -1,
        timeout_state: params.timeout_state || false,
        stdout_hash: params.stdout_hash || '',
        stderr_hash: params.stderr_hash || '',
        result_parser: params.result_parser || 'ASanParser',
        repetition_count: params.repetition_count || '0/3',
        e0_e5_state: params.e0_e5_state || 'E1',
        promotion_reason: params.promotion_reason || '',
        verdict: params.verdict || 'FAILED_TO_REPRODUCE',
        timestamp: params.timestamp || new Date().toISOString()
    };
}

export function createHardwareAssertionRecord(params = {}) {
    return {
        assertion_id: params.assertion_id || `SVA-${crypto.randomBytes(4).toString('hex')}`,
        case_id: params.case_id || '',
        source_rtl_revision: params.source_rtl_revision || 'HEAD',
        generated_assertion_text: params.generated_assertion_text || '',
        assertion_sha256: params.assertion_sha256 || '',
        generator_version: params.generator_version || '1.0.0',
        generation_hypothesis: params.generation_hypothesis || '',
        compile_result: params.compile_result || 'PASSED',
        formal_engine_result: params.formal_engine_result || 'UNPROVED',
        proof_result: params.proof_result || 'FAIL',
        vacuity_status: params.vacuity_status || 'NON_VACUOUS',
        semantic_status: params.semantic_status || 'UNVERIFIED',
        manual_review_status: params.manual_review_status || 'PENDING'
    };
}

export function createCaseResultRecord(params = {}) {
    return {
        case_id: params.case_id || '',
        ground_truth: params.ground_truth || GroundTruthLabel.UNKNOWN,
        prediction: params.prediction || PredictionState.INCONCLUSIVE,
        hwsec_final: params.hwsec_final || params.prediction || 'INCONCLUSIVE',
        classification: params.classification || CaseClassification.INCONCLUSIVE,
        first_detection_stage: params.first_detection_stage || 'NONE',
        final_confirmation_stage: params.final_confirmation_stage || 'NONE',
        source_finding_ids: params.source_finding_ids || [],
        transition_ids: params.transition_ids || [],
        verifier_decision_ids: params.verifier_decision_ids || [],
        proof_ids: params.proof_ids || [],
        assertion_ids: params.assertion_ids || [],
        evidence_strength: params.evidence_strength || 'E1',
        reproducible: params.reproducible !== undefined ? params.reproducible : false,
        reclassification_taxonomy: params.reclassification_taxonomy || ReclassificationType.NONE,
        inconclusive_reason: params.inconclusive_reason || null,
        recommended_next_action: params.recommended_next_action || null
    };
}
