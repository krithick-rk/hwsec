/**
 * Authoritative, Versioned Finding and Evidence Schemas for HWSEC
 * Schema Version: 2.0.0
 */

export const SCHEMA_VERSION = "2.0.0";

/**
 * @enum {string}
 */
export const Severity = {
    INFO: "INFO",
    LOW: "LOW",
    MEDIUM: "MEDIUM",
    HIGH: "HIGH",
    CRITICAL: "CRITICAL"
};

/**
 * @enum {string}
 */
export const VerificationState = {
    PROPOSED: "PROPOSED",
    TESTING: "TESTING",
    CANDIDATE: "CANDIDATE",
    SUPPORTED: "SUPPORTED",
    VERIFIED: "VERIFIED",
    REFUTED: "REFUTED",
    INCONCLUSIVE: "INCONCLUSIVE"
};

/**
 * Lifecycle states for bounded PoC reproduction / exploit verification
 * @enum {string}
 */
export const ExploitVerificationState = {
    NOT_ATTEMPTED: "NOT_ATTEMPTED",
    ATTEMPT_SCHEDULED: "ATTEMPT_SCHEDULED",
    POC_GENERATED: "POC_GENERATED",
    EXECUTED: "EXECUTED",
    REPRODUCED: "REPRODUCED",
    SEMANTICALLY_CONFIRMED: "SEMANTICALLY_CONFIRMED",
    SECURITY_CONFIRMED: "SECURITY_CONFIRMED",
    VERIFIED_EXPLOITABLE: "VERIFIED_EXPLOITABLE",
    // Failure branches
    GENERATION_FAILED: "GENERATION_FAILED",
    EXECUTION_BLOCKED: "EXECUTION_BLOCKED",
    NOT_REPRODUCIBLE: "NOT_REPRODUCIBLE",
    CLAIM_MISMATCH: "CLAIM_MISMATCH",
    UNSAFE_TO_EXECUTE: "UNSAFE_TO_EXECUTE",
    INSUFFICIENT_EVIDENCE: "INSUFFICIENT_EVIDENCE"
};

/**
 * Standard classification taxonomy for exploit verification reports
 * @enum {string}
 */
export const ExploitClassification = {
    VULNERABLE: "VULNERABLE",
    REPRODUCIBLE: "REPRODUCIBLE",
    SECURITY_RELEVANT: "SECURITY-RELEVANT",
    EXPLOITABLE: "EXPLOITABLE",
    UNVERIFIED: "UNVERIFIED",
    REFUTED: "REFUTED"
};

/**
 * Proof Status lifecycle for Controlled Proof-of-Impact Verifier
 * @enum {string}
 */
export const ProofStatus = {
    NOT_ELIGIBLE: "NOT_ELIGIBLE",
    QUEUED: "QUEUED",
    GENERATING: "GENERATING",
    READY: "READY",
    EXECUTING: "EXECUTING",
    REPRODUCED: "REPRODUCED",
    FAILED_TO_REPRODUCE: "FAILED_TO_REPRODUCE",
    REJECTED: "REJECTED",
    VERIFIED: "VERIFIED"
};

/**
 * Controlled Impact Classification categories
 * @enum {string}
 */
export const ImpactClass = {
    MEMORY_CORRUPTION: "MEMORY_CORRUPTION",
    CODE_EXECUTION_IN_FIXTURE: "CODE_EXECUTION_IN_FIXTURE",
    AUTHORIZATION_BYPASS: "AUTHORIZATION_BYPASS",
    PRIVILEGE_BOUNDARY_CROSSING: "PRIVILEGE_BOUNDARY_CROSSING",
    DATA_EXPOSURE_IN_FIXTURE: "DATA_EXPOSURE_IN_FIXTURE",
    INTEGRITY_VIOLATION: "INTEGRITY_VIOLATION",
    DENIAL_OF_SERVICE_IN_FIXTURE: "DENIAL_OF_SERVICE_IN_FIXTURE",
    SECURITY_PROPERTY_VIOLATION: "SECURITY_PROPERTY_VIOLATION",
    INFORMATIONAL_ONLY: "INFORMATIONAL_ONLY"
};

/**
 * Minimum Proof Artifact Types
 * @enum {string}
 */
export const ProofType = {
    REGRESSION_TEST: "REGRESSION_TEST",
    MINIMAL_INPUT: "MINIMAL_INPUT",
    TARGETED_HARNESS: "TARGETED_HARNESS",
    BOUNDED_SYMBOLIC: "BOUNDED_SYMBOLIC",
    LOCAL_FUZZING_SEED: "LOCAL_FUZZING_SEED",
    FORMAL_COUNTEREXAMPLE: "FORMAL_COUNTEREXAMPLE",
    SIMULATION_TRACE: "SIMULATION_TRACE"
};

/**
 * Creates a structured proof record adhering to the Controlled Proof-of-Impact model.
 */
export function createProofRecord(data = {}) {
    return {
        proof_id: data.proof_id || `PROOF-${Math.random().toString(16).slice(2, 10)}`,
        finding_id: data.finding_id || null,
        analysis_id: data.analysis_id || null,
        target_id: data.target_id || null,
        proof_type: data.proof_type || ProofType.REGRESSION_TEST,
        proof_status: data.proof_status || ProofStatus.QUEUED,
        preflight_estimate: data.preflight_estimate || null,
        estimated_tokens: Number(data.estimated_tokens) || 0,
        estimated_runtime: Number(data.estimated_runtime) || 0,
        actual_tokens: Number(data.actual_tokens) || 0,
        actual_runtime: Number(data.actual_runtime) || 0,
        generated_artifact: data.generated_artifact || null,
        artifact_hash: data.artifact_hash || null,
        execution_environment: data.execution_environment || "hwsec_isolated_sandbox",
        execution_command: data.execution_command || null,
        observable_result: data.observable_result || null,
        expected_result: data.expected_result || null,
        actual_result: data.actual_result || null,
        impact_class: data.impact_class || ImpactClass.INFORMATIONAL_ONLY,
        reproducibility_count: Number(data.reproducibility_count) || 0,
        reproducibility_rate: data.reproducibility_rate || null,
        reproducibility_attempts: data.reproducibility_attempts || 0,
        evidence_ids: Array.isArray(data.evidence_ids) ? data.evidence_ids : [],
        verifier_level: data.verifier_level || "E0",
        failure_reason: data.failure_reason || null,
        created_at: data.created_at || new Date().toISOString(),
        completed_at: data.completed_at || null
    };
}

/**
 * Creates a normalized source code / RTL location object.
 */
export function createSourceLocation(data = {}) {
    const start = Number(data.startLine || data.line || data.lineNumber) || 1;
    const end = Number(data.endLine || start) || start;
    return {
        path: data.path || null,
        startLine: start,
        endLine: end,
        line: start,
        startColumn: Number(data.startColumn || data.column) || 1,
        endColumn: Number(data.endColumn || data.startColumn || 1) || 1,
        symbol: data.symbol || null
    };
}

/**
 * Creates a normalized Evidence object with provenance.
 */
export function createEvidence(data = {}) {
    return {
        id: data.id || `EV-${Math.random().toString(16).slice(2, 10)}`,
        run_id: data.run_id || data.runId || null,
        tool: data.tool || data.tool_name || "unknown",
        tool_run_id: data.tool_run_id || null,
        evidence_type: data.evidence_type || data.type || "GENERIC_EVIDENCE",
        invocation: data.invocation || null,
        artifact_path: data.artifact_path || null,
        artifact_hash: data.artifact_hash || null,
        observation: data.observation || data.description || "",
        raw_evidence: data.raw_evidence || data.metadata || null,
        timestamp: data.timestamp || new Date().toISOString(),
        validity_status: data.validity_status || "VALID"
    };
}

/**
 * Creates a normalized, generalized Finding object adhering to Schema v2.0.0.
 */
export function createFinding(data = {}) {
    // Normalization for source locations
    let sourceLocations = [];
    if (Array.isArray(data.source_locations) && data.source_locations.length > 0) {
        sourceLocations = data.source_locations.map(loc => createSourceLocation(loc));
    } else if (data.rtl_location) {
        const parts = String(data.rtl_location).split(':');
        const locPath = parts.slice(0, parts.length > 2 ? -1 : 1).join(':');
        const line = parseInt(parts[parts.length - 1], 10) || 1;
        sourceLocations.push(createSourceLocation({
            path: locPath,
            startLine: line,
            endLine: line
        }));
    }

    // Normalization for evidence objects
    const evidenceList = (data.evidence || []).map(e => createEvidence(e));
    const evidenceIds = data.evidence_ids || evidenceList.map(e => e.id);

    const sourceTool = data.source_tool || data.provenance?.tool || (evidenceList[0]?.tool) || "hwsec";

    return {
        schema_version: SCHEMA_VERSION,
        id: data.id || `FIND-${Math.random().toString(16).slice(2, 10)}`,
        run_id: data.run_id || data.runId || null,
        status: data.status || "OPEN",
        type: data.type || "SECURITY_FINDING",
        title: data.title || "Untitled Finding",
        description: data.description || "",
        severity: data.severity || Severity.MEDIUM,
        confidence: typeof data.confidence === 'number' ? data.confidence : 0.6,
        source_locations: sourceLocations,
        affected_assets: data.affected_assets || [],
        security_property: data.security_property || null,
        cwe_id: data.cwe_id || null,
        evidence_ids: evidenceIds,
        supporting_evidence: data.supporting_evidence || evidenceList,
        contradicting_evidence: data.contradicting_evidence || [],
        exploitability: data.exploitability || "UNKNOWN",
        exploit_state: data.exploit_state || ExploitVerificationState.NOT_ATTEMPTED,
        exploit_evidence: data.exploit_evidence || null,
        proof_id: data.proof_id || null,
        proof_status: data.proof_status || ProofStatus.NOT_ELIGIBLE,
        proof_record: data.proof_record || null,
        impact: data.impact || "UNKNOWN",
        verification_state: data.verification_state || VerificationState.PROPOSED,
        provenance: {
            tool: sourceTool,
            created_at: data.provenance?.created_at || new Date().toISOString()
        },
        
        // Backwards-compatibility fields for legacy callers
        source_tool: sourceTool,
        rtl_location: data.rtl_location || (sourceLocations[0] ? `${sourceLocations[0].path}:${sourceLocations[0].startLine}` : null),
        evidence: evidenceList
    };
}

/**
 * Migrates a legacy finding to Schema v2.0.0 without data loss.
 */
export function migrateFinding(legacyFinding) {
    if (!legacyFinding) return null;
    if (legacyFinding.schema_version === SCHEMA_VERSION && legacyFinding.source_locations) {
        return legacyFinding;
    }
    return createFinding(legacyFinding);
}
