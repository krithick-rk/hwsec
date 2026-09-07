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
