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
 * @typedef {Object} Evidence
 * @property {string} id
 * @property {string} tool_name
 * @property {string} artifact_path
 * @property {string} description
 * @property {Object.<string, any>} metadata
 */

/**
 * @typedef {Object} Finding
 * @property {string} id
 * @property {string} title
 * @property {string} description
 * @property {Severity} severity
 * @property {string} source_tool
 * @property {string|null} rtl_location
 * @property {Evidence[]} evidence
 * @property {string} verification_state - e.g., "PROPOSED", "TESTING", "SUPPORTED", "VERIFIED", "REFUTED"
 */

export function createFinding(data) {
    return {
        id: data.id,
        title: data.title,
        description: data.description,
        severity: data.severity,
        source_tool: data.source_tool,
        rtl_location: data.rtl_location || null,
        evidence: data.evidence || [],
        verification_state: data.verification_state || "PROPOSED"
    };
}
