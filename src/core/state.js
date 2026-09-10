/**
 * Explicit analysis lifecycle state machine and operating modes for HWSEC
 * 
 * Sections 19 & 23: Simplified 5-state semantic lifecycle and 4 operating modes.
 */

export const OperatingMode = {
    FAST: 'FAST',           // Developer / triage scan (Discovery + normalization + basic risk ranking)
    STANDARD: 'STANDARD',   // Security operations (Discovery + hypotheses + selected witness search + runtime observation)
    DEEP: 'DEEP',           // High-value investigation (Standard + slicing + refinement + stronger controls + replay bundle)
    FORENSIC: 'FORENSIC'    // Incident / high assurance (Deep + extended traces + preserved environment + human approval + full provenance)
};

export const SemanticLifecycleState = {
    DISCOVERED: 'DISCOVERED',
    HYPOTHESIS_READY: 'HYPOTHESIS_READY',
    EXECUTING: 'EXECUTING',
    EVIDENCE_READY: 'EVIDENCE_READY',
    VERDICTED: 'VERDICTED'
};

export const AnalysisStatus = {
    CREATED: 'CREATED',
    PLANNING: 'PLANNING',
    PLANNED: 'PLANNED',
    APPROVED: 'APPROVED',
    RUNNING: 'RUNNING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
    CANCELLED: 'CANCELLED',
    TIMEOUT: 'TIMEOUT'
};

const VALID_TRANSITIONS = {
    [AnalysisStatus.CREATED]: [AnalysisStatus.PLANNING, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.PLANNING]: [AnalysisStatus.PLANNED, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.PLANNED]: [AnalysisStatus.APPROVED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.APPROVED]: [AnalysisStatus.RUNNING, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.RUNNING]: [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED, AnalysisStatus.TIMEOUT],
    [AnalysisStatus.COMPLETED]: [],
    [AnalysisStatus.FAILED]: [],
    [AnalysisStatus.CANCELLED]: [],
    [AnalysisStatus.TIMEOUT]: []
};

/**
 * Checks if a transition between states is valid.
 * @param {string} currentStatus 
 * @param {string} nextStatus 
 * @returns {boolean}
 */
export function isValidTransition(currentStatus, nextStatus) {
    const allowed = VALID_TRANSITIONS[currentStatus];
    return Array.isArray(allowed) && allowed.includes(nextStatus);
}

/**
 * Asserts that a state transition is legal, throwing a descriptive error otherwise.
 * @param {string} currentStatus 
 * @param {string} nextStatus 
 * @param {string} [context=""]
 */
export function assertTransition(currentStatus, nextStatus, context = '') {
    if (!isValidTransition(currentStatus, nextStatus)) {
        const prefix = context ? `[${context}] ` : '';
        throw new Error(
            `${prefix}Illegal state transition from '${currentStatus}' to '${nextStatus}'. ` +
            `Allowed next states: [${(VALID_TRANSITIONS[currentStatus] || []).join(', ')}]`
        );
    }
}
