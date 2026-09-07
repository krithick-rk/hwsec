/**
 * Explicit analysis lifecycle state machine for HWSEC
 */

export const AnalysisStatus = {
    CREATED: 'CREATED',
    PLANNING: 'PLANNING',
    PLANNED: 'PLANNED',
    APPROVED: 'APPROVED',
    RUNNING: 'RUNNING',
    COMPLETED: 'COMPLETED',
    FAILED: 'FAILED',
    CANCELLED: 'CANCELLED'
};

const VALID_TRANSITIONS = {
    [AnalysisStatus.CREATED]: [AnalysisStatus.PLANNING, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.PLANNING]: [AnalysisStatus.PLANNED, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.PLANNED]: [AnalysisStatus.APPROVED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.APPROVED]: [AnalysisStatus.RUNNING, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.RUNNING]: [AnalysisStatus.COMPLETED, AnalysisStatus.FAILED, AnalysisStatus.CANCELLED],
    [AnalysisStatus.COMPLETED]: [],
    [AnalysisStatus.FAILED]: [],
    [AnalysisStatus.CANCELLED]: []
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
