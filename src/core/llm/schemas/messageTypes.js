/**
 * Message type constants for bounded multi-model coordination.
 */
export const MessageTypes = {
    HYPOTHESIS_PROPOSAL: 'HYPOTHESIS_PROPOSAL',
    CRITIQUE: 'CRITIQUE',
    DEEP_REASONING_REQUEST: 'DEEP_REASONING_REQUEST',
    INVESTIGATION_PLAN: 'INVESTIGATION_PLAN',
    RESULT_REVIEW: 'RESULT_REVIEW',
    NO_VERDICT: 'NO_VERDICT'
};

/**
 * Operating Modes and their coordination bounds
 */
export const OperatingModes = {
    FAST: 'FAST',
    STANDARD: 'STANDARD',
    DEEP: 'DEEP',
    FORENSIC: 'FORENSIC'
};

export const MODE_ROUND_LIMITS = {
    [OperatingModes.FAST]: 1,        // Scout only
    [OperatingModes.STANDARD]: 2,    // Scout -> Critic on ambiguous
    [OperatingModes.DEEP]: 3,        // Scout -> Critic -> Reasoner on conflict
    [OperatingModes.FORENSIC]: 4     // Full team + bounded second-pass review
};
