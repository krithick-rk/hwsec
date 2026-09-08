/**
 * Adaptive Escalation Policy Engine
 *
 * Implements the 6 analysis levels from the architecture spec (Section 6):
 *
 *   LEVEL 0 - Baseline:                 cheap deterministic SAST only
 *   LEVEL 1 - Static Deepening:         additional SAST/dataflow queries
 *   LEVEL 2 - Graph/Reachability:       program graph traversal + source->sink analysis
 *   LEVEL 3 - Semantic Reasoning:       RAG retrieval + LLM hypothesis/invariant generation
 *   LEVEL 4 - Targeted Dynamic/Formal:  symbolic execution, formal properties, targeted fuzzing
 *   LEVEL 5 - Novelty Exploration:      highest-value unresolved candidates, budget permitting
 */

export const EscalationLevel = Object.freeze({
    BASELINE: 0,
    STATIC_DEEPENING: 1,
    GRAPH_REACHABILITY: 2,
    SEMANTIC_REASONING: 3,
    TARGETED_DYNAMIC_FORMAL: 4,
    NOVELTY_EXPLORATION: 5
});

const LEVEL_LABELS = {
    0: 'BASELINE',
    1: 'STATIC_DEEPENING',
    2: 'GRAPH_REACHABILITY',
    3: 'SEMANTIC_REASONING',
    4: 'TARGETED_DYNAMIC_FORMAL',
    5: 'NOVELTY_EXPLORATION'
};

const LEVEL_DESCRIPTIONS = {
    0: 'Cheap deterministic SAST scans only (Semgrep baseline)',
    1: 'Additional SAST/dataflow queries - deeper Semgrep rulesets',
    2: 'Program graph traversal and source->sink analysis via Joern/CodeQL',
    3: 'RAG retrieval + LLM hypothesis/invariant generation',
    4: 'Targeted symbolic execution, formal properties, focused fuzzing (AFL++/SymbiYosys)',
    5: 'Novelty exploration for unresolved high-value candidates within budget'
};

/**
 * Determines the appropriate escalation level for a candidate/target.
 *
 * Decision factors:
 *   - suspicion_score and uncertainty_score from SuspicionEngine
 *   - analyzer_disagreement flag
 *   - coverage_gap flag (weakly covered CWE/language)
 *   - budget consumption ratio
 *   - novelty mode setting
 *   - existing evidence level
 *
 * @param {Object} params
 * @param {number} params.suspicionScore  0.0 - 1.0
 * @param {number} [params.uncertaintyScore]  0.0 - 1.0
 * @param {boolean} [params.hasDisagreement]
 * @param {boolean} [params.hasCoverageGap]
 * @param {number} [params.budgetRatio]  0.0 - 1.0+
 * @param {string} [params.noveltyMode]  'off' | 'minimal' | 'standard' | 'deep'
 * @param {number} [params.currentEvidenceLevel]  E0-E5
 * @returns {{ level: number, label: string, description: string, rationale: string[] }}
 */
export function determineEscalationLevel({
    suspicionScore = 0,
    uncertaintyScore = null,
    hasDisagreement = false,
    hasCoverageGap = false,
    budgetRatio = 0,
    noveltyMode = 'standard',
    currentEvidenceLevel = 0
} = {}) {
    const rationale = [];

    // Budget hard blocks (spec section 16)
    if (budgetRatio >= 1.0) {
        rationale.push('Budget exhausted (>= 100%): forced to BASELINE');
        return _result(EscalationLevel.BASELINE, rationale);
    }
    if (budgetRatio >= 0.90) {
        rationale.push('Budget at >= 90%: novelty/deep analysis suppressed, max GRAPH_REACHABILITY');
        const cappedLevel = Math.min(EscalationLevel.GRAPH_REACHABILITY, _rawLevel(suspicionScore));
        return _result(cappedLevel, rationale);
    }
    if (budgetRatio >= 0.70 && noveltyMode === 'deep') {
        rationale.push('Budget at >= 70%: deep novelty capped at SEMANTIC_REASONING');
    }

    // Novelty mode gates
    if (noveltyMode === 'off') {
        rationale.push('Novelty mode OFF: max level is GRAPH_REACHABILITY');
        const cappedLevel = Math.min(EscalationLevel.GRAPH_REACHABILITY, _rawLevel(suspicionScore));
        return _result(cappedLevel, rationale);
    }

    // Already sufficient evidence: no need to escalate further
    if (currentEvidenceLevel >= 3) {
        rationale.push('Evidence already at E' + currentEvidenceLevel + ': escalation capped at SEMANTIC_REASONING');
        const cappedLevel = Math.min(EscalationLevel.SEMANTIC_REASONING, _rawLevel(suspicionScore));
        return _result(cappedLevel, rationale);
    }

    // Calculate raw level from suspicion score
    let level = _rawLevel(suspicionScore);
    rationale.push('Suspicion score ' + suspicionScore.toFixed(3) + ' -> initial level ' + LEVEL_LABELS[level]);

    // Boost for analyzer disagreement
    if (hasDisagreement && level < EscalationLevel.SEMANTIC_REASONING) {
        level = Math.min(level + 1, EscalationLevel.SEMANTIC_REASONING);
        rationale.push('Analyzer disagreement detected: +1 escalation level');
    }

    // Boost for coverage gap
    if (hasCoverageGap && level < EscalationLevel.GRAPH_REACHABILITY) {
        level = Math.min(level + 1, EscalationLevel.GRAPH_REACHABILITY);
        rationale.push('Coverage gap in CWE family/language: +1 escalation level -> graph reachability');
    }

    // Novelty mode gating for levels 4-5
    if (level >= EscalationLevel.TARGETED_DYNAMIC_FORMAL) {
        if (noveltyMode === 'minimal') {
            level = EscalationLevel.SEMANTIC_REASONING;
            rationale.push('Novelty mode MINIMAL: capped at SEMANTIC_REASONING');
        } else if (noveltyMode === 'standard' && level === EscalationLevel.NOVELTY_EXPLORATION) {
            level = EscalationLevel.TARGETED_DYNAMIC_FORMAL;
            rationale.push('Novelty mode STANDARD: capped at TARGETED_DYNAMIC_FORMAL');
        }
    }

    return _result(level, rationale);
}

function _rawLevel(suspicionScore) {
    if (suspicionScore >= 0.80) return EscalationLevel.NOVELTY_EXPLORATION;
    if (suspicionScore >= 0.65) return EscalationLevel.TARGETED_DYNAMIC_FORMAL;
    if (suspicionScore >= 0.50) return EscalationLevel.SEMANTIC_REASONING;
    if (suspicionScore >= 0.35) return EscalationLevel.GRAPH_REACHABILITY;
    if (suspicionScore >= 0.20) return EscalationLevel.STATIC_DEEPENING;
    return EscalationLevel.BASELINE;
}

function _result(level, rationale) {
    return {
        level,
        label: LEVEL_LABELS[level],
        description: LEVEL_DESCRIPTIONS[level],
        rationale
    };
}

/**
 * Given a ranked list of targets (from SuspicionEngine.rankTargets),
 * returns a full escalation plan mapping each target to its analysis level.
 *
 * @param {Array<Object>} rankedTargets  [{path, suspicion_score, signals}]
 * @param {Object} options
 * @param {number} [options.budgetRatio]
 * @param {string} [options.noveltyMode]
 * @param {Object} [options.coverageGaps]  set keyed by file path -> true/false
 * @returns {Array<{ path: string, level: number, label: string, rationale: string[] }>}
 */
export function buildEscalationPlan(rankedTargets, { budgetRatio = 0, noveltyMode = 'standard', coverageGaps = {} } = {}) {
    return rankedTargets.map(target => {
        const result = determineEscalationLevel({
            suspicionScore: target.suspicion_score || 0,
            hasDisagreement: target.signals?.analyzer_disagreement?.hasDisagreement ?? false,
            hasCoverageGap: !!coverageGaps[target.path],
            budgetRatio,
            noveltyMode
        });
        return {
            path: target.path,
            level: result.level,
            label: result.label,
            description: result.description,
            rationale: result.rationale
        };
    });
}
