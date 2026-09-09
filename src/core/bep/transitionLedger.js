import { createTransitionRecord, ReclassificationType, CaseClassification } from './bepSchema.js';

/**
 * Append-Only Classification Transition Ledger
 * Tracks state changes per test case and categorizes improvements.
 */

export class TransitionLedger {
    constructor() {
        this.transitions = [];
        this.transitionsByCase = new Map();
    }

    recordTransition(params) {
        const record = createTransitionRecord({
            case_id: params.case_id,
            from_state: params.from_state,
            to_state: params.to_state,
            stage: params.stage,
            reason_code: params.reason_code,
            inconclusive_reason: params.inconclusive_reason || null,
            recommended_next_action: params.recommended_next_action || null,
            evidence_refs: params.evidence_refs || [],
            verifier_decision_id: params.verifier_decision_id || null,
            proof_ref: params.proof_ref || null,
            transition_type: params.transition_type || this.categorizeTransition(params)
        });

        this.transitions.push(record);

        if (!this.transitionsByCase.has(record.case_id)) {
            this.transitionsByCase.set(record.case_id, []);
        }
        this.transitionsByCase.get(record.case_id).push(record);

        return record;
    }

    categorizeTransition(params) {
        const hasDeterministicEvidence = (params.evidence_refs || []).some(ref => 
            ref.startsWith('EV-') || ref.startsWith('CPG-') || ref.startsWith('ASAN-') || ref.startsWith('SBY-')
        );
        const hasProof = !!params.proof_ref;

        if (hasDeterministicEvidence || hasProof) {
            return ReclassificationType.EVIDENCE_BACKED;
        } else if (params.stage === 'LLM_VERIFIER' && params.verifier_decision_id) {
            return ReclassificationType.MODEL_ASSISTED;
        } else if (params.stage === 'LLM_VERIFIER' && !hasDeterministicEvidence) {
            return ReclassificationType.MODEL_ONLY;
        }
        return ReclassificationType.NONE;
    }

    getTransitionsForCase(caseId) {
        return this.transitionsByCase.get(caseId) || [];
    }

    getFPtoTNTransitions() {
        return this.transitions.filter(t => t.from_state === CaseClassification.FP && t.to_state === CaseClassification.TN);
    }

    getSummaryMetrics() {
        const summary = {
            total_transitions: this.transitions.length,
            fp_to_tn: 0,
            tp_to_fn: 0,
            fn_to_tp: 0,
            unknown_to_tp: 0,
            unknown_to_tn: 0,
            by_taxonomy: {
                EVIDENCE_BACKED: 0,
                MODEL_ASSISTED: 0,
                MODEL_ONLY: 0,
                NONE: 0
            }
        };

        for (const t of this.transitions) {
            if (t.from_state === CaseClassification.FP && t.to_state === CaseClassification.TN) summary.fp_to_tn++;
            if (t.from_state === CaseClassification.TP && t.to_state === CaseClassification.FN) summary.tp_to_fn++;
            if (t.from_state === CaseClassification.FN && t.to_state === CaseClassification.TP) summary.fn_to_tp++;
            if (t.from_state === CaseClassification.UNKNOWN && t.to_state === CaseClassification.TP) summary.unknown_to_tp++;
            if (t.from_state === CaseClassification.UNKNOWN && t.to_state === CaseClassification.TN) summary.unknown_to_tn++;

            const tax = t.transition_type || ReclassificationType.NONE;
            if (summary.by_taxonomy[tax] !== undefined) {
                summary.by_taxonomy[tax]++;
            }
        }

        return summary;
    }
}
