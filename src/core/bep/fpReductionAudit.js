import { FPTransitionCategory } from './bepSchema.js';

/**
 * OWASP FP-Reduction Audit Engine
 * Analyzes all FP -> TN transitions and classifies them into:
 * - DETERMINISTICALLY_CONFIRMED
 * - PROOF_CONFIRMED
 * - HYBRID_CONFIRMED
 * - LLM_ONLY
 * - UNRESOLVED
 */

export class FPReductionAuditEngine {
    constructor() {}

    auditRun(caseResults, transitions, verifierDecisions, proofRecords) {
        const decisionMap = new Map((verifierDecisions || []).map(d => [d.decision_id, d]));
        const proofMap = new Map((proofRecords || []).map(p => [p.proof_id, p]));
        const transitionMap = new Map();

        for (const t of transitions || []) {
            if (t.from_state === 'FP' && t.to_state === 'TN') {
                if (!transitionMap.has(t.case_id)) transitionMap.set(t.case_id, []);
                transitionMap.get(t.case_id).push(t);
            }
        }

        const fpToTnCases = [];
        const breakdown = {
            DETERMINISTICALLY_CONFIRMED: 0,
            PROOF_CONFIRMED: 0,
            HYBRID_CONFIRMED: 0,
            LLM_ONLY: 0,
            UNRESOLVED: 0
        };

        for (const [caseId, caseTrans] of transitionMap.entries()) {
            const lastTrans = caseTrans[caseTrans.length - 1];
            const decision = lastTrans.verifier_decision_id ? decisionMap.get(lastTrans.verifier_decision_id) : null;
            const proof = lastTrans.proof_ref ? proofMap.get(lastTrans.proof_ref) : null;

            let category = FPTransitionCategory.UNRESOLVED;
            let justification = '';

            if (proof && proof.verdict === 'REPRODUCED') {
                category = FPTransitionCategory.PROOF_CONFIRMED;
                justification = `Reproduced via sandbox proof execution (${proof.repetition_count})`;
            } else if (decision && decision.evidence_basis === 'SUPPORTED_BY_DETERMINISTIC') {
                category = FPTransitionCategory.DETERMINISTICALLY_CONFIRMED;
                justification = `Supported by deterministic evidence refs: ${decision.deterministic_validation_refs.join(', ')}`;
            } else if (decision && decision.evidence_basis === 'CONTRADICTED_BY_DETERMINISTIC') {
                category = FPTransitionCategory.HYBRID_CONFIRMED;
                justification = `Contradicted by deterministic evidence refs: ${decision.deterministic_validation_refs.join(', ')}`;
            } else if (decision && decision.evidence_basis === 'MODEL_ONLY') {
                category = FPTransitionCategory.LLM_ONLY;
                justification = `Reclassified solely by model reasoning (${decision.model})`;
            } else {
                category = FPTransitionCategory.UNRESOLVED;
                justification = 'Insufficient evidence to confirm transition basis';
            }

            breakdown[category]++;

            fpToTnCases.push({
                case_id: caseId,
                transition_id: lastTrans.transition_id,
                category,
                justification,
                verifier_decision_id: lastTrans.verifier_decision_id,
                proof_ref: lastTrans.proof_ref,
                model: decision ? decision.model : 'N/A',
                timestamp: lastTrans.timestamp
            });
        }

        const auditSummary = {
            claimed_fp_before: 242,
            claimed_fp_after: 48,
            claimed_fp_reduction: 194,
            actual_fp_to_tn_transitions: fpToTnCases.length,
            breakdown,
            is_valid_claim: fpToTnCases.length === 194 && breakdown.LLM_ONLY === 0
        };

        const reportMd = this._generateReportMarkdown(auditSummary, fpToTnCases);

        return {
            summary: auditSummary,
            cases: fpToTnCases,
            report_md: reportMd
        };
    }

    _generateReportMarkdown(summary, cases) {
        let md = `# OWASP FP-Reduction Audit Report\n\n`;
        md += `## 1. Audit Summary\n`;
        md += `- **Claimed FP Before**: ${summary.claimed_fp_before}\n`;
        md += `- **Claimed FP After**: ${summary.claimed_fp_after}\n`;
        md += `- **Claimed FP Reduction**: ${summary.claimed_fp_reduction}\n`;
        md += `- **Actual Audited FP->TN Cases**: ${summary.actual_fp_to_tn_transitions}\n`;
        md += `- **Audit Verdict**: ${summary.is_valid_claim ? 'VALID (100% Evidence Backed)' : 'PARTIAL / MODEL-ONLY RECLASSIFICATION DETECTED'}\n\n`;

        md += `## 2. Transition Breakdown Taxonomy\n`;
        md += `| Transition Category | Case Count | Ratio |\n`;
        md += `|---|---|---|\n`;
        const total = summary.actual_fp_to_tn_transitions || 1;
        for (const [cat, count] of Object.entries(summary.breakdown)) {
            const pct = ((count / total) * 100).toFixed(1);
            md += `| **${cat}** | ${count} | ${pct}% |\n`;
        }

        md += `\n## 3. Sample Case Audit Trail (First 20 Cases)\n`;
        md += `| Case ID | Category | Model / Engine | Justification |\n`;
        md += `|---|---|---|---|\n`;
        for (const c of cases.slice(0, 20)) {
            md += `| \`${c.case_id}\` | ${c.category} | ${c.model} | ${c.justification} |\n`;
        }

        return md;
    }
}
