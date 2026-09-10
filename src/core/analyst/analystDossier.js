/**
 * AnalystDossier
 * 
 * Section 24: Analyst experience formatter answering the 10 core operational questions.
 */
export class AnalystDossier {
    /**
     * Generates a human and machine-readable case summary answering the 10 operational questions.
     * @param {Object} hypothesis VulnerabilityHypothesis
     * @param {Object} evidenceDag EvidenceDag or DAG JSON
     * @param {Object} verdictEnvelope VerdictEnvelope from EvidenceAuthority
     * @returns {Object} AnalystCaseSummary
     */
    static generateCaseSummary(hypothesis, evidenceDag, verdictEnvelope) {
        const hyp = hypothesis || {};
        const v = verdictEnvelope || {};
        const ob = v.obligations || {};

        const analystActions = {
            DETECTED: 'Confirm vulnerability patch or apply synthetic fix; replay witness in CI/CD pipeline.',
            NOT_DETECTED: 'No action required within declared scope; candidate refutation recorded.',
            INCONCLUSIVE: `Investigate missing evidence: ${v.reason_code}. Manually verify entry point or provide custom driver harness.`
        };

        const questionsAndAnswers = {
            q1_suspected_vulnerability: `${hyp.cwe || 'UNKNOWN'}: ${hyp.security_condition || 'Security condition violation'}`,
            q2_attack_surface_and_entry_point: {
                attack_surface: hyp.attack_surface || 'UNKNOWN',
                entry_point: hyp.entry_point || { status: 'UNRESOLVED' },
                resolved: hyp.entry_point?.status === 'RESOLVED'
            },
            q3_analyzers_and_disagreement: {
                signals: hyp.discovery_signals || [],
                analyzers_count: (hyp.discovery_signals || []).length,
                priority_consensus: hyp.priority || 0.5
            },
            q4_evidence_attempted: Object.keys(ob).filter(k => ob[k] === true),
            q5_concrete_inputs_tried: v.witness_input ? [v.witness_input] : [],
            q6_application_executed_attack_path: Boolean(ob.concrete_execution_succeeded),
            q7_security_effect_observed: Boolean(ob.security_oracle_fired),
            q8_controls_status: {
                negative_control_passed: Boolean(ob.negative_control_passed),
                provenance_verified: Boolean(ob.provenance_manifest_verified)
            },
            q9_replayable: Boolean(v.verdict === 'DETECTED'),
            q10_verdict_decision: {
                verdict: v.verdict || 'INCONCLUSIVE',
                reason_code: v.reason_code || 'SEARCH_BUDGET_EXHAUSTED',
                reasons: v.reasons || [],
                dag_hash: v.dag_hash || null
            },
            next_action_recommendation: analystActions[v.verdict] || analystActions.INCONCLUSIVE
        };

        return {
            case_id: hyp.id || 'case_unknown',
            run_id: hyp.run_id || 'run_unknown',
            verdict: v.verdict || 'INCONCLUSIVE',
            summary: questionsAndAnswers,
            markdown_dossier: this.renderMarkdown(questionsAndAnswers)
        };
    }

    static renderMarkdown(summary) {
        return `
# HWSEC Security Operations Case Dossier

## 1. Suspected Vulnerability
**${summary.q1_suspected_vulnerability}**

## 2. Attack Surface & Entry Point
- **Attack Surface**: \`${summary.q2_attack_surface_and_entry_point.attack_surface}\`
- **Entry Point**: \`${JSON.stringify(summary.q2_attack_surface_and_entry_point.entry_point)}\`
- **Status**: ${summary.q2_attack_surface_and_entry_point.resolved ? '✅ RESOLVED' : '⚠️ UNRESOLVED'}

## 3. Analyzer Discovery & Consensus
- Analyzers: ${(summary.q3_analyzers_and_disagreement.signals || []).map(s => `${s.analyzer} (${s.rule_id})`).join(', ') || 'None'}
- Priority Score: **${summary.q3_analyzers_and_disagreement.priority_consensus}**

## 4. Operational Verdict & Evidence
- **Verdict**: **\`${summary.q10_verdict_decision.verdict}\`** (\`${summary.q10_verdict_decision.reason_code}\`)
- **Security Effect Observed**: ${summary.q7_security_effect_observed ? '✅ YES' : '❌ NO'}
- **Negative Control Passed**: ${summary.q8_controls_status.negative_control_passed ? '✅ YES' : '❌ NO'}
- **Replayable Witness**: ${summary.q9_replayable ? '✅ YES' : '❌ NO'}

## 5. Analyst Recommendation
> ${summary.next_action_recommendation}
`.trim();
    }
}
