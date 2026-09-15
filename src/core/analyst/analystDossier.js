/**
 * AnalystDossier
 * 
 * Section 24: Analyst experience formatter answering the 10 core operational questions.
 */
export class AnalystDossier {
    /**
     * Generates a human and machine-readable case summary answering the 10 operational questions
     * plus first-class Proof-of-Vulnerability (PoV) artifact status and replay metrics.
     * @param {Object} hypothesis VulnerabilityHypothesis
     * @param {Object} evidenceDag EvidenceDag or DAG JSON
     * @param {Object} verdictEnvelope VerdictEnvelope from EvidenceAuthority
     * @param {Object} [povData] ProofOfVulnerability instance or object
     * @param {Object} [povReplayLog] Replay verification log
     * @returns {Object} AnalystCaseSummary
     */
    static generateCaseSummary(hypothesis, evidenceDag, verdictEnvelope, povData = null, povReplayLog = null) {
        const hyp = hypothesis || {};
        const v = verdictEnvelope || {};
        const ob = v.obligations || {};

        const analystActions = {
            DETECTED: 'Confirm vulnerability patch or apply synthetic fix; replay witness in CI/CD pipeline.',
            NOT_DETECTED: 'No action required within declared scope; candidate refutation recorded.',
            INCONCLUSIVE: `Investigate missing evidence: ${v.reason_code}. Manually verify entry point or provide custom driver harness.`
        };

        // Resolve PoV Artifact from explicit param, verdict envelope, or DAG nodes
        let pov = null;
        if (povData) {
            pov = typeof povData.toJSON === 'function' ? povData.toJSON() : povData;
        } else if (v.pov) {
            pov = typeof v.pov.toJSON === 'function' ? v.pov.toJSON() : v.pov;
        } else if (evidenceDag && typeof evidenceDag.findNodesByType === 'function') {
            const povNodes = evidenceDag.findNodesByType('pov_artifact');
            if (povNodes && povNodes.length > 0) {
                pov = povNodes[0].data;
            }
        }

        // Resolve PoV Replay & Verification
        let replayResult = 'UNVERIFIED';
        let replayReason = null;
        if (povReplayLog) {
            replayResult = povReplayLog.verified ? 'PASS' : 'FAIL';
            replayReason = povReplayLog.reason_code;
        } else if (evidenceDag && typeof evidenceDag.findNodesByType === 'function') {
            const verNodes = evidenceDag.findNodesByType('pov_verification');
            if (verNodes && verNodes.length > 0) {
                replayResult = verNodes[0].data.verified ? 'PASS' : 'FAIL';
                replayReason = verNodes[0].data.reason_code;
            } else if (pov?.status === 'VERIFIED') {
                replayResult = 'PASS';
            }
        }

        let resolvedStatus = pov?.status || 'UNVERIFIED';
        if (replayResult === 'PASS') {
            resolvedStatus = 'VERIFIED';
        } else if (replayResult === 'FAIL' && (resolvedStatus === 'GENERATED' || resolvedStatus === 'VERIFIED')) {
            resolvedStatus = 'FAILED';
        }

        const povSummary = pov ? {
            status: resolvedStatus,
            bundle_path: pov.bundle_path || (pov.pov_id ? `pov/${pov.pov_id}` : null),
            bundle_hash: pov.bundle_hash || null,
            replay_result: replayResult,
            reason_code: replayReason,
            reproduction_command: pov.reproduction?.command || null,
            environment_requirements: (pov.reproduction?.environment_requirements || ['Standard']).join(', '),
            vulnerability_class: pov.vulnerability_class || hyp.cwe || 'UNKNOWN',
            observed_security_effect: pov.security_effect?.observed || (ob.security_oracle_fired ? 'Observed security oracle condition satisfied' : null)
        } : (v.verdict === 'DETECTED' ? {
            status: 'UNVERIFIED',
            bundle_path: null,
            bundle_hash: null,
            replay_result: 'UNVERIFIED',
            reason_code: 'POV_NOT_GENERATED',
            reproduction_command: null,
            environment_requirements: 'Standard',
            vulnerability_class: hyp.cwe || 'UNKNOWN',
            observed_security_effect: ob.security_oracle_fired ? 'Observed security oracle condition satisfied' : null
        } : {
            status: 'NOT_REQUESTED',
            bundle_path: null,
            bundle_hash: null,
            replay_result: 'NOT_REQUESTED',
            reason_code: 'INSUFFICIENT_EVIDENCE',
            reproduction_command: null,
            environment_requirements: 'Standard',
            vulnerability_class: hyp.cwe || 'UNKNOWN',
            observed_security_effect: null
        });

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
                priority_consensus: hyp.priority || 0.5,
                model_team_narrative: hyp.model_team_narrative || hyp.coordination_summary || null
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
            pov_artifact: povSummary,
            next_action_recommendation: analystActions[v.verdict] || analystActions.INCONCLUSIVE
        };

        return {
            case_id: hyp.id || 'case_unknown',
            run_id: hyp.run_id || 'run_unknown',
            verdict: v.verdict || 'INCONCLUSIVE',
            pov: povSummary,
            summary: questionsAndAnswers,
            markdown_dossier: this.renderMarkdown(questionsAndAnswers)
        };
    }

    static renderMarkdown(summary) {
        const modelTeamSection = summary.q3_analyzers_and_disagreement.model_team_narrative
            ? `\n- **Model Team Coordination**: \`${summary.q3_analyzers_and_disagreement.model_team_narrative}\``
            : '';

        const pov = summary.pov_artifact;
        let povSection = '';
        if (pov && (pov.status !== 'NOT_REQUESTED' || summary.q10_verdict_decision.verdict === 'DETECTED')) {
            const replayBadge = pov.replay_result === 'PASS' ? '✅ PASS' : (pov.replay_result === 'FAIL' ? '❌ FAIL' : '⚠️ UNVERIFIED');
            const negControlBadge = summary.q8_controls_status.negative_control_passed ? '✅ PASS' : '❌ FAIL';
            povSection = `
## 5. Proof-of-Vulnerability (PoV) Artifact & Replay
- **PoV Status**: **\`${pov.status}\`**
- **PoV Artifact**: \`${pov.bundle_path || 'N/A'}\`
- **Replay**: ${replayBadge}
- **Negative Control**: ${negControlBadge}
- **Reproduction Command**: \`${pov.reproduction_command || 'N/A'}\`
- **Content Hash**: \`${pov.bundle_hash || 'N/A'}\`
- **Environment Requirements**: \`${pov.environment_requirements || 'Standard'}\`
- **Observed Security Effect**: \`${pov.observed_security_effect || (summary.q7_security_effect_observed ? 'Security condition triggered' : 'None')}\`
`;
        }

        return `
# HWSEC Security Operations Case Dossier

## 1. Suspected Vulnerability
**${summary.q1_suspected_vulnerability}**

## 2. Attack Surface & Entry Point
- **Attack Surface**: \`${summary.q2_attack_surface_and_entry_point.attack_surface}\`
- **Entry Point**: \`${JSON.stringify(summary.q2_attack_surface_and_entry_point.entry_point)}\`
- **Status**: ${summary.q2_attack_surface_and_entry_point.resolved ? '✅ RESOLVED' : '⚠️ UNRESOLVED'}

## 3. Analyzer Discovery & Model Team Consensus
- Analyzers: ${(summary.q3_analyzers_and_disagreement.signals || []).map(s => `${s.analyzer} (${s.rule_id})`).join(', ') || 'None'}
- Priority Score: **${summary.q3_analyzers_and_disagreement.priority_consensus}**${modelTeamSection}

## 4. Operational Verdict & Evidence
- **Verdict**: **\`${summary.q10_verdict_decision.verdict}\`** (\`${summary.q10_verdict_decision.reason_code}\`)
- **Security Effect Observed**: ${summary.q7_security_effect_observed ? '✅ YES' : '❌ NO'}
- **Negative Control Passed**: ${summary.q8_controls_status.negative_control_passed ? '✅ YES' : '❌ NO'}
- **Replayable Witness**: ${summary.q9_replayable ? '✅ YES' : '❌ NO'}
${povSection}
## ${povSection ? '6' : '5'}. Analyst Recommendation
> ${summary.next_action_recommendation}
`.trim();
    }
}
