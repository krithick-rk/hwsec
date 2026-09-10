/**
 * ConsensusEngine
 * 
 * Performs structural and semantic comparison between Scout proposals and Critic challenges.
 * Evaluates whether the model team has reached consensus or requires escalation to the Deep Reasoner.
 */
export class ConsensusEngine {
    /**
     * Analyzes agreement/disagreement between Scout proposal and Critic response.
     * @param {Object} proposal - Validated HypothesisProposal
     * @param {Object} critique - Validated Critique
     * @returns {Object} Structured consensus evaluation
     */
    static evaluateConsensus(proposal, critique) {
        if (!proposal || !critique) {
            return {
                decision: 'UNRESOLVED',
                hasMaterialDisagreement: true,
                disagreements: [{ field: 'general', critique: 'Missing proposal or critique' }],
                materialFields: ['general'],
                summary: 'Incomplete model-to-model coordination inputs'
            };
        }

        const disagreements = Array.isArray(critique.disagreements) ? critique.disagreements : [];
        const materialDisagreements = disagreements.filter(d => d.severity === 'MATERIAL');
        const materialFields = materialDisagreements.map(d => d.field);

        // Check if critical fields (cwe, entry_point, sink, security_condition) are contested
        const criticalFieldsContested = materialFields.filter(f => ['cwe', 'entry_point', 'sink', 'security_condition'].includes(f));
        const hasMaterialDisagreement = materialDisagreements.length > 0 || criticalFieldsContested.length > 0;

        let decision;
        let summary;

        if (!hasMaterialDisagreement && disagreements.length === 0) {
            decision = 'AGREEMENT';
            summary = 'Scout and Critic agree on core vulnerability hypothesis and entry point';
        } else if (hasMaterialDisagreement) {
            decision = 'DISAGREEMENT';
            summary = `Material disagreement on: ${[...new Set(materialFields)].join(', ')}`;
        } else {
            decision = 'MINOR_DISAGREEMENT';
            summary = 'Minor critique points noted, core hypothesis remains intact';
        }

        return {
            decision,
            hasMaterialDisagreement,
            disagreements,
            materialDisagreements,
            materialFields: [...new Set(materialFields)],
            unsupportedAssumptions: critique.unsupported_assumptions || [],
            missingEvidence: critique.missing_evidence || [],
            summary,
            evaluatedAt: new Date().toISOString()
        };
    }
}
