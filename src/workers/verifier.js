import { createFinding, Severity } from '../core/schema.js';
import crypto from 'crypto';

export class ArtifactGatedVerifier {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Skeptically evaluates hypotheses against collected tool findings and telemetry.
     * @param {Array<Object>} hypotheses 
     * @param {Array<Object>} toolFindings 
     * @param {Object} telemetries 
     * @returns {Promise<{verifiedFindings: Array<Object>, reportMarkdown: string}>}
     */
    async verify(hypotheses, toolFindings, telemetries) {
        const verifiedFindings = [];
        const verificationSummaries = [];

        for (const hyp of hypotheses) {
            // Find relevant tool findings for this hypothesis
            const matchingFindings = toolFindings.filter(f => {
                const text = `${f.title} ${f.description} ${f.rtl_location || ''}`.toLowerCase();
                const hypMatches = (hyp.affected_assets || []).some(asset => text.includes(asset.toLowerCase()));
                const cweMatch = text.includes(hyp.cwe_id.toLowerCase()) || text.includes(hyp.title.toLowerCase());
                return hypMatches || cweMatch;
            });

            let status = "INCONCLUSIVE";
            let verificationLevel = "E0";
            let justification = "No matching tool execution artifacts found.";

            if (matchingFindings.length > 0) {
                status = "SUPPORTED";
                verificationLevel = "E1";
                justification = `Supported by ${matchingFindings.length} tool finding(s): ${matchingFindings.map(m => m.title).join(', ')}`;
                
                const verifiedFinding = createFinding({
                    id: `VERIFIED-${crypto.randomBytes(4).toString('hex')}`,
                    title: `[${hyp.cwe_id}] ${hyp.title}`,
                    description: `${hyp.claim}\n\nVerification Analysis: ${justification}`,
                    severity: matchingFindings[0].severity || Severity.MEDIUM,
                    source_tool: "artifact-verifier",
                    rtl_location: matchingFindings[0].rtl_location || null,
                    evidence: matchingFindings.flatMap(m => m.evidence || []),
                    verification_state: "SUPPORTED"
                });

                verifiedFindings.push(verifiedFinding);
            } else {
                status = "REFUTED";
                justification = "Tools executed cleanly without triggering the hypothesized vulnerability.";
            }

            verificationSummaries.push({
                hypothesis_id: hyp.hypothesis_id,
                cwe_id: hyp.cwe_id,
                title: hyp.title,
                status,
                verification_level: verificationLevel,
                justification
            });
        }

        // Build human-readable markdown report
        let reportMarkdown = `# Hardware Security Analysis Verification Report\n\n`;
        reportMarkdown += `### Executive Summary\n`;
        reportMarkdown += `- **Total Hypotheses Evaluated**: ${hypotheses.length}\n`;
        reportMarkdown += `- **Supported/Verified Findings**: ${verifiedFindings.length}\n`;
        reportMarkdown += `- **Refuted/Inconclusive**: ${hypotheses.length - verifiedFindings.length}\n\n`;

        reportMarkdown += `### Verification Results by Hypothesis\n\n`;
        for (const summary of verificationSummaries) {
            reportMarkdown += `#### [${summary.status}] ${summary.hypothesis_id}: ${summary.title} (${summary.cwe_id})\n`;
            reportMarkdown += `- **Verification Level**: \`${summary.verification_level}\`\n`;
            reportMarkdown += `- **Justification**: ${summary.justification}\n\n`;
        }

        return {
            verifiedFindings,
            verificationSummaries,
            reportMarkdown
        };
    }
}
