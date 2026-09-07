/**
 * Analyzer Disagreement Detector
 * Measures variance and conflict among multiple static/formal/graph analyzers.
 */

export class DisagreementDetector {
    /**
     * Evaluates whether tools disagree on a specific file or component.
     * @param {string} filePath 
     * @param {Array<Object>} toolFindings 
     * @param {Array<string>} executedTools 
     * @returns {{hasDisagreement: boolean, disagreementScore: number, conflictingTools: string[], reason: string}}
     */
    detect(filePath, toolFindings = [], executedTools = []) {
        if (executedTools.length < 2) {
            return {
                hasDisagreement: false,
                disagreementScore: 0.0,
                conflictingTools: [],
                reason: "Fewer than 2 tools executed on this asset"
            };
        }

        const reportingTools = new Set();
        for (const f of toolFindings) {
            const locMatches = (f.source_locations || []).some(l => l.path === filePath) || 
                               (f.rtl_location && f.rtl_location.includes(filePath));
            if (locMatches) {
                reportingTools.add(f.source_tool || f.provenance?.tool);
            }
        }

        const silentTools = executedTools.filter(t => !reportingTools.has(t));

        // If at least one tool reported findings and at least one tool remained silent
        if (reportingTools.size > 0 && silentTools.length > 0) {
            const ratio = silentTools.length / executedTools.length;
            const disagreementScore = Number(Math.min(0.4 * ratio + 0.3, 0.8).toFixed(2));
            return {
                hasDisagreement: true,
                disagreementScore,
                reportingTools: Array.from(reportingTools),
                silentTools,
                conflictingTools: [...reportingTools, ...silentTools],
                reason: `Tool disagreement: [${Array.from(reportingTools).join(', ')}] reported findings, while [${silentTools.join(', ')}] reported none.`
            };
        }

        return {
            hasDisagreement: false,
            disagreementScore: 0.0,
            conflictingTools: [],
            reason: "All executed tools are in consensus"
        };
    }
}
