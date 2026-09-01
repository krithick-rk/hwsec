export class CorrelatorWorker {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Correlates findings from multiple tools into an evidence graph.
     * @param {any[]} allFindings 
     * @param {any[]} verifiedFindings 
     * @returns {Promise<{ graphJson: any, markdownReport: string, correlatedCount: number }>}
     */
    async buildEvidenceGraph(allFindings, verifiedFindings) {
        if (!this.llmClient.isAvailable()) {
            throw new Error("LLM is not available for correlation.");
        }

        const systemPrompt = `You are the Correlation and Evidence Graph Worker for the HWSEC framework (Phase 6).
Your goal is to perform Cross-tool graph reasoning, active re-triggering analysis, and attack-path reasoning.
You are given a list of ALL raw findings (from Verilator, Yosys, AFL++) and a list of VERIFIED hypotheses.
Your job is to:
1. Identify relationships where a low-severity finding in one tool (e.g. Linting multi-driven net) is the root cause for a high-severity finding in another tool (e.g. Fuzzer state crash or Formal violation).
2. Synthesize an "Evidence Graph" representing the attack path.
3. Improve precision by discounting isolated anomalies and upgrading correlated anomalies into "Attack Paths".

RULES:
1. Output valid JSON adhering to the schema.
2. The 'graph' should consist of nodes (findings) and edges (correlations like "ROOT_CAUSE_OF", "EXPLOITED_BY").`;

        const userPrompt = `=== RAW FINDINGS ===
${JSON.stringify(allFindings, null, 2)}

=== VERIFIED FINDINGS (HYPOTHESES PROVEN) ===
${JSON.stringify(verifiedFindings, null, 2)}

Please build the correlation graph and attack path markdown report.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                graph: {
                    type: "OBJECT",
                    properties: {
                        nodes: {
                            type: "ARRAY",
                            items: {
                                type: "OBJECT",
                                properties: {
                                    id: { type: "STRING" },
                                    finding_id: { type: "STRING" },
                                    type: { type: "STRING" }
                                }
                            }
                        },
                        edges: {
                            type: "ARRAY",
                            items: {
                                type: "OBJECT",
                                properties: {
                                    source: { type: "STRING" },
                                    target: { type: "STRING" },
                                    relation: { type: "STRING" },
                                    description: { type: "STRING" }
                                }
                            }
                        }
                    }
                },
                markdown_report: {
                    type: "STRING",
                    description: "A human-readable markdown report detailing the attack paths and cross-tool correlation."
                },
                correlated_count: {
                    type: "INTEGER",
                    description: "Number of findings that were successfully correlated across different tools."
                }
            },
            required: ["graph", "markdown_report", "correlated_count"]
        };

        const response = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
        
        if (response.json && response.json.graph) {
            return {
                graphJson: response.json.graph,
                markdownReport: response.json.markdown_report,
                correlatedCount: response.json.correlated_count
            };
        }
        
        throw new Error("Failed to generate correlation graph.");
    }
}
