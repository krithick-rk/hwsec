import { matchCwePatterns } from '../core/cweCatalog.js';
import fs from 'fs';

export class HypothesisGenerator {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Generates CWE-informed hypotheses based on RTL inventory and source inspection.
     * @param {string[]} rtlFiles 
     * @param {string[]} availableTools 
     * @returns {Promise<Array<Object>>}
     */
    async generateHypotheses(rtlFiles, availableTools) {
        let combinedRtl = "";
        for (const file of rtlFiles) {
            if (fs.existsSync(file)) {
                combinedRtl += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8') + '\n\n';
            }
        }

        const matchedCwes = matchCwePatterns(combinedRtl);
        if (matchedCwes.length === 0) {
            return [];
        }

        if (!this.llmClient.isAvailable()) {
            // Fallback deterministic hypotheses from pattern matching
            return matchedCwes.slice(0, 3).map((cwe, idx) => ({
                hypothesis_id: `HYP-${String(idx + 1).padStart(3, '0')}`,
                cwe_id: cwe.id,
                title: `${cwe.name} Hypothesis`,
                claim: `The design may violate ${cwe.name} based on keyword matches: ${cwe.keywords.join(', ')}`,
                affected_assets: ["top"],
                proposed_test: cwe.applicable_tools.find(t => availableTools.includes(t)) || availableTools[0],
                required_artifact: "telemetry log or counterexample trace",
                status: "PLANNED"
            }));
        }

        const systemPrompt = `You are the Hardware Security Hypothesis Generator in the HWSEC system.
Your job is to formulate testable, grounded security hypotheses for an RTL design by mapping hardware CWE patterns to actual code structures.

RULES:
1. Grounding: Map hypotheses to real signals, ports, and modules present in the provided RTL.
2. Formulate 1 to 3 concise, testable hypotheses.
3. For each hypothesis, select a valid proposed_test from the available tools: ${availableTools.join(', ')}.`;

        const userPrompt = `Available Verification Tools: ${availableTools.join(', ')}
Relevant CWE Weakness Patterns:
${JSON.stringify(matchedCwes.slice(0, 4), null, 2)}

RTL Source Code:
${combinedRtl.slice(0, 10000)}

Generate testable hypotheses.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                hypotheses: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            hypothesis_id: { type: "STRING" },
                            cwe_id: { type: "STRING" },
                            title: { type: "STRING" },
                            claim: { type: "STRING" },
                            affected_assets: { type: "ARRAY", items: { type: "STRING" } },
                            proposed_test: { type: "STRING" },
                            required_artifact: { type: "STRING" }
                        },
                        required: ["hypothesis_id", "cwe_id", "title", "claim", "proposed_test"]
                    }
                }
            },
            required: ["hypotheses"]
        };

        try {
            const response = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
            const list = response.json?.hypotheses || [];
            return list.map((h, i) => ({
                ...h,
                hypothesis_id: h.hypothesis_id || `HYP-${String(i + 1).padStart(3, '0')}`,
                status: "PLANNED"
            }));
        } catch {
            return [];
        }
    }
}
