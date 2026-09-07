import { TaskTypes } from '../core/llm/taskTypes.js';
import fs from 'fs';
import path from 'path';

export class HypothesisGenerator {
    /**
     * @param {Object} modelRouter ModelRouter or LLMClient instance
     * @param {Object} [ragEngine] Optional RAG engine for focused context
     */
    constructor(modelRouter = null, ragEngine = null) {
        this.modelRouter = modelRouter;
        this.ragEngine = ragEngine;
    }

    /**
     * Formulates grounded security hypotheses from deterministic observations and suspicious targets.
     * @param {Object} params
     * @param {Array<Object>} params.deterministicFindings
     * @param {Array<Object>} params.suspiciousTargets
     * @param {Array<string>} params.availableTools
     * @param {string} [params.analysisId]
     * @param {string} [params.noveltyMode='standard']
     * @returns {Promise<Array<Object>>}
     */
    async generateHypotheses(params) {
        const {
            deterministicFindings = [],
            suspiciousTargets = [],
            availableTools = [],
            analysisId = 'global',
            noveltyMode = 'standard'
        } = params;

        if (noveltyMode === 'off') {
            return [];
        }

        // Limit hypotheses based on novelty mode
        const maxHypotheses = noveltyMode === 'deep' ? 6 : (noveltyMode === 'minimal' ? 2 : 3);

        // Fallback deterministic hypotheses when LLM is unavailable
        const isLlmAvailable = this.modelRouter && typeof this.modelRouter.isAvailable === 'function' && this.modelRouter.isAvailable();

        if (!isLlmAvailable) {
            return deterministicFindings.slice(0, maxHypotheses).map((finding, idx) => ({
                hypothesis_id: `HYP-${String(idx + 1).padStart(3, '0')}`,
                cwe_id: finding.title.match(/CWE-\d+/)?.[0] || 'SECURITY-HYPOTHESIS',
                title: `Hypothesis: ${finding.title}`,
                claim: `The application may violate security invariants due to: ${finding.description}`,
                affected_assets: (finding.source_locations || []).map(l => l.path),
                proposed_test: availableTools[0] || 'static_reproduction',
                required_artifact: 'execution trace or counterexample',
                status: 'PLANNED'
            }));
        }

        // Retrieve focused RAG context for top suspicious targets
        let focusedContext = "";
        if (this.ragEngine && suspiciousTargets.length > 0) {
            try {
                const ragRes = typeof this.ragEngine.retrieveSemanticContext === 'function'
                    ? await this.ragEngine.retrieveSemanticContext({ query: suspiciousTargets[0].path, limit: 2 })
                    : this.ragEngine.retrieveContext({ query: suspiciousTargets[0].path, limit: 2 });
                focusedContext = `Relevant Security Knowledge:\n${JSON.stringify(ragRes.security_knowledge, null, 2)}\n`;
            } catch {
                const ragRes = this.ragEngine.retrieveContext({ query: suspiciousTargets[0].path, limit: 2 });
                focusedContext = `Relevant Security Knowledge:\n${JSON.stringify(ragRes.security_knowledge, null, 2)}\n`;
            }
        }

        const systemPrompt = `You are the HWSEC Security Hypothesis Generator.
Your job is to formulate testable, grounded security hypotheses based on deterministic tool observations and suspicious code targets.

RULES:
1. Grounding: Every hypothesis must map to real files, functions, or signals present in the provided evidence.
2. DO NOT declare vulnerabilities as proven fact; propose a testable claim and expected behavior.
3. Formulate between 1 and ${maxHypotheses} concise hypotheses.
4. Proposed test must be one of the available tools: ${availableTools.join(', ')}.`;

        const userPrompt = `Available Tools: ${availableTools.join(', ')}
Novelty Mode: ${noveltyMode}
${focusedContext}
Deterministic Observations:
${JSON.stringify(deterministicFindings.slice(0, 5).map(f => ({ title: f.title, location: f.rtl_location || f.source_locations?.[0] })), null, 2)}

Top Suspicious Targets:
${JSON.stringify(suspiciousTargets.slice(0, 3).map(s => ({ path: s.path, score: s.suspicion_score })), null, 2)}

Formulate testable hypotheses.`;

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
                        required: ["hypothesis_id", "title", "claim", "proposed_test"]
                    }
                }
            },
            required: ["hypotheses"]
        };

        try {
            const res = await this.modelRouter.execute({
                taskType: TaskTypes.HYPOTHESIS_FORMULATION,
                systemPrompt,
                userPrompt,
                jsonSchema,
                analysisId,
                noveltyMode
            });

            const list = res.json?.hypotheses || [];
            return list.slice(0, maxHypotheses).map((h, i) => ({
                ...h,
                hypothesis_id: h.hypothesis_id || `HYP-${String(i + 1).padStart(3, '0')}`,
                status: "PLANNED"
            }));
        } catch (err) {
            console.warn(`[!] [HypothesisGenerator] LLM routing failed: ${err.message}. Using deterministic fallback.`);
            return deterministicFindings.slice(0, maxHypotheses).map((f, i) => ({
                hypothesis_id: `HYP-${String(i + 1).padStart(3, '0')}`,
                cwe_id: 'CANDIDATE',
                title: f.title,
                claim: f.description,
                affected_assets: (f.source_locations || []).map(l => l.path),
                proposed_test: availableTools[0] || 'inspection',
                status: 'PLANNED'
            }));
        }
    }
}
