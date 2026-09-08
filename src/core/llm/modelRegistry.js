/**
 * Model Capability Registry
 */

const DEFAULT_MODELS = [
    // NVIDIA NIM Models
    {
        id: 'meta/llama-3.3-70b-instruct',
        provider: 'nvidia',
        contextWindow: 128000,
        capabilities: {
            reasoning: 0.90,
            coding: 0.88,
            summarization: 0.95,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'medium',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'nvidia/llama-3.1-nemotron-70b-instruct',
        provider: 'nvidia',
        contextWindow: 128000,
        capabilities: {
            reasoning: 0.94,
            coding: 0.90,
            summarization: 0.92,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'medium',
        latencyTier: 'medium',
        enabled: true
    },
    {
        id: 'mistralai/codestral-22b-instruct-v0.1',
        provider: 'nvidia',
        contextWindow: 32768,
        capabilities: {
            reasoning: 0.82,
            coding: 0.95,
            summarization: 0.80,
            structuredOutput: true,
            toolUse: false
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'deepseek-ai/deepseek-r1',
        provider: 'nvidia',
        contextWindow: 64000,
        capabilities: {
            reasoning: 0.98,
            coding: 0.94,
            summarization: 0.88,
            structuredOutput: true,
            toolUse: false
        },
        costTier: 'high',
        latencyTier: 'slow',
        enabled: true
    },

    // Gemini Fallback Models
    {
        id: 'gemini-1.5-flash',
        provider: 'gemini',
        contextWindow: 1048576,
        capabilities: {
            reasoning: 0.88,
            coding: 0.86,
            summarization: 0.95,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'gemini-2.5-flash',
        provider: 'gemini',
        contextWindow: 1048576,
        capabilities: {
            reasoning: 0.92,
            coding: 0.90,
            summarization: 0.96,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'gemini-1.5-pro',
        provider: 'gemini',
        contextWindow: 2097152,
        capabilities: {
            reasoning: 0.95,
            coding: 0.92,
            summarization: 0.98,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'high',
        latencyTier: 'medium',
        enabled: true
    },

    // OpenRouter Models
    {
        id: 'meta-llama/llama-3.3-70b-instruct',
        provider: 'openrouter',
        contextWindow: 128000,
        capabilities: {
            reasoning: 0.92,
            coding: 0.90,
            summarization: 0.94,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'anthropic/claude-3.5-sonnet',
        provider: 'openrouter',
        contextWindow: 200000,
        capabilities: {
            reasoning: 0.96,
            coding: 0.95,
            summarization: 0.97,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'high',
        latencyTier: 'medium',
        enabled: true
    },
    {
        id: 'google/gemini-2.5-flash',
        provider: 'openrouter',
        contextWindow: 1048576,
        capabilities: {
            reasoning: 0.90,
            coding: 0.88,
            summarization: 0.95,
            structuredOutput: true,
            toolUse: true
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    },
    {
        id: 'google/gemini-1.5-flash',
        provider: 'openrouter',
        contextWindow: 1048576,
        capabilities: {
            reasoning: 0.86,
            coding: 0.84,
            summarization: 0.94,
            structuredOutput: true,
            toolUse: false
        },
        costTier: 'low',
        latencyTier: 'fast',
        enabled: true
    }
];

export class ModelRegistry {
    constructor(config = {}) {
        this.config = config;
        this.models = new Map();

        // 1. Load default models
        for (const m of DEFAULT_MODELS) {
            this.models.set(m.id, { ...m });
        }

        // 2. Allow user config overrides and additions
        if (config.models && typeof config.models === 'object') {
            for (const [key, conf] of Object.entries(config.models)) {
                const modelId = conf.model || conf.id || key;
                const existing = this.models.get(modelId) || {};
                this.models.set(modelId, {
                    id: modelId,
                    provider: conf.provider || existing.provider || 'nvidia',
                    contextWindow: conf.contextWindow || existing.contextWindow || 32768,
                    capabilities: {
                        reasoning: conf.capabilities?.reasoning ?? existing.capabilities?.reasoning ?? 0.8,
                        coding: conf.capabilities?.coding ?? existing.capabilities?.coding ?? 0.8,
                        summarization: conf.capabilities?.summarization ?? existing.capabilities?.summarization ?? 0.8,
                        structuredOutput: conf.capabilities?.structuredOutput ?? existing.capabilities?.structuredOutput ?? true,
                        toolUse: conf.capabilities?.toolUse ?? existing.capabilities?.toolUse ?? false
                    },
                    costTier: conf.costTier || existing.costTier || 'medium',
                    latencyTier: conf.latencyTier || existing.latencyTier || 'medium',
                    enabled: conf.enabled !== undefined ? conf.enabled : true
                });
            }
        }
    }

    register(model) {
        if (!model || !model.id) {
            throw new Error("Model registration requires an 'id'");
        }
        this.models.set(model.id, model);
    }

    getModel(id) {
        return this.models.get(id) || null;
    }

    getAllModels() {
        return Array.from(this.models.values());
    }

    getEnabledModels(provider = null) {
        return Array.from(this.models.values()).filter(m => {
            if (!m.enabled) return false;
            if (provider && m.provider !== provider) return false;
            return true;
        });
    }

    /**
     * Finds the best model matching task criteria.
     */
    findBestModel({ provider = null, requiresReasoning = false, requiresCode = false, maxCostTier = null, minContext = 0 }) {
        let candidates = this.getEnabledModels(provider);

        if (minContext > 0) {
            candidates = candidates.filter(m => m.contextWindow >= minContext);
        }

        if (maxCostTier === 'low') {
            const lowTier = candidates.filter(m => m.costTier === 'low');
            if (lowTier.length > 0) candidates = lowTier;
        }

        candidates.sort((a, b) => {
            let scoreA = 0;
            let scoreB = 0;

            if (requiresCode) {
                scoreA += (a.capabilities.coding || 0) * 2;
                scoreB += (b.capabilities.coding || 0) * 2;
            }
            if (requiresReasoning) {
                scoreA += (a.capabilities.reasoning || 0) * 2;
                scoreB += (b.capabilities.reasoning || 0) * 2;
            }
            scoreA += (a.capabilities.summarization || 0);
            scoreB += (b.capabilities.summarization || 0);

            return scoreB - scoreA;
        });

        return candidates[0] || null;
    }
}
