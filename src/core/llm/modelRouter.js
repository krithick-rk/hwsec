import { ModelRegistry } from './modelRegistry.js';
import { BudgetController } from './budgetController.js';
import { NvidiaProvider } from './nvidiaProvider.js';
import { GeminiProvider } from './geminiProvider.js';
import { OpenRouterProvider } from './openRouterProvider.js';
import { ProviderPool } from './providerPool.js';
import { TaskRouter } from './taskRouter.js';
import { TaskTypes, TASK_PROFILES } from './taskTypes.js';


export class ModelRouter {
    /**
     * @param {Object} config 
     * @param {Object} [db]
     */
    constructor(config = {}, db = null) {
        this.config = config || {};
        this.registry = new ModelRegistry(this.config);
        this.budgetController = new BudgetController(this.config, db);
        this.providerPool = new ProviderPool(this.config);
        this.taskRouter = new TaskRouter(this.providerPool, this.config);

        this.providers = {
            nvidia: this.providerPool.getEndpoint('nvidia')?.provider || new NvidiaProvider(this.config),
            gemini: this.providerPool.getEndpoint('gemini_account_1')?.provider || new GeminiProvider(this.config),
            openrouter: this.providerPool.getEndpoint('openrouter')?.provider || new OpenRouterProvider(this.config)
        };
    }

    setDb(db) {
        this.budgetController.setDb(db);
    }

    /**
     * Returns true if at least one LLM provider is available.
     */
    isAvailable() {
        return Object.values(this.providers).some(p => p.isAvailable());
    }

    /**
     * Chooses the best model and provider for the requested taskType.
     */
    routeTask(taskType, params = {}) {
        const profile = TASK_PROFILES[taskType] || {
            requiresReasoning: params.requiresReasoning ?? false,
            requiresCode: params.requiresCode ?? false,
            costPreference: 'medium'
        };

        const requiresReasoning = params.requiresReasoning ?? profile.requiresReasoning;
        const requiresCode = params.requiresCode ?? profile.requiresCode;
        const minContext = params.contextTokens || 0;

        // Try NVIDIA first, then Gemini
        let primaryProvider = 'nvidia';
        if (!this.providers.nvidia.isAvailable() && this.providers.gemini.isAvailable()) {
            primaryProvider = 'gemini';
        }

        let model = this.registry.findBestModel({
            provider: primaryProvider,
            requiresReasoning,
            requiresCode,
            maxCostTier: profile.costPreference === 'low' ? 'low' : null,
            minContext
        });

        // If no model found for primary provider, search any enabled provider
        if (!model) {
            model = this.registry.findBestModel({
                requiresReasoning,
                requiresCode,
                minContext
            });
        }

        return model;
    }

    /**
     * Executes a task-based LLM request.
     * @param {Object} params
     * @param {string} params.taskType
     * @param {string} params.systemPrompt
     * @param {string} params.userPrompt
     * @param {Object} [params.jsonSchema]
     * @param {string} [params.analysisId]
     * @param {number} [params.contextTokens]
     * @param {string} [params.priority]
     * @param {boolean} [params.requiresReasoning]
     * @param {boolean} [params.requiresCode]
     * @param {number} [params.temperature]
     * @returns {Promise<{text: string, json: any, usage: Object, model: string, provider: string}>}
     */
    async execute(params) {
        const {
            taskType,
            systemPrompt,
            userPrompt,
            jsonSchema = null,
            analysisId = 'global',
            temperature = 0.1,
            maxTokens = 4096
        } = params;

        // 1. Enforce Budget Policies
        const budgetCheck = this.budgetController.canExecute(taskType, params);
        if (!budgetCheck.allowed) {
            throw new Error(`[ModelRouter] Budget policy rejected task '${taskType}': ${budgetCheck.reason}`);
        }

        // 2. Route task to appropriate model
        const modelEntry = this.routeTask(taskType, params);
        if (!modelEntry) {
            throw new Error(`[ModelRouter] No available model found for task '${taskType}'`);
        }

        const provider = this.providers[modelEntry.provider];
        if (!provider || !provider.isAvailable()) {
            // Check fallback provider
            const fallbackProviderName = modelEntry.provider === 'nvidia' ? 'gemini' : 'nvidia';
            const fallbackProvider = this.providers[fallbackProviderName];
            
            if (fallbackProvider && fallbackProvider.isAvailable()) {
                console.log(`[!] [ModelRouter] Primary provider '${modelEntry.provider}' unavailable. Falling back to '${fallbackProviderName}'...`);
                const fallbackModel = this.registry.findBestModel({ provider: fallbackProviderName });
                if (fallbackModel) {
                    return this._callProvider(fallbackProvider, fallbackModel, params);
                }
            }

            throw new Error(`[ModelRouter] Provider '${modelEntry.provider}' is not available (no credentials).`);
        }

        try {
            return await this._callProvider(provider, modelEntry, params);
        } catch (err) {
            const fallbackPriority = ['gemini', 'openrouter', 'nvidia'].filter(p => p !== modelEntry.provider);
            for (const altName of fallbackPriority) {
                const altProvider = this.providers[altName];
                if (altProvider && altProvider.isAvailable()) {
                    const altModel = this.registry.findBestModel({ provider: altName }) || modelEntry;
                    try {
                        console.log(`[!] [ModelRouter] Provider '${modelEntry.provider}' failed (${err.message}). Falling back to '${altName}'...`);
                        return await this._callProvider(altProvider, altModel, params);
                    } catch (altErr) {
                        console.warn(`[!] [ModelRouter] Fallback provider '${altName}' also failed: ${altErr.message}`);
                    }
                }
            }
            throw err;
        }
    }

    async _callProvider(provider, modelEntry, params) {
        const { taskType, systemPrompt, userPrompt, jsonSchema, analysisId, temperature, maxTokens } = params;

        const result = await provider.generateChat({
            model: modelEntry.id,
            systemPrompt,
            userPrompt,
            jsonSchema,
            temperature,
            maxTokens
        });

        // Record token usage in global ledger
        const usage = result.usage || { promptTokens: 0, completionTokens: 0, totalTokens: 0 };
        this.budgetController.recordUsage({
            analysisId,
            taskType,
            modelId: modelEntry.id,
            provider: provider.name,
            promptTokens: usage.promptTokens,
            completionTokens: usage.completionTokens
        });

        return {
            text: result.text,
            json: result.json,
            usage: usage,
            model: modelEntry.id,
            provider: provider.name
        };
    }
}
