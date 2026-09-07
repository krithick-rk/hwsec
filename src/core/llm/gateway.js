import { ModelRouter } from './modelRouter.js';
import { TaskTypes } from './taskTypes.js';

/**
 * Role to TaskType mapping for backward compatibility
 */
const ROLE_TO_TASK = {
    'planner': TaskTypes.PLANNING,
    'hypothesis_generator': TaskTypes.HYPOTHESIS_GENERATION,
    'invariant_synthesizer': TaskTypes.INVARIANT_SYNTHESIS,
    'verifier': TaskTypes.VERIFICATION,
    'correlator': TaskTypes.CORRELATION,
    'interpreter': TaskTypes.VULNERABILITY_CLASSIFICATION,
    'refiner': TaskTypes.NOVELTY_ANALYSIS,
    'spec_ingestor': TaskTypes.SPEC_INGESTION,
    'spec_divergence': TaskTypes.SPEC_INGESTION,
    'worker': TaskTypes.VULNERABILITY_CLASSIFICATION,
    'default': TaskTypes.SUMMARY
};

/**
 * Unified LLM Gateway for HWSEC
 * Consolidates ModelRouter, BudgetController, and LLMClient interfaces.
 */
export class LLMGateway {
    constructor(config = {}, db = null, role = 'default') {
        this.config = config || {};
        this.db = db;
        this.role = role;
        this.router = new ModelRouter(this.config, this.db);
        this.requestAuditLog = [];
    }

    setDb(db) {
        this.db = db;
        this.router.setDb(db);
    }

    /**
     * Check if any configured provider is available
     */
    isAvailable() {
        return this.router.isAvailable();
    }

    /**
     * Returns an instance bound to a specific functional role
     */
    forRole(role) {
        const gw = new LLMGateway(this.config, this.db, role);
        gw.router = this.router; // Share the same router and budget controller
        return gw;
    }

    /**
     * Backward-compatible generateContent method.
     */
    async generateContent(systemPrompt, userPrompt, jsonSchema = null, options = {}) {
        const taskType = options.taskType || ROLE_TO_TASK[this.role] || TaskTypes.SUMMARY;
        return this.execute({
            taskType,
            systemPrompt,
            userPrompt,
            jsonSchema,
            ...options
        });
    }

    /**
     * Unified execution method with comprehensive telemetry, budget tracking, and auditing.
     * @param {Object} params
     * @returns {Promise<{text: string, json: any, usage: Object, model: string, provider: string, telemetry: Object}>}
     */
    async execute(params) {
        const startTime = Date.now();
        const taskType = params.taskType || ROLE_TO_TASK[this.role] || TaskTypes.SUMMARY;
        const analysisId = params.analysisId || 'global';
        const fallbackEvents = [];

        // 1. Budget Decision
        const budgetDecision = this.router.budgetController.canExecute(taskType, params);
        if (!budgetDecision.allowed) {
            const telemetry = {
                timestamp: new Date().toISOString(),
                taskType,
                allowed: false,
                reason: budgetDecision.reason,
                budgetRatio: budgetDecision.budgetRatio,
                durationMs: Date.now() - startTime
            };
            this._logAudit(telemetry);
            throw new Error(`[LLMGateway] Budget policy rejected task '${taskType}': ${budgetDecision.reason}`);
        }

        // 2. Route Task to Model
        let modelEntry = this.router.routeTask(taskType, params);
        if (!modelEntry) {
            throw new Error(`[LLMGateway] No suitable model entry found for task '${taskType}'`);
        }

        let providerName = modelEntry.provider;
        let provider = this.router.providers[providerName];

        // 3. Provider Availability & Fallback
        if (!provider || !provider.isAvailable()) {
            const fallbackName = providerName === 'nvidia' ? 'gemini' : 'nvidia';
            const fallbackProvider = this.router.providers[fallbackName];
            if (fallbackProvider && fallbackProvider.isAvailable()) {
                fallbackEvents.push({
                    from: providerName,
                    to: fallbackName,
                    reason: 'Primary provider credentials missing or unavailable'
                });
                providerName = fallbackName;
                provider = fallbackProvider;
                const fallbackModel = this.router.registry.findBestModel({ provider: fallbackName });
                if (fallbackModel) {
                    modelEntry = fallbackModel;
                }
            } else {
                throw new Error(`[LLMGateway] Provider '${providerName}' is not available (no credentials).`);
            }
        }

        // 4. Invocation with Fallback Recovery
        let result;
        try {
            result = await provider.generateChat({
                model: modelEntry.id,
                systemPrompt: params.systemPrompt,
                userPrompt: params.userPrompt,
                jsonSchema: params.jsonSchema,
                temperature: params.temperature ?? 0.1,
                maxTokens: params.maxTokens ?? 4096
            });
        } catch (err) {
            // Try fallback provider on execution failure if not already tried
            const altName = providerName === 'nvidia' ? 'gemini' : 'nvidia';
            const altProvider = this.router.providers[altName];
            if (fallbackEvents.length === 0 && altProvider && altProvider.isAvailable()) {
                fallbackEvents.push({
                    from: providerName,
                    to: altName,
                    reason: `Primary provider call failed: ${err.message}`
                });
                const altModel = this.router.registry.findBestModel({ provider: altName }) || modelEntry;
                result = await altProvider.generateChat({
                    model: altModel.id,
                    systemPrompt: params.systemPrompt,
                    userPrompt: params.userPrompt,
                    jsonSchema: params.jsonSchema,
                    temperature: params.temperature ?? 0.1,
                    maxTokens: params.maxTokens ?? 4096
                });
                providerName = altName;
                modelEntry = altModel;
            } else {
                throw err;
            }
        }

        const durationMs = Date.now() - startTime;
        const usage = result.usage || { promptTokens: 0, completionTokens: 0, totalTokens: 0 };

        // 5. Cost Estimation & Ledger Recording
        const estimatedCost = this.router.budgetController.recordUsage({
            analysisId,
            taskType,
            modelId: modelEntry.id,
            provider: providerName,
            promptTokens: usage.promptTokens,
            completionTokens: usage.completionTokens
        });

        const telemetry = {
            timestamp: new Date().toISOString(),
            provider: providerName,
            model: modelEntry.id,
            taskType,
            analysisId,
            promptTokens: usage.promptTokens,
            completionTokens: usage.completionTokens,
            totalTokens: usage.totalTokens,
            estimatedCostUsd: estimatedCost,
            latencyMs: durationMs,
            fallbackEvents,
            budgetRatio: this.router.budgetController.getConsumptionRatio()
        };

        this._logAudit(telemetry);

        return {
            text: result.text,
            json: result.json,
            usage,
            model: modelEntry.id,
            provider: providerName,
            telemetry
        };
    }

    _logAudit(record) {
        this.requestAuditLog.push(record);
        if (this.db && typeof this.db.recordAuditEvent === 'function') {
            try {
                this.db.recordAuditEvent({
                    runId: record.analysisId || record.runId || 'global',
                    eventType: 'LLM_GATEWAY',
                    message: `LLM gateway telemetry: ${record.taskType || 'unknown'}`,
                    metadata: record
                });
            } catch (err) {
                console.error(`[-] Failed to persist LLM audit event: ${err.message}`);
            }
        }
    }
}
