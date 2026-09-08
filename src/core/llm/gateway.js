import { ModelRouter } from './modelRouter.js';
import { TaskTypes } from './taskTypes.js';
import { DynamicTokenScheduler } from './dynamicTokenScheduler.js';
import { PreflightEstimator } from './preflightEstimator.js';
import { TokenBatcher } from './tokenBatcher.js';

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
    'exploit_writer': TaskTypes.EXPLOIT_GENERATION,
    'exploit_verifier': TaskTypes.EXPLOIT_VERIFICATION,
    'poc_generator': TaskTypes.EXPLOIT_GENERATION,
    'exploitability_triage': TaskTypes.EXPLOIT_TRIAGE,
    'default': TaskTypes.SUMMARY
};

/**
 * Unified LLM Gateway for HWSEC
 * Consolidates ModelRouter, BudgetController, DynamicTokenScheduler, and LLMClient interfaces.
 */
export class LLMGateway {
    constructor(config = {}, db = null, role = 'default') {
        this.config = config || {};
        this.db = db;
        this.role = role;
        this.router = new ModelRouter(this.config, this.db);
        this.scheduler = new DynamicTokenScheduler(this.config, this.db);
        this.estimator = this.scheduler.estimator;
        this.batcher = this.scheduler.batcher;
        this.requestAuditLog = [];
    }

    setDb(db) {
        this.db = db;
        this.router.setDb(db);
        this.scheduler.db = db;
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
     * Run Two-Pass Pre-Flight token estimation + greedy bin-packing.
     * @param {Object} opts
     * @param {Array}  [opts.files]              - Flat array of {filePath, content, metadata} objects
     * @param {Object} [opts.inventory]          - RepositoryDiscovery inventory ({languages, file_metadata})
     * @param {string} [opts.modelOrProvider]    - Model name or provider key (defaults to SUMMARY task model)
     * @param {Object} [opts.batchOptions]       - Overrides for TokenBatcher (maxBatchTokens, etc.)
     * @param {string} [opts.analysisId]         - Analysis run ID for report labelling
     * @returns {Promise<Object>} schedulePlan with {batches, report, estimatorSummary, providerRpm, ...}
     */
    async planWorkload({ files = null, inventory = null, modelOrProvider = null, batchOptions = {}, analysisId = 'global' } = {}) {
        const model = modelOrProvider || this.router.routeTask(TaskTypes.SUMMARY);
        return this.scheduler.plan({ files, inventory, modelOrProvider: model, batchOptions, analysisId });
    }

    /**
     * Execute pre-planned batches via rate-limit-aware scheduler.
     * @param {Object} opts
     * @param {Array}  opts.batches     - Batch array from planWorkload()
     * @param {Function} opts.workerFn - async (batch) => any — called per batch
     * @param {string} [opts.provider] - Provider key for RPM lookup
     * @param {number} [opts.concurrency] - Max parallel workers (default 1)
     * @param {Function} [opts.onProgress] - Optional progress callback
     * @returns {Promise<Array>} Ordered results array
     */
    async executeWorkload({ batches, workerFn, provider = 'gemini', concurrency = 1, onProgress = null } = {}) {
        return this.scheduler.executeBatches({ batches, workerFn, provider, concurrency, onProgress });
    }

    /**
     * Convenience: plan then format and log the pre-flight report.
     * @param {Object} opts  - Same options as planWorkload()
     * @returns {Promise<{plan: Object, reportText: string}>}
     */
    async preflightSchedule(opts = {}) {
        const plan = await this.planWorkload(opts);
        const reportText = this.scheduler.formatPreflightReport(plan);
        return { plan, reportText };
    }

    /**
     * Plan & schedule bounded exploit verification for candidate findings.
     * Selects models across OpenRouter and Gemini providers, estimates tokens & runtime,
     * enforces safe sandbox parameters, and generates report.
     * @param {Object} opts
     * @returns {Object} ExploitSchedulePlan
     */
    scheduleExploitVerification(opts = {}) {
        return this.scheduler.scheduleExploitVerification(opts);
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

        // 3. Provider Availability & Fallback (try all available providers in priority order)
        const PROVIDER_PRIORITY = ['nvidia', 'gemini', 'openrouter'];
        if (!provider || !provider.isAvailable()) {
            let found = false;
            for (const altName of PROVIDER_PRIORITY) {
                if (altName === providerName) continue;
                const altProvider = this.router.providers[altName];
                if (altProvider && altProvider.isAvailable()) {
                    fallbackEvents.push({
                        from: providerName,
                        to: altName,
                        reason: 'Primary provider credentials missing or unavailable'
                    });
                    providerName = altName;
                    provider = altProvider;
                    const fallbackModel = this.router.registry.findBestModel({ provider: altName });
                    if (fallbackModel) modelEntry = fallbackModel;
                    found = true;
                    break;
                }
            }
            if (!found) {
                throw new Error(`[LLMGateway] No available provider found. Tried: ${PROVIDER_PRIORITY.join(', ')}.`);
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
            // Try fallback providers on execution failure (in priority order, skipping already-tried)
            let recovered = false;
            if (fallbackEvents.length === 0) {
                for (const altName of PROVIDER_PRIORITY) {
                    if (altName === providerName) continue;
                    const altProvider = this.router.providers[altName];
                    if (altProvider && altProvider.isAvailable()) {
                        fallbackEvents.push({
                            from: providerName,
                            to: altName,
                            reason: `Primary provider call failed: ${err.message}`
                        });
                        const altModel = this.router.registry.findBestModel({ provider: altName }) || modelEntry;
                        try {
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
                            recovered = true;
                            break;
                        } catch (altErr) {
                            console.warn(`[LLMGateway] Fallback provider ${altName} also failed: ${altErr.message}`);
                            // Continue to next provider
                        }
                    }
                }
            }
            if (!recovered) throw err;
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
