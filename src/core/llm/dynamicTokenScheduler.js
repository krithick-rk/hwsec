import crypto from 'crypto';
import { PreflightEstimator } from './preflightEstimator.js';
import { TokenBatcher } from './tokenBatcher.js';

/**
 * Standard default Rate Limits (Requests Per Minute) per LLM provider
 */
const DEFAULT_PROVIDER_RPM = {
    'gemini': 30,
    'openrouter': 20,
    'nvidia': 5,
    'default': 15
};

/**
 * Dynamic Token Scheduler & Rate-Limit Aware Workload Manager
 * Coordinates Pass 1 (Estimation) and Pass 2 (Bin-Packing), plans API rate-limit allocation,
 * logs comprehensive pre-flight reports, and executes batched LLM workloads safely.
 */
export class DynamicTokenScheduler {
    /**
     * @param {Object} [config]
     * @param {Object} [db]
     */
    constructor(config = {}, db = null) {
        this.config = config || {};
        this.db = db;
        this.estimator = new PreflightEstimator(config);
        this.batcher = new TokenBatcher(config.batcher_options || {});
        
        // Rate limit configurations
        const rateLimits = config.token_budgets?.rate_limits || {};
        this.providerRpm = {
            gemini: config.llm_providers?.gemini?.rpm || rateLimits.gemini || DEFAULT_PROVIDER_RPM.gemini,
            openrouter: config.llm_providers?.openrouter?.rpm || rateLimits.openrouter || DEFAULT_PROVIDER_RPM.openrouter,
            nvidia: config.llm_providers?.nvidia?.rpm || rateLimits.nvidia || DEFAULT_PROVIDER_RPM.nvidia,
            default: rateLimits.default || DEFAULT_PROVIDER_RPM.default
        };

        this.executionHistory = [];
    }

    /**
     * Gets configured RPM quota for a provider.
     * @param {string} provider
     * @returns {number}
     */
    getProviderRpm(provider) {
        if (!provider) return this.providerRpm.default;
        const norm = provider.toLowerCase();
        return this.providerRpm[norm] || this.providerRpm.default;
    }

    /**
     * Runs complete pre-flight analysis (Pass 1 + Pass 2 + Rate-Limit Scheduling).
     * @param {Object} params
     * @param {Array<string|Object>} [params.files] List of file paths or file objects
     * @param {Object} [params.inventory] Discovered inventory structure from RepositoryDiscovery
     * @param {Object|string} [params.modelOrProvider] Target model entry or provider name
     * @param {Object} [params.batchOptions] Batching option overrides
     * @param {string} [params.analysisId='global']
     * @returns {Object} PreflightSchedulePlan
     */
    plan({ files = null, inventory = null, modelOrProvider = 'gemini', batchOptions = {}, analysisId = 'global' } = {}) {
        // Pass 1: Workload & Token Estimation
        let estimationResult;
        if (inventory) {
            estimationResult = this.estimator.estimateInventory(inventory);
        } else if (files && Array.isArray(files)) {
            estimationResult = this.estimator.estimateFiles(files);
        } else {
            estimationResult = this.estimator.estimateFiles([]);
        }

        const { files: fileProfiles, summary: workloadSummary } = estimationResult;

        // Pass 2: Dynamic Knapsack Bin-Packing
        const batchPlan = this.batcher.createBatches(fileProfiles, {
            ...batchOptions,
            model: typeof modelOrProvider === 'object' ? modelOrProvider : null,
            provider: typeof modelOrProvider === 'string' ? modelOrProvider : modelOrProvider?.provider
        });

        // Step 3: Rate-Limit Quota & Runtime Calculation
        const targetProvider = batchPlan.parameters.provider || (typeof modelOrProvider === 'string' ? modelOrProvider : modelOrProvider?.provider) || 'gemini';
        const targetModelId = batchPlan.parameters.modelId || (typeof modelOrProvider === 'object' ? modelOrProvider.id : modelOrProvider) || 'gemini-2.5-flash';
        const rpm = this.getProviderRpm(targetProvider);
        const minIntervalMs = Math.ceil(60000 / rpm);

        const totalBatches = batchPlan.totalBatches;
        const estimatedRequests = totalBatches;
        
        // Estimated execution time: sequential batch time with rate limit interval + estimated latency per call (1.5s avg)
        const estimatedLatencyPerCallMs = 1500;
        const totalDurationMs = totalBatches > 0 
            ? (totalBatches * minIntervalMs) + (totalBatches * estimatedLatencyPerCallMs)
            : 0;
        const estimatedDurationSeconds = Math.ceil(totalDurationMs / 1000);

        // Format duration mm:ss or hh:mm:ss
        const mins = Math.floor(estimatedDurationSeconds / 60);
        const secs = estimatedDurationSeconds % 60;
        const durationFormatted = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;

        const schedulePlan = {
            analysisId,
            timestamp: new Date().toISOString(),
            targetProvider,
            targetModelId,
            contextWindow: batchPlan.parameters.contextWindow,
            maxBatchTokensLimit: batchPlan.parameters.maxBatchTokens,
            targetBatchTokens: batchPlan.parameters.targetBatchTokens,
            rpmQuota: rpm,
            minIntervalMs,
            workloadSummary,
            batchPlan,
            totalFiles: workloadSummary.totalFiles,
            totalTokens: workloadSummary.totalTokens,
            totalBatches: batchPlan.totalBatches,
            estimatedRequests,
            estimatedDurationSeconds,
            durationFormatted,
            batches: batchPlan.batches
        };

        schedulePlan.report = this.formatPreflightReport(schedulePlan);

        return schedulePlan;
    }

    /**
     * Formats a clean, user-facing Pre-Flight Summary Report.
     * @param {Object} plan
     * @returns {string}
     */
    formatPreflightReport(plan) {
        const { workloadSummary, batchPlan, rpmQuota, minIntervalMs, durationFormatted, targetProvider, targetModelId } = plan;
        const cb = workloadSummary.complexityBreakdown || {};
        const db = workloadSummary.domainBreakdown || {};

        return [
            `================================================================================`,
            `        HWSEC TWO-PASS PRE-FLIGHT TOKEN & DYNAMIC SCHEDULER REPORT`,
            `================================================================================`,
            `[Pass 1: Workload & Token Estimation]`,
            `  • Total Discovered Files:    ${workloadSummary.totalFiles.toLocaleString()} files (~${workloadSummary.totalLoc.toLocaleString()} LOC)`,
            `  • Total Estimated Tokens:    ~${workloadSummary.totalTokens.toLocaleString()} tokens (avg ~${workloadSummary.avgTokensPerFile.toLocaleString()} tokens/file)`,
            `  • Complexity Distribution:   LOW: ${cb.LOW || 0} | MEDIUM: ${cb.MEDIUM || 0} | HIGH: ${cb.HIGH || 0} | CRITICAL: ${cb.CRITICAL || 0}`,
            `  • Domain Classification:     Hardware: ${db.hardware || 0} | Software: ${db.software || 0} | Config/Other: ${(db.config || 0) + (db.other || 0)}`,
            `  • Peak File Workload:        ${workloadSummary.largestFile || 'None'} (~${(workloadSummary.maxFileTokens || 0).toLocaleString()} tokens)`,
            ``,
            `[Pass 2: Knapsack Bin-Packing]`,
            `  • Target Model / Provider:   ${targetModelId} via [${targetProvider.toUpperCase()}]`,
            `  • Model Max Context:         ${plan.contextWindow.toLocaleString()} tokens (80% Ceiling Cap: ${plan.maxBatchTokensLimit.toLocaleString()} tokens)`,
            `  • Target Batch Size:         ~${plan.targetBatchTokens.toLocaleString()} tokens/batch`,
            `  • Batches Created:           ${batchPlan.totalBatches} batch(es) (Zero dropped files guaranteed: ${batchPlan.totalFiles}/${workloadSummary.totalFiles})`,
            `  • Average Batch Size:        ~${batchPlan.avgBatchTokens.toLocaleString()} tokens (Peak Batch: ~${batchPlan.maxBatchTokens.toLocaleString()} tokens)`,
            ``,
            `[Pass 3: Rate-Limit Quotas & Execution Schedule]`,
            `  • Provider Rate Limit:       ${rpmQuota} RPM (Min call spacing: ${minIntervalMs}ms)`,
            `  • Total Required API Calls:  ${plan.estimatedRequests} requests`,
            `  • Estimated Runtime:         ~${durationFormatted} (${plan.estimatedDurationSeconds}s)`,
            `================================================================================`
        ].join('\n');
    }

    /**
     * Executes batched requests through a worker function while strictly honoring rate limits.
     * @param {Object} params
     * @param {Array<Object>} params.batches Array of batch objects from plan()
     * @param {Function} params.workerFn Async function (batch, index) => Promise<any>
     * @param {string} [params.provider='gemini']
     * @param {number} [params.concurrency=1] Max parallel workers (rate limiter maintains global RPM)
     * @param {Function} [params.onProgress] Optional callback (completed, total, result) => void
     * @returns {Promise<Array<any>>}
     */
    async executeBatches({ batches = [], workerFn, provider = 'gemini', concurrency = 1, onProgress = null }) {
        if (!Array.isArray(batches) || batches.length === 0) return [];
        if (typeof workerFn !== 'function') throw new Error('[DynamicTokenScheduler] workerFn must be a function');

        const rpm = this.getProviderRpm(provider);
        const minIntervalMs = Math.ceil(60000 / rpm);
        const results = [];
        let completed = 0;
        let lastCallTime = 0;

        // Rate limiter helper ensuring minIntervalMs between calls
        const acquireSlot = async () => {
            const now = Date.now();
            const elapsed = now - lastCallTime;
            if (elapsed < minIntervalMs) {
                const waitMs = minIntervalMs - elapsed;
                await new Promise(resolve => setTimeout(resolve, waitMs));
            }
            lastCallTime = Date.now();
        };

        for (let i = 0; i < batches.length; i++) {
            const batch = batches[i];
            await acquireSlot();

            try {
                const res = await workerFn(batch, i);
                results.push({ batchId: batch.batchId, status: 'SUCCESS', result: res });
            } catch (err) {
                results.push({ batchId: batch.batchId, status: 'ERROR', error: err.message });
            }

            completed++;
            if (typeof onProgress === 'function') {
                onProgress(completed, batches.length, results[results.length - 1]);
            }
        }

        return results;
    }

    /**
     * Schedules bounded budgets and selects target models/providers for exploit verification.
     * Integrates Gemini (multi-key pool) and OpenRouter (for exploit writing/reasoning).
     *
     * @param {Object} params
     * @param {Array<Object>} params.findings Array of candidate findings
     * @param {number} [params.remainingTokenBudget] Remaining tokens allocated for PoC generation
     * @param {number} [params.remainingRuntimeBudget] Remaining time in seconds
     * @param {string} [params.exploitMode='standard'] 'off' | 'minimal' | 'standard' | 'deep'
     * @param {string} [params.preferredProvider=null] 'openrouter' | 'gemini' | null (auto-select)
     * @param {string} [params.analysisId='global']
     * @returns {Object} ExploitSchedulePlan
     */
    scheduleExploitVerification({
        findings = [],
        remainingTokenBudget = null,
        remainingRuntimeBudget = null,
        exploitMode = 'standard',
        preferredProvider = null,
        analysisId = 'global'
    } = {}) {
        const mode = (exploitMode || 'standard').toLowerCase();
        const maxTokensBudget = remainingTokenBudget ?? this.config.exploit_verifier?.max_tokens ?? 50000;
        const maxTimeBudget = remainingRuntimeBudget ?? this.config.exploit_verifier?.max_runtime_seconds ?? 300;

        // Check provider availability and inject configured keys
        const openrouterKey = process.env.OPENROUTER_API_KEY || this.config.llm_providers?.openrouter?.api_key || '';
        const geminiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || this.config.llm_providers?.gemini?.api_key || '';
        const hasGemini = !!geminiKey;
        const hasOpenRouter = !!openrouterKey;

        const scheduledAttempts = [];
        const skippedFindings = [];
        const deferredFindings = [];
        let allocatedTokens = 0;
        let allocatedRuntimeSeconds = 0;

        if (mode === 'off') {
            for (const f of findings) {
                skippedFindings.push({
                    findingId: f.id,
                    reason: 'EXPLOIT_MODE_OFF',
                    description: 'Exploit verification disabled via --exploit-mode off',
                    decision: 'SKIP'
                });
            }
            const plan = {
                analysisId,
                exploitMode: mode,
                totalFindings: findings.length,
                eligibleFindings: 0,
                scheduledAttempts: [],
                skippedFindings,
                deferredFindings: [],
                decisions: { RUN: 0, DEFER: 0, SKIP: findings.length },
                allocatedTokens: 0,
                allocatedRuntimeSeconds: 0,
                estimatedCostUsd: 0,
                providers: [],
                keyStatus: {
                    openrouter: hasOpenRouter ? 'CONFIGURED (Active for Code Writing)' : 'MISSING',
                    gemini: hasGemini ? 'CONFIGURED (Active for Triage/Verification)' : 'MISSING'
                },
                rpmQuotas: {
                    gemini: this.getProviderRpm('gemini'),
                    openrouter: this.getProviderRpm('openrouter')
                }
            };
            plan.report = this.formatExploitPreflightReport(plan);
            return plan;
        }

        const maxIterations = mode === 'deep' ? 3 : (mode === 'minimal' ? 1 : 2);

        // Pre-estimate and sort findings by priority score descending
        const estimatedFindings = findings.map(f => {
            const est = this.estimator.estimateFindingExploitCost(f, {
                remainingTokenBudget: maxTokensBudget,
                remainingRuntimeBudget: maxTimeBudget
            });
            return { finding: f, estimate: est };
        });

        // Priority ordering: highest proof priority score first
        estimatedFindings.sort((a, b) => (b.estimate.proof_priority_score || 0) - (a.estimate.proof_priority_score || 0));

        for (const { finding, estimate } of estimatedFindings) {
            // Filter out non-feasible findings
            if (estimate.triageDecision === 'UNSAFE_TARGET') {
                skippedFindings.push({
                    findingId: finding.id,
                    reason: 'UNSAFE_TARGET',
                    description: estimate.triageReason,
                    metrics: estimate.metrics,
                    decision: 'SKIP'
                });
                continue;
            }

            if (estimate.triageDecision === 'NO_POC') {
                skippedFindings.push({
                    findingId: finding.id,
                    reason: 'TRIAGE_REJECTED',
                    description: estimate.triageReason,
                    metrics: estimate.metrics,
                    decision: 'SKIP'
                });
                continue;
            }

            // Mode 'minimal' requires high severity or confidence
            if (mode === 'minimal' && estimate.metrics.exploitability_score < 0.65) {
                skippedFindings.push({
                    findingId: finding.id,
                    reason: 'MINIMAL_MODE_THRESHOLD',
                    description: 'Score below minimal mode threshold (0.65)',
                    metrics: estimate.metrics,
                    decision: 'SKIP'
                });
                continue;
            }

            // Check budget constraints for RUN vs DEFER
            const requiredTokens = estimate.resourceEstimation.totalEstimatedTokens;
            const requiredTime = estimate.resourceEstimation.estimatedRuntimeSeconds;

            if (allocatedTokens + requiredTokens > maxTokensBudget) {
                const deferRecord = {
                    findingId: finding.id,
                    reason: 'TOKEN_BUDGET_EXHAUSTED',
                    description: `Allocated ${allocatedTokens} tokens would exceed budget of ${maxTokensBudget}`,
                    metrics: estimate.metrics,
                    decision: 'DEFER'
                };
                deferredFindings.push(deferRecord);
                skippedFindings.push(deferRecord);
                continue;
            }

            if (allocatedRuntimeSeconds + requiredTime > maxTimeBudget) {
                const deferRecord = {
                    findingId: finding.id,
                    reason: 'RUNTIME_BUDGET_EXHAUSTED',
                    description: `Allocated runtime ${allocatedRuntimeSeconds}s would exceed budget of ${maxTimeBudget}s`,
                    metrics: estimate.metrics,
                    decision: 'DEFER'
                };
                deferredFindings.push(deferRecord);
                skippedFindings.push(deferRecord);
                continue;
            }

            // Provider & Model Selection
            let chosenProvider = preferredProvider;
            let chosenModel;

            if (!chosenProvider) {
                // OpenRouter preferred for complex exploit/code synthesis, Gemini for high RPM & fast formal triage
                if (hasOpenRouter && estimate.domain === 'software') {
                    chosenProvider = 'openrouter';
                    chosenModel = 'meta-llama/llama-3.3-70b-instruct';
                } else if (hasGemini) {
                    chosenProvider = 'gemini';
                    chosenModel = 'gemini-2.5-flash';
                } else if (hasOpenRouter) {
                    chosenProvider = 'openrouter';
                    chosenModel = 'meta-llama/llama-3.3-70b-instruct';
                } else {
                    chosenProvider = 'nvidia';
                    chosenModel = 'meta/llama-3.3-70b-instruct';
                }
            } else {
                chosenModel = chosenProvider === 'openrouter'
                    ? 'meta-llama/llama-3.3-70b-instruct'
                    : (chosenProvider === 'gemini' ? 'gemini-2.5-flash' : 'meta/llama-3.3-70b-instruct');
            }

            // Allowed tools based on domain/language
            const allowedTools = [];
            if (estimate.domain === 'hardware') {
                allowedTools.push('yosys', 'sby', 'verilator');
            } else if (estimate.language === 'c' || estimate.language === 'cpp') {
                allowedTools.push('gcc', 'clang', 'gdb', 'asan');
            } else if (estimate.language === 'python' || estimate.language === 'py') {
                allowedTools.push('python3', 'pytest');
            } else if (estimate.language === 'javascript' || estimate.language === 'typescript') {
                allowedTools.push('node');
            } else {
                allowedTools.push('local_test_runner');
            }

            const proofId = `PROOF-${crypto.randomBytes(6).toString('hex')}`;
            const proofType = estimate.domain === 'hardware' ? 'FORMAL_COUNTEREXAMPLE' : 'REGRESSION_TEST';

            const attempt = {
                proofId,
                findingId: finding.id,
                title: finding.title,
                cweId: finding.cwe_id || 'CWE-UNKNOWN',
                severity: estimate.severity,
                language: estimate.language,
                domain: estimate.domain,
                proofType,
                triageDecision: estimate.triageDecision,
                triageReason: estimate.triageReason,
                proofPriorityScore: estimate.proof_priority_score,
                proofEligibility: estimate.proof_eligibility,
                reasoningSummary: estimate.reasoning_summary,
                decision: 'RUN',
                metrics: estimate.metrics,
                budget: {
                    model: chosenModel,
                    provider: chosenProvider,
                    max_input_tokens: estimate.resourceEstimation.maxInputTokens,
                    max_output_tokens: estimate.resourceEstimation.maxOutputTokens,
                    max_iterations: maxIterations,
                    max_runtime_seconds: estimate.resourceEstimation.estimatedRuntimeSeconds,
                    sandbox_profile: 'strict',
                    allowed_tools: allowedTools,
                    stop_conditions: [
                        'reproduced',
                        'claim_mismatch',
                        'timeout',
                        'unsafe_blocked',
                        'max_iterations_reached'
                    ]
                },
                estimatedTokens: requiredTokens,
                estimatedRuntimeSeconds: requiredTime,
                estimatedCostUsd: estimate.resourceEstimation.estimatedCostUsd
            };

            scheduledAttempts.push(attempt);
            allocatedTokens += requiredTokens;
            allocatedRuntimeSeconds += requiredTime;

            // Persist to database if db is available
            if (this.db) {
                if (typeof this.db.saveProofRecord === 'function') {
                    try {
                        this.db.saveProofRecord({
                            proof_id: proofId,
                            finding_id: finding.id,
                            analysis_id: analysisId,
                            proof_type: proofType,
                            proof_status: 'QUEUED',
                            preflight_estimate: estimate,
                            estimated_tokens: requiredTokens,
                            estimated_runtime: requiredTime,
                            execution_environment: 'hwsec_isolated_sandbox'
                        });
                    } catch (e) {
                        // non-fatal
                    }
                }
                if (typeof this.db.recordExploitAttempt === 'function') {
                    try {
                        this.db.recordExploitAttempt({
                            runId: analysisId,
                            findingId: finding.id,
                            state: 'ATTEMPT_SCHEDULED',
                            decision: estimate.triageDecision,
                            provider: chosenProvider,
                            model: chosenModel,
                            allocatedTokens: requiredTokens,
                            sandboxProfile: 'strict'
                        });
                    } catch (e) {
                        // non-fatal
                    }
                }
            }
        }

        const totalCostUsd = scheduledAttempts.reduce((acc, a) => acc + (a.estimatedCostUsd || 0), 0);
        const usedProviders = Array.from(new Set(scheduledAttempts.map(a => a.budget.provider)));

        const plan = {
            analysisId,
            exploitMode: mode,
            totalFindings: findings.length,
            eligibleFindings: scheduledAttempts.length,
            scheduledAttempts,
            skippedFindings,
            deferredFindings,
            decisions: {
                RUN: scheduledAttempts.length,
                DEFER: deferredFindings.length,
                SKIP: skippedFindings.length - deferredFindings.length
            },
            allocatedTokens,
            allocatedRuntimeSeconds,
            estimatedCostUsd: Math.round(totalCostUsd * 10000) / 10000,
            providers: usedProviders,
            keyStatus: {
                openrouter: hasOpenRouter ? 'CONFIGURED (Active for Code Writing)' : 'MISSING',
                gemini: hasGemini ? 'CONFIGURED (Active for Triage/Verification)' : 'MISSING'
            },
            rpmQuotas: {
                gemini: this.getProviderRpm('gemini'),
                openrouter: this.getProviderRpm('openrouter')
            }
        };

        plan.report = this.formatExploitPreflightReport(plan);
        return plan;
    }

    /**
     * Alias for scheduleExploitVerification adhering to the Controlled Proof-of-Impact terminology.
     */
    scheduleProofValidation(opts = {}) {
        return this.scheduleExploitVerification(opts);
    }

    /**
     * Formats a user-facing Exploit Pre-Flight Schedule Report.
     * @param {Object} plan
     * @returns {string}
     */
    formatExploitPreflightReport(plan) {
        const lines = [
            `================================================================================`,
            `        HWSEC EXPLOIT VERIFIER — PRE-FLIGHT TOKEN & DYNAMIC SCHEDULE REPORT`,
            `================================================================================`,
            `[Exploit Verifier Triage & Budget]`,
            `  • Execution Mode:            ${(plan.exploitMode || 'standard').toUpperCase()}`,
            `  • Total Evaluated Findings:  ${plan.totalFindings}`,
            `  • Scheduler Decisions:       RUN: ${plan.decisions?.RUN ?? plan.eligibleFindings} | DEFER: ${plan.decisions?.DEFER ?? plan.deferredFindings?.length ?? 0} | SKIP: ${plan.decisions?.SKIP ?? plan.skippedFindings?.length ?? 0}`,
            `  • Eligible for PoC Testing:  ${plan.eligibleFindings} finding(s)`,
            `  • Skipped / Retained:        ${plan.skippedFindings.length} finding(s)`,
            `  • Total Allocated Tokens:    ~${plan.allocatedTokens.toLocaleString()} tokens`,
            `  • Total Estimated Runtime:   ~${plan.allocatedRuntimeSeconds}s`,
            `  • Estimated Cost (USD):      ~$${(plan.estimatedCostUsd || 0).toFixed(4)}`,
            `  • Active LLM Providers:      ${plan.providers && plan.providers.length > 0 ? plan.providers.map(p => p.toUpperCase()).join(', ') : 'None'}`,
            `  • Provider Rate Limits:      Gemini: ${plan.rpmQuotas?.gemini || 30} RPM | OpenRouter: ${plan.rpmQuotas?.openrouter || 20} RPM`,
            `  • Code Writer (OpenRouter):  ${plan.keyStatus?.openrouter || 'ACTIVE'}`,
            `  • Verifier Pool (Gemini):    ${plan.keyStatus?.gemini || 'ACTIVE'}`,
            ``,
            `[Scheduled PoC Verifications]`
        ];

        if (plan.scheduledAttempts.length === 0) {
            lines.push(`  (No findings scheduled for PoC generation under current constraints)`);
        } else {
            for (const att of plan.scheduledAttempts) {
                const b = att.budget;
                lines.push(`  • [${att.findingId}] ${(att.title || '').slice(0, 50)} (${att.cweId})`);
                lines.push(`    - Triage:      ${att.triageDecision} (Score: ${att.metrics.exploitability_score})`);
                lines.push(`    - Allocation:  ${b.provider.toUpperCase()} / ${b.model} | Max Toks: ${b.max_input_tokens + b.max_output_tokens} (In: ${b.max_input_tokens}, Out: ${b.max_output_tokens})`);
                lines.push(`    - Sandbox:     Profile: ${b.sandbox_profile} | Net: NONE | Timeout: ${b.max_runtime_seconds}s | Tools: [${b.allowed_tools.join(', ')}]`);
            }
        }

        if (plan.skippedFindings && plan.skippedFindings.length > 0) {
            lines.push(``);
            lines.push(`[Skipped Candidates Summary]`);
            const reasonsCount = {};
            for (const s of plan.skippedFindings) {
                reasonsCount[s.reason] = (reasonsCount[s.reason] || 0) + 1;
            }
            for (const [r, count] of Object.entries(reasonsCount)) {
                lines.push(`  • ${r}: ${count} finding(s)`);
            }
        }

        lines.push(`================================================================================`);
        return lines.join('\n');
    }
}
