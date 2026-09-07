import crypto from 'crypto';
import { TASK_PROFILES, TaskTypes } from './taskTypes.js';

export class BudgetController {
    /**
     * @param {Object} config 
     * @param {Object} [db] Optional database handle for logging to token_ledger
     */
    constructor(config = {}, db = null) {
        this.config = config;
        this.db = db;
        
        const budgetConfig = config.token_budgets || {};
        this.maxCostUsd = budgetConfig.max_cost_usd !== undefined ? Number(budgetConfig.max_cost_usd) : 10.0;
        this.maxTotalTokens = budgetConfig.max_tokens !== undefined ? Number(budgetConfig.max_tokens) : 1000000;
        
        this.promptTokensTotal = 0;
        this.completionTokensTotal = 0;
        this.totalTokensConsumed = 0;
        this.totalCostUsd = 0.0;
        
        this.ledger = [];
        if (this.db) {
            this.loadFromDatabase();
        }
    }

    setDb(db) {
        this.db = db;
        if (db) {
            this.loadFromDatabase();
        }
    }

    loadFromDatabase(runId = null) {
        if (!this.db || !this.db.db) return;
        try {
            const query = runId 
                ? `SELECT * FROM token_ledger WHERE run_id = ?`
                : `SELECT * FROM token_ledger`;
            const rows = this.db.db.prepare(query).all(...(runId ? [runId] : []));
            this.promptTokensTotal = 0;
            this.completionTokensTotal = 0;
            this.totalTokensConsumed = 0;
            this.totalCostUsd = 0.0;
            this.ledger = [];
            for (const r of rows) {
                this.promptTokensTotal += r.prompt_tokens || 0;
                this.completionTokensTotal += r.completion_tokens || 0;
                this.totalTokensConsumed += r.total_tokens || 0;
                this.totalCostUsd += r.estimated_cost || 0.0;
                this.ledger.push(r);
            }
        } catch {}
    }

    /**
     * Calculates the current budget consumption ratio (0.0 to 1.0+).
     * @returns {number}
     */
    getConsumptionRatio() {
        const costRatio = this.maxCostUsd > 0 ? this.totalCostUsd / this.maxCostUsd : 0;
        const tokenRatio = this.maxTotalTokens > 0 ? this.totalTokensConsumed / this.maxTotalTokens : 0;
        return Math.max(costRatio, tokenRatio);
    }

    /**
     * Determines whether an LLM task is allowed to execute based on tiered budget policies.
     * @param {string} taskType 
     * @param {Object} options 
     * @returns {{allowed: boolean, reason: string|null, budgetRatio: number}}
     */
    canExecute(taskType, options = {}) {
        const ratio = this.getConsumptionRatio();
        const profile = TASK_PROFILES[taskType] || { priority: 'medium', isExploratory: false };
        const isVerification = taskType === TaskTypes.VERIFICATION || options.priority === 'critical';

        // >= 100%: Block all LLM calls except critical verification emergency allowance (up to 105%)
        if (ratio >= 1.0) {
            if (isVerification && ratio < 1.05) {
                return {
                    allowed: true,
                    reason: 'Emergency verification allowance triggered above 100% budget',
                    budgetRatio: ratio
                };
            }
            return {
                allowed: false,
                reason: `Global budget exceeded (consumed ${(ratio * 100).toFixed(1)}% of $${this.maxCostUsd} cap)`,
                budgetRatio: ratio
            };
        }

        // 90-95%: Stop novelty/exploration, focus on important verification
        if (ratio >= 0.90) {
            if (profile.isExploratory || taskType === TaskTypes.NOVELTY_ANALYSIS) {
                return {
                    allowed: false,
                    reason: `Budget at ${(ratio * 100).toFixed(1)}%: novelty and exploratory LLM tasks are suppressed to preserve verification budget`,
                    budgetRatio: ratio
                };
            }
        }

        // 80-90%: Throttle expensive exploratory calls
        if (ratio >= 0.80) {
            if (taskType === TaskTypes.NOVELTY_ANALYSIS && options.noveltyMode === 'deep') {
                return {
                    allowed: false,
                    reason: `Budget at ${(ratio * 100).toFixed(1)}%: deep novelty analysis throttled to conserve budget`,
                    budgetRatio: ratio
                };
            }
        }

        return {
            allowed: true,
            reason: null,
            budgetRatio: ratio
        };
    }

    /**
     * Records token usage and cost in the ledger and optionally the database.
     */
    recordUsage({ analysisId, taskType, modelId, provider, promptTokens = 0, completionTokens = 0, cost = null }) {
        const pTokens = Number(promptTokens) || 0;
        const cTokens = Number(completionTokens) || 0;
        const total = pTokens + cTokens;
        
        // Compute cost estimate if not provided (default baseline $0.50 / 1M input, $1.50 / 1M output)
        const computedCost = cost !== null ? Number(cost) : Number(((pTokens * 0.0000005) + (cTokens * 0.0000015)).toFixed(6));

        this.promptTokensTotal += pTokens;
        this.completionTokensTotal += cTokens;
        this.totalTokensConsumed += total;
        this.totalCostUsd += computedCost;

        const entry = {
            id: `TL-${crypto.randomBytes(4).toString('hex')}`,
            analysis_id: analysisId || 'global',
            task_type: taskType || 'unknown',
            model_id: modelId || 'unknown',
            provider: provider || 'unknown',
            prompt_tokens: pTokens,
            completion_tokens: cTokens,
            total_tokens: total,
            estimated_cost: computedCost,
            timestamp: new Date().toISOString()
        };

        this.ledger.push(entry);

        if (this.db && typeof this.db.recordTokenUsage === 'function') {
            try {
                this.db.recordTokenUsage(entry);
            } catch (err) {
                console.error(`[-] [BudgetController] Failed to record token ledger in DB: ${err.message}`);
            }
        }

        return entry;
    }

    getStats() {
        return {
            prompt_tokens: this.promptTokensTotal,
            completion_tokens: this.completionTokensTotal,
            total_tokens: this.totalTokensConsumed,
            total_cost_usd: Number(this.totalCostUsd.toFixed(4)),
            max_cost_usd: this.maxCostUsd,
            consumption_ratio: Number(this.getConsumptionRatio().toFixed(3)),
            ledger_entries_count: this.ledger.length
        };
    }
}
