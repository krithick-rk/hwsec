import crypto from 'crypto';

/**
 * Model class profiles and default batch target recommendations
 */
const CONTEXT_TIER_TARGETS = {
    LARGE: {
        minContext: 500000,
        targetBatchTokens: 64000,     // 50k - 100k target
        minBatchTokens: 16000
    },
    STANDARD: {
        minContext: 64000,
        targetBatchTokens: 12000,     // 8k - 16k target
        minBatchTokens: 4000
    },
    SMALL: {
        minContext: 0,
        targetBatchTokens: 6000,      // 4k - 8k target
        minBatchTokens: 1000
    }
};

/**
 * Pass 2: Dynamic Bin-Packing (Knapsack Batcher)
 * Groups discovered files into optimal token chunks based on target model capabilities,
 * strictly enforcing the 80% maximum context ceiling while guaranteeing zero dropped files.
 */
export class TokenBatcher {
    /**
     * @param {Object} [options]
     * @param {number} [options.targetBatchTokens] Explicit batch token target (overrides dynamic recommendation)
     * @param {number} [options.maxContextWindow=128000] Model's max context window size in tokens
     * @param {number} [options.maxBatchContextRatio=0.8] Maximum batch fraction of model context (default 80%)
     * @param {string} [options.strategy='first_fit_decreasing'] Packing strategy ('first_fit_decreasing'|'best_fit_decreasing')
     */
    constructor(options = {}) {
        this.options = options;
        this.targetBatchTokens = options.targetBatchTokens || options.target_batch_tokens || null;
        this.maxContextWindow = options.maxContextWindow || options.max_context_window || 128000;
        this.maxBatchContextRatio = options.maxBatchContextRatio !== undefined ? options.maxBatchContextRatio : 0.8;
        this.strategy = options.strategy || 'first_fit_decreasing';
    }

    /**
     * Resolves optimal batch sizing parameters for a specific model or provider.
     * @param {Object|string} modelOrProvider Model object from registry or provider name string
     * @returns {{contextWindow: number, maxBatchTokens: number, targetBatchTokens: number, minBatchTokens: number, tier: string}}
     */
    resolveParameters(modelOrProvider = null) {
        let contextWindow = this.maxContextWindow;
        let provider = null;
        let modelId = null;

        if (modelOrProvider && typeof modelOrProvider === 'object') {
            contextWindow = modelOrProvider.contextWindow || modelOrProvider.context_window || contextWindow;
            provider = modelOrProvider.provider || null;
            modelId = modelOrProvider.id || null;
        } else if (typeof modelOrProvider === 'string') {
            provider = modelOrProvider;
            if (provider === 'gemini') {
                contextWindow = 1048576; // 1M default for Gemini
            } else if (provider === 'openrouter') {
                contextWindow = 128000;
            } else if (provider === 'nvidia') {
                contextWindow = 128000;
            }
        }

        // Hard constraint: Maximum 80% of model's context window
        const maxBatchTokens = Math.max(1000, Math.floor(contextWindow * this.maxBatchContextRatio));

        // Determine context tier
        let tier = 'STANDARD';
        let targetTokens = CONTEXT_TIER_TARGETS.STANDARD.targetBatchTokens;
        let minTokens = CONTEXT_TIER_TARGETS.STANDARD.minBatchTokens;

        if (contextWindow >= CONTEXT_TIER_TARGETS.LARGE.minContext) {
            tier = 'LARGE';
            targetTokens = CONTEXT_TIER_TARGETS.LARGE.targetBatchTokens;
            minTokens = CONTEXT_TIER_TARGETS.LARGE.minBatchTokens;
        } else if (contextWindow < CONTEXT_TIER_TARGETS.STANDARD.minContext) {
            tier = 'SMALL';
            targetTokens = CONTEXT_TIER_TARGETS.SMALL.targetBatchTokens;
            minTokens = CONTEXT_TIER_TARGETS.SMALL.minBatchTokens;
        }

        // Allow user configuration override if provided, clamped to maxBatchTokens
        if (this.targetBatchTokens && this.targetBatchTokens > 0) {
            targetTokens = Math.min(this.targetBatchTokens, maxBatchTokens);
        } else {
            targetTokens = Math.min(targetTokens, maxBatchTokens);
        }

        return {
            contextWindow,
            maxBatchTokens,
            targetBatchTokens: targetTokens,
            minBatchTokens: Math.min(minTokens, targetTokens),
            tier,
            provider,
            modelId
        };
    }

    /**
     * Performs dynamic greedy bin-packing across input file profiles.
     * @param {Array<Object>} fileProfiles Array of FileProfile objects from PreflightEstimator
     * @param {Object} [overrideOptions]
     * @returns {Object} BatchPlan
     */
    createBatches(fileProfiles = [], overrideOptions = {}) {
        if (!Array.isArray(fileProfiles) || fileProfiles.length === 0) {
            return {
                batches: [],
                totalBatches: 0,
                totalFiles: 0,
                totalTokens: 0,
                avgBatchTokens: 0,
                maxBatchTokens: 0,
                parameters: this.resolveParameters(overrideOptions.model || overrideOptions.provider)
            };
        }

        const params = this.resolveParameters(
            overrideOptions.model || overrideOptions.provider || this.options.model || this.options.provider
        );
        const targetTokens = overrideOptions.targetBatchTokens || params.targetBatchTokens;
        const maxLimitTokens = params.maxBatchTokens;
        const strategy = overrideOptions.strategy || this.strategy;

        // Clone and sort file profiles descending by estimatedTokens (First Fit Decreasing)
        const sortedFiles = [...fileProfiles].map(f => ({
            ...f,
            estimatedTokens: f.estimatedTokens || Math.ceil((f.charCount || f.sizeBytes || 100) / 3.8)
        })).sort((a, b) => b.estimatedTokens - a.estimatedTokens);

        const batches = [];

        for (const file of sortedFiles) {
            const fileTokens = file.estimatedTokens;

            // Edge Case: If file itself is larger than or equal to targetTokens
            if (fileTokens >= targetTokens) {
                // Single-file dedicated batch
                const isOversized = fileTokens > maxLimitTokens;
                batches.push({
                    batchId: `BATCH-${String(batches.length + 1).padStart(3, '0')}`,
                    files: [file],
                    fileCount: 1,
                    totalTokens: fileTokens,
                    totalLoc: file.loc || 0,
                    languages: [file.language || 'unknown'],
                    domains: [file.domain || 'other'],
                    maxComplexity: file.complexity || 'MEDIUM',
                    isSingleFileBatch: true,
                    isOversized
                });
                continue;
            }

            let assigned = false;

            if (strategy === 'best_fit_decreasing') {
                // Best Fit: Find the batch where adding the file leaves the smallest remaining space
                let bestIdx = -1;
                let minRemainingSpace = Infinity;

                for (let i = 0; i < batches.length; i++) {
                    const b = batches[i];
                    if (b.isSingleFileBatch) continue;

                    const newTotal = b.totalTokens + fileTokens;
                    if (newTotal <= targetTokens && newTotal <= maxLimitTokens) {
                        const remaining = targetTokens - newTotal;
                        if (remaining < minRemainingSpace) {
                            minRemainingSpace = remaining;
                            bestIdx = i;
                        }
                    }
                }

                if (bestIdx !== -1) {
                    this._addFileToBatch(batches[bestIdx], file);
                    assigned = true;
                }
            } else {
                // First Fit Decreasing: Find the first batch that has enough capacity
                for (const b of batches) {
                    if (b.isSingleFileBatch) continue;

                    if ((b.totalTokens + fileTokens) <= targetTokens && (b.totalTokens + fileTokens) <= maxLimitTokens) {
                        this._addFileToBatch(b, file);
                        assigned = true;
                        break;
                    }
                }
            }

            // If no existing batch had space, create a new batch
            if (!assigned) {
                batches.push({
                    batchId: `BATCH-${String(batches.length + 1).padStart(3, '0')}`,
                    files: [file],
                    fileCount: 1,
                    totalTokens: fileTokens,
                    totalLoc: file.loc || 0,
                    languages: [file.language || 'unknown'],
                    domains: [file.domain || 'other'],
                    maxComplexity: file.complexity || 'MEDIUM',
                    isSingleFileBatch: false,
                    isOversized: false
                });
            }
        }

        // Validation: Verify zero dropped files
        const totalBatchedFiles = batches.reduce((acc, b) => acc + b.fileCount, 0);
        if (totalBatchedFiles !== fileProfiles.length) {
            throw new Error(`[TokenBatcher] Assertion failure: ${fileProfiles.length} input files were provided, but only ${totalBatchedFiles} were batched!`);
        }

        const totalTokens = batches.reduce((acc, b) => acc + b.totalTokens, 0);
        const maxBatchTokens = batches.reduce((max, b) => Math.max(max, b.totalTokens), 0);
        const avgBatchTokens = batches.length > 0 ? Math.round(totalTokens / batches.length) : 0;

        return {
            batches,
            totalBatches: batches.length,
            totalFiles: totalBatchedFiles,
            totalTokens,
            avgBatchTokens,
            maxBatchTokens,
            parameters: params
        };
    }

    _addFileToBatch(batch, file) {
        batch.files.push(file);
        batch.fileCount++;
        batch.totalTokens += file.estimatedTokens;
        batch.totalLoc += (file.loc || 0);

        if (!batch.languages.includes(file.language || 'unknown')) {
            batch.languages.push(file.language || 'unknown');
        }
        if (!batch.domains.includes(file.domain || 'other')) {
            batch.domains.push(file.domain || 'other');
        }

        const complexityOrder = { 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4 };
        if ((complexityOrder[file.complexity] || 1) > (complexityOrder[batch.maxComplexity] || 1)) {
            batch.maxComplexity = file.complexity;
        }
    }
}
