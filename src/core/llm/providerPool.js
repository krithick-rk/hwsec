import { GeminiProvider } from './geminiProvider.js';
import { NvidiaProvider } from './nvidiaProvider.js';
import { OpenRouterProvider } from './openRouterProvider.js';

export const CircuitState = {
    HEALTHY: 'HEALTHY',
    DEGRADED: 'DEGRADED',
    OPEN: 'OPEN',          // Circuit breaker open - requests blocked until cooldown
    HALF_OPEN: 'HALF_OPEN'
};

export const AccountRole = {
    SCOUT: 'scout',                // Gemini Account 1
    CRITIC: 'critic',              // Gemini Account 2
    DEEP_REASONER: 'deep_reasoner',// NVIDIA model pool
    SPECIALIST: 'specialist',      // OpenRouter pool
    FALLBACK: 'fallback'           // OpenRouter fallback
};

/**
 * ProviderPool
 * 
 * Manages discrete LLM provider accounts with independent health tracking,
 * latency profiling, rate-limit handling, circuit breaking, and secret isolation.
 */
export class ProviderPool {
    constructor(config = {}) {
        this.config = config || {};
        this.cooldownPeriodMs = this.config.cooldown_ms || 15000;
        this.failureThreshold = this.config.failure_threshold || 3;

        // Initialize discrete provider endpoints
        this.endpoints = new Map();
        this._initEndpoints();
    }

    _initEndpoints() {
        // 1. Gemini Account 1 (Fast Scout)
        const geminiKey1 = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || this.config.llm_providers?.gemini?.api_key || null;
        this._registerEndpoint('gemini_account_1', {
            providerType: 'gemini',
            role: AccountRole.SCOUT,
            displayName: 'Gemini Account 1 (Fast Scout)',
            preferredModel: 'gemini-2.5-flash',
            provider: new GeminiProvider({
                ...this.config,
                llm_providers: {
                    ...this.config.llm_providers,
                    gemini: { api_key: geminiKey1, api_keys: geminiKey1 ? [geminiKey1] : [] }
                }
            }),
            hasKey: !!geminiKey1
        });

        // 2. Gemini Account 2 (Independent Critic)
        const geminiKey2 = process.env.GEMINI_API_KEY_2 || this.config.llm_providers?.gemini_2?.api_key || null;
        this._registerEndpoint('gemini_account_2', {
            providerType: 'gemini',
            role: AccountRole.CRITIC,
            displayName: 'Gemini Account 2 (Independent Critic)',
            preferredModel: 'gemini-2.5-flash',
            provider: new GeminiProvider({
                ...this.config,
                llm_providers: {
                    ...this.config.llm_providers,
                    gemini: { api_key: geminiKey2, api_keys: geminiKey2 ? [geminiKey2] : [] }
                }
            }),
            hasKey: !!geminiKey2
        });

        // 3. Gemini Account 3 (Scout Redundancy)
        const geminiKey3 = process.env.GEMINI_API_KEY_3 || this.config.llm_providers?.gemini_3?.api_key || null;
        this._registerEndpoint('gemini_account_3', {
            providerType: 'gemini',
            role: AccountRole.SCOUT,
            displayName: 'Gemini Account 3 (Scout Redundancy)',
            preferredModel: 'gemini-2.5-flash',
            provider: new GeminiProvider({
                ...this.config,
                llm_providers: {
                    ...this.config.llm_providers,
                    gemini: { api_key: geminiKey3, api_keys: geminiKey3 ? [geminiKey3] : [] }
                }
            }),
            hasKey: !!geminiKey3
        });

        // 4. NVIDIA (Deep Reasoner / Case Lead)
        const nvidiaKey = process.env.NVIDIA_API_KEY || this.config.llm_providers?.nvidia?.api_key || null;
        this._registerEndpoint('nvidia', {
            providerType: 'nvidia',
            role: AccountRole.DEEP_REASONER,
            displayName: 'NVIDIA NIM Model Pool (Deep Reasoner)',
            preferredModel: 'meta/llama-3.3-70b-instruct',
            provider: new NvidiaProvider({
                ...this.config,
                llm_providers: {
                    ...this.config.llm_providers,
                    nvidia: { api_key: nvidiaKey }
                }
            }),
            hasKey: !!nvidiaKey
        });

        // 5. OpenRouter (Fallback / Specialist Pool)
        const openrouterKey = process.env.OPENROUTER_API_KEY || this.config.llm_providers?.openrouter?.api_key || null;
        this._registerEndpoint('openrouter', {
            providerType: 'openrouter',
            role: AccountRole.SPECIALIST,
            displayName: 'OpenRouter Pool (Fallback/Specialist)',
            preferredModel: 'meta-llama/llama-3.3-70b-instruct',
            provider: new OpenRouterProvider({
                ...this.config,
                llm_providers: {
                    ...this.config.llm_providers,
                    openrouter: { api_key: openrouterKey }
                }
            }),
            hasKey: !!openrouterKey
        });
    }

    _registerEndpoint(id, meta) {
        this.endpoints.set(id, {
            id,
            ...meta,
            state: CircuitState.HEALTHY,
            consecutiveFailures: 0,
            circuitOpenedAt: null,
            forcedUnavailable: false,
            metrics: {
                totalRequests: 0,
                successfulRequests: 0,
                failedRequests: 0,
                rateLimitCount: 0,
                timeoutCount: 0,
                latencyEmaMs: 0,
                lastSuccessTimestamp: null,
                lastFailureTimestamp: null,
                lastErrorReason: null,
                tokens: { prompt: 0, completion: 0, total: 0 },
                estimatedCostUsd: 0.0
            }
        });
    }

    /**
     * Retrieves an endpoint by ID
     * @param {string} endpointId 
     * @returns {Object|null}
     */
    getEndpoint(endpointId) {
        return this.endpoints.get(endpointId) || null;
    }

    /**
     * Checks if a specific endpoint is available and healthy.
     * @param {string} endpointId 
     * @returns {boolean}
     */
    isHealthy(endpointId) {
        const ep = this.endpoints.get(endpointId);
        if (!ep || ep.forcedUnavailable || !ep.hasKey) return false;

        // Check if circuit breaker is OPEN
        if (ep.state === CircuitState.OPEN) {
            const elapsed = Date.now() - (ep.circuitOpenedAt || 0);
            if (elapsed > this.cooldownPeriodMs) {
                // Half-open transition: allow test request
                ep.state = CircuitState.HALF_OPEN;
                return true;
            }
            return false;
        }

        return ep.provider.isAvailable();
    }

    /**
     * Executes a chat request through a specific provider endpoint with full telemetry & circuit breaking.
     * @param {string} endpointId 
     * @param {Object} params 
     * @returns {Promise<{text: string, json: any, usage: Object, endpointId: string, model: string, durationMs: number}>}
     */
    async execute(endpointId, params) {
        const ep = this.endpoints.get(endpointId);
        if (!ep) {
            throw new Error(`[ProviderPool] Unknown endpoint: '${endpointId}'`);
        }

        if (!this.isHealthy(endpointId)) {
            throw new Error(`[ProviderPool] Endpoint '${endpointId}' is currently unavailable or circuit is OPEN (state: ${ep.state})`);
        }

        const startTime = Date.now();
        ep.metrics.totalRequests++;

        try {
            const modelToUse = params.model || ep.preferredModel;
            const res = await ep.provider.generateChat({
                model: modelToUse,
                systemPrompt: params.systemPrompt,
                userPrompt: params.userPrompt,
                jsonSchema: params.jsonSchema,
                temperature: params.temperature ?? 0.1,
                maxTokens: params.maxTokens ?? 4096
            });

            const durationMs = Date.now() - startTime;
            
            // Record Success Metrics
            ep.metrics.successfulRequests++;
            ep.consecutiveFailures = 0;
            ep.state = CircuitState.HEALTHY;
            ep.metrics.lastSuccessTimestamp = new Date().toISOString();
            
            // Update Latency EMA
            if (ep.metrics.latencyEmaMs === 0) {
                ep.metrics.latencyEmaMs = durationMs;
            } else {
                ep.metrics.latencyEmaMs = Math.round((ep.metrics.latencyEmaMs * 0.7) + (durationMs * 0.3));
            }

            // Update Token & Cost Accounting
            const usage = res.usage || { promptTokens: 0, completionTokens: 0, totalTokens: 0 };
            ep.metrics.tokens.prompt += (usage.promptTokens || 0);
            ep.metrics.tokens.completion += (usage.completionTokens || 0);
            ep.metrics.tokens.total += (usage.totalTokens || 0);

            return {
                text: res.text,
                json: res.json,
                usage,
                endpointId,
                model: modelToUse,
                durationMs
            };

        } catch (err) {
            const durationMs = Date.now() - startTime;
            ep.metrics.failedRequests++;
            ep.consecutiveFailures++;
            ep.metrics.lastFailureTimestamp = new Date().toISOString();
            ep.metrics.lastErrorReason = err.message;

            if (err.message.includes('429') || err.message.toLowerCase().includes('rate limit')) {
                ep.metrics.rateLimitCount++;
            }
            if (err.name === 'AbortError' || err.message.toLowerCase().includes('timeout')) {
                ep.metrics.timeoutCount++;
            }

            // Trip circuit breaker if consecutive failure threshold exceeded
            if (ep.consecutiveFailures >= this.failureThreshold) {
                ep.state = CircuitState.OPEN;
                ep.circuitOpenedAt = Date.now();
            } else {
                ep.state = CircuitState.DEGRADED;
            }

            throw err;
        }
    }

    /**
     * For testing/adversarial simulation: Override an endpoint's availability or state.
     */
    setEndpointAvailability(endpointId, available) {
        const ep = this.endpoints.get(endpointId);
        if (ep) {
            ep.forcedUnavailable = !available;
            if (!available) {
                ep.state = CircuitState.OPEN;
                ep.circuitOpenedAt = Date.now();
            } else {
                ep.state = CircuitState.HEALTHY;
                ep.consecutiveFailures = 0;
            }
        }
    }

    /**
     * Resolves user-supplied alias to canonical internal endpoint ID.
     * @param {string} alias 
     * @returns {string|null}
     */
    resolveEndpointId(alias) {
        if (!alias) return null;
        const norm = String(alias).trim().toLowerCase().replace(/_/g, '-');
        const map = {
            'gemini-1': 'gemini_account_1',
            'gemini1': 'gemini_account_1',
            'gemini_account_1': 'gemini_account_1',
            'gemini-2': 'gemini_account_2',
            'gemini2': 'gemini_account_2',
            'gemini_account_2': 'gemini_account_2',
            'gemini-3': 'gemini_account_3',
            'gemini3': 'gemini_account_3',
            'gemini_account_3': 'gemini_account_3',
            'nvidia': 'nvidia',
            'openrouter': 'openrouter'
        };
        return map[norm] || (this.endpoints.has(alias) ? alias : null);
    }

    /**
     * Updates key for a specific endpoint dynamically without printing secrets.
     */
    updateKey(alias, apiKey) {
        const id = this.resolveEndpointId(alias);
        const ep = this.endpoints.get(id);
        if (!ep) throw new Error(`Unknown provider endpoint: '${alias}'`);

        const cleanKey = apiKey && apiKey.trim() ? apiKey.trim() : null;
        ep.hasKey = !!cleanKey;

        if (ep.providerType === 'gemini') {
            ep.provider = new GeminiProvider({
                ...this.config,
                llm_providers: { gemini: { api_key: cleanKey, api_keys: cleanKey ? [cleanKey] : [] } }
            });
        } else if (ep.providerType === 'nvidia') {
            ep.provider = new NvidiaProvider({
                ...this.config,
                llm_providers: { nvidia: { api_key: cleanKey } }
            });
        } else if (ep.providerType === 'openrouter') {
            ep.provider = new OpenRouterProvider({
                ...this.config,
                llm_providers: { openrouter: { api_key: cleanKey } }
            });
        }

        if (cleanKey) {
            ep.forcedUnavailable = false;
            ep.state = CircuitState.HEALTHY;
            ep.consecutiveFailures = 0;
        } else {
            ep.forcedUnavailable = true;
            ep.state = CircuitState.OPEN;
        }
        return ep;
    }

    /**
     * Disables or enables an endpoint explicitly.
     */
    setDisabled(alias, disabled) {
        const id = this.resolveEndpointId(alias);
        const ep = this.endpoints.get(id);
        if (!ep) throw new Error(`Unknown provider endpoint: '${alias}'`);

        ep.forcedUnavailable = !!disabled;
        if (disabled) {
            ep.state = CircuitState.OPEN;
        } else if (ep.hasKey) {
            ep.state = CircuitState.HEALTHY;
            ep.consecutiveFailures = 0;
        }
        return ep;
    }

    /**
     * Tests a specific provider endpoint safely.
     */
    async testEndpoint(alias) {
        const id = this.resolveEndpointId(alias);
        const ep = this.endpoints.get(id);
        if (!ep) throw new Error(`Unknown provider endpoint: '${alias}'`);
        if (!ep.hasKey || ep.forcedUnavailable) {
            return { id, healthy: false, state: ep.forcedUnavailable ? 'DISABLED' : 'NOT_CONFIGURED', reason: 'NO_KEY_OR_DISABLED' };
        }
        try {
            const avail = ep.provider.isAvailable();
            if (!avail) {
                return { id, healthy: false, state: ep.state, reason: 'PROVIDER_UNAVAILABLE' };
            }
            return { id, healthy: true, state: ep.state, model: ep.preferredModel };
        } catch (err) {
            return { id, healthy: false, state: ep.state, reason: err.message };
        }
    }

    /**
     * Returns sanitized health & telemetry report for all endpoints (no API keys).
     */
    getPoolStatus() {
        const status = {};
        for (const [id, ep] of this.endpoints.entries()) {
            status[id] = {
                displayName: ep.displayName,
                role: ep.role,
                configured: ep.hasKey,
                healthy: this.isHealthy(id),
                circuitState: ep.forcedUnavailable ? 'DISABLED' : ep.state,
                metrics: { ...ep.metrics }
            };
        }
        return status;
    }
}

