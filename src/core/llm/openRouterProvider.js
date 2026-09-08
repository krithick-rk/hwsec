import { BaseLLMProvider } from './provider.js';

/**
 * OpenRouter provider - OpenAI-compatible API fronting many model families.
 * Docs: https://openrouter.ai/docs
 */
export class OpenRouterProvider extends BaseLLMProvider {
    constructor(config = {}) {
        super(config);
        const orConfig = config.llm_providers?.openrouter || {};
        this.apiKey = process.env.OPENROUTER_API_KEY || orConfig.api_key || null;
        this.baseUrl = (process.env.OPENROUTER_BASE_URL || orConfig.base_url || 'https://openrouter.ai/api/v1').replace(/\/+$/, '');
        this.timeout = orConfig.timeout_ms || 60000;
        this.siteUrl = orConfig.site_url || 'https://hwsec.local';
        this.siteName = orConfig.site_name || 'HWSEC Security Analyzer';
    }

    get name() { return 'openrouter'; }

    isAvailable() { return !!this.apiKey; }

    async generateChat({ model, systemPrompt, userPrompt, jsonSchema = null, temperature = 0.1, maxTokens = 4096, retries = 3 }) {
        if (!this.isAvailable()) {
            throw new Error('[OpenRouterProvider] OPENROUTER_API_KEY not set.');
        }
        const endpoint = this.baseUrl + '/chat/completions';
        const messages = [];
        let systemInstruction = systemPrompt || '';
        if (jsonSchema) {
            systemInstruction += '\n\nCRITICAL: Respond ONLY with valid JSON matching schema:\n' + JSON.stringify(jsonSchema, null, 2);
        }
        if (systemInstruction) messages.push({ role: 'system', content: systemInstruction });
        messages.push({ role: 'user', content: userPrompt });
        const OPENROUTER_ALIASES = {
            'anthropic/claude-3.5-sonnet': 'meta-llama/llama-3.3-70b-instruct',
            'anthropic/claude-3-5-sonnet': 'meta-llama/llama-3.3-70b-instruct',
            'google/gemini-flash-1.5': 'google/gemini-2.5-flash',
            'google/gemini-1.5-flash': 'google/gemini-2.5-flash',
            'google/gemini-1.5-pro': 'google/gemini-2.5-flash'
        };
        const rawModel = model || 'meta-llama/llama-3.3-70b-instruct';
        const effectiveModel = OPENROUTER_ALIASES[rawModel] || rawModel;
        const requestBody = {
            model: effectiveModel,
            messages,
            temperature: Math.max(0.0, Math.min(temperature, 1.0)),
            max_tokens: maxTokens
        };
        if (jsonSchema) requestBody.response_format = { type: 'json_object' };

        for (let attempt = 1; attempt <= retries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);
            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': 'Bearer ' + this.apiKey,
                        'HTTP-Referer': this.siteUrl,
                        'X-Title': this.siteName
                    },
                    body: JSON.stringify(requestBody),
                    signal: controller.signal
                });
                clearTimeout(timeoutId);
                if (response.status === 429 && attempt < retries) {
                    const delay = attempt * 5000;
                    console.log('[!] [OpenRouterProvider] Rate limit. Retrying in ' + (delay/1000) + 's...');
                    await new Promise(r => setTimeout(r, delay));
                    continue;
                }
                if (!response.ok) {
                    const errBody = await response.text();
                    throw new Error('OpenRouter API HTTP ' + response.status + ': ' + errBody);
                }
                const data = await response.json();
                const choice = data.choices?.[0];
                const text = choice?.message?.content || '';
                const usage = {
                    promptTokens: data.usage?.prompt_tokens || 0,
                    completionTokens: data.usage?.completion_tokens || 0,
                    totalTokens: data.usage?.total_tokens || 0
                };
                let json = null;
                if (jsonSchema || text.trim().startsWith('{') || text.trim().startsWith('[')) {
                    try { json = JSON.parse(text); } catch {
                        const m = text.match(/`(?:json)?\s*([\s\S]*?)\s*`/);
                        if (m) { try { json = JSON.parse(m[1]); } catch {} }
                    }
                }
                return { text, json, usage };
            } catch (err) {
                clearTimeout(timeoutId);
                if (attempt < retries && (err.name === 'AbortError' || err.message.includes('fetch failed'))) {
                    await new Promise(r => setTimeout(r, 2000));
                    continue;
                }
                throw err;
            }
        }
    }
}
