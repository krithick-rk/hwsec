import { BaseLLMProvider } from './provider.js';

/**
 * Gemini provider with multi-key credential pool.
 * Reads GEMINI_API_KEY (primary) and GEMINI_API_KEY_2..N for failover.
 * Keys are rotated round-robin; on 429 or auth error the next key is tried.
 */
export class GeminiProvider extends BaseLLMProvider {
    constructor(config = {}) {
        super(config);
        const geminiConfig = config.llm_providers?.gemini || config.llm_providers?.default || {};

        // Build key pool: env vars GEMINI_API_KEY, GEMINI_API_KEY_2, ... then config
        this._keyPool = [];
        const primaryKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || geminiConfig.api_key || null;
        if (primaryKey) this._keyPool.push(primaryKey);

        // Additional keys from env: GEMINI_API_KEY_2, GEMINI_API_KEY_3, ...
        for (let i = 2; i <= 9; i++) {
            const extra = process.env['GEMINI_API_KEY_' + i];
            if (extra) this._keyPool.push(extra);
        }

        // Keys from config array
        if (Array.isArray(geminiConfig.api_keys)) {
            for (const k of geminiConfig.api_keys) {
                if (k && !this._keyPool.includes(k)) this._keyPool.push(k);
            }
        }

        this._keyIndex = 0;
        this.timeout = geminiConfig.timeout_ms || 60000;
    }

    get name() { return 'gemini'; }

    // Backward compat: expose single key for legacy callers
    get apiKey() { return this._keyPool[0] || null; }

    isAvailable() { return this._keyPool.length > 0; }

    _nextKey() {
        if (this._keyPool.length === 0) return null;
        const key = this._keyPool[this._keyIndex % this._keyPool.length];
        this._keyIndex = (this._keyIndex + 1) % this._keyPool.length;
        return key;
    }

    async generateChat({ model, systemPrompt, userPrompt, jsonSchema = null, temperature = 0.1, maxTokens = 4096, retries = 3 }) {
        if (!this.isAvailable()) {
            throw new Error('[GeminiProvider] No Gemini API keys configured. Set GEMINI_API_KEY.');
        }

        const MODEL_ALIASES = {
            'gemini-1.5-flash': 'gemini-2.5-flash',
            'gemini-1.5-pro': 'gemini-2.5-flash',
            'gemini-2.5-pro': 'gemini-2.5-flash',
            'gemini-pro': 'gemini-2.5-flash',
            'gemini-flash': 'gemini-2.5-flash'
        };
        const rawModel = model || 'gemini-2.5-flash';
        const modelName = MODEL_ALIASES[rawModel] || rawModel;

        const body = {
            system_instruction: { parts: [{ text: systemPrompt || '' }] },
            contents: [{ parts: [{ text: userPrompt }] }],
            generationConfig: {
                temperature: Math.max(0.0, Math.min(temperature, 1.0)),
                maxOutputTokens: maxTokens
            }
        };

        if (jsonSchema) {
            body.generationConfig.responseMimeType = 'application/json';
            body.generationConfig.responseSchema = jsonSchema;
        }

        let lastErr;
        // Outer loop: one full retry pass per key in pool (round-robin on 429/auth failure)
        for (let keyAttempt = 0; keyAttempt < this._keyPool.length; keyAttempt++) {
            const apiKey = this._nextKey();
            const url = 'https://generativelanguage.googleapis.com/v1beta/models/' + modelName + ':generateContent?key=' + apiKey;

            for (let attempt = 1; attempt <= retries; attempt++) {
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), this.timeout);

                try {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                        signal: controller.signal
                    });

                    clearTimeout(timeoutId);

                    if (response.status === 429 && attempt < retries) {
                        const delay = attempt * 5000;
                        console.log('[!] [GeminiProvider] Rate limit on key ' + (keyAttempt + 1) + '. Retrying in ' + (delay/1000) + 's...');
                        await new Promise(r => setTimeout(r, delay));
                        continue;
                    }

                    // 401/403: rotate to next key immediately
                    if ((response.status === 401 || response.status === 403) && keyAttempt < this._keyPool.length - 1) {
                        console.log('[!] [GeminiProvider] Auth error on key ' + (keyAttempt + 1) + ' - rotating to next key.');
                        lastErr = new Error('Gemini auth error on key ' + (keyAttempt + 1) + ': HTTP ' + response.status);
                        break; // break inner to rotate key
                    }

                    if (!response.ok) {
                        const errText = await response.text();
                        throw new Error('Gemini API HTTP ' + response.status + ': ' + errText);
                    }

                    const data = await response.json();
                    const candidate = data.candidates?.[0];
                    const text = candidate?.content?.parts?.[0]?.text || '';
                    const usage = {
                        promptTokens: data.usageMetadata?.promptTokenCount || 0,
                        completionTokens: data.usageMetadata?.candidatesTokenCount || 0,
                        totalTokens: data.usageMetadata?.totalTokenCount || 0
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
                    lastErr = err;
                    if (attempt < retries) {
                        await new Promise(r => setTimeout(r, 2000));
                        continue;
                    }
                }
            }
        }

        throw lastErr || new Error('[GeminiProvider] All keys and retries exhausted.');
    }
}
