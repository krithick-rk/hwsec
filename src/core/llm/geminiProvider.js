import { BaseLLMProvider } from './provider.js';

export class GeminiProvider extends BaseLLMProvider {
    constructor(config = {}) {
        super(config);
        const geminiConfig = config.llm_providers?.gemini || config.llm_providers?.default || {};
        this.apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || geminiConfig.api_key || null;
        this.timeout = geminiConfig.timeout_ms || 60000;
    }

    get name() {
        return 'gemini';
    }

    isAvailable() {
        return !!this.apiKey;
    }

    async generateChat({ model, systemPrompt, userPrompt, jsonSchema = null, temperature = 0.1, maxTokens = 4096, retries = 3 }) {
        if (!this.isAvailable()) {
            throw new Error(`[GeminiProvider] Gemini API key not found. Please set GEMINI_API_KEY or configure llm_providers.gemini.api_key.`);
        }

        const modelName = model || 'gemini-2.5-flash';
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${this.apiKey}`;

        const body = {
            system_instruction: { parts: [{ text: systemPrompt || '' }] },
            contents: [{ parts: [{ text: userPrompt }] }],
            generationConfig: {
                temperature: Math.max(0.0, Math.min(temperature, 1.0)),
                maxOutputTokens: maxTokens
            }
        };

        if (jsonSchema) {
            body.generationConfig.responseMimeType = "application/json";
            body.generationConfig.responseSchema = jsonSchema;
        }

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
                    console.log(`[!] [GeminiProvider] Rate limit hit (429). Retrying in ${delay / 1000}s...`);
                    await new Promise(r => setTimeout(r, delay));
                    continue;
                }

                if (!response.ok) {
                    const errText = await response.text();
                    throw new Error(`Gemini API HTTP ${response.status}: ${errText}`);
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
                    try {
                        json = JSON.parse(text);
                    } catch {
                        const jsonMatch = text.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
                        if (jsonMatch) {
                            try {
                                json = JSON.parse(jsonMatch[1]);
                            } catch {}
                        }
                    }
                }

                return { text, json, usage };
            } catch (err) {
                clearTimeout(timeoutId);
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 2000));
                    continue;
                }
                throw err;
            }
        }
    }
}
