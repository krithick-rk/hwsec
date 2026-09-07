import { BaseLLMProvider } from './provider.js';

export class NvidiaProvider extends BaseLLMProvider {
    constructor(config = {}) {
        super(config);
        const nvidiaConfig = config.llm_providers?.nvidia || {};
        
        // Prioritize NVIDIA_API_KEY environment variable, then config
        this.apiKey = process.env.NVIDIA_API_KEY || nvidiaConfig.api_key || null;
        
        // Base URL configurable via environment variable or config, defaulting to NVIDIA NIM API
        this.baseUrl = (process.env.NVIDIA_BASE_URL || nvidiaConfig.base_url || 'https://integrate.api.nvidia.com/v1').replace(/\/+$/, '');
        this.timeout = nvidiaConfig.timeout_ms || 60000;
    }

    get name() {
        return 'nvidia';
    }

    isAvailable() {
        return !!this.apiKey;
    }

    async generateChat({ model, systemPrompt, userPrompt, jsonSchema = null, temperature = 0.1, maxTokens = 4096, retries = 3 }) {
        if (!this.isAvailable()) {
            throw new Error(`[NvidiaProvider] NVIDIA API key not found. Please set NVIDIA_API_KEY environment variable or configure llm_providers.nvidia.api_key.`);
        }

        const endpoint = `${this.baseUrl}/chat/completions`;
        const messages = [];

        let systemInstruction = systemPrompt || '';
        if (jsonSchema) {
            systemInstruction += `\n\nCRITICAL: You MUST respond ONLY with valid, RFC-8259 compliant JSON matching this schema:\n${JSON.stringify(jsonSchema, null, 2)}`;
        }

        if (systemInstruction) {
            messages.push({ role: 'system', content: systemInstruction });
        }

        messages.push({ role: 'user', content: userPrompt });

        const requestBody = {
            model: model,
            messages: messages,
            temperature: Math.max(0.0, Math.min(temperature, 1.0)),
            max_tokens: maxTokens
        };

        if (jsonSchema) {
            requestBody.response_format = { type: 'json_object' };
        }

        for (let attempt = 1; attempt <= retries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), this.timeout);

            try {
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${this.apiKey}`
                    },
                    body: JSON.stringify(requestBody),
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.status === 429 && attempt < retries) {
                    const delay = attempt * 3000;
                    console.log(`[!] [NvidiaProvider] Rate limit (429) on ${model}. Retrying in ${delay / 1000}s (Attempt ${attempt}/${retries})...`);
                    await new Promise(r => setTimeout(r, delay));
                    continue;
                }

                if (!response.ok) {
                    const errBody = await response.text();
                    throw new Error(`NVIDIA API HTTP ${response.status}: ${errBody}`);
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
                    try {
                        json = JSON.parse(text);
                    } catch {
                        // Extract JSON substring if wrapped in markdown code blocks
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
                if (attempt < retries && (err.name === 'AbortError' || err.message.includes('fetch failed'))) {
                    console.log(`[!] [NvidiaProvider] Network glitch (${err.message}). Retrying (Attempt ${attempt}/${retries})...`);
                    await new Promise(r => setTimeout(r, 2000));
                    continue;
                }
                throw err;
            }
        }
    }
}
