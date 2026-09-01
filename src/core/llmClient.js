/**
 * Lightweight LLM Client for HWSEC
 */
export class LLMClient {
    constructor(config, role = 'default') {
        this.config = config || {};
        this.role = role;

        // Resolve model and provider for this specific role or fallback to default
        const roleConfig = this.config.models?.[role];
        const defaultProvider = this.config.llm_providers?.default || {};
        
        if (roleConfig) {
            this.provider = roleConfig.provider || 'gemini';
            this.model = roleConfig.model || 'gemini-3.6-flash';
            this.apiKey = roleConfig.api_key || this.config.llm_providers?.[this.provider]?.api_key || defaultProvider.api_key || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
        } else {
            this.provider = defaultProvider.provider || 'gemini';
            this.apiKey = defaultProvider.api_key || process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY;
            this.model = defaultProvider.model || 'gemini-3.6-flash';
        }
    }

    /**
     * Returns an LLMClient instance configured for a specific role.
     * @param {string} role - e.g. "planner", "worker", "hypothesis_generator", "verifier"
     * @returns {LLMClient}
     */
    forRole(role) {
        return new LLMClient(this.config, role);
    }

    isAvailable() {
        return !!this.apiKey;
    }

    /**
     * Sends a prompt with optional JSON schema enforcement.
     * @param {string} systemPrompt 
     * @param {string} userPrompt 
     * @param {Object} [jsonSchema] 
     * @returns {Promise<{text: string, json: any, usage: Object}>}
     */
    async generateContent(systemPrompt, userPrompt, jsonSchema = null) {
        if (!this.isAvailable()) {
            throw new Error(`LLM provider for role '${this.role}' is not configured or missing API key.`);
        }

        if (this.provider === 'gemini') {
            return this._callGemini(systemPrompt, userPrompt, jsonSchema);
        }

        throw new Error(`Unsupported LLM provider: ${this.provider}`);
    }

    async _callGemini(systemPrompt, userPrompt, jsonSchema, retries = 3) {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/${this.model}:generateContent?key=${this.apiKey}`;
        
        const body = {
            system_instruction: {
                parts: [{ text: systemPrompt }]
            },
            contents: [
                {
                    parts: [{ text: userPrompt }]
                }
            ],
            generationConfig: {
                temperature: 0.1 // Low temperature for deterministic/strict extraction
            }
        };

        if (jsonSchema) {
            body.generationConfig.responseMimeType = "application/json";
            body.generationConfig.responseSchema = jsonSchema;
        }

        for (let attempt = 1; attempt <= retries; attempt++) {
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });

                if (response.status === 429 && attempt < retries) {
                    console.log(`[!] [LLMClient] Rate limit hit (429). Retrying in 10s (Attempt ${attempt}/${retries})...`);
                    await new Promise(r => setTimeout(r, 10000));
                    continue;
                }

                if (!response.ok) {
                    const errText = await response.text();
                    throw new Error(`Gemini API error (${response.status}): ${errText}`);
                }

                const data = await response.json();
                const candidate = data.candidates?.[0];
                const text = candidate?.content?.parts?.[0]?.text || '';
                const usage = data.usageMetadata || {};

                let json = null;
                if (jsonSchema || text.trim().startsWith('{') || text.trim().startsWith('[')) {
                    try {
                        json = JSON.parse(text);
                    } catch {
                        // If parsing fails, leave json as null
                    }
                }

                return { text, json, usage };
            } catch (err) {
                if (attempt < retries) {
                    console.log(`[!] [LLMClient] Network error (${err.message}). Retrying in 5s (Attempt ${attempt}/${retries})...`);
                    await new Promise(r => setTimeout(r, 5000));
                    continue;
                }
                throw err;
            }
        }
    }
}
