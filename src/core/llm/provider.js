/**
 * Abstract Base Class for LLM Providers
 */
export class BaseLLMProvider {
    constructor(config = {}) {
        this.config = config;
    }

    get name() {
        throw new Error("Must implement provider 'name' getter");
    }

    /**
     * Checks if this provider has credentials/configuration to operate.
     * @returns {boolean}
     */
    isAvailable() {
        throw new Error("Must implement isAvailable()");
    }

    /**
     * Executes a chat completion request with structured output support.
     * @param {Object} params
     * @param {string} params.model
     * @param {string} params.systemPrompt
     * @param {string} params.userPrompt
     * @param {Object} [params.jsonSchema]
     * @param {number} [params.temperature=0.1]
     * @param {number} [params.maxTokens=4096]
     * @returns {Promise<{text: string, json: any, usage: {promptTokens: number, completionTokens: number, totalTokens: number}}>}
     */
    async generateChat(params) {
        throw new Error("Must implement generateChat()");
    }
}
