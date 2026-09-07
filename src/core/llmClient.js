import { LLMGateway } from './llm/gateway.js';

/**
 * Lightweight LLM Client for HWSEC.
 * Converged behind the unified LLMGateway architecture.
 */
export class LLMClient {
    constructor(config = {}, role = 'default', db = null) {
        this.config = config;
        this.role = role;
        this.gateway = new LLMGateway(config, db, role);
    }

    /**
     * Returns an LLMClient instance configured for a specific role.
     * @param {string} role - e.g. "planner", "worker", "hypothesis_generator", "verifier"
     * @returns {LLMClient}
     */
    forRole(role) {
        const client = new LLMClient(this.config, role, this.gateway.db);
        client.gateway = this.gateway.forRole(role);
        return client;
    }

    isAvailable() {
        return this.gateway.isAvailable();
    }

    /**
     * Sends a prompt with optional JSON schema enforcement.
     * @param {string} systemPrompt 
     * @param {string} userPrompt 
     * @param {Object} [jsonSchema] 
     * @param {Object} [options]
     * @returns {Promise<{text: string, json: any, usage: Object}>}
     */
    async generateContent(systemPrompt, userPrompt, jsonSchema = null, options = {}) {
        const res = await this.gateway.generateContent(systemPrompt, userPrompt, jsonSchema, options);
        return {
            text: res.text,
            json: res.json,
            usage: res.usage
        };
    }
}
