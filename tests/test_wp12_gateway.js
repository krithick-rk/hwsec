import assert from 'assert';
import { LLMGateway } from '../src/core/llm/gateway.js';
import { LLMClient } from '../src/core/llmClient.js';
import { loadConfig, sanitizeConfig } from '../src/core/config.js';
import { TaskTypes } from '../src/core/llm/taskTypes.js';

console.log("=== Running WP12: Unified LLM Gateway & Credential Hardening Tests ===");

// 1. Test Credential Redaction & Sanitization
console.log("[Test 1] Testing Credential Redaction & Sanitization...");
const rawConfig = {
    llm_providers: {
        nvidia: { api_key: "secret-key-12345", base_url: "https://example.com" },
        gemini: { api_key: "gemini-secret-67890" }
    },
    some_secret: "hidden_token"
};
const sanitized = sanitizeConfig(rawConfig);
assert.strictEqual(sanitized.llm_providers.nvidia.api_key, "[REDACTED]", "Nvidia API key must be redacted");
assert.strictEqual(sanitized.llm_providers.gemini.api_key, "[REDACTED]", "Gemini API key must be redacted");
assert.strictEqual(sanitized.some_secret, "[REDACTED]", "Generic secret field must be redacted");
assert.strictEqual(sanitized.llm_providers.nvidia.base_url, "https://example.com", "Non-secret fields must be preserved");
console.log("  -> Credential redaction passed.");

// 2. Test LLMGateway Initialization & Role Binding
console.log("[Test 2] Testing LLMGateway Initialization & Role Binding...");
const mockConfig = {
    token_budgets: { max_cost_usd: 5.0 },
    llm_providers: {
        nvidia: { api_key: "test_key", base_url: "https://mock.nvidia.com" }
    }
};

const gateway = new LLMGateway(mockConfig);
assert.strictEqual(typeof gateway.execute, 'function', "Gateway must have execute method");
assert.strictEqual(typeof gateway.generateContent, 'function', "Gateway must have generateContent method");

const verifierGateway = gateway.forRole('verifier');
assert.strictEqual(verifierGateway.role, 'verifier', "Role binding must preserve role");
assert.strictEqual(verifierGateway.router, gateway.router, "Role binding must share underlying router");
console.log("  -> Gateway initialization and role binding passed.");

// 3. Test LLMClient Delegation to Gateway
console.log("[Test 3] Testing LLMClient Delegation to LLMGateway...");
const legacyClient = new LLMClient(mockConfig, 'hypothesis_generator');
assert.strictEqual(typeof legacyClient.generateContent, 'function', "LLMClient must preserve generateContent");
assert.strictEqual(typeof legacyClient.forRole, 'function', "LLMClient must preserve forRole");
const childClient = legacyClient.forRole('planner');
assert.strictEqual(childClient.role, 'planner', "LLMClient forRole must update role");
console.log("  -> LLMClient delegation passed.");

// 4. Test Budget Enforcement through Gateway
console.log("[Test 4] Testing Budget Enforcement Rejection through Gateway...");
// Exceed budget
gateway.router.budgetController.totalCostUsd = 6.0;
let rejected = false;
try {
    await gateway.execute({
        taskType: TaskTypes.NOVELTY_ANALYSIS,
        systemPrompt: "test",
        userPrompt: "test"
    });
} catch (err) {
    rejected = true;
    assert.ok(err.message.includes('Budget policy rejected'), "Error must cite budget rejection");
}
assert.ok(rejected, "Discretionary task must be rejected when budget exceeded");
console.log("  -> Budget rejection passed.");

console.log("\n[PASS] All WP12 Unified LLM Gateway tests passed successfully!\n");
