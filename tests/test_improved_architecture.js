/**
 * Tests for Improved Architecture components:
 *   1. OpenRouterProvider - basic instantiation, isAvailable(), structure
 *   2. GeminiProvider multi-key pool - key rotation, pool construction
 *   3. AdaptiveEscalation - determineEscalationLevel(), buildEscalationPlan()
 *   4. ModelRegistry - OpenRouter models registered
 *   5. LLMGateway - OpenRouter in providers map, 3-provider isAvailable
 */

import assert from 'assert';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log('[PASS] ' + name);
        passed++;
    } catch (err) {
        console.error('[FAIL] ' + name + ': ' + err.message);
        failed++;
    }
}

async function testAsync(name, fn) {
    try {
        await fn();
        console.log('[PASS] ' + name);
        passed++;
    } catch (err) {
        console.error('[FAIL] ' + name + ': ' + err.message);
        failed++;
    }
}

// ========== 1. OpenRouterProvider ==========
const { OpenRouterProvider } = await import('../src/core/llm/openRouterProvider.js');

test('OpenRouterProvider: instantiates without credentials', () => {
    const or = new OpenRouterProvider({});
    assert.strictEqual(or.name, 'openrouter');
    assert.strictEqual(or.isAvailable(), false); // no key in CI
    assert.ok(typeof or.generateChat === 'function');
});

test('OpenRouterProvider: reads OPENROUTER_API_KEY env var', () => {
    const orig = process.env.OPENROUTER_API_KEY;
    process.env.OPENROUTER_API_KEY = 'test-key-abc';
    const or = new OpenRouterProvider({});
    assert.strictEqual(or.isAvailable(), true);
    assert.strictEqual(or.apiKey, 'test-key-abc');
    if (orig) process.env.OPENROUTER_API_KEY = orig;
    else delete process.env.OPENROUTER_API_KEY;
});

test('OpenRouterProvider: config api_key fallback', () => {
    delete process.env.OPENROUTER_API_KEY;
    const or = new OpenRouterProvider({ llm_providers: { openrouter: { api_key: 'config-key' } } });
    assert.strictEqual(or.isAvailable(), true);
});

// ========== 2. GeminiProvider multi-key pool ==========
const { GeminiProvider } = await import('../src/core/llm/geminiProvider.js');

test('GeminiProvider: single key from env', () => {
    const orig1 = process.env.GEMINI_API_KEY;
    const orig2 = process.env.GEMINI_API_KEY_2;
    process.env.GEMINI_API_KEY = 'key-primary';
    delete process.env.GEMINI_API_KEY_2;
    const gp = new GeminiProvider({});
    assert.strictEqual(gp._keyPool.length, 1);
    assert.strictEqual(gp.isAvailable(), true);
    assert.strictEqual(gp._nextKey(), 'key-primary');
    if (orig1) process.env.GEMINI_API_KEY = orig1; else delete process.env.GEMINI_API_KEY;
    if (orig2) process.env.GEMINI_API_KEY_2 = orig2;
});

test('GeminiProvider: multi-key pool from env (GEMINI_API_KEY + GEMINI_API_KEY_2)', () => {
    const orig1 = process.env.GEMINI_API_KEY;
    const orig2 = process.env.GEMINI_API_KEY_2;
    process.env.GEMINI_API_KEY = 'key-A';
    process.env.GEMINI_API_KEY_2 = 'key-B';
    const gp = new GeminiProvider({});
    assert.strictEqual(gp._keyPool.length, 2);
    assert.strictEqual(gp._keyPool[0], 'key-A');
    assert.strictEqual(gp._keyPool[1], 'key-B');
    // Round-robin rotation
    const k1 = gp._nextKey();
    const k2 = gp._nextKey();
    const k3 = gp._nextKey();
    assert.strictEqual(k1, 'key-A');
    assert.strictEqual(k2, 'key-B');
    assert.strictEqual(k3, 'key-A'); // wraps around
    if (orig1) process.env.GEMINI_API_KEY = orig1; else delete process.env.GEMINI_API_KEY;
    if (orig2) process.env.GEMINI_API_KEY_2 = orig2; else delete process.env.GEMINI_API_KEY_2;
});

test('GeminiProvider: no keys -> isAvailable() false', () => {
    const orig1 = process.env.GEMINI_API_KEY;
    const orig2 = process.env.GOOGLE_API_KEY;
    delete process.env.GEMINI_API_KEY;
    delete process.env.GOOGLE_API_KEY;
    const gp = new GeminiProvider({});
    assert.strictEqual(gp.isAvailable(), false);
    if (orig1) process.env.GEMINI_API_KEY = orig1;
    if (orig2) process.env.GOOGLE_API_KEY = orig2;
});

// ========== 3. Adaptive Escalation ==========
const { determineEscalationLevel, buildEscalationPlan, EscalationLevel } = await import('../src/core/escalation/adaptiveEscalation.js');

test('AdaptiveEscalation: low suspicion -> BASELINE', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.10 });
    assert.strictEqual(r.level, EscalationLevel.BASELINE);
    assert.strictEqual(r.label, 'BASELINE');
});

test('AdaptiveEscalation: mid suspicion (0.35) -> GRAPH_REACHABILITY', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.35 });
    assert.strictEqual(r.level, EscalationLevel.GRAPH_REACHABILITY);
});

test('AdaptiveEscalation: high suspicion (0.70) -> TARGETED_DYNAMIC_FORMAL', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.70 });
    assert.strictEqual(r.level, EscalationLevel.TARGETED_DYNAMIC_FORMAL);
});

test('AdaptiveEscalation: budget >= 1.0 forces BASELINE', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.95, budgetRatio: 1.0 });
    assert.strictEqual(r.level, EscalationLevel.BASELINE);
    assert.ok(r.rationale.some(s => s.includes('Budget exhausted')));
});

test('AdaptiveEscalation: budget >= 0.90 caps at GRAPH_REACHABILITY', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.95, budgetRatio: 0.92 });
    assert.ok(r.level <= EscalationLevel.GRAPH_REACHABILITY);
});

test('AdaptiveEscalation: noveltyMode=off caps at GRAPH_REACHABILITY', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.90, noveltyMode: 'off' });
    assert.ok(r.level <= EscalationLevel.GRAPH_REACHABILITY);
});

test('AdaptiveEscalation: noveltyMode=minimal caps at SEMANTIC_REASONING when high suspicion', () => {
    const r = determineEscalationLevel({ suspicionScore: 0.90, noveltyMode: 'minimal' });
    assert.ok(r.level <= EscalationLevel.SEMANTIC_REASONING);
});

test('AdaptiveEscalation: disagreement boosts level', () => {
    const withoutDisagreement = determineEscalationLevel({ suspicionScore: 0.22, hasDisagreement: false });
    const withDisagreement = determineEscalationLevel({ suspicionScore: 0.22, hasDisagreement: true });
    assert.ok(withDisagreement.level >= withoutDisagreement.level);
});

test('AdaptiveEscalation: coverage gap boosts level', () => {
    const withoutGap = determineEscalationLevel({ suspicionScore: 0.12, hasCoverageGap: false });
    const withGap = determineEscalationLevel({ suspicionScore: 0.12, hasCoverageGap: true });
    assert.ok(withGap.level >= withoutGap.level);
});

test('AdaptiveEscalation: buildEscalationPlan returns plan for each target', () => {
    const targets = [
        { path: 'a.c', suspicion_score: 0.10, signals: {} },
        { path: 'b.c', suspicion_score: 0.60, signals: { analyzer_disagreement: { hasDisagreement: true } } },
        { path: 'c.c', suspicion_score: 0.85, signals: {} }
    ];
    const plan = buildEscalationPlan(targets, { budgetRatio: 0.3, noveltyMode: 'standard' });
    assert.strictEqual(plan.length, 3);
    assert.ok(plan[0].level <= plan[2].level); // lower suspicion gets lower or equal level
    plan.forEach(p => {
        assert.ok(typeof p.level === 'number');
        assert.ok(typeof p.label === 'string');
        assert.ok(Array.isArray(p.rationale));
    });
});

// ========== 4. ModelRegistry: OpenRouter models registered ==========
const { ModelRegistry } = await import('../src/core/llm/modelRegistry.js');

test('ModelRegistry: OpenRouter models are registered by default', () => {
    const registry = new ModelRegistry({});
    const orModels = registry.getEnabledModels('openrouter');
    assert.ok(orModels.length >= 3, 'Expected at least 3 OpenRouter models, got ' + orModels.length);
    const ids = orModels.map(m => m.id);
    assert.ok(ids.includes('meta-llama/llama-3.3-70b-instruct'));
    assert.ok(ids.includes('anthropic/claude-3.5-sonnet'));
});

test('ModelRegistry: findBestModel can route to openrouter', () => {
    const registry = new ModelRegistry({});
    const model = registry.findBestModel({ provider: 'openrouter', requiresReasoning: true });
    assert.ok(model !== null, 'Should find a model for openrouter');
    assert.strictEqual(model.provider, 'openrouter');
});

// ========== 5. LLMGateway: OpenRouter in providers ==========
const { LLMGateway } = await import('../src/core/llm/gateway.js');

test('LLMGateway: openrouter provider exists in router', () => {
    const gw = new LLMGateway({});
    assert.ok(gw.router.providers.openrouter !== undefined, 'OpenRouter provider should be registered');
    assert.strictEqual(gw.router.providers.openrouter.name, 'openrouter');
});

test('LLMGateway: isAvailable() returns true if openrouter key is set', () => {
    const orig = process.env.OPENROUTER_API_KEY;
    process.env.OPENROUTER_API_KEY = 'test-key';
    delete process.env.NVIDIA_API_KEY;
    delete process.env.GEMINI_API_KEY;
    const gw = new LLMGateway({});
    assert.strictEqual(gw.isAvailable(), true);
    if (orig) process.env.OPENROUTER_API_KEY = orig; else delete process.env.OPENROUTER_API_KEY;
});

// ========== Summary ==========
console.log('\n--- Improved Architecture Tests Summary ---');
console.log('PASSED: ' + passed + ', FAILED: ' + failed);
if (failed > 0) process.exit(1);
