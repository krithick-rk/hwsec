import assert from 'assert';
import { ProviderPool } from './src/core/llm/providerPool.js';
import { DiagnosticsFacade } from './src/core/console/diagnostics.js';

console.log('[*] Testing Provider Management & Secret Isolation...');

// 1. Initialize Pool & test 3 Gemini accounts + NVIDIA + OpenRouter
const pool = new ProviderPool();
const status = pool.getPoolStatus();

assert.ok(status.gemini_account_1, 'gemini_account_1 registered');
assert.ok(status.gemini_account_2, 'gemini_account_2 registered');
assert.ok(status.gemini_account_3, 'gemini_account_3 registered');
assert.ok(status.nvidia, 'nvidia registered');
assert.ok(status.openrouter, 'openrouter registered');

console.log('[+] ProviderPool endpoints initialized successfully (5 endpoints).');

// 2. Alias resolution
assert.strictEqual(pool.resolveEndpointId('gemini-1'), 'gemini_account_1');
assert.strictEqual(pool.resolveEndpointId('gemini-2'), 'gemini_account_2');
assert.strictEqual(pool.resolveEndpointId('gemini-3'), 'gemini_account_3');
assert.strictEqual(pool.resolveEndpointId('nvidia'), 'nvidia');
assert.strictEqual(pool.resolveEndpointId('openrouter'), 'openrouter');
console.log('[+] Endpoint alias resolution working correctly.');

// 3. Dynamic Key update & secret isolation
pool.updateKey('gemini-3', 'test-secret-key-12345');
const ep3 = pool.getEndpoint('gemini_account_3');
assert.strictEqual(ep3.hasKey, true);
assert.strictEqual(ep3.forcedUnavailable, false);

// Check that getPoolStatus does NOT expose raw key string
const poolStatus = pool.getPoolStatus();
const poolStatusStr = JSON.stringify(poolStatus);
assert.strictEqual(poolStatusStr.includes('test-secret-key-12345'), false, 'Raw key must not leak in pool status output');
console.log('[+] Dynamic key update & secret isolation verified.');

// 4. Disable and Enable
pool.setDisabled('gemini-3', true);
assert.strictEqual(pool.isHealthy('gemini_account_3'), false);
const statusDisabled = pool.getPoolStatus();
assert.strictEqual(statusDisabled.gemini_account_3.circuitState, 'DISABLED');

pool.setDisabled('gemini-3', false);
assert.strictEqual(pool.isHealthy('gemini_account_3'), true);
console.log('[+] Disable / Enable operations verified.');

// 5. Remove key
pool.updateKey('gemini-3', null);
assert.strictEqual(pool.getEndpoint('gemini_account_3').hasKey, false);
console.log('[+] Remove key verified.');

// 6. DiagnosticsFacade formatProviders output
const diag = new DiagnosticsFacade({}, pool);
const formatted = await diag.formatProviders();
assert.ok(formatted.includes('Gemini-1'), 'Contains Gemini-1');
assert.ok(formatted.includes('Gemini-2'), 'Contains Gemini-2');
assert.ok(formatted.includes('Gemini-3'), 'Contains Gemini-3');
assert.ok(formatted.includes('NVIDIA'), 'Contains NVIDIA');
assert.ok(formatted.includes('OpenRouter'), 'Contains OpenRouter');
assert.strictEqual(formatted.includes('test-secret-key'), false, 'No secret in formatted output');
console.log('[+] DiagnosticsFacade provider formatting verified:\n');
console.log(formatted);
console.log('\n[=== ALL PROVIDER MANAGEMENT TESTS PASSED ===]');
