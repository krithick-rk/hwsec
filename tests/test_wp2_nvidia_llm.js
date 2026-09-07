import assert from 'assert';
import { ModelRegistry } from '../src/core/llm/modelRegistry.js';
import { ModelRouter } from '../src/core/llm/modelRouter.js';
import { BudgetController } from '../src/core/llm/budgetController.js';
import { TaskTypes } from '../src/core/llm/taskTypes.js';

console.log('=== Running WP2: NVIDIA LLM Architecture & Routing Tests ===');

// Test 1: Model Capability Registry
console.log('[Test 1] Testing Model Capability Registry...');
const registry = new ModelRegistry({
    models: {
        'custom/sec-model': {
            provider: 'nvidia',
            contextWindow: 65536,
            capabilities: { reasoning: 0.99, coding: 0.95 }
        }
    }
});

const defaultNvidia = registry.getModel('meta/llama-3.3-70b-instruct');
assert.ok(defaultNvidia);
assert.strictEqual(defaultNvidia.provider, 'nvidia');
assert.strictEqual(defaultNvidia.capabilities.toolUse, true);

const customModel = registry.getModel('custom/sec-model');
assert.ok(customModel);
assert.strictEqual(customModel.capabilities.reasoning, 0.99);

const bestCoder = registry.findBestModel({ requiresCode: true });
assert.ok(bestCoder);
console.log(`  -> Best coding model resolved: ${bestCoder.id}`);

// Test 2: Task-based routing selection
console.log('[Test 2] Testing Task-Based Router Model Selection...');
const router = new ModelRouter({});
const verifyModel = router.routeTask(TaskTypes.VERIFICATION);
assert.ok(verifyModel);
assert.ok(verifyModel.capabilities.reasoning >= 0.85);

const summaryModel = router.routeTask(TaskTypes.REPOSITORY_SUMMARY);
assert.ok(summaryModel);
console.log(`  -> Task routing passed: VERIFICATION -> ${verifyModel.id}, SUMMARY -> ${summaryModel.id}`);

// Test 3: Global Token & Cost Budget Enforcement
console.log('[Test 3] Testing Budget Controller & Threshold Policies...');
const budget = new BudgetController({
    token_budgets: {
        max_cost_usd: 1.0, // $1.00 max budget for test
        max_tokens: 1000000
    }
});

// Initial state: normal (<80%)
assert.strictEqual(budget.canExecute(TaskTypes.NOVELTY_ANALYSIS).allowed, true);
assert.strictEqual(budget.canExecute(TaskTypes.VERIFICATION).allowed, true);

// Record usage to reach 85% ($0.85, 850k tokens)
budget.recordUsage({
    analysisId: 'test-run-1',
    taskType: 'exploration',
    modelId: 'test-model',
    provider: 'nvidia',
    promptTokens: 500000,
    completionTokens: 350000,
    cost: 0.85
});

let check = budget.canExecute(TaskTypes.NOVELTY_ANALYSIS, { noveltyMode: 'deep' });
assert.strictEqual(check.allowed, false, 'Deep novelty should be throttled at >80%');
assert.strictEqual(budget.canExecute(TaskTypes.VERIFICATION).allowed, true, 'Verification must still be allowed at 85%');

// Record usage to reach 93% ($0.93)
budget.recordUsage({
    analysisId: 'test-run-1',
    taskType: 'exploration',
    modelId: 'test-model',
    provider: 'nvidia',
    promptTokens: 50000,
    completionTokens: 30000,
    cost: 0.08
});

check = budget.canExecute(TaskTypes.HYPOTHESIS_FORMULATION);
assert.strictEqual(check.allowed, false, 'Exploratory tasks must be stopped at >90%');
assert.strictEqual(budget.canExecute(TaskTypes.VERIFICATION).allowed, true, 'Verification must still be allowed at 93%');

// Record usage to reach 102% ($1.02)
budget.recordUsage({
    analysisId: 'test-run-1',
    taskType: 'verification',
    modelId: 'test-model',
    provider: 'nvidia',
    promptTokens: 50000,
    completionTokens: 40000,
    cost: 0.09
});

check = budget.canExecute(TaskTypes.CODE_REASONING);
assert.strictEqual(check.allowed, false, 'General tasks must be blocked at >=100%');

// Emergency verification allowance up to 105%
check = budget.canExecute(TaskTypes.VERIFICATION);
assert.strictEqual(check.allowed, true, 'Emergency verification allowance must allow critical verifier up to 105%');

const stats = budget.getStats();
assert.ok(stats.total_cost_usd >= 1.0);
assert.ok(stats.ledger_entries_count >= 3);
console.log(`  -> Budget enforcement passed. Stats: Cost $${stats.total_cost_usd}, Consumption ${(stats.consumption_ratio * 100).toFixed(1)}%`);

console.log('\n[PASS] All WP2 NVIDIA LLM Architecture tests passed successfully!\n');
