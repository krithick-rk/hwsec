/**
 * test_preflight_scheduler.js
 * ============================
 * Unit tests for the Two-Pass Pre-Flight Token Estimation & Dynamic Token
 * Scheduler pipeline:
 *
 *   Pass 1 -- PreflightEstimator   (preflightEstimator.js)
 *   Pass 2 -- TokenBatcher         (tokenBatcher.js)
 *   Pass 3 -- DynamicTokenScheduler (dynamicTokenScheduler.js)
 *
 * Run: node tests/test_preflight_scheduler.js
 */

import { PreflightEstimator } from '../src/core/llm/preflightEstimator.js';
import { TokenBatcher } from '../src/core/llm/tokenBatcher.js';
import { DynamicTokenScheduler } from '../src/core/llm/dynamicTokenScheduler.js';

// minimal assertion helpers
let passed = 0;
let failed = 0;

function assert(condition, label) {
    if (condition) { console.log('  ok ' + label); passed++; }
    else { console.error('  FAIL ' + label); failed++; }
}
function assertEqual(actual, expected, label) {
    const ok = actual === expected;
    if (ok) { console.log('  ok ' + label + ' (' + actual + ')'); passed++; }
    else { console.error('  FAIL ' + label + ' -- expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual)); failed++; }
}
function assertGte(actual, min, label) {
    const ok = actual >= min;
    if (ok) { console.log('  ok ' + label + ' (' + actual + ' >= ' + min + ')'); passed++; }
    else { console.error('  FAIL ' + label + ' -- expected >= ' + min + ', got ' + actual); failed++; }
}
function assertLte(actual, max, label) {
    const ok = actual <= max;
    if (ok) { console.log('  ok ' + label + ' (' + actual + ' <= ' + max + ')'); passed++; }
    else { console.error('  FAIL ' + label + ' -- expected <= ' + max + ', got ' + actual); failed++; }
}
function section(title) {
    console.log('\n' + '='.repeat(60));
    console.log('  ' + title);
    console.log('='.repeat(60));
}

// synthetic profile factory (no fs I/O)
function syntheticProfile({ path = '/mock/file.v', language = 'verilog', domain = 'hardware', loc = 100, estimatedTokens = 500, complexity = 'MEDIUM', sizeBytes, charCount } = {}) {
    const _bytes = sizeBytes !== undefined ? sizeBytes : estimatedTokens * 4;
    const _chars = charCount  !== undefined ? charCount  : estimatedTokens * 4;
    return { path, relativePath: path.split('/').pop(), filename: path.split('/').pop(), extension: '.' + path.split('.').pop(), language, domain, sizeBytes: _bytes, charCount: _chars, loc, estimatedTokens, complexity, astNodeCount: 10, branchCount: 3, complexityScore: 25 };
}

function generateMockProfiles(n, { minT = 10, maxT = 5000, domain = null } = {}) {
    const domains = ['hardware', 'software', 'config', 'other'];
    const langs   = { hardware: 'verilog', software: 'python', config: 'yaml', other: 'markdown' };
    const exts    = { hardware: '.v', software: '.py', config: '.yaml', other: '.md' };
    return Array.from({ length: n }, (_, i) => {
        const d = domain || domains[i % domains.length];
        const toks = minT + Math.floor(Math.random() * (maxT - minT));
        return syntheticProfile({ path: '/mock/file_' + i + exts[d], language: langs[d], domain: d, estimatedTokens: toks, loc: Math.round(toks / 5) });
    });
}

async function main() {

// ── SUITE 1: estimateTokenCount ───────────────────────────────────────────────
section('SUITE 1 -- PreflightEstimator: estimateTokenCount()');
{
    const est = new PreflightEstimator();
    assert(est.estimateTokenCount('') === 0, 'Empty string -> 0 tokens');
    assert(est.estimateTokenCount(null) === 0, 'Null -> 0 tokens');
    assert(est.estimateTokenCount(undefined) === 0, 'Undefined -> 0 tokens');
    const count100 = est.estimateTokenCount('a'.repeat(380));
    assertGte(count100, 95,  '380-char string >= 95 tokens');
    assertLte(count100, 140, '380-char string <= 140 tokens');
    const sparseToks = est.estimateTokenCount('hello world '.repeat(50));
    const denseToks  = est.estimateTokenCount('{ } [ ] ( ) ; : = ! + - * / & | ^ % ~ , . '.repeat(20));
    assert(denseToks >= sparseToks, 'Symbol-dense text produces >= tokens as sparse text');
    const small = est.estimateTokenCount('module foo();endmodule');
    const large = est.estimateTokenCount('module foo();endmodule'.repeat(100));
    assert(large > small, 'Larger text -> more tokens than smaller text');
}

// ── SUITE 2: classifyDomain ───────────────────────────────────────────────────
section('SUITE 2 -- PreflightEstimator: classifyDomain()');
{
    const est = new PreflightEstimator();
    assertEqual(est.classifyDomain('verilog'),       'hardware', 'verilog -> hardware');
    assertEqual(est.classifyDomain('systemverilog'),  'hardware', 'systemverilog -> hardware');
    assertEqual(est.classifyDomain('python'),         'software', 'python -> software');
    assertEqual(est.classifyDomain('c'),              'software', 'c -> software');
    assertEqual(est.classifyDomain('cpp'),            'software', 'cpp -> software');
    assertEqual(est.classifyDomain('java'),           'software', 'java -> software');
    assertEqual(est.classifyDomain('go'),             'software', 'go -> software');
    assertEqual(est.classifyDomain('yaml'),           'config',   'yaml -> config');
    assertEqual(est.classifyDomain('json'),           'config',   'json -> config');
    assertEqual(est.classifyDomain('unknown_xyz'),    'other',    'unknown_xyz -> other');
    assertEqual(est.classifyDomain(null),             'other',    'null -> other');
    assertEqual(est.classifyDomain('/foo/bar.v'),     'hardware', '/foo/bar.v extension -> hardware');
    assertEqual(est.classifyDomain('/foo/bar.sv'),    'hardware', '/foo/bar.sv extension -> hardware');
    assertEqual(est.classifyDomain('/foo/bar.py'),    'software', '/foo/bar.py extension -> software');
    assertEqual(est.classifyDomain('/foo/bar.json'),  'config',   '/foo/bar.json extension -> config');
}

// ── SUITE 3: analyzeComplexity ────────────────────────────────────────────────
section('SUITE 3 -- PreflightEstimator: analyzeComplexity()');
{
    const est = new PreflightEstimator();
    const hwSimple  = est.analyzeComplexity('module foo(); endmodule', 'hardware', 5);
    const hwComplex = est.analyzeComplexity(
        Array.from({length: 1200}, (_, i) =>
            'always_ff @(posedge clk) begin if (rst) state <= IDLE; else state <= next_state; end // ' + i
        ).join('\n'),
        'hardware', 1200
    );
    assert(['LOW','MEDIUM','HIGH','CRITICAL'].includes(hwSimple.complexity), 'Simple HW -> valid complexity label');
    assertEqual(hwComplex.complexity, 'CRITICAL', '1200-line always_ff state machine -> CRITICAL');
    assert(hwComplex.astNodeCount > 0, 'Complex HW -> astNodeCount > 0');
    assert(hwComplex.branchCount  > 0, 'Complex HW -> branchCount > 0');

    const swComplex = est.analyzeComplexity(
        Array.from({length:500}, (_, i) =>
            'def fn_' + i + '(x):\n  if x > 0:\n    for j in range(x):\n      malloc(j)\n'
        ).join(''),
        'software', 500
    );
    assert(['HIGH','CRITICAL'].includes(swComplex.complexity), '500-fn software file -> HIGH or CRITICAL');
    assert(swComplex.astNodeCount > 0, 'Complex SW -> astNodeCount > 0');

    const cfg = est.analyzeComplexity('{ "key": "value", "nested": { "a": 1 } }', 'config', 2);
    assert(['LOW','MEDIUM'].includes(cfg.complexity), 'Small config -> LOW or MEDIUM');

    const hwFormal = est.analyzeComplexity(
        'assert (x == y); assume (valid); cover (state == DONE); property p1; assert property (p1);',
        'hardware', 10
    );
    assert(hwFormal.astNodeCount > 0, 'Formal properties detected -> astNodeCount > 0');
}

// ── SUITE 4: estimateFiles batch profiling ────────────────────────────────────
section('SUITE 4 -- PreflightEstimator: estimateFiles() batch profiling');
{
    const est = new PreflightEstimator();
    const empty = est.estimateFiles([]);
    assertEqual(empty.summary.totalFiles,  0, 'Empty list -> totalFiles=0');
    assertEqual(empty.summary.totalTokens, 0, 'Empty list -> totalTokens=0');
    assertEqual(empty.files.length,        0, 'Empty list -> files array is empty');

    const items = [
        { path: '/mock/a.v',    content: 'module a(); endmodule', language: 'verilog', loc: 1 },
        { path: '/mock/b.py',   content: 'def foo(): pass',       language: 'python',  loc: 1 },
        { path: '/mock/c.yaml', content: 'key: value',            language: 'yaml',    loc: 1 },
    ];
    const result = est.estimateFiles(items);
    assertEqual(result.summary.totalFiles, 3, '3 items -> totalFiles=3');
    assert(result.summary.totalTokens > 0,    'estimateFiles -> totalTokens > 0');
    assert(result.files.length === 3,         'estimateFiles -> exactly 3 profiles');
    assert(result.summary.domainBreakdown.hardware >= 1, 'At least 1 hardware file');
    assert(result.summary.domainBreakdown.software >= 1, 'At least 1 software file');
    assert(result.summary.domainBreakdown.config   >= 1, 'At least 1 config file');
    assert(result.summary.complexityBreakdown !== undefined, 'complexityBreakdown present');
}

// ── SUITE 5: TokenBatcher.resolveParameters ───────────────────────────────────
section('SUITE 5 -- TokenBatcher: resolveParameters()');
{
    const batcher = new TokenBatcher();
    const gParams = batcher.resolveParameters('gemini');
    assertEqual(gParams.tier, 'LARGE', 'Gemini provider -> LARGE tier');
    assertGte(gParams.contextWindow, 1000000, 'Gemini context window >= 1M');
    assert(gParams.maxBatchTokens < gParams.contextWindow, 'maxBatchTokens < contextWindow');
    assert(gParams.targetBatchTokens <= gParams.maxBatchTokens, 'targetBatchTokens <= maxBatchTokens');
    assertGte(gParams.targetBatchTokens, 16000, 'Gemini target batch >= 16k tokens');
    assertLte(gParams.maxBatchTokens, Math.floor(1048576 * 0.8) + 1, 'Gemini maxBatch <= 80% of 1M');

    const orParams = batcher.resolveParameters('openrouter');
    assert(['STANDARD','SMALL'].includes(orParams.tier), 'OpenRouter -> STANDARD or SMALL tier');
    assertGte(orParams.contextWindow, 64000, 'OpenRouter context window >= 64k');
    assert(orParams.maxBatchTokens < orParams.contextWindow, 'OpenRouter maxBatchTokens < contextWindow');

    const modelObj = { id: 'custom-model', provider: 'openrouter', contextWindow: 32000 };
    const mParams = batcher.resolveParameters(modelObj);
    assertEqual(mParams.contextWindow, 32000, 'Custom model object contextWindow=32000');
    assert(mParams.maxBatchTokens <= Math.floor(32000 * 0.8) + 1, 'Custom model maxBatch <= 80% of 32k');
}

// ── SUITE 6: createBatches core invariants ────────────────────────────────────
section('SUITE 6 -- TokenBatcher: createBatches() core invariants');
{
    const batcher = new TokenBatcher();
    const emptyPlan = batcher.createBatches([]);
    assertEqual(emptyPlan.totalBatches, 0, 'Empty profiles -> 0 batches');
    assertEqual(emptyPlan.totalFiles,   0, 'Empty profiles -> 0 batched files');
    assertEqual(emptyPlan.totalTokens,  0, 'Empty profiles -> 0 total tokens');

    const single = [syntheticProfile({ estimatedTokens: 100 })];
    const singlePlan = batcher.createBatches(single, { provider: 'gemini' });
    assertEqual(singlePlan.totalFiles,   1, 'Single file -> 1 batched file');
    assertEqual(singlePlan.totalBatches, 1, 'Single file -> 1 batch');
    assert(singlePlan.batches[0].totalTokens === 100, 'Single batch has 100 tokens');

    const small10 = Array.from({length:10}, (_, i) =>
        syntheticProfile({ path: '/mock/s' + i + '.py', estimatedTokens: 100, language: 'python', domain: 'software' })
    );
    const smallPlan = batcher.createBatches(small10, { provider: 'gemini' });
    assertEqual(smallPlan.totalFiles, 10, '10 small files -> 10 batched files (zero dropped)');
    assert(smallPlan.totalBatches <= 10, '10 small files -> <= 10 batches (some may merge)');
}

// ── SUITE 7: 1000 file stress Gemini LARGE ───────────────────────────────────
section('SUITE 7 -- TokenBatcher: 1,000-file stress test (Gemini LARGE)');
{
    const batcher = new TokenBatcher();
    const N = 1000;
    const mockFiles = generateMockProfiles(N, { minT: 10, maxT: 5000 });
    const plan = batcher.createBatches(mockFiles, { provider: 'gemini' });

    assertEqual(plan.totalFiles, N, 'All 1000 files batched -- zero dropped');
    assert(plan.totalBatches > 0, 'At least 1 batch produced');

    const ceiling80 = Math.floor(plan.parameters.contextWindow * 0.8);
    const oversized = plan.batches.filter(b => !b.isOversized && b.totalTokens > ceiling80);
    assert(oversized.length === 0,
        'No non-oversized batch exceeds 80% Gemini context (' + ceiling80.toLocaleString() + ' tokens)');

    const inputTotal = mockFiles.reduce((s, f) => s + f.estimatedTokens, 0);
    const batchTotal = plan.batches.reduce((s, b) => s + b.totalTokens,  0);
    assertEqual(batchTotal, inputTotal, 'Token conservation: batch total == input total');
    assert(plan.avgBatchTokens > 0, 'avgBatchTokens > 0');
    assertGte(plan.parameters.contextWindow, 1000000, 'Gemini context >= 1M');
    console.log('  info: ' + N + ' files -> ' + plan.totalBatches + ' batches | avg ' + plan.avgBatchTokens.toLocaleString() + ' tok/batch');
}

// ── SUITE 8: 1000 file stress OpenRouter STANDARD ────────────────────────────
section('SUITE 8 -- TokenBatcher: 1,000-file stress test (OpenRouter STANDARD)');
{
    const batcher = new TokenBatcher();
    const N = 1000;
    const mockFiles = generateMockProfiles(N, { minT: 10, maxT: 5000 });
    const plan = batcher.createBatches(mockFiles, { provider: 'openrouter' });

    assertEqual(plan.totalFiles, N, 'All 1000 files batched -- zero dropped');
    const ceiling80 = Math.floor(plan.parameters.contextWindow * 0.8);
    const oversized = plan.batches.filter(b => !b.isOversized && b.totalTokens > ceiling80);
    assert(oversized.length === 0, 'No batch exceeds 80% OpenRouter context ceiling');

    const targetToks = plan.parameters.targetBatchTokens;
    const tooLarge   = plan.batches.filter(b => !b.isSingleFileBatch && b.totalTokens > targetToks);
    assert(tooLarge.length === 0, 'No multi-file batch exceeds targetBatchTokens (' + targetToks.toLocaleString() + ')');
    assertLte(targetToks, 12001, 'Standard context targetBatchTokens <= 12,000');
    console.log('  info: ' + N + ' files -> ' + plan.totalBatches + ' batches | avg ' + plan.avgBatchTokens.toLocaleString() + ' tok/batch');
}

// ── SUITE 9: best_fit_decreasing ─────────────────────────────────────────────
section('SUITE 9 -- TokenBatcher: best_fit_decreasing strategy');
{
    const batcher = new TokenBatcher({ strategy: 'best_fit_decreasing' });
    const N = 200;
    const mockFiles = generateMockProfiles(N, { minT: 50, maxT: 3000 });
    const plan = batcher.createBatches(mockFiles, { provider: 'openrouter', strategy: 'best_fit_decreasing' });
    assertEqual(plan.totalFiles, N, 'BFD: zero dropped files');
    assert(plan.totalBatches > 0, 'BFD: at least 1 batch');
    const ceiling80 = Math.floor(plan.parameters.contextWindow * 0.8);
    const oversized = plan.batches.filter(b => !b.isOversized && b.totalTokens > ceiling80);
    assert(oversized.length === 0, 'BFD: no batch exceeds 80% context ceiling');
}

// ── SUITE 10: DynamicTokenScheduler.getProviderRpm ───────────────────────────
section('SUITE 10 -- DynamicTokenScheduler: getProviderRpm()');
{
    const scheduler = new DynamicTokenScheduler();
    assertEqual(scheduler.getProviderRpm('gemini'),     30, 'Gemini RPM = 30');
    assertEqual(scheduler.getProviderRpm('openrouter'), 20, 'OpenRouter RPM = 20');
    assertEqual(scheduler.getProviderRpm('nvidia'),      5, 'NVIDIA RPM = 5');
    assertEqual(scheduler.getProviderRpm('GEMINI'),     30, 'Case-insensitive GEMINI -> 30');
    assertEqual(scheduler.getProviderRpm('OpenRouter'), 20, 'Case-insensitive OpenRouter -> 20');
    assertEqual(scheduler.getProviderRpm('unknown'),    15, 'Unknown provider -> default 15');
    assertEqual(scheduler.getProviderRpm(null),         15, 'Null provider -> default 15');

    const customSched = new DynamicTokenScheduler({ llm_providers: { gemini: { rpm: 60 }, openrouter: { rpm: 10 } } });
    assertEqual(customSched.getProviderRpm('gemini'),     60, 'Config override: gemini RPM = 60');
    assertEqual(customSched.getProviderRpm('openrouter'), 10, 'Config override: openrouter RPM = 10');
    assertEqual(customSched.getProviderRpm('nvidia'),      5, 'Config: nvidia still default 5');
}

// ── SUITE 11: plan() with synthetic file list ─────────────────────────────────
section('SUITE 11 -- DynamicTokenScheduler: plan() with file list');
{
    const scheduler = new DynamicTokenScheduler();
    const N = 50;
    const files = generateMockProfiles(N, { minT: 100, maxT: 2000 }).map(p => ({
        path: p.path, content: '', language: p.language,
        loc: p.loc, size: p.sizeBytes, relativePath: p.relativePath
    }));
    const plan = scheduler.plan({ files, modelOrProvider: 'gemini', analysisId: 'test-run-001' });

    assert(plan !== null && typeof plan === 'object', 'plan() returns an object');
    assert(typeof plan.report === 'string',           'plan.report is a string');
    assert(plan.report.length > 0,                   'plan.report is non-empty');
    assert(Array.isArray(plan.batches),              'plan.batches is an array');
    assert(typeof plan.totalFiles === 'number',      'plan.totalFiles is a number');
    assertEqual(plan.rpmQuota, 30,                   'plan.rpmQuota = 30 (Gemini default)');
    assert(plan.minIntervalMs === Math.ceil(60000 / 30), 'plan.minIntervalMs correct');
    assert(typeof plan.estimatedDurationSeconds === 'number', 'plan.estimatedDurationSeconds is a number');
    assert(typeof plan.durationFormatted === 'string', 'plan.durationFormatted is a string');
    assertEqual(plan.analysisId, 'test-run-001',     'plan.analysisId preserved');
    assert(plan.totalBatches === plan.batches.length, 'plan.totalBatches matches batches array length');
}

// ── SUITE 12: plan() with inventory structure ─────────────────────────────────
section('SUITE 12 -- DynamicTokenScheduler: plan() with inventory structure');
{
    const scheduler = new DynamicTokenScheduler();
    const inventory = {
        languages: {
            verilog: ['/mock/cpu.v', '/mock/alu.v'],
            python:  ['/mock/test.py'],
            yaml:    ['/mock/cfg.yaml'],
        },
        file_metadata: {
            '/mock/cpu.v':    { loc: 400, size: 16000, relativePath: 'cpu.v' },
            '/mock/alu.v':    { loc: 200, size: 8000,  relativePath: 'alu.v' },
            '/mock/test.py':  { loc: 100, size: 4000,  relativePath: 'test.py' },
            '/mock/cfg.yaml': { loc: 20,  size: 600,   relativePath: 'cfg.yaml' },
        }
    };
    const plan = scheduler.plan({ inventory, modelOrProvider: 'openrouter', analysisId: 'inv-test' });

    assert(plan !== null, 'plan() with inventory returns an object');
    assertEqual(plan.totalFiles, 4, 'Inventory with 4 files -> totalFiles=4');
    assert(plan.totalBatches >= 1, 'Inventory plan -> at least 1 batch');
    assert(plan.batches.reduce((s, b) => s + b.fileCount, 0) === 4, 'All 4 files appear in batches');
    assert(plan.report.includes('Pass 1'), 'Report contains Pass 1 section');
    assert(plan.report.includes('Pass 2'), 'Report contains Pass 2 section');
    assert(plan.report.includes('Pass 3'), 'Report contains Pass 3 section');
}

// ── SUITE 13: executeBatches rate-limit + error recovery ─────────────────────
section('SUITE 13 -- DynamicTokenScheduler: executeBatches() rate-limit & error recovery');
{
    const fastSched = new DynamicTokenScheduler({ llm_providers: { gemini: { rpm: 600 } } });
    const batches = [
        { batchId: 'BATCH-001', files: [], totalTokens: 100 },
        { batchId: 'BATCH-002', files: [], totalTokens: 200 },
        { batchId: 'BATCH-003', files: [], totalTokens: 50  },
    ];
    const callTs = [];
    const results = await fastSched.executeBatches({
        batches,
        workerFn: async (b) => { callTs.push(Date.now()); return b.batchId; },
        provider: 'gemini'
    });

    assert(results.length === 3, 'executeBatches returns 3 results for 3 batches');
    assert(results.every(r => r.status === 'SUCCESS'), 'All batches report SUCCESS');
    assert(results[0].batchId === 'BATCH-001', 'Result[0] -> BATCH-001');
    assert(results[1].batchId === 'BATCH-002', 'Result[1] -> BATCH-002');
    assert(results[2].batchId === 'BATCH-003', 'Result[2] -> BATCH-003');

    if (callTs.length >= 2) {
        const gap1 = callTs[1] - callTs[0];
        const gap2 = callTs[2] - callTs[1];
        assert(gap1 >= 80, 'Gap between call 1 and 2 >= 80ms (got ' + gap1 + 'ms)');
        assert(gap2 >= 80, 'Gap between call 2 and 3 >= 80ms (got ' + gap2 + 'ms)');
    }

    // Error recovery
    const errorWorker = async (b, i) => { if (i === 1) throw new Error('Simulated API failure'); return 'ok'; };
    const errResults = await fastSched.executeBatches({ batches, workerFn: errorWorker, provider: 'gemini' });
    assertEqual(errResults[0].status, 'SUCCESS', 'Batch 0 SUCCESS even when batch 1 throws');
    assertEqual(errResults[1].status, 'ERROR',   'Batch 1 ERROR captured gracefully');
    assertEqual(errResults[2].status, 'SUCCESS', 'Batch 2 SUCCESS after error recovery');
    assert(typeof errResults[1].error === 'string', 'Error message captured as string');
}

// ── SUITE 14: onProgress callback ────────────────────────────────────────────
section('SUITE 14 -- DynamicTokenScheduler: executeBatches() onProgress callback');
{
    const fastSched = new DynamicTokenScheduler({ llm_providers: { gemini: { rpm: 600 } } });
    const batches = Array.from({length:5}, (_, i) => ({ batchId: 'B-' + i, files: [], totalTokens: 50 * (i + 1) }));
    const progressLog = [];
    await fastSched.executeBatches({
        batches,
        workerFn: async () => 'done',
        provider: 'gemini',
        onProgress: (completed, total) => progressLog.push({ completed, total })
    });
    assertEqual(progressLog.length, 5, 'onProgress fired exactly 5 times for 5 batches');
    assertEqual(progressLog[0].completed, 1, 'After batch 1: completed=1');
    assertEqual(progressLog[4].completed, 5, 'After batch 5: completed=5');
    assert(progressLog.every(p => p.total === 5), 'Total is always 5 in all progress events');
}

// ── SUITE 15: edge cases ──────────────────────────────────────────────────────
section('SUITE 15 -- DynamicTokenScheduler: executeBatches() edge cases');
{
    const sched = new DynamicTokenScheduler();
    const empty = await sched.executeBatches({ batches: [], workerFn: async () => {} });
    assert(Array.isArray(empty) && empty.length === 0, 'Empty batches -> empty results array');

    let threw = false;
    try { await sched.executeBatches({ batches: [{ batchId: 'B1', files: [] }], workerFn: 'not-fn' }); }
    catch { threw = true; }
    assert(threw, 'Non-function workerFn -> throws Error');
}

// ── SUITE 16: formatPreflightReport content ───────────────────────────────────
section('SUITE 16 -- DynamicTokenScheduler: formatPreflightReport() content');
{
    const scheduler = new DynamicTokenScheduler();
    const mockPlan = {
        targetProvider: 'gemini', targetModelId: 'gemini-2.5-flash',
        contextWindow: 1048576, maxBatchTokensLimit: 838860, targetBatchTokens: 64000,
        rpmQuota: 30, minIntervalMs: 2000, estimatedDurationSeconds: 120,
        durationFormatted: '2m 0s', estimatedRequests: 4,
        workloadSummary: {
            totalFiles: 100, totalLoc: 5000, totalTokens: 250000, avgTokensPerFile: 2500,
            largestFile: 'cpu.v', maxFileTokens: 15000,
            complexityBreakdown: { LOW: 40, MEDIUM: 35, HIGH: 20, CRITICAL: 5 },
            domainBreakdown: { hardware: 60, software: 30, config: 7, other: 3 },
        },
        batchPlan: { totalBatches: 4, totalFiles: 100, avgBatchTokens: 62500, maxBatchTokens: 68000 },
    };
    const report = scheduler.formatPreflightReport(mockPlan);
    assert(typeof report === 'string',           'formatPreflightReport returns a string');
    assert(report.includes('HWSEC TWO-PASS'),    'Report has HWSEC header');
    assert(report.includes('Pass 1'),            'Report includes Pass 1 section');
    assert(report.includes('Pass 2'),            'Report includes Pass 2 section');
    assert(report.includes('Pass 3'),            'Report includes Pass 3 section');
    assert(report.includes('gemini-2.5-flash'), 'Report includes model name');
    assert(report.includes('GEMINI'),            'Report includes provider uppercased');
    assert(report.includes('30 RPM'),            'Report includes RPM value');
    assert(report.includes('4 batch'),           'Report includes batch count');
    assert(report.includes('cpu.v'),             'Report includes largest file name');
    assert(report.includes('LOW: 40'),           'Report includes LOW complexity count');
    assert(report.includes('CRITICAL: 5'),       'Report includes CRITICAL complexity count');
}

// ── SUITE 17: 1,200-file plan() stress ───────────────────────────────────────
section('SUITE 17 -- Full plan(): 1,200-file stress test via DynamicTokenScheduler');
{
    const scheduler = new DynamicTokenScheduler();
    const N = 1200;
    const mockFiles = generateMockProfiles(N, { minT: 10, maxT: 5000 });
    const fileList  = mockFiles.map(p => ({
        path: p.path,
        content: 'x'.repeat(p.estimatedTokens * 4),
        language: p.language, loc: p.loc, size: p.sizeBytes, relativePath: p.relativePath,
    }));
    const plan = scheduler.plan({ files: fileList, modelOrProvider: 'gemini', analysisId: 'stress-1200' });

    assertEqual(plan.totalFiles, N, 'All 1200 files appear in plan (zero dropped)');
    assertGte(plan.totalBatches, 1, 'At least 1 batch created');

    const inputTotal = plan.workloadSummary.totalTokens;
    const batchTotal = plan.batches.reduce((s, b) => s + b.totalTokens, 0);
    assertEqual(batchTotal, inputTotal, 'Token conservation: batch total == workload total');

    const ceiling80 = Math.floor(plan.contextWindow * 0.8);
    const badBatches = plan.batches.filter(b => !b.isOversized && b.totalTokens > ceiling80);
    assert(badBatches.length === 0, 'No non-oversized batch exceeds 80% ceiling (' + ceiling80.toLocaleString() + ' tokens)');

    const reportHasCount = plan.report.includes('1,200') || plan.report.includes('1200');
    assert(reportHasCount, 'Report mentions 1200 files');
    console.log('  info: ' + N + ' files -> ' + plan.totalBatches + ' batches | rpm=' + plan.rpmQuota + ' | est: ' + plan.durationFormatted);
}

// ── Final Summary ─────────────────────────────────────────────────────────────
console.log('\n' + '='.repeat(60));
console.log('  TEST SUMMARY: ' + passed + ' PASSED, ' + failed + ' FAILED (Total: ' + (passed + failed) + ')');
console.log('='.repeat(60));
if (failed > 0) process.exit(1);

} // main()

main().catch(err => { console.error('[FATAL]', err); process.exit(1); });
