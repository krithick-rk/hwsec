import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { SuspicionEngine } from '../src/core/suspicion/engine.js';
import { DisagreementDetector } from '../src/core/suspicion/disagreement.js';
import { RAGEngine } from '../src/core/knowledge/rag.js';
import { CodeGraph, NodeTypes, EdgeRelations } from '../src/core/graph/codeGraph.js';
import { HypothesisGenerator } from '../src/workers/hypothesisGenerator.js';

console.log('=== Running WP8-WP11: Intelligence, Graph, RAG & Suspicion Tests ===');

// Test 1: Disagreement Detector
console.log('[Test 1] Testing Analyzer Disagreement Detection...');
const detector = new DisagreementDetector();
const mockFindings = [
    {
        title: 'Command Injection',
        severity: 'HIGH',
        source_tool: 'semgrep',
        source_locations: [{ path: 'src/auth.py', startLine: 10 }]
    }
];
const disagreementRes = detector.detect('src/auth.py', mockFindings, ['semgrep', 'codeql', 'joern']);
assert.strictEqual(disagreementRes.hasDisagreement, true);
assert.ok(disagreementRes.disagreementScore > 0);
assert.deepStrictEqual(disagreementRes.reportingTools, ['semgrep']);
assert.ok(disagreementRes.silentTools.includes('codeql'));
console.log(`  -> Disagreement signal detected (${disagreementRes.reason}).`);

// Test 2: Suspicion Engine Scoring & Top Percentage Ranking
console.log('[Test 2] Testing Suspicion Engine Prioritization...');
const suspicion = new SuspicionEngine();
const target1 = {
    path: 'src/auth.py',
    content: 'def verify_token(secret, key): eval(key)',
    findings: mockFindings,
    executedTools: ['semgrep', 'codeql']
};
const target2 = {
    path: 'src/utils.py',
    content: 'def add(a, b): return a + b',
    findings: [],
    executedTools: ['semgrep', 'codeql']
};

const score1 = suspicion.scoreTarget(target1);
const score2 = suspicion.scoreTarget(target2);

assert.ok(score1.suspicion_score > score2.suspicion_score, 'Suspicious target must score higher than benign utils');
assert.ok(score1.suspicion_score >= 0.40, `Expected score >= 0.40, got ${score1.suspicion_score}`);

const ranking = suspicion.rankTargets([target1, target2], 0.50);
assert.strictEqual(ranking.prioritizedTargets.length, 1);
assert.strictEqual(ranking.prioritizedTargets[0].path, 'src/auth.py');
console.log(`  -> Suspicion ranking passed: Auth score = ${score1.suspicion_score}, Utils score = ${score2.suspicion_score}`);

// Test 3: RAG Multi-Store Separation
console.log('[Test 3] Testing RAG Logical Knowledge Store Separation...');
const rag = new RAGEngine();
const ragRes = rag.retrieveContext({ query: 'buffer overflow', language: 'c', limit: 2 });
assert.ok(ragRes.security_knowledge.length > 0);
assert.strictEqual(ragRes.security_knowledge[0].id, 'CWE-120');
assert.ok(Array.isArray(ragRes.project_specifications));
assert.ok(Array.isArray(ragRes.audit_memory));
console.log('  -> RAG retrieved focused context from logically separated stores.');

// Test 4: Code & Evidence Graph Attack Path Discovery
console.log('[Test 4] Testing CodeGraph & Attack Path Discovery...');
const graph = new CodeGraph();
graph.addNode('src_input', NodeTypes.SOURCE, 'HTTP Request Body');
graph.addNode('auth_handler', NodeTypes.FUNCTION, 'handleAuth()');
graph.addNode('sink_exec', NodeTypes.SINK, 'system() Execution');

graph.addEdge('src_input', 'auth_handler', EdgeRelations.DATAFLOW);
graph.addEdge('auth_handler', 'sink_exec', EdgeRelations.CALLS);

const paths = graph.findPaths('src_input', 'sink_exec');
assert.strictEqual(paths.length, 1);
assert.strictEqual(paths[0].length, 3);

const attackPaths = graph.findAttackPaths();
assert.strictEqual(attackPaths.length, 1);
assert.strictEqual(attackPaths[0].source.id, 'src_input');
assert.strictEqual(attackPaths[0].sink.id, 'sink_exec');
console.log('  -> Attack path successfully discovered via graph traversal.');

// Test 5: Novelty Modes & Hypothesis Bounding
console.log('[Test 5] Testing Novelty Mode Bounding...');
const hypGen = new HypothesisGenerator(null, rag);

// Novelty = off must yield 0 novel hypotheses
const hypOff = await hypGen.generateHypotheses({
    deterministicFindings: mockFindings,
    suspiciousTargets: [score1],
    availableTools: ['semgrep'],
    noveltyMode: 'off'
});
assert.strictEqual(hypOff.length, 0, 'Novelty off must produce 0 hypotheses');

// Novelty = standard produces bounded candidates
const hypStd = await hypGen.generateHypotheses({
    deterministicFindings: mockFindings,
    suspiciousTargets: [score1],
    availableTools: ['semgrep'],
    noveltyMode: 'standard'
});
assert.ok(hypStd.length > 0 && hypStd.length <= 3, 'Novelty standard must be bounded to <= 3');
console.log(`  -> Novelty mode policies verified (off: ${hypOff.length}, standard: ${hypStd.length}).`);

console.log('\n[PASS] All WP8-WP11 Intelligence tests passed successfully!\n');
