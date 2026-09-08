import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { CoverageMatrix, CWE_FAMILIES } from '../src/core/coverageMatrix.js';
import { CandidateGenerator } from '../src/workers/candidateGenerator.js';
import { LayeredVerifier, VerificationLevel } from '../src/workers/verifier.js';
import { getCommonAncestor } from '../src/domains/software/tools/joern.js';
import { createFinding, createEvidence, Severity, VerificationState } from '../src/core/schema.js';
import { CodeGraph } from '../src/core/graph/codeGraph.js';

console.log('=== Running Architecture Upgrade Verification Test Suite ===\n');

// -------------------------------------------------------------
// Test 1: CoverageMatrix Initialization & Gap Identification
// -------------------------------------------------------------
console.log('[Test 1] Testing CoverageMatrix initialization & gap analysis...');
const matrix = new CoverageMatrix();
assert.ok(matrix.matrix.MemorySafety, 'MemorySafety family must exist in matrix');
assert.ok(matrix.matrix.SQLInjection, 'SQLInjection family must exist in matrix');

const gapsC = matrix.identifyGaps(['c']);
assert.ok(gapsC.some(g => g.family === 'MemorySafety'), 'MemorySafety must be identified as gap for C initially');

// Record analysis and verify status update
matrix.recordAnalysis({
    family: 'MemorySafety',
    language: 'c',
    tool: 'semgrep',
    findingsCount: 3
});
assert.strictEqual(matrix.matrix.MemorySafety.c.findingsCount, 3);
assert.strictEqual(matrix.matrix.MemorySafety.c.status, 'COVERED');

// Serialization test
const exported = matrix.exportState();
assert.ok(exported.matrix.MemorySafety.c.semgrep, 'Exported state should reflect recorded semgrep analysis');
const restoredMatrix = new CoverageMatrix();
restoredMatrix.importState(exported);
assert.strictEqual(restoredMatrix.matrix.MemorySafety.c.findingsCount, 3);
console.log('  -> CoverageMatrix correctly tracks families, gaps, and state persistence.');

// -------------------------------------------------------------
// Test 2: Joern Common Ancestor Resolution
// -------------------------------------------------------------
console.log('\n[Test 2] Testing Joern getCommonAncestor directory resolution...');
const paths1 = [
    path.resolve('src/core/planner.js'),
    path.resolve('src/core/broker.js'),
    path.resolve('src/core/state.js')
];
const ancestor1 = getCommonAncestor(paths1);
assert.strictEqual(ancestor1, path.resolve('src/core'), 'Common ancestor of src/core/*.js should be src/core');

const paths2 = [
    path.resolve('src/core/planner.js'),
    path.resolve('src/workers/verifier.js')
];
const ancestor2 = getCommonAncestor(paths2);
assert.strictEqual(ancestor2, path.resolve('src'), 'Common ancestor of src/core and src/workers should be src');

const singleDir = getCommonAncestor([path.resolve('src')]);
assert.strictEqual(singleDir, path.resolve('src'), 'Single directory should resolve to itself');
console.log('  -> Joern getCommonAncestor correctly resolves root directories.');

// -------------------------------------------------------------
// Test 3: CandidateGenerator Pooling & Boundary Escalation
// -------------------------------------------------------------
console.log('\n[Test 3] Testing CandidateGenerator pooling & boundary detection...');
const codeGraph = new CodeGraph();
const candidateGen = new CandidateGenerator(codeGraph, matrix);

const dummyFinding = createFinding({
    id: 'FIND-SAST-01',
    title: 'CWE-89 SQL Injection in query parser',
    cwe_id: 'CWE-89',
    severity: Severity.HIGH,
    source_tool: 'semgrep',
    source_locations: [{ path: 'src/query.js', startLine: 42 }]
});

// Create a mock source file with boundary input and dangerous sink
const testScratchDir = path.resolve('hwsec-output/test_arch_upgrade');
if (!fs.existsSync(testScratchDir)) fs.mkdirSync(testScratchDir, { recursive: true });

const mockBoundaryFile = path.join(testScratchDir, 'boundary_test.js');
fs.writeFileSync(mockBoundaryFile, `
function handleRequest(req, res) {
    const input = req.query.cmd;
    const proc = system(input);
}
`, 'utf8');

const candidates = candidateGen.generateCandidates({
    files: [{ path: mockBoundaryFile, language: 'javascript' }],
    deterministicFindings: [dummyFinding],
    executedTools: ['semgrep', 'joern']
});

assert.ok(candidates.some(c => c.id === 'FIND-SAST-01'), 'Deterministic findings must be pooled');
assert.ok(candidates.some(c => c.source === 'security_boundary_escalation'), 'Boundary sink crossing must escalate');
assert.ok(candidates.some(c => c.source === 'analyzer_disagreement'), 'Disagreement across executed tools must escalate');
console.log('  -> CandidateGenerator successfully pooled findings, boundary crossings, and disagreements.');

// -------------------------------------------------------------
// Test 4: Verifier Evidence Hardening & Self-Certification Reject
// -------------------------------------------------------------
console.log('\n[Test 4] Testing Verifier strict evidence hardening...');
const verifier = new LayeredVerifier();

// 4a. Static findings telemetry JSON must NOT award counterexample
const staticTelemetryPath = path.join(testScratchDir, 'static_telemetry.json');
fs.writeFileSync(staticTelemetryPath, JSON.stringify({
    tool: 'semgrep',
    findings: [{ ruleId: 'cwe-89', match: 'foo' }]
}), 'utf8');

const staticEval = verifier._inspectArtifact({ artifact_path: staticTelemetryPath }, { source_locations: ['src/app.py'] });
assert.strictEqual(staticEval.hasCounterexample, false, 'Static telemetry findings array must NOT award dynamic counterexample');
assert.ok(staticEval.reason.includes('observation only'), 'Reason must indicate observation only');

// 4b. Dynamic violation telemetry JSON awards counterexample
const dynamicTelemetryPath = path.join(testScratchDir, 'dynamic_telemetry.json');
fs.writeFileSync(dynamicTelemetryPath, JSON.stringify({
    tool: 'symbiyosys',
    violations: 1,
    counterexample: true
}), 'utf8');

const dynamicEval = verifier._inspectArtifact({ artifact_path: dynamicTelemetryPath }, { source_locations: ['rtl/alu.v'] });
assert.strictEqual(dynamicEval.hasCounterexample, true, 'Dynamic violations count must award counterexample');

// 4c. Generic text log "FAIL" or "crash" must NOT award counterexample
const genericLogPath = path.join(testScratchDir, 'generic_fail.log');
fs.writeFileSync(genericLogPath, 'Build output: FAILURE. Something crashed with error code 1. Status: FAIL.', 'utf8');

const genericEval = verifier._inspectArtifact({ artifact_path: genericLogPath }, { source_locations: ['src/main.c'] });
assert.strictEqual(genericEval.hasCounterexample, false, 'Generic failure substrings must NOT award counterexample');

// 4d. Strict execution failure log DOES award counterexample
const strictLogPath = path.join(testScratchDir, 'strict_violation.log');
fs.writeFileSync(strictLogPath, 'Execution started... AddressSanitizer: heap-buffer-overflow on address 0x1234', 'utf8');

const strictEval = verifier._inspectArtifact({ artifact_path: strictLogPath }, { source_locations: ['src/main.c'] });
assert.strictEqual(strictEval.hasCounterexample, true, 'AddressSanitizer violation trace must award counterexample');

// 4e. LLM self-certification rejection
const llmFinding = createFinding({
    id: 'FIND-LLM-01',
    title: 'LLM Self-Certified Vulnerability',
    source_tool: 'deep_reasoning',
    llm_certified: true,
    evidence: [createEvidence({ tool: 'deep_reasoning', artifact_path: staticTelemetryPath })]
});

const rawEval = verifier._evaluateRawFinding(llmFinding);
assert.strictEqual(rawEval.status, VerificationState.CANDIDATE, 'LLM finding without dynamic counterexample must remain CANDIDATE');
assert.ok(rawEval.justification.includes('cannot self-certify'), 'Justification must state LLM cannot self-certify');

console.log('  -> Verifier strictly rejects false counterexamples and LLM self-certification.');

console.log('\n[PASS] All Architecture Upgrade tests passed successfully!\n');
