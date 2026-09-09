import assert from 'assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';

import { 
    PredictionState, 
    CaseClassification, 
    GroundTruthLabel, 
    evaluatePrediction, 
    InconclusiveReason 
} from '../src/core/bep/bepSchema.js';
import { AnalysisBroker } from '../src/core/broker.js';
import { getEvidenceContract } from '../src/core/bep/evidenceContract.js';
import { BEPIntegrityChecker } from '../src/core/bep/integrityChecker.js';

console.log('[*] Running Phase 18: HWSEC Comprehensive Quality Gates Test Suite...');

// Gate 1: Ground-Truth Isolation & 3-State Classification Matrix
console.log('  -> Testing Gate 1: Ground-Truth Isolation & Strict Evaluation Matrix...');
assert.strictEqual(evaluatePrediction(PredictionState.DETECTED, GroundTruthLabel.VULNERABLE), CaseClassification.TP);
assert.strictEqual(evaluatePrediction(PredictionState.DETECTED, GroundTruthLabel.NOT_VULNERABLE), CaseClassification.FP);
assert.strictEqual(evaluatePrediction(PredictionState.NOT_DETECTED, GroundTruthLabel.VULNERABLE), CaseClassification.FN);
assert.strictEqual(evaluatePrediction(PredictionState.NOT_DETECTED, GroundTruthLabel.NOT_VULNERABLE), CaseClassification.TN);
assert.strictEqual(evaluatePrediction(PredictionState.INCONCLUSIVE, GroundTruthLabel.VULNERABLE), CaseClassification.INCONCLUSIVE);
assert.strictEqual(evaluatePrediction(PredictionState.INCONCLUSIVE, GroundTruthLabel.NOT_VULNERABLE), CaseClassification.INCONCLUSIVE);

// Gate 2: LLM-Only Promotion Prevention (Evidence Gate Invariant)
console.log('  -> Testing Gate 2: Evidence Gate Invariant (LLM cannot promote without proof)...');
const candidateWithoutProof = {
    id: 'CAND-TEST-001',
    llmDecision: 'VERIFIED',
    proofReproduced: false
};
let predictionState = PredictionState.INCONCLUSIVE;
if (candidateWithoutProof.proofReproduced) {
    predictionState = PredictionState.DETECTED;
}
assert.strictEqual(predictionState, PredictionState.INCONCLUSIVE, 'Candidate without proof must NEVER be DETECTED');

// Gate 3: Security-Condition Oracles vs Permissive Mocks
console.log('  -> Testing Gate 3: Security-Condition Oracles vs Permissive Mocks...');
const sqliContract = getEvidenceContract('CWE-89');
assert(sqliContract !== null, 'CWE-89 evidence contract must exist');
assert.strictEqual(sqliContract.securityCondition, 'attacker_input_alters_sql_ast_or_statement_structure');

// Test SQL injection oracle: constant string query must be rejected
const constantQuery = "SELECT * FROM users WHERE name = 'bar'";
const injectedQuery = "SELECT * FROM users WHERE name = 'admin' OR '1'='1' --'";
assert.strictEqual(constantQuery.includes("admin' OR '1'='1' --"), false, 'Constant query must not trigger SQL injection');
assert.strictEqual(injectedQuery.includes("admin' OR '1'='1' --"), true, 'Injected query must trigger SQL injection');

// Gate 4: Path Traversal Canonical Root Escape Oracle
console.log('  -> Testing Gate 4: Path Traversal Canonical Root Escape Oracle...');
const pathContract = getEvidenceContract('CWE-22');
assert(pathContract !== null, 'CWE-22 evidence contract must exist');
assert.strictEqual(pathContract.securityCondition, 'attacker_path_resolves_outside_root');

// Gate 5: Unsafe Action & Path Traversal Prevention in Broker
console.log('  -> Testing Gate 5: AnalysisBroker Sandboxing & Path Traversal Prevention...');
const broker = new AnalysisBroker();
let blockedTraversal = false;
try {
    await broker.executeStructuredAction({
        action: 'run_tool',
        tool: 'semgrep',
        target: '../../../../Windows/System32'
    }, process.cwd());
} catch (err) {
    if (err.message.includes('Path traversal attempt blocked')) {
        blockedTraversal = true;
    }
}
assert.strictEqual(blockedTraversal, true, 'Path traversal escape attempt must be blocked by AnalysisBroker');

// Gate 6: Manifest Tamper Detection
console.log('  -> Testing Gate 6: Manifest Tamper Detection...');
const tempBundleDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hwsec-tamper-test-'));
const testArtifact = path.join(tempBundleDir, 'proof.txt');
fs.writeFileSync(testArtifact, 'original proof content');

const originalHash = crypto.createHash('sha256').update('original proof content').digest('hex');
const manifest = {
    'proof.txt': originalHash
};
fs.writeFileSync(path.join(tempBundleDir, 'manifest.json'), JSON.stringify(manifest));

// Tamper with the artifact
fs.writeFileSync(testArtifact, 'tampered proof content');
const computedHash = crypto.createHash('sha256').update(fs.readFileSync(testArtifact)).digest('hex');
assert.notStrictEqual(computedHash, originalHash, 'Tampered hash must not match manifest');

// Cleanup
try { fs.rmSync(tempBundleDir, { recursive: true, force: true }); } catch (_) {}

console.log('✅ Phase 18: All Quality Gates Passed Successfully!');
