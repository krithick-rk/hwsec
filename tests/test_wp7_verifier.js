import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { LayeredVerifier, VerificationLevel } from '../src/workers/verifier.js';
import { createFinding, createEvidence, Severity, VerificationState } from '../src/core/schema.js';

console.log('=== Running WP7: Layered Technical Verifier Tests ===');

const testDir = path.resolve('./hwsec-output/test_verifier');
fs.mkdirSync(testDir, { recursive: true });

// Create a mock concrete crash artifact
const crashArtifact = path.join(testDir, 'afl_crashes.json');
fs.writeFileSync(crashArtifact, JSON.stringify({
    crashesFound: 1,
    crash_trace: 'FATAL: assertion violation state == 3 at clock cycle 45'
}), 'utf-8');

// Create a static warning artifact (lint only)
const lintArtifact = path.join(testDir, 'lint_telemetry.json');
fs.writeFileSync(lintArtifact, JSON.stringify({
    warnings: ['Width truncation warning on line 12']
}), 'utf-8');

const verifier = new LayeredVerifier();

// Test 1: Static observation without reproducing artifact remains CANDIDATE (E1)
console.log('[Test 1] Testing static warning produces CANDIDATE (E1), NOT VERIFIED...');
const hypStatic = {
    hypothesis_id: 'HYP-STATIC',
    cwe_id: 'CWE-120',
    title: 'Buffer Truncation',
    claim: 'Data input truncation causes state desynchronization',
    affected_assets: ['top.v']
};

const staticFinding = createFinding({
    id: 'FIND-LINT',
    title: 'Verilator Width Warning',
    source_tool: 'verilator',
    source_locations: [{ path: 'top.v', startLine: 12 }],
    evidence: [createEvidence({
        id: 'EV-LINT',
        tool: 'verilator',
        artifact_path: lintArtifact,
        observation: 'Operator expects 8 bits'
    })]
});

const resStatic = await verifier.verify([hypStatic], [staticFinding], {});
assert.strictEqual(resStatic.verifiedFindings.length, 0, 'Static warning alone must NOT verify finding');
assert.ok(resStatic.candidateFindings.length > 0, 'Static warning must be held as CANDIDATE');
const sumStatic = resStatic.verificationSummaries.find(s => s.hypothesis_id === 'HYP-STATIC');
assert.strictEqual(sumStatic.level, VerificationLevel.E1_TOOL_OBSERVATION);
assert.strictEqual(sumStatic.status, VerificationState.CANDIDATE);
assert.ok(sumStatic.justification.includes('lacks dynamic reproducing counterexample'));
console.log('  -> Static observation held at CANDIDATE (E1). Substring elevation prevented.');

// Test 2: Concrete reproducing artifact promotes to VERIFIED (E3)
console.log('[Test 2] Testing concrete reproducing artifact verifies finding (E3)...');
const hypCrash = {
    hypothesis_id: 'HYP-CRASH',
    cwe_id: 'CWE-20',
    title: 'Magic Sequence Fatal Crash',
    claim: 'Feeding sequence DEAD BEEF CAFE triggers crash',
    affected_assets: ['top.v']
};

const crashFinding = createFinding({
    id: 'FIND-CRASH',
    title: 'AFL++ Discovered Crash',
    severity: Severity.CRITICAL,
    source_tool: 'afl++',
    source_locations: [{ path: 'top.v', startLine: 20 }],
    evidence: [createEvidence({
        id: 'EV-CRASH',
        tool: 'afl++',
        artifact_path: crashArtifact,
        observation: '1 crash found'
    })]
});

const resCrash = await verifier.verify([hypCrash], [crashFinding], {});
assert.strictEqual(resCrash.verifiedFindings.length, 1, 'Reproducible crash must verify finding');
const sumCrash = resCrash.verificationSummaries.find(s => s.hypothesis_id === 'HYP-CRASH');
assert.strictEqual(sumCrash.level, VerificationLevel.E3_SEMANTIC_MATCH);
assert.strictEqual(sumCrash.status, VerificationState.VERIFIED);
assert.ok(sumCrash.justification.includes('verified in execution trace'));
console.log('  -> Concrete artifact successfully promoted finding to VERIFIED (E3).');

// Test 3: Unsupported claim is REFUTED (E0)
console.log('[Test 3] Testing unsupported claim is cleanly REFUTED (E0)...');
const hypUnrelated = {
    hypothesis_id: 'HYP-FAKE',
    cwe_id: 'CWE-999',
    title: 'Fabricated Memory Bug',
    claim: 'Out of bounds write in unreferenced memory controller',
    affected_assets: ['nonexistent_core.v']
};

const resRefuted = await verifier.verify([hypUnrelated], [staticFinding], {});
const sumRefuted = resRefuted.verificationSummaries.find(s => s.hypothesis_id === 'HYP-FAKE');
assert.strictEqual(sumRefuted.status, VerificationState.REFUTED);
assert.strictEqual(sumRefuted.level, VerificationLevel.E0_CLAIM_ONLY);
console.log('  -> Unsupported claim cleanly REFUTED (E0).');

console.log('\n[PASS] All WP7 Verifier tests passed successfully!\n');
