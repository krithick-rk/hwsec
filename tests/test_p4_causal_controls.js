import assert from 'assert';
import { CausalControlEngine } from '../src/core/controls/causalControls.js';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';

console.log("============================================================");
console.log("    HWSEC PHASE P4: CAUSAL & NEGATIVE CONTROLS TEST SUITE");
console.log("============================================================\n");

const controlEngine = new CausalControlEngine();

const pathHyp = new VulnerabilityHypothesis({
    cwe: 'CWE-22',
    security_condition: 'PathTraversalOracle',
    source: 'filename',
    sink: 'File'
});

// Test 1: Negative-Input Control Valid Causal Demonstration
console.log("[P4-Test 1] Testing Negative-Input Control on Real Delta...");
const mockPathRunner = async (probe) => {
    const isAttack = probe.value.includes('..');
    return {
        exitCode: 0,
        parsed_result: {
            canonical_path: isAttack ? '/etc/passwd' : '/var/app/data/safe.txt',
            base_directory: '/var/app/data'
        },
        stdout: isAttack ? 'CANONICAL_ESCAPE: /etc/passwd' : 'Loaded /var/app/data/safe.txt'
    };
};

const negCtrlResult = await controlEngine.executeNegativeInputControl(
    pathHyp,
    { parameter: 'filename', value: '../../etc/passwd' },
    { parameter: 'filename', value: 'safe.txt' },
    mockPathRunner
);

assert.strictEqual(negCtrlResult.passed, true);
assert.strictEqual(negCtrlResult.attack_oracle.condition_satisfied, true);
assert.strictEqual(negCtrlResult.benign_oracle.condition_satisfied, false);
assert.ok(negCtrlResult.control_hash);
console.log("  -> [PASS] Negative-input control passed with clear causal delta.");

// Test 2: Ineffective Negative Control Rejection
console.log("\n[P4-Test 2] Testing Negative Control Rejection when Benign Also Triggers...");
const brokenRunner = async (probe) => {
    // Both attack and benign escape
    return {
        exitCode: 0,
        parsed_result: { canonical_path: '/etc/passwd', base_directory: '/var/app/data' }
    };
};

const brokenCtrlResult = await controlEngine.executeNegativeInputControl(
    pathHyp,
    { parameter: 'filename', value: '../../etc/passwd' },
    { parameter: 'filename', value: 'safe.txt' },
    brokenRunner
);
assert.strictEqual(brokenCtrlResult.passed, false, "Negative control must fail when benign input also triggers oracle");
console.log("  -> [PASS] Non-causal / indiscriminate behavior correctly rejected.");

// Test 3: Patch-Differential Control (Vul4J Style)
console.log("\n[P4-Test 3] Testing Patch-Differential Control...");
const unpatchedRunner = async (probe) => ({
    exitCode: 0,
    parsed_result: { canonical_path: '/etc/passwd', base_directory: '/var/app/data' }
});

const patchedRunner = async (probe) => ({
    exitCode: 0,
    parsed_result: { canonical_path: '/var/app/data/etc/passwd', base_directory: '/var/app/data' }
});

const patchCtrlResult = await controlEngine.executePatchDifferentialControl(
    pathHyp,
    { parameter: 'filename', value: '../../etc/passwd' },
    unpatchedRunner,
    patchedRunner
);

assert.strictEqual(patchCtrlResult.passed, true);
console.log("  -> [PASS] Patch-differential verified (vulnerability eliminated by patch).");

// Test 4: Replay Control
console.log("\n[P4-Test 4] Testing Replay Control Reproducibility...");
const replayResult = await controlEngine.executeReplayControl(
    pathHyp,
    { parameter: 'filename', value: '../../etc/passwd' },
    mockPathRunner
);
assert.strictEqual(replayResult.reproduced, true);
assert.strictEqual(replayResult.passed, true);
console.log("  -> [PASS] Replay reproduction verified.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P4 CAUSAL CONTROLS TESTS PASSED");
console.log("============================================================\n");
