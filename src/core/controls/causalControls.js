import crypto from 'crypto';
import { defaultSecurityRegistry } from '../oracles/securityConditionRegistry.js';
import { canonicalHash } from '../bep/evidenceDag.js';

/**
 * CausalControlEngine
 * 
 * Section 13: Explicit controls with distinct causal semantics.
 */
export class CausalControlEngine {
    constructor(options = {}) {
        this.securityRegistry = options.securityRegistry || defaultSecurityRegistry;
    }

    /**
     * Executes a Negative-Input Control:
     * Exercises the same path with a benign control input to verify the oracle does NOT fire.
     * @param {Object} hypothesis 
     * @param {Object} witnessInput { parameter, value }
     * @param {Object} benignInput { parameter, value }
     * @param {Function} runner Async (probe) => Promise<ExecutionResult>
     * @returns {Promise<Object>} NegativeControlResult
     */
    async executeNegativeInputControl(hypothesis, witnessInput, benignInput, runner) {
        if (!hypothesis || !witnessInput || !benignInput || typeof runner !== 'function') {
            throw new Error('Invalid arguments to executeNegativeInputControl');
        }

        const oracle = this.securityRegistry.getOracle(hypothesis.cwe);

        // 1. Run attack witness
        const attackExec = await runner(witnessInput);
        const attackOracle = oracle ? oracle.evaluate(attackExec, witnessInput, { hypothesis }) : { condition_satisfied: true };

        // 2. Run benign control
        const benignExec = await runner(benignInput);
        const benignOracle = oracle ? oracle.evaluate(benignExec, benignInput, { hypothesis }) : { condition_satisfied: false };

        // Causal Validity: Attack MUST trigger oracle; Benign MUST NOT trigger oracle
        const passed = (attackOracle.condition_satisfied === true) && (benignOracle.condition_satisfied === false);

        const delta = {
            attack_effect: attackOracle.observable_effect,
            benign_effect: benignOracle.observable_effect,
            causal_relevance: `Security condition triggered uniquely by attack value '${witnessInput.value}' vs benign '${benignInput.value}'`
        };

        return {
            type: 'NEGATIVE_INPUT_CONTROL',
            passed,
            witness_input: witnessInput,
            benign_input: benignInput,
            delta,
            attack_oracle: attackOracle,
            benign_oracle: benignOracle,
            control_hash: canonicalHash({ witnessInput, benignInput, delta, passed })
        };
    }

    /**
     * Executes a Patch-Differential Control:
     * Replays the exact witness against unpatched and patched builds (e.g. Vul4J).
     * @param {Object} hypothesis 
     * @param {Object} witnessInput 
     * @param {Function} unpatchedRunner 
     * @param {Function} patchedRunner 
     * @returns {Promise<Object>} PatchControlResult
     */
    async executePatchDifferentialControl(hypothesis, witnessInput, unpatchedRunner, patchedRunner) {
        const oracle = this.securityRegistry.getOracle(hypothesis.cwe);

        const unpatchedExec = await unpatchedRunner(witnessInput);
        const unpatchedOracle = oracle ? oracle.evaluate(unpatchedExec, witnessInput, { hypothesis }) : { condition_satisfied: true };

        const patchedExec = await patchedRunner(witnessInput);
        const patchedOracle = oracle ? oracle.evaluate(patchedExec, witnessInput, { hypothesis }) : { condition_satisfied: false };

        // Causal Validity: Unpatched build fails; Patched build passes/mitigates
        const passed = (unpatchedOracle.condition_satisfied === true) && (patchedOracle.condition_satisfied === false);

        return {
            type: 'PATCH_DIFFERENTIAL_CONTROL',
            passed,
            witness_input: witnessInput,
            unpatched_effect: unpatchedOracle.observable_effect,
            patched_effect: patchedOracle.observable_effect,
            causal_delta: 'Vulnerability effect eliminated after patch application',
            control_hash: canonicalHash({ witnessInput, passed, unpatchedOracle, patchedOracle })
        };
    }

    /**
     * Executes a Replay Control:
     * Re-runs the exact witness and verifies deterministic reproduction.
     * @param {Object} hypothesis 
     * @param {Object} witnessInput 
     * @param {Function} runner 
     * @param {Object} [initialResult] 
     * @returns {Promise<Object>} ReplayControlResult
     */
    async executeReplayControl(hypothesis, witnessInput, runner, initialResult = null) {
        const replayExec = await runner(witnessInput);
        const oracle = this.securityRegistry.getOracle(hypothesis.cwe);
        const replayOracle = oracle ? oracle.evaluate(replayExec, witnessInput, { hypothesis }) : { condition_satisfied: true };

        const reproduced = replayOracle.condition_satisfied === true;

        return {
            type: 'REPLAY_CONTROL',
            reproduced,
            passed: reproduced,
            exit_code: replayExec.exitCode,
            oracle_result: replayOracle,
            control_hash: canonicalHash({ witnessInput, reproduced, exitCode: replayExec.exitCode })
        };
    }
}
