import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Evidence Contract Engine
 * 
 * Implements machine-checkable, fail-closed evidence contract rules.
 * Evaluates the 7 required evidence items and derives deterministic verdicts:
 * DETECTED | NOT_DETECTED | INCONCLUSIVE.
 */
export class EvidenceContract {
    constructor(options = {}) {
        this.options = options;
    }

    evaluate(packet) {
        if (!packet || typeof packet !== 'object') {
            throw new Error('Evidence packet must be a non-null object');
        }

        const itemsPassed = {
            static_path_evidence: false,
            symbolic_feasibility: false,
            successful_replay: false,
            runtime_taint_evidence: false,
            security_condition_satisfied: false,
            negative_control: false,
            provenance_and_hashes: false
        };

        // 1. Static Path Evidence
        if (packet.static && packet.static.has_finding === true && Array.isArray(packet.static.tools_executed) && packet.static.tools_executed.length > 0) {
            itemsPassed.static_path_evidence = true;
        }

        // 2. Symbolic Feasibility Evidence
        if (packet.symbolic && packet.symbolic.status === 'SAT' && packet.symbolic.generated_input !== null) {
            itemsPassed.symbolic_feasibility = true;
        }

        // 3. Successful Replay
        if (packet.runtime && packet.runtime.exit_code === 0 && !packet.runtime.timeout) {
            itemsPassed.successful_replay = true;
        }

        // 4. Runtime Dynamic Taint Evidence
        if (packet.runtime && packet.runtime.taint_observed === true && packet.runtime.sink_reached === true) {
            itemsPassed.runtime_taint_evidence = true;
        }

        // 5. Security-Condition Satisfied
        if (packet.security_condition && packet.security_condition.satisfied === true) {
            itemsPassed.security_condition_satisfied = true;
        }

        // 6. Negative Control
        if (packet.differential && 
            packet.differential.delta_detected === true && 
            packet.differential.baseline_observed && 
            packet.differential.baseline_observed.security_condition_violated === false) {
            itemsPassed.negative_control = true;
        }

        // 7. Provenance & Hashes
        if (packet.provenance && 
            packet.provenance.java_version && 
            packet.provenance.artifact_hashes && 
            Object.keys(packet.provenance.artifact_hashes).length > 0) {
            itemsPassed.provenance_and_hashes = true;
        }

        // Compute serialization digest of the packet for immutable linking
        const packetSerialized = JSON.stringify(packet, null, 2);
        const evidenceHash = crypto.createHash('sha256').update(packetSerialized).digest('hex');

        // Check for Explicit Inconclusive Conditions
        const hasTimeout = Boolean(packet.runtime?.timeout || packet.differential?.baseline_observed?.timeout || packet.differential?.attack_observed?.timeout);
        const hasInstrumentationFailure = packet.runtime?.instrumentation_status === 'FAILED' || packet.runtime?.instrumentation_status === 'UNAVAILABLE';
        const hasUnknownSolver = packet.symbolic?.status === 'UNKNOWN';
        const hasMissingHarness = packet.runtime?.exit_code !== 0 && packet.runtime?.exit_code !== undefined;

        if (hasTimeout || hasInstrumentationFailure || hasUnknownSolver || hasMissingHarness) {
            let inconclusiveReason = 'Incomplete evidence';
            if (hasTimeout) inconclusiveReason = 'Execution timeout encountered in worker sandbox';
            else if (hasInstrumentationFailure) inconclusiveReason = 'Instrumentation failure or unavailable agent';
            else if (hasUnknownSolver) inconclusiveReason = 'Symbolic constraint solver returned UNKNOWN status';
            else if (hasMissingHarness) inconclusiveReason = 'Harness execution failed with non-zero exit code';

            return {
                case_id: packet.case_id,
                verdict: 'INCONCLUSIVE',
                reason_code: 'INCONCLUSIVE_INCOMPLETE_PROOF',
                confidence: 0.5,
                required_evidence_items_passed: itemsPassed,
                evidence_hash: evidenceHash,
                inconclusive_reason: inconclusiveReason,
                recommended_next_action: 'Perform manual audit or increase execution timeout',
                timestamp: new Date().toISOString()
            };
        }

        // Rule A: All 7 required evidence items passed -> DETECTED
        const allPassed = Object.values(itemsPassed).every(v => v === true);
        if (allPassed) {
            return {
                case_id: packet.case_id,
                verdict: 'DETECTED',
                reason_code: 'FULL_EVIDENCE_CONTRACT_SATISFIED',
                confidence: 1.0,
                required_evidence_items_passed: itemsPassed,
                evidence_hash: evidenceHash,
                inconclusive_reason: null,
                recommended_next_action: null,
                timestamp: new Date().toISOString()
            };
        }

        // Rule B: Explicit evidence establishes absence of condition -> NOT_DETECTED
        // Absence criteria:
        // 1. Symbolic solver proved UNSAT (mathematically impossible to violate)
        // 2. Taint did not reach sink (sink_tainted === false / safe constant assigned)
        // 3. Differential baseline and attack are both negative (delta_detected === false)
        const isExplicitUnsat = packet.symbolic?.status === 'UNSAT';
        const isSafeTaintBranch = packet.runtime?.sink_reached === false || packet.runtime?.taint_observed === false;
        const isNegativeDelta = packet.differential?.delta_detected === false && packet.security_condition?.satisfied === false;

        if (isExplicitUnsat && isSafeTaintBranch && isNegativeDelta) {
            return {
                case_id: packet.case_id,
                verdict: 'NOT_DETECTED',
                reason_code: 'FORMALLY_PROVEN_SAFE_ABSENCE',
                confidence: 1.0,
                required_evidence_items_passed: itemsPassed,
                evidence_hash: evidenceHash,
                inconclusive_reason: null,
                recommended_next_action: null,
                timestamp: new Date().toISOString()
            };
        }

        // Rule C: Partial evidence without explicit absence proof -> INCONCLUSIVE (Fail-Closed)
        // NEVER coerce partial evidence into True Negative or False Negative
        const missingItems = Object.entries(itemsPassed)
            .filter(([_, passed]) => !passed)
            .map(([k]) => k);

        return {
            case_id: packet.case_id,
            verdict: 'INCONCLUSIVE',
            reason_code: 'PARTIAL_EVIDENCE_UNRESOLVED',
            confidence: 0.5,
            required_evidence_items_passed: itemsPassed,
            evidence_hash: evidenceHash,
            inconclusive_reason: `Missing affirmative proof for: ${missingItems.join(', ')}`,
            recommended_next_action: 'Inspect solver constraints and dynamic instrumentation',
            timestamp: new Date().toISOString()
        };
    }
}
