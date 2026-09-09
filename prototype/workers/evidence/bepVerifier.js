import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { EvidenceContract } from './evidenceContract.js';
import { DifferentialValidator } from './differentialValidator.js';

export class BEPVerifier {
    constructor(options = {}) {
        this.evidenceContract = new EvidenceContract(options);
        this.differentialValidator = new DifferentialValidator(options);
    }

    verifyBEP(bepBundleOrPath, options = {}) {
        let bundle = bepBundleOrPath;
        if (typeof bepBundleOrPath === 'string') {
            if (!fs.existsSync(bepBundleOrPath)) {
                return {
                    valid: false,
                    integrity_status: 'MISSING_ARTIFACT',
                    errors: [`BEP bundle file not found: ${bepBundleOrPath}`],
                    recalculated_verdict: 'INCONCLUSIVE'
                };
            }
            try {
                bundle = JSON.parse(fs.readFileSync(bepBundleOrPath, 'utf8'));
            } catch (err) {
                return {
                    valid: false,
                    integrity_status: 'MALFORMED_JSON',
                    errors: [`Failed to parse BEP JSON: ${err.message}`],
                    recalculated_verdict: 'INCONCLUSIVE'
                };
            }
        }

        const errors = [];
        const packet = bundle.evidence_packet;
        const declaredVerdict = bundle.verdict || bundle.verdict_decision?.verdict;

        if (!packet) {
            return {
                valid: false,
                integrity_status: 'MISSING_EVIDENCE_PACKET',
                errors: ['Missing evidence_packet inside BEP bundle'],
                recalculated_verdict: 'INCONCLUSIVE'
            };
        }

        // 1. Check Artifact Hashes Integrity
        if (packet.provenance?.artifact_hashes) {
            for (const [artName, expHash] of Object.entries(packet.provenance.artifact_hashes)) {
                if (expHash && options.checkDiskHashes) {
                    // Check if file hash on disk matches
                    const artFile = path.resolve('prototype/artifacts', artName.replace('_', '/') + '.json');
                    if (fs.existsSync(artFile)) {
                        const actualHash = crypto.createHash('sha256').update(fs.readFileSync(artFile)).digest('hex');
                        if (actualHash !== expHash) {
                            errors.push(`Hash mismatch for ${artName}: expected ${expHash}, got ${actualHash}`);
                        }
                    }
                }
            }
        }

        // 2. Adversarial Tamper Checks
        // A: Taint reported without trace
        if (packet.runtime?.taint_observed === true && (!packet.runtime.trace_hash || packet.runtime.trace_hash.length === 0)) {
            errors.push('Adversarial tampering detected: runtime taint reported without trace hash');
        }

        // B: SAT reported without generated input
        if (packet.symbolic?.status === 'SAT' && !packet.symbolic.generated_input) {
            errors.push('Adversarial tampering detected: solver status SAT declared without generated input');
        }

        // C: Differential delta claimed true without observable violation
        if (packet.differential?.delta_detected === true && packet.differential?.attack_observed?.security_condition_violated !== true) {
            errors.push('Adversarial tampering detected: differential delta claimed true without attack condition violation');
        }

        // D: Provenance missing or corrupted
        if (!packet.provenance || !packet.provenance.java_version || !packet.provenance.artifact_hashes) {
            errors.push('Incomplete evidence: missing provenance metadata or artifact hashes');
        }

        // 3. Recalculate Verdict using Evidence Contract
        let evalResult;
        try {
            evalResult = this.evidenceContract.evaluate(packet);
        } catch (err) {
            return {
                valid: false,
                integrity_status: 'EVALUATION_ERROR',
                errors: [`Evidence evaluation threw exception: ${err.message}`],
                recalculated_verdict: 'INCONCLUSIVE'
            };
        }

        const recalculatedVerdict = evalResult.verdict;

        // 4. Verify Declared Verdict Matches Recalculated Verdict
        if (declaredVerdict && declaredVerdict !== recalculatedVerdict) {
            errors.push(`Verdict discrepancy: declared '${declaredVerdict}' does not match recalculated '${recalculatedVerdict}'`);
        }

        // 5. Optional Deterministic Replay Check
        let replaySucceeded = true;
        if (options.replay && bundle.replay_manifest) {
            try {
                const replayDiff = this.differentialValidator.validateDifferential(packet.case_id, {
                    baselineInput: bundle.replay_manifest.baseline_input,
                    attackInput: bundle.replay_manifest.attack_input
                });
                if (replayDiff.differential.delta_detected !== packet.differential.delta_detected) {
                    errors.push(`Replay discrepancy: original delta was ${packet.differential.delta_detected}, replay produced ${replayDiff.differential.delta_detected}`);
                    replaySucceeded = false;
                }
            } catch (replayErr) {
                errors.push(`Replay execution failed: ${replayErr.message}`);
                replaySucceeded = false;
            }
        }

        const isValid = errors.length === 0;

        return {
            valid: isValid,
            case_id: packet.case_id,
            declared_verdict: declaredVerdict,
            recalculated_verdict: recalculatedVerdict,
            integrity_status: isValid ? 'VALID' : 'TAMPER_OR_INCONSISTENCY_DETECTED',
            errors,
            required_evidence_items_passed: evalResult.required_evidence_items_passed,
            replay_succeeded: replaySucceeded
        };
    }
}
