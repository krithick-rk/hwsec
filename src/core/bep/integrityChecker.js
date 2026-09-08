import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * HWSEC Fail-Closed Evidence Integrity Checker
 */

export class BEPIntegrityChecker {
    constructor() {}

    verifyBundle(bundleReader) {
        const errors = [];
        const warnings = [];

        const manifest = bundleReader.manifest;
        if (!manifest) {
            return {
                passed: false,
                errors: ['Missing manifest.json in evidence bundle'],
                warnings: []
            };
        }

        const cases = bundleReader.readJsonl('case_results.jsonl');
        const groundTruth = bundleReader.readJsonl('ground_truth.jsonl');
        const transitions = bundleReader.readJsonl('classification_transitions.jsonl');
        const verifierDecisions = bundleReader.readJsonl('verifier_decisions.jsonl');
        const proofArtifacts = bundleReader.readJsonl('proof_artifacts.jsonl');
        const rawFindings = bundleReader.readJsonl('raw_findings.jsonl');
        const aggregateMetrics = bundleReader.readJson('aggregate_metrics.json');

        const gtCaseMap = new Map(groundTruth.map(gt => [gt.case_id, gt]));
        const caseResultMap = new Map(cases.map(c => [c.case_id, c]));
        const decisionMap = new Map(verifierDecisions.map(d => [d.decision_id, d]));

        // 1. Every case has ground truth
        for (const c of cases) {
            if (!gtCaseMap.has(c.case_id)) {
                errors.push(`Case ${c.case_id} lacks matching ground_truth.jsonl entry`);
            }
        }

        // 2. Every ground truth maps to a case result
        for (const gt of groundTruth) {
            if (!caseResultMap.has(gt.case_id)) {
                errors.push(`Ground truth entry ${gt.case_id} lacks matching case_results.jsonl entry`);
            }
        }

        // 3. Every transition references valid states
        const validStates = new Set([
            'NOT_EVALUATED', 'UNVERIFIED', 'CANDIDATE', 'STRUCTURALLY_CORROBORATED', 
            'EXECUTION_CONFIRMED', 'SECURITY_PROPERTY_RELEVANT', 'DEFINITIVE_COUNTEREXAMPLE', 
            'VERIFIED_FALSE', 'DETECTED', 'NOT_DETECTED', 'INCONCLUSIVE',
            'TP', 'FP', 'FN', 'TN', 'UNKNOWN'
        ]);
        for (const t of transitions) {
            if (!validStates.has(t.from_state)) errors.push(`Transition ${t.transition_id} has invalid from_state: ${t.from_state}`);
            if (!validStates.has(t.to_state)) errors.push(`Transition ${t.transition_id} has invalid to_state: ${t.to_state}`);
            if (t.verifier_decision_id && !decisionMap.has(t.verifier_decision_id)) {
                errors.push(`Transition ${t.transition_id} references non-existent verifier_decision_id: ${t.verifier_decision_id}`);
            }
        }

        // 4. SHA-256 checksums verification
        const checksumFile = path.join(bundleReader.bundlePath, 'checksums.sha256');
        if (fs.existsSync(checksumFile)) {
            const lines = fs.readFileSync(checksumFile, 'utf8').split('\n').filter(l => l.trim().length > 0);
            for (const line of lines) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 2) {
                    const expectedSha = parts[0];
                    const relPath = parts.slice(1).join(' ');
                    const fullPath = path.join(bundleReader.bundlePath, relPath);
                    if (!fs.existsSync(fullPath)) {
                        errors.push(`Checksum file references missing file: ${relPath}`);
                    } else {
                        const content = fs.readFileSync(fullPath);
                        const actualSha = crypto.createHash('sha256').update(content).digest('hex');
                        if (actualSha !== expectedSha) {
                            errors.push(`SHA-256 mismatch for ${relPath}: expected ${expectedSha}, got ${actualSha}`);
                        }
                    }
                }
            }
        } else {
            warnings.push('checksums.sha256 missing from bundle');
        }

        // 5. Aggregate metrics recomputation
        if (aggregateMetrics) {
            let recomputedTp = 0, recomputedFp = 0, recomputedFn = 0, recomputedTn = 0, recomputedInconclusive = 0, recomputedUnk = 0;
            for (const c of cases) {
                if (c.classification === 'TP') recomputedTp++;
                else if (c.classification === 'FP') recomputedFp++;
                else if (c.classification === 'FN') recomputedFn++;
                else if (c.classification === 'TN') recomputedTn++;
                else if (c.classification === 'INCONCLUSIVE') recomputedInconclusive++;
                else recomputedUnk++;
            }

            if (aggregateMetrics.tp !== undefined && aggregateMetrics.tp !== recomputedTp) {
                errors.push(`Aggregate metrics TP mismatch: manifest says ${aggregateMetrics.tp}, recomputed ${recomputedTp}`);
            }
            if (aggregateMetrics.fp !== undefined && aggregateMetrics.fp !== recomputedFp) {
                errors.push(`Aggregate metrics FP mismatch: manifest says ${aggregateMetrics.fp}, recomputed ${recomputedFp}`);
            }
            if (aggregateMetrics.fn !== undefined && aggregateMetrics.fn !== recomputedFn) {
                errors.push(`Aggregate metrics FN mismatch: manifest says ${aggregateMetrics.fn}, recomputed ${recomputedFn}`);
            }
            if (aggregateMetrics.tn !== undefined && aggregateMetrics.tn !== recomputedTn) {
                errors.push(`Aggregate metrics TN mismatch: manifest says ${aggregateMetrics.tn}, recomputed ${recomputedTn}`);
            }
            if (aggregateMetrics.inconclusive !== undefined && aggregateMetrics.inconclusive !== recomputedInconclusive) {
                errors.push(`Aggregate metrics INCONCLUSIVE mismatch: manifest says ${aggregateMetrics.inconclusive}, recomputed ${recomputedInconclusive}`);
            }
        }

        const passed = errors.length === 0;

        return {
            passed,
            errors,
            warnings,
            stats: {
                total_cases: cases.length,
                total_ground_truth: groundTruth.length,
                total_raw_findings: rawFindings.length,
                total_transitions: transitions.length,
                total_verifier_decisions: verifierDecisions.length,
                total_proof_artifacts: proofArtifacts.length
            }
        };
    }
}
