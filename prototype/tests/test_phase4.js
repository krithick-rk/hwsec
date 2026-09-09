import assert from 'assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { BEPPackager } from '../workers/evidence/bepPackager.js';
import { BEPVerifier } from '../workers/evidence/bepVerifier.js';
import { DifferentialValidator } from '../workers/evidence/differentialValidator.js';
import { EvidenceContract } from '../workers/evidence/evidenceContract.js';

console.log('============================================================');
console.log('    HWSEC PHASE 4 DIFFERENTIAL VALIDATION & BEP GATE SUITE');
console.log('============================================================\n');

const packager = new BEPPackager();
const verifier = new BEPVerifier();
const contract = new EvidenceContract();

// 1. Gate 1: Differential Validation Across Representative Subset (6 CWEs)
console.log('[Gate 1] Executing Differential Validation Across Representative Subset (6 CWEs)...');
const subsetRes = packager.packageRepresentativeSubset();

assert.ok(subsetRes.results.length >= 7, `Expected at least 7 representative cases, got ${subsetRes.results.length}`);
console.log(`  -> [PASS] Executed differential validation on ${subsetRes.results.length} cases.`);

// 2. Gate 2: Schema Compliance with evidence-packet.schema.json and verdict.schema.json
console.log('\n[Gate 2] Validating Schema Compliance (evidence-packet.schema.json & verdict.schema.json)...');
const evidenceSchema = JSON.parse(fs.readFileSync('prototype/schemas/evidence-packet.schema.json', 'utf8'));
const verdictSchema = JSON.parse(fs.readFileSync('prototype/schemas/verdict.schema.json', 'utf8'));

for (const res of subsetRes.results) {
    const ep = res.evidence;
    const ev = res.verdict;

    // Check EvidencePacket required properties
    for (const req of evidenceSchema.required) {
        assert.ok(ep[req] !== undefined, `Case ${ep.case_id} EvidencePacket missing required property: ${req}`);
    }
    assert.strictEqual(typeof ep.case_id, 'string');
    assert.strictEqual(typeof ep.hypothesis, 'object');
    assert.strictEqual(typeof ep.static, 'object');
    assert.strictEqual(typeof ep.symbolic, 'object');
    assert.strictEqual(typeof ep.runtime, 'object');
    assert.strictEqual(typeof ep.differential, 'object');
    assert.strictEqual(typeof ep.security_condition, 'object');
    assert.strictEqual(typeof ep.provenance, 'object');

    // Check EvidenceVerdict required properties
    for (const req of verdictSchema.required) {
        assert.ok(ev[req] !== undefined, `Case ${ev.case_id} EvidenceVerdict missing required property: ${req}`);
    }
    assert.ok(['DETECTED', 'NOT_DETECTED', 'INCONCLUSIVE'].includes(ev.verdict), `Invalid verdict: ${ev.verdict}`);
    assert.strictEqual(typeof ev.reason_code, 'string');
    assert.strictEqual(typeof ev.required_evidence_items_passed, 'object');
    assert.strictEqual(typeof ev.evidence_hash, 'string');
}
console.log('  -> [PASS] 100% of generated EvidencePackets and Verdicts conform strictly to schemas.');

// 3. Gate 3: Deterministic Verdict Correctness & Discrimination
console.log('\n[Gate 3] Validating Deterministic Verdict Correctness (DETECTED vs NOT_DETECTED vs INCONCLUSIVE)...');
const case1 = subsetRes.results.find(r => r.case_id === 'BenchmarkTest00001');
const case63 = subsetRes.results.find(r => r.case_id === 'BenchmarkTest00063');

assert.ok(case1, 'BenchmarkTest00001 must exist');
assert.ok(case63, 'BenchmarkTest00063 must exist');

assert.strictEqual(case1.verdict.verdict, 'DETECTED', 'BenchmarkTest00001 must evaluate to DETECTED');
assert.strictEqual(case63.verdict.verdict, 'NOT_DETECTED', 'BenchmarkTest00063 must evaluate to NOT_DETECTED');

// Synthetic Incomplete/Timeout Case: must evaluate to INCONCLUSIVE without coercion
const syntheticTimeoutPacket = JSON.parse(JSON.stringify(case1.evidence));
syntheticTimeoutPacket.case_id = 'BenchmarkTestTimeout';
syntheticTimeoutPacket.runtime.timeout = true;
const timeoutVerdict = contract.evaluate(syntheticTimeoutPacket);
assert.strictEqual(timeoutVerdict.verdict, 'INCONCLUSIVE', 'Timeout case must evaluate to INCONCLUSIVE');
assert.notStrictEqual(timeoutVerdict.verdict, 'NOT_DETECTED', 'Timeout MUST NEVER be coerced into NOT_DETECTED/TN');
assert.notStrictEqual(timeoutVerdict.verdict, 'DETECTED', 'Timeout MUST NEVER be coerced into DETECTED/FP');
console.log('  -> [PASS] Verdict discrimination verified: BenchmarkTest00001=DETECTED, BenchmarkTest00063=NOT_DETECTED, Timeout=INCONCLUSIVE (never coerced).');

// 4. Gate 4: Security-Relevant Differential Observables (Not Mere API Invocation)
console.log('\n[Gate 4] Validating Security-Relevant Differential Observables...');
for (const res of subsetRes.results) {
    const diff = res.evidence.differential;
    assert.ok(diff.baseline_observed !== undefined, 'Must record baseline observation');
    assert.ok(diff.attack_observed !== undefined, 'Must record attack observation');
    assert.strictEqual(typeof diff.delta_detected, 'boolean');
    assert.ok(diff.security_relevant_observable.length > 0, 'Must record security-relevant observable type');
}

// Check that BenchmarkTest00001 exhibits canonical path escape observable
assert.strictEqual(case1.evidence.differential.security_relevant_observable, 'CANONICAL_PATH_ESCAPE');
assert.strictEqual(case1.evidence.differential.delta_detected, true);
assert.strictEqual(case1.evidence.differential.baseline_observed.security_condition_violated, false);
assert.strictEqual(case1.evidence.differential.attack_observed.security_condition_violated, true);

// Check that BenchmarkTest00063 maintains invariant on both baseline and attack
assert.strictEqual(case63.evidence.differential.delta_detected, false);
assert.strictEqual(case63.evidence.differential.baseline_observed.security_condition_violated, false);
assert.strictEqual(case63.evidence.differential.attack_observed.security_condition_violated, false);
console.log('  -> [PASS] Security observables verified: differential delta accurately discriminates condition violations.');

// 5. Gate 5: Machine-Checkable BEP Verification & Deterministic Replay
console.log('\n[Gate 5] Validating Machine-Checkable BEP Verification...');
for (const res of subsetRes.results) {
    const vResult = verifier.verifyBEP(res.bep);
    assert.strictEqual(vResult.valid, true, `Verification failed for ${res.case_id}: ${vResult.errors.join(', ')}`);
    assert.strictEqual(vResult.recalculated_verdict, res.verdict.verdict, 'Recalculated verdict must match declared verdict');
}
console.log('  -> [PASS] BEP Verifier successfully recalculated 100% of verdicts independently without LLM reliance.');

// 6. Gate 6: Adversarial Evidence Integrity & Tamper Resistance
console.log('\n[Gate 6] Testing Adversarial Evidence Integrity & Tamper Resistance...');

// Attack 1: Tampered Verdict Flag (claim DETECTED on a NOT_DETECTED bundle)
const tamperedVerdictBundle = JSON.parse(JSON.stringify(case63.bep));
tamperedVerdictBundle.verdict = 'DETECTED';
const tamperVerdictRes = verifier.verifyBEP(tamperedVerdictBundle);
assert.strictEqual(tamperVerdictRes.valid, false, 'Verifier must reject tampered verdict flag');
console.log('  -> [PASS] Adversarial tamper 1: Tampered verdict flag successfully detected and rejected.');

// Attack 2: Runtime Taint Claimed Without Trace
const noTraceBundle = JSON.parse(JSON.stringify(case1.bep));
noTraceBundle.evidence_packet.runtime.trace_hash = '';
const noTraceRes = verifier.verifyBEP(noTraceBundle);
assert.strictEqual(noTraceRes.valid, false, 'Verifier must reject taint claimed without trace hash');
console.log('  -> [PASS] Adversarial tamper 2: Taint without trace hash successfully detected and rejected.');

// Attack 3: Solver Status SAT Claimed Without Concrete Generated Input
const noInputBundle = JSON.parse(JSON.stringify(case1.bep));
noInputBundle.evidence_packet.symbolic.generated_input = null;
const noInputRes = verifier.verifyBEP(noInputBundle);
assert.strictEqual(noInputRes.valid, false, 'Verifier must reject SAT claimed without concrete input');
console.log('  -> [PASS] Adversarial tamper 3: SAT without concrete input successfully detected and rejected.');

// Attack 4: Missing Required Artifact File
const missingBundleRes = verifier.verifyBEP('prototype/artifacts/evidence/NonExistent_bep.json');
assert.strictEqual(missingBundleRes.valid, false);
assert.strictEqual(missingBundleRes.recalculated_verdict, 'INCONCLUSIVE');
console.log('  -> [PASS] Adversarial tamper 4: Missing artifact safely handled with fail-closed INCONCLUSIVE.');

// 7. Gate 7: Zero Credential or Secret Leakage in Phase 4 Artifacts
console.log('\n[Gate 7] Scanning Phase 4 Evidence Artifacts for Credentials and Secrets...');
const sensitivePatterns = [
    /nvapi-[a-zA-Z0-9_-]{20,}/i,
    /AIza[0-9A-Za-z-_]{35}/,
    /sk-[a-zA-Z0-9]{20,}/,
    /ghp_[a-zA-Z0-9]{20,}/
];

const evidenceDir = path.resolve('prototype/artifacts/evidence');
const entries = fs.readdirSync(evidenceDir, { withFileTypes: true });
for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith('.json')) {
        const full = path.join(evidenceDir, entry.name);
        const content = fs.readFileSync(full, 'utf8');
        for (const pattern of sensitivePatterns) {
            const match = content.match(pattern);
            if (match) {
                throw new Error(`Credential leaked in ${full}: ${match[0]}`);
            }
        }
    }
}
console.log('  -> [PASS] 0 credentials or secrets detected across Phase 4 artifacts.');

console.log('\n============================================================');
console.log('    [SUCCESS] ALL 7 PHASE 4 GATES PASSED (100% VERIFIED)');
console.log('============================================================\n');
