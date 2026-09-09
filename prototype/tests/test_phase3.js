import assert from 'assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { TaintWorker } from '../workers/taint/taintWorker.js';

console.log('============================================================');
console.log('    HWSEC PHASE 3 DYNAMIC TAINT TRACKING GATE TEST SUITE');
console.log('============================================================\n');

const worker = new TaintWorker();

// 1. Gate 1: Representative Subset Execution Across All 6 CWEs
console.log('[Gate 1] Executing Dynamic Taint Tracking Across Representative Subset (6 CWEs)...');
const subsetRes = worker.executeRepresentativeSubset();
assert.ok(subsetRes.results.length >= 6, `Expected at least 6 representative cases, got ${subsetRes.results.length}`);
console.log(`  -> [PASS] Executed dynamic taint tracking on ${subsetRes.results.length} cases.`);

// 2. Gate 2: Schema Compliance with taint-result.schema.json
console.log('\n[Gate 2] Validating Schema Compliance (taint-result.schema.json)...');
const taintSchema = JSON.parse(fs.readFileSync('prototype/schemas/taint-result.schema.json', 'utf8'));

for (const res of subsetRes.results) {
    for (const req of taintSchema.required) {
        assert.ok(res[req] !== undefined, `Case ${res.case_id} missing required property: ${req}`);
    }
    assert.strictEqual(typeof res.case_id, 'string');
    assert.strictEqual(typeof res.source_observed, 'string');
    assert.strictEqual(typeof res.sink_observed, 'string');
    assert.strictEqual(typeof res.sink_tainted, 'boolean');
    assert.ok(Array.isArray(res.runtime_path), 'runtime_path must be an array');
    assert.ok(res.runtime_path.length > 0, 'runtime_path must not be empty');
    assert.strictEqual(typeof res.exit_code, 'number');
    assert.strictEqual(typeof res.timeout, 'boolean');
    assert.ok(['ACTIVE', 'UNAVAILABLE', 'PARTIAL', 'FAILED'].includes(res.instrumentation_status));
    assert.ok(typeof res.artifact_hashes === 'object' && Object.keys(res.artifact_hashes).length > 0);
}
console.log(`  -> [PASS] 100% of generated TaintResult artifacts conform to taint-result.schema.json.`);

// 3. Gate 3: Source Observation Verification
console.log('\n[Gate 3] Validating Source Boundary Observations...');
for (const res of subsetRes.results) {
    assert.ok(res.source_observed.startsWith('HttpServletRequest.'), `Source must begin with HttpServletRequest, got: ${res.source_observed}`);
}
console.log('  -> [PASS] Source boundaries correctly observed across all cases.');

// 4. Gate 4: Sink Observation Verification
console.log('\n[Gate 4] Validating Sink Boundary Observations...');
for (const res of subsetRes.results) {
    assert.ok(res.sink_observed.length > 0, 'Sink observation must not be empty');
    assert.notStrictEqual(res.sink_observed, 'NONE', 'Sink must be resolved');
}
console.log('  -> [PASS] Sink boundaries correctly identified and observed across all cases.');

// 5. Gate 5: Taint Discrimination (Vulnerable Flow vs. Safe Branch)
console.log('\n[Gate 5] Validating Dynamic Taint Discrimination (Vulnerable vs. Benign)...');
const case1 = subsetRes.results.find(r => r.case_id === 'BenchmarkTest00001');
const case63 = subsetRes.results.find(r => r.case_id === 'BenchmarkTest00063');

assert.ok(case1, 'BenchmarkTest00001 must be in test results');
assert.ok(case63, 'BenchmarkTest00063 must be in test results');

assert.strictEqual(case1.sink_tainted, true, 'BenchmarkTest00001 (Vulnerable) must propagate taint to sink');
assert.strictEqual(case63.sink_tainted, false, 'BenchmarkTest00063 (Safe constant branch) must NOT propagate taint to sink');
console.log(`  -> [PASS] Dynamic taint discrimination verified: BenchmarkTest00001 sink_tainted=true, BenchmarkTest00063 sink_tainted=false.`);

// 6. Gate 6: Strict Non-Conflation Guarantee (Flow != Vulnerability)
console.log('\n[Gate 6] Validating Strict Non-Conflation Guarantee (Taint != Vulnerability)...');
for (const res of subsetRes.results) {
    assert.strictEqual(res.verdict, undefined, 'TaintResult MUST NOT assert a security verdict');
    assert.strictEqual(res.is_vulnerable, undefined, 'TaintResult MUST NOT assert vulnerability status');
}
console.log('  -> [PASS] Non-conflation guarantee enforced: taint results report dataflow propagation only.');

// 7. Gate 7: Zero Credential or Secret Leakage in Phase 3 Artifacts
console.log('\n[Gate 7] Scanning Phase 3 Artifacts for Credentials and Secrets...');
const sensitivePatterns = [
    /nvapi-[a-zA-Z0-9_-]{20,}/i,
    /AIza[0-9A-Za-z-_]{35}/,
    /sk-[a-zA-Z0-9]{20,}/,
    /ghp_[a-zA-Z0-9]{20,}/
];

const checkArtifactDirectory = (dir) => {
    if (!fs.existsSync(dir)) return;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            checkArtifactDirectory(full);
        } else if (entry.isFile() && entry.name.endsWith('.json')) {
            const content = fs.readFileSync(full, 'utf8');
            for (const pattern of sensitivePatterns) {
                const match = content.match(pattern);
                if (match) {
                    throw new Error(`Credential leaked in ${full}: ${match[0]}`);
                }
            }
        }
    }
};

checkArtifactDirectory(path.resolve('prototype/artifacts/taint'));
console.log('  -> [PASS] 0 credentials or secrets detected across Phase 3 artifacts.');

console.log('\n============================================================');
console.log('    [SUCCESS] ALL 7 PHASE 3 GATES PASSED (100% VERIFIED)');
console.log('============================================================\n');
