import assert from 'assert';
import { DirectSinkObservationProvider, GaletteObservationProvider } from '../src/core/observation/runtimeObservationProvider.js';

console.log("============================================================");
console.log("    HWSEC PHASE P6: RUNTIME OBSERVATION PROVIDERS TEST SUITE");
console.log("============================================================\n");

// Test 1: DirectSinkObservationProvider Default Execution
console.log("[P6-Test 1] Testing DirectSinkObservationProvider Default Behavior...");
const directObserver = new DirectSinkObservationProvider();
const mockTarget = { target_id: 'target_1', cwe: 'CWE-89' };
const inputProbe = { parameter: 'query', value: "' OR 1=1" };

const mockExec = async (probe) => ({
    exitCode: 0,
    parsed_result: {
        sink_observed: 'java.sql.Statement.executeQuery',
        value_at_sink: probe.value,
        security_effect: 'SQL_AST_ALTERED'
    },
    stdout: `Executing query with param: ${probe.value}`
});

const obsResult = await directObserver.observe(mockTarget, inputProbe, mockExec);
assert.strictEqual(obsResult.sink_observed, 'java.sql.Statement.executeQuery');
assert.strictEqual(obsResult.sink_tainted, true);
assert.strictEqual(obsResult.provenance.observer_type, 'DIRECT_SINK_OBSERVER');
assert.strictEqual(obsResult.provenance.agent_backed, false);
assert.ok(obsResult.observation_hash);
console.log("  -> [PASS] Direct sink observer cleanly captured sink effect without JVM agent.");

// Test 2: Galette Provider Fail-Closed on Unverified Agent
console.log("\n[P6-Test 2] Testing Galette Provider Fail-Closed on Unverified Agent...");
const unverifiedGalette = new GaletteObservationProvider({ agentLoaded: false });
const unverifiedResult = await unverifiedGalette.observe(mockTarget, inputProbe, mockExec);

assert.strictEqual(unverifiedResult.status, 'PROVIDER_UNAVAILABLE');
assert.strictEqual(unverifiedResult.provenance.verified, false);
console.log("  -> [PASS] Unverified Galette agent fails closed honestly.");

// Test 3: Verified Pluggable Taint Provider
console.log("\n[P6-Test 3] Testing Verified Pluggable Taint Provider Execution...");
const verifiedGalette = new GaletteObservationProvider({ agentLoaded: true });
const galetteExec = async (probe, opts) => ({
    exitCode: 0,
    sink_observed: 'PreparedStatement.execute',
    sink_tainted: true,
    taint_labels: ['GALETTE_TAG_01']
});

const galetteResult = await verifiedGalette.observe(mockTarget, inputProbe, galetteExec);
assert.strictEqual(galetteResult.status, 'ACTIVE');
assert.strictEqual(galetteResult.sink_tainted, true);
assert.strictEqual(galetteResult.provenance.agent_backed, true);
console.log("  -> [PASS] Verified pluggable taint provider cleanly integrates.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P6 OBSERVATION PROVIDER TESTS PASSED");
console.log("============================================================\n");
