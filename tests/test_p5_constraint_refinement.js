import assert from 'assert';
import { ConstraintRefinementProvider } from '../src/core/refinement/constraintRefinementProvider.js';

console.log("============================================================");
console.log("    HWSEC PHASE P5: CONSTRAINT REFINEMENT TEST SUITE");
console.log("============================================================\n");

const solver = new ConstraintRefinementProvider();

// Test 1: Integer Constraint System Solving
console.log("[P5-Test 1] Testing Integer Constraint Solving...");
const intConstraints = [
    { var: 'port', op: '>', val: '1024', type: 'integer' },
    { var: 'auth_id', op: '==', val: '42', type: 'integer' }
];

const intResult = await solver.solve({ slice_id: 'slice_1' }, { cwe: 'CWE-89' }, intConstraints);
assert.strictEqual(intResult.status, 'SAT');
assert.ok(intResult.concrete_input);
assert.ok(intResult.model_artifact.model_variables.port > 1024);
assert.strictEqual(intResult.model_artifact.model_variables.auth_id, 42);
console.log(`  -> [PASS] Integer model extracted: port=${intResult.model_artifact.model_variables.port}, auth_id=42`);

// Test 2: String Path Constraint Solving
console.log("\n[P5-Test 2] Testing String Constraint Solving...");
const strConstraints = [
    { var: 'filepath', op: 'startsWith', val: 'etc/passwd', type: 'string' }
];

const strResult = await solver.solve({ slice_id: 'slice_2' }, { cwe: 'CWE-22' }, strConstraints);
assert.strictEqual(strResult.status, 'SAT');
assert.ok(strResult.concrete_input.value.startsWith('etc/passwd'));
console.log(`  -> [PASS] String model extracted: filepath='${strResult.concrete_input.value}'`);

// Test 3: Contradictory / UNSAT Constraint System
console.log("\n[P5-Test 3] Testing Contradictory Constraint System -> UNSAT...");
const unsatConstraints = [
    { var: 'x', op: 'UNSAT_CONFLICT', val: '0', type: 'integer' }
];

const unsatResult = await solver.solve({ slice_id: 'slice_3' }, { cwe: 'CWE-78' }, unsatConstraints);
assert.strictEqual(unsatResult.status, 'UNSAT');
assert.strictEqual(unsatResult.concrete_input, null, "UNSAT must not fabricate concrete input");
console.log("  -> [PASS] Contradictory constraints correctly resolved as UNSAT without synthetic input.");

// Test 4: Empty Constraints -> UNKNOWN
console.log("\n[P5-Test 4] Testing Empty Constraints -> UNKNOWN...");
const emptyResult = await solver.solve({ slice_id: 'slice_4' }, { cwe: 'CWE-79' }, []);
assert.strictEqual(emptyResult.status, 'UNKNOWN');
assert.strictEqual(emptyResult.concrete_input, null);
console.log("  -> [PASS] Empty constraint input returns UNKNOWN.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P5 CONSTRAINT REFINEMENT TESTS PASSED");
console.log("============================================================\n");
