import assert from 'assert';
import { createFinding, createEvidence, createSourceLocation, migrateFinding, Severity, VerificationState, SCHEMA_VERSION } from '../src/core/schema.js';

console.log('=== Running WP6: Versioned Generalized Finding & Evidence Schema Tests ===');

// Test 1: Generalized Source Location & Finding Creation
console.log('[Test 1] Testing Generalized Finding Creation...');
const finding = createFinding({
    id: 'FIND-001',
    title: 'SQL Injection in User Service',
    description: 'Direct string concatenation in SQL query.',
    severity: Severity.HIGH,
    confidence: 0.9,
    source_locations: [
        { path: 'src/services/user.py', startLine: 42, endLine: 45, symbol: 'get_user' }
    ],
    security_property: 'Database Query Sanitization',
    verification_state: VerificationState.CANDIDATE
});

assert.strictEqual(finding.schema_version, SCHEMA_VERSION);
assert.strictEqual(finding.id, 'FIND-001');
assert.strictEqual(finding.source_locations.length, 1);
assert.strictEqual(finding.source_locations[0].path, 'src/services/user.py');
assert.strictEqual(finding.source_locations[0].startLine, 42);
assert.strictEqual(finding.source_locations[0].symbol, 'get_user');
// Backwards compatibility check
assert.strictEqual(finding.rtl_location, 'src/services/user.py:42');
console.log('  -> Generalized finding creation and backwards compatibility verified.');

// Test 2: Structured Evidence Creation
console.log('[Test 2] Testing Structured Evidence Creation...');
const evidence = createEvidence({
    id: 'EV-001',
    tool: 'semgrep',
    artifact_path: 'hwsec-output/tools/semgrep_telemetry.json',
    artifact_hash: 'abc123hash',
    observation: 'Matched rule sql-injection at line 42',
    raw_evidence: { line: 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")' }
});

assert.strictEqual(evidence.id, 'EV-001');
assert.strictEqual(evidence.tool, 'semgrep');
assert.strictEqual(evidence.validity_status, 'VALID');
assert.ok(evidence.timestamp);
console.log('  -> Structured evidence model verified.');

// Test 3: Legacy RTL Finding Migration
console.log('[Test 3] Testing Legacy Finding Migration...');
const legacy = {
    id: 'LEGACY-001',
    title: 'Verilator Width Warning',
    description: 'Operator expects 8 bits, got 1 bit',
    severity: 'LOW',
    source_tool: 'verilator',
    rtl_location: 'E:/Intern/hwsec/dummy_rtl/top.v:10'
};

const migrated = migrateFinding(legacy);
assert.strictEqual(migrated.schema_version, SCHEMA_VERSION);
assert.strictEqual(migrated.source_locations.length, 1);
assert.strictEqual(migrated.source_locations[0].path, 'E:/Intern/hwsec/dummy_rtl/top.v');
assert.strictEqual(migrated.source_locations[0].startLine, 10);
assert.strictEqual(migrated.rtl_location, 'E:/Intern/hwsec/dummy_rtl/top.v:10');
console.log('  -> Legacy finding migration verified without data loss.');

console.log('\n[PASS] All WP6 Schema / Evidence tests passed successfully!\n');
