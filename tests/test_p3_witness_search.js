import assert from 'assert';
import { WitnessSearchEngine } from '../src/core/witness/witnessSearch.js';
import { defaultSecurityRegistry } from '../src/core/oracles/securityConditionRegistry.js';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';

console.log("============================================================");
console.log("    HWSEC PHASE P3: WITNESS SEARCH & ORACLES TEST SUITE");
console.log("============================================================\n");

// Test 1: Typed Security Oracles (CWE-89, CWE-22, CWE-78, CWE-79)
console.log("[P3-Test 1] Testing Typed CWE Security Condition Oracles...");
const sqliOracle = defaultSecurityRegistry.getOracle('CWE-89');
const pathOracle = defaultSecurityRegistry.getOracle('CWE-22');
const cmdiOracle = defaultSecurityRegistry.getOracle('CWE-78');
const xssOracle = defaultSecurityRegistry.getOracle('CWE-79');

// SQLi test
const sqliViolated = sqliOracle.evaluate({ parsed_result: { sql_query: "SELECT * FROM users WHERE name = '' OR '1'='1'" } }, { value: "' OR '1'='1" });
assert.strictEqual(sqliViolated.condition_satisfied, true);
const sqliSafe = sqliOracle.evaluate({ parsed_result: { sql_query: "SELECT * FROM users WHERE name = 'alice'" } }, { value: "alice" });
assert.strictEqual(sqliSafe.condition_satisfied, false);

// Path traversal test
const pathViolated = pathOracle.evaluate({ parsed_result: { canonical_path: "/etc/passwd", base_directory: "/var/app/data" } }, { value: "../../etc/passwd" });
assert.strictEqual(pathViolated.condition_satisfied, true);
const pathSafe = pathOracle.evaluate({ parsed_result: { canonical_path: "/var/app/data/file.txt", base_directory: "/var/app/data" } }, { value: "file.txt" });
assert.strictEqual(pathSafe.condition_satisfied, false);

// Command injection test
const cmdiViolated = cmdiOracle.evaluate({ stdout: "INJECTED_CMD_OUTPUT\nuid=1000" }, { value: "hello; echo INJECTED_CMD_OUTPUT" });
assert.strictEqual(cmdiViolated.condition_satisfied, true);
const cmdiSafe = cmdiOracle.evaluate({ stdout: "Processing hello..." }, { value: "hello" });
assert.strictEqual(cmdiSafe.condition_satisfied, false);

// XSS test
const xssViolated = xssOracle.evaluate({ parsed_result: { response_body: "<div>Hello <script>alert(1)</script></div>" } }, { value: "<script>alert(1)</script>" });
assert.strictEqual(xssViolated.condition_satisfied, true);
const xssSafe = xssOracle.evaluate({ parsed_result: { response_body: "<div>Hello &lt;script&gt;</div>" } }, { value: "<script>" });
assert.strictEqual(xssSafe.condition_satisfied, false);

console.log("  -> [PASS] All 4 CWE Security Oracles correctly distinguish exploit vs safe conditions.");

// Test 2: Budgeted Witness Search on Vulnerable Target
console.log("\n[P3-Test 2] Testing Budgeted Witness Search -> WITNESS_FOUND...");
const searchEngine = new WitnessSearchEngine({ maxExecutions: 10 });
const sqliHyp = new VulnerabilityHypothesis({
    cwe: 'CWE-89',
    security_condition: 'SQLiOracle',
    source: 'id',
    sink: 'stmt.executeQuery'
});

// Mock runner simulating vulnerable query concatenation
const vulnSqlRunner = async (probe) => {
    const rawSql = `SELECT * FROM items WHERE id = '${probe.value}'`;
    return {
        exitCode: 0,
        parsed_result: { sql_query: rawSql },
        stdout: `Executed: ${rawSql}`
    };
};

const searchResult = await searchEngine.searchWitness(sqliHyp, vulnSqlRunner);
assert.strictEqual(searchResult.status, 'WITNESS_FOUND');
assert.ok(searchResult.witness_input);
assert.strictEqual(searchResult.oracle_result.condition_satisfied, true);
assert.ok(searchResult.search_metrics.execution_count <= 10);
console.log(`  -> [PASS] Witness found in ${searchResult.search_metrics.execution_count} attempts: ${searchResult.witness_input.value}`);

// Test 3: Budgeted Witness Search on Sanitized/Safe Target
console.log("\n[P3-Test 3] Testing Budgeted Witness Search on Safe Target -> BUDGET_EXHAUSTED...");
const safeSqlRunner = async (probe) => {
    // Parameterized / sanitized execution
    const sanitized = probe.value.replace(/'/g, "''");
    return {
        exitCode: 0,
        parsed_result: { sql_query: `SELECT * FROM items WHERE id = ?`, parameters: [sanitized], is_parameterized: true },
        stdout: `Executed safely.`
    };
};

const safeResult = await searchEngine.searchWitness(sqliHyp, safeSqlRunner, { maxExecutions: 5 });
assert.strictEqual(safeResult.status, 'SEARCH_BUDGET_EXHAUSTED');
assert.strictEqual(safeResult.witness_input, null);
assert.strictEqual(safeResult.search_metrics.execution_count, 5);
assert.strictEqual(safeResult.search_metrics.termination_reason, 'MAX_EXECUTIONS_REACHED');
console.log("  -> [PASS] Exhausted search returns explicit bounded reason without false positive.");

console.log("\n============================================================");
console.log("    [SUCCESS] ALL P3 WITNESS SEARCH & ORACLE TESTS PASSED");
console.log("============================================================\n");
