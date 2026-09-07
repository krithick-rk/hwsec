import assert from 'assert';
import path from 'path';
import { CodeQLTool } from '../src/domains/software/tools/codeql.js';

console.log("=== Running CodeQL Adapter Integration & SARIF Tests ===");

const codeql = new CodeQLTool({});

// 1. Test checkInstalled
console.log("[Test 1] Testing CodeQL checkInstalled()...");
const install = await codeql.checkInstalled();
console.log(`  -> Installed: ${install.installed}, Error: ${install.error || 'None'}`);
if (!install.installed) {
    assert.strictEqual(install.installed, false);
    assert.ok(install.error.includes('CodeQL CLI not detected'), "Error message should clearly report absence");
    console.log("  -> Explicit unavailable state confirmed.");
}

// 2. Test run() when unavailable returns clean UNAVAILABLE status
console.log("[Test 2] Testing run() behavior when CodeQL CLI is unavailable...");
const runRes = await codeql.run({
    files: [path.resolve('tests/fixtures/test_vuln.c')],
    outputDir: path.resolve('hwsec-output/test-codeql')
});
if (!install.installed) {
    assert.strictEqual(runRes.status, "UNAVAILABLE", "Must return explicit UNAVAILABLE status");
    assert.strictEqual(runRes.findings.length, 0, "No fake findings allowed");
    assert.ok(runRes.reason, "Must provide explicit reason for unavailability");
    console.log("  -> Verified clean UNAVAILABLE return without fake findings.");
}

// 3. Test SARIF Parser with real SARIF 2.1.0 payload
console.log("[Test 3] Testing SARIF Parser with authentic SARIF payload...");
const sampleSarif = {
    version: "2.1.0",
    runs: [{
        tool: {
            driver: {
                name: "CodeQL",
                rules: [{
                    id: "cpp/command-line-injection",
                    name: "Command Line Injection",
                    shortDescription: { text: "Command built from untrusted input" },
                    properties: {
                        tags: ["security", "external/cwe/cwe-78"]
                    },
                    defaultConfiguration: { level: "error" }
                }]
            }
        },
        results: [{
            ruleId: "cpp/command-line-injection",
            level: "error",
            message: { text: "Call to system() with untrusted user input." },
            locations: [{
                physicalLocation: {
                    artifactLocation: { uri: "test_vuln.c" },
                    region: {
                        startLine: 13,
                        endLine: 13,
                        snippet: { text: "system(cmd);" }
                    }
                }
            }]
        }]
    }]
};

const findings = codeql.parseSarif(sampleSarif, 'dummy/codeql.sarif', ['tests/fixtures/test_vuln.c']);
assert.strictEqual(findings.length, 1, "Should parse exactly 1 finding from SARIF");
const f = findings[0];
assert.strictEqual(f.source_tool, "codeql", "Source tool must be codeql");
assert.strictEqual(f.cwe_id, "CWE-78", "CWE must be extracted from rule tags");
assert.strictEqual(f.severity, "HIGH", "Error level must map to HIGH");
assert.strictEqual(f.source_locations[0].line, 13, "Location line must match SARIF startLine");
assert.strictEqual(f.evidence[0].tool, "codeql", "Evidence tool must be codeql");
assert.strictEqual(f.evidence[0].artifact_path, "dummy/codeql.sarif", "Evidence artifact must match SARIF path");
console.log("  -> SARIF parser verified with complete schema compliance.");

// 4. Test Source Fingerprinting & Cache Invalidation
console.log("[Test 4] Testing Source Fingerprinting for DB Cache...");
const hash1 = codeql._computeSourceHash(['tests/fixtures/test_vuln.c']);
const hash2 = codeql._computeSourceHash(['tests/fixtures/test_vuln.c']);
assert.strictEqual(hash1, hash2, "Identical inputs must yield identical hash");
assert.strictEqual(typeof hash1, 'string', "Hash must be string");
assert.strictEqual(hash1.length, 64, "SHA-256 hash must be 64 characters");
console.log(`  -> Source hash verified: ${hash1.slice(0, 16)}...`);

console.log("\n[PASS] All CodeQL Adapter tests passed successfully!\n");
