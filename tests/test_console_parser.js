import assert from 'assert';
import { ConsoleParser } from '../src/core/console/consoleParser.js';

console.log("=== Running Console Parser Unit Tests ===");

// 1. Basic tokenization
console.log("[Test 1] Basic tokenization...");
const tokens1 = ConsoleParser.tokenize('set mode DEEP');
assert.deepStrictEqual(tokens1, ['set', 'mode', 'DEEP']);

// 2. Double quotes with spaces
console.log("[Test 2] Double quotes with spaces...");
const tokens2 = ConsoleParser.tokenize('set target "C:\\My Documents\\Project Alpha"');
assert.deepStrictEqual(tokens2, ['set', 'target', 'C:\\My Documents\\Project Alpha']);

// 3. Single quotes with spaces
console.log("[Test 3] Single quotes with spaces...");
const tokens3 = ConsoleParser.tokenize("set context 'E:\\Context Dir\\data'");
assert.deepStrictEqual(tokens3, ['set', 'context', 'E:\\Context Dir\\data']);

// 4. Escaped quotes
console.log("[Test 4] Escaped characters...");
const tokens4 = ConsoleParser.tokenize('set test "hello \\"world\\""');
assert.deepStrictEqual(tokens4, ['set', 'test', 'hello "world"']);

// 5. Command and subcommand parsing
console.log("[Test 5] Command and subcommand parsing...");
const p1 = ConsoleParser.parse('show options');
assert.strictEqual(p1.command, 'show');
assert.strictEqual(p1.subcommand, 'options');

const p2 = ConsoleParser.parse('inspect hypothesis HYP-001');
assert.strictEqual(p2.command, 'inspect');
assert.strictEqual(p2.subcommand, 'hypothesis');
assert.deepStrictEqual(p2.args, ['HYP-001']);

const p3 = ConsoleParser.parse('doctor execution');
assert.strictEqual(p3.command, 'doctor');
assert.strictEqual(p3.subcommand, 'execution');

const p4 = ConsoleParser.parse('pov replay BUNDLE-01');
assert.strictEqual(p4.command, 'pov');
assert.strictEqual(p4.subcommand, 'replay');
assert.deepStrictEqual(p4.args, ['BUNDLE-01']);

// 6. Sensitive token redaction
console.log("[Test 6] Sensitive token redaction...");
const redacted = ConsoleParser.redactSensitive('set api_key secret_token_12345');
assert(!redacted.includes('secret_token_12345'), 'Must redact token');
assert(redacted.includes('********'), 'Must contain mask');

// 7. Empty and whitespace handling
console.log("[Test 7] Empty input handling...");
const pEmpty = ConsoleParser.parse('   ');
assert.strictEqual(pEmpty.command, '');
assert.strictEqual(pEmpty.subcommand, null);
assert.deepStrictEqual(pEmpty.args, []);

console.log("\n>>> ALL CONSOLE PARSER TESTS PASSED! <<<\n");
