import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ConsoleSession, SessionManager, SessionPhase } from '../src/core/console/consoleSession.js';

console.log("=== Running Console Session & Persistence Tests ===");

const testDbPath = path.resolve('hwsec-output/test-session.db');
if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
}

// 1. ConsoleSession defaults
console.log("[Test 1] Testing ConsoleSession defaults...");
const session = new ConsoleSession();
assert(session.id.startsWith('HW-'), "Session ID must start with HW-");
assert.strictEqual(session.mode, 'STANDARD');
assert.strictEqual(session.llmStrategy, 'ADAPTIVE');
assert.strictEqual(session.povMode, 'ON-DETECTED');
assert.strictEqual(session.budget, 10.0);
assert.strictEqual(session.approvalPolicy, 'REQUIRED');
assert.strictEqual(session.status, SessionPhase.INITIALIZED);

// 2. Strict option validation
console.log("[Test 2] Testing strict option validation...");

// Mode validation
session.set('mode', 'DEEP');
assert.strictEqual(session.mode, 'DEEP');
assert.throws(() => session.set('mode', 'SUPER_DEEP'), /Invalid mode/);

// LLM strategy validation
session.set('llm', 'SCOUT');
assert.strictEqual(session.llmStrategy, 'SCOUT');
assert.throws(() => session.set('llm', 'QUANTUM'), /Invalid LLM strategy/);

// Budget validation
session.set('budget', '25.5');
assert.strictEqual(session.budget, 25.5);
assert.throws(() => session.set('budget', '-5'), /positive number/);
assert.throws(() => session.set('budget', 'abc'), /positive number/);

// Target validation
const fixturesDir = path.resolve('tests/fixtures');
session.set('target', fixturesDir);
assert.strictEqual(session.targetDir, fixturesDir);
assert.throws(() => session.set('target', 'non_existent_folder_xyz_123'), /does not exist/);

// Unset validation
session.set('context', fixturesDir);
assert.strictEqual(session.contextDir, fixturesDir);
session.unset('context');
assert.strictEqual(session.contextDir, null);
assert.throws(() => session.unset('mode'), /Cannot unset required option/);

// 3. SQLite persistence and session reload
console.log("[Test 3] Testing SQLite persistence and SessionManager...");
const manager1 = new SessionManager({ dbPath: testDbPath });
const activeSession = manager1.getActiveSession();
activeSession.set('target', fixturesDir);
activeSession.set('mode', 'FORENSIC');
activeSession.set('budget', '50');
manager1.persistActiveSession();

// Record history
manager1.recordHistory('set mode FORENSIC');
manager1.recordHistory('set budget 50');
manager1.recordHistory('run');

const history = manager1.getHistory();
assert.strictEqual(history.length, 3);
assert.strictEqual(history[0].command, 'set mode FORENSIC');

// Reload via new SessionManager instance
const manager2 = new SessionManager({ dbPath: testDbPath });
const loaded = manager2.loadSession(activeSession.id);
assert.strictEqual(loaded.id, activeSession.id);
assert.strictEqual(loaded.targetDir, fixturesDir);
assert.strictEqual(loaded.mode, 'FORENSIC');
assert.strictEqual(loaded.budget, 50);

const list = manager2.listSessions();
assert(list.length >= 1, "Must list at least one session");
assert.strictEqual(list[0].id, activeSession.id);

manager1.close();
manager2.close();

// Cleanup
if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
}

console.log("\n>>> ALL CONSOLE SESSION TESTS PASSED! <<<\n");
