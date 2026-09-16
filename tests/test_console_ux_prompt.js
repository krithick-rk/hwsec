import assert from 'assert';
import path from 'path';
import fs from 'fs';
import { ConsoleApp } from '../src/core/console/consoleApp.js';
import { ConsoleInspectors } from '../src/core/console/inspectors.js';
import { DiagnosticsFacade } from '../src/core/console/diagnostics.js';
import { SessionPhase } from '../src/core/console/consoleSession.js';

console.log("=== Running Comprehensive Console UX Acceptance Test (PDF Specs) ===");

const fixturesDir = path.resolve('tests/fixtures');
const testOutputDir = path.resolve('hwsec-output/test-console-ux');

if (fs.existsSync(testOutputDir)) {
    fs.rmSync(testOutputDir, { recursive: true, force: true });
}

// 1. Verify ASCII Key Banner and Startup Readiness
console.log("\n[Test 1] Key Motif ASCII Banner & Startup Readiness...");
const banner = ConsoleInspectors.formatBanner();
assert(banner.includes('H W S E C'), "Banner must include HWSEC logo");
assert(banner.includes('====>'), "Banner must have key shape");

const diagnostics = new DiagnosticsFacade({});
const readiness = await diagnostics.checkStartupReadiness();
assert.strictEqual(readiness.engine, 'READY');
assert.strictEqual(readiness.evidenceAuthority, 'READY');
assert.strictEqual(readiness.executionBroker, 'READY');
assert.strictEqual(readiness.providerPool, 'READY');
assert.strictEqual(readiness.workspaceManager, 'READY');

const summary = ConsoleInspectors.formatStartupSummary(readiness);
assert(summary.includes('[+] HWSEC engine READY'));
assert(summary.includes('[+] EvidenceAuthority READY'));
assert(summary.includes('[+] Execution Broker READY'));
assert(summary.includes('[+] Provider Pool READY'));
assert(summary.includes('[+] Workspace Manager READY'));
console.log("  -> Banner and startup readiness checks PASS");

// 2. Initialize ConsoleApp in non-interactive test mode
const app = new ConsoleApp({
    outputDir: testOutputDir,
    skipOnboarding: true
});

// 3. Test Direct Configuration Commands (Section 5)
console.log("\n[Test 2] Direct Configuration Commands & Immediate Validation...");
await app.executeCommand(`set target "${fixturesDir}"`);
await app.executeCommand('set context "' + fixturesDir + '"');
await app.executeCommand('set mode DEEP');
await app.executeCommand('set llm ADAPTIVE');
await app.executeCommand('set pov ON-DETECTED');
await app.executeCommand('set budget 20');
await app.executeCommand('set approval REQUIRED');

assert.strictEqual(app.session.targetDir, fixturesDir);
assert.strictEqual(app.session.contextDir, fixturesDir);
assert.strictEqual(app.session.mode, 'DEEP');
assert.strictEqual(app.session.llmStrategy, 'ADAPTIVE');
assert.strictEqual(app.session.povMode, 'ON-DETECTED');
assert.strictEqual(app.session.budget, 20);
assert.strictEqual(app.session.approvalPolicy, 'REQUIRED');

// Strict validation test: invalid mode should fail safely
let invalidCaught = false;
try {
    app.session.set('mode', 'SUPER_DEEP');
} catch (err) {
    invalidCaught = true;
    assert(err.message.includes('Allowed: FAST, STANDARD, DEEP, FORENSIC'));
}
assert(invalidCaught, "Invalid mode must be rejected with allowed options shown");
console.log("  -> Direct configuration commands and validation PASS");

// 4. Test Tool Path & Environment Overrides (Section 8)
console.log("\n[Test 3] Flexible Tool Path and Environment Configuration...");
const fakeYosys = path.resolve('tests/fixtures/fake_yosys.exe');
await app.executeCommand(`set tool.yosys.path "${fakeYosys}"`);
assert.strictEqual(app.session.toolPaths?.yosys, fakeYosys);
assert.strictEqual(app.config.tool_paths?.yosys, fakeYosys);

await app.executeCommand('set OSS_CAD_SUITE "E:\\fake\\oss-cad-suite"');
assert.strictEqual(process.env.OSS_CAD_SUITE, 'E:\\fake\\oss-cad-suite');
console.log("  -> Tool path and environment configuration PASS");

// 5. Test Toolchain Status Center (Section 7)
console.log("\n[Test 4] Toolchain Status Center (`tools` & `doctor`)...");
const toolStatus = await app.diagnostics.getToolchainStatus();
assert(Array.isArray(toolStatus.core), "Must have CORE section");
assert(Array.isArray(toolStatus.software), "Must have SOFTWARE section");
assert(Array.isArray(toolStatus.hardware), "Must have HARDWARE section");
assert(Array.isArray(toolStatus.infrastructure), "Must have INFRASTRUCTURE section");

const formattedTools = ConsoleInspectors.formatToolsStatus(toolStatus);
assert(formattedTools.includes('HWSEC TOOLCHAIN STATUS'));
assert(formattedTools.includes('CORE'));
assert(formattedTools.includes('SOFTWARE'));
assert(formattedTools.includes('HARDWARE'));
assert(formattedTools.includes('INFRASTRUCTURE'));
assert(formattedTools.includes('Use `doctor <tool>` for details.'));

// Doctor tool detail
const yosysDoctor = await app.diagnostics.runDoctor('yosys', []);
assert(yosysDoctor.includes('TOOL: yosys'));
assert(yosysDoctor.includes('Capability :'));
assert(yosysDoctor.includes('Actions:'));
assert(yosysDoctor.includes('doctor yosys --test'));
assert(yosysDoctor.includes('set tool.yosys.path'));

// Test doctor execution diagnostics
const execDoctor = await app.diagnostics.runDoctor('execution', []);
assert(execDoctor.includes('[+] EXECUTION CAPABILITIES:'));
console.log("  -> Toolchain status and doctor diagnostics PASS");

// 6. Test Provider Area & Masked Key Rotation (Sections 9 & 10)
console.log("\n[Test 5] Provider Status, Configuration & Masked Rotation...");
const providersOut = await app.diagnostics.formatProviders();
assert(providersOut.includes('LLM PROVIDERS'));
assert(providersOut.includes('Gemini-1'));
assert(providersOut.includes('role : Fast Scout'));
assert(providersOut.includes('NVIDIA'));
assert(providersOut.includes('role : Deep Reasoner'));
assert(providersOut.includes('OpenRouter'));

// Rotate credential with fake key and verify key is never exposed in output or history
const fakeKey = "test-secret-key-xyz-987";
app.askMasked = async () => fakeKey;
await app.executeCommand('providers rotate gemini-2');

const history = app.sessionManager.getHistory(5);
const lastHistory = history[history.length - 1];
assert(!lastHistory.command.includes(fakeKey), "Secret key must never leak into command history");
console.log("  -> Provider management and secret scrubbing PASS");

// 7. Test Status Command with Brain Visibility (Sections 11 & 12)
console.log("\n[Test 6] LLM Brain Visibility & Session Status (`status`)...");
const statusOut = await ConsoleInspectors.formatStatus(app.session, null, app.diagnostics);
assert(statusOut.includes('BRAIN / ORCHESTRATION'));
assert(statusOut.includes('Mode : ADAPTIVE'));
assert(statusOut.includes('Current phase :'));
assert(statusOut.includes('Active hypothesis :'));
assert(statusOut.includes('Scout :'));
assert(statusOut.includes('Critic :'));
assert(statusOut.includes('Deep reasoner :'));
assert(statusOut.includes('Worker activity'));
assert(statusOut.includes('Operational state'));
assert(statusOut.includes('SESSION'));
assert(statusOut.includes('EXECUTION'));
assert(statusOut.includes('SECURITY'));
assert(statusOut.includes('Network : BLOCKED'));
assert(statusOut.includes('PoV integrity : ENABLED'));
console.log("  -> Status command with brain visibility PASS");

// 8. Test Structured Help Command (Section 14)
console.log("\n[Test 7] Help System Verification (Section 14)...");
let helpText = '';
const originalLog = console.log;
console.log = (...args) => {
    helpText += args.join(' ') + '\n';
};
try {
    app.renderHelp();
} finally {
    console.log = originalLog;
}

assert(helpText.includes('CORE'));
assert(helpText.includes('menu'));
assert(helpText.includes('ANALYSIS'));
assert(helpText.includes('run'));
assert(helpText.includes('plan'));
assert(helpText.includes('approve'));
assert(helpText.includes('proceed'));
assert(helpText.includes('LLM / TOOLS'));
assert(helpText.includes('providers'));
assert(helpText.includes('tools'));
assert(helpText.includes('doctor'));
assert(helpText.includes('ARTIFACTS'));
assert(helpText.includes('evidence'));
assert(helpText.includes('pov'));
assert(helpText.includes('dossier'));
assert(helpText.includes('report'));
assert(helpText.includes('SESSION'));
assert(helpText.includes('workspace'));
assert(helpText.includes('history'));
assert(helpText.includes('reset'));
assert(helpText.includes('exit'));
console.log("  -> Structured help system PASS");

// 9. Test Interactive Menus Navigation (Guided Setup & Settings Menu)
console.log("\n[Test 8] Interactive Menus & Navigation (Options, Back, Defaults)...");
// Simulate choosing '9' (Start with defaults) in session setup menu
app.ask = async (q) => {
    if (q.includes('Select option [9]')) return '9';
    return '';
};
await app.runSessionSetupMenu();

// Simulate choosing '0' (Back) in settings menu
app.ask = async (q) => {
    if (q.includes('Select:')) return '0';
    return '';
};
await app.renderSettingsMenu();

// Simulate choosing '0' (Back) in tools config menu
await app.handleToolsConfigMenu();

// Simulate choosing '0' (Back) in providers configure menu
await app.handleProvidersConfigureMenu();
console.log("  -> Menu navigation and exit/back options PASS");

// Clean up
app.close();

console.log("\n>>> ALL CONSOLE UX ACCEPTANCE TESTS PASSED SUCCESSFULLY! <<<\n");
