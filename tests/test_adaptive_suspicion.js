import assert from 'assert';
import { SuspicionEngine } from '../src/core/suspicion/engine.js';
import { DisagreementDetector } from '../src/core/suspicion/disagreement.js';
import { createFinding, Severity } from '../src/core/schema.js';

console.log("=== Running Adaptive Suspicion & Disagreement Escalation Tests ===");

const engine = new SuspicionEngine();
const detector = new DisagreementDetector();

// 1. Test Analysis Depth Allocation
console.log("[Test 1] Testing Adaptive Analysis Depth Decisions...");
// Clean target -> LOW -> BASELINE_ONLY
const cleanTarget = engine.scoreTarget({
    path: 'clean_utils.c',
    content: 'int add(int a, int b) { return a + b; }',
    findings: [],
    executedTools: ['semgrep']
});
assert.strictEqual(cleanTarget.priority, 'LOW');
assert.strictEqual(cleanTarget.analysis_depth, 'BASELINE_ONLY');
console.log("  -> Clean target -> BASELINE_ONLY verified.");

// Suspicious target with critical findings -> CRITICAL -> TARGETED_FORMAL_LLM
const criticalFinding = createFinding({
    id: 'F-CRIT',
    title: 'Arbitrary Command Execution',
    severity: Severity.CRITICAL,
    source_locations: [{ path: 'vulnerable.py', line: 15 }]
});
const critTarget = engine.scoreTarget({
    path: 'vulnerable.py',
    content: 'def run_command(payload):\n    os.system(payload)\n',
    findings: [criticalFinding],
    executedTools: ['semgrep', 'joern'],
    graphData: { inDegree: 2, outDegree: 1, crossesBoundary: true },
    noveltyMode: 'deep'
});
assert.strictEqual(critTarget.priority, 'CRITICAL');
assert.strictEqual(critTarget.analysis_depth, 'TARGETED_FORMAL_LLM');
console.log("  -> Critical target -> TARGETED_FORMAL_LLM verified.");

// 2. Test Analyzer Disagreement Escalation
console.log("[Test 2] Testing Analyzer Disagreement Escalation...");
const controllerFinding = createFinding({
    id: 'F-CTRL',
    title: 'Command Execution in Controller',
    severity: Severity.CRITICAL,
    source_tool: 'semgrep',
    source_locations: [{ path: 'controller.c', line: 15 }]
});
const disagreement = detector.detect('controller.c', [controllerFinding], ['semgrep', 'codeql', 'joern']);
assert.strictEqual(disagreement.hasDisagreement, true, "Disagreement must be flagged when semgrep reports but codeql & joern are silent");
assert.ok(disagreement.disagreementScore > 0, "Disagreement score must be positive");
assert.ok(disagreement.reason.includes('Tool disagreement'), "Reason must explain conflict");
console.log(`  -> Disagreement successfully detected: ${disagreement.reason}`);

// Target score with disagreement must be elevated
const targetWithDisagreement = engine.scoreTarget({
    path: 'controller.c',
    content: 'void handle_req() { return; }',
    findings: [controllerFinding],
    executedTools: ['semgrep', 'codeql', 'joern']
});
assert.ok(targetWithDisagreement.signals.analyzer_disagreement.hasDisagreement, "Signal must include analyzer disagreement");
assert.ok(targetWithDisagreement.suspicion_score > 0.40, "Disagreement must escalate suspicion score");
console.log(`  -> Suspicion score escalated to ${targetWithDisagreement.suspicion_score} with depth: ${targetWithDisagreement.analysis_depth}`);

console.log("\n[PASS] All Adaptive Suspicion tests passed successfully!\n");
