import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

console.log('============================================================');
console.log('   HWSEC PHASE 9 & 17: DIFFERENTIAL & INTEGRITY SUITE       ');
console.log('============================================================\n');

const povSourceDir = path.resolve('hwsec-output', 'benchmark_pov_matrix', 'python', 'POV-PYTHON-d00eda9f');
const testWorkDir = path.resolve('experiments', 'autonomous_validation', 'integrity_test');
const fixedTargetDir = path.resolve('experiments', 'autonomous_validation', 'targets', 'safe', 'target-05', 'app.py');

fs.mkdirSync(testWorkDir, { recursive: true });

// Copy PoV bundle to testWorkDir
const testBundleDir = path.join(testWorkDir, 'POV-TEST-BUNDLE');
fs.cpSync(povSourceDir, testBundleDir, { recursive: true });

console.log(`[*] Baseline Replay of Original PoV Bundle...`);
const baselineRes = spawnSync(process.execPath, [
    path.resolve('src/index.js'),
    'verify-pov',
    testBundleDir
], { encoding: 'utf-8' });

console.log(baselineRes.stdout);
const baselineVerified = baselineRes.status === 0 && baselineRes.stdout.includes('VERIFIED');
console.log(`  -> Baseline Verification Result: ${baselineVerified ? 'PASS (VERIFIED)' : 'FAIL'}`);

// -------------------------------------------------------------
// Phase 9: Vulnerable vs Fixed Differential
// -------------------------------------------------------------
console.log(`\n------------------------------------------------------------`);
console.log(`[*] Phase 9: Replaying SAME PoV against Remediated Target: target-05`);
console.log(`    Target: ${fixedTargetDir}`);
console.log(`------------------------------------------------------------`);

const fixedRes = spawnSync(process.execPath, [
    path.resolve('src/index.js'),
    'verify-pov',
    testBundleDir,
    '--fixed',
    '--target-override', fixedTargetDir
], { encoding: 'utf-8' });

console.log(fixedRes.stdout);
const fixedBlocked = fixedRes.status === 0 && fixedRes.stdout.includes('POV_BLOCKED_BY_FIX');
console.log(`  -> Fixed Target Differential Result: ${fixedBlocked ? 'PASS (POV_BLOCKED_BY_FIX)' : 'FAIL'}`);

// -------------------------------------------------------------
// Phase 17: PoV Tamper Integrity Test
// -------------------------------------------------------------
console.log(`\n------------------------------------------------------------`);
console.log(`[*] Phase 17: Tamper Integrity Test`);
console.log(`------------------------------------------------------------`);

const reproducePyPath = path.join(testBundleDir, 'reproduce.py');
const originalReproduceContent = fs.readFileSync(reproducePyPath, 'utf-8');

// 1. Tamper with reproduce.py
console.log(`  -> Tampering with 1 byte in reproduce.py...`);
fs.writeFileSync(reproducePyPath, originalReproduceContent + '\n# TAMPERED_BYTE = 1\n');

// 2. Attempt replay on tampered bundle
console.log(`  -> Replaying tampered bundle...`);
const tamperedRes = spawnSync(process.execPath, [
    path.resolve('src/index.js'),
    'verify-pov',
    testBundleDir
], { encoding: 'utf-8' });

console.log(tamperedRes.stdout);
const tamperDetected = tamperedRes.stdout.includes('TAMPER_DETECTED') || tamperedRes.status !== 0;
console.log(`  -> Tamper Interception Result: ${tamperDetected ? 'PASS (TAMPER_DETECTED / REJECTED)' : 'FAIL'}`);

// 3. Restore original content
console.log(`  -> Restoring original bundle contents...`);
fs.writeFileSync(reproducePyPath, originalReproduceContent);

// 4. Replay restored bundle
console.log(`  -> Replaying restored bundle...`);
const restoredRes = spawnSync(process.execPath, [
    path.resolve('src/index.js'),
    'verify-pov',
    testBundleDir
], { encoding: 'utf-8' });

console.log(restoredRes.stdout);
const restoredVerified = restoredRes.status === 0 && restoredRes.stdout.includes('VERIFIED');
console.log(`  -> Restored Verification Result: ${restoredVerified ? 'PASS (VERIFIED)' : 'FAIL'}`);

const differentialAndIntegrityReport = {
    baseline_verification: baselineVerified,
    phase_9_fixed_differential: {
        fixed_target_path: fixedTargetDir,
        expected: 'POV_BLOCKED_BY_FIX',
        actual: fixedBlocked ? 'POV_BLOCKED_BY_FIX' : 'FAILED_TO_BLOCK',
        success: fixedBlocked
    },
    phase_17_tamper_integrity: {
        tamper_detected: tamperDetected,
        restored_verified: restoredVerified,
        success: tamperDetected && restoredVerified
    }
};

fs.writeFileSync(path.resolve('reports', 'autonomous_validation', 'differential_and_integrity.json'), JSON.stringify(differentialAndIntegrityReport, null, 2));
console.log(`\n[+] Phase 9 & 17 verification successfully recorded to reports/autonomous_validation/differential_and_integrity.json`);
