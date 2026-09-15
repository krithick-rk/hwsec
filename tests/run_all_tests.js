import { spawnSync } from 'child_process';
import path from 'path';
import fs from 'fs';

const testFiles = [
    'test_wp1_planning_gate.js',
    'test_wp2_nvidia_llm.js',
    'test_wp3_sqlite_db.js',
    'test_wp4_broker_multilang.js',
    'test_wp6_schema.js',
    'test_wp7_verifier.js',
    'test_wp8_wp11_intelligence.js',
    'test_wp12_gateway.js',
    'test_joern_adapter.js',
    'test_codeql_adapter.js',
    'test_symbiyosys_adapter.js',
    'test_yosys_adapter.js',
    'test_spike_adapter.js',
    'test_qdrant_rag.js',
    'test_graph_strengthening.js',
    'test_e0_e5_verifier.js',
    'test_adaptive_suspicion.js',
    'test_cli_commands.js',
    'test_e2e_multilang.js',
    'test_benchmark_crawler.js',
    'test_architecture_upgrade.js',
    'test_improved_architecture.js',
    'test_preflight_scheduler.js',
    'test_exploit_preflight.js',
    'test_controlled_proof_verifier.js',
    'test_bep_evidence.js',
    'test_anti_leakage.js',
    'test_evidence_pipeline.js',
    'test_p0_security_hardening.js',
    'test_p1_evidence_dag.js',
    'test_p2_hypothesis_inventory.js',
    'test_p3_witness_search.js',
    'test_p4_causal_controls.js',
    'test_p5_constraint_refinement.js',
    'test_p6_observation_provider.js',
    'test_p7_operational_modes.js',
    'test_pov_unit.js',
    'test_pov_cross_domain.js',
    'test_pov_adversarial.js',
    'test_execution_capability.js',
    'test_target06_uncertainty_regression.js'
];

console.log('=====================================================');
console.log('   HWSEC COMPREHENSIVE REGRESSION & REMEDIATION SUITE');
console.log('=====================================================\n');

let failed = 0;
let passed = 0;

for (const file of testFiles) {
    const fullPath = path.resolve('tests', file);
    console.log(`>>> Running: ${file}`);
    const res = spawnSync(process.execPath, [fullPath], { stdio: 'inherit', env: process.env });
    if (res.status === 0) {
        passed++;
    } else {
        console.error(`[FAIL] ${file} exited with status ${res.status}`);
        failed++;
    }
}

console.log('\n=====================================================');
console.log(`SUMMARY: ${passed} PASSED, ${failed} FAILED (Total: ${testFiles.length})`);
console.log('=====================================================\n');

if (failed > 0) process.exit(1);
