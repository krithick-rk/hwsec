import { runSuite as runResourceLimits } from '../tests/resource/resource_limits.adversarial.js';
import { runSuite as runProcTreeCleanup } from '../tests/resource/process_tree_cleanup.stress.js';

export async function runPerformanceProfile() {
    console.log(`\n======================================================`);
    console.log(`[*] EXECUTING PERFORMANCE & RESOURCE STRESS PROFILE`);
    console.log(`======================================================\n`);

    const summaries = [];
    summaries.push(await runResourceLimits());
    summaries.push(await runProcTreeCleanup());

    return summaries;
}

if (process.argv[1]?.endsWith('performance-audit.js')) {
    runPerformanceProfile().then(summaries => {
        const total = summaries.reduce((acc, s) => acc + s.total, 0);
        const passed = summaries.reduce((acc, s) => acc + s.passed, 0);
        console.log(`\nPerformance Audit Complete: ${passed}/${total} passed.\n`);
        process.exit(passed === total ? 0 : 1);
    });
}
