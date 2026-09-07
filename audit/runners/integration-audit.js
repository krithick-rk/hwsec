import { runSuite as runCodeGraphLive } from '../tests/graph/codegraph_live.integration.js';
import { runSuite as runQdrantIsolation } from '../tests/rag/qdrant_isolation.integration.js';
import { runSuite as runIncrementalLifecycle } from '../tests/integration/incremental_lifecycle.integration.js';
import { runSuite as runStateMachine } from '../tests/integration/state_machine.adversarial.js';
import { runSuite as runRealTools } from '../tests/tools/real_tool_validation.integration.js';

export async function runIntegrationProfile() {
    console.log(`\n======================================================`);
    console.log(`[*] EXECUTING ARCHITECTURAL INTEGRATION AUDIT PROFILE`);
    console.log(`======================================================\n`);

    const summaries = [];
    summaries.push(await runCodeGraphLive());
    summaries.push(await runQdrantIsolation());
    summaries.push(await runIncrementalLifecycle());
    summaries.push(await runStateMachine());
    summaries.push(await runRealTools());

    return summaries;
}

if (process.argv[1]?.endsWith('integration-audit.js')) {
    runIntegrationProfile().then(summaries => {
        const total = summaries.reduce((acc, s) => acc + s.total, 0);
        const passed = summaries.reduce((acc, s) => acc + s.passed, 0);
        console.log(`\nIntegration Audit Complete: ${passed}/${total} passed.\n`);
        process.exit(passed === total ? 0 : 1);
    });
}
