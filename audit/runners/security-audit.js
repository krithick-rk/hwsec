import { runSuite as runExecInjection } from '../tests/security/execution_injection.adversarial.js';
import { runSuite as runFsTraversal } from '../tests/security/filesystem_traversal.adversarial.js';
import { runSuite as runSymlinkEscape } from '../tests/security/symlink_escape.adversarial.js';
import { runSuite as runProcIsolation } from '../tests/security/process_isolation.adversarial.js';
import { runSuite as runPromptInjection } from '../tests/llm/prompt_injection.adversarial.js';
import { runSuite as runGatewayTelemetry } from '../tests/llm/gateway_telemetry.security.js';

export async function runSecurityProfile() {
    console.log(`\n======================================================`);
    console.log(`[*] EXECUTING ADVERSARIAL SECURITY AUDIT PROFILE`);
    console.log(`======================================================\n`);

    const summaries = [];
    summaries.push(await runExecInjection());
    summaries.push(await runFsTraversal());
    summaries.push(await runSymlinkEscape());
    summaries.push(await runProcIsolation());
    summaries.push(await runPromptInjection());
    summaries.push(await runGatewayTelemetry());

    return summaries;
}

if (process.argv[1]?.endsWith('security-audit.js')) {
    runSecurityProfile().then(summaries => {
        const total = summaries.reduce((acc, s) => acc + s.total, 0);
        const passed = summaries.reduce((acc, s) => acc + s.passed, 0);
        console.log(`\nSecurity Audit Complete: ${passed}/${total} passed.\n`);
        process.exit(passed === total ? 0 : 1);
    });
}
