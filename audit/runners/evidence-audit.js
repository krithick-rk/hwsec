import { runSuite as runVerifierIntegrity } from '../tests/evidence/verifier_integrity.adversarial.js';
import { runSuite as runProvenance } from '../tests/evidence/artifact_provenance.adversarial.js';
import { runSuite as runCrossDomain } from '../tests/evidence/cross_domain_evidence.adversarial.js';
import { runSuite as runPoisoning } from '../tests/evidence/telemetry_poisoning.adversarial.js';

export async function runEvidenceProfile() {
    console.log(`\n======================================================`);
    console.log(`[*] EXECUTING EVIDENCE & PROVENANCE AUDIT PROFILE`);
    console.log(`======================================================\n`);

    const summaries = [];
    summaries.push(await runVerifierIntegrity());
    summaries.push(await runProvenance());
    summaries.push(await runCrossDomain());
    summaries.push(await runPoisoning());

    return summaries;
}

if (process.argv[1]?.endsWith('evidence-audit.js')) {
    runEvidenceProfile().then(summaries => {
        const total = summaries.reduce((acc, s) => acc + s.total, 0);
        const passed = summaries.reduce((acc, s) => acc + s.passed, 0);
        console.log(`\nEvidence Audit Complete: ${passed}/${total} passed.\n`);
        process.exit(passed === total ? 0 : 1);
    });
}
