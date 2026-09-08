import { ProofSandbox } from '../src/core/proofSandbox.js';
import { ControlledProofVerifier } from '../src/workers/proofVerifier.js';
import path from 'path';
import fs from 'fs';

async function run() {
    console.log('[*] Testing ProofSandbox Java capabilities...');
    const sb = new ProofSandbox();
    const avail = sb.checkJavaAvailability();
    console.log('[+] Java Availability:', avail);

    const ws = sb.createIsolatedWorkspace('test-java-proof');
    const className = 'ProofTest_sample';
    const javaCode = `
public class ${className} {
    public static void main(String[] args) {
        System.err.println("HWSEC_PROOF_EXECUTION: TEST-SAMPLE-01");
        throw new SecurityException("Controlled authorization violation: TEST-SAMPLE-01");
    }
}
`;
    fs.writeFileSync(path.join(ws, `${className}.java`), javaCode, 'utf8');
    const execRes = sb.executeJava(`javac ${className}.java && java ${className}`, { cwd: ws });
    console.log('[+] Execution Exit Code:', execRes.exitCode);
    console.log('[+] Execution Stderr:\n', execRes.stderr);
    console.log('[+] Tool Version:', execRes.toolVersion);

    const verifier = new ControlledProofVerifier({}, null, null);
    const mockFinding = {
        id: 'FINDING-JAVA-001',
        title: 'Test Path Traversal',
        source_locations: [{ path: 'src/main/java/BenchmarkTest00001.java' }]
    };
    const gen = await verifier.generateProof(mockFinding, process.cwd());
    console.log('[+] Generated proof record:', gen.proofRecord.proof_id);
    const result = await verifier.executeProof(gen.proofRecord, process.cwd(), 1);
    console.log('[+] Reproduced:', result.reproduced);
    console.log('[+] Status:', result.proofRecord.proof_status);
    console.log('[+] Rate:', result.reproducibilityRate);
    console.log('[+] Artifact Hash:', result.proofRecord.artifact_hash);

    sb.cleanupWorkspace(ws);
    console.log('[+] Test Finished Successfully!');
}

run().catch(e => {
    console.error('[-] Test failed:', e);
    process.exit(1);
});
