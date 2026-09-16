import path from 'path';
import { WitnessSearchEngine } from '../../src/core/witness/witnessSearch.js';
import { VulnerabilityHypothesis } from '../../src/core/hypothesis/vulnerabilityHypothesis.js';
import { ProofSandbox } from '../../src/core/proofSandbox.js';

const targetFile = path.resolve('experiments/autonomous_validation/targets/python/target-01/app.py');
const targetDir = path.dirname(targetFile);

const hyp = new VulnerabilityHypothesis({
    id: 'HYP-TEST-01',
    cwe: "CWE-78: IMPROPER NEUTRALIZATION OF SPECIAL ELEMENTS USED IN AN OS COMMAND ('OS COMMAND INJECTION')",
    file: targetFile,
    source: 'USER_INPUT',
    sink: 'subprocess.run',
    security_condition: 'Command Injection'
});

const sandbox = new ProofSandbox({ baseDir: path.resolve('hwsec-output/test_sandbox') });
const executor = async (probe) => {
    const cmd = process.platform === 'win32' ? 'py' : 'python3';
    const args = [targetFile, String(probe.value)];
    const res = sandbox.execute(cmd, args, { cwd: targetDir, timeout: 5000 });
    const stdout = res.stdout || '';
    const stderr = res.stderr || '';
    return {
        stdout,
        stderr,
        exitCode: res.exitCode,
        timedOut: res.timedOut,
        parsed_result: {
            sink_observed: stdout.includes('[APP_EXEC]') || stdout.includes('EXEC') ? 'exec' : null,
            value_at_sink: probe.value
        }
    };
};

const ws = new WitnessSearchEngine();
const res = await ws.searchWitness(hyp, executor);
console.log('Witness Search Status:', res.status);
if (res.witness_input) {
    console.log('Witness Found:', res.witness_input);
}
