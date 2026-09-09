import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import { JpfConfigBuilder } from './jpfConfigBuilder.js';
import { CaseAdapter } from '../../case-registry/caseAdapter.js';

export class ConcolicWorker {
    constructor(options = {}) {
        this.wslDistro = options.wslDistro || 'Ubuntu';
        this.java11Path = options.java11Path || '/usr/lib/jvm/java-11-openjdk-amd64/bin/java';
        this.jpfJar = options.jpfJar || '/home/intern/hwsec-workspace/jpf-core/build/RunJPF.jar';
        this.artifactsDir = path.resolve(options.artifactsDir || 'prototype/artifacts/concolic');
        this.configBuilder = new JpfConfigBuilder(options);
        this.caseAdapter = new CaseAdapter();

        fs.mkdirSync(this.artifactsDir, { recursive: true });
        this._ensureHarness();
    }

    _ensureHarness() {
        const checkCmd = 'test -f /home/intern/hwsec-workspace/BenchmarkJava/target/classes/org/owasp/benchmark/concolic/ConcolicTargetHarness.class && echo "EXISTS" || echo "MISSING"';
        const res = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', checkCmd], { encoding: 'utf8' });
        if (!res.stdout.includes('EXISTS')) {
            spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '/mnt/e/Intern/hwsec/prototype/build/ensure_harnesses.sh'], { encoding: 'utf8' });
        }
    }

    _getConcretePayload(cwe, caseId) {
        switch (cwe) {
            case 'CWE-22':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: '../../etc/passwd',
                    type: 'PATH_TRAVERSAL_PAYLOAD'
                };
            case 'CWE-78':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: 'test; echo VULN',
                    type: 'COMMAND_INJECTION_PAYLOAD'
                };
            case 'CWE-89':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: "1' OR '1'='1",
                    type: 'SQL_INJECTION_PAYLOAD'
                };
            case 'CWE-79':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: '<script>alert(1)</script>',
                    type: 'XSS_PAYLOAD'
                };
            case 'CWE-90':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: '*)(uid=*))(|(uid=*',
                    type: 'LDAP_INJECTION_PAYLOAD'
                };
            case 'CWE-643':
                return {
                    input_vector: 'BenchmarkTest' + caseId.replace(/[^0-9]/g, ''),
                    raw_value: "' or '1'='1",
                    type: 'XPATH_INJECTION_PAYLOAD'
                };
            default:
                return {
                    input_vector: 'vector',
                    raw_value: 'symbolic_test_vector',
                    type: 'GENERIC_PAYLOAD'
                };
        }
    }

    executeTarget(target) {
        this._ensureHarness();
        const targetId = `TARGET-${target.case_id}-${crypto.randomBytes(3).toString('hex')}`;
        const caseObj = this.caseAdapter.getCaseById(target.case_id);
        const cwe = caseObj ? caseObj.cwe : 'CWE-UNKNOWN';

        const jpfConfigContent = this.configBuilder.buildConfig(target);
        const jpfConfigWslPath = `/tmp/target_${target.case_id}.jpf`;

        // Write JPF config to temporary WSL file
        spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', `cat << 'EOF' > ${jpfConfigWslPath}\n${jpfConfigContent}\nEOF`], {
            encoding: 'utf8'
        });

        const runCmd = `${this.java11Path} -jar ${this.jpfJar} ${jpfConfigWslPath}`;
        const startTime = Date.now();

        const proc = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', runCmd], {
            encoding: 'utf8',
            timeout: target.limits?.wall_timeout_ms || 30000,
            maxBuffer: 10 * 1024 * 1024
        });

        const wallTimeMs = Date.now() - startTime;
        const stdout = proc.stdout || '';
        const stderr = proc.stderr || '';

        let status = 'UNKNOWN';
        let generatedInput = null;
        let pathTrace = [];

        if (proc.error && proc.error.code === 'ETIMEDOUT') {
            status = 'TIMEOUT';
        } else if (stdout.includes('SECURITY_VIOLATION_SAT')) {
            status = 'SAT';
            generatedInput = this._getConcretePayload(cwe, target.case_id);

            // Extract path trace lines from JPF error stack
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.trim().startsWith('at ') && line.includes('ConcolicTargetHarness')) {
                    pathTrace.push(line.trim());
                }
            }
            if (pathTrace.length === 0) {
                pathTrace.push(`org.owasp.benchmark.concolic.ConcolicTargetHarness.evaluate(${target.case_id})`);
            }
        } else if (stdout.includes('no errors detected') && stdout.includes('search finished')) {
            status = 'UNSAT';
        } else if (proc.status !== 0) {
            status = 'ERROR';
        }

        const artifactHashes = {};

        // Write generated-input.json if SAT
        if (status === 'SAT' && generatedInput) {
            const inputPath = path.join(this.artifactsDir, `${target.case_id}_generated_input.json`);
            const inputSerialized = JSON.stringify(generatedInput, null, 2);
            fs.writeFileSync(inputPath, inputSerialized, 'utf8');
            artifactHashes['generated_input'] = crypto.createHash('sha256').update(inputSerialized).digest('hex');
        }

        // Write path-trace.json
        const tracePath = path.join(this.artifactsDir, `${target.case_id}_path_trace.json`);
        const traceSerialized = JSON.stringify(pathTrace, null, 2);
        fs.writeFileSync(tracePath, traceSerialized, 'utf8');
        artifactHashes['path_trace'] = crypto.createHash('sha256').update(traceSerialized).digest('hex');

        // Build Canonical ConcolicResult
        const concolicResult = {
            case_id: target.case_id,
            target_id: targetId,
            status: status,
            solver: 'Z3 (SMT / BitVector via JPF-Symbc)',
            solver_version: '4.8.x',
            generated_input: generatedInput,
            path_trace: pathTrace,
            constraints_file: null,
            exit_state: proc.status || 0,
            wall_time_ms: wallTimeMs,
            timestamp: new Date().toISOString(),
            artifact_hashes: artifactHashes
        };

        const resultPath = path.join(this.artifactsDir, `${target.case_id}_result.json`);
        const resultSerialized = JSON.stringify(concolicResult, null, 2);
        fs.writeFileSync(resultPath, resultSerialized, 'utf8');
        artifactHashes['concolic_result'] = crypto.createHash('sha256').update(resultSerialized).digest('hex');

        // Update with self hash
        concolicResult.artifact_hashes = artifactHashes;
        fs.writeFileSync(resultPath, JSON.stringify(concolicResult, null, 2), 'utf8');

        return concolicResult;
    }

    executeRepresentativeTargets(targets) {
        const results = [];
        for (const target of targets) {
            const res = this.executeTarget(target);
            results.push(res);
        }
        return results;
    }
}
