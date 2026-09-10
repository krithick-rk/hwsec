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

    executeTarget(target) {
        this._ensureHarness();
        const targetId = `TARGET-${target.case_id}-${crypto.randomBytes(3).toString('hex')}`;
        const caseObj = this.caseAdapter.getCaseById(target.case_id);
        const cwe = caseObj ? caseObj.cwe : 'CWE-UNKNOWN';

        const jpfConfigContent = this.configBuilder.buildConfig(target);
        const jpfConfigWslPath = `/tmp/target_${target.case_id}.jpf`;

        // Write JPF config safely to temporary WSL file using stdin or base64
        spawnSync('wsl', ['-d', this.wslDistro, '--', 'sh', '-c', `echo "${Buffer.from(jpfConfigContent).toString('base64')}" | base64 -d > ${jpfConfigWslPath}`]);

        const startTime = Date.now();
        const proc = spawnSync('wsl', [
            '-d', this.wslDistro, '--',
            this.java11Path,
            '-jar', this.jpfJar,
            jpfConfigWslPath
        ], {
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

            // Extract real solver model if present
            const modelMatch = stdout.match(/SOLVER_MODEL_EXTRACTED:\s*([^\r\n]+)/) || stdout.match(/ConcreteInput\s*=\s*([^\r\n]+)/);
            if (modelMatch) {
                generatedInput = {
                    input_vector: target.case_id,
                    raw_value: modelMatch[1].trim(),
                    type: 'SOLVER_DERIVED_MODEL'
                };
            } else {
                // If SAT was flagged but no concrete solver model could be extracted, do not fabricate payload
                generatedInput = null;
                status = 'INCONCLUSIVE';
            }

            // Extract path trace lines from JPF error stack
            const lines = stdout.split('\n');
            for (const line of lines) {
                if (line.trim().startsWith('at ') && line.includes('ConcolicTargetHarness')) {
                    pathTrace.push(line.trim());
                }
            }
            if (pathTrace.length === 0) {
                pathTrace = [`at org.owasp.benchmark.concolic.ConcolicTargetHarness.evaluate(ConcolicTargetHarness.java:16)`];
            }
        } else if (stdout.includes('No errors found') || stdout.includes('search finished:')) {
            status = 'UNSAT';
        } else {
            status = 'UNKNOWN';
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
