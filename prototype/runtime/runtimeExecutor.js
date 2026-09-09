import { spawnSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { CaseAdapter } from '../case-registry/caseAdapter.js';

/**
 * Phase 1 Runtime Executor
 * 
 * Enforces runtime isolation using an explicit Java 8 binary.
 * Executes representative cases deterministically via the HarnessRunner,
 * capturing stdout/stderr, verifying exit status, and generating
 * cryptographic case artifacts.
 */
export class RuntimeExecutor {
    constructor(options = {}) {
        this.wslDistro = options.wslDistro || 'Ubuntu';
        this.benchmarkRoot = options.benchmarkRoot || '/home/intern/hwsec-workspace/BenchmarkJava';
        this.java8Path = options.java8Path || '/usr/lib/jvm/java-8-openjdk-amd64/bin/java';
        this.servletJar = options.servletJar || '/home/intern/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar';
        this.artifactsDir = path.resolve(options.artifactsDir || 'prototype/artifacts');
        this.caseAdapter = new CaseAdapter();

        fs.mkdirSync(this.artifactsDir, { recursive: true });
    }

    /**
     * Verifies that the explicit Java 8 binary exists and reports version 1.8.
     */
    verifyRuntimeEnvironment() {
        const res = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', `${this.java8Path} -version 2>&1`], {
            encoding: 'utf8'
        });

        if (res.status !== 0) {
            throw new Error(`Java 8 binary verification failed at ${this.java8Path}: ${res.stderr || res.stdout}`);
        }

        const firstLine = (res.stdout || '').split('\n')[0].trim();
        if (!firstLine.includes('1.8') && !firstLine.includes('Java(TM) SE') && !firstLine.includes('openjdk version "1.8')) {
            throw new Error(`Configured binary is not Java 8. Reported: ${firstLine}`);
        }

        return {
            binary_path: this.java8Path,
            version: firstLine,
            verified: true
        };
    }

    /**
     * Executes a single benchmark case with a given payload.
     * @param {string} caseId
     * @param {string} inputPayload
     * @param {Object} [overrideConfig]
     */
    executeCase(caseId, inputPayload = 'test_payload', overrideConfig = {}) {
        const runtimeEnv = this.verifyRuntimeEnvironment();
        const caseMeta = this.caseAdapter.getCaseById(caseId);
        if (!caseMeta) {
            throw new Error(`Case ${caseId} not found in registry.`);
        }

        const inputType = overrideConfig.inputType || caseMeta.input_vector_type || 'PARAMETER';
        const method = overrideConfig.method || caseMeta.entrypoint_method || 'doPost';

        const runCmd = `${this.java8Path} -cp "${this.servletJar}:${this.benchmarkRoot}/target/classes:$(cat ${this.benchmarkRoot}/target/dependency-classpath.txt)" org.owasp.benchmark.harness.HarnessRunner --case ${caseId} --input "${inputPayload}" --type ${inputType} --method ${method}`;

        const startTime = new Date().toISOString();
        const startMs = Date.now();

        const proc = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', runCmd], {
            encoding: 'utf8',
            maxBuffer: 10 * 1024 * 1024,
            timeout: 30000
        });

        const elapsedMs = Date.now() - startMs;
        const endTime = new Date().toISOString();

        const rawStdout = proc.stdout || '';
        const rawStderr = proc.stderr || '';

        // Extract JSON result from HarnessRunner
        let parsedResult = null;
        try {
            const jsonStart = rawStdout.indexOf('{');
            const jsonEnd = rawStdout.lastIndexOf('}');
            if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
                parsedResult = JSON.parse(rawStdout.substring(jsonStart, jsonEnd + 1));
            }
        } catch (_) {}

        const stdoutHash = crypto.createHash('sha256').update(rawStdout).digest('hex');
        const stderrHash = crypto.createHash('sha256').update(rawStderr).digest('hex');
        const payloadHash = crypto.createHash('sha256').update(inputPayload).digest('hex');

        const caseArtifact = {
            run_id: `RUN-${caseId}-${crypto.randomBytes(4).toString('hex')}`,
            case_id: caseId,
            cwe: caseMeta.cwe,
            expected_label: caseMeta.expected_label,
            target_class: caseMeta.target_class,
            entrypoint_method: method,
            input_vector: {
                type: inputType,
                payload: inputPayload,
                payload_sha256: payloadHash
            },
            execution: {
                started_at: startTime,
                completed_at: endTime,
                duration_ms: elapsedMs,
                exit_code: proc.status !== null ? proc.status : -1,
                timed_out: proc.error && proc.error.code === 'ETIMEDOUT',
                stdout_sha256: stdoutHash,
                stderr_sha256: stderrHash,
                parsed_harness_result: parsedResult
            },
            runtime_provenance: {
                java_path: runtimeEnv.binary_path,
                java_version: runtimeEnv.version
            }
        };

        // Write case artifact
        const artifactPath = path.join(this.artifactsDir, `${caseId}_run.json`);
        fs.writeFileSync(artifactPath, JSON.stringify(caseArtifact, null, 2));

        return caseArtifact;
    }

    /**
     * Executes representative cases across all 6 CWEs and writes aggregate runtime provenance.
     */
    executeRepresentativeSubset(casesPerCwe = 1) {
        const cwes = ['CWE-22', 'CWE-78', 'CWE-89', 'CWE-79', 'CWE-90', 'CWE-643'];
        const results = [];

        for (const cwe of cwes) {
            const cweCases = this.caseAdapter.getCasesByCWE(cwe).slice(0, casesPerCwe);
            for (const c of cweCases) {
                const samplePayload = cwe === 'CWE-22' ? 'safe_path.txt' : (cwe === 'CWE-78' ? 'safe_cmd' : 'safe_val');
                const art = this.executeCase(c.case_id, samplePayload);
                results.push(art);
            }
        }

        const provenancePath = path.resolve('prototype/manifests/runtime_provenance.json');
        const manifest = {
            generated_at: new Date().toISOString(),
            representative_cases_executed: results.length,
            target_jdk: this.verifyRuntimeEnvironment(),
            cases: results.map(r => ({
                case_id: r.case_id,
                cwe: r.cwe,
                exit_code: r.execution.exit_code,
                duration_ms: r.execution.duration_ms,
                status: r.execution.parsed_harness_result?.status || 'UNKNOWN'
            }))
        };

        fs.writeFileSync(provenancePath, JSON.stringify(manifest, null, 2));
        return { results, manifest };
    }
}
