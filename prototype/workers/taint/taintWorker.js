import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import { CaseAdapter } from '../../case-registry/caseAdapter.js';

export class TaintWorker {
    constructor(options = {}) {
        this.wslDistro = options.wslDistro || 'Ubuntu';
        this.java8Path = options.java8Path || '/usr/lib/jvm/java-8-openjdk-amd64/bin/java';
        this.benchmarkRoot = options.benchmarkRoot || '/home/intern/hwsec-workspace/BenchmarkJava';
        this.servletJar = options.servletJar || '/home/intern/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar';
        this.artifactsDir = path.resolve(options.artifactsDir || 'prototype/artifacts/taint');
        this.caseAdapter = new CaseAdapter();

        fs.mkdirSync(this.artifactsDir, { recursive: true });
        this._ensureHarness();
    }

    _getClasspath() {
        if (this._cachedClasspath) return this._cachedClasspath;
        try {
            const cpProc = spawnSync('wsl', ['-d', this.wslDistro, '--', 'cat', `${this.benchmarkRoot}/target/dependency-classpath.txt`], { encoding: 'utf8' });
            const depCp = (cpProc.stdout || '').trim();
            this._cachedClasspath = `${this.servletJar}:${this.benchmarkRoot}/target/classes:${depCp}`;
            return this._cachedClasspath;
        } catch (_) {
            return `${this.servletJar}:${this.benchmarkRoot}/target/classes`;
        }
    }

    _ensureHarness() {
        const check = spawnSync('wsl', ['-d', this.wslDistro, '--', 'test', '-f', `${this.benchmarkRoot}/target/classes/org/owasp/benchmark/harness/TaintHarnessRunner.class`]);
        if (check.status !== 0) {
            spawnSync('wsl', ['-d', this.wslDistro, '--', '/mnt/e/Intern/hwsec/prototype/build/ensure_harnesses.sh'], { encoding: 'utf8' });
        }
    }

    executeCase(caseId, options = {}) {
        this._ensureHarness();
        const caseObj = this.caseAdapter.getCaseById(caseId);
        if (!caseObj) {
            throw new Error(`Case ${caseId} not found in case registry`);
        }

        const inputType = options.inputType || caseObj.input_vector_type || 'PARAMETER';
        const method = options.method || caseObj.entrypoint_method || 'doPost';
        const inputValue = options.inputValue || 'taint_probe';
        const classpath = this._getClasspath();

        const startTime = Date.now();
        const proc = spawnSync('wsl', [
            '-d', this.wslDistro, '--',
            this.java8Path,
            '-cp', classpath,
            'org.owasp.benchmark.harness.TaintHarnessRunner',
            '--case', String(caseId),
            '--input', String(inputValue),
            '--type', String(inputType),
            '--method', String(method)
        ], {
            encoding: 'utf8',
            timeout: options.timeoutMs || 30000,
            maxBuffer: 10 * 1024 * 1024
        });
        const durationMs = Date.now() - startTime;

        const stdout = proc.stdout || '';
        const stderr = proc.stderr || '';

        let parsed = null;
        try {
            const jsonStart = stdout.indexOf('{\n  "case_id"');
            const jsonEnd = stdout.lastIndexOf('}');
            if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
                parsed = JSON.parse(stdout.substring(jsonStart, jsonEnd + 1));
            }
        } catch (_) {}

        const isTimeout = proc.error && proc.error.code === 'ETIMEDOUT';

        const taintResult = {
            case_id: caseId,
            source_observed: parsed?.source_observed || `HttpServletRequest.${inputType.toLowerCase()}`,
            sink_observed: parsed?.sink_observed || caseObj.sink_type || 'UNKNOWN_SINK',
            sink_tainted: parsed ? Boolean(parsed.sink_tainted) : false,
            runtime_path: parsed?.runtime_path || [`${caseObj.target_class}.${method}`],
            exit_code: proc.status !== null ? proc.status : 1,
            timeout: Boolean(isTimeout),
            instrumentation_status: isTimeout ? 'PARTIAL' : (proc.status === 0 ? 'ACTIVE' : 'FAILED'),
            execution_time_ms: parsed?.execution_time_ms || durationMs,
            timestamp: new Date().toISOString(),
            artifact_hashes: {}
        };

        const resultPath = path.join(this.artifactsDir, `${caseId}_taint.json`);
        const serialized = JSON.stringify(taintResult, null, 2);
        fs.writeFileSync(resultPath, serialized, 'utf8');

        const sha256 = crypto.createHash('sha256').update(serialized).digest('hex');
        taintResult.artifact_hashes = {
            taint_result: sha256,
            stdout_sha256: crypto.createHash('sha256').update(stdout).digest('hex'),
            stderr_sha256: crypto.createHash('sha256').update(stderr).digest('hex')
        };

        // Write final with self-hash
        fs.writeFileSync(resultPath, JSON.stringify(taintResult, null, 2), 'utf8');

        return taintResult;
    }

    executeRepresentativeSubset() {
        // Run across 6 distinct CWE representative cases + benign controls
        const testCases = [
            'BenchmarkTest00001', // CWE-22 (Vulnerable)
            'BenchmarkTest00063', // CWE-22 (Safe/Benign)
            'BenchmarkTest00006', // CWE-78 (Vulnerable)
            'BenchmarkTest00008', // CWE-89 (Vulnerable)
            'BenchmarkTest00013', // CWE-79 (Vulnerable)
            'BenchmarkTest00012', // CWE-90 (Vulnerable)
            'BenchmarkTest00207'  // CWE-643 (Vulnerable)
        ];

        const results = [];
        for (const caseId of testCases) {
            results.push(this.executeCase(caseId));
        }

        const summaryPath = path.join(this.artifactsDir, 'taint_summary.json');
        const summary = {
            total_cases_analyzed: results.length,
            cases: results.map(r => ({
                case_id: r.case_id,
                source_observed: r.source_observed,
                sink_observed: r.sink_observed,
                sink_tainted: r.sink_tainted,
                instrumentation_status: r.instrumentation_status,
                execution_time_ms: r.execution_time_ms
            })),
            timestamp: new Date().toISOString()
        };
        fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2), 'utf8');

        return {
            results: results,
            summary: summary
        };
    }
}
