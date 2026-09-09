import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';
import { CaseAdapter } from '../../case-registry/caseAdapter.js';

/**
 * CWE Security Condition Rules and Differential Assertions
 */
const CWE_SECURITY_RULES = {
    'CWE-22': {
        rule: 'canonicalPath.startsWith(baseDir) == false',
        observable: 'CANONICAL_PATH_ESCAPE',
        defaultBaseline: 'safe_file.txt',
        defaultAttack: '../../etc/passwd',
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            const hasTraversal = observable.includes('..') || observable.includes('/etc/passwd');
            const retainsConstant = observable.includes('This_should_always_happen') || observable.includes('Safe');
            return hasTraversal && !retainsConstant;
        }
    },
    'CWE-78': {
        rule: 'process_args.contains_unquoted_shell_metachars == true',
        observable: 'PROCESS_ARG_INJECTION',
        defaultBaseline: 'safe_arg',
        defaultAttack: 'hello; echo INJECTED_CMD_OUTPUT',
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            return observable.includes('INJECTED_CMD_OUTPUT') || 
                   (observable.includes(';') && (observable.includes('echo') || observable.includes('id')));
        }
    },
    'CWE-89': {
        rule: 'sql_statement_syntax_tree_altered == true',
        observable: 'SQL_STATEMENT_SYNTAX_ALTERATION',
        defaultBaseline: 'safe_user_id',
        defaultAttack: "' OR '1'='1",
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            return observable.includes("' OR '1'='1") || observable.includes("OR 1=1") || observable.includes("' OR '");
        }
    },
    'CWE-79': {
        rule: 'response_body_contains_unescaped_input == true',
        observable: 'UNENCODED_XSS_OUTPUT_REFLECTION',
        defaultBaseline: 'safe_content',
        defaultAttack: '<script>alert(1)</script>',
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            return observable.includes('<script>') || observable.includes('alert(1)');
        }
    },
    'CWE-90': {
        rule: 'ldap_filter_structure_altered == true',
        observable: 'LDAP_FILTER_MANIPULATION',
        defaultBaseline: 'safe_user',
        defaultAttack: '*(|(objectclass=*))',
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            return observable.includes('*(') || observable.includes('objectclass=*');
        }
    },
    'CWE-643': {
        rule: 'xpath_expression_structure_altered == true',
        observable: 'XPATH_EXPRESSION_ALTERATION',
        defaultBaseline: 'safe_empl_id',
        defaultAttack: "' or ''='",
        evaluateViolation: (observable, input) => {
            if (!observable) return false;
            return observable.includes("' or ''='") || observable.includes("' or '1'='1");
        }
    }
};

export class DifferentialValidator {
    constructor(options = {}) {
        this.wslDistro = options.wslDistro || 'Ubuntu';
        this.java8Path = options.java8Path || '/usr/lib/jvm/java-8-openjdk-amd64/bin/java';
        this.benchmarkRoot = options.benchmarkRoot || '/home/intern/hwsec-workspace/BenchmarkJava';
        this.servletJar = options.servletJar || '/home/intern/.m2/repository/javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar';
        this.caseAdapter = new CaseAdapter();
        this._cachedClasspath = null;
    }

    _getClasspath() {
        if (!this._cachedClasspath) {
            const cpRes = spawnSync('wsl', ['-d', this.wslDistro, '--', 'cat', `${this.benchmarkRoot}/target/dependency-classpath.txt`], {
                encoding: 'utf8'
            });
            const depCp = (cpRes.stdout || '').trim();
            this._cachedClasspath = `${this.servletJar}:${this.benchmarkRoot}/target/classes:${depCp}`;
        }
        return this._cachedClasspath;
    }

    _runHarness(caseId, inputValue, inputType, method, timeoutMs = 25000) {
        const fullCp = this._getClasspath();

        const b64Val = Buffer.from(inputValue, 'utf8').toString('base64');
        const startTime = Date.now();
        // Shell-safe structured argument array with base64 encoding to prevent any shell metacharacter expansion
        const proc = spawnSync('wsl', [
            '-d', this.wslDistro,
            '--',
            this.java8Path,
            '-cp', fullCp,
            'org.owasp.benchmark.harness.HarnessRunner',
            '--case', caseId,
            '--b64input', b64Val,
            '--type', inputType,
            '--method', method
        ], {
            encoding: 'utf8',
            timeout: timeoutMs,
            maxBuffer: 10 * 1024 * 1024
        });
        const durationMs = Date.now() - startTime;

        const stdout = proc.stdout || '';
        const stderr = proc.stderr || '';
        const isTimeout = Boolean(proc.error && proc.error.code === 'ETIMEDOUT');

        let parsed = null;
        try {
            const jsonStart = stdout.indexOf('{\n  "case_id"');
            const jsonEnd = stdout.lastIndexOf('}');
            if (jsonStart !== -1 && jsonEnd !== -1 && jsonEnd > jsonStart) {
                parsed = JSON.parse(stdout.substring(jsonStart, jsonEnd + 1));
            }
        } catch (_) {}

        return {
            stdout,
            stderr,
            exitCode: proc.status !== null ? proc.status : 1,
            timeout: isTimeout,
            parsed,
            durationMs
        };
    }

    _extractObservable(caseObj, runResult, inputValue) {
        const fullOutput = (runResult.stdout + '\n' + runResult.stderr);
        const cwe = caseObj.cwe;

        if (cwe === 'CWE-22') {
            const fileMatch = fullOutput.match(/FileInputStream on file: '([^']+)'/);
            if (fileMatch) return fileMatch[1];
            const snippetMatch = fullOutput.match(/Problem getting FileInputStream: ([^\n]+)/);
            if (snippetMatch) return snippetMatch[1];
            return runResult.parsed?.output_snippet || '';
        }

        if (cwe === 'CWE-78') {
            if (fullOutput.includes('INJECTED_CMD_OUTPUT')) return 'INJECTED_CMD_OUTPUT';
            return runResult.parsed?.output_snippet || fullOutput.slice(0, 300);
        }

        if (cwe === 'CWE-89') {
            const sqlMatch = fullOutput.match(/sql:\s*([^\n]+)/i);
            if (sqlMatch) return sqlMatch[1];
            return inputValue;
        }

        if (cwe === 'CWE-79') {
            return runResult.parsed?.output_snippet || fullOutput.slice(0, 300);
        }

        if (cwe === 'CWE-90') {
            const ldapMatch = fullOutput.match(/filter:\s*([^\n]+)/i);
            if (ldapMatch) return ldapMatch[1];
            return inputValue;
        }

        if (cwe === 'CWE-643') {
            const xpathMatch = fullOutput.match(/expression:\s*([^\n]+)/i);
            if (xpathMatch) return xpathMatch[1];
            return inputValue;
        }

        return runResult.parsed?.output_snippet || inputValue;
    }

    validateDifferential(caseId, customOptions = {}) {
        const caseObj = this.caseAdapter.getCaseById(caseId);
        if (!caseObj) {
            throw new Error(`Case ${caseId} not found in case registry`);
        }

        const cweRuleConfig = CWE_SECURITY_RULES[caseObj.cwe] || {
            rule: 'security_invariant_holds == true',
            observable: 'GENERIC_OBSERVABLE',
            defaultBaseline: 'safe_input',
            defaultAttack: 'attack_probe',
            evaluateViolation: (obs, inp) => obs.includes('attack')
        };

        const inputType = customOptions.inputType || caseObj.input_vector_type || 'PARAMETER';
        const method = customOptions.method || caseObj.entrypoint_method || 'doPost';

        const baselineInput = customOptions.baselineInput || cweRuleConfig.defaultBaseline;
        const attackInput = customOptions.attackInput || cweRuleConfig.defaultAttack;

        // Run 1: Benign Baseline Input (Negative Control)
        const baselineRun = this._runHarness(caseId, baselineInput, inputType, method);
        const baselineObs = this._extractObservable(caseObj, baselineRun, baselineInput);
        const baselineViolation = cweRuleConfig.evaluateViolation(baselineObs, baselineInput);

        const baselineObserved = {
            input_value: baselineInput,
            sink_called: baselineRun.parsed ? true : false,
            sink_observed: caseObj.sink_type,
            observable_value: baselineObs.substring(0, 200),
            security_condition_violated: Boolean(baselineViolation),
            exit_code: baselineRun.exitCode
        };

        // Run 2: Attack Input
        const attackRun = this._runHarness(caseId, attackInput, inputType, method);
        const attackObs = this._extractObservable(caseObj, attackRun, attackInput);
        const attackViolation = cweRuleConfig.evaluateViolation(attackObs, attackInput);

        const attackObserved = {
            input_value: attackInput,
            sink_called: attackRun.parsed ? true : false,
            sink_observed: caseObj.sink_type,
            observable_value: attackObs.substring(0, 200),
            security_condition_violated: Boolean(attackViolation),
            exit_code: attackRun.exitCode
        };

        // Delta Detection: attack input triggers violation while baseline does not
        const deltaDetected = Boolean(attackViolation && !baselineViolation);

        const differentialRecord = {
            baseline_observed: baselineObserved,
            attack_observed: attackObserved,
            delta_detected: deltaDetected,
            security_relevant_observable: cweRuleConfig.observable
        };

        const securityCondition = {
            satisfied: deltaDetected,
            rule: cweRuleConfig.rule,
            details: deltaDetected 
                ? `Observable diverged under attack input: '${cweRuleConfig.observable}' violated rule '${cweRuleConfig.rule}'`
                : `No security-violating divergence detected. Invariant preserved.`
        };

        return {
            case_id: caseId,
            cwe: caseObj.cwe,
            differential: differentialRecord,
            security_condition: securityCondition,
            baseline_run: baselineRun,
            attack_run: attackRun
        };
    }
}
