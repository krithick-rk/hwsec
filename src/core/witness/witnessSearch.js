import crypto from 'crypto';
import { defaultSecurityRegistry } from '../oracles/securityConditionRegistry.js';

/**
 * WitnessSearchEngine
 * 
 * Section 8: Execution-guided budgeted witness generation.
 */
export class WitnessSearchEngine {
    constructor(options = {}) {
        this.securityRegistry = options.securityRegistry || defaultSecurityRegistry;
        this.maxExecutionsDefault = options.maxExecutions || 25;
        this.timeoutMsDefault = options.timeoutMs || 30000;
    }

    /**
     * Generates initial deterministic seeds based on CWE and input parameter type.
     * @param {string} cwe 
     * @param {string} [vectorType]
     * @returns {Array<string>} Seed values
     */
    generateDeterministicSeeds(cwe, vectorType = 'PARAMETER') {
        const raw = String(cwe || '').toUpperCase().trim();
        const match = raw.match(/\bCWE-\d+\b/);
        const normCwe = match ? match[0] : raw;
        const seedBank = {
            'CWE-22': [
                '../../../../etc/passwd',
                '..\\..\\..\\..\\windows\\win.ini',
                '....//....//....//etc/passwd',
                '/etc/passwd',
                'safe_file.txt'
            ],
            'CWE-89': [
                "' OR '1'='1",
                "1' OR '1'='1' --",
                "admin'--",
                "1; DROP TABLE users--",
                "normal_search_term"
            ],
            'CWE-78': [
                'hello; echo INJECTED_CMD_OUTPUT',
                'hello | echo INJECTED_CMD_OUTPUT',
                'hello && echo INJECTED_CMD_OUTPUT',
                '`echo INJECTED_CMD_OUTPUT`',
                'normal_filename.txt'
            ],
            'CWE-79': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '"><script>alert(1)</script>',
                'clean_user_input'
            ],
            'CWE-90': [
                '*(|(objectclass=*))',
                '*)(&)',
                'admin*',
                'valid_username'
            ],
            'CWE-643': [
                "' or ''='",
                "' or '1'='1",
                "1 or 1=1",
                "normal_item"
            ]
        };

        return seedBank[normCwe] || ['attack_probe_default', 'benign_probe_default'];
    }

    /**
     * Generates mutated variations of seed values.
     * @param {Array<string>} seeds 
     * @returns {Array<string>} Mutated values
     */
    mutateSeeds(seeds) {
        const mutations = new Set(seeds);
        for (const seed of seeds) {
            // URL encoding
            mutations.add(encodeURIComponent(seed));
            // Double URL encoding
            mutations.add(encodeURIComponent(encodeURIComponent(seed)));
            // Null-byte injection
            mutations.add(`${seed}%00`);
            // Trailing space / comments
            mutations.add(`${seed} `);
            mutations.add(`${seed}/*comment*/`);
        }
        return Array.from(mutations);
    }

    /**
     * Searches for a concrete witness that satisfies the hypothesis's security condition.
     * @param {Object} hypothesis VulnerabilityHypothesis
     * @param {Function} executionRunner Async function: (inputProbe) => Promise<ExecutionResult>
     * @param {Object} [options]
     * @returns {Promise<Object>} WitnessSearchResult
     */
    async searchWitness(hypothesis, executionRunner, options = {}) {
        if (!hypothesis || typeof executionRunner !== 'function') {
            throw new Error('hypothesis and executionRunner must be provided');
        }

        const cwe = hypothesis.cwe;
        const oracle = this.securityRegistry.getOracle(cwe);
        const maxExecutions = options.maxExecutions || this.maxExecutionsDefault;
        const timeoutMs = options.timeoutMs || this.timeoutMsDefault;
        const startTime = Date.now();

        // 1. Build seed corpus (Deterministic + Optional Untrusted LLM seeds)
        const deterministicSeeds = this.generateDeterministicSeeds(cwe, hypothesis.attack_surface);
        const llmSeeds = Array.isArray(options.untrustedLlmSeeds) ? options.untrustedLlmSeeds : [];
        const baseCorpus = [...new Set([...deterministicSeeds, ...llmSeeds])];
        const fullQueue = this.mutateSeeds(baseCorpus);

        let executionCount = 0;
        let mutationsTested = 0;
        const searchLog = [];

        // 2. Budgeted execution search loop
        for (const candidateValue of fullQueue) {
            if (executionCount >= maxExecutions) {
                break;
            }
            if (Date.now() - startTime >= timeoutMs) {
                break;
            }

            executionCount++;
            mutationsTested++;

            const inputProbe = {
                parameter: hypothesis.source || 'param',
                value: candidateValue,
                type: hypothesis.attack_surface || 'PARAMETER'
            };

            try {
                const execResult = await executionRunner(inputProbe);
                let conditionSatisfied = false;
                let oracleEvaluation = null;

                if (oracle) {
                    oracleEvaluation = oracle.evaluate(execResult, inputProbe, { hypothesis });
                    conditionSatisfied = oracleEvaluation.condition_satisfied;
                } else {
                    // Fallback generic heuristic
                    conditionSatisfied = (execResult.sink_tainted === true);
                }

                searchLog.push({
                    attempt: executionCount,
                    value: candidateValue,
                    exit_code: execResult.exitCode,
                    condition_satisfied: conditionSatisfied
                });

                if (conditionSatisfied) {
                    const elapsedMs = Date.now() - startTime;
                    return {
                        status: 'WITNESS_FOUND',
                        witness_input: inputProbe,
                        oracle_result: oracleEvaluation,
                        execution_result: execResult,
                        search_metrics: {
                            execution_count: executionCount,
                            mutations_tested: mutationsTested,
                            duration_ms: elapsedMs,
                            termination_reason: 'SECURITY_CONDITION_SATISFIED'
                        },
                        search_log: searchLog
                    };
                }
            } catch (err) {
                searchLog.push({
                    attempt: executionCount,
                    value: candidateValue,
                    error: err.message
                });
            }
        }

        const elapsedMs = Date.now() - startTime;
        return {
            status: 'SEARCH_BUDGET_EXHAUSTED',
            witness_input: null,
            oracle_result: null,
            search_metrics: {
                execution_count: executionCount,
                mutations_tested: mutationsTested,
                duration_ms: elapsedMs,
                termination_reason: executionCount >= maxExecutions ? 'MAX_EXECUTIONS_REACHED' : 'TIMEOUT_REACHED'
            },
            search_log: searchLog
        };
    }
}
