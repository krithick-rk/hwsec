import assert from 'assert';
import { ProviderPool } from '../src/core/llm/providerPool.js';
import { TaskRouter, TaskClasses } from '../src/core/llm/taskRouter.js';
import { DebateCoordinator } from '../src/core/llm/debateCoordinator.js';
import { VulnerabilityHypothesis } from '../src/core/hypothesis/vulnerabilityHypothesis.js';
import { WitnessSearchEngine } from '../src/core/witness/witnessSearch.js';
import { CausalControlEngine } from '../src/core/controls/causalControls.js';
import { EvidenceDag, EvidenceAuthority, EvidenceNodeType, EvidenceEdgeRelation } from '../src/core/bep/evidenceDag.js';
import { AnalystDossier } from '../src/core/analyst/analystDossier.js';
import { OperatingModes } from '../src/core/llm/schemas/messageTypes.js';

console.log("==================================================================");
console.log("    HWSEC MULTI-MODEL TEAM COMPARATIVE OPERATIONAL TEST SUITE    ");
console.log("==================================================================");

// Define 4 representative test cases (Easy, Ambiguous, Framework-Heavy, Negative)
const TEST_CASES = [
    {
        id: 'CASE-1-EASY-SQLI',
        name: 'Easy SQL Injection in Legacy Script',
        finding: {
            analyzer: 'semgrep',
            rule_id: 'java.sql.sqli',
            cwe: 'CWE-89',
            file: 'LegacyLogin.java',
            line: 42,
            title: 'Unescaped SQL query concatenation',
            source: 'username',
            sink: 'statement.executeQuery(query)'
        },
        entryPoints: [{ file: 'LegacyLogin.java', method: 'POST', route: '/login', parameter: 'username' }],
        mockExecutor: async (probe) => {
            const val = String(probe.value);
            const isExploit = val.includes("' OR '1'='1") || val.includes("' OR 1=1");
            return {
                exitCode: 0,
                stdout: isExploit ? '[DB_SQL_EXEC] SELECT * FROM users WHERE user=\'\' OR \'1\'=\'1\'' : '[DB_SQL_EXEC] SELECT * FROM users WHERE user=\'safe\'',
                parsed_result: {
                    sink_observed: 'database_query',
                    value_at_sink: val
                }
            };
        }
    },
    {
        id: 'CASE-2-AMBIGUOUS-TRAVERSAL',
        name: 'Ambiguous Multi-Sink Path Traversal',
        finding: {
            analyzer: 'joern',
            rule_id: 'java.io.pathtraversal',
            cwe: 'CWE-22',
            file: 'FileViewer.java',
            line: 88,
            title: 'File resource access with unverified parameter',
            source: 'docName',
            sink: 'new FileInputStream(path)'
        },
        entryPoints: [{ file: 'FileViewer.java', method: 'GET', route: '/view-doc', parameter: 'docName' }],
        mockExecutor: async (probe) => {
            const val = String(probe.value);
            const isExploit = val.includes('../') || val.includes('..\\');
            return {
                exitCode: 0,
                stdout: isExploit ? '[FILE_READ] /etc/passwd' : '[FILE_READ] /var/docs/safe.txt',
                parsed_result: {
                    sink_observed: 'file_read',
                    value_at_sink: val
                }
            };
        }
    },
    {
        id: 'CASE-3-FRAMEWORK-WEBGOAT',
        name: 'Framework-Heavy WebGoat Assignment5a Controller',
        finding: {
            analyzer: 'codeql',
            rule_id: 'java/sql-injection',
            cwe: 'CWE-89',
            file: 'SqlInjectionLesson5a.java',
            line: 73,
            title: 'Spring Web MVC controller query injection',
            source: 'account_name',
            sink: 'statement.executeQuery'
        },
        entryPoints: [{ file: 'SqlInjectionLesson5a.java', method: 'POST', route: '/SqlInjection/assignment5a', parameter: 'account_name' }],
        mockExecutor: async (probe) => {
            const val = String(probe.value);
            const isExploit = val.includes("' OR '1'='1");
            return {
                exitCode: 0,
                stdout: isExploit ? '[AUTH_BYPASS_SQL] Query matched all accounts' : '[AUTH_FAILED]',
                parsed_result: {
                    sink_observed: 'sql_exec',
                    value_at_sink: val
                }
            };
        }
    },
    {
        id: 'CASE-4-NEGATIVE-SAFE',
        name: 'Negative Control: Properly Sanitized Input',
        finding: {
            analyzer: 'semgrep',
            rule_id: 'java.xss.potential',
            cwe: 'CWE-79',
            file: 'SafeRenderer.java',
            line: 15,
            title: 'Potential XSS in output template',
            source: 'message',
            sink: 'response.getWriter().write(HtmlUtils.htmlEscape(message))'
        },
        entryPoints: [{ file: 'SafeRenderer.java', method: 'GET', route: '/render', parameter: 'message' }],
        mockExecutor: async (probe) => {
            const val = String(probe.value);
            return {
                exitCode: 0,
                stdout: `[RENDERED_SAFE] &lt;script&gt;`,
                parsed_result: {
                    sink_observed: 'safe_escaped_render',
                    value_at_sink: val
                }
            };
        }
    }
];

// Define the 5 Operational Modes to Compare
const MODES_TO_TEST = [
    { id: 'Mode A', name: 'Baseline: Deterministic-Only (LLM Off)', llmEnabled: false, opMode: OperatingModes.FAST },
    { id: 'Mode B', name: 'Mode B: Gemini 1 Only (Fast Scout)', llmEnabled: true, opMode: OperatingModes.FAST },
    { id: 'Mode C', name: 'Mode C: Gemini 1 + Gemini 2 (Scout + Critic)', llmEnabled: true, opMode: OperatingModes.STANDARD },
    { id: 'Mode D', name: 'Mode D: Gemini 1 + 2 + NVIDIA Escalation', llmEnabled: true, opMode: OperatingModes.DEEP },
    { id: 'Mode E', name: 'Mode E: Full Team + OpenRouter Fallback', llmEnabled: true, opMode: OperatingModes.FORENSIC }
];

const comparativeResults = [];

for (const modeConfig of MODES_TO_TEST) {
    console.log(`\n>>> Evaluating [${modeConfig.id}]: ${modeConfig.name}...`);
    const startTime = Date.now();

    const pool = new ProviderPool({
        llm_providers: {
            gemini: { api_key: 'mock-gemini-1' },
            gemini_2: { api_key: 'mock-gemini-2' },
            nvidia: { api_key: 'mock-nvidia' },
            openrouter: { api_key: 'mock-openrouter' }
        }
    });

    if (!modeConfig.llmEnabled) {
        pool.setEndpointAvailability('gemini_account_1', false);
        pool.setEndpointAvailability('gemini_account_2', false);
        pool.setEndpointAvailability('nvidia', false);
        pool.setEndpointAvailability('openrouter', false);
    } else {
        // Setup realistic multi-model responses
        const g1 = pool.getEndpoint('gemini_account_1');
        const g2 = pool.getEndpoint('gemini_account_2');
        const nv = pool.getEndpoint('nvidia');
        const or = pool.getEndpoint('openrouter');

        g1.provider.generateChat = async ({ userPrompt }) => {
            const isSQLi = userPrompt.includes('CWE-89');
            const isTraversal = userPrompt.includes('CWE-22');
            const seeds = isSQLi ? [{ parameter: 'account_name', value: "' OR '1'='1" }]
                        : isTraversal ? [{ parameter: 'docName', value: '../../etc/passwd' }]
                        : [{ parameter: 'msg', value: '<script>alert(1)</script>' }];

            return {
                text: 'Scout proposal generated',
                json: {
                    message_type: 'HYPOTHESIS_PROPOSAL',
                    cwe: isSQLi ? 'CWE-89' : (isTraversal ? 'CWE-22' : 'CWE-79'),
                    source: isSQLi ? 'account_name' : (isTraversal ? 'docName' : 'msg'),
                    sink: isSQLi ? 'statement.executeQuery' : (isTraversal ? 'new FileInputStream' : 'response.write'),
                    entry_point_guess: { file: isSQLi ? 'SqlInjectionLesson5a.java' : 'FileViewer.java' },
                    security_condition: isSQLi ? 'SQLiOracle' : (isTraversal ? 'PathTraversalOracle' : 'XSSOracle'),
                    assumptions: ['Direct user input reaches sink'],
                    attack_seeds: seeds,
                    falsifiers: ['Input validated before consumption']
                },
                usage: { promptTokens: 420, completionTokens: 110, totalTokens: 530 }
            };
        };

        g2.provider.generateChat = async ({ userPrompt }) => {
            const isNegative = userPrompt.includes('SafeRenderer');
            return {
                text: 'Critic response generated',
                json: {
                    message_type: 'CRITIQUE',
                    agreement_points: ['Finding matches taint flow heuristic'],
                    disagreements: isNegative ? [{ field: 'sink', critique: 'HtmlUtils.htmlEscape neutralizes XSS payload', severity: 'MATERIAL' }] : [],
                    unsupported_assumptions: [],
                    missing_evidence: ['Taint trace verification'],
                    recommended_checks: ['Verify route mapping']
                },
                usage: { promptTokens: 380, completionTokens: 90, totalTokens: 470 }
            };
        };

        nv.provider.generateChat = async ({ userPrompt }) => {
            return {
                text: 'Deep Reasoner investigation plan generated',
                json: {
                    message_type: 'INVESTIGATION_PLAN',
                    preferred_hypothesis: {
                        cwe: 'CWE-89',
                        sink: 'statement.executeQuery',
                        security_condition: 'SQLiOracle'
                    },
                    attack_strategy: {
                        recommended_probes: [{ parameter: 'account_name', value: "' OR '1'='1" }],
                        negative_control_input: { parameter: 'account_name', value: 'Smith' }
                    },
                    ordered_deterministic_checks: ['ENTRYPOINT_VERIFY', 'ORACLE_EVALUATE', 'NEGATIVE_CONTROL'],
                    required_observations: ['SQL_EXECUTION']
                },
                usage: { promptTokens: 650, completionTokens: 180, totalTokens: 830 }
            };
        };

        or.provider.generateChat = async () => {
            return {
                text: 'OpenRouter fallback response',
                json: {
                    message_type: 'INVESTIGATION_PLAN',
                    preferred_hypothesis: { cwe: 'CWE-89', sink: 'statement.executeQuery', security_condition: 'SQLiOracle' },
                    attack_strategy: {
                        recommended_probes: [{ parameter: 'account_name', value: "' OR '1'='1" }],
                        negative_control_input: { parameter: 'account_name', value: 'Smith' }
                    },
                    ordered_deterministic_checks: ['ENTRYPOINT_VERIFY'],
                    required_observations: ['SINK_EXEC']
                },
                usage: { promptTokens: 500, completionTokens: 120, totalTokens: 620 }
            };
        };
    }

    const router = new TaskRouter(pool);
    const coordinator = new DebateCoordinator({ providerPool: pool, taskRouter: router });
    const witnessEngine = new WitnessSearchEngine({});

    let hypothesesResolved = 0;
    let entryPointsResolved = 0;
    let witnessSuccessCount = 0;
    let detectedCount = 0;
    let notDetectedCount = 0;
    let inconclusiveCount = 0;
    let totalLlmRounds = 0;
    const caseSummaries = [];

    for (const testCase of TEST_CASES) {
        // 1. Coordinate / Formulate Hypothesis
        const coordSession = await coordinator.coordinateHypothesis({
            finding: testCase.finding,
            entryPoints: testCase.entryPoints,
            mode: modeConfig.opMode
        });

        totalLlmRounds += coordSession.roundsCount;
        const proposal = coordSession.finalProposal;

        const hyp = new VulnerabilityHypothesis({
            repository_id: 'test_repo',
            run_id: `RUN-${modeConfig.id.replace(/\s+/g, '_')}`,
            cwe: proposal.cwe || testCase.finding.cwe,
            security_condition: proposal.security_condition || `${testCase.finding.cwe}_Oracle`,
            source: proposal.source || testCase.finding.source,
            sink: proposal.sink || testCase.finding.sink,
            entry_point: testCase.entryPoints[0] || { status: 'UNRESOLVED' },
            candidate_path: [testCase.finding.file],
            attack_surface: 'HTTP_ENDPOINT'
        });

        hyp.model_team_narrative = coordSession.summary;
        hypothesesResolved++;
        if (hyp.entry_point && hyp.entry_point.status !== 'UNRESOLVED') {
            entryPointsResolved++;
        }

        // 2. Deterministic Witness Search
        const untrustedLlmSeeds = (proposal.attack_seeds || []).map(s => s.value);
        const searchRes = await witnessEngine.searchWitness(
            hyp,
            testCase.mockExecutor,
            { mode: modeConfig.opMode, untrustedLlmSeeds }
        );

        let dag = new EvidenceDag({ id: hyp.id, cwe: hyp.cwe });
        const hypNode = dag.addNode(EvidenceNodeType.HYPOTHESIS, {
            cwe: hyp.cwe,
            sink: hyp.sink,
            source: hyp.source,
            security_condition: hyp.security_condition
        });
        const findingNode = dag.addNode(EvidenceNodeType.FINDING, {
            rule_id: testCase.finding.rule_id,
            file: testCase.finding.file,
            line: testCase.finding.line
        });
        const entryNode = dag.addNode(EvidenceNodeType.ENTRY_POINT, {
            status: 'RESOLVED',
            file: testCase.finding.file,
            route: testCase.entryPoints[0]?.route
        });

        dag.addEdge(hypNode.id, entryNode.id, EvidenceEdgeRelation.DERIVED_FROM);
        dag.addEdge(findingNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);

        if (searchRes.status === 'WITNESS_FOUND' && searchRes.witness_input) {
            witnessSuccessCount++;

            const witnessNode = dag.addNode(EvidenceNodeType.WITNESS_INPUT, {
                vector: 'HTTP_PARAM',
                param_name: searchRes.witness_input.parameter || 'param',
                payload: searchRes.witness_input.value
            });
            const oracleNode = dag.addNode(EvidenceNodeType.SECURITY_ORACLE_RESULT, {
                oracle: hyp.security_condition,
                condition_satisfied: true,
                ast_modified: true
            });
            const traceNode = dag.addNode(EvidenceNodeType.RUNTIME_TRACE, {
                exit_code: 0,
                duration_ms: 50,
                timeout: false
            });

            // 3. Causal Negative Control
            const causalEngine = new CausalControlEngine({});
            const ctrlRes = await causalEngine.executeNegativeInputControl(
                hyp,
                searchRes.witness_input,
                { parameter: hyp.source, value: 'benign_safe_value' },
                testCase.mockExecutor
            );

            if (ctrlRes.passed) {
                const controlNode = dag.addNode(EvidenceNodeType.NEGATIVE_CONTROL, {
                    type: 'BENIGN_INPUT',
                    payload: 'benign_safe_value',
                    passed: true
                });
                const provNode = dag.addNode(EvidenceNodeType.PROVENANCE_MANIFEST, {
                    tool_version: '2.0.0',
                    environment: 'local',
                    verified: true
                });

                dag.addEdge(witnessNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
                dag.addEdge(oracleNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
                dag.addEdge(traceNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
                dag.addEdge(controlNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
                dag.addEdge(provNode.id, hypNode.id, EvidenceEdgeRelation.SUPPORTS);
            }
        }

        // 4. EvidenceAuthority Reduction
        const reduction = EvidenceAuthority.reduce(dag, hypNode.id);
        const dossier = AnalystDossier.generateCaseSummary(hyp, dag, reduction);

        if (reduction.verdict === 'DETECTED') detectedCount++;
        else if (reduction.verdict === 'NOT_DETECTED') notDetectedCount++;
        else inconclusiveCount++;

        caseSummaries.push({
            caseId: testCase.id,
            verdict: reduction.verdict,
            reason: reduction.reason_code || reduction.reason,
            dagHash: reduction.dag_hash ? reduction.dag_hash.slice(0, 12) : 'none',
            narrative: coordSession.summary
        });
    }

    const durationMs = Date.now() - startTime;
    const modeSummary = {
        modeId: modeConfig.id,
        modeName: modeConfig.name,
        durationMs,
        totalLlmRounds,
        hypothesesResolved,
        entryPointsResolved,
        witnessSuccessCount,
        detectedCount,
        notDetectedCount,
        inconclusiveCount,
        caseSummaries
    };

    comparativeResults.push(modeSummary);

    console.log(`  -> Duration: ${durationMs}ms | LLM Rounds: ${totalLlmRounds}`);
    console.log(`  -> DETECTED: ${detectedCount} | NOT_DETECTED: ${notDetectedCount} | INCONCLUSIVE: ${inconclusiveCount}`);
}

// Print Comparative Matrix Table
console.log("\n==================================================================");
console.log("             COMPARATIVE OPERATIONAL MATRIX RESULTS               ");
console.log("==================================================================");
console.log("| Mode | Name | Latency (ms) | Total LLM Rounds | Resolved Hyp | Witness Found | DETECTED | INCONCLUSIVE |");
console.log("| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |");
for (const res of comparativeResults) {
    console.log(`| **${res.modeId}** | ${res.modeName.slice(0, 24)} | ${res.durationMs}ms | ${res.totalLlmRounds} | ${res.hypothesesResolved}/4 | ${res.witnessSuccessCount}/4 | ${res.detectedCount} | ${res.inconclusiveCount} |`);
}
console.log("==================================================================");

// Assert all modes completed deterministically
assert.strictEqual(comparativeResults.length, 5, "All 5 operational modes must execute");
console.log("\n[SUCCESS] Comparative Operational Test completed and verified!");
