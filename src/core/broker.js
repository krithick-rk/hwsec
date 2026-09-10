import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// Domain Tools
import { VerilatorTool } from '../domains/hardware/tools/verilator.js';
import { YosysTool } from '../domains/hardware/tools/yosys.js';
import { AflTool } from '../domains/hardware/tools/afl.js';
import { SymbiYosysTool } from '../domains/hardware/tools/symbiyosys.js';
import { SpikeTool } from '../domains/hardware/tools/spike.js';
import { SemgrepTool } from '../domains/software/tools/semgrep.js';
import { CodeQLTool } from '../domains/software/tools/codeql.js';
import { JoernTool } from '../domains/software/tools/joern.js';

// Section 20 Core Capability Providers
import { WitnessSearchEngine } from './witness/witnessSearch.js';
import { ConstraintRefinementProvider } from './refinement/constraintRefinementProvider.js';
import { DirectSinkObservationProvider } from './observation/runtimeObservationProvider.js';
import { CausalControlEngine } from './controls/causalControls.js';
import { EvidenceDag, EvidenceAuthority, EvidenceNodeType, EvidenceEdgeRelation, canonicalHash } from './bep/evidenceDag.js';
import { VulnerabilityHypothesis } from './hypothesis/vulnerabilityHypothesis.js';
import { EntryPointInventory } from './inventory/entryPointInventory.js';
import { defaultSecurityRegistry } from './oracles/securityConditionRegistry.js';
import { RepositoryDiscovery } from './discovery.js';

export const BrokerCapability = {
    // Section 20: 9 Core Broker Capabilities
    DISCOVERY: 'DISCOVERY',
    SLICE: 'SLICE',
    HYPOTHESIS: 'HYPOTHESIS',
    WITNESS_SEARCH: 'WITNESS_SEARCH',
    CONSTRAINT_REFINEMENT: 'CONSTRAINT_REFINEMENT',
    RUNTIME_OBSERVATION: 'RUNTIME_OBSERVATION',
    CONTROL_EXECUTION: 'CONTROL_EXECUTION',
    EVIDENCE_ASSEMBLY: 'EVIDENCE_ASSEMBLY',
    VERDICT_REDUCTION: 'VERDICT_REDUCTION',

    // Tool & domain capabilities
    LEXICAL_PATTERN_SAST: 'sast_pattern_scan',
    AST_ANALYSIS: 'ast_analysis',
    SEMANTIC_DATAFLOW: 'deep_dataflow',
    CODE_PROPERTY_GRAPH: 'graph_dataflow',
    TAINT_ANALYSIS: 'taint_analysis',
    DEPENDENCY_ANALYSIS: 'dependency_analysis',
    BUILD_AWARE_ANALYSIS: 'build_aware_analysis',
    FORMAL_RTL_VERIFICATION: 'formal_invariant_verification',
    RTL_LINT: 'rtl_lint',
    RTL_FORMAL: 'rtl_formal',
    UNIT_TEST_REPRODUCER: 'unit_test_reproducer'
};

export class ToolRegistry {
    constructor(config = {}) {
        this.config = config;
        this.tools = new Map();
        this._registerDefaults();
    }

    _registerDefaults() {
        this.register(new VerilatorTool(this.config));
        this.register(new YosysTool(this.config));
        this.register(new AflTool(this.config));
        this.register(new SymbiYosysTool(this.config));
        this.register(new SpikeTool(this.config));
        this.register(new SemgrepTool(this.config));
        this.register(new CodeQLTool(this.config));
        this.register(new JoernTool(this.config));
    }

    register(toolAdapter) {
        if (!toolAdapter || !toolAdapter.id) {
            throw new Error("Cannot register tool adapter without an id");
        }
        this.tools.set(toolAdapter.id, toolAdapter);
    }

    getTool(id) {
        return this.tools.get(id) || null;
    }

    getAllTools() {
        return Array.from(this.tools.values());
    }

    /**
     * Finds registered tools that satisfy a requested capability and optional language filter.
     * @param {Object} query
     * @param {string} query.capability
     * @param {string[]} [query.languages=[]]
     * @returns {Array<import('../tools/base.js').ToolAdapter>}
     */
    findToolsForCapability({ capability, languages = [] }) {
        const matches = [];
        for (const tool of this.tools.values()) {
            if (tool.capabilities.includes(capability)) {
                if (languages.length === 0) {
                    matches.push(tool);
                } else {
                    const hasLang = languages.some(l => tool.supportedLanguages.includes(l));
                    if (hasLang) matches.push(tool);
                }
            }
        }
        return matches;
    }
}

export class AnalysisBroker {
    /**
     * @param {Object} config 
     * @param {ToolRegistry} [registry] 
     * @param {Object} [db] 
     */
    constructor(config = {}, registry = null, db = null) {
        this.config = config || {};
        this.registry = registry || new ToolRegistry(this.config);
        this.db = db;
    }

    setDb(db) {
        this.db = db;
    }

    /**
     * Probes all registered tools in parallel with lightweight timeouts.
     */
    async probeTools() {
        const available = [];
        const unavailable = [];

        for (const tool of this.registry.getAllTools()) {
            try {
                const check = await tool.checkInstalled();
                if (check.installed) {
                    available.push({
                        id: tool.id,
                        name: tool.name,
                        capabilities: tool.capabilities,
                        supportedLanguages: tool.supportedLanguages,
                        version: check.version || 'Detected'
                    });
                } else {
                    unavailable.push({
                        id: tool.id,
                        name: tool.name,
                        capabilities: tool.capabilities,
                        supportedLanguages: tool.supportedLanguages,
                        reason: check.error || 'Executable check failed'
                    });
                }
            } catch (err) {
                unavailable.push({
                    id: tool.id,
                    name: tool.name,
                    capabilities: tool.capabilities,
                    supportedLanguages: tool.supportedLanguages,
                    reason: err.message
                });
            }
        }

        return { available, unavailable };
    }

    /**
     * Dynamically selects the best set of analyzers based on language, vulnerability class,
     * repository structure, and prior disagreement context.
     * 
     * @param {Object} criteria
     * @param {string} criteria.language
     * @param {string} [criteria.cwe]
     * @param {string} [criteria.framework]
     * @param {boolean} [criteria.priorDisagreement=false]
     * @param {number} [criteria.costBudget]
     * @returns {Array<{ tool: Object, role: 'PRIMARY' | 'SECONDARY' | 'CROSS_CHECK' }>}
     */
    selectAnalyzers(criteria = {}) {
        const { language, cwe, framework, priorDisagreement = false } = criteria;
        const selected = [];

        const allTools = this.registry.getAllTools();
        const langMatches = allTools.filter(t => !language || t.supportedLanguages.includes(language));

        if (language === 'verilog') {
            for (const tool of langMatches) {
                if (tool.id === 'symbiyosys') {
                    selected.push({ tool, role: 'PRIMARY' });
                } else if (tool.id === 'yosys' || tool.id === 'verilator') {
                    selected.push({ tool, role: 'SECONDARY' });
                }
            }
            return selected;
        }

        // Software languages: Python, Java, C, C++, Go
        const semgrep = langMatches.find(t => t.id === 'semgrep');
        if (semgrep) {
            selected.push({ tool: semgrep, role: 'PRIMARY' });
        }

        const joern = langMatches.find(t => t.id === 'joern');
        if (joern) {
            selected.push({ tool: joern, role: priorDisagreement ? 'CROSS_CHECK' : 'SECONDARY' });
        }

        const codeql = langMatches.find(t => t.id === 'codeql');
        if (codeql) {
            selected.push({ tool: codeql, role: 'CROSS_CHECK' });
        }

        return selected;
    }

    /**
     * Section 20 Capability: DISCOVERY
     */
    async executeDiscovery(request = {}) {
        const targetDir = request.targetDir || request.files?.[0] || process.cwd();
        const inventoryScanner = new EntryPointInventory();
        const entryPoints = inventoryScanner.discover(targetDir);
        const repoDiscovery = new RepositoryDiscovery(this.config);
        const { inventory, summary } = repoDiscovery.discover(targetDir);
        return {
            status: 'SUCCESS',
            capability: BrokerCapability.DISCOVERY,
            entryPoints,
            inventory,
            summary,
            provenance: {
                timestamp: new Date().toISOString(),
                targetDir
            }
        };
    }

    /**
     * Section 20 Capability: SLICE
     */
    async executeSlice(request = {}) {
        const { targetFile, targetLine, candidatePath = [] } = request;
        const sliceData = {
            targetFile: targetFile || candidatePath[0] || 'unknown',
            targetLine: targetLine || 1,
            candidatePath,
            slice_sha256: canonicalHash({ targetFile, targetLine, candidatePath })
        };
        return {
            status: 'SUCCESS',
            capability: BrokerCapability.SLICE,
            slice: sliceData,
            provenance: {
                timestamp: new Date().toISOString()
            }
        };
    }

    /**
     * Section 20 Capability: HYPOTHESIS
     */
    async executeHypothesis(request = {}) {
        const { findings = [], targetDir = process.cwd(), runId = `RUN-${Date.now()}`, repositoryId = 'default_repo' } = request;
        const inventoryScanner = new EntryPointInventory();
        const entryPoints = inventoryScanner.discover(targetDir);
        const hypotheses = [];

        for (const finding of findings) {
            const hyp = VulnerabilityHypothesis.fromFinding(finding, { run_id: runId, repository_id: repositoryId });
            const resolvedEp = inventoryScanner.resolveForHypothesis(hyp);
            hyp.setEntryPoint(resolvedEp);
            hypotheses.push(hyp);
        }

        return {
            status: 'SUCCESS',
            capability: BrokerCapability.HYPOTHESIS,
            hypotheses,
            entryPoints,
            provenance: {
                timestamp: new Date().toISOString(),
                runId
            }
        };
    }

    /**
     * Section 20 Capability: WITNESS_SEARCH
     */
    async executeWitnessSearch(request = {}) {
        const { hypothesis, executor, mode = 'STANDARD', options = {} } = request;
        if (!hypothesis || typeof executor !== 'function') {
            throw new Error('[AnalysisBroker WITNESS_SEARCH] hypothesis and executor function are required');
        }

        const modeBudgets = {
            FAST: { maxExecutions: 5, timeoutMs: 5000 },
            STANDARD: { maxExecutions: 25, timeoutMs: 20000 },
            DEEP: { maxExecutions: 50, timeoutMs: 60000 },
            FORENSIC: { maxExecutions: 100, timeoutMs: 120000 }
        };

        const budget = modeBudgets[mode.toUpperCase()] || modeBudgets.STANDARD;
        const searchEngine = new WitnessSearchEngine({
            maxExecutions: options.maxExecutions || budget.maxExecutions,
            timeoutMs: options.timeoutMs || budget.timeoutMs,
            securityRegistry: options.securityRegistry || defaultSecurityRegistry
        });

        const result = await searchEngine.searchWitness(hypothesis, executor, options);
        return {
            status: result.status,
            capability: BrokerCapability.WITNESS_SEARCH,
            witness_input: result.witness_input,
            oracle_result: result.oracle_result,
            execution_result: result.execution_result,
            search_metrics: result.search_metrics,
            search_log: result.search_log,
            provenance: {
                timestamp: new Date().toISOString(),
                mode,
                hypothesis_id: hypothesis.id
            }
        };
    }

    /**
     * Section 20 Capability: CONSTRAINT_REFINEMENT
     */
    async executeConstraintRefinement(request = {}) {
        const { slice = {}, hypothesis = {}, constraints = [], options = {} } = request;
        const provider = new ConstraintRefinementProvider(options);
        const result = await provider.solve(slice, hypothesis, constraints, options);
        return {
            status: result.status,
            capability: BrokerCapability.CONSTRAINT_REFINEMENT,
            model_artifact: result.model_artifact,
            concrete_input: result.concrete_input,
            duration_ms: result.duration_ms,
            provenance: result.provenance
        };
    }

    /**
     * Section 20 Capability: RUNTIME_OBSERVATION
     */
    async executeRuntimeObservation(request = {}) {
        const { target, input, executor, options = {} } = request;
        if (!input || typeof executor !== 'function') {
            throw new Error('[AnalysisBroker RUNTIME_OBSERVATION] input and executor function are required');
        }
        const provider = options.provider || new DirectSinkObservationProvider(options);
        const result = await provider.observe(target || {}, input, executor, options);
        return {
            status: 'SUCCESS',
            capability: BrokerCapability.RUNTIME_OBSERVATION,
            observationRecord: result,
            sink_observed: result.sink_observed,
            sink_tainted: result.sink_tainted,
            provenance: result.provenance
        };
    }

    /**
     * Section 20 Capability: CONTROL_EXECUTION
     */
    async executeControlExecution(request = {}) {
        const { controlType = 'NEGATIVE_INPUT', hypothesis, attackInput, benignInput, patchedTarget, executor, options = {} } = request;
        if (!hypothesis || !attackInput || typeof executor !== 'function') {
            throw new Error('[AnalysisBroker CONTROL_EXECUTION] hypothesis, attackInput, and executor are required');
        }
        const engine = new CausalControlEngine(options);
        let result;
        if (controlType === 'PATCH_DIFFERENTIAL' && patchedTarget) {
            result = await engine.executePatchDifferentialControl(hypothesis, attackInput, { file: hypothesis.targetFile || hypothesis.candidate_path?.[0] }, patchedTarget, executor);
        } else {
            result = await engine.executeNegativeInputControl(hypothesis, attackInput, benignInput || { parameter: hypothesis.source || 'param', value: 'benign_safe_input_123' }, executor);
        }
        return {
            status: result.passed ? 'CONTROL_PASSED' : 'CONTROL_FAILED',
            capability: BrokerCapability.CONTROL_EXECUTION,
            controlResult: result,
            passed: result.passed,
            delta: result.delta,
            provenance: result.provenance
        };
    }

    /**
     * Section 20 Capability: EVIDENCE_ASSEMBLY
     */
    async executeEvidenceAssembly(request = {}) {
        const {
            runId = `RUN-${Date.now()}`,
            hypothesis,
            entryPoint,
            witness,
            oracleResult,
            solverModel,
            observation,
            controlResult,
            patchResult,
            provenanceManifest
        } = request;

        if (!hypothesis) {
            throw new Error('[AnalysisBroker EVIDENCE_ASSEMBLY] hypothesis is required');
        }

        const dag = new EvidenceDag({ run_id: runId });
        const hypNode = dag.addNode(EvidenceNodeType.HYPOTHESIS, hypothesis.toJSON ? hypothesis.toJSON() : hypothesis, hypothesis.id);

        if (entryPoint) {
            const epNode = dag.addNode(EvidenceNodeType.ENTRY_POINT, entryPoint, entryPoint.id || `EP-${entryPoint.type}`);
            dag.addEdge(hypNode.id, epNode.id, EvidenceEdgeRelation.SUPPORTS);
        }

        if (witness) {
            const wNode = dag.addNode(EvidenceNodeType.WITNESS_INPUT, witness, `WITNESS-${canonicalHash(witness).substring(0, 10)}`);
            dag.addEdge(hypNode.id, wNode.id, EvidenceEdgeRelation.SUPPORTS);

            if (observation) {
                const obsNode = dag.addNode(EvidenceNodeType.RUNTIME_TRACE, observation, `OBS-${canonicalHash(observation).substring(0, 10)}`);
                dag.addEdge(wNode.id, obsNode.id, EvidenceEdgeRelation.OBSERVED_IN);

                if (observation.sink_observed) {
                    const sinkNode = dag.addNode(EvidenceNodeType.SINK_EVENT, { sink: observation.sink_observed, value: observation.value_at_sink }, `SINK-${canonicalHash(observation.sink_observed).substring(0, 10)}`);
                    dag.addEdge(obsNode.id, sinkNode.id, EvidenceEdgeRelation.OBSERVED_IN);
                }
            }
        }

        if (solverModel) {
            const smNode = dag.addNode(EvidenceNodeType.SOLVER_MODEL, solverModel, `MODEL-${canonicalHash(solverModel).substring(0, 10)}`);
            dag.addEdge(hypNode.id, smNode.id, EvidenceEdgeRelation.SUPPORTS);
        }

        if (controlResult) {
            const cNode = dag.addNode(EvidenceNodeType.NEGATIVE_CONTROL, controlResult, `CTRL-${canonicalHash(controlResult).substring(0, 10)}`);
            dag.addEdge(hypNode.id, cNode.id, controlResult.passed ? EvidenceEdgeRelation.SUPPORTS : EvidenceEdgeRelation.REFUTES);
        }

        if (patchResult) {
            const pNode = dag.addNode(EvidenceNodeType.PATCH_RESULT, patchResult, `PATCH-${canonicalHash(patchResult).substring(0, 10)}`);
            dag.addEdge(hypNode.id, pNode.id, EvidenceEdgeRelation.SUPPORTS);
        }

        if (oracleResult) {
            const oNode = dag.addNode(EvidenceNodeType.SECURITY_ORACLE_RESULT, oracleResult, `ORACLE-${canonicalHash(oracleResult).substring(0, 10)}`);
            dag.addEdge(hypNode.id, oNode.id, oracleResult.condition_satisfied ? EvidenceEdgeRelation.SUPPORTS : EvidenceEdgeRelation.REFUTES);
        }

        const provData = {
            created_at: new Date().toISOString(),
            broker_version: '2.0.0',
            verified: true,
            ...(provenanceManifest || {})
        };
        const provNode = dag.addNode(
            EvidenceNodeType.PROVENANCE_MANIFEST,
            provData,
            `PROV-${runId}`
        );
        dag.addEdge(hypNode.id, provNode.id, EvidenceEdgeRelation.SAME_ENVIRONMENT_AS);

        return {
            status: 'SUCCESS',
            capability: BrokerCapability.EVIDENCE_ASSEMBLY,
            dag,
            dagHash: dag.getRootHash(),
            provenance: {
                timestamp: new Date().toISOString(),
                runId
            }
        };
    }

    /**
     * Section 20 Capability: VERDICT_REDUCTION
     */
    async executeVerdictReduction(request = {}) {
        const { dag, hypothesisId, options = {} } = request;
        if (!dag) {
            throw new Error('[AnalysisBroker VERDICT_REDUCTION] dag is required');
        }
        const reduction = EvidenceAuthority.reduce(dag, hypothesisId, options);
        return {
            status: 'SUCCESS',
            capability: BrokerCapability.VERDICT_REDUCTION,
            reduction,
            verdict: reduction.verdict,
            reason: reduction.reason_code || reduction.reason,
            details: reduction.details,
            provenance: {
                timestamp: new Date().toISOString(),
                hypothesisId
            }
        };
    }

    /**
     * Dispatches a capability request across registered tools or core operational providers.
     * Supports single-tool dispatch or multi-analyzer cooperation and cross-checking.
     */
    async dispatch(request) {
        const { capability, languages = [], files = [], outputDir = 'hwsec-output/tools', runId = null, timeout = 120000, cooperative = false } = request;
        
        // Check for Core Broker Operational Capabilities (Section 20)
        switch (capability) {
            case BrokerCapability.DISCOVERY:
            case 'discovery':
                return this.executeDiscovery(request);
            case BrokerCapability.SLICE:
            case 'slice':
                return this.executeSlice(request);
            case BrokerCapability.HYPOTHESIS:
            case 'hypothesis':
                return this.executeHypothesis(request);
            case BrokerCapability.WITNESS_SEARCH:
            case 'witness_search':
                return this.executeWitnessSearch(request);
            case BrokerCapability.CONSTRAINT_REFINEMENT:
            case 'constraint_refinement':
                return this.executeConstraintRefinement(request);
            case BrokerCapability.RUNTIME_OBSERVATION:
            case 'runtime_observation':
                return this.executeRuntimeObservation(request);
            case BrokerCapability.CONTROL_EXECUTION:
            case 'control_execution':
                return this.executeControlExecution(request);
            case BrokerCapability.EVIDENCE_ASSEMBLY:
            case 'evidence_assembly':
                return this.executeEvidenceAssembly(request);
            case BrokerCapability.VERDICT_REDUCTION:
            case 'verdict_reduction':
                return this.executeVerdictReduction(request);
        }

        const candidateTools = this.registry.findToolsForCapability({ capability, languages });
        if (candidateTools.length === 0) {
            return {
                status: "NO_TOOL_AVAILABLE",
                findings: [],
                telemetry: { reason: `No registered tool satisfies capability '${capability}' for languages [${languages.join(', ')}]` }
            };
        }

        if (cooperative && candidateTools.length > 1) {
            return this.dispatchCooperative(request);
        }

        // Standard sequential fallback
        let lastResult = null;
        for (const tool of candidateTools) {
            const toolRunId = `TR-${crypto.randomBytes(4).toString('hex')}`;
            const startTime = new Date().toISOString();

            try {
                const result = await tool.run({
                    files,
                    capability,
                    language: languages[0] || null,
                    outputDir,
                    timeout,
                    config: this.config
                });

                if (this.db && runId) {
                    try {
                        this.db.saveToolRun({
                            id: toolRunId,
                            runId,
                            toolName: tool.name,
                            capability,
                            status: result.status,
                            startedAt: startTime,
                            finishedAt: new Date().toISOString(),
                            artifactDir: outputDir
                        });

                        for (const finding of (result.findings || [])) {
                            for (const ev of (finding.evidence || [])) {
                                this.db.saveEvidence({
                                    id: ev.id,
                                    toolRunId,
                                    fileId: null,
                                    artifactPath: ev.artifact_path,
                                    observation: ev.description,
                                    rawEvidence: ev.metadata
                                });
                            }
                        }
                    } catch (dbErr) {
                        console.warn(`[-] [AnalysisBroker] DB recording note: ${dbErr.message}`);
                    }
                }

                return {
                    toolId: tool.id,
                    toolName: tool.name,
                    status: result.status,
                    findings: result.findings || [],
                    toolErrors: result.toolErrors || [],
                    telemetry: result.telemetry || {}
                };
            } catch (err) {
                lastResult = {
                    toolId: tool.id,
                    status: "EXECUTION_ERROR",
                    findings: [],
                    telemetry: { error: err.message }
                };
            }
        }

        return lastResult || { status: "FAILED", findings: [], telemetry: {} };
    }

    /**
     * Executes multiple analyzers cooperatively over the same input,
     * cross-checks their outputs, and records explicit agreement/disagreement signals.
     */
    async dispatchCooperative(request) {
        const { capability, languages = [], files = [], outputDir = 'hwsec-output/tools', runId = null, timeout = 120000 } = request;
        const candidateTools = this.registry.findToolsForCapability({ capability, languages });

        const toolResults = [];
        const aggregatedFindings = [];
        const executedToolNames = [];

        for (const tool of candidateTools) {
            try {
                const res = await tool.run({
                    files,
                    capability,
                    language: languages[0] || null,
                    outputDir,
                    timeout,
                    config: this.config
                });
                executedToolNames.push(tool.name);
                toolResults.push({ toolId: tool.id, toolName: tool.name, result: res });
                if (Array.isArray(res.findings)) {
                    aggregatedFindings.push(...res.findings);
                }
            } catch (err) {
                toolResults.push({ toolId: tool.id, toolName: tool.name, error: err.message });
            }
        }

        // Cross-check findings across tools to identify agreement vs disagreement
        const locationMap = new Map(); // locKey -> Set<toolName>
        for (const finding of aggregatedFindings) {
            const loc = finding.source_locations?.[0]?.path;
            if (!loc) continue;
            const key = `${loc}:${finding.cwe_id || 'UNKNOWN'}`;
            if (!locationMap.has(key)) locationMap.set(key, new Set());
            locationMap.get(key).add(finding.source_tool || 'unknown');
        }

        const agreements = [];
        const disagreements = [];

        for (const [key, toolsFound] of locationMap.entries()) {
            if (toolsFound.size > 1) {
                agreements.push({ key, tools: Array.from(toolsFound) });
            } else {
                const missing = executedToolNames.filter(t => !toolsFound.has(t));
                disagreements.push({ key, reportingTools: Array.from(toolsFound), silentTools: missing });
            }
        }

        return {
            status: "COOPERATIVE_SUCCESS",
            executedTools: executedToolNames,
            findings: aggregatedFindings,
            cooperativeTelemetry: {
                totalFindings: aggregatedFindings.length,
                agreementsCount: agreements.length,
                disagreementsCount: disagreements.length,
                disagreements
            }
        };
    }

    /**
     * Validates and executes a structured action from an LLM/MCP agent.
     * Prevents shell injection and path traversal.
     */
    async executeStructuredAction(actionObj, repoRoot) {
        if (!actionObj || typeof actionObj !== 'object') {
            throw new Error("Invalid structured action: must be an object");
        }

        const { action, tool: toolId, target, timeout = 300 } = actionObj;

        if (action !== 'run_tool') {
            throw new Error(`Action '${action}' is not permitted. Only 'run_tool' is authorized.`);
        }

        const tool = this.registry.getTool(toolId);
        if (!tool) {
            throw new Error(`Tool '${toolId}' is not registered in ToolRegistry.`);
        }

        // Validate target path is strictly within repoRoot (Path Traversal Protection)
        const resolvedRepoRoot = path.resolve(repoRoot);
        const resolvedTarget = path.resolve(resolvedRepoRoot, target || '.');

        const relative = path.relative(resolvedRepoRoot, resolvedTarget);
        if (relative.startsWith('..') || path.isAbsolute(relative)) {
            throw new Error(`Path traversal attempt blocked: target '${target}' is outside repository root.`);
        }

        // Validate symlink / reparse point boundary escape
        if (fs.existsSync(resolvedTarget)) {
            const realTarget = fs.realpathSync(resolvedTarget);
            const realRepoRoot = fs.realpathSync(resolvedRepoRoot);
            const realRelative = path.relative(realRepoRoot, realTarget);
            if (realRelative.startsWith('..') || path.isAbsolute(realRelative)) {
                throw new Error(`Path traversal / symlink escape blocked: target '${target}' is outside repository root.`);
            }
            try {
                const lstat = fs.lstatSync(resolvedTarget);
                if (lstat.isSymbolicLink()) {
                    const linkDest = fs.readlinkSync(resolvedTarget);
                    const absLinkDest = path.resolve(path.dirname(resolvedTarget), linkDest);
                    const linkRel = path.relative(resolvedRepoRoot, absLinkDest);
                    if (linkRel.startsWith('..') || path.isAbsolute(linkRel)) {
                        throw new Error(`Symlink boundary escape blocked: '${target}' points outside repository root.`);
                    }
                }
            } catch (err) {
                if (err.message.includes('Symlink boundary escape') || err.message.includes('outside repository root')) throw err;
            }
        }

        // Validate timeout policy (max 600s)
        const safeTimeout = Math.min(Math.max(Number(timeout) || 30, 5), 600) * 1000;

        let files = [];
        if (fs.existsSync(resolvedTarget)) {
            const stat = fs.statSync(resolvedTarget);
            if (stat.isDirectory()) {
                const entries = fs.readdirSync(resolvedTarget, { recursive: true });
                files = entries
                    .map(e => path.join(resolvedTarget, e))
                    .filter(p => fs.statSync(p).isFile());
            } else {
                files = [resolvedTarget];
            }
        }

        return tool.run({
            files,
            target: resolvedTarget,
            timeout: safeTimeout,
            outputDir: path.join(resolvedRepoRoot, 'hwsec-output', 'tools')
        });
    }
}
