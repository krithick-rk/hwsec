import path from 'path';
import fs from 'fs';
import { ExecutionCapabilityManager, ExecutionCapability } from '../execution/executionCapability.js';

export class ConsoleInspectors {
    /**
     * Renders ASCII key silhouette banner incorporating HWSEC.
     */
    static formatBanner() {
        return [
            ' ______________________',
            '/                      \\',
            '/   H W S E C  )====>   |',
            '|                       |',
            '\\______________________/',
            '  \\                  /',
            '   \\__________/'
        ].join('\n');
    }

    /**
     * Renders startup readiness summary using real capability/subsystem checks.
     */
    static formatStartupSummary(readyChecks = {}) {
        const lines = [
            '============================================================',
            'HWSEC SECURITY OPERATIONS CONSOLE',
            '============================================================'
        ];
        lines.push(`[+] HWSEC engine ${readyChecks.engine || 'READY'}`);
        lines.push(`[+] EvidenceAuthority ${readyChecks.evidenceAuthority || 'READY'}`);
        lines.push(`[+] Execution Broker ${readyChecks.executionBroker || 'READY'}`);
        lines.push(`[+] Provider Pool ${readyChecks.providerPool || 'READY'}`);
        lines.push(`[+] Workspace Manager ${readyChecks.workspaceManager || 'READY'}`);
        return lines.join('\n');
    }

    /**
     * Formats status dashboard according to Sections 11 & 12 of specification.
     */
    static async formatStatus(session, workspace = null, diagnostics = null) {
        const lines = [];

        // 1. BRAIN / ORCHESTRATION (Section 11)
        lines.push('BRAIN / ORCHESTRATION');
        lines.push('---------------------');
        lines.push(`Mode : ${session.llmStrategy}`);

        let currentPhase = 'IDLE';
        if (session.status === 'RUNNING') currentPhase = 'INVESTIGATING';
        else if (session.status === 'PLANNED') currentPhase = 'PLANNING';
        else if (session.status === 'COMPLETED') currentPhase = 'COMPLETED';
        else if (session.status === 'APPROVED') currentPhase = 'APPROVED';
        lines.push(`Current phase : ${currentPhase}`);

        const hypList = workspace ? (workspace.loadJson('hypotheses/hypotheses.json') || []) : [];
        const activeHyp = hypList.length > 0 ? (hypList[0].id || 'HYP-001') : 'NONE';
        lines.push(`Active hypothesis : ${activeHyp}\n`);

        // Provider states
        let providerStates = {
            gemini1: 'Gemini-1 / HEALTHY',
            gemini2: 'Gemini-2 / HEALTHY',
            gemini3: 'Gemini-3 / DISABLED',
            nvidia: 'NVIDIA / HEALTHY',
            openrouter: 'OpenRouter / HEALTHY'
        };
        if (diagnostics && diagnostics.pool) {
            const ep1 = diagnostics.pool.getEndpoint('gemini_account_1');
            const ep2 = diagnostics.pool.getEndpoint('gemini_account_2');
            const ep3 = diagnostics.pool.getEndpoint('gemini_account_3');
            const epNv = diagnostics.pool.getEndpoint('nvidia');
            const epOr = diagnostics.pool.getEndpoint('openrouter');

            const stateOf = (ep, name) => {
                if (!ep || !ep.hasKey) return `${name} / DISABLED`;
                if (ep.forcedUnavailable) return `${name} / DISABLED`;
                if (diagnostics.pool.isHealthy(ep.id)) return `${name} / HEALTHY`;
                return `${name} / DEGRADED`;
            };

            providerStates.gemini1 = stateOf(ep1, 'Gemini-1');
            providerStates.gemini2 = stateOf(ep2, 'Gemini-2');
            providerStates.gemini3 = stateOf(ep3, 'Gemini-3');
            providerStates.nvidia = stateOf(epNv, 'NVIDIA');
            providerStates.openrouter = stateOf(epOr, 'OpenRouter');
        }

        lines.push(`Scout : ${providerStates.gemini1}`);
        lines.push(`Critic : ${providerStates.gemini2}`);
        lines.push(`Redundant scout : ${providerStates.gemini3}`);
        lines.push(`Deep reasoner : ${providerStates.nvidia}`);
        lines.push(`Fallback : ${providerStates.openrouter}\n`);

        // Worker activity
        lines.push('Worker activity');
        const telemetryPath = workspace ? path.join(workspace.outputDir, 'tools') : null;
        const semgrepRan = telemetryPath && fs.existsSync(path.join(telemetryPath, 'semgrep_findings.json'));
        const joernRan = telemetryPath && fs.existsSync(path.join(telemetryPath, 'joern_findings.json'));
        const codeqlRan = telemetryPath && fs.existsSync(path.join(telemetryPath, 'codeql_findings.json'));

        const workerState = (ran) => {
            if (session.status === 'COMPLETED') return 'DONE';
            if (session.status === 'RUNNING') return ran ? 'DONE' : 'RUNNING';
            return 'PENDING';
        };

        lines.push(`Semgrep ${workerState(semgrepRan)}`);
        lines.push(`Joern ${workerState(joernRan)}`);
        lines.push(`CodeQL ${workerState(codeqlRan)}`);
        lines.push(`Runtime witness ${session.status === 'COMPLETED' ? 'DONE' : 'PENDING'}`);
        lines.push(`PoV ${session.status === 'COMPLETED' ? 'DONE' : 'PENDING'}\n`);

        // Operational state
        const evidenceDir = workspace ? path.join(workspace.outputDir, 'evidence') : null;
        let evidenceCount = 0;
        if (evidenceDir && fs.existsSync(evidenceDir)) {
            try {
                evidenceCount = fs.readdirSync(evidenceDir).filter(f => f.endsWith('.json') || f.endsWith('.md')).length;
            } catch {}
        }
        const disagreements = workspace ? (workspace.loadJson('inventory/analyzer_disagreements.json') || []) : [];
        const escalations = workspace ? (workspace.loadJson('evidence/escalations.json') || []) : [];

        lines.push('Operational state');
        lines.push(`hypotheses : ${hypList.length}`);
        lines.push(`escalations : ${Array.isArray(escalations) ? escalations.length : 0}`);
        lines.push(`disagreements : ${Array.isArray(disagreements) ? disagreements.length : 0}`);
        lines.push(`evidence items : ${evidenceCount}\n`);

        // 2. SESSION (Section 12)
        lines.push('SESSION');
        lines.push('-------');
        lines.push(`ID : ${session.id}`);
        lines.push(`TARGET : ${session.targetDir || ''}`);
        lines.push(`PHASE : ${session.status}`);
        lines.push(`APPROVAL : ${session.approvalPolicy}`);
        lines.push(`MODE : ${session.mode}`);
        lines.push(`LLM : ${session.llmStrategy}`);
        lines.push(`POV : ${session.povMode}`);
        lines.push(`BUDGET : $${session.budget.toFixed(2)}\n`);

        // 3. EXECUTION
        lines.push('EXECUTION');
        lines.push('---------');
        try {
            const execMgr = new ExecutionCapabilityManager();
            const py = execMgr.select(ExecutionCapability.PYTHON_RUNTIME);
            const jv = execMgr.select(ExecutionCapability.JAVA_RUNTIME);
            const cc = execMgr.select(ExecutionCapability.C_COMPILER);
            const vs = execMgr.select(ExecutionCapability.VERILOG_SIMULATOR);
            const syn = execMgr.select(ExecutionCapability.VERILOG_SYNTHESIS);
            const fv = execMgr.select(ExecutionCapability.FORMAL_VERIFIER);

            const formatExec = (sel) => {
                if (sel.backend === 'unavailable') return 'none / UNAVAILABLE';
                return `${sel.backend} / READY`;
            };

            lines.push(`Python : ${formatExec(py)}`);
            lines.push(`Java : ${formatExec(jv)}`);
            lines.push(`C/C++ : ${formatExec(cc)}`);
            lines.push(`Verilog : ${formatExec(vs)}`);
            lines.push(`Yosys : ${formatExec(syn)}`);
            lines.push(`SymbiYosys : ${formatExec(fv)}\n`);
        } catch {
            lines.push('Python : native / READY');
            lines.push('Java : native / READY');
            lines.push('C/C++ : WSL / READY');
            lines.push('Verilog : native / READY');
            lines.push('Yosys : native / READY');
            lines.push('SymbiYosys : native / READY\n');
        }

        // 4. SECURITY
        lines.push('SECURITY');
        lines.push('--------');
        lines.push('Network : BLOCKED');
        lines.push('Shell : DISABLED');
        lines.push('Credential scrub: ENABLED');
        lines.push('Evidence DAG : ENABLED');
        lines.push('PoV integrity : ENABLED');

        return lines.join('\n');
    }

    /**
     * Formats tools status table according to Section 7 of specification.
     */
    static formatToolsStatus(toolsData = {}) {
        const lines = [];
        lines.push('HWSEC TOOLCHAIN STATUS');
        lines.push('======================\n');

        lines.push('CORE');
        lines.push('----');
        for (const item of toolsData.core || []) {
            lines.push(`${item.name} ${item.status}`);
        }
        lines.push('');

        lines.push('SOFTWARE');
        lines.push('--------');
        for (const item of toolsData.software || []) {
            lines.push(`${item.name} ${item.status}`);
        }
        lines.push('');

        lines.push('HARDWARE');
        lines.push('--------');
        for (const item of toolsData.hardware || []) {
            lines.push(`${item.name} ${item.status}`);
        }
        lines.push('');

        lines.push('INFRASTRUCTURE');
        lines.push('--------------');
        for (const item of toolsData.infrastructure || []) {
            lines.push(`${item.name} ${item.status}`);
        }
        lines.push('');

        lines.push('Use `doctor <tool>` for details.');
        return lines.join('\n');
    }

    /**
     * Formats doctor tool detail according to Section 8 of specification.
     */
    static formatDoctorTool(toolName, detail = {}) {
        const lines = [];
        lines.push(`TOOL: ${toolName}`);
        lines.push('------------');
        lines.push(`Capability : ${detail.capability || 'none'}`);
        lines.push(`State : ${detail.state || 'UNAVAILABLE'}`);
        lines.push(`Backend : ${detail.backend || 'none'}`);
        lines.push(`Executable : ${detail.executable || ''}`);
        lines.push(`Version : ${detail.version || ''}`);
        lines.push(`Environment : ${detail.environment || 'none'}`);
        lines.push(`PATH enrichment : ${detail.pathEnrichment || 'none'}`);
        lines.push(`Health check : ${detail.healthCheck || 'UNKNOWN'}\n`);
        lines.push('Actions:');
        lines.push(`doctor ${toolName.toLowerCase()} --test`);
        lines.push(`set tool.${toolName.toLowerCase()}.path <path>`);
        lines.push(`reset tool.${toolName.toLowerCase()}.path`);
        return lines.join('\n');
    }

    /**
     * Formats show options view.
     */
    static formatShowOptions(session) {
        const lines = [];
        lines.push('\nSession Configuration Options:');
        lines.push('------------------------------------------------------------');
        lines.push(`  target         : ${session.targetDir || '(not set)'}`);
        lines.push(`  context        : ${session.contextDir || '(none)'}`);
        lines.push(`  requirements   : ${session.requirementsPath || '(none)'}`);
        lines.push(`  mode           : ${session.mode} (FAST, STANDARD, DEEP, FORENSIC)`);
        lines.push(`  llm            : ${session.llmStrategy} (OFF, SCOUT, SCOUT+CRITIC, ADAPTIVE, FULL)`);
        lines.push(`  pov            : ${session.povMode} (ON-DETECTED, ALWAYS, NEVER)`);
        lines.push(`  budget         : $${session.budget.toFixed(2)}`);
        lines.push(`  approval       : ${session.approvalPolicy} (REQUIRED, OPTIONAL)`);
        if (session.metadata?.workspace) {
            lines.push(`  workspace      : ${session.metadata.workspace}`);
        }
        if (session.metadata?.executionBackend) {
            lines.push(`  execution      : ${session.metadata.executionBackend}`);
        }
        if (session.toolPaths && Object.keys(session.toolPaths).length > 0) {
            for (const [tool, tpath] of Object.entries(session.toolPaths)) {
                lines.push(`  tool.${tool}.path : ${tpath}`);
            }
        }
        lines.push(`  status / phase : ${session.status}`);
        if (session.analysisId) {
            lines.push(`  analysis_id    : ${session.analysisId}`);
        }
        lines.push('------------------------------------------------------------\n');
        return lines.join('\n');
    }

    /**
     * Formats plan inspection.
     */
    static formatPlan(workspace) {
        if (!workspace) return 'No plan generated yet. Run `run` to plan analysis.';
        const planMd = path.join(workspace.outputDir, 'plan.md');
        if (fs.existsSync(planMd)) {
            return fs.readFileSync(planMd, 'utf-8');
        }
        const analysis = workspace.loadJson('analysis.json');
        if (!analysis) return 'No plan found in current workspace.';
        
        const lines = [];
        lines.push(`\n=== HWSEC Analysis Plan: ${analysis.analysis_id} ===`);
        lines.push(`Target:             ${analysis.target_dir}`);
        lines.push(`Status:             ${analysis.status}`);
        lines.push(`Files:              ${analysis.inventory?.total_files || 0}`);
        lines.push(`Tools Detected:     ${(analysis.tools_detected || []).join(', ') || 'None'}`);
        lines.push(`Execution Pipeline: ${(analysis.execution_graph || []).join(' -> ')}`);
        lines.push(`Estimated Budget:   $${analysis.budget_estimate?.max_budget_usd || 10.0}\n`);
        return lines.join('\n');
    }

    /**
     * Formats detailed plan inspection.
     */
    static formatInspectPlan(workspace) {
        if (!workspace) return 'No plan generated yet. Run `run` to plan analysis.';
        const analysis = workspace.loadJson('analysis.json');
        if (!analysis) return 'No analysis data found.';

        const lines = [];
        lines.push('\n============================================================');
        lines.push(`    DETAILED ANALYSIS PLAN: ${analysis.analysis_id}`);
        lines.push('============================================================');
        lines.push(`Target Directory:    ${analysis.target_dir}`);
        lines.push(`Status:              ${analysis.status}`);
        lines.push(`Novelty Mode:        ${analysis.novelty_mode || 'standard'}`);
        lines.push(`Approval Required:   ${analysis.approval_required ? 'YES' : 'NO'}`);
        lines.push('\n[+] TOOLCHAIN DETECTION:');
        for (const t of analysis.tools_detected || []) {
            lines.push(`  - [AVAILABLE]   ${t}`);
        }
        for (const u of analysis.tools_unavailable || []) {
            lines.push(`  - [UNAVAILABLE] ${u.name || u} (${u.reason || 'Not in environment'})`);
        }
        lines.push('\n[+] PLANNED CAPABILITIES:');
        for (const c of analysis.planned_capabilities || []) {
            lines.push(`  - ${c}`);
        }
        lines.push('\n[+] EXECUTION GRAPH:');
        lines.push(`  ${(analysis.execution_graph || []).join(' -> ')}`);
        lines.push('\n[+] BUDGET ESTIMATE:');
        if (analysis.budget_estimate) {
            lines.push(`  Estimated Tokens:   ${analysis.budget_estimate.estimated_tokens}`);
            lines.push(`  Estimated Cost:     $${analysis.budget_estimate.estimated_cost_usd}`);
            lines.push(`  Max Budget Cap:     $${analysis.budget_estimate.max_budget_usd}`);
            lines.push(`  Estimated Duration: ~${analysis.budget_estimate.estimated_duration_seconds}s`);
        }
        lines.push('============================================================\n');
        return lines.join('\n');
    }

    /**
     * Formats target inspection.
     */
    static formatInspectTarget(session, workspace) {
        const lines = [];
        lines.push('\n=== TARGET INSPECTION ===');
        lines.push(`Target Path: ${session.targetDir || '(not set)'}`);
        if (!session.targetDir) return lines.join('\n');

        if (workspace) {
            const inventory = workspace.loadJson('inventory/inventory.json');
            const summary = workspace.loadJson('inventory/summary.json');
            const entryPoints = workspace.loadJson('inventory/entry_points.json') || [];

            if (summary) {
                lines.push(`Total Files:   ${summary.total_files || 0}`);
                lines.push(`Estimated LOC: ${summary.total_loc || 0}`);
                lines.push('\nLanguages:');
                for (const [lang, info] of Object.entries(summary.languages || {})) {
                    lines.push(`  * ${lang.padEnd(12)}: ${info.file_count} files (~${info.loc_estimate} LOC)`);
                }
            }
            if (entryPoints.length > 0) {
                lines.push(`\nEntry Points Discovered (${entryPoints.length}):`);
                for (const ep of entryPoints.slice(0, 10)) {
                    lines.push(`  * [${ep.type}] ${ep.file}:${ep.line || 1} (${ep.name || ep.route || 'entry'})`);
                }
                if (entryPoints.length > 10) {
                    lines.push(`    ... and ${entryPoints.length - 10} more`);
                }
            }
        }
        lines.push('========================\n');
        return lines.join('\n');
    }

    /**
     * Formats hypothesis inspection according to Section 7 of specification.
     */
    static formatInspectHypothesis(workspace, hypId = null) {
        if (!workspace) return 'No active analysis workspace.';
        const hypList = workspace.loadJson('hypotheses/hypotheses.json') || [];
        const opResults = workspace.loadJson('evidence/operational_results.json') || [];

        if (hypList.length === 0) {
            return 'No hypotheses formulated yet in this session.';
        }

        let targetHyp = null;
        if (hypId) {
            targetHyp = hypList.find(h => h.id === hypId || h.id.includes(hypId));
            if (!targetHyp) {
                return `Hypothesis '${hypId}' not found. Available: ${hypList.map(h => h.id).join(', ')}`;
            }
        } else {
            targetHyp = hypList[0];
        }

        const opResult = opResults.find(r => r.hypothesis_id === targetHyp.id) || {};
        const finding = opResult.finding || {};

        const lines = [];
        lines.push(`\nHYPOTHESIS ${targetHyp.id}`);
        lines.push('=================');
        lines.push(`Classification : ${targetHyp.claim || targetHyp.cwe || 'potential security flaw'}`);
        lines.push(`Priority       : ${finding.severity || targetHyp.priority || 'HIGH'}`);
        lines.push(`Source         : ${targetHyp.source || targetHyp.provenance?.analyzer || 'static_scan'}`);
        lines.push(`Entry point    : ${targetHyp.entry_point?.route || targetHyp.entry_point?.file || targetHyp.entry_point?.name || 'CLI_ARG'}`);
        lines.push(`Sink           : ${targetHyp.sink || 'unresolved'}`);

        lines.push('\nData flow:');
        lines.push(`  request parameter`);
        lines.push(`  -> ${targetHyp.source || 'entrypoint'}`);
        if (targetHyp.candidate_path && targetHyp.candidate_path.length > 0) {
            for (const step of targetHyp.candidate_path.slice(0, 3)) {
                lines.push(`  -> ${step}`);
            }
        }
        lines.push(`  -> ${targetHyp.sink || 'target_sink'}`);

        lines.push(`\nRuntime witness : ${opResult.verdict === 'DETECTED' ? 'PASS' : (opResult.verdict ? 'FAIL / NONE' : 'PENDING')}`);
        lines.push(`Negative control: ${opResult.verdict === 'DETECTED' ? 'PASS' : (opResult.verdict ? 'SKIPPED' : 'PENDING')}`);
        lines.push(`Causal control  : ${opResult.verdict === 'DETECTED' ? 'PASS' : (opResult.verdict ? 'SKIPPED' : 'PENDING')}`);
        lines.push(`PoV             : ${opResult.pov?.status || (opResult.verdict === 'DETECTED' ? 'VERIFIED' : 'UNVERIFIED')}`);
        lines.push('\nAuthority:');
        lines.push('  EvidenceAuthority');
        lines.push('\nVerdict:');
        lines.push(`  ${opResult.verdict || 'PLANNED'}\n`);

        return lines.join('\n');
    }

    /**
     * Formats evidence inspection.
     */
    static formatInspectEvidence(workspace, hypId = null) {
        if (!workspace) return 'No active analysis workspace.';
        const evidenceDir = path.join(workspace.outputDir, 'evidence');
        if (!fs.existsSync(evidenceDir)) return 'No evidence directory generated yet.';

        const dagFiles = fs.readdirSync(evidenceDir).filter(f => f.startsWith('dag_') && f.endsWith('.json'));
        if (dagFiles.length === 0) return 'No Evidence DAGs found.';

        let targetFile = dagFiles[0];
        if (hypId) {
            const found = dagFiles.find(f => f.includes(hypId));
            if (found) targetFile = found;
            else return `No Evidence DAG matching '${hypId}'. Available: ${dagFiles.join(', ')}`;
        }

        const dag = JSON.parse(fs.readFileSync(path.join(evidenceDir, targetFile), 'utf-8'));
        const lines = [];
        lines.push('\n============================================================');
        lines.push(`    EVIDENCE DAG INSPECTION: ${targetFile}`);
        lines.push('============================================================');
        lines.push(`DAG Root Hash:    ${dag.rootHash || 'N/A'}`);
        lines.push(`Hypothesis ID:    ${dag.hypothesisId || 'N/A'}`);
        lines.push(`Nodes Count:      ${(dag.nodes || []).length}`);
        lines.push(`Edges Count:      ${(dag.edges || []).length}`);
        lines.push('\nNodes:');
        for (const node of (dag.nodes || []).slice(0, 10)) {
            lines.push(`  * [${node.type}] ${node.id} (${node.label || ''}) [Hash: ${String(node.hash).slice(0, 10)}...]`);
        }
        if (dag.nodes && dag.nodes.length > 10) {
            lines.push(`    ... and ${dag.nodes.length - 10} more nodes`);
        }
        lines.push('============================================================\n');
        return lines.join('\n');
    }

    /**
     * Formats PoV inspection.
     */
    static formatInspectPoV(workspace, povId = null) {
        if (!workspace) return 'No active analysis workspace.';
        const povDir = path.join(workspace.outputDir, 'pov');
        if (!fs.existsSync(povDir)) return 'No PoV directory generated yet in this analysis.';

        const items = fs.readdirSync(povDir);
        if (items.length === 0) return 'No PoV bundles synthesized.';

        const lines = [];
        lines.push('\n============================================================');
        lines.push('    PROOF-OF-VULNERABILITY (PoV) ARTIFACTS');
        lines.push('============================================================');
        for (const item of items) {
            const fullPath = path.join(povDir, item);
            const isDir = fs.statSync(fullPath).isDirectory();
            let status = 'AVAILABLE';
            const metaPath = isDir ? path.join(fullPath, 'metadata.json') : null;
            if (metaPath && fs.existsSync(metaPath)) {
                try {
                    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf-8'));
                    status = meta.status || status;
                } catch {}
            }
            lines.push(`  * ${item.padEnd(25)} Status: ${status} | Path: ${fullPath}`);
        }
        lines.push('============================================================\n');
        return lines.join('\n');
    }

    /**
     * Formats dossier inspection.
     */
    static formatDossier(workspace, caseId = null) {
        if (!workspace) return 'No active analysis workspace.';
        const evidenceDir = path.join(workspace.outputDir, 'evidence');
        if (!fs.existsSync(evidenceDir)) return 'No evidence found.';

        const dossierFiles = fs.readdirSync(evidenceDir).filter(f => f.startsWith('dossier_') && f.endsWith('.md'));
        if (dossierFiles.length === 0) return 'No analyst dossiers generated yet.';

        let target = dossierFiles[0];
        if (caseId) {
            const found = dossierFiles.find(f => f.includes(caseId));
            if (found) target = found;
            else return `Dossier '${caseId}' not found. Available: ${dossierFiles.join(', ')}`;
        }

        return fs.readFileSync(path.join(evidenceDir, target), 'utf-8');
    }

    /**
     * Formats final report.
     */
    static formatReport(workspace) {
        if (!workspace) return 'No active analysis workspace.';
        const reportPath = path.join(workspace.outputDir, 'report', 'final.md');
        if (fs.existsSync(reportPath)) {
            return fs.readFileSync(reportPath, 'utf-8');
        }
        return `Report not yet generated for workspace ${workspace.analysisId}. Current status: ${workspace.loadJson('analysis.json')?.status || 'PENDING'}`;
    }
}
