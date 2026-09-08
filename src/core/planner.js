import fs from 'fs';
import path from 'path';
import { RepositoryDiscovery } from './discovery.js';
import { AnalysisStatus } from './state.js';
import { AnalysisBroker } from './broker.js';
import { CoverageMatrix } from './coverageMatrix.js';

export class Planner {
    /**
     * @param {string} targetDir 
     * @param {Object} config 
     * @param {string|null} specPath
     * @param {string} [noveltyMode='standard']
     */
    constructor(targetDir, config = {}, specPath = null, noveltyMode = 'standard') {
        this.targetDir = path.resolve(targetDir);
        this.config = config || {};
        this.specPath = specPath ? path.resolve(specPath) : null;
        this.noveltyMode = ['off', 'minimal', 'standard', 'deep'].includes(noveltyMode) ? noveltyMode : 'standard';
    }

    /**
     * Probes tool availability safely via AnalysisBroker without running any expensive work.
     */
    async probeTools() {
        const broker = new AnalysisBroker(this.config);
        return broker.probeTools();
    }

    /**
     * Estimates budget, tokens, and execution runtime based on discovery and novelty mode.
     */
    estimateBudget(summary) {
        const totalFiles = summary.total_files || 1;
        const totalLoc = summary.total_loc || 50;

        let multiplier = 1.0;
        if (this.noveltyMode === 'off') multiplier = 0.3;
        else if (this.noveltyMode === 'minimal') multiplier = 0.6;
        else if (this.noveltyMode === 'standard') multiplier = 1.0;
        else if (this.noveltyMode === 'deep') multiplier = 2.5;

        const baseTokens = Math.min(Math.max(totalLoc * 15, 2000), 80000);
        const estimatedTokens = Math.round(baseTokens * multiplier);
        const estimatedCostUsd = Number(((estimatedTokens / 1000) * 0.0004).toFixed(4));
        const maxBudgetUsd = this.config.token_budgets?.max_cost_usd || 10.0;
        const estimatedDurationSeconds = Math.max(10, Math.min(Math.round(totalFiles * 3 * multiplier), 300));

        return {
            novelty_mode: this.noveltyMode,
            estimated_tokens: estimatedTokens,
            estimated_cost_usd: estimatedCostUsd,
            max_budget_usd: maxBudgetUsd,
            estimated_duration_seconds: estimatedDurationSeconds
        };
    }

    /**
     * Constructs the lightweight execution plan without performing expensive operations.
     * @param {import('./workspace.js').Workspace} workspace 
     */
    async plan(workspace) {
        if (!fs.existsSync(this.targetDir)) {
            throw new Error(`Target repository directory not found: ${this.targetDir}`);
        }

        // 1. Recursive discovery
        const discovery = new RepositoryDiscovery(this.config);
        const { inventory, summary } = discovery.discover(this.targetDir);

        workspace.saveJson('inventory/inventory.json', inventory);
        workspace.saveJson('inventory/summary.json', summary);

        // 2. Probe tools via Broker
        const { available, unavailable } = await this.probeTools();

        // 3. Build task graph
        const executionGraph = ['discovery'];
        const plannedCapabilities = [];

        const hasRtl = (inventory.languages.verilog || []).length > 0;
        const hasSoftware = Object.entries(inventory.languages).some(([lang, files]) => lang !== 'verilog' && files.length > 0);

        if (hasRtl) {
            const availNames = available.map(a => a.name);
            if (availNames.includes('verilator')) {
                executionGraph.push('rtl_lint');
                plannedCapabilities.push('rtl_lint');
            }
            if (availNames.includes('yosys')) {
                executionGraph.push('rtl_formal');
                plannedCapabilities.push('rtl_formal');
            }
            if (availNames.includes('symbiyosys')) {
                executionGraph.push('formal_invariant_verification');
                plannedCapabilities.push('formal_invariant_verification');
            }
            if (availNames.includes('afl++')) {
                executionGraph.push('rtl_fuzz');
                plannedCapabilities.push('rtl_fuzz');
            }
            if (availNames.includes('spike')) {
                executionGraph.push('reference_model');
                plannedCapabilities.push('reference_model');
            }
        }

        if (hasSoftware) {
            executionGraph.push('sast_pattern_scan');
            plannedCapabilities.push('sast_pattern_scan');
            const availNames = available.map(a => a.name);
            if (availNames.includes('codeql')) {
                executionGraph.push('deep_dataflow');
                plannedCapabilities.push('deep_dataflow');
            }
            if (availNames.includes('joern')) {
                executionGraph.push('graph_dataflow');
                plannedCapabilities.push('graph_dataflow');
            }
        }

        // Post-deterministic phases planned for execution after approval
        executionGraph.push('suspicion_scoring');
        if (this.noveltyMode !== 'off') {
            executionGraph.push('hypothesis_formulation');
        }
        executionGraph.push('artifact_verification');
        executionGraph.push('correlation');
        executionGraph.push('report_generation');

        // 4. Coverage Matrix Gap Analysis
        const coverageMatrix = new CoverageMatrix();
        const activeLanguages = Object.entries(inventory.languages)
            .filter(([_, files]) => files.length > 0)
            .map(([lang]) => lang);
        const coverageGaps = coverageMatrix.identifyGaps(activeLanguages);

        workspace.saveJson('inventory/coverage_matrix.json', coverageMatrix.exportState());
        workspace.saveJson('inventory/coverage_gaps.json', coverageGaps);

        // 5. Budget calculation
        const budgetEstimate = this.estimateBudget(summary);

        // 6. Build authoritative analysis state (PLANNED)
        const analysisState = {
            schema_version: '2.0.0',
            analysis_id: workspace.analysisId,
            status: AnalysisStatus.PLANNED,
            approval_required: true,
            execution_started: false,
            created_at: new Date().toISOString(),
            target_dir: this.targetDir,
            novelty_mode: this.noveltyMode,
            spec_path: this.specPath,
            inventory: {
                total_files: inventory.total_files,
                total_loc: inventory.total_loc,
                languages: Object.fromEntries(
                    Object.entries(inventory.languages).map(([l, files]) => [l, files.map(f => path.relative(this.targetDir, f))])
                ),
                manifests: summary.manifests
            },
            summary: summary,
            tools_detected: available.map(a => a.name),
            tools_unavailable: unavailable.map(u => ({ name: u.name, reason: u.reason })),
            planned_capabilities: plannedCapabilities,
            execution_graph: executionGraph,
            coverage_matrix: {
                gaps_count: coverageGaps.length,
                high_priority_gaps: coverageGaps.filter(g => g.priority === 'HIGH').map(g => `${g.language}: ${g.title}`)
            },
            budget_estimate: budgetEstimate
        };

        workspace.saveJson('analysis.json', analysisState);

        // 6. Generate plan.md according to Part W specification
        const availableToolsMd = available.length > 0 
            ? available.map(a => `- **${a.name}** (\`${(a.capabilities || []).join(', ')}\`): ${a.version}`).join('\n')
            : '- None detected';
        
        const unavailableToolsMd = unavailable.length > 0
            ? unavailable.map(u => `- **${u.name}** (\`${(u.capabilities || []).join(', ')}\`): ${u.reason}`).join('\n')
            : '- None';

        const languagesMd = Object.entries(summary.languages).length > 0
            ? Object.entries(summary.languages).map(([lang, info]) => `- **${lang}**: ${info.file_count} file(s), ~${info.loc_estimate} LOC`).join('\n')
            : '- No supported language files identified';

        const manifestsMd = summary.manifests.length > 0
            ? summary.manifests.map(m => `- **${m.name}** (${m.type})`).join('\n')
            : '- None detected';

        const planMd = `# HWSEC Analysis Plan

**Analysis ID**: \`${workspace.analysisId}\`  
**Target Repository**: \`${this.targetDir}\`  
**Novelty Mode**: \`${this.noveltyMode.toUpperCase()}\`  
**Status**: \`PLANNED\` (Approval Required)  
**Creation Date**: ${analysisState.created_at}  

---

> [!IMPORTANT]
> **ANALYSIS HAS NOT STARTED**  
> **WAITING FOR APPROVAL**  
> 
> Review this plan carefully. To execute this approved plan, run:  
> \`hwsec proceed ${workspace.analysisId}\`

---

## 1. Repository Inventory & Scope
- **Total Files**: ${summary.total_files}
- **Estimated Source LOC**: ${summary.total_loc}
- **Build / Manifest Systems**:
${manifestsMd}

### Detected Languages
${languagesMd}

---

## 2. Tool Capability & Environment Probe
### Available Tools
${availableToolsMd}

### Unavailable / Skipped Tools
${unavailableToolsMd}

---

## 3. Planned Execution Pipeline
\`\`\`text
${executionGraph.join(' -> ')}
\`\`\`

- **Planned Capabilities**: ${plannedCapabilities.join(', ') || 'General Inspection'}
- **Novelty Mode**: ${this.noveltyMode} (controls hypothesis depth and invariant exploration)
${this.specPath ? `- **Specification Path**: \`${this.specPath}\` (will be ingested during approved execution)` : ''}

---

## 4. Resource & Budget Estimate
- **Estimated Tokens**: ~${budgetEstimate.estimated_tokens.toLocaleString()}
- **Estimated Cost**: ~$${budgetEstimate.estimated_cost_usd} USD
- **Configured Global Cost Cap**: $${budgetEstimate.max_budget_usd} USD
- **Estimated Runtime**: ~${budgetEstimate.estimated_duration_seconds} seconds

---

## 5. Risk Assessment & Dependencies
- Hardware/WSL tools require functional environment if Verilog files are present.
- Unsupported files (${summary.unsupported_count}) will be safely skipped without interrupting pipeline.
- All hypothesis generation and invariant synthesis remain completely gated until explicit human approval.

---

## 6. Vulnerability Coverage Matrix & Targeted Gaps
${coverageMatrix.toMarkdown(activeLanguages)}

**Top Identified Gaps**:
${coverageGaps.slice(0, 8).map(g => `- **[${g.priority}] ${g.title} (${g.language})**: Recommended tools: \`${g.recommendedTools.join(', ') || 'deep_reasoning'}\``).join('\n') || '- No critical gaps identified'}
`;

        workspace.saveMarkdown('plan.md', planMd);

        // 7. Initial status.md
        const statusMd = `# HWSEC Analysis Status

**Analysis ID**: \`${workspace.analysisId}\`  
**Current Phase**: \`PLANNED\`  
**Approval State**: \`WAITING_FOR_APPROVAL\`  
**Execution Started**: \`false\`  
**Last Updated**: ${new Date().toISOString()}  

> [!NOTE]  
> Analysis has been planned and gated. Awaiting human approval via \`hwsec proceed ${workspace.analysisId}\`.
`;
        workspace.saveMarkdown('status.md', statusMd);

        return analysisState;
    }
}
