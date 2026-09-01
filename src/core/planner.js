import fs from 'fs';
import path from 'path';
import { VerilatorTool } from '../tools/verilator.js';
import { YosysTool } from '../tools/yosys.js';
import { AflTool } from '../tools/afl.js';

function findVerilogFiles(dir, fileList = []) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const fullPath = path.join(dir, file);
        if (fs.statSync(fullPath).isDirectory()) {
            findVerilogFiles(fullPath, fileList);
        } else if (fullPath.endsWith('.v') || fullPath.endsWith('.sv')) {
            fileList.push(fullPath);
        }
    }
    return fileList;
}

export class Planner {
    /**
     * @param {string} rtlDir 
     * @param {Object} config 
     * @param {string} specPath
     */
    constructor(rtlDir, config, specPath = null) {
        this.rtlDir = path.resolve(rtlDir);
        this.config = config;
        this.specPath = specPath;
    }

    /**
     * @param {import('./workspace.js').Workspace} workspace 
     */
    async plan(workspace) {
        // 1. Inspect RTL directory
        if (!fs.existsSync(this.rtlDir)) {
            throw new Error(`RTL directory not found: ${this.rtlDir}`);
        }
        const verilogFiles = findVerilogFiles(this.rtlDir);
        
        // 2. Build project inventory
        const inventory = {
            files: verilogFiles,
            module_count_estimate: verilogFiles.length
        };
        workspace.saveJson('inventory/inventory.json', inventory);
        
        // 3. Dynamically probe available tools
        const toolsDetected = [];
        const executionGraph = [];

        const verilator = new VerilatorTool(this.config);
        const verilatorCheck = await verilator.checkInstalled();
        if (verilatorCheck.installed) {
            toolsDetected.push("verilator");
            executionGraph.push("linting");
        }

        const yosys = new YosysTool(this.config);
        const yosysCheck = await yosys.checkInstalled();
        if (yosysCheck.installed) {
            toolsDetected.push("yosys");
            executionGraph.push("formal");
        }

        const afl = new AflTool(this.config);
        const aflCheck = await afl.checkInstalled();
        if (aflCheck.installed) {
            toolsDetected.push("afl++");
            executionGraph.push("fuzzing");
        }
        
        const { LLMClient } = await import('./llmClient.js');
        const llmClient = new LLMClient(this.config);

        // Phase 4: Specification Ingestion + Divergence
        if (this.specPath && fs.existsSync(this.specPath) && llmClient.isAvailable()) {
            console.log(`[*] [Phase 4] Ingesting specification from ${this.specPath}...`);
            const specContent = fs.readFileSync(this.specPath, 'utf-8');
            let combinedRtl = "";
            for (const file of verilogFiles) {
                combinedRtl += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8') + '\n\n';
            }

            try {
                const { SpecIngestion } = await import('./specIngestion.js');
                const specIngestion = new SpecIngestion(llmClient);
                const specFiles = [{ path: this.specPath, content: specContent }];
                const clauses = await specIngestion.extractClauses(specFiles);
                workspace.saveJson('inventory/spec_clauses.json', clauses);
                console.log(`[+] [Phase 4] Extracted ${clauses.length} structured specification clauses.`);

                const { SpecIngestorWorker } = await import('../workers/specIngestor.js');
                const specIngestor = new SpecIngestorWorker(llmClient);
                const specRes = await specIngestor.generateMonitor(specContent, combinedRtl);
                
                const monitorPath = path.join(workspace.outputDir, 'spec_monitor.sv');
                fs.writeFileSync(monitorPath, specRes.monitor_code, 'utf-8');
                verilogFiles.push(monitorPath); // Add the newly generated assertion monitor to inventory
                
                console.log(`[+] [Phase 4] Successfully generated spec_monitor.sv from specification.`);
                workspace.saveJson('inventory/spec_ingestion.json', specRes.ingested_rules);
            } catch (err) {
                console.error(`[-] [Phase 4] Failed to ingest specification: ${err.message}`);
            }
        }

        // 4. Phase 3: Generate CWE-informed hypotheses
        const { HypothesisGenerator } = await import('../workers/hypothesisGenerator.js');
        const hypothesisGen = new HypothesisGenerator(llmClient);
        
        const hypotheses = await hypothesisGen.generateHypotheses(verilogFiles, executionGraph);
        
        // Phase 5: Implicit Invariant Synthesis for Novel Discovery
        let synthesizedInvariants = [];
        if (llmClient.isAvailable()) {
            console.log(`[*] [Phase 5] Synthesizing implicit security invariants and SVA monitors...`);
            const { InvariantSynthesizer } = await import('../workers/invariantSynthesizer.js');
            const invSynthesizer = new InvariantSynthesizer(llmClient);
            const invRes = await invSynthesizer.synthesizeInvariants(verilogFiles, path.join(workspace.outputDir, 'tools'));
            synthesizedInvariants = invRes.invariants;
            workspace.saveJson('inventory/synthesized_invariants.json', synthesizedInvariants);
            if (invRes.monitorPath) {
                console.log(`[+] [Phase 5] Successfully synthesized ${synthesizedInvariants.length} implicit invariant(s) to ${invRes.monitorPath}`);
            }
        }

        const allHypotheses = [...hypotheses, ...synthesizedInvariants.map(inv => ({
            hypothesis_id: inv.invariant_id,
            cwe_id: "NOVEL-INVARIANT",
            title: inv.title,
            claim: inv.claim,
            proposed_test: "formal",
            status: "PLANNED"
        }))];

        workspace.saveJson('hypotheses/hypotheses.json', allHypotheses);
        for (const h of allHypotheses) {
            workspace.saveJson(`hypotheses/${h.hypothesis_id}.json`, h);
        }

        // 5. Build execution graph state
        const analysisState = {
            status: "PLANNED",
            analysis_id: workspace.analysisId,
            inventory: inventory,
            tools_detected: toolsDetected,
            execution_graph: executionGraph,
            hypotheses_count: allHypotheses.length,
            invariants_count: synthesizedInvariants.length
        };
        workspace.saveJson('analysis.json', analysisState);
        
        // 6. Produce human-readable artifacts
        let hypothesesListMd = "";
        if (allHypotheses.length > 0) {
            hypothesesListMd = `\n### Planned Security Hypotheses (Phase 3 CWE + Phase 5 Novel Invariants)\n` +
                allHypotheses.map(h => `- **[${h.cwe_id}] ${h.hypothesis_id}**: ${h.title}\n  *Claim*: ${h.claim}\n  *Proposed Test*: \`${h.proposed_test}\``).join('\n') + `\n`;
        }

        const planMd = `# HWSEC Analysis Plan\n\n` +
            `**Analysis ID**: \`${workspace.analysisId}\`\n` +
            `**Status**: PLANNED\n` +
            `**Files found**: ${verilogFiles.length}\n` +
            `**Tools detected**: ${toolsDetected.join(', ') || 'None'}\n` +
            `**Execution pipeline**: ${executionGraph.join(' -> ') || 'None'}\n` +
            hypothesesListMd +
            `\n> [!WARNING]\n` +
            `> Analysis has NOT started. Review this plan and approve execution using:\n` +
            `> \`hwsec proceed ${workspace.analysisId}\`\n`;
            
        workspace.saveMarkdown('plan.md', planMd);
        workspace.saveMarkdown('status.md', '# Status\n\nPlanning completed. Awaiting execution approval.\n');
        
        return analysisState;
    }
}
