import fs from 'fs';
import path from 'path';

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
     */
    constructor(rtlDir, config) {
        this.rtlDir = path.resolve(rtlDir);
        this.config = config;
    }

    /**
     * @param {import('./workspace.js').Workspace} workspace 
     */
    plan(workspace) {
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
        
        // 3. Detect available tools (mocked for Phase 1 based on config)
        const toolPaths = this.config.tool_paths || {};
        const toolsDetected = Object.keys(toolPaths);
        
        // 4. Build execution graph
        const analysisState = {
            status: "PLANNED",
            analysis_id: workspace.analysisId,
            inventory: inventory,
            tools_detected: toolsDetected,
            execution_graph: ["linting", "formal", "fuzzing"]
        };
        workspace.saveJson('analysis.json', analysisState);
        
        // 5. Produce human-readable artifacts
        const planMd = `# HWSEC Analysis Plan\n\n` +
            `**Analysis ID**: \`${workspace.analysisId}\`\n` +
            `**Status**: PLANNED\n` +
            `**Files found**: ${verilogFiles.length}\n\n` +
            `> [!WARNING]\n` +
            `> Analysis has NOT started. Review this plan and approve execution using:\n` +
            `> \`hwsec proceed ${workspace.analysisId}\`\n`;
            
        workspace.saveMarkdown('plan.md', planMd);
        workspace.saveMarkdown('status.md', '# Status\n\nPlanning completed. Awaiting execution approval.\n');
        
        return analysisState;
    }
}
