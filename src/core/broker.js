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
     * Dispatches a capability request to the appropriate registered tool adapter.
     * @param {Object} request
     * @param {string} request.capability
     * @param {string[]} [request.languages=[]]
     * @param {string[]} [request.files=[]]
     * @param {string} [request.outputDir]
     * @param {string} [request.runId]
     * @param {number} [request.timeout]
     */
    async dispatch(request) {
        const { capability, languages = [], files = [], outputDir = 'hwsec-output/tools', runId = null, timeout = 120000 } = request;
        
        const candidateTools = this.registry.findToolsForCapability({ capability, languages });
        if (candidateTools.length === 0) {
            return {
                status: "NO_TOOL_AVAILABLE",
                findings: [],
                telemetry: { reason: `No registered tool satisfies capability '${capability}' for languages [${languages.join(', ')}]` }
            };
        }

        // Try candidate tools in registration order
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
