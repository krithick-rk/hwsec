/**
 * Generalized Base Tool Adapter for HWSEC (Hardware and Software Domains)
 */
export class ToolAdapter {
    constructor(config = {}) {
        this.config = config;
    }

    /**
     * Unique identifier of the tool (e.g. 'verilator', 'semgrep')
     * @returns {string}
     */
    get id() {
        return this.name;
    }

    get name() {
        throw new Error("Must implement name/id getter");
    }

    /**
     * Capabilities this tool satisfies (e.g. ['rtl_lint'], ['sast_pattern_scan'])
     * @returns {string[]}
     */
    get capabilities() {
        return [];
    }

    /**
     * Supported programming / hardware languages (e.g. ['verilog'], ['python', 'c'])
     * @returns {string[]}
     */
    get supportedLanguages() {
        return [];
    }

    /**
     * Whether this adapter supports MCP transport
     * @returns {boolean}
     */
    get supportsMCP() {
        return false;
    }

    /**
     * Checks if the tool is installed and accessible.
     * @returns {Promise<{installed: boolean, version?: string, error?: string}>}
     */
    async checkInstalled() {
        throw new Error("Must implement checkInstalled()");
    }

    /**
     * Generalized execution method supporting both object params and legacy (files, outputDir) call signatures.
     * @param {Object|string[]} params
     * @param {string} [legacyOutputDir]
     * @param {Object} [legacyOptions]
     * @returns {Promise<{status: string, findings: Array<Object>, toolErrors?: Array<Object>, telemetry?: Object}>}
     */
    async run(params, legacyOutputDir, legacyOptions) {
        throw new Error("Must implement run()");
    }
}

/**
 * Adapter for tools executed as local child processes
 */
export class LocalProcessAdapter extends ToolAdapter {
    get adapterType() {
        return 'local_process';
    }
}

/**
 * Adapter for tools communicating over Model Context Protocol (MCP)
 */
export class MCPAdapter extends ToolAdapter {
    constructor(config = {}, mcpClient = null) {
        super(config);
        this.mcpClient = mcpClient;
    }

    get adapterType() {
        return 'mcp';
    }

    get supportsMCP() {
        return true;
    }
}
