/**
 * Base Tool Adapter for HWSEC
 */
export class ToolAdapter {
    constructor(config) {
        this.config = config;
    }

    /**
     * @returns {string} The name of the tool
     */
    get name() {
        throw new Error("Must implement name getter");
    }

    /**
     * Checks if the tool is installed and accessible.
     * @returns {boolean}
     */
    checkInstalled() {
        throw new Error("Must implement checkInstalled()");
    }

    /**
     * Executes the deterministic tool and returns structured findings/evidence.
     * @param {string[]} rtlFiles - List of RTL source files
     * @param {string} outputDir - Directory to store evidence artifacts
     * @returns {import('../core/schema.js').Finding[]}
     */
    async run(rtlFiles, outputDir) {
        throw new Error("Must implement run()");
    }
}
