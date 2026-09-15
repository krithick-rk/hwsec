import {
    PathTraversalOracle,
    SQLiOracle,
    CommandInjectionOracle,
    XSSOracle,
    LDAPInjectionOracle,
    XPathInjectionOracle
} from './cweOracles.js';

/**
 * SecurityConditionRegistry
 * 
 * Section 12: Registry of typed CWE-specific conditions and observable oracles.
 */
export class SecurityConditionRegistry {
    constructor() {
        this.oracles = new Map();
        this._registerDefaults();
    }

    _registerDefaults() {
        this.register('CWE-22', new PathTraversalOracle());
        this.register('CWE-89', new SQLiOracle());
        this.register('CWE-78', new CommandInjectionOracle());
        this.register('CWE-79', new XSSOracle());
        this.register('CWE-90', new LDAPInjectionOracle());
        this.register('CWE-643', new XPathInjectionOracle());
    }

    register(cwe, oracle) {
        const key = String(cwe).toUpperCase().trim();
        this.oracles.set(key, oracle);
    }

    getOracle(cwe) {
        if (!cwe) return null;
        const key = String(cwe).toUpperCase().trim();
        if (this.oracles.has(key)) return this.oracles.get(key);
        const match = key.match(/\bCWE-\d+\b/);
        if (match && this.oracles.has(match[0])) {
            return this.oracles.get(match[0]);
        }
        return null;
    }

    listSupportedCWEs() {
        return Array.from(this.oracles.keys());
    }
}

export const defaultSecurityRegistry = new SecurityConditionRegistry();
