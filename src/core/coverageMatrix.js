/**
 * HWSEC Vulnerability Coverage Matrix
 * Multi-dimensional tracking across CWE families, languages, and analysis methods.
 * Drives proactive targeting of unanalyzed or weakly-covered code regions.
 */

export const CWE_FAMILIES = {
    MemorySafety: {
        id: "MemorySafety",
        title: "Memory Safety & Corruption",
        cwes: ["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-124", "CWE-125", "CWE-126", "CWE-127", "CWE-131", "CWE-134", "CWE-416", "CWE-476", "CWE-787"],
        primaryLanguages: ["c", "cpp"],
        criticalTools: ["semgrep", "joern", "codeql"]
    },
    CommandInjection: {
        id: "CommandInjection",
        title: "Command & Code Injection",
        cwes: ["CWE-77", "CWE-78", "CWE-88", "CWE-94", "CWE-1336"],
        primaryLanguages: ["python", "java", "go", "c", "cpp"],
        criticalTools: ["semgrep", "joern", "codeql"]
    },
    SQLInjection: {
        id: "SQLInjection",
        title: "SQL & Query Injection",
        cwes: ["CWE-89"],
        primaryLanguages: ["python", "java", "go"],
        criticalTools: ["semgrep", "joern", "codeql"]
    },
    LDAPInjection: {
        id: "LDAPInjection",
        title: "LDAP Injection",
        cwes: ["CWE-90"],
        primaryLanguages: ["java", "python"],
        criticalTools: ["semgrep", "codeql"]
    },
    PathTraversal: {
        id: "PathTraversal",
        title: "Path Traversal & File Inclusion",
        cwes: ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-98"],
        primaryLanguages: ["c", "cpp", "java", "python", "go"],
        criticalTools: ["semgrep", "joern", "codeql"]
    },
    CrossSiteScripting: {
        id: "CrossSiteScripting",
        title: "Cross-Site Scripting (XSS)",
        cwes: ["CWE-79", "CWE-80", "CWE-83"],
        primaryLanguages: ["python", "java", "go"],
        criticalTools: ["semgrep", "codeql"]
    },
    XMLInjectionXXE: {
        id: "XMLInjectionXXE",
        title: "XML External Entity (XXE)",
        cwes: ["CWE-611", "CWE-827"],
        primaryLanguages: ["java", "python"],
        criticalTools: ["semgrep", "codeql"]
    },
    Deserialization: {
        id: "Deserialization",
        title: "Insecure Deserialization",
        cwes: ["CWE-502"],
        primaryLanguages: ["java", "python"],
        criticalTools: ["semgrep", "joern", "codeql"]
    },
    ServerSideRequestForgery: {
        id: "ServerSideRequestForgery",
        title: "Server-Side Request Forgery (SSRF)",
        cwes: ["CWE-918"],
        primaryLanguages: ["python", "java", "go"],
        criticalTools: ["semgrep", "codeql"]
    },
    BrokenAuthAndAccess: {
        id: "BrokenAuthAndAccess",
        title: "Broken Authentication & Access Control",
        cwes: ["CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-384", "CWE-639", "CWE-862", "CWE-863"],
        primaryLanguages: ["java", "python", "go"],
        criticalTools: ["semgrep", "deep_reasoning"]
    },
    CryptographicFailures: {
        id: "CryptographicFailures",
        title: "Cryptographic & Randomness Failures",
        cwes: ["CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338"],
        primaryLanguages: ["c", "cpp", "java", "python", "go"],
        criticalTools: ["semgrep", "deep_reasoning"]
    },
    HardcodedCredentials: {
        id: "HardcodedCredentials",
        title: "Hardcoded Credentials & Secrets",
        cwes: ["CWE-798", "CWE-259"],
        primaryLanguages: ["c", "cpp", "java", "python", "go", "verilog"],
        criticalTools: ["semgrep", "deep_reasoning"]
    },
    SecurityMisconfiguration: {
        id: "SecurityMisconfiguration",
        title: "Security Misconfiguration",
        cwes: ["CWE-16", "CWE-614", "CWE-1188"],
        primaryLanguages: ["python", "java", "go"],
        criticalTools: ["semgrep", "deep_reasoning"]
    },
    HardwareRTL: {
        id: "HardwareRTL",
        title: "Hardware RTL Vulnerabilities",
        cwes: ["CWE-1234", "CWE-1256", "CWE-1271", "CWE-1277", "CWE-1189", "CWE-1300"],
        primaryLanguages: ["verilog"],
        criticalTools: ["verilator", "yosys", "symbiyosys", "fuzz_formal"]
    }
};

export class CoverageMatrix {
    constructor() {
        this.matrix = {};
        this.analyzedFiles = new Set();
        this.findingsCountByFamily = {};
        this._initMatrix();
    }

    _initMatrix() {
        for (const [famKey, fam] of Object.entries(CWE_FAMILIES)) {
            this.matrix[famKey] = {};
            this.findingsCountByFamily[famKey] = 0;
            for (const lang of ["c", "cpp", "java", "python", "go", "verilog"]) {
                this.matrix[famKey][lang] = {
                    applicable: fam.primaryLanguages.includes(lang),
                    semgrep: false,
                    joern: false,
                    codeql: false,
                    graph: false,
                    fuzz_formal: false,
                    deep_reasoning: false,
                    findingsCount: 0,
                    status: fam.primaryLanguages.includes(lang) ? "UNCOVERED" : "NOT_APPLICABLE"
                };
            }
        }
    }

    /**
     * Resolves CWE ID to CWE Family Key.
     */
    static resolveFamily(cweId) {
        if (!cweId) return null;
        const norm = cweId.toUpperCase();
        for (const [key, fam] of Object.entries(CWE_FAMILIES)) {
            if (fam.cwes.includes(norm)) return key;
        }
        return null;
    }

    /**
     * Records an analysis observation across the matrix.
     */
    recordAnalysis({ family, cwe, language, tool, filePath, findingsCount = 0 }) {
        const famKey = family || CoverageMatrix.resolveFamily(cwe);
        const lang = (language || "").toLowerCase();

        if (filePath) {
            this.analyzedFiles.add(filePath);
        }

        if (!famKey || !this.matrix[famKey] || !this.matrix[famKey][lang]) {
            return;
        }

        const cell = this.matrix[famKey][lang];
        if (tool) {
            const toolKey = tool.toLowerCase().replace(/[+-]/g, '_');
            if (cell[toolKey] !== undefined) {
                cell[toolKey] = true;
            } else if (toolKey.includes('sby') || toolKey.includes('formal') || toolKey.includes('afl')) {
                cell.fuzz_formal = true;
            } else if (toolKey.includes('joern')) {
                cell.joern = true;
            } else if (toolKey.includes('codeql')) {
                cell.codeql = true;
            } else {
                cell.deep_reasoning = true;
            }
        }

        cell.findingsCount += findingsCount;
        this.findingsCountByFamily[famKey] += findingsCount;

        // Update cell status
        const toolsUsedCount = ['semgrep', 'joern', 'codeql', 'graph', 'fuzz_formal', 'deep_reasoning']
            .filter(t => cell[t]).length;

        if (toolsUsedCount >= 2 || (toolsUsedCount >= 1 && cell.findingsCount > 0)) {
            cell.status = "COVERED";
        } else if (toolsUsedCount === 1) {
            cell.status = "PARTIALLY_COVERED";
        }
    }

    /**
     * Identifies coverage gaps for target languages in the repository.
     */
    identifyGaps(targetLanguages = []) {
        const activeLangs = (targetLanguages.length > 0 ? targetLanguages : ["c", "cpp", "java", "python", "go", "verilog"]).map(l => l.toLowerCase());
        const gaps = [];

        for (const [famKey, fam] of Object.entries(CWE_FAMILIES)) {
            for (const lang of activeLangs) {
                if (!fam.primaryLanguages.includes(lang)) continue;

                const cell = this.matrix[famKey][lang];
                if (cell.status === "UNCOVERED" || cell.status === "PARTIALLY_COVERED") {
                    gaps.push({
                        family: famKey,
                        title: fam.title,
                        language: lang,
                        cwes: fam.cwes,
                        status: cell.status,
                        recommendedTools: fam.criticalTools.filter(t => !cell[t]),
                        priority: cell.status === "UNCOVERED" ? "HIGH" : "MEDIUM"
                    });
                }
            }
        }

        // Sort: UNCOVERED first, then by number of CWEs
        gaps.sort((a, b) => (a.status === "UNCOVERED" ? -1 : 1));
        return gaps;
    }

    /**
     * Generates a markdown summary table of current coverage.
     */
    toMarkdown(targetLanguages = []) {
        const langs = (targetLanguages.length > 0 ? targetLanguages : ["c", "cpp", "java", "python", "go", "verilog"]).map(l => l.toLowerCase());
        let md = "# Vulnerability Coverage Matrix\n\n";
        md += "| CWE Family | Language | Semgrep | Joern | CodeQL | Graph | Fuzz/Formal | Status | Findings |\n";
        md += "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |\n";

        for (const [famKey, fam] of Object.entries(CWE_FAMILIES)) {
            for (const lang of langs) {
                if (!fam.primaryLanguages.includes(lang)) continue;
                const c = this.matrix[famKey][lang];
                md += `| **${fam.title}** | \`${lang}\` | ${c.semgrep ? "YES" : "-"} | ${c.joern ? "YES" : "-"} | ${c.codeql ? "YES" : "-"} | ${c.graph ? "YES" : "-"} | ${c.fuzz_formal ? "YES" : "-"} | **${c.status}** | ${c.findingsCount} |\n`;
            }
        }
        return md;
    }

    /**
     * Serializes coverage matrix state for saving to disk / workspace.
     */
    exportState() {
        return {
            matrix: this.matrix,
            analyzedFiles: Array.from(this.analyzedFiles),
            findingsCountByFamily: this.findingsCountByFamily
        };
    }

    /**
     * Restores coverage matrix state.
     */
    importState(state) {
        if (!state) return;
        if (state.matrix) this.matrix = state.matrix;
        if (state.analyzedFiles) this.analyzedFiles = new Set(state.analyzedFiles);
        if (state.findingsCountByFamily) this.findingsCountByFamily = state.findingsCountByFamily;
    }
}
