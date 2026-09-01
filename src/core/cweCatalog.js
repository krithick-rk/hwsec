/**
 * Hardware Security CWE Knowledge Base for Phase 3
 */
export const HARDWARE_CWE_CATALOG = [
    {
        id: "CWE-1271",
        name: "Uninitialized State on Reset",
        description: "Registers or security configurations not explicitly reset to secure default values.",
        keywords: ["reset", "rst", "init", "default", "power-on"],
        applicable_tools: ["linting", "formal"]
    },
    {
        id: "CWE-1256",
        name: "Improper Access Control for Hardware Reg/Bus",
        description: "Unprivileged bus masters or debug interfaces can access privileged memory or register spaces.",
        keywords: ["bus", "addr", "privilege", "master", "slave", "access", "csr"],
        applicable_tools: ["formal", "fuzzing"]
    },
    {
        id: "CWE-1277",
        name: "Firmware / Hardware Trust Boundary Bypass",
        description: "Signals crossing clock or trust domains without proper synchronization or authorization filtering.",
        keywords: ["clock", "clk", "domain", "cdc", "sync", "boundary"],
        applicable_tools: ["linting", "formal"]
    },
    {
        id: "CWE-1189",
        name: "Improper Isolation of Shared Resources on SoC",
        description: "Shared hardware pipelines or caches leaking data between security domains.",
        keywords: ["cache", "pipeline", "shared", "leak", "sidechannel"],
        applicable_tools: ["formal", "fuzzing"]
    },
    {
        id: "CWE-1234",
        name: "Hardware Logic Truncation / Arithmetic Mismatch",
        description: "Signal width truncation or signed/unsigned arithmetic bugs causing overflow or logic bypass.",
        keywords: ["truncation", "width", "overflow", "assign", "cast", "size"],
        applicable_tools: ["linting", "formal"]
    },
    {
        id: "CWE-1300",
        name: "Improper Protection of Physical/Debug Interface",
        description: "JTAG, scan chains, or test ports active during normal mission mode allowing asset dumping.",
        keywords: ["jtag", "debug", "scan", "test_mode", "bist"],
        applicable_tools: ["linting", "formal"]
    }
];

export function matchCwePatterns(rtlFilesText) {
    const matched = [];
    const lower = rtlFilesText.toLowerCase();
    
    for (const cwe of HARDWARE_CWE_CATALOG) {
        const hits = cwe.keywords.filter(k => lower.includes(k));
        if (hits.length > 0) {
            matched.push({ ...cwe, match_score: hits.length });
        }
    }
    // Sort by relevance score
    matched.sort((a, b) => b.match_score - a.match_score);
    return matched;
}
