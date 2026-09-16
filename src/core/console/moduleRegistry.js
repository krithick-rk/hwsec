/**
 * Module Registry
 * 
 * Minimal discoverable capability registry for the HWSEC console.
 * Organizes capabilities into DISCOVERY, WITNESS, and POV categories.
 */

export const ModuleRegistry = {
    DISCOVERY: [
        { id: 'discovery/static', name: 'Static File & Pattern Scanner', description: 'Deterministic AST and rule-based pattern matching (Semgrep, Verilator)' },
        { id: 'discovery/dataflow', name: 'Code Property Graph & Dataflow', description: 'Interprocedural dataflow and taint tracking (Joern, CodeQL)' },
        { id: 'discovery/entrypoints', name: 'Entry Point Discovery', description: 'Automated discovery of HTTP routes, CLI entrypoints, and callable interfaces' },
        { id: 'discovery/analyzer-disagreement', name: 'Analyzer Disagreement Mining', description: 'Suspicion scoring and candidate generation from divergent tool outputs' }
    ],
    WITNESS: [
        { id: 'witness/http', name: 'HTTP Route Witness Search', description: 'Web/API endpoint request synthesis and parameter injection testing' },
        { id: 'witness/python', name: 'Python Runtime Witness Search', description: 'Dynamic Python argument and environment probing in ProofSandbox' },
        { id: 'witness/java', name: 'Java Runtime Witness Search', description: 'JVM-based exploit harness execution and negative control checking' },
        { id: 'witness/native', name: 'C/Native Binary Witness Search', description: 'Target compilation (host/WSL) and input fuzzing execution' },
        { id: 'witness/rtl', name: 'Verilog/RTL Witness Search', description: 'RTL simulation (iverilog/vvp) and formal verification witness extraction' }
    ],
    POV: [
        { id: 'pov/python', name: 'Python PoV Generator & Replay', description: 'Self-contained reproducible Python exploit bundle generation and verification' },
        { id: 'pov/java', name: 'Java PoV Generator & Replay', description: 'Standalone Java PoV bundle packaging with classpath dependencies' },
        { id: 'pov/c', name: 'C PoV Generator & Replay', description: 'C exploit source bundle with Makefile and isolated execution script' },
        { id: 'pov/cpp', name: 'C++ PoV Generator & Replay', description: 'C++ exploit bundle with compiler flags and negative control harnesses' },
        { id: 'pov/verilog', name: 'Verilog PoV Generator & Replay', description: 'RTL testbench PoV bundle with VVP replay verification script' }
    ]
};

/**
 * Renders formatted module listing.
 * @returns {string}
 */
export function formatModules() {
    const lines = [];
    for (const [category, modules] of Object.entries(ModuleRegistry)) {
        lines.push(`\n${category}`);
        for (const mod of modules) {
            lines.push(`  ${mod.id.padEnd(35)} ${mod.description}`);
        }
    }
    return lines.join('\n');
}
