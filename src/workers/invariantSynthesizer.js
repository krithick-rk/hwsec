import fs from 'fs';
import crypto from 'crypto';

export class InvariantSynthesizer {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient.forRole('hypothesis_generator');
    }

    /**
     * Generates implicit security invariants and SVA assertions from RTL logic.
     * @param {string[]} rtlFiles 
     * @param {string} outputDir 
     * @returns {Promise<{invariants: Array<Object>, monitorPath: string|null}>}
     */
    async synthesizeInvariants(rtlFiles, outputDir) {
        let combinedRtl = "";
        for (const file of rtlFiles) {
            if (fs.existsSync(file)) {
                combinedRtl += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8') + '\n\n';
            }
        }

        if (!this.llmClient.isAvailable()) {
            return { invariants: [], monitorPath: null };
        }

        const systemPrompt = `You are an expert Formal Hardware Verification Engineer in Phase 5 of the HWSEC framework.
Your task is 'Hypothesis Generation Loop & Invariant Synthesis' for novel vulnerability discovery.

GOAL:
Derive implicit hardware security invariants from the RTL state machines, control registers, and data paths without relying on known CWE pattern lookup.
Generate:
1. Concise invariant claims (e.g. valid state transitions, no unreachable unhandled states, data integrity invariants).
2. Synthesized SystemVerilog Assertions (SVA) to prove or falsify these invariants via formal verification or simulation.

RULES:
1. Grounding: Invariants must strictly reference valid signal names and modules from the RTL.
2. In the 'sva_code' field, provide valid SystemVerilog assertion monitor code that binds to the top module.`;

        const userPrompt = `RTL Source Code:
${combinedRtl.slice(0, 12000)}

Synthesize implicit security invariants and corresponding SVA assertions.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                invariants: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            invariant_id: { type: "STRING" },
                            title: { type: "STRING" },
                            property_type: { 
                                type: "STRING", 
                                enum: ["STATE_REACHABILITY", "DATA_INTEGRITY", "CONTROL_FLOW", "ARITHMETIC_BOUND"] 
                            },
                            claim: { type: "STRING" },
                            target_signals: { type: "ARRAY", items: { type: "STRING" } },
                            sva_assertion: { type: "STRING" }
                        },
                        required: ["invariant_id", "title", "property_type", "claim", "sva_assertion"]
                    }
                },
                sva_monitor_code: {
                    type: "STRING",
                    description: "Full SystemVerilog monitor module with assertions and bind statement."
                }
            },
            required: ["invariants", "sva_monitor_code"]
        };

        try {
            const res = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
            const invariants = res.json?.invariants || [];
            const monitorCode = res.json?.sva_monitor_code || '';

            let monitorPath = null;
            if (monitorCode && monitorCode.trim()) {
                monitorPath = `${outputDir}/synthesized_invariants.sv`;
                fs.writeFileSync(monitorPath, monitorCode, 'utf-8');
            }

            return {
                invariants: invariants.map((inv, idx) => ({
                    ...inv,
                    invariant_id: inv.invariant_id || `INV-${String(idx + 1).padStart(3, '0')}`,
                    class: "novel_hypothesis",
                    status: "PLANNED"
                })),
                monitorPath
            };
        } catch (e) {
            console.error(`[-] [Phase 5] Invariant synthesis error: ${e.message}`);
            return { invariants: [], monitorPath: null };
        }
    }
}
