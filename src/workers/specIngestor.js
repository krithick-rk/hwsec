import fs from 'fs';

export class SpecIngestorWorker {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Ingests a markdown specification and RTL code to generate a SystemVerilog monitor.
     * @param {string} specContent 
     * @param {string} rtlContent 
     * @returns {Promise<string>} The generated SystemVerilog assertions code
     */
    async generateMonitor(specContent, rtlContent) {
        if (!this.llmClient.isAvailable()) {
            throw new Error("LLM is not available. Cannot perform specification ingestion.");
        }

        const systemPrompt = `You are an expert Hardware Security Engineer operating in Phase 4 of the HWSEC framework.
Your task is to perform 'Specification Ingestion + Divergence' testing.
You will be provided with a natural language specification (Markdown) and the RTL source code.

Your goal is to generate a SystemVerilog monitor module that encodes the specification as SystemVerilog Assertions (SVA) using 'assert property' or standard 'always @(...) assert(...)'.
You must also include a 'bind' statement at the bottom of your output to bind your monitor to the top-level RTL module.

RULES:
1. The monitor module should only have inputs corresponding to the signals in the top-level module it binds to.
2. If the specification describes sequences, state machines, or invariants, encode them using assertions. If the RTL violates the spec, the assertion must fail (which our fuzzer will catch as a crash).
3. Do not include any markdown formatting or \`\`\`verilog tags in the 'monitor_code' field. It must be raw valid SystemVerilog code ready to be compiled.
4. Ensure you use '$fatal' or 'assert' correctly.`;

        const userPrompt = `=== SPECIFICATION ===
${specContent}

=== RTL SOURCE CODE ===
${rtlContent}

Generate the SystemVerilog monitor and bind statement.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                monitor_code: {
                    type: "STRING",
                    description: "Raw SystemVerilog code containing the monitor module and bind statement. No markdown."
                },
                ingested_rules: {
                    type: "ARRAY",
                    items: { type: "STRING" },
                    description: "List of specification rules successfully encoded."
                }
            },
            required: ["monitor_code", "ingested_rules"]
        };

        const response = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
        
        if (response.json && response.json.monitor_code) {
            return response.json;
        }
        
        throw new Error("Failed to generate monitor code.");
    }
}
