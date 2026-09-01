import fs from 'fs';
import path from 'path';

export class RefinerWorker {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Reads the RTL and refuted hypotheses to generate refinements (like AFL dictionaries).
     * @param {string[]} rtlFiles 
     * @param {any[]} refutedHypotheses 
     * @returns {Promise<{ dictionary: string, rationale: string }>}
     */
    async generateFuzzerDictionary(rtlFiles, refutedHypotheses) {
        if (!this.llmClient.isAvailable()) {
            throw new Error("LLM is not available for refinement.");
        }

        let combinedRtl = "";
        for (const file of rtlFiles) {
            if (fs.existsSync(file)) {
                combinedRtl += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8') + '\n\n';
            }
        }

        const systemPrompt = `You are the Refinement and Escalation Worker in the HWSEC framework (Phase 5).
The fuzzer previously failed to prove the security hypotheses (they were refuted), likely because it got stuck on complex state machine transitions or magic number comparisons.
Your task is to extract ALL magic constants, hex values, and magic strings from the RTL source code and output them as an AFL++ dictionary file.

RULES:
1. AFL dictionary format requires entries like:
   state1="\\xDE\\xAD"
   state2="\\xBE\\xEF"
2. Convert all Verilog hex literals (e.g. 16'hDEAD, 32'hCAFEBABE) into exact AFL hex escape sequences. For 16'hDEAD, it is "\\xDE\\xAD" (assuming big-endian or little-endian, just output the bytes).
3. Do not include markdown formatting in the 'dictionary_content' field.`;

        const userPrompt = `=== REFUTED HYPOTHESES ===
${JSON.stringify(refutedHypotheses, null, 2)}

=== RTL SOURCE CODE ===
${combinedRtl.slice(0, 15000)}

Generate an AFL++ dictionary to help the fuzzer bypass these checks.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                dictionary_content: {
                    type: "STRING",
                    description: "Raw AFL dictionary content without markdown formatting."
                },
                rationale: {
                    type: "STRING",
                    description: "Explanation of what constants were extracted and why."
                }
            },
            required: ["dictionary_content", "rationale"]
        };

        const response = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
        
        if (response.json && response.json.dictionary_content) {
            return response.json;
        }
        
        throw new Error("Failed to generate dictionary.");
    }
}
