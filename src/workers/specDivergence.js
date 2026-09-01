import fs from 'fs';
import crypto from 'crypto';
import { createFinding, Severity } from '../core/schema.js';

export class SpecDivergenceAnalyzer {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Compares RTL source implementation against ingested specification clauses.
     * @param {string[]} rtlFiles 
     * @param {Array<Object>} specClauses 
     * @param {string} outputDir 
     * @returns {Promise<{divergenceFindings: Array<Object>, differentialLog: string}>}
     */
    async analyze(rtlFiles, specClauses, outputDir) {
        if (!specClauses || specClauses.length === 0) {
            return { divergenceFindings: [], differentialLog: "No specification clauses provided for divergence analysis." };
        }

        let combinedRtl = "";
        for (const file of rtlFiles) {
            if (fs.existsSync(file)) {
                combinedRtl += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8') + '\n\n';
            }
        }

        if (!this.llmClient || !this.llmClient.isAvailable()) {
            return { divergenceFindings: [], differentialLog: "LLM client unavailable for differential specification analysis." };
        }

        const systemPrompt = `You are the Specification Divergence & Differential Testing Engine in the HWSEC system.
Your job is to compare the RTL implementation against explicit project specifications and detect behavioral divergences.

DIVERGENCE CLASSIFICATION TAXONOMY:
- SPEC_VIOLATION: Implementation directly violates or fails to satisfy an explicit specification clause.
- ALLOWED_UNDEFINED_BEHAVIOR: Implementation behavior in an area left unspecified by the specification.
- MODEL_LIMITATION: Divergence due to abstract reference model constraints.
- HARNESS_ERROR: Divergence caused by testbench or signal connection error.

RULES:
1. Grounding: Every reported divergence must explicitly quote the RTL code snippet and reference the specific clause_id.
2. Only classify as SPEC_VIOLATION if the code behavior directly contradicts the requirement.
3. Be skeptical and accurate.`;

        const userPrompt = `Specification Clauses:
${JSON.stringify(specClauses, null, 2)}

RTL Implementation Code:
${combinedRtl.slice(0, 12000)}

Perform differential divergence analysis between RTL implementation and specification requirements.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                divergences: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            clause_id: { type: "STRING" },
                            title: { type: "STRING" },
                            classification: {
                                type: "STRING",
                                enum: ["SPEC_VIOLATION", "ALLOWED_UNDEFINED_BEHAVIOR", "MODEL_LIMITATION", "HARNESS_ERROR"]
                            },
                            explanation: { type: "STRING" },
                            rtl_location: { type: "STRING" },
                            rtl_code_snippet: { type: "STRING" },
                            severity: {
                                type: "STRING",
                                enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                            }
                        },
                        required: ["clause_id", "title", "classification", "explanation", "severity"]
                    }
                }
            },
            required: ["divergences"]
        };

        const divergenceFindings = [];
        let logContent = `=== Specification Divergence & Differential Analysis Log ===\n`;

        try {
            const res = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
            const list = res.json?.divergences || [];

            for (const item of list) {
                logContent += `\n[${item.classification}] Clause ${item.clause_id}: ${item.title}\n`;
                logContent += `Explanation: ${item.explanation}\n`;
                if (item.rtl_location) logContent += `Location: ${item.rtl_location}\n`;

                if (item.classification === "SPEC_VIOLATION") {
                    const finding = createFinding({
                        id: `SPEC-DIV-${crypto.randomBytes(4).toString('hex')}`,
                        title: `[Spec Divergence] ${item.title} (${item.clause_id})`,
                        description: `Specification Clause ${item.clause_id} Violation: ${item.explanation}`,
                        severity: Severity[item.severity] || Severity.HIGH,
                        source_tool: "spec-divergence-engine",
                        rtl_location: item.rtl_location || null,
                        evidence: [{
                            id: crypto.randomBytes(4).toString('hex'),
                            tool_name: "spec-divergence",
                            artifact_path: "tools/spec_divergence_log.txt",
                            description: `Specification requirement mismatch on clause ${item.clause_id}`,
                            metadata: {
                                clause_id: item.clause_id,
                                classification: item.classification,
                                snippet: item.rtl_code_snippet
                            }
                        }],
                        verification_state: "PROPOSED"
                    });
                    divergenceFindings.push(finding);
                }
            }
        } catch (e) {
            logContent += `\nAnalysis error: ${e.message}\n`;
        }

        // Save log artifact
        fs.writeFileSync(`${outputDir}/spec_divergence_log.txt`, logContent, 'utf-8');

        return {
            divergenceFindings,
            differentialLog: logContent
        };
    }
}
