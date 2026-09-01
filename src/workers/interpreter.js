import crypto from 'crypto';
import { createFinding, Severity } from '../core/schema.js';

export class ToolOutputInterpreterWorker {
    /**
     * @param {import('../core/llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Interprets raw tool output into structured findings and validates against hallucination.
     * @param {string} toolName - e.g. "verilator", "yosys", "afl++"
     * @param {Object} telemetry - Raw telemetry object
     * @param {string} artifactPath - Path to saved telemetry evidence
     * @returns {Promise<{findings: import('../core/schema.js').Finding[], rejectedCount: number, auditLog: string[]}>}
     */
    async interpret(toolName, telemetry, artifactPath) {
        const rawLogs = (telemetry.stdout || '') + '\n' + (telemetry.stderr || '');
        if (!rawLogs.trim()) {
            return { findings: [], rejectedCount: 0, auditLog: ["No raw output to interpret."] };
        }

        const systemPrompt = `You are a bounded, single-purpose Hardware/RTL Tool Output Interpreter in the HWSEC system.
Your SOLE responsibility is to parse and interpret raw outputs from hardware verification tools (${toolName}) into structured findings.

STRICT OPERATIONAL RULES:
1. Grounding: You must ONLY report issues, warnings, or anomalies that are explicitly printed in the provided tool output.
2. Anti-Hallucination: Do NOT invent, assume, or extrapolate security bugs or file locations not present in the output.
3. Every finding MUST include the exact verbatim quote ('raw_evidence_quote') from the log as proof.
4. If the tool output contains pure syntax/compilation errors or clean execution with 0 issues, return an empty findings list.
5. All findings must have verification_state: "PROPOSED".`;

        const userPrompt = `Tool Name: ${toolName}
Exit Code: ${telemetry.exitCode}
Duration: ${telemetry.durationMs}ms

--- RAW TOOL LOG START ---
${rawLogs.slice(0, 15000)}
--- RAW TOOL LOG END ---

Extract any legitimate hardware security-relevant warnings, potential logic flaws, or synthesis issues mentioned in the log.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                findings: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            title: { type: "STRING" },
                            description: { type: "STRING" },
                            severity: { 
                                type: "STRING", 
                                enum: ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] 
                            },
                            rtl_location: { type: "STRING" },
                            raw_evidence_quote: { type: "STRING" }
                        },
                        required: ["title", "description", "severity", "raw_evidence_quote"]
                    }
                }
            },
            required: ["findings"]
        };

        const response = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
        const rawFindings = response.json?.findings || [];

        return this._validateAntiHallucination(rawFindings, rawLogs, toolName, artifactPath);
    }

    /**
     * Verifies that every finding's quoted evidence actually exists in the raw logs.
     * Rejects any finding that cannot be grounded in raw evidence.
     */
    _validateAntiHallucination(rawFindings, rawLogs, toolName, artifactPath) {
        const validatedFindings = [];
        const auditLog = [];
        let rejectedCount = 0;

        for (const item of rawFindings) {
            const quote = (item.raw_evidence_quote || '').trim();
            
            // Check if the quote exists in the raw output (flexible whitespace matching)
            const cleanQuote = quote.replace(/\s+/g, ' ');
            const cleanLogs = rawLogs.replace(/\s+/g, ' ');

            if (!quote || (!cleanLogs.includes(cleanQuote) && !rawLogs.includes(quote))) {
                rejectedCount++;
                auditLog.push(`[ANTI-HALLUCINATION REJECTED] Finding "${item.title}" failed grounding: quote not found in tool log.`);
                continue;
            }

            const finding = createFinding({
                id: `${toolName.toUpperCase().slice(0, 4)}-LLM-${crypto.randomBytes(4).toString('hex')}`,
                title: item.title,
                description: item.description,
                severity: Severity[item.severity] || Severity.LOW,
                source_tool: `${toolName}-interpreter`,
                rtl_location: item.rtl_location || null,
                evidence: [{
                    id: crypto.randomBytes(4).toString('hex'),
                    tool_name: toolName,
                    artifact_path: artifactPath,
                    description: `LLM-interpreted tool output verified against raw evidence`,
                    metadata: {
                        verified_quote: quote
                    }
                }],
                verification_state: "PROPOSED"
            });

            validatedFindings.push(finding);
            auditLog.push(`[VERIFIED GROUNDING] Finding "${item.title}" validated against raw tool evidence.`);
        }

        return {
            findings: validatedFindings,
            rejectedCount,
            auditLog
        };
    }
}
