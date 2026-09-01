import fs from 'fs';
import path from 'path';

/**
 * Ingests and parses specification files into structured clauses.
 */
export class SpecIngestion {
    /**
     * @param {import('./llmClient.js').LLMClient} llmClient 
     */
    constructor(llmClient) {
        this.llmClient = llmClient;
    }

    /**
     * Finds and reads specification files from a directory or specific file.
     * @param {string} specPath 
     * @returns {Array<{path: string, content: string}>}
     */
    loadSpecFiles(specPath) {
        if (!specPath || !fs.existsSync(specPath)) {
            return [];
        }

        const stat = fs.statSync(specPath);
        const specFiles = [];

        if (stat.isFile()) {
            specFiles.push({
                path: path.resolve(specPath),
                content: fs.readFileSync(specPath, 'utf-8')
            });
        } else if (stat.isDirectory()) {
            const entries = fs.readdirSync(specPath);
            for (const entry of entries) {
                const fullPath = path.join(specPath, entry);
                if (fs.statSync(fullPath).isFile() && (entry.endsWith('.md') || entry.endsWith('.txt') || entry.endsWith('.json'))) {
                    specFiles.push({
                        path: fullPath,
                        content: fs.readFileSync(fullPath, 'utf-8')
                    });
                }
            }
        }

        return specFiles;
    }

    /**
     * Extracts structured clauses from raw specification text using LLM.
     * @param {Array<{path: string, content: string}>} specFiles 
     * @returns {Promise<Array<Object>>}
     */
    async extractClauses(specFiles) {
        if (!specFiles || specFiles.length === 0) return [];

        const combinedText = specFiles.map(f => `--- SPEC FILE: ${f.path} ---\n${f.content}`).join('\n\n');

        if (!this.llmClient || !this.llmClient.isAvailable()) {
            // Fallback rule-based clause extraction
            const lines = combinedText.split('\n').filter(l => l.trim().startsWith('-') || l.trim().startsWith('*') || l.match(/^\d+\./));
            return lines.slice(0, 5).map((l, i) => ({
                clause_id: `SPEC-CLAUSE-${String(i + 1).padStart(3, '0')}`,
                title: `Specification Rule ${i + 1}`,
                requirement: l.replace(/^[-*\d.]+\s*/, '').trim(),
                target_module: "top",
                security_relevant: true
            }));
        }

        const systemPrompt = `You are a Hardware Specification Ingestion Engine in the HWSEC system.
Your job is to parse functional and security requirements from hardware documentation into structured, testable clauses.

RULES:
1. Extract 2 to 5 explicit requirements, interface rules, register constraints, or invariants.
2. Formulate clear, unambiguous requirement statements.`;

        const userPrompt = `Specification Documents:
${combinedText.slice(0, 10000)}

Extract structured clauses.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                clauses: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            clause_id: { type: "STRING" },
                            title: { type: "STRING" },
                            requirement: { type: "STRING" },
                            target_module: { type: "STRING" },
                            security_relevant: { type: "BOOLEAN" }
                        },
                        required: ["clause_id", "title", "requirement", "target_module"]
                    }
                }
            },
            required: ["clauses"]
        };

        try {
            const res = await this.llmClient.generateContent(systemPrompt, userPrompt, jsonSchema);
            return res.json?.clauses || [];
        } catch {
            return [];
        }
    }
}
