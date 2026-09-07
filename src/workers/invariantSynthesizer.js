import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { TaskTypes } from '../core/llm/taskTypes.js';

export class InvariantSynthesizer {
    /**
     * @param {Object} modelRouter ModelRouter instance
     */
    constructor(modelRouter = null) {
        this.modelRouter = modelRouter;
    }

    /**
     * Synthesizes testable security invariants (property, expected behavior, test strategy).
     * @param {string[]} sourceFiles 
     * @param {string} outputDir 
     * @param {Object} [options={}]
     * @returns {Promise<{invariants: Array<Object>, monitorPath: string|null}>}
     */
    async synthesizeInvariants(sourceFiles, outputDir, options = {}) {
        let combinedSource = "";
        for (const file of sourceFiles) {
            if (fs.existsSync(file)) {
                combinedSource += `// File: ${file}\n` + fs.readFileSync(file, 'utf-8').slice(0, 4000) + '\n\n';
            }
        }

        const isLlmAvailable = this.modelRouter && typeof this.modelRouter.isAvailable === 'function' && this.modelRouter.isAvailable();
        if (!isLlmAvailable) {
            return { invariants: [], monitorPath: null };
        }

        const systemPrompt = `You are the HWSEC Security Invariant Engine.
Your task is to derive formal/testable security invariants for the target source code.

RULES:
1. Formulate:
   - security_property: the specific property being enforced (e.g. Memory Bounds, Reset State Trap)
   - expected_behavior: what correct, secure execution guarantees
   - test_strategy: how to deterministically verify or falsify this property
2. DO NOT declare 'this is vulnerable'; formulate a testable property.
3. Reference real ports, variables, or functions from the code.`;

        const userPrompt = `Source Code:\n${combinedSource.slice(0, 10000)}\n\nSynthesize testable security invariants.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                invariants: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            invariant_id: { type: "STRING" },
                            security_property: { type: "STRING" },
                            expected_behavior: { type: "STRING" },
                            test_strategy: { type: "STRING" },
                            target_signals: { type: "ARRAY", items: { type: "STRING" } },
                            sva_code: { type: "STRING" }
                        },
                        required: ["invariant_id", "security_property", "expected_behavior", "test_strategy"]
                    }
                },
                sva_monitor_code: { type: "STRING" }
            },
            required: ["invariants"]
        };

        try {
            const res = await this.modelRouter.execute({
                taskType: TaskTypes.INVARIANT_GENERATION,
                systemPrompt,
                userPrompt,
                jsonSchema,
                analysisId: options.analysisId || 'global'
            });

            const invariants = (res.json?.invariants || []).map((inv, idx) => ({
                id: inv.invariant_id || `INV-${String(idx + 1).padStart(3, '0')}`,
                hypothesis_id: `HYP-INV-${String(idx + 1).padStart(3, '0')}`,
                title: inv.security_property,
                claim: inv.expected_behavior,
                security_property: inv.security_property,
                expected_behavior: inv.expected_behavior,
                test_strategy: inv.test_strategy,
                generation_model: res.model || 'modelRouter',
                test_methods: [inv.test_strategy || 'formal'],
                results: 'PLANNED',
                evidence: []
            }));

            let monitorPath = null;
            if (res.json?.sva_monitor_code) {
                monitorPath = path.join(outputDir, 'synthesized_invariants.sv');
                fs.writeFileSync(monitorPath, res.json.sva_monitor_code, 'utf-8');
            }

            return { invariants, monitorPath };
        } catch (e) {
            console.warn(`[-] Invariant synthesis skipped: ${e.message}`);
            return { invariants: [], monitorPath: null };
        }
    }
}
