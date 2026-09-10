/**
 * Schema for HYPOTHESIS_PROPOSAL (Scout output).
 */
export const HypothesisProposalSchema = {
    type: "object",
    properties: {
        message_type: { type: "string", enum: ["HYPOTHESIS_PROPOSAL"] },
        cwe: { type: "string" },
        source: { type: "string" },
        sink: { type: "string" },
        entry_point_guess: {
            type: "object",
            properties: {
                file: { type: "string" },
                method: { type: "string" },
                route: { type: "string" },
                parameter: { type: "string" }
            },
            required: ["file"]
        },
        security_condition: { type: "string" },
        assumptions: {
            type: "array",
            items: { type: "string" }
        },
        attack_seeds: {
            type: "array",
            items: {
                type: "object",
                properties: {
                    parameter: { type: "string" },
                    value: { type: "string" },
                    rationale: { type: "string" }
                },
                required: ["parameter", "value"]
            }
        },
        falsifiers: {
            type: "array",
            items: { type: "string" }
        },
        confidence_notes: { type: "string" }
    },
    required: ["message_type", "cwe", "sink", "security_condition", "assumptions", "attack_seeds", "falsifiers"]
};
