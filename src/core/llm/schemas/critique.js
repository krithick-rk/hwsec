/**
 * Schema for CRITIQUE (Independent Critic output).
 */
export const CritiqueSchema = {
    type: "object",
    properties: {
        message_type: { type: "string", enum: ["CRITIQUE"] },
        agreement_points: {
            type: "array",
            items: { type: "string" }
        },
        disagreements: {
            type: "array",
            items: {
                type: "object",
                properties: {
                    field: { type: "string", enum: ["cwe", "entry_point", "sink", "security_condition", "assumptions", "attack_seeds"] },
                    critique: { type: "string" },
                    proposed_alternative: { type: "string" },
                    severity: { type: "string", enum: ["MATERIAL", "MINOR"] }
                },
                required: ["field", "critique", "severity"]
            }
        },
        unsupported_assumptions: {
            type: "array",
            items: { type: "string" }
        },
        alternative_hypotheses: {
            type: "array",
            items: {
                type: "object",
                properties: {
                    cwe: { type: "string" },
                    sink: { type: "string" },
                    entry_point: { type: "string" },
                    rationale: { type: "string" }
                },
                required: ["cwe", "rationale"]
            }
        },
        missing_evidence: {
            type: "array",
            items: { type: "string" }
        },
        recommended_checks: {
            type: "array",
            items: { type: "string" }
        },
        falsification_plan: { type: "string" }
    },
    required: ["message_type", "agreement_points", "disagreements", "unsupported_assumptions", "missing_evidence", "recommended_checks"]
};
