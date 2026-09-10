/**
 * Schema for INVESTIGATION_PLAN (Deep Reasoner / Case Lead output).
 */
export const InvestigationPlanSchema = {
    type: "object",
    properties: {
        message_type: { type: "string", enum: ["INVESTIGATION_PLAN"] },
        preferred_hypothesis: {
            type: "object",
            properties: {
                cwe: { type: "string" },
                source: { type: "string" },
                sink: { type: "string" },
                entry_point: {
                    type: "object",
                    properties: {
                        file: { type: "string" },
                        method: { type: "string" },
                        route: { type: "string" },
                        parameter: { type: "string" }
                    },
                    required: ["file"]
                },
                security_condition: { type: "string" }
            },
            required: ["cwe", "sink", "security_condition"]
        },
        conflict_resolution_notes: { type: "string" },
        attack_strategy: {
            type: "object",
            properties: {
                recommended_probes: {
                    type: "array",
                    items: {
                        type: "object",
                        properties: {
                            parameter: { type: "string" },
                            value: { type: "string" },
                            purpose: { type: "string" }
                        },
                        required: ["parameter", "value"]
                    }
                },
                negative_control_input: {
                    type: "object",
                    properties: {
                        parameter: { type: "string" },
                        value: { type: "string" }
                    },
                    required: ["parameter", "value"]
                }
            },
            required: ["recommended_probes", "negative_control_input"]
        },
        ordered_deterministic_checks: {
            type: "array",
            items: { type: "string" }
        },
        required_observations: {
            type: "array",
            items: { type: "string" }
        },
        expected_artifacts: {
            type: "array",
            items: { type: "string" }
        },
        search_budget: {
            type: "object",
            properties: {
                max_iterations: { type: "number" },
                timeout_seconds: { type: "number" }
            }
        },
        fallback_plan: { type: "string" }
    },
    required: ["message_type", "preferred_hypothesis", "attack_strategy", "ordered_deterministic_checks", "required_observations"]
};
