import { TaskTypes } from '../core/llm/taskTypes.js';
import fs from 'fs';
import path from 'path';
import { getEvidenceContract } from '../core/bep/evidenceContract.js';

/**
 * Creates a validated StructuredEvidencePlan.
 * @param {Object} p
 * @returns {Object}
 */
export function createStructuredEvidencePlan(p = {}) {
    return {
        hypothesis_id: p.hypothesis_id || `HYP-${Date.now()}`,
        suspected_cwe: p.suspected_cwe || 'CWE-UNKNOWN',
        title: p.title || 'Security Hypothesis',
        claim: p.claim || '',
        exact_source_locations: p.exact_source_locations || [],
        source_boundary: p.source_boundary || 'HTTP_REQUEST_PARAMETER',
        sink_location: p.sink_location || 'DANGEROUS_SINK',
        transformation_path: p.transformation_path || 'INPUT -> SOURCE -> SINK',
        missing_or_weak_validation: p.missing_or_weak_validation || 'No sanitization observed',
        required_preconditions: p.required_preconditions || [],
        minimal_deterministic_test: p.minimal_deterministic_test || 'DEFAULT_HARNESS',
        expected_oracle: p.expected_oracle || 'EXIT_CODE_OR_SIGNAL',
        negative_control: p.negative_control || null,
        recommended_tool: p.recommended_tool || 'java_sandbox',
        expected_artifacts: p.expected_artifacts || ['harness_source', 'execution_log'],
        timeout_budget_ms: p.timeout_budget_ms || 25000,
        quality_score: p.quality_score || 1.0,
        status: p.status || 'PLANNED'
    };
}

/**
 * Enforces Plan-Quality Validation.
 * Rejects malformed, unsupported, or non-testable plans before consuming execution budget.
 * @param {Object} plan
 * @returns {{ valid: boolean, reason: string }}
 */
export function validatePlanQuality(plan) {
    if (!plan || typeof plan !== 'object') {
        return { valid: false, reason: 'Plan is null or not an object' };
    }
    if (!plan.suspected_cwe || plan.suspected_cwe === 'CWE-UNKNOWN') {
        return { valid: false, reason: 'Plan lacks a specific suspected CWE' };
    }
    if (!Array.isArray(plan.exact_source_locations) || plan.exact_source_locations.length === 0) {
        return { valid: false, reason: 'Plan lacks concrete grounded source locations' };
    }
    if (!plan.expected_oracle) {
        return { valid: false, reason: 'Plan lacks a testable deterministic expected oracle' };
    }
    if (!plan.minimal_deterministic_test) {
        return { valid: false, reason: 'Plan lacks a minimal deterministic test description' };
    }
    return { valid: true, reason: 'Plan is grounded, specific, and testable' };
}

export class HypothesisGenerator {
    /**
     * @param {Object} modelRouter ModelRouter or LLMClient instance
     * @param {Object} [ragEngine] Optional RAG engine for focused context
     */
    constructor(modelRouter = null, ragEngine = null) {
        this.modelRouter = modelRouter;
        this.ragEngine = ragEngine;
    }

    /**
     * Formulates grounded security hypotheses and structured evidence plans.
     * @param {Object} params
     * @param {Array<Object>} params.deterministicFindings
     * @param {Array<Object>} params.suspiciousTargets
     * @param {Array<string>} params.availableTools
     * @param {string} [params.analysisId]
     * @param {string} [params.noveltyMode='standard']
     * @returns {Promise<Array<Object>>}
     */
    async generateHypotheses(params) {
        const {
            deterministicFindings = [],
            suspiciousTargets = [],
            availableTools = [],
            analysisId = 'global',
            noveltyMode = 'standard'
        } = params;

        if (noveltyMode === 'off') {
            return [];
        }

        const maxHypotheses = noveltyMode === 'deep' ? 6 : (noveltyMode === 'minimal' ? 2 : 3);

        // Grounded deterministic plan generation
        const generateDeterministicPlan = (finding, idx) => {
            const titleLower = (finding.title || '').toLowerCase();
            let cweId = finding.cwe_id || finding.title?.match(/CWE-\d+/)?.[0];
            if (!cweId) {
                if (titleLower.includes('command') || titleLower.includes('exec')) cweId = 'CWE-78';
                else if (titleLower.includes('sql')) cweId = 'CWE-89';
                else if (titleLower.includes('traversal') || titleLower.includes('path')) cweId = 'CWE-22';
                else if (titleLower.includes('xss') || titleLower.includes('script')) cweId = 'CWE-79';
                else if (titleLower.includes('ldap')) cweId = 'CWE-90';
                else if (titleLower.includes('xpath')) cweId = 'CWE-643';
                else cweId = 'CWE-UNKNOWN';
            }
            const contract = getEvidenceContract(cweId);
            const sourceLoc = finding.source_locations?.[0] || { path: 'unknown', startLine: 1 };

            const plan = createStructuredEvidencePlan({
                hypothesis_id: `HYP-${String(idx + 1).padStart(3, '0')}`,
                suspected_cwe: cweId,
                title: `Structured Hypothesis: ${finding.title}`,
                claim: `Attacker-controlled input reaches ${contract?.sink || 'sink'} violating ${cweId} security condition.`,
                exact_source_locations: (finding.source_locations || []).map(l => (typeof l === 'string' ? l : l.path)),
                source_boundary: contract?.attackerSourceBoundary || 'HTTP_REQUEST_PARAMETER',
                sink_location: contract?.sink || 'DANGEROUS_SECURITY_SINK',
                transformation_path: contract?.transformationPath || 'INPUT -> SOURCE -> SINK',
                missing_or_weak_validation: contract?.sanitizationValidationChecks?.[0] || 'Unvalidated input reaching sink',
                required_preconditions: ['Sandbox execution runtime available', 'Compiler tools installed'],
                minimal_deterministic_test: contract?.proofOracle || 'TARGETED_CONTAINER_HARNESS',
                expected_oracle: contract?.expectedImpactSignal || 'SINK_TRIGGER_CONFIRMED',
                negative_control: contract?.negativeControlProbe || 'BENIGN_CONTROL_PROBE',
                recommended_tool: availableTools[0] || 'hwsec_isolated_sandbox',
                expected_artifacts: ['proof_artifact.java', 'execution.log'],
                timeout_budget_ms: 25000,
                status: 'PLANNED'
            });

            return plan;
        };

        const isLlmAvailable = this.modelRouter && typeof this.modelRouter.isAvailable === 'function' && this.modelRouter.isAvailable();

        if (!isLlmAvailable) {
            const plans = deterministicFindings.slice(0, maxHypotheses).map(generateDeterministicPlan);
            return plans.filter(p => validatePlanQuality(p).valid);
        }

        const systemPrompt = `You are the HWSEC Targeted Evidence Planner.
Your job is to formulate actionable, testable StructuredEvidencePlans based on deterministic tool observations.

RULES:
1. Grounding: Every plan must map to real files, lines, and sinks present in the provided observations.
2. DO NOT declare vulnerabilities as proven fact; propose a testable hypothesis, negative control, and deterministic oracle.
3. Formulate between 1 and ${maxHypotheses} concise plans.
4. Recommended tool must be one of: ${availableTools.join(', ')}.`;

        const userPrompt = `Available Tools: ${availableTools.join(', ')}
Novelty Mode: ${noveltyMode}
Deterministic Observations:
${JSON.stringify(deterministicFindings.slice(0, 5).map(f => ({ id: f.id, title: f.title, cwe: f.cwe_id, location: f.source_locations?.[0] })), null, 2)}

Formulate testable StructuredEvidencePlans.`;

        const jsonSchema = {
            type: "OBJECT",
            properties: {
                plans: {
                    type: "ARRAY",
                    items: {
                        type: "OBJECT",
                        properties: {
                            hypothesis_id: { type: "STRING" },
                            suspected_cwe: { type: "STRING" },
                            title: { type: "STRING" },
                            claim: { type: "STRING" },
                            exact_source_locations: { type: "ARRAY", items: { type: "STRING" } },
                            source_boundary: { type: "STRING" },
                            sink_location: { type: "STRING" },
                            transformation_path: { type: "STRING" },
                            missing_or_weak_validation: { type: "STRING" },
                            minimal_deterministic_test: { type: "STRING" },
                            expected_oracle: { type: "STRING" },
                            negative_control: { type: "STRING" },
                            recommended_tool: { type: "STRING" }
                        },
                        required: ["hypothesis_id", "suspected_cwe", "title", "claim", "exact_source_locations", "expected_oracle", "minimal_deterministic_test"]
                    }
                }
            },
            required: ["plans"]
        };

        try {
            const res = await this.modelRouter.execute({
                taskType: TaskTypes.HYPOTHESIS_FORMULATION,
                systemPrompt,
                userPrompt,
                jsonSchema,
                analysisId,
                noveltyMode
            });

            const rawPlans = res.json?.plans || [];
            const validatedPlans = [];

            for (let i = 0; i < Math.min(rawPlans.length, maxHypotheses); i++) {
                const rp = rawPlans[i];
                const contract = getEvidenceContract(rp.suspected_cwe);
                const plan = createStructuredEvidencePlan({
                    ...rp,
                    hypothesis_id: rp.hypothesis_id || `HYP-${String(i + 1).padStart(3, '0')}`,
                    negative_control: rp.negative_control || contract?.negativeControlProbe || 'BENIGN_CONTROL',
                    status: 'PLANNED'
                });

                const quality = validatePlanQuality(plan);
                if (quality.valid) {
                    validatedPlans.push(plan);
                } else {
                    console.warn(`[!] [HypothesisGenerator] Rejected low-quality plan ${plan.hypothesis_id}: ${quality.reason}`);
                }
            }

            return validatedPlans.length > 0 ? validatedPlans : deterministicFindings.slice(0, maxHypotheses).map(generateDeterministicPlan);
        } catch (err) {
            console.warn(`[!] [HypothesisGenerator] LLM routing note: ${err.message}. Using deterministic fallback.`);
            const fallbackPlans = deterministicFindings.slice(0, maxHypotheses).map(generateDeterministicPlan);
            return fallbackPlans.filter(p => validatePlanQuality(p).valid);
        }
    }
}
