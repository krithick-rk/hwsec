import { OperatingModes } from './schemas/messageTypes.js';

export const TaskClasses = {
    SUMMARIZATION: 'file_function_summarization',
    INITIAL_HYPOTHESIS: 'initial_vulnerability_hypothesis',
    INDEPENDENT_CRITIQUE: 'independent_critique',
    CONFLICT_RESOLUTION: 'cross_tool_conflict_resolution',
    COMPLEX_REASONING: 'complex_framework_dataflow_reasoning',
    ATTACK_SEED_GEN: 'attack_seed_generation',
    ORACLE_DRAFTING: 'harness_oracle_drafting',
    ANALYST_EXPLANATION: 'analyst_explanation'
};

/**
 * TaskRouter
 * 
 * Dynamic, task-based routing engine matching tasks to the optimal provider endpoint and model.
 * Considers task classification, operating mode, provider health, latency, context size, and escalation rules.
 */
export class TaskRouter {
    constructor(providerPool, config = {}) {
        this.providerPool = providerPool;
        this.config = config || {};
        this.routingLog = [];
    }

    /**
     * Determines the optimal provider endpoint and model for a given task.
     * @param {Object} task
     * @param {string} task.taskClass - One of TaskClasses
     * @param {string} [task.mode] - FAST, STANDARD, DEEP, FORENSIC
     * @param {boolean} [task.hasDisagreement]
     * @param {boolean} [task.repeatedFailure]
     * @param {number} [task.contextTokens]
     * @param {boolean} [task.requiresDeepReasoning]
     * @returns {{ endpointId: string, model: string, reason: string, escalated: boolean, fallback: boolean }}
     */
    route(task) {
        const mode = (task.mode || OperatingModes.STANDARD).toUpperCase();
        const taskClass = task.taskClass || TaskClasses.INITIAL_HYPOTHESIS;
        const contextTokens = task.contextTokens || 0;
        let escalated = false;
        let fallback = false;
        let selectedEndpoint = null;
        let reason = '';

        // 1. Determine Preferred Route & Escalation Rules
        switch (taskClass) {
            case TaskClasses.SUMMARIZATION:
            case TaskClasses.ANALYST_EXPLANATION:
                if (mode === OperatingModes.FORENSIC && task.requiresDeepReasoning) {
                    selectedEndpoint = 'nvidia';
                    reason = 'Forensic mode requested complex narrative generation';
                    escalated = true;
                } else {
                    selectedEndpoint = 'gemini_account_1';
                    reason = 'High-throughput low-latency summarization';
                }
                break;

            case TaskClasses.INITIAL_HYPOTHESIS:
                if (task.requiresDeepReasoning || (mode === OperatingModes.DEEP && task.hasDisagreement)) {
                    selectedEndpoint = 'nvidia';
                    reason = 'Deep reasoning required for ambiguous multi-file hypothesis formulation';
                    escalated = true;
                } else {
                    selectedEndpoint = 'gemini_account_1';
                    reason = 'Fast reconnaissance and initial hypothesis proposal';
                }
                break;

            case TaskClasses.INDEPENDENT_CRITIQUE:
                if (mode === OperatingModes.FAST) {
                    selectedEndpoint = 'gemini_account_1';
                    reason = 'Fast mode minimal critique triage';
                } else {
                    selectedEndpoint = 'gemini_account_2';
                    reason = 'Independent second opinion and falsification challenge';
                }
                break;

            case TaskClasses.CONFLICT_RESOLUTION:
            case TaskClasses.COMPLEX_REASONING:
                selectedEndpoint = 'nvidia';
                reason = 'Cross-tool disagreement or complex framework reasoning';
                escalated = true;
                break;

            case TaskClasses.ATTACK_SEED_GEN:
                if (task.repeatedFailure) {
                    selectedEndpoint = 'nvidia';
                    reason = 'Initial seeds failed repeatedly; escalating to deep constraint reasoning';
                    escalated = true;
                } else {
                    selectedEndpoint = 'gemini_account_1';
                    reason = 'Standard rapid attack seed generation';
                }
                break;

            case TaskClasses.ORACLE_DRAFTING:
                selectedEndpoint = 'nvidia';
                reason = 'Precise security condition oracle synthesis';
                break;

            default:
                selectedEndpoint = 'gemini_account_1';
                reason = 'Default fast reconnaissance';
        }

        // 2. Health & Availability Filter with Intelligent Failover
        if (!this.providerPool.isHealthy(selectedEndpoint)) {
            const originalEndpoint = selectedEndpoint;
            fallback = true;

            if (selectedEndpoint === 'gemini_account_1' && this.providerPool.isHealthy('gemini_account_2')) {
                selectedEndpoint = 'gemini_account_2';
                reason = `Primary Gemini 1 unavailable/degraded; failing over to Gemini 2`;
            } else if ((selectedEndpoint === 'gemini_account_1' || selectedEndpoint === 'gemini_account_2') && this.providerPool.isHealthy('nvidia')) {
                selectedEndpoint = 'nvidia';
                reason = `Gemini accounts unavailable; failing over to NVIDIA deep reasoner`;
            } else if (selectedEndpoint === 'nvidia' && this.providerPool.isHealthy('openrouter')) {
                selectedEndpoint = 'openrouter';
                reason = `NVIDIA pool unavailable; failing over to OpenRouter specialist`;
            } else if (this.providerPool.isHealthy('openrouter')) {
                selectedEndpoint = 'openrouter';
                reason = `Primary endpoint '${originalEndpoint}' unavailable; falling back to OpenRouter pool`;
            } else if (this.providerPool.isHealthy('gemini_account_1')) {
                selectedEndpoint = 'gemini_account_1';
                reason = `Failing back to Gemini 1`;
            } else if (this.providerPool.isHealthy('gemini_account_2')) {
                selectedEndpoint = 'gemini_account_2';
                reason = `Failing back to Gemini 2`;
            } else if (this.providerPool.isHealthy('nvidia')) {
                selectedEndpoint = 'nvidia';
                reason = `Failing back to NVIDIA`;
            } else {
                reason = `All configured provider accounts are currently unavailable or circuit breakers are open`;
            }
        }

        const endpointObj = this.providerPool.getEndpoint(selectedEndpoint);
        const model = endpointObj?.preferredModel || 'default';

        const routeDecision = {
            taskClass,
            mode,
            endpointId: selectedEndpoint,
            model,
            reason,
            escalated,
            fallback,
            timestamp: new Date().toISOString()
        };

        this.routingLog.push(routeDecision);
        return routeDecision;
    }
}
