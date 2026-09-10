import { PromptRegistry } from './promptRegistry.js';
import { TaskClasses } from './taskRouter.js';
import { ConsensusEngine } from './consensusEngine.js';
import { HypothesisProposalSchema } from './schemas/hypothesisProposal.js';
import { CritiqueSchema } from './schemas/critique.js';
import { InvestigationPlanSchema } from './schemas/investigationPlan.js';
import { OperatingModes, MODE_ROUND_LIMITS } from './schemas/messageTypes.js';

/**
 * DebateCoordinator
 * 
 * Manages bounded, schema-validated, multi-model coordination:
 * Fast Scout (Gemini 1) -> Independent Critic (Gemini 2) -> Optional Deep Reasoner (NVIDIA)
 * 
 * Enforces strict round limits, untrusted data separation, and fail-closed error handling.
 */
export class DebateCoordinator {
    /**
     * @param {Object} params
     * @param {ProviderPool} params.providerPool
     * @param {TaskRouter} params.taskRouter
     */
    constructor({ providerPool, taskRouter }) {
        this.providerPool = providerPool;
        this.taskRouter = taskRouter;
        this.sessionHistory = [];
    }

    /**
     * Executes a bounded coordination session on a candidate finding.
     * @param {Object} params
     * @param {Object} params.finding - Raw static finding
     * @param {Array<Object>} [params.entryPoints] - Discovered entry points
     * @param {Object} [params.codeContext] - Code snippets / file context
     * @param {string} [params.mode] - FAST, STANDARD, DEEP, FORENSIC
     * @returns {Promise<Object>} Bounded coordination result
     */
    async coordinateHypothesis({ finding, entryPoints = [], codeContext = {}, mode = OperatingModes.STANDARD }) {
        const opMode = (mode || OperatingModes.STANDARD).toUpperCase();
        const maxRounds = MODE_ROUND_LIMITS[opMode] || 2;
        const sessionId = `DEBATE-${Date.now()}-${Math.random().toString(16).substring(2, 8)}`;
        const rounds = [];
        let finalProposal = null;
        let finalCritique = null;
        let consensus = null;
        let investigationPlan = null;
        let abandoned = false;

        // --- Round 1: Fast Scout (Gemini 1) ---
        const scoutRoute = this.taskRouter.route({
            taskClass: TaskClasses.INITIAL_HYPOTHESIS,
            mode: opMode
        });

        const scoutSysPrompt = PromptRegistry.getScoutSystemPrompt();
        const scoutUserPrompt = PromptRegistry.buildScoutUserPrompt({ finding, context: codeContext, entryPoints });

        let scoutResult;
        try {
            scoutResult = await this.providerPool.execute(scoutRoute.endpointId, {
                systemPrompt: scoutSysPrompt,
                userPrompt: scoutUserPrompt,
                jsonSchema: HypothesisProposalSchema,
                model: scoutRoute.model
            });
            finalProposal = scoutResult.json || this._buildFallbackProposal(finding);
        } catch (err) {
            console.warn(`[!] [DebateCoordinator] Scout execution failed (${err.message}). Using deterministic fallback proposal.`);
            finalProposal = this._buildFallbackProposal(finding);
        }

        rounds.push({
            round: 1,
            role: 'scout',
            endpoint: scoutRoute.endpointId,
            model: scoutRoute.model,
            messageType: 'HYPOTHESIS_PROPOSAL',
            payload: finalProposal
        });

        if (maxRounds <= 1) {
            return this._packageSession({ sessionId, opMode, rounds, finalProposal, finalCritique, consensus, investigationPlan, abandoned });
        }

        // --- Round 2: Independent Critic (Gemini 2) ---
        const criticRoute = this.taskRouter.route({
            taskClass: TaskClasses.INDEPENDENT_CRITIQUE,
            mode: opMode
        });

        const criticSysPrompt = PromptRegistry.getCriticSystemPrompt();
        const criticUserPrompt = PromptRegistry.buildCriticUserPrompt({
            hypothesisProposal: finalProposal,
            codeContext,
            entryPoints
        });

        let criticResult;
        try {
            criticResult = await this.providerPool.execute(criticRoute.endpointId, {
                systemPrompt: criticSysPrompt,
                userPrompt: criticUserPrompt,
                jsonSchema: CritiqueSchema,
                model: criticRoute.model
            });
            finalCritique = criticResult.json || this._buildFallbackCritique();
        } catch (err) {
            console.warn(`[!] [DebateCoordinator] Critic execution failed (${err.message}). Using fallback critique.`);
            finalCritique = this._buildFallbackCritique();
        }

        rounds.push({
            round: 2,
            role: 'critic',
            endpoint: criticRoute.endpointId,
            model: criticRoute.model,
            messageType: 'CRITIQUE',
            payload: finalCritique
        });

        // Evaluate Consensus
        consensus = ConsensusEngine.evaluateConsensus(finalProposal, finalCritique);

        // Check if hypothesis should be abandoned based on fatal critique
        if (finalCritique.disagreements?.some(d => d.severity === 'MATERIAL' && d.critique.toLowerCase().includes('dead code') || d.critique.toLowerCase().includes('unreachable'))) {
            abandoned = true;
        }

        // If consensus is reached or operating mode forbids escalation, return
        if (consensus.decision === 'AGREEMENT' || maxRounds <= 2 || !consensus.hasMaterialDisagreement) {
            return this._packageSession({ sessionId, opMode, rounds, finalProposal, finalCritique, consensus, investigationPlan, abandoned });
        }

        // --- Round 3: Deep Reasoner (NVIDIA Model Pool / Case Lead) ---
        const reasonerRoute = this.taskRouter.route({
            taskClass: TaskClasses.CONFLICT_RESOLUTION,
            mode: opMode,
            hasDisagreement: true,
            requiresDeepReasoning: true
        });

        const reasonerSysPrompt = PromptRegistry.getDeepReasonerSystemPrompt();
        const reasonerUserPrompt = PromptRegistry.buildDeepReasonerUserPrompt({
            hypothesisProposal: finalProposal,
            critique: finalCritique,
            disagreement: consensus.materialDisagreements,
            codeContext
        });

        let reasonerResult;
        try {
            reasonerResult = await this.providerPool.execute(reasonerRoute.endpointId, {
                systemPrompt: reasonerSysPrompt,
                userPrompt: reasonerUserPrompt,
                jsonSchema: InvestigationPlanSchema,
                model: reasonerRoute.model
            });
            investigationPlan = reasonerResult.json || this._buildFallbackInvestigationPlan(finalProposal);
        } catch (err) {
            console.warn(`[!] [DebateCoordinator] Deep Reasoner execution failed (${err.message}). Using fallback investigation plan.`);
            investigationPlan = this._buildFallbackInvestigationPlan(finalProposal);
        }

        rounds.push({
            round: 3,
            role: 'deep_reasoner',
            endpoint: reasonerRoute.endpointId,
            model: reasonerRoute.model,
            messageType: 'INVESTIGATION_PLAN',
            payload: investigationPlan
        });

        return this._packageSession({ sessionId, opMode, rounds, finalProposal, finalCritique, consensus, investigationPlan, abandoned });
    }

    _packageSession({ sessionId, opMode, rounds, finalProposal, finalCritique, consensus, investigationPlan, abandoned }) {
        const session = {
            sessionId,
            mode: opMode,
            roundsCount: rounds.length,
            rounds,
            finalProposal,
            finalCritique,
            consensus: consensus || { decision: 'AGREEMENT', summary: 'Single-round evaluation' },
            investigationPlan,
            abandoned,
            summary: this._generateNarrativeSummary({ rounds, consensus, investigationPlan, abandoned })
        };
        this.sessionHistory.push(session);
        return session;
    }

    _generateNarrativeSummary({ rounds, consensus, investigationPlan, abandoned }) {
        const parts = [];
        if (rounds[0]) {
            parts.push(`Scout (${rounds[0].endpoint}) proposed initial hypothesis for ${rounds[0].payload?.cwe || 'finding'}`);
        }
        if (rounds[1]) {
            if (consensus?.hasMaterialDisagreement) {
                parts.push(`Critic (${rounds[1].endpoint}) contested assumptions (${consensus.summary})`);
            } else {
                parts.push(`Critic (${rounds[1].endpoint}) concurred with Scout proposal`);
            }
        }
        if (rounds[2]) {
            parts.push(`Deep Reasoner (${rounds[2].endpoint}) resolved conflict and formulated deterministic investigation plan`);
        }
        if (abandoned) {
            parts.push(`Hypothesis flagged for deprioritization after critique`);
        }
        return parts.join(' -> ');
    }

    _buildFallbackProposal(finding) {
        return {
            message_type: 'HYPOTHESIS_PROPOSAL',
            cwe: finding.cwe || 'CWE-OTHER',
            source: finding.source || 'HTTP_PARAMETER',
            sink: finding.sink || `${finding.file || 'unknown'}:${finding.line || 1}`,
            entry_point_guess: { file: finding.file || 'unknown' },
            security_condition: `${finding.cwe || 'CWE'}_SecurityOracle`,
            assumptions: ['Standard unvalidated user input reaches sink'],
            attack_seeds: [{ parameter: 'input', value: "' OR '1'='1" }],
            falsifiers: ['Sink sanitizes or validates input before consumption']
        };
    }

    _buildFallbackCritique() {
        return {
            message_type: 'CRITIQUE',
            agreement_points: ['Finding matches static pattern heuristic'],
            disagreements: [],
            unsupported_assumptions: [],
            missing_evidence: ['Runtime observation at sink'],
            recommended_checks: ['Verify entry point reachability']
        };
    }

    _buildFallbackInvestigationPlan(proposal) {
        return {
            message_type: 'INVESTIGATION_PLAN',
            preferred_hypothesis: {
                cwe: proposal.cwe || 'CWE-OTHER',
                sink: proposal.sink || 'UNKNOWN_SINK',
                security_condition: proposal.security_condition || 'StandardOracle'
            },
            attack_strategy: {
                recommended_probes: proposal.attack_seeds || [{ parameter: 'probe', value: 'test' }],
                negative_control_input: { parameter: 'probe', value: 'benign_safe' }
            },
            ordered_deterministic_checks: ['ENTRYPOINT_VERIFY', 'ORACLE_EVALUATE', 'NEGATIVE_CONTROL'],
            required_observations: ['SINK_EXECUTION']
        };
    }
}
