import fs from 'fs';
import path from 'path';
import { DisagreementDetector } from './disagreement.js';

const SENSITIVE_KEYWORDS = [
    'auth', 'token', 'secret', 'key', 'password', 'admin', 'root',
    'exec', 'system', 'eval', 'payload', 'crypto', 'rst', 'reset',
    'privilege', 'permission', 'overflow', 'bypass', 'untrusted', 'sink'
];

export class SuspicionEngine {
    constructor(config = {}) {
        this.config = config;
        this.disagreementDetector = new DisagreementDetector();
    }

    /**
     * Calculates a normalized suspicion score (0.0 to 1.0) for a specific source file or entity.
     * @param {Object} target
     * @param {string} target.path
     * @param {string} [target.content]
     * @param {Array<Object>} [target.findings=[]]
     * @param {Array<string>} [target.executedTools=[]]
     * @param {Object} [target.graphData]
     * @param {string} [target.noveltyMode='standard']
     * @returns {{path: string, suspicion_score: number, priority: string, signals: Object}}
     */
    scoreTarget(target) {
        const filePath = target.path;
        let content = target.content;
        if (!content && fs.existsSync(filePath)) {
            try { content = fs.readFileSync(filePath, 'utf-8'); } catch {}
        }
        content = content || '';

        const signals = {};
        let score = 0.0;

        // 1. Deterministic Findings Signal (Weight: up to 0.40)
        const relevantFindings = (target.findings || []).filter(f => {
            return (f.source_locations || []).some(l => l.path === filePath) ||
                   (f.rtl_location && f.rtl_location.includes(filePath));
        });

        let findingsScore = 0.0;
        for (const f of relevantFindings) {
            switch ((f.severity || '').toUpperCase()) {
                case 'CRITICAL': findingsScore += 0.40; break;
                case 'HIGH': findingsScore += 0.25; break;
                case 'MEDIUM': findingsScore += 0.15; break;
                case 'LOW': findingsScore += 0.05; break;
                default: findingsScore += 0.05; break;
            }
        }
        findingsScore = Math.min(findingsScore, 0.40);
        signals.deterministic_findings = { count: relevantFindings.length, score: findingsScore };
        score += findingsScore;

        // 2. Sensitive Source/Sink Keyword Density (Weight: up to 0.20)
        let keywordHits = 0;
        const lowerContent = content.toLowerCase();
        for (const kw of SENSITIVE_KEYWORDS) {
            if (lowerContent.includes(kw)) keywordHits++;
        }
        const keywordScore = Math.min(keywordHits * 0.04, 0.20);
        signals.sensitive_keywords = { hits: keywordHits, score: keywordScore };
        score += keywordScore;

        // 3. Analyzer Disagreement (Weight: up to 0.20)
        const disagreement = this.disagreementDetector.detect(filePath, target.findings || [], target.executedTools || []);
        const disagreementScore = disagreement.hasDisagreement ? Math.min(disagreement.disagreementScore * 0.25, 0.20) : 0.0;
        signals.analyzer_disagreement = { ...disagreement, score: disagreementScore };
        score += disagreementScore;

        // 4. Graph Risk & Security Boundary Crossing (Weight: up to 0.15)
        let graphScore = 0.0;
        if (target.graphData) {
            // Check if node is connected to both source and sink
            const inDegree = target.graphData.inDegree || 0;
            const outDegree = target.graphData.outDegree || 0;
            if (inDegree > 0 && outDegree > 0) graphScore += 0.10;
            if (target.graphData.crossesBoundary) graphScore += 0.05;
        }
        signals.graph_risk = { score: graphScore };
        score += graphScore;

        // 5. Novelty Mode Sensitivity Modifier (Weight: up to 0.05)
        let noveltyBonus = 0.0;
        if (target.noveltyMode === 'deep') noveltyBonus = 0.05;
        else if (target.noveltyMode === 'minimal') noveltyBonus = 0.01;
        else noveltyBonus = 0.02;
        score += noveltyBonus;
        signals.novelty_modifier = noveltyBonus;

        const normalizedScore = Number(Math.min(Math.max(score, 0.0), 1.0).toFixed(3));

        let priority = 'LOW';
        let analysisDepth = 'BASELINE_ONLY';

        if (normalizedScore >= 0.70) {
            priority = 'CRITICAL';
            analysisDepth = 'TARGETED_FORMAL_LLM';
        } else if (normalizedScore >= 0.45) {
            priority = 'HIGH';
            analysisDepth = 'DEEP_DATAFLOW';
        } else if (normalizedScore >= 0.25) {
            priority = 'MEDIUM';
            analysisDepth = 'CHEAP_DETERMINISTIC';
        } else {
            priority = 'LOW';
            analysisDepth = 'BASELINE_ONLY';
        }

        return {
            path: filePath,
            suspicion_score: normalizedScore,
            priority,
            analysis_depth: analysisDepth,
            signals
        };
    }

    /**
     * Ranks a collection of targets and isolates the top suspicious subset for deep reasoning.
     * @param {Array<Object>} targets 
     * @param {number} [topPercentage=0.20] Default top 20%
     * @returns {{ranked: Array<Object>, prioritizedTargets: Array<Object>}}
     */
    rankTargets(targets, topPercentage = 0.20) {
        const scored = targets.map(t => this.scoreTarget(t));
        scored.sort((a, b) => b.suspicion_score - a.suspicion_score);

        const cutoffIndex = Math.max(1, Math.ceil(scored.length * topPercentage));
        const prioritizedTargets = scored.slice(0, cutoffIndex);

        return {
            ranked: scored,
            prioritizedTargets
        };
    }
}
