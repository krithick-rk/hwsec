/**
 * BEP Ablation & Control Experiment Suite
 * Manages controlled configurations A through H and computes paired per-case diffs.
 */

export const AblationConfig = Object.freeze({
    A: { id: 'A', name: 'Semgrep Only', semgrep: true, joern: false, candGen: false, graph: false, rag: false, hypothesis: false, verifier: false, proof: false },
    B: { id: 'B', name: 'Semgrep + Joern', semgrep: true, joern: true, candGen: false, graph: false, rag: false, hypothesis: false, verifier: false, proof: false },
    C: { id: 'C', name: 'B + Candidate Generator', semgrep: true, joern: true, candGen: true, graph: false, rag: false, hypothesis: false, verifier: false, proof: false },
    D: { id: 'D', name: 'C + CodeGraph', semgrep: true, joern: true, candGen: true, graph: true, rag: false, hypothesis: false, verifier: false, proof: false },
    E: { id: 'E', name: 'D + Qdrant/RAG', semgrep: true, joern: true, candGen: true, graph: true, rag: true, hypothesis: false, verifier: false, proof: false },
    F: { id: 'F', name: 'E + Hypothesis/Invariant', semgrep: true, joern: true, candGen: true, graph: true, rag: true, hypothesis: true, verifier: false, proof: false },
    G: { id: 'G', name: 'Full HWSEC', semgrep: true, joern: true, candGen: true, graph: true, rag: true, hypothesis: true, verifier: true, proof: true },
    H: { id: 'H', name: 'Full HWSEC - LLM Verifier', semgrep: true, joern: true, candGen: true, graph: true, rag: true, hypothesis: true, verifier: false, proof: true }
});

export class AblationSuite {
    constructor() {
        this.results = new Map();
    }

    recordConfigResult(configKey, caseResults) {
        const metrics = this.computeMetrics(caseResults);
        this.results.set(configKey, {
            config: AblationConfig[configKey] || { id: configKey, name: configKey },
            metrics,
            caseResults
        });
        return metrics;
    }

    computeMetrics(caseResults) {
        let tp = 0, fp = 0, fn = 0, tn = 0, unknown = 0;
        for (const cr of caseResults || []) {
            const cls = cr.classification;
            if (cls === 'TP') tp++;
            else if (cls === 'FP') fp++;
            else if (cls === 'FN') fn++;
            else if (cls === 'TN') tn++;
            else unknown++;
        }

        const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
        const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
        const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
        const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0;
        const fnr = (fn + tp) > 0 ? fn / (fn + tp) : 0;

        return {
            tp, fp, fn, tn, unknown,
            total_cases: (caseResults || []).length,
            precision,
            recall,
            f1,
            false_positive_rate: fpr,
            false_negative_rate: fnr
        };
    }

    computeDiff(configKeyA, configKeyB) {
        const resA = this.results.get(configKeyA);
        const resB = this.results.get(configKeyB);

        if (!resA || !resB) {
            throw new Error(`Ablation results missing for diff between ${configKeyA} and ${configKeyB}`);
        }

        const mapA = new Map(resA.caseResults.map(c => [c.case_id, c]));
        const mapB = new Map(resB.caseResults.map(c => [c.case_id, c]));

        const diffs = [];
        let fpToTn = 0, fnToTp = 0, tpToFn = 0, tnToFp = 0;

        for (const [caseId, caseB] of mapB.entries()) {
            const caseA = mapA.get(caseId);
            if (!caseA) continue;

            if (caseA.classification !== caseB.classification) {
                const change = `${caseA.classification} -> ${caseB.classification}`;
                if (caseA.classification === 'FP' && caseB.classification === 'TN') fpToTn++;
                if (caseA.classification === 'FN' && caseB.classification === 'TP') fnToTp++;
                if (caseA.classification === 'TP' && caseB.classification === 'FN') tpToFn++;
                if (caseA.classification === 'TN' && caseB.classification === 'FP') tnToFp++;

                diffs.push({
                    case_id: caseId,
                    classification_before: caseA.classification,
                    classification_after: caseB.classification,
                    change,
                    reclassification_taxonomy: caseB.reclassification_taxonomy || 'NONE'
                });
            }
        }

        return {
            config_a: configKeyA,
            config_b: configKeyB,
            metrics_a: resA.metrics,
            metrics_b: resB.metrics,
            total_changed_cases: diffs.length,
            fp_to_tn_count: fpToTn,
            fn_to_tp_count: fnToTp,
            tp_to_fn_count: tpToFn,
            tn_to_fp_count: tnToFp,
            diffs
        };
    }

    generateAblationReportMarkdown() {
        let md = `# HWSEC Ablation & Control Experiment Report\n\n`;
        md += `| Config ID | Description | TP | FP | FN | TN | Precision | Recall | F1 | FPR |\n`;
        md += `|---|---|---|---|---|---|---|---|---|---|\n`;

        for (const [key, res] of this.results.entries()) {
            const m = res.metrics;
            md += `| **${key}** | ${res.config.name} | ${m.tp} | ${m.fp} | ${m.fn} | ${m.tn} | ${(m.precision * 100).toFixed(1)}% | ${(m.recall * 100).toFixed(1)}% | ${(m.f1 * 100).toFixed(1)}% | ${(m.false_positive_rate * 100).toFixed(1)}% |\n`;
        }

        return md;
    }
}
