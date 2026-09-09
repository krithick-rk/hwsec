/**
 * BEP Ablation & Control Experiment Suite
 * Manages controlled configurations A through H and computes paired per-case diffs.
 */

export const AblationConfig = Object.freeze({
    A: { id: 'A', name: 'Semgrep Only', semgrep: true, joern: false, candGen: false, evidencePlan: false, javaValidation: false, proof: false, full: false },
    B: { id: 'B', name: 'Semgrep + Joern', semgrep: true, joern: true, candGen: false, evidencePlan: false, javaValidation: false, proof: false, full: false },
    C: { id: 'C', name: 'B + Candidate Generator', semgrep: true, joern: true, candGen: true, evidencePlan: false, javaValidation: false, proof: false, full: false },
    D: { id: 'D', name: 'C + Structured Evidence Plan', semgrep: true, joern: true, candGen: true, evidencePlan: true, javaValidation: false, proof: false, full: false },
    E: { id: 'E', name: 'D + Java/Maven Validation Profile', semgrep: true, joern: true, candGen: true, evidencePlan: true, javaValidation: true, proof: false, full: false },
    F: { id: 'F', name: 'E + Controlled Proof Validation', semgrep: true, joern: true, candGen: true, evidencePlan: true, javaValidation: true, proof: true, full: false },
    G: { id: 'G', name: 'Full HWSEC (All Stages Active)', semgrep: true, joern: true, candGen: true, evidencePlan: true, javaValidation: true, proof: true, full: true }
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
        let tp = 0, fp = 0, fn = 0, tn = 0, inconclusive = 0;
        let detected = 0, not_detected = 0, inconclusive_pred = 0;

        for (const cr of caseResults || []) {
            const cls = cr.classification;
            const pred = cr.prediction;
            if (cls === 'TP') tp++;
            else if (cls === 'FP') fp++;
            else if (cls === 'FN') fn++;
            else if (cls === 'TN') tn++;
            else inconclusive++;

            if (pred === 'DETECTED') detected++;
            else if (pred === 'NOT_DETECTED') not_detected++;
            else inconclusive_pred++;
        }

        const totalCases = (caseResults || []).length;
        const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
        const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
        const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
        const detected_coverage = totalCases > 0 ? detected / totalCases : 0;
        const inconclusive_coverage = totalCases > 0 ? inconclusive_pred / totalCases : 0;

        return {
            tp, fp, fn, tn, inconclusive,
            total_cases: totalCases,
            precision,
            recall,
            f1,
            detected_coverage,
            inconclusive_coverage
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
