import { createHardwareAssertionRecord } from './bepSchema.js';

/**
 * Hardware SVA & Formal Assertion Evidence Tracker
 * Tracks per-assertion results for Hack@DAC and RTL benchmarks.
 */

export class HardwareAssertionTracker {
    constructor() {
        this.assertions = [];
        this.assertionsByCase = new Map();
    }

    recordAssertion(params) {
        const record = createHardwareAssertionRecord(params);
        this.assertions.push(record);

        if (!this.assertionsByCase.has(record.case_id)) {
            this.assertionsByCase.set(record.case_id, []);
        }
        this.assertionsByCase.get(record.case_id).push(record);

        return record;
    }

    getMetrics() {
        const total = this.assertions.length;
        if (total === 0) {
            return {
                total_assertions: 0,
                generation_rate: 0,
                syntax_compile_success_rate: 0,
                elaboration_success_rate: 0,
                semantic_validity_rate: 0,
                non_vacuous_proof_rate: 0,
                known_bug_detection_rate: 0,
                confirmed_proof_rate: 0
            };
        }

        const compilePassed = this.assertions.filter(a => a.compile_result === 'PASSED').length;
        const nonVacuous = this.assertions.filter(a => a.vacuity_status === 'NON_VACUOUS').length;
        const proofPassed = this.assertions.filter(a => a.proof_result === 'PASS').length;
        const bugsDetected = this.assertions.filter(a => a.proof_result === 'FAIL' || a.proof_result === 'COUNTEREXAMPLE_FOUND').length;

        return {
            total_assertions: total,
            generation_rate: 1.0,
            syntax_compile_success_rate: compilePassed / total,
            elaboration_success_rate: compilePassed / total,
            semantic_validity_rate: nonVacuous / total,
            non_vacuous_proof_rate: nonVacuous / total,
            known_bug_detection_rate: bugsDetected / total,
            confirmed_proof_rate: proofPassed / total
        };
    }

    generateTableMarkdown() {
        let md = `## Hardware SVA & Formal Assertion Evidence Matrix\n\n`;
        md += `| Assertion ID | Case / Bug ID | Compile Result | Vacuity Status | Proof Result | Semantic Status |\n`;
        md += `|---|---|---|---|---|---|\n`;
        if (this.assertions.length === 0) {
            md += `| *No assertions generated* | - | - | - | - | - |\n`;
        } else {
            for (const a of this.assertions) {
                md += `| \`${a.assertion_id}\` | \`${a.case_id}\` | ${a.compile_result} | ${a.vacuity_status} | ${a.proof_result} | ${a.semantic_status} |\n`;
            }
        }
        return md;
    }
}
