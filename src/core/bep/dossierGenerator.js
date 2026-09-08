/**
 * Single-Case Human Review Dossier Generator
 * Generates an auditable dossier for an individual test case.
 */

export class DossierGenerator {
    constructor() {}

    generateDossier(bundleReader, caseId) {
        const cases = bundleReader.readJsonl('case_results.jsonl');
        const caseRecord = cases.find(c => c.case_id === caseId);

        if (!caseRecord) {
            throw new Error(`Case ${caseId} not found in bundle ${bundleReader.bundlePath}`);
        }

        const groundTruths = bundleReader.readJsonl('ground_truth.jsonl');
        const rawFindings = bundleReader.readJsonl('raw_findings.jsonl');
        const normalizedFindings = bundleReader.readJsonl('normalized_findings.jsonl');
        const candidates = bundleReader.readJsonl('candidates.jsonl');
        const transitions = bundleReader.readJsonl('classification_transitions.jsonl');
        const decisions = bundleReader.readJsonl('verifier_decisions.jsonl');
        const proofs = bundleReader.readJsonl('proof_artifacts.jsonl');

        const gt = groundTruths.find(g => g.case_id === caseId) || {};
        const caseCandidates = candidates.filter(c => c.case_id === caseId);
        const caseTransitions = transitions.filter(t => t.case_id === caseId);
        const caseDecisions = decisions.filter(d => d.case_id === caseId);
        const caseProofs = proofs.filter(p => p.case_id === caseId);

        const sourceFindingIds = caseRecord.source_finding_ids || [];
        const matchedRaw = rawFindings.filter(r => sourceFindingIds.includes(r.finding_id));
        const matchedNorm = normalizedFindings.filter(n => sourceFindingIds.includes(n.finding_id));

        const dossier = {
            case_identity: {
                case_id: caseId,
                benchmark_id: gt.benchmark_id || bundleReader.manifest.benchmark_id,
                source_file: gt.source_file || '',
                line_range: gt.line_range || [1, 1],
                cwe: gt.cwe || 'CWE-000'
            },
            ground_truth: {
                label: gt.ground_truth_label || 'UNKNOWN',
                source: gt.ground_truth_source || 'N/A',
                reference: gt.ground_truth_reference || 'N/A'
            },
            raw_findings: matchedRaw,
            normalized_findings: matchedNorm,
            candidate_hypotheses: caseCandidates,
            verifier_decisions: caseDecisions,
            classification_transitions: caseTransitions,
            proof_artifacts: caseProofs,
            final_result: {
                classification: caseRecord.classification,
                hwsec_final: caseRecord.hwsec_final,
                evidence_strength: caseRecord.evidence_strength,
                reproducible: caseRecord.reproducible,
                reclassification_taxonomy: caseRecord.reclassification_taxonomy
            }
        };

        const markdown = this._generateDossierMarkdown(dossier);
        return { dossier, markdown };
    }

    _generateDossierMarkdown(d) {
        let md = `# Audit Dossier: Case ${d.case_identity.case_id}\n\n`;
        md += `## 1. Case Identity & Ground Truth\n`;
        md += `- **Benchmark ID**: \`${d.case_identity.benchmark_id}\`\n`;
        md += `- **Source File**: \`${d.case_identity.source_file}\` (Lines ${d.case_identity.line_range.join('-')})\n`;
        md += `- **Target CWE**: \`${d.case_identity.cwe}\`\n`;
        md += `- **Ground Truth Label**: **${d.ground_truth.label}**\n\n`;

        md += `## 2. Final Classification\n`;
        md += `- **Classification**: **${d.final_result.classification}** (${d.final_result.hwsec_final})\n`;
        md += `- **Evidence Strength**: \`${d.final_result.evidence_strength}\`\n`;
        md += `- **Reproducible**: ${d.final_result.reproducible ? '✅ YES' : '❌ NO'}\n`;
        md += `- **Taxonomy**: \`${d.final_result.reclassification_taxonomy}\`\n\n`;

        md += `## 3. Raw Analyzer Findings (${d.raw_findings.length})\n`;
        for (const r of d.raw_findings) {
            md += `- [\`${r.analyzer}\`] Rule: \`${r.rule_id}\` (${r.severity}) - *${r.message}*\n`;
        }

        md += `\n## 4. Verifier Decisions (${d.verifier_decisions.length})\n`;
        for (const v of d.verifier_decisions) {
            md += `- Decision: **${v.decision}** (Confidence: ${(v.confidence * 100).toFixed(0)}%) via \`${v.model}\` [Basis: \`${v.evidence_basis}\`]\n`;
        }

        md += `\n## 5. Transition History (${d.classification_transitions.length})\n`;
        for (const t of d.classification_transitions) {
            md += `- \`${t.from_state}\` ──► \`${t.to_state}\` (${t.stage}: ${t.reason_code})\n`;
        }

        md += `\n## 6. Proof Artifacts (${d.proof_artifacts.length})\n`;
        for (const p of d.proof_artifacts) {
            md += `- Proof ID: \`${p.proof_id}\` | Verdict: **${p.verdict}** | Repetitions: ${p.repetition_count}\n`;
        }

        return md;
    }
}
