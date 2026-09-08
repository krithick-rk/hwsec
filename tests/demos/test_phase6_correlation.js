// Phase 6 standalone test — runs with NO LLM calls
// Loads real findings from the last successful analysis and runs the correlation engine

import { EvidenceCorrelationEngine } from './src/workers/evidenceCorrelation.js';
import fs from 'fs';
import path from 'path';

const BASE = 'hwsec-output/20260901103417-ab15fdd3';

function load(rel) {
    const full = path.join(BASE, rel);
    return fs.existsSync(full) ? JSON.parse(fs.readFileSync(full, 'utf-8')) : [];
}

const lintFindings    = load('findings/linting.json');
const formalFindings  = load('findings/formal.json');
const specFindings    = load('findings/spec_divergence.json');
const interpFindings  = load('findings/llm_interpreted.json');

const allFindings = [...lintFindings, ...formalFindings, ...specFindings, ...interpFindings];
const hypotheses  = load('hypotheses/hypotheses.json');

console.log(`[*] Loaded ${allFindings.length} findings from ${BASE}`);
console.log(`    Linting: ${lintFindings.length}, Formal: ${formalFindings.length}, SpecDiv: ${specFindings.length}, LLM-Interp: ${interpFindings.length}`);

// Run Phase 6 with no LLM (pass null)
const engine = new EvidenceCorrelationEngine(null);
const result = await engine.correlate(allFindings, hypotheses, {});

console.log('\n' + result.summary);

// Save artifacts
fs.mkdirSync(`${BASE}/report`, { recursive: true });
fs.writeFileSync(`${BASE}/report/evidence_graph.json`, JSON.stringify(result.graph, null, 2));
fs.writeFileSync(`${BASE}/report/correlated_clusters.json`, JSON.stringify(result.correlatedClusters, null, 2));
fs.writeFileSync(`${BASE}/report/attack_paths.json`, JSON.stringify(result.attackPaths, null, 2));

const correlationMd = `# Phase 6: Evidence Correlation & Attack-Path Report\n\n` +
    `\`\`\`\n${result.summary}\n\`\`\`\n\n` +
    `## Evidence Clusters\n` +
    result.correlatedClusters.map(c =>
        `### Cluster ${c.cluster_id}\n- **Location**: \`${c.location}\`\n- **Severity**: ${c.severity}\n- **Confidence**: ${(c.confidence * 100).toFixed(0)}%\n- **Join Type**: ${c.relationship}\n- **Findings**: ${c.titles.join(', ')}\n`
    ).join('\n') +
    `\n## Attack Paths\n` +
    (result.attackPaths.length > 0
        ? result.attackPaths.map(p => `### ${p.path_id}: ${p.title}\n- **Evidence Strength**: ${p.evidence_strength}\n- ${p.description}\n`).join('\n')
        : '_No multi-evidence attack paths identified._');

fs.writeFileSync(`${BASE}/report/correlation.md`, correlationMd);

console.log(`\n[+] Phase 6 artifacts written to ${BASE}/report/`);
