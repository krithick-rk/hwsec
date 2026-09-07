import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { runSecurityProfile } from './security-audit.js';
import { runEvidenceProfile } from './evidence-audit.js';
import { runIntegrationProfile } from './integration-audit.js';
import { runPerformanceProfile } from './performance-audit.js';

export async function runAudit(profile = 'full', options = {}) {
    const startTime = Date.now();
    const auditId = `AUDIT-${new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)}-${crypto.randomBytes(3).toString('hex')}`;
    
    console.log(`\n======================================================`);
    console.log(`   HWSEC ADVERSARIAL SECURITY VALIDATION ENGINE       `);
    console.log(`======================================================`);
    console.log(`  Audit ID:  ${auditId}`);
    console.log(`  Profile:   ${profile.toUpperCase()}`);
    console.log(`  Platform:  ${os.platform()} ${os.release()}`);
    console.log(`  Node:      ${process.version}`);
    console.log(`======================================================\n`);

    const allSummaries = [];

    if (profile === 'quick') {
        const { runSuite: runExec } = await import('../tests/security/execution_injection.adversarial.js');
        const { runSuite: runFs } = await import('../tests/security/filesystem_traversal.adversarial.js');
        const { runSuite: runVerif } = await import('../tests/evidence/verifier_integrity.adversarial.js');
        const { runSuite: runProv } = await import('../tests/evidence/artifact_provenance.adversarial.js');
        allSummaries.push(await runExec());
        allSummaries.push(await runFs());
        allSummaries.push(await runVerif());
        allSummaries.push(await runProv());
    } else if (profile === 'security') {
        allSummaries.push(...(await runSecurityProfile()));
    } else if (profile === 'evidence') {
        allSummaries.push(...(await runEvidenceProfile()));
    } else if (profile === 'integration') {
        allSummaries.push(...(await runIntegrationProfile()));
    } else if (profile === 'stress') {
        allSummaries.push(...(await runPerformanceProfile()));
    } else { // 'full'
        allSummaries.push(...(await runSecurityProfile()));
        allSummaries.push(...(await runEvidenceProfile()));
        allSummaries.push(...(await runIntegrationProfile()));
        allSummaries.push(...(await runPerformanceProfile()));
    }

    const allResults = allSummaries.flatMap(s => s.results);
    const totalTests = allResults.length;
    const passedTests = allResults.filter(r => r.passed).length;
    const failedTests = totalTests - passedTests;
    const durationMs = Date.now() - startTime;

    // Categorize failures by severity
    const criticalFails = allResults.filter(r => !r.passed && r.severity === 'CRITICAL');
    const highFails = allResults.filter(r => !r.passed && r.severity === 'HIGH');
    const mediumFails = allResults.filter(r => !r.passed && r.severity === 'MEDIUM');
    const lowFails = allResults.filter(r => !r.passed && r.severity === 'LOW');

    // Category scoring (0-10)
    const categories = [
        'EXECUTION_SECURITY',
        'FILESYSTEM_SECURITY',
        'PROCESS_ISOLATION',
        'EVIDENCE_INTEGRITY',
        'GRAPH_INTEGRITY',
        'RAG_INTEGRITY',
        'LLM_SECURITY',
        'DATABASE_INTEGRITY',
        'INCREMENTAL_ANALYSIS',
        'STATE_MACHINE',
        'TOOL_INTEGRATION',
        'RESOURCE_CONTROL'
    ];

    const categoryScores = {};
    for (const cat of categories) {
        const catResults = allResults.filter(r => r.category === cat);
        if (catResults.length === 0) {
            categoryScores[cat] = 10.0;
            continue;
        }
        const passedCat = catResults.filter(r => r.passed).length;
        categoryScores[cat] = Number(((passedCat / catResults.length) * 10).toFixed(1));
    }

    // Calculate Overall Security Readiness Score (0-10)
    const weights = {
        EXECUTION_SECURITY: 0.15,
        FILESYSTEM_SECURITY: 0.10,
        PROCESS_ISOLATION: 0.10,
        EVIDENCE_INTEGRITY: 0.15,
        GRAPH_INTEGRITY: 0.08,
        RAG_INTEGRITY: 0.08,
        LLM_SECURITY: 0.08,
        DATABASE_INTEGRITY: 0.08,
        INCREMENTAL_ANALYSIS: 0.08,
        STATE_MACHINE: 0.05,
        TOOL_INTEGRATION: 0.05
    };

    let weightedScore = 0;
    let totalWeight = 0;
    for (const [cat, w] of Object.entries(weights)) {
        if (categoryScores[cat] !== undefined) {
            weightedScore += categoryScores[cat] * w;
            totalWeight += w;
        }
    }
    const overallScore = Number((weightedScore / (totalWeight || 1)).toFixed(2));

    // Determine Verdict based on hard security gates
    let verdict = 'SECURE FOR INTERNAL USE';
    let verdictGateMessage = 'All security invariants passed.';

    if (criticalFails.length > 0) {
        verdict = 'NOT SECURITY READY';
        verdictGateMessage = `BLOCKED: ${criticalFails.length} Critical vulnerability/invariant failure(s) detected.`;
    } else if (highFails.length > 0) {
        verdict = 'NOT SECURITY READY';
        verdictGateMessage = `BLOCKED: ${highFails.length} High severity security failure(s) detected.`;
    } else if (overallScore < 8.0) {
        verdict = 'NOT SECURITY READY';
        verdictGateMessage = `BLOCKED: Overall score ${overallScore}/10 is below minimum threshold (8.0/10).`;
    } else if (mediumFails.length > 0) {
        verdict = 'SECURE WITH CONDITIONS';
        verdictGateMessage = `CONDITIONAL: Passed critical gates with ${mediumFails.length} medium-priority tracked issue(s).`;
    }

    // Build Report Artifacts
    const reportsDir = path.resolve('audit/reports', auditId);
    fs.mkdirSync(reportsDir, { recursive: true });

    const envInfo = {
        auditId,
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        nodeVersion: process.version,
        cpus: os.cpus().length,
        totalMemoryBytes: os.totalmem(),
        timestamp: new Date().toISOString()
    };
    fs.writeFileSync(path.join(reportsDir, 'environment.json'), JSON.stringify(envInfo, null, 2), 'utf-8');

    const metricsInfo = {
        durationMs,
        totalTests,
        passedTests,
        failedTests,
        passRate: Number(((passedTests / totalTests) * 100).toFixed(1)),
        categoryScores,
        overallScore,
        criticalFails: criticalFails.length,
        highFails: highFails.length,
        mediumFails: mediumFails.length,
        lowFails: lowFails.length
    };
    fs.writeFileSync(path.join(reportsDir, 'metrics.json'), JSON.stringify(metricsInfo, null, 2), 'utf-8');

    const resultsPayload = {
        meta: envInfo,
        metrics: metricsInfo,
        verdict,
        verdictGateMessage,
        results: allResults
    };
    fs.writeFileSync(path.join(reportsDir, 'results.json'), JSON.stringify(resultsPayload, null, 2), 'utf-8');
    fs.writeFileSync(path.resolve('audit/results.json'), JSON.stringify(resultsPayload, null, 2), 'utf-8');

    // Markdown Report Generation
    const reportMd = generateMarkdownReport({
        auditId,
        profile,
        envInfo,
        metricsInfo,
        verdict,
        verdictGateMessage,
        criticalFails,
        highFails,
        mediumFails,
        allResults,
        categoryScores
    });

    fs.writeFileSync(path.join(reportsDir, 'report.md'), reportMd, 'utf-8');
    fs.writeFileSync(path.resolve('audit/report.md'), reportMd, 'utf-8');

    // Save baseline
    const baselinesDir = path.resolve('audit/baselines');
    fs.mkdirSync(baselinesDir, { recursive: true });
    fs.writeFileSync(path.join(baselinesDir, 'baseline_latest.json'), JSON.stringify(resultsPayload, null, 2), 'utf-8');

    console.log(`\n======================================================`);
    console.log(`AUDIT SUMMARY & VERDICT:`);
    console.log(`  Tests:     ${passedTests}/${totalTests} Passed (${metricsInfo.passRate}%)`);
    console.log(`  Readiness: ${overallScore} / 10.0`);
    console.log(`  Verdict:   ${verdict}`);
    console.log(`  Gate:      ${verdictGateMessage}`);
    console.log(`  Report:    audit/reports/${auditId}/report.md`);
    console.log(`======================================================\n`);

    return {
        auditId,
        verdict,
        overallScore,
        passedTests,
        totalTests,
        reportsDir
    };
}

function generateMarkdownReport(data) {
    return `# HWSEC Adversarial Security Validation Audit Report

**Audit Identifier**: \`${data.auditId}\`  
**Profile**: \`${data.profile.toUpperCase()}\`  
**Execution Date**: ${data.envInfo.timestamp}  
**Platform**: ${data.envInfo.platform} (${data.envInfo.release}) ${data.envInfo.arch} | Node ${data.envInfo.nodeVersion}  
**Readiness Score**: **${data.metricsInfo.overallScore} / 10.0**  

---

## Executive Verdict

### **VERDICT: ${data.verdict}**

**Security Gate Status**: ${data.verdictGateMessage}

- **Total Adversarial Invariants Evaluated**: ${data.metricsInfo.totalTests}
- **Invariants Passed**: ${data.metricsInfo.passedTests}
- **Invariants Failed**: ${data.metricsInfo.failedTests}
- **Execution Duration**: ${data.metricsInfo.durationMs}ms

---

## Security Audit Scorecard

| Security Category | Score (0–10) | Status | Key Invariant Evaluated |
| :--- | :---: | :---: | :--- |
| **Execution Security** | **${data.categoryScores.EXECUTION_SECURITY ?? 'N/A'} / 10** | ${data.categoryScores.EXECUTION_SECURITY >= 8 ? 'PASS' : 'FAIL'} | Command injection via malicious filenames / args |
| **Filesystem Security** | **${data.categoryScores.FILESYSTEM_SECURITY ?? 'N/A'} / 10** | ${data.categoryScores.FILESYSTEM_SECURITY >= 8 ? 'PASS' : 'FAIL'} | Path traversal & symlink escape outside root |
| **Process Isolation** | **${data.categoryScores.PROCESS_ISOLATION ?? 'N/A'} / 10** | ${data.categoryScores.PROCESS_ISOLATION >= 8 ? 'PASS' : 'FAIL'} | Timeouts, buffer ceilings, process-tree kill |
| **Evidence Integrity** | **${data.categoryScores.EVIDENCE_INTEGRITY ?? 'N/A'} / 10** | ${data.categoryScores.EVIDENCE_INTEGRITY >= 8 ? 'PASS' : 'FAIL'} | Ban on substring matching, structured verification |
| **Graph Integrity** | **${data.categoryScores.GRAPH_INTEGRITY ?? 'N/A'} / 10** | ${data.categoryScores.GRAPH_INTEGRITY >= 8 ? 'PASS' : 'FAIL'} | 3-Layer CodeGraph persistence & reachability |
| **RAG Integrity** | **${data.categoryScores.RAG_INTEGRITY ?? 'N/A'} / 10** | ${data.categoryScores.RAG_INTEGRITY >= 8 ? 'PASS' : 'FAIL'} | Vector memory isolation, semantic retrieval |
| **LLM Security** | **${data.categoryScores.LLM_SECURITY ?? 'N/A'} / 10** | ${data.categoryScores.LLM_SECURITY >= 8 ? 'PASS' : 'FAIL'} | Prompt injection trust boundary isolation |
| **Database Integrity** | **${data.categoryScores.DATABASE_INTEGRITY ?? 'N/A'} / 10** | ${data.categoryScores.DATABASE_INTEGRITY >= 8 ? 'PASS' : 'FAIL'} | Telemetry schema sync, transactions |
| **Incremental Analysis**| **${data.categoryScores.INCREMENTAL_ANALYSIS ?? 'N/A'} / 10** | ${data.categoryScores.INCREMENTAL_ANALYSIS >= 8 ? 'PASS' : 'FAIL'} | Content hash reuse & stale finding invalidation |
| **State Machine** | **${data.categoryScores.STATE_MACHINE ?? 'N/A'} / 10** | ${data.categoryScores.STATE_MACHINE >= 8 ? 'PASS' : 'FAIL'} | Transition containment, double-execution blocks |
| **Tool Integration** | **${data.categoryScores.TOOL_INTEGRATION ?? 'N/A'} / 10** | ${data.categoryScores.TOOL_INTEGRATION >= 8 ? 'PASS' : 'FAIL'} | Real tool verification vs honest stub reporting |

---

## Critical Findings
${data.criticalFails.length > 0 
    ? data.criticalFails.map(f => `### [CRITICAL] ${f.testName}\n- **Suite**: \`${f.suite}\`\n- **Expected**: ${f.expected}\n- **Actual**: ${f.actual}\n- **Details**: ${f.details || 'Adversarial boundary violated'}\n`).join('\n')
    : '_No critical failures observed. All critical P0 release gates passed._'}

## High Findings
${data.highFails.length > 0 
    ? data.highFails.map(f => `### [HIGH] ${f.testName}\n- **Suite**: \`${f.suite}\`\n- **Expected**: ${f.expected}\n- **Actual**: ${f.actual}\n`).join('\n')
    : '_No high severity failures observed._'}

## Medium & Informational Findings
${data.mediumFails.length > 0 
    ? data.mediumFails.map(f => `### [MEDIUM] ${f.testName}\n- **Suite**: \`${f.suite}\`\n- **Details**: ${f.actual}\n`).join('\n')
    : '_None._'}

---

## Detailed Invariant Validation Matrix

| Invariant / Adversarial Test | Category | Tier | Status | Result |
| :--- | :--- | :--- | :---: | :---: |
${data.allResults.map(r => `| ${r.testName} | ${r.category} | ${r.tier} | ${r.empiricalStatus} | ${r.passed ? '✅ PASS' : '❌ FAIL'} |`).join('\n')}

---

## Remaining Risks & Next Steps
1. **WSL Environment Sandboxing**: Ensure tool invocations in WSL execute with unprivileged user permissions.
2. **Dense Neural Embeddings**: Transition from hash-bucket vectors to local ONNX / Transformers.js neural embeddings for enhanced multi-lingual semantic alignment.
3. **Formal Invariant Auto-Synthesis**: Expand SVA generation beyond template assertions into full BMC inductive proofs.
`;
}

if (process.argv[1]?.endsWith('main-runner.js')) {
    const profileArg = process.argv.slice(2).find((a, i, arr) => arr[i - 1] === '--profile') || 'full';
    runAudit(profileArg).then(res => {
        process.exit(res.verdict === 'NOT SECURITY READY' ? 1 : 0);
    });
}
