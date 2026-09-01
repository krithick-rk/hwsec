#!/usr/bin/env node

import { Command } from 'commander';
import path from 'path';
import fs from 'fs';
import { loadConfig } from './core/config.js';
import { Workspace } from './core/workspace.js';
import { Planner } from './core/planner.js';

const program = new Command();

program
  .name('hwsec')
  .description('HWSEC - Autonomous Hardware/RTL Security Analysis Framework')
  .version('0.1.0');

program.command('analyze')
  .description('Plan analysis for an RTL directory without executing')
  .argument('<rtl-directory>', 'Directory containing RTL files')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-s, --spec <path>', 'Path to markdown specification for Phase 4 Differential Testing')
  .action(async (rtlDirectory, options) => {
    console.log(`[*] Planning analysis for ${rtlDirectory}...`);
    
    const configPath = path.resolve(options.config);
    const config = loadConfig(configPath);
    
    const workspace = new Workspace('hwsec-output');
    const planner = new Planner(rtlDirectory, config, options.spec ? path.resolve(options.spec) : null);
    
    try {
        await planner.plan(workspace);
        
        console.log(`[+] Planning complete! Analysis ID: ${workspace.analysisId}`);
        console.log(`[!] Analysis has NOT started. Review the plan and approve execution.`);
        console.log(`[*] Run \`hwsec proceed ${workspace.analysisId}\` to begin.`);
    } catch (e) {
        console.error(`[-] Planning failed: ${e.message}`);
    }
  });

program.command('proceed')
  .description('Execute an approved analysis plan')
  .argument('<analysis-id>', 'ID of the analysis to execute')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .action(async (analysisId, options) => {
    console.log(`[*] Starting execution for analysis ${analysisId}...`);
    
    try {
        const configPath = path.resolve(options.config);
        const config = loadConfig(configPath);
        
        const workspace = Workspace.load('hwsec-output', analysisId);
        const analysis = workspace.loadJson('analysis.json');
        
        if (!analysis) {
            console.error(`[-] Analysis ${analysisId} does not exist.`);
            process.exit(1);
        }
        
        analysis.status = 'EXECUTING';
        workspace.saveJson('analysis.json', analysis);
        workspace.saveMarkdown('status.md', '# Status\n\nExecuting...\n');
        
        const rtlFiles = analysis.inventory.files;
        
        if (analysis.execution_graph.includes("linting")) {
            console.log(`[*] Running Verilator linting...`);
            const { VerilatorTool } = await import('./tools/verilator.js');
            const verilator = new VerilatorTool(config);
            const check = await verilator.checkInstalled();
            
            if (!check.installed) {
                console.error(`[-] Verilator is not installed or accessible: ${check.error}`);
            } else {
                const result = await verilator.run(rtlFiles, path.join(workspace.outputDir, 'tools'));
                workspace.saveJson('findings/linting.json', result.findings);
                console.log(`[+] Verilator finished with status: ${result.status}. Found ${result.findings.length} findings.`);
            }
        }

        if (analysis.execution_graph.includes("formal")) {
            console.log(`[*] Running Yosys formal/synthesis check...`);
            const { YosysTool } = await import('./tools/yosys.js');
            const yosys = new YosysTool(config);
            const check = await yosys.checkInstalled();
            
            if (!check.installed) {
                console.error(`[-] Yosys is not installed or accessible: ${check.error}`);
            } else {
                const result = await yosys.run(rtlFiles, path.join(workspace.outputDir, 'tools'));
                workspace.saveJson('findings/formal.json', result.findings);
                console.log(`[+] Yosys finished with status: ${result.status}. Found ${result.findings.length} findings.`);
            }
        }

        if (analysis.execution_graph.includes("fuzzing")) {
            console.log(`[*] Running AFL++ check via WSL...`);
            const { AflTool } = await import('./tools/afl.js');
            const afl = new AflTool(config);
            const check = await afl.checkInstalled();
            
            if (!check.installed) {
                console.error(`[-] AFL++ is not installed or accessible: ${check.error}`);
            } else {
                const aflOptions = { timeout: 5 };
                if (analysis.refined) {
                    aflOptions.dict_path = analysis.dict_path;
                    aflOptions.timeout = 20; // Escalate timeout on refinement!
                }
                const result = await afl.run(rtlFiles, path.join(workspace.outputDir, 'tools'), aflOptions);
                workspace.saveJson('findings/fuzzing.json', result.findings);
                console.log(`[+] AFL++ finished with status: ${result.status}. Found ${result.findings.length} findings.`);
            }
        }

        // Phase 2: Single-Purpose LLM Worker Interpreter
        const { LLMClient } = await import('./core/llmClient.js');
        const llmClient = new LLMClient(config);
        
        if (llmClient.isAvailable()) {
            console.log(`[*] [Phase 2] Running Single-Purpose LLM Worker Interpreter...`);
            const { ToolOutputInterpreterWorker } = await import('./workers/interpreter.js');
            const interpreter = new ToolOutputInterpreterWorker(llmClient);
            
            const allInterpretedFindings = [];
            const allAuditLogs = [];

            // Interpret Verilator telemetry
            const verilatorTelemetry = workspace.loadJson('tools/verilator_telemetry.json');
            if (verilatorTelemetry) {
                const res = await interpreter.interpret('verilator', verilatorTelemetry, 'tools/verilator_telemetry.json');
                allInterpretedFindings.push(...res.findings);
                allAuditLogs.push(...res.auditLog);
            }

            // Interpret Yosys telemetry
            const yosysTelemetry = workspace.loadJson('tools/yosys_telemetry.json');
            if (yosysTelemetry) {
                const res = await interpreter.interpret('yosys', yosysTelemetry, 'tools/yosys_telemetry.json');
                allInterpretedFindings.push(...res.findings);
                allAuditLogs.push(...res.auditLog);
            }

            workspace.saveJson('findings/llm_interpreted.json', allInterpretedFindings);
            workspace.saveMarkdown('logs/interpreter_audit.log', allAuditLogs.join('\n') + '\n');
            console.log(`[+] [Phase 2] Interpreter completed. Generated ${allInterpretedFindings.length} grounded findings (Audit logged).`);

            // Phase 4: Specification Divergence & Differential Engine
            let specFindings = [];
            const specClauses = workspace.loadJson('inventory/spec_clauses.json');
            if (specClauses && specClauses.length > 0) {
                console.log(`[*] [Phase 4] Running Specification Divergence & Differential Analyzer...`);
                const { SpecDivergenceAnalyzer } = await import('./workers/specDivergence.js');
                const specAnalyzer = new SpecDivergenceAnalyzer(llmClient);
                const specRes = await specAnalyzer.analyze(rtlFiles, specClauses, path.join(workspace.outputDir, 'tools'));
                specFindings = specRes.divergenceFindings;
                workspace.saveJson('findings/spec_divergence.json', specFindings);
                console.log(`[+] [Phase 4] Spec Divergence completed. Found ${specFindings.length} specification divergence violation(s).`);
            }

            // Phase 3: Artifact-Gated Verification Engine
            console.log(`[*] [Phase 3] Running Artifact-Gated Verifier...`);
            const { ArtifactGatedVerifier } = await import('./workers/verifier.js');
            const verifier = new ArtifactGatedVerifier(llmClient);
            
            const hypotheses = workspace.loadJson('hypotheses/hypotheses.json') || [];
            const lintFindings = workspace.loadJson('findings/linting.json') || [];
            const formalFindings = workspace.loadJson('findings/formal.json') || [];
            const allFindings = [...lintFindings, ...formalFindings, ...allInterpretedFindings, ...specFindings];

            const telemetries = {
                verilator: verilatorTelemetry,
                yosys: yosysTelemetry
            };

            const verificationResult = await verifier.verify(hypotheses, allFindings, telemetries);
            workspace.saveJson('findings/verified_findings.json', verificationResult.verifiedFindings);
            workspace.saveMarkdown('report/report.md', verificationResult.reportMarkdown);
            console.log(`[+] [Phase 3] Verification completed. Verified findings: ${verificationResult.verifiedFindings.length}. Report written to report/report.md.`);

            // Phase 6: Correlation + Evidence Graph
            console.log(`[*] [Phase 6] Running Cross-Tool Evidence Correlation & Attack-Path Engine...`);
            const { EvidenceCorrelationEngine } = await import('./workers/evidenceCorrelation.js');
            const correlator = new EvidenceCorrelationEngine(llmClient);
            const correlationResult = await correlator.correlate(allFindings, hypotheses, telemetries);
            
            workspace.saveJson('report/evidence_graph.json', correlationResult.graph);
            workspace.saveJson('report/correlated_clusters.json', correlationResult.correlatedClusters);
            workspace.saveJson('report/attack_paths.json', correlationResult.attackPaths);
            workspace.saveMarkdown('report/correlation.md', 
                `# Phase 6: Evidence Correlation & Attack-Path Report\n\n` +
                `\`\`\`\n${correlationResult.summary}\n\`\`\`\n\n` +
                `## Evidence Clusters\n` +
                correlationResult.correlatedClusters.map(c =>
                    `### Cluster ${c.cluster_id}\n- **Location**: \`${c.location}\`\n- **Severity**: ${c.severity}\n- **Confidence**: ${(c.confidence * 100).toFixed(0)}%\n- **Join Type**: ${c.relationship}\n- **Findings**: ${c.titles.join(', ')}\n`
                ).join('\n') +
                `\n## Attack Paths\n` +
                (correlationResult.attackPaths.length > 0 
                    ? correlationResult.attackPaths.map(p => `### ${p.path_id}: ${p.title}\n- **Evidence Strength**: ${p.evidence_strength}\n- ${p.description}\n`).join('\n')
                    : '_No multi-evidence attack paths identified._')
            );
            console.log(`[+] [Phase 6] Correlation completed. Clusters: ${correlationResult.correlatedClusters.length}, Attack paths: ${correlationResult.attackPaths.length}. Report written to report/correlation.md.`);
        }
        
        analysis.status = 'COMPLETED';
        workspace.saveJson('analysis.json', analysis);
        workspace.saveMarkdown('status.md', '# Status\n\nExecution COMPLETED.\n');
        console.log(`[+] Execution finished. Check hwsec-output/${analysisId}/status.md for updates.`);
        
    } catch (e) {
        console.error(`[-] Execution failed: ${e.message}`);
    }
  });

program.command('refine')
  .description('Phase 5: Refine analysis (generate fuzzer dictionaries for refuted hypotheses)')
  .argument('<analysis-id>', 'ID of the analysis to refine')
  .option('-c, --config <path>', 'Path to config file', 'config.json')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action(async (analysisId, options) => {
    try {
        const configPath = path.resolve(options.config);
        const config = loadConfig(configPath);
        const workspace = Workspace.load(options.outputDir, analysisId);
        
        const analysis = workspace.loadJson('analysis.json');
        if (!analysis) {
            console.error(`[-] Analysis ${analysisId} not found.`);
            return;
        }

        const hypotheses = workspace.loadJson('hypotheses/hypotheses.json') || [];
        const verified = workspace.loadJson('findings/verified_findings.json') || [];
        // Treat hypotheses as refuted if they are not in the verified list
        const verifiedIds = verified.map(v => v.hypothesis_id);
        const refuted = hypotheses.filter(h => !verifiedIds.includes(h.hypothesis_id));

        if (refuted.length === 0) {
            console.log(`[*] No refuted hypotheses to refine. All were verified!`);
            return;
        }

        console.log(`[*] [Phase 5] Found ${refuted.length} refuted hypotheses. Initiating Refinement Loop...`);
        
        const { LLMClient } = await import('./core/llmClient.js');
        const { RefinerWorker } = await import('./workers/refiner.js');
        
        const llmClient = new LLMClient(config);
        const refiner = new RefinerWorker(llmClient);

        const rtlFiles = analysis.inventory.files;
        console.log(`[*] Generating fuzzer dictionary from RTL magic constants...`);
        const result = await refiner.generateFuzzerDictionary(rtlFiles, refuted);

        const dictPath = path.join(workspace.outputDir, 'tools', 'fuzz_dict.txt');
        fs.writeFileSync(dictPath, result.dictionary_content, 'utf-8');
        
        // Update analysis state to indicate refinement occurred
        analysis.refined = true;
        analysis.dict_path = dictPath;
        workspace.saveJson('analysis.json', analysis);
        
        console.log(`[+] Dictionary generated at ${dictPath}`);
        console.log(`[+] Rationale: ${result.rationale}`);
        console.log(`[*] The fuzzing step in 'proceed' will now automatically use this dictionary.`);
        console.log(`[*] Run \`hwsec proceed ${analysisId}\` again to execute the refined fuzzing loop.`);
    } catch (e) {
        console.error(`[-] Refinement failed: ${e.message}`);
    }
  });

program.command('status')
  .description('Check the status of an analysis')
  .argument('<analysis-id>', 'ID of the analysis')
  .option('-o, --output-dir <path>', 'Base output directory', 'hwsec-output')
  .action((analysisId, options) => {
    try {
      const workspace = Workspace.load(options.outputDir, analysisId);
      const analysis = workspace.loadJson('analysis.json');
      if (analysis) {
        console.log(`[*] Analysis ID:  ${analysis.analysis_id}`);
        console.log(`[*] Status:       ${analysis.status}`);
        console.log(`[*] Files Found:  ${analysis.inventory?.files?.length ?? 0}`);
        console.log(`[*] Tools Found:  ${analysis.tools_detected?.join(', ') || 'none'}`);
        console.log(`[*] Plan Steps:   ${analysis.execution_graph?.join(' -> ') || 'none'}`);
      } else {
        console.log(`[!] No analysis metadata found for ID: ${analysisId}`);
      }
    } catch (e) {
      console.error(`[-] Failed to retrieve status: ${e.message}`);
    }
  });

program.parse(process.argv);
