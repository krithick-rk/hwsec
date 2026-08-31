#!/usr/bin/env node

import { Command } from 'commander';
import path from 'path';
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
  .action((rtlDirectory, options) => {
    console.log(`[*] Planning analysis for ${rtlDirectory}...`);
    
    const configPath = path.resolve(options.config);
    const config = loadConfig(configPath);
    
    const workspace = new Workspace('hwsec-output');
    const planner = new Planner(rtlDirectory, config);
    
    try {
        planner.plan(workspace);
        
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
  .action((analysisId) => {
    console.log(`[*] Starting execution for analysis ${analysisId}...`);
    // Phase 1 implementation stub
    console.log(`[+] Execution finished (Stub for Phase 1). Check hwsec-output/${analysisId}/status.md for updates.`);
  });

program.command('status')
  .description('Check the status of an analysis')
  .argument('<analysis-id>', 'ID of the analysis')
  .action((analysisId) => {
    console.log(`[*] Fetching status for analysis ${analysisId}...`);
    // Stub
  });

program.parse(process.argv);
