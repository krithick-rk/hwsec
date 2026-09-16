import readline from 'readline';
import path from 'path';
import fs from 'fs';
import { ConsoleParser } from './consoleParser.js';
import { SessionManager, SessionPhase } from './consoleSession.js';
import { ConsoleInspectors } from './inspectors.js';
import { DiagnosticsFacade } from './diagnostics.js';
import { formatModules } from './moduleRegistry.js';
import { Planner } from '../planner.js';
import { Workspace } from '../workspace.js';
import { loadConfig } from '../config.js';
import { runAnalysisPipeline } from '../pipelineRunner.js';
import { AnalysisBroker, BrokerCapability } from '../broker.js';
import { EntryPointInventory } from '../inventory/entryPointInventory.js';

export class ConsoleApp {
    /**
     * @param {Object} [options={}]
     */
    constructor(options = {}) {
        this.options = options;
        this.configPath = path.resolve(options.config || 'config.json');
        this.config = loadConfig(this.configPath);
        this.sessionManager = new SessionManager({ dbPath: path.join(options.outputDir || 'hwsec-output', 'hwsec.db') });
        this.session = this.sessionManager.getActiveSession();
        this.diagnostics = new DiagnosticsFacade(this.config);
        this.workspace = null;
        this.rl = null;
        this.activeTask = null;
        this.running = false;
    }

    /**
     * Helper to prompt operator for text input.
     * @param {string} query 
     * @returns {Promise<string>}
     */
    async ask(query) {
        return new Promise((resolve) => {
            if (!this.rl) {
                resolve('');
                return;
            }
            this.rl.question(query, (ans) => {
                resolve(ans.trim());
            });
        });
    }

    /**
     * Prompt operator for sensitive text input without displaying cleartext secrets.
     * @param {string} query 
     * @returns {Promise<string>}
     */
    async askMasked(query) {
        return new Promise((resolve) => {
            if (!this.rl) {
                resolve('');
                return;
            }
            const rl = this.rl;
            const oldWrite = rl._writeToOutput;
            rl._writeToOutput = function stringToWrite(str) {
                if (rl.line && rl.line.length > 0) {
                    rl.output.write('\x1B[2K\x1B[200D' + query + '********');
                } else {
                    oldWrite.call(rl, str);
                }
            };
            rl.question(query, (ans) => {
                rl._writeToOutput = oldWrite;
                console.log();
                resolve(ans.trim());
            });
        });
    }

    /**
     * Interactive provider configuration wizard.
     */
    async runProviderSetupWizard() {
        console.log('\n[ Gemini ]');
        const numGemini = await this.ask('How many Gemini keys/accounts? [1-3, 0 to skip]:\n> ');
        const count = parseInt(numGemini, 10);
        if (!isNaN(count) && count > 0) {
            for (let i = 1; i <= Math.min(count, 3); i++) {
                const key = await this.askMasked(`Gemini API Key #${i}:\n> `);
                if (key) {
                    this.diagnostics.pool.updateKey(`gemini_${i}`, key);
                }
            }
        }

        console.log('\n[ NVIDIA NIM ]');
        const configNvidia = await this.ask('Configure NVIDIA API key? [Y/n]:\n> ');
        if (configNvidia.toLowerCase() !== 'n') {
            const key = await this.askMasked('NVIDIA API Key:\n> ');
            if (key) {
                this.diagnostics.pool.updateKey('nvidia', key);
            }
        }

        console.log('\n[ OpenRouter ]');
        const configOpenRouter = await this.ask('Configure OpenRouter API key? [Y/n]:\n> ');
        if (configOpenRouter.toLowerCase() !== 'n') {
            const key = await this.askMasked('OpenRouter API Key:\n> ');
            if (key) {
                this.diagnostics.pool.updateKey('openrouter', key);
            }
        }

        const runChecks = await this.ask('\nRun provider health checks? [Y/n]:\n> ');
        if (runChecks.toLowerCase() !== 'n') {
            console.log();
            const pool = this.diagnostics.pool;
            const endpoints = [
                { alias: 'gemini-1', name: 'Gemini #1' },
                { alias: 'gemini-2', name: 'Gemini #2' },
                { alias: 'gemini-3', name: 'Gemini #3' },
                { alias: 'nvidia', name: 'NVIDIA' },
                { alias: 'openrouter', name: 'OpenRouter' }
            ];
            for (const ep of endpoints) {
                const res = await pool.testEndpoint(ep.alias);
                const statusStr = res.healthy ? 'HEALTHY' : (res.state || 'UNAVAILABLE');
                console.log(`${ep.name} ${statusStr}`);
            }
        }
        console.log('\nConfiguration complete.');
    }

    /**
     * Renders Metasploit-style launch banner and runs onboarding if required.
     */
    async runOnboarding() {
        console.log(ConsoleInspectors.formatBanner());
        const ready = await this.diagnostics.checkStartupReadiness();
        console.log(ConsoleInspectors.formatStartupSummary(ready));
        console.log();

        if (this.options.skipOnboarding || this.session.targetDir) {
            return;
        }

        await this.runSessionSetupMenu();
    }

    /**
     * Renders guided session setup menu (Section 4).
     */
    async runSessionSetupMenu() {
        while (this.running) {
            console.log('HWSEC SESSION SETUP');
            console.log('-------------------');
            console.log('1. Target / scope');
            console.log('2. Context / requirements');
            console.log('3. Analysis mode');
            console.log('4. LLM / provider configuration');
            console.log('5. PoV policy');
            console.log('6. Execution policy');
            console.log('7. Budget');
            console.log('8. Tool status');
            console.log('9. Start with defaults');
            console.log('0. Exit setup\n');

            const choice = await this.ask('Select option [9]:\n> ');
            const selected = choice || '9';

            if (['0', 'exit', 'quit', 'back', 'q'].includes(selected.toLowerCase())) {
                console.log('[*] Exiting session setup.');
                break;
            }

            if (selected === '9') {
                console.log('[+] Starting session with default configuration.');
                break;
            }

            switch (selected) {
                case '1': {
                    const target = await this.ask('Target source directory:\n> ');
                    if (target) {
                        this.applySetOption('target', target);
                    }
                    break;
                }
                case '2': {
                    const ctx = await this.ask('Context directory (optional, leave blank to skip):\n> ');
                    if (ctx) {
                        this.applySetOption('context', ctx);
                    }
                    const req = await this.ask('Requirements file (optional, leave blank to skip):\n> ');
                    if (req) {
                        this.applySetOption('requirements', req);
                    }
                    break;
                }
                case '3': {
                    console.log('\nAnalysis modes: FAST, STANDARD, DEEP, FORENSIC');
                    const mode = await this.ask(`Select analysis mode [${this.session.mode}]:\n> `);
                    if (mode) {
                        this.applySetOption('mode', mode);
                    }
                    break;
                }
                case '4': {
                    console.log('\nLLM strategies: OFF, SCOUT, SCOUT+CRITIC, ADAPTIVE, FULL');
                    const strat = await this.ask(`Select strategy [${this.session.llmStrategy}]:\n> `);
                    if (strat) {
                        this.applySetOption('llm', strat);
                    }
                    const cfg = await this.ask('Configure provider API keys now? [y/N]:\n> ');
                    if (cfg.toLowerCase() === 'y' || cfg.toLowerCase() === 'yes') {
                        await this.handleProvidersConfigureMenu();
                    }
                    break;
                }
                case '5': {
                    console.log('\nPoV policies: ON-DETECTED, ALWAYS, NEVER');
                    const pov = await this.ask(`Select PoV policy [${this.session.povMode}]:\n> `);
                    if (pov) {
                        this.applySetOption('pov', pov);
                    }
                    break;
                }
                case '6': {
                    console.log('\nExecution approval policies: REQUIRED, OPTIONAL');
                    const app = await this.ask(`Select approval policy [${this.session.approvalPolicy}]:\n> `);
                    if (app) {
                        this.applySetOption('approval', app);
                    }
                    break;
                }
                case '7': {
                    const budget = await this.ask(`Budget in USD [${this.session.budget}]:\n> `);
                    if (budget) {
                        this.applySetOption('budget', budget);
                    }
                    break;
                }
                case '8': {
                    const status = await this.diagnostics.getToolchainStatus();
                    console.log('\n' + ConsoleInspectors.formatToolsStatus(status) + '\n');
                    break;
                }
                default:
                    console.log(`[-] Invalid option '${selected}'. Select 1-9 or 0.`);
                    break;
            }
            console.log();
        }
    }

    /**
     * Applies a configuration option with validation and immediate user feedback.
     * @param {string} optKey 
     * @param {string} optVal 
     */
    applySetOption(optKey, optVal) {
        try {
            this.session.set(optKey, optVal);
            const normKey = optKey.toLowerCase();
            if (normKey.startsWith('tool.') && normKey.endsWith('.path')) {
                const toolName = normKey.split('.')[1];
                this.config.tool_paths = this.config.tool_paths || {};
                this.config.tool_paths[toolName] = optVal;
            } else if (normKey === 'oss_cad_suite') {
                process.env.OSS_CAD_SUITE = optVal;
                process.env.YOSYSHQ_ROOT = optVal;
            }
            this.sessionManager.persistActiveSession();
            console.log(`[+] ${optKey} => ${optVal}`);
        } catch (err) {
            console.log(`[-] ${err.message}`);
        }
    }

    /**
     * Renders numbered settings menu (Section 6).
     */
    async renderSettingsMenu() {
        console.log('SETTINGS');
        console.log('--------');
        console.log('1. target');
        console.log('2. context');
        console.log('3. requirements');
        console.log('4. mode');
        console.log('5. llm');
        console.log('6. pov');
        console.log('7. budget');
        console.log('8. approval');
        console.log('9. execution');
        console.log('10. workspace');
        console.log('11. tools');
        console.log('12. providers');
        console.log('0. back\n');

        const choice = await this.ask('Select:\n> ');
        if (!choice || ['0', 'back', 'q', 'exit'].includes(choice.toLowerCase())) {
            return;
        }

        switch (choice) {
            case '1': {
                const val = await this.ask(`Target path [current: ${this.session.targetDir || 'none'}]:\n> `);
                if (val) this.applySetOption('target', val);
                break;
            }
            case '2': {
                const val = await this.ask(`Context path [current: ${this.session.contextDir || 'none'}]:\n> `);
                if (val) this.applySetOption('context', val);
                break;
            }
            case '3': {
                const val = await this.ask(`Requirements path [current: ${this.session.requirementsPath || 'none'}]:\n> `);
                if (val) this.applySetOption('requirements', val);
                break;
            }
            case '4': {
                const val = await this.ask(`Mode (FAST, STANDARD, DEEP, FORENSIC) [current: ${this.session.mode}]:\n> `);
                if (val) this.applySetOption('mode', val);
                break;
            }
            case '5': {
                const val = await this.ask(`LLM (OFF, SCOUT, SCOUT+CRITIC, ADAPTIVE, FULL) [current: ${this.session.llmStrategy}]:\n> `);
                if (val) this.applySetOption('llm', val);
                break;
            }
            case '6': {
                const val = await this.ask(`PoV (ON-DETECTED, ALWAYS, NEVER) [current: ${this.session.povMode}]:\n> `);
                if (val) this.applySetOption('pov', val);
                break;
            }
            case '7': {
                const val = await this.ask(`Budget ($) [current: ${this.session.budget}]:\n> `);
                if (val) this.applySetOption('budget', val);
                break;
            }
            case '8': {
                const val = await this.ask(`Approval (REQUIRED, OPTIONAL) [current: ${this.session.approvalPolicy}]:\n> `);
                if (val) this.applySetOption('approval', val);
                break;
            }
            case '9': {
                const val = await this.ask(`Execution backend (AUTO, NATIVE, WSL, CONTAINER) [current: ${this.session.metadata?.executionBackend || 'AUTO'}]:\n> `);
                if (val) this.applySetOption('execution', val);
                break;
            }
            case '10': {
                const val = await this.ask(`Workspace output path [current: ${this.session.metadata?.workspace || this.options.outputDir || 'hwsec-output'}]:\n> `);
                if (val) this.applySetOption('workspace', val);
                break;
            }
            case '11': {
                await this.handleToolsConfigMenu();
                break;
            }
            case '12': {
                await this.handleProvidersConfigureMenu();
                break;
            }
            default:
                console.log(`[-] Invalid choice '${choice}'. Allowed: 1-12, 0.`);
                break;
        }
    }

    /**
     * Renders tools config menu (Section 8).
     */
    async handleToolsConfigMenu() {
        while (this.running) {
            console.log('1. List configured tool paths');
            console.log('2. Set tool path');
            console.log('3. Reset tool path');
            console.log('4. View backend resolution');
            console.log('5. Re-probe tools');
            console.log('0. Back\n');

            const choice = await this.ask('Select:\n> ');
            if (!choice || ['0', 'back', 'q', 'exit'].includes(choice.toLowerCase())) {
                break;
            }

            switch (choice) {
                case '1': {
                    console.log('\nConfigured Tool Paths:');
                    console.log('------------------------------------------------------------');
                    const suiteRoot = process.env.OSS_CAD_SUITE || process.env.YOSYSHQ_ROOT || '(not set)';
                    console.log(`  OSS_CAD_SUITE : ${suiteRoot}`);
                    const paths = this.config.tool_paths || {};
                    const sessionPaths = this.session.toolPaths || {};
                    const combined = { ...paths, ...sessionPaths };
                    if (Object.keys(combined).length === 0) {
                        console.log('  (No custom tool paths configured - using auto-discovery)');
                    } else {
                        for (const [k, v] of Object.entries(combined)) {
                            console.log(`  tool.${k}.path : ${v}`);
                        }
                    }
                    console.log('------------------------------------------------------------');
                    break;
                }
                case '2': {
                    const tool = await this.ask('Tool name (e.g. yosys, verilator, semgrep, joern, codeql):\n> ');
                    if (tool) {
                        const tpath = await this.ask(`Path to ${tool} executable:\n> `);
                        if (tpath) {
                            this.applySetOption(`tool.${tool}.path`, tpath);
                        }
                    }
                    break;
                }
                case '3': {
                    const tool = await this.ask('Tool name to reset:\n> ');
                    if (tool) {
                        this.session.unset(`tool.${tool}.path`);
                        if (this.config.tool_paths) delete this.config.tool_paths[tool];
                        this.sessionManager.persistActiveSession();
                        console.log(`[+] Reset tool.${tool}.path`);
                    }
                    break;
                }
                case '4': {
                    console.log(await this.diagnostics.runDoctor('execution'));
                    break;
                }
                case '5': {
                    console.log('[*] Re-probing tool capabilities...');
                    const st = await this.diagnostics.getToolchainStatus();
                    console.log(ConsoleInspectors.formatToolsStatus(st));
                    break;
                }
                default:
                    console.log(`[-] Invalid choice '${choice}'. Select 1-5 or 0.`);
                    break;
            }
            console.log();
        }
    }

    /**
     * Renders providers configuration menu (Section 10).
     */
    async handleProvidersConfigureMenu() {
        while (this.running) {
            console.log('1. Gemini-1');
            console.log('2. Gemini-2');
            console.log('3. Gemini-3');
            console.log('4. NVIDIA');
            console.log('5. OpenRouter');
            console.log('6. Disable/enable provider');
            console.log('7. Test providers');
            console.log('0. Back\n');

            const choice = await this.ask('Select:\n> ');
            if (!choice || ['0', 'back', 'q', 'exit'].includes(choice.toLowerCase())) {
                break;
            }

            const map = {
                '1': 'gemini_account_1',
                '2': 'gemini_account_2',
                '3': 'gemini_account_3',
                '4': 'nvidia',
                '5': 'openrouter'
            };
            const labelMap = {
                '1': 'Gemini-1',
                '2': 'Gemini-2',
                '3': 'Gemini-3',
                '4': 'NVIDIA',
                '5': 'OpenRouter'
            };

            if (map[choice]) {
                const target = map[choice];
                const label = labelMap[choice];
                const key = await this.askMasked('Enter new key:\n> ');
                if (key) {
                    this.diagnostics.pool.updateKey(target, key);
                    console.log(`[+] ${label} credential updated.`);
                }
            } else if (choice === '6') {
                const target = await this.ask('Provider to toggle (gemini-1, gemini-2, gemini-3, nvidia, openrouter):\n> ');
                if (target) {
                    const norm = target.toLowerCase().replace('gemini-', 'gemini_account_');
                    const ep = this.diagnostics.pool.getEndpoint(norm) || this.diagnostics.pool.getEndpoint(target.toLowerCase());
                    if (ep) {
                        const newDisabled = !ep.forcedUnavailable;
                        this.diagnostics.pool.setDisabled(ep.id, newDisabled);
                        console.log(`[+] ${target} is now ${newDisabled ? 'DISABLED' : 'ENABLED'}`);
                    } else {
                        console.log(`[-] Unknown provider: '${target}'`);
                    }
                }
            } else if (choice === '7') {
                await this.handleProviders('test', []);
            } else {
                console.log(`[-] Invalid option '${choice}'. Select 1-7 or 0.`);
            }
            console.log();
        }
    }

    /**
     * Executes an operator command string.
     * @param {string} line 
     */
    async executeCommand(line) {
        const parsed = ConsoleParser.parse(line);
        if (!parsed.command) return;

        // Record in history (with sensitive tokens masked)
        const redacted = ConsoleParser.redactSensitive(parsed.raw);
        this.sessionManager.recordHistory(redacted);

        const { command, subcommand, args } = parsed;

        try {
            switch (command) {
                case 'help':
                    this.renderHelp(subcommand || args[0]);
                    break;

                case 'menu':
                    await this.runSessionSetupMenu();
                    break;

                case 'set': {
                    if (args.length < 1 && !subcommand) {
                        await this.renderSettingsMenu();
                        break;
                    }
                    const optKey = subcommand || args[0];
                    const optVal = subcommand ? args.join(' ') : args.slice(1).join(' ');
                    this.applySetOption(optKey, optVal);
                    break;
                }

                case 'unset': {
                    const optKey = subcommand || args[0];
                    this.session.unset(optKey);
                    this.sessionManager.persistActiveSession();
                    console.log(`[+] Unset ${optKey}`);
                    break;
                }

                case 'show': {
                    if (subcommand === 'options' || args[0] === 'options' || !subcommand) {
                        console.log(ConsoleInspectors.formatShowOptions(this.session));
                    } else {
                        console.log(`Unknown show target: '${subcommand}'. Valid: show options`);
                    }
                    break;
                }

                case 'status':
                    console.log(await ConsoleInspectors.formatStatus(this.session, this.workspace, this.diagnostics));
                    break;

                case 'tools': {
                    if (subcommand === 'config') {
                        await this.handleToolsConfigMenu();
                    } else {
                        const st = await this.diagnostics.getToolchainStatus();
                        console.log(ConsoleInspectors.formatToolsStatus(st));
                    }
                    break;
                }

                case 'run':
                    await this.handleRun();
                    break;

                case 'plan':
                    console.log(ConsoleInspectors.formatPlan(this.workspace));
                    break;

                case 'inspect':
                    await this.handleInspect(subcommand, args);
                    break;

                case 'approve':
                    await this.handleApprove();
                    break;

                case 'proceed':
                    await this.handleProceed();
                    break;

                case 'stop':
                    if (this.activeTask) {
                        this.activeTask.cancelled = true;
                        console.log('[!] Active operation cancellation requested.');
                    } else {
                        console.log('[*] No active background operation running.');
                    }
                    break;

                case 'evidence':
                    console.log(ConsoleInspectors.formatInspectEvidence(this.workspace, subcommand || args[0]));
                    break;

                case 'pov':
                    await this.handlePov(subcommand, args);
                    break;

                case 'report':
                    console.log(ConsoleInspectors.formatReport(this.workspace));
                    break;

                case 'dossier':
                    console.log(ConsoleInspectors.formatDossier(this.workspace, subcommand || args[0]));
                    break;

                case 'doctor':
                    console.log(await this.diagnostics.runDoctor(subcommand || args[0], args));
                    break;

                case 'providers':
                    await this.handleProviders(subcommand, args);
                    break;

                case 'workspace': {
                    console.log('\nWORKSPACE INFORMATION');
                    console.log('---------------------');
                    console.log(`Target Directory : ${this.session.targetDir || '(not set)'}`);
                    console.log(`Context Directory: ${this.session.contextDir || '(none)'}`);
                    console.log(`Output Directory : ${this.options.outputDir || 'hwsec-output'}`);
                    if (this.workspace) {
                        console.log(`Analysis ID      : ${this.workspace.analysisId}`);
                        console.log(`Workspace Path   : ${this.workspace.outputDir}`);
                    }
                    console.log();
                    break;
                }

                case 'sessions':
                    await this.handleSessions(subcommand, args);
                    break;

                case 'history':
                    this.renderHistory();
                    break;

                case 'modules':
                    console.log(formatModules());
                    break;

                case 'reset':
                    this.session.reset();
                    this.workspace = null;
                    this.sessionManager.persistActiveSession();
                    console.log('[+] Session configuration reset safely.');
                    break;

                case 'exit':
                case 'quit':
                    this.sessionManager.persistActiveSession();
                    this.close();
                    break;

                default:
                    console.log(`[-] Unknown command: '${command}'. Type 'help' for available commands.`);
                    break;
            }
        } catch (err) {
            console.error(`[-] Error: ${err.message}`);
        }
    }

    /**
     * Executes the planning phase (`run`).
     */
    async handleRun() {
        if (!this.session.targetDir) {
            console.error("[-] Target directory not set. Use 'set target <path>' before running.");
            return;
        }

        console.log('[*] Initializing repository discovery and planning...');
        const baseOutputDir = this.options.outputDir || 'hwsec-output';
        this.workspace = new Workspace(baseOutputDir);
        this.session.analysisId = this.workspace.analysisId;

        const planner = new Planner(
            this.session.targetDir,
            this.config,
            this.session.requirementsPath,
            this.session.mode.toLowerCase()
        );

        console.log('[+] inventory complete');
        const plan = await planner.plan(this.workspace);
        console.log('[+] deterministic analysis complete');
        console.log('[+] intelligent planning complete');

        // Discover and cache Entry Points in repository
        const epInventory = new EntryPointInventory();
        const entryPoints = epInventory.discover(this.session.targetDir);
        this.workspace.saveJson('inventory/entry_points.json', entryPoints);

        const analysis = this.workspace.loadJson('analysis.json') || {};
        analysis.entry_points_count = entryPoints.length;
        analysis.pov_mode = this.session.povMode.toLowerCase();
        analysis.proof_mode = this.session.mode.toLowerCase();
        this.workspace.saveJson('analysis.json', analysis);

        this.session.status = SessionPhase.PLANNED;
        this.session.metadata = {
            total_files: plan.inventory.total_files,
            total_loc: plan.inventory.total_loc,
            tools_detected: plan.tools_detected,
            estimated_cost_usd: plan.budget_estimate?.estimated_cost_usd || 0.0
        };
        this.sessionManager.persistActiveSession();

        console.log('[+] plan generated');
        console.log(`Phase: PLANNED`);
        console.log(`Analysis ID: ${this.workspace.analysisId}`);
        console.log(`Use 'plan' to view the plan, 'inspect plan' for details, and 'approve' to approve execution.`);
    }

    /**
     * Handles `approve` command.
     */
    async handleApprove() {
        if (this.session.status !== SessionPhase.PLANNED) {
            console.error(`[-] Cannot approve plan in '${this.session.status}' state. Run 'run' first.`);
            return;
        }

        console.log('WARNING: execution will run target code inside bounded sandboxes.');
        const ans = await this.ask('Approve plan? [y/N]:\n> ');
        if (ans.toLowerCase() === 'y' || ans.toLowerCase() === 'yes') {
            this.session.status = SessionPhase.APPROVED;
            this.sessionManager.persistActiveSession();
            console.log('Plan approved. Use `proceed` to execute.');
        } else {
            console.log('[*] Plan approval declined.');
        }
    }

    /**
     * Handles `proceed` command with live execution UX.
     */
    async handleProceed() {
        if (this.session.approvalPolicy === 'REQUIRED' && this.session.status !== SessionPhase.APPROVED) {
            console.error(`[-] Execution approval required before proceeding. Current state: '${this.session.status}'. Use 'approve' first.`);
            return;
        }

        if (!this.workspace || !this.session.analysisId) {
            console.error("[-] No planned analysis found. Run 'run' first.");
            return;
        }

        this.session.status = SessionPhase.RUNNING;
        this.sessionManager.persistActiveSession();

        const progressCb = (step, total, name, status, extra) => {
            const stepStr = `[${String(step).padStart(2, '0')}/${String(total).padStart(2, '0')}]`;
            const nameStr = `${name}`.padEnd(32, '.');
            let statusStr = status;
            if (extra) statusStr += ` (${extra})`;
            console.log(`${stepStr} ${nameStr} ${statusStr}`);
        };

        try {
            const res = await runAnalysisPipeline(
                this.session.analysisId,
                {
                    config: this.configPath,
                    outputDir: this.options.outputDir || 'hwsec-output',
                    mode: this.session.mode.toLowerCase(),
                    povMode: this.session.povMode.toLowerCase(),
                    verbose: false
                },
                progressCb
            );

            this.session.status = SessionPhase.COMPLETED;
            this.session.metadata.results = res.results;
            this.sessionManager.persistActiveSession();

            console.log(`\n[+] Analysis execution COMPLETED successfully!`);
            console.log(`    DETECTED:           ${res.results.detected_count}`);
            console.log(`    NOT_DETECTED:       ${res.results.not_detected_count}`);
            console.log(`    INCONCLUSIVE:       ${res.results.inconclusive_count}`);
            console.log(`    Final report saved: ${res.reportPath}\n`);
        } catch (err) {
            this.session.status = SessionPhase.INITIALIZED;
            this.sessionManager.persistActiveSession();
            throw err;
        }
    }

    /**
     * Handles `inspect` subcommands.
     */
    async handleInspect(subcommand, args) {
        if (!subcommand) {
            console.log('Usage: inspect <target|plan|hypothesis|evidence|pov|execution|llm> [id]');
            return;
        }

        switch (subcommand.toLowerCase()) {
            case 'target':
                console.log(ConsoleInspectors.formatInspectTarget(this.session, this.workspace));
                break;
            case 'plan':
                console.log(ConsoleInspectors.formatInspectPlan(this.workspace));
                break;
            case 'hypothesis':
                console.log(ConsoleInspectors.formatInspectHypothesis(this.workspace, args[0]));
                break;
            case 'evidence':
                console.log(ConsoleInspectors.formatInspectEvidence(this.workspace, args[0]));
                break;
            case 'pov':
                console.log(ConsoleInspectors.formatInspectPoV(this.workspace, args[0]));
                break;
            case 'execution':
                console.log(await this.diagnostics.runDoctor('execution'));
                break;
            case 'llm':
                console.log(await this.diagnostics.formatProviders());
                break;
            default:
                console.log(`Unknown inspect target '${subcommand}'. Valid: target, plan, hypothesis, evidence, pov, execution, llm`);
                break;
        }
    }

    /**
     * Handles `pov` subcommands.
     */
    async handlePov(subcommand, args) {
        if (!subcommand || subcommand === 'list') {
            console.log(ConsoleInspectors.formatInspectPoV(this.workspace, args[0]));
            return;
        }

        const povTarget = args[0] || subcommand;
        if (subcommand === 'verify' || subcommand === 'replay') {
            console.log(`[*] Executing independent sandbox ${subcommand} for PoV: ${povTarget}...`);
            const baseDir = this.workspace ? path.join(this.workspace.outputDir, 'pov') : path.resolve('hwsec-output/pov');
            let bundleDir = path.resolve(povTarget);
            if (!fs.existsSync(bundleDir)) {
                bundleDir = path.join(baseDir, povTarget);
            }
            if (!fs.existsSync(bundleDir)) {
                console.error(`[-] PoV bundle not found at: ${bundleDir}`);
                return;
            }

            const broker = new AnalysisBroker();
            const res = await broker.dispatch({
                capability: BrokerCapability.POV_VERIFICATION,
                povBundleDir: bundleDir,
                targetDirOverride: this.session.targetDir
            });

            console.log(`  PoV Status:   ${res.pov_status}`);
            console.log(`  Verification: ${res.verified ? 'VERIFIED (PASS)' : 'FAILED / UNVERIFIED'}`);
            console.log(`  Reason Code:  ${res.reason_code}`);
        } else {
            console.log("Usage: pov <list|replay|verify> [id]");
        }
    }

    /**
     * Handles `providers` subcommands.
     */
    async handleProviders(subcommand, args) {
        const pool = this.diagnostics.pool;
        if (!subcommand || subcommand === 'status') {
            console.log(await this.diagnostics.formatProviders());
            return;
        }

        switch (subcommand.toLowerCase()) {
            case 'configure':
                await this.handleProvidersConfigureMenu();
                break;

            case 'test': {
                const target = args[0];
                if (target) {
                    const res = await pool.testEndpoint(target);
                    console.log(`Provider ${target}: ${res.healthy ? 'HEALTHY' : (res.state || 'UNAVAILABLE')} (${res.reason || res.model || 'OK'})`);
                } else {
                    console.log('Testing all provider endpoints...');
                    const endpoints = [
                        { alias: 'gemini-1', name: 'Gemini #1' },
                        { alias: 'gemini-2', name: 'Gemini #2' },
                        { alias: 'gemini-3', name: 'Gemini #3' },
                        { alias: 'nvidia', name: 'NVIDIA' },
                        { alias: 'openrouter', name: 'OpenRouter' }
                    ];
                    for (const ep of endpoints) {
                        const res = await pool.testEndpoint(ep.alias);
                        console.log(`${ep.name.padEnd(14)} ${res.healthy ? 'HEALTHY' : (res.state || 'UNAVAILABLE')}`);
                    }
                }
                break;
            }

            case 'disable': {
                if (!args[0]) {
                    console.log('Usage: providers disable <provider-id>');
                    break;
                }
                try {
                    pool.setDisabled(args[0], true);
                    console.log(`[+] Disabled provider '${args[0]}'`);
                } catch (err) {
                    console.log(`[-] ${err.message}`);
                }
                break;
            }

            case 'enable': {
                if (!args[0]) {
                    console.log('Usage: providers enable <provider-id>');
                    break;
                }
                try {
                    pool.setDisabled(args[0], false);
                    console.log(`[+] Enabled provider '${args[0]}'`);
                } catch (err) {
                    console.log(`[-] ${err.message}`);
                }
                break;
            }

            case 'rotate':
            case 'set': {
                if (!args[0]) {
                    console.log('Usage: providers rotate <provider-id> [new-key]');
                    break;
                }
                const rawTarget = args[0];
                const aliasMap = {
                    'gemini-1': 'gemini_account_1',
                    'gemini-2': 'gemini_account_2',
                    'gemini-3': 'gemini_account_3',
                    'gemini_1': 'gemini_account_1',
                    'gemini_2': 'gemini_account_2',
                    'gemini_3': 'gemini_account_3',
                    'nvidia': 'nvidia',
                    'openrouter': 'openrouter'
                };
                const target = aliasMap[rawTarget.toLowerCase()] || rawTarget;
                let key = args[1];
                if (!key) {
                    key = await this.askMasked('Enter new key:\n> ');
                }
                try {
                    pool.updateKey(target, key);
                    const displayLabel = rawTarget.charAt(0).toUpperCase() + rawTarget.slice(1);
                    console.log(`[+] ${displayLabel} credential updated.`);
                } catch (err) {
                    console.log(`[-] ${err.message}`);
                }
                break;
            }

            case 'remove': {
                if (!args[0]) {
                    console.log('Usage: providers remove <provider-id>');
                    break;
                }
                try {
                    pool.updateKey(args[0], null);
                    console.log(`[+] Removed key and disabled provider '${args[0]}'`);
                } catch (err) {
                    console.log(`[-] ${err.message}`);
                }
                break;
            }

            default:
                console.log(`Unknown providers subcommand '${subcommand}'. Valid: status, configure, test, disable, enable, rotate, remove`);
                break;
        }
    }

    /**
     * Handles `sessions` subcommands.
     */
    async handleSessions(subcommand, args) {
        if (subcommand === 'load' && args.length > 0) {
            this.session = this.sessionManager.loadSession(args[0]);
            if (this.session.analysisId) {
                const baseOutputDir = this.options.outputDir || 'hwsec-output';
                try {
                    this.workspace = Workspace.load(baseOutputDir, this.session.analysisId);
                } catch {}
            }
            console.log(`[+] Loaded session '${this.session.id}' (Target: ${this.session.targetDir || 'not set'})`);
            return;
        }

        if (subcommand === 'new') {
            this.session = this.sessionManager.createSession();
            this.workspace = null;
            console.log(`[+] Created new session '${this.session.id}'`);
            return;
        }

        const list = this.sessionManager.listSessions();
        console.log('\nID                   TARGET                         STATUS      UPDATED');
        console.log('--------------------------------------------------------------------------------');
        if (list.length === 0) {
            console.log('  (No recorded sessions)');
        }
        for (const s of list) {
            const target = (s.targetDir ? path.basename(s.targetDir) : 'not set').slice(0, 28).padEnd(30);
            const activeMark = s.id === this.session.id ? '* ' : '  ';
            const idStr = (activeMark + s.id).padEnd(20);
            const status = (s.status || 'INITIALIZED').padEnd(11);
            const date = (s.updatedAt || '').slice(0, 16).replace('T', ' ');
            console.log(`${idStr} ${target} ${status} ${date}`);
        }
        console.log();
    }

    /**
     * Displays command history.
     */
    renderHistory() {
        const history = this.sessionManager.getHistory(50);
        console.log('\nSESSION HISTORY:');
        console.log('------------------------------------------------------------');
        if (history.length === 0) {
            console.log('  (No commands executed yet)');
        }
        for (const item of history) {
            const time = (item.timestamp || '').slice(11, 16);
            console.log(`  [${time}] ${item.command}`);
        }
        console.log('------------------------------------------------------------\n');
    }

    /**
     * Renders help table according to Section 14 of specification.
     */
    renderHelp(cmd = null) {
        console.log('\nCORE');
        console.log('----');
        console.log('help         Show help');
        console.log('menu         Guided setup');
        console.log('status       Session + engine health');
        console.log('show options Current configuration');
        console.log('set          Change a setting');
        console.log('unset        Remove a setting\n');

        console.log('ANALYSIS');
        console.log('--------');
        console.log('run          Prepare analysis');
        console.log('plan         Display plan');
        console.log('approve      Approve execution');
        console.log('proceed      Execute approved plan');
        console.log('inspect      Inspect artifacts/hypotheses/evidence\n');

        console.log('LLM / TOOLS');
        console.log('-----------');
        console.log('providers    Manage LLM providers');
        console.log('tools        Tool capability status');
        console.log('doctor       Detailed diagnostics\n');

        console.log('ARTIFACTS');
        console.log('---------');
        console.log('evidence     Evidence view');
        console.log('pov          PoV operations');
        console.log('dossier      Analyst dossier');
        console.log('report       Final report\n');

        console.log('SESSION');
        console.log('-------');
        console.log('workspace    Workspace information');
        console.log('history      Command history');
        console.log('reset        Reset session');
        console.log('exit         Exit console\n');
    }

    /**
     * Starts the interactive REPL.
     */
    async start() {
        this.running = true;
        this.rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            prompt: 'hwsec > '
        });

        await this.runOnboarding();

        if (this.running) {
            this.rl.prompt();
        }

        let commandQueue = Promise.resolve();

        this.rl.on('line', (line) => {
            commandQueue = commandQueue.then(async () => {
                const trimmed = line.trim();
                if (trimmed && this.running) {
                    await this.executeCommand(trimmed);
                }
                if (this.running) {
                    this.rl.prompt();
                }
            }).catch((err) => {
                console.error(`[-] Stream Error: ${err.message}`);
            });
        });

        this.rl.on('close', () => {
            commandQueue.finally(() => {
                this.close();
            });
        });

        this.rl.on('SIGINT', () => {
            console.log('\n(Interrupted. Type exit to quit)');
            if (this.running) {
                this.rl.prompt();
            }
        });
    }

    close() {
        if (!this.running && this.closed) return;
        this.running = false;
        this.closed = true;
        if (this.sessionManager) {
            this.sessionManager.persistActiveSession();
            this.sessionManager.close();
        }
        if (this.rl) {
            this.rl.close();
        }
    }
}
