import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand, toWslPath, toWindowsPath } from '../../../core/execUtils.js';
import { createFinding, Severity, VerificationState, createEvidence } from '../../../core/schema.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export function getCommonAncestor(filePaths) {
    if (!filePaths || filePaths.length === 0) return process.cwd();
    if (filePaths.length === 1) {
        try {
            const stats = fs.existsSync(filePaths[0]) ? fs.statSync(filePaths[0]) : null;
            if (stats && stats.isDirectory()) return path.resolve(filePaths[0]);
        } catch (_) {}
        return path.dirname(path.resolve(filePaths[0]));
    }

    const resolvedPaths = filePaths.map(p => path.resolve(p));
    const splitPaths = resolvedPaths.map(p => p.split(/[/\\]/).filter(Boolean));
    const isWindows = process.platform === 'win32';
    const drivePrefix = isWindows && /^[a-zA-Z]:/.test(resolvedPaths[0]) ? resolvedPaths[0].slice(0, 2) : '';

    const minLength = Math.min(...splitPaths.map(p => p.length));
    const commonParts = [];

    for (let i = 0; i < minLength; i++) {
        const part = splitPaths[0][i];
        if (splitPaths.every(sp => sp[i].toLowerCase() === part.toLowerCase())) {
            commonParts.push(part);
        } else {
            break;
        }
    }

    if (commonParts.length === 0) {
        return path.resolve('.');
    }

    let commonPath = commonParts.join(path.sep);
    if (isWindows && drivePrefix) {
        if (!commonPath.toLowerCase().startsWith(drivePrefix.toLowerCase())) {
            commonPath = drivePrefix + path.sep + commonPath;
        }
    } else if (!isWindows) {
        commonPath = path.sep + commonPath;
    }

    try {
        if (fs.existsSync(commonPath) && !fs.statSync(commonPath).isDirectory()) {
            commonPath = path.dirname(commonPath);
        }
    } catch (_) {}

    return commonPath;
}

export class JoernTool extends ToolAdapter {
    get name() {
        return "joern";
    }

    get id() {
        return "joern";
    }

    get capabilities() {
        return ["graph_dataflow", "code_property_graph"];
    }

    get supportedLanguages() {
        return ["c", "cpp", "java", "python", "go"];
    }

    /**
     * Resolves the configured or default Joern installation path and execution mode (WSL vs Windows).
     */
    async checkInstalled() {
        const configuredPath = this.config.tool_paths?.joern;

        // 1. If configured as wsl:<path>
        if (configuredPath && configuredPath.startsWith('wsl:')) {
            const wslBinDir = configuredPath.slice(4).trim();
            const parseBin = `${wslBinDir}/joern-parse`;
            const check = await runWslCommand(parseBin, ['--help'], { timeout: 8000 });
            if (check.exitCode === 0) {
                return { installed: true, isWsl: true, binDir: wslBinDir, version: 'Joern CLI (WSL)' };
            }
        }

        // 2. Try default WSL path if on Windows
        if (process.platform === 'win32') {
            const defaultWslBin = '/home/intern/bin/joern/joern-cli';
            const check = await runWslCommand(`${defaultWslBin}/joern-parse`, ['--help'], { timeout: 8000 });
            if (check.exitCode === 0) {
                return { installed: true, isWsl: true, binDir: defaultWslBin, version: 'Joern CLI (WSL)' };
            }
        }

        // 3. Try native Windows command
        const nativeCmd = configuredPath || 'joern-parse';
        const nativeCheck = await runCommand(nativeCmd, ['--help'], { timeout: 8000 });
        if (nativeCheck.exitCode === 0) {
            return { installed: true, isWsl: false, binDir: path.dirname(nativeCmd), version: 'Joern CLI (Native)' };
        }

        return { installed: false, error: 'Joern CLI not detected in PATH or WSL (/home/intern/bin/joern/joern-cli)' };
    }

    /**
     * Executes Joern CPG generation and dataflow security queries.
     */
    async run(params, legacyOutputDir, legacyOptions) {
        const startTime = Date.now();
        let files = [];
        let outputDir = legacyOutputDir;
        let language = null;
        let timeout = 120000;

        if (Array.isArray(params)) {
            files = params;
            outputDir = legacyOutputDir || path.resolve('hwsec-output');
        } else if (params && typeof params === 'object') {
            files = params.files || [];
            outputDir = params.outputDir || legacyOutputDir || path.resolve('hwsec-output');
            language = params.language || null;
            timeout = params.timeout || timeout;
        }

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const install = await this.checkInstalled();
        if (!install.installed) {
            return {
                status: "UNAVAILABLE",
                findings: [],
                telemetry: { error: install.error }
            };
        }

        // Filter supported files
        const supportedExts = ['.c', '.cpp', '.cc', '.h', '.hpp', '.java', '.py', '.go'];
        const targetFiles = files.filter(f => supportedExts.includes(path.extname(f).toLowerCase()));

        if (targetFiles.length === 0) {
            return {
                status: "SKIPPED",
                findings: [],
                reason: "No matching source files for Joern analysis"
            };
        }

        const toolsDir = path.join(outputDir, 'tools', 'joern');
        const cacheDir = path.join(outputDir, '.joern_cache');
        if (!fs.existsSync(toolsDir)) fs.mkdirSync(toolsDir, { recursive: true });
        if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });

        const queryScriptSrc = path.resolve(path.dirname(new URL(import.meta.url).pathname.replace(/^\/([a-zA-Z]:)/, '$1')), 'joern_query.sc');

        // Batching: split large target file lists into chunks of up to 50 files
        const BATCH_SIZE = 50;
        const batches = [];
        if (targetFiles.length <= BATCH_SIZE) {
            batches.push(targetFiles);
        } else {
            for (let i = 0; i < targetFiles.length; i += BATCH_SIZE) {
                batches.push(targetFiles.slice(i, i + BATCH_SIZE));
            }
        }

        const allFindings = [];
        const artifacts = [];
        let batchesSucceeded = 0;
        let batchesTimedOut = 0;
        let batchesFailed = 0;
        const timedOutFiles = [];
        const parsedFiles = [];

        for (let bIdx = 0; bIdx < batches.length; bIdx++) {
            const currentBatch = batches[bIdx];
            // Compute deterministic batch cache hash
            const batchHash = crypto.createHash('sha256')
                .update(currentBatch.map(f => {
                    try {
                        const st = fs.statSync(f);
                        return `${f}:${st.size}:${st.mtimeMs}`;
                    } catch (_) {
                        return f;
                    }
                }).sort().join('|'))
                .digest('hex').slice(0, 16);

            const batchCpgPath = path.join(cacheDir, `cpg_batch_${batchHash}.bin`);
            const batchFindingsJson = path.join(toolsDir, `joern_findings_batch_${bIdx}.json`);
            let cpgReady = fs.existsSync(batchCpgPath);

            const batchTimeout = Math.min(timeout, Math.max(30000, currentBatch.length * 1500));

            if (!cpgReady) {
                let stagedBatchDir = null;
                try {
                    let targetInput;
                    if (currentBatch.length === 1 && fs.existsSync(currentBatch[0]) && !fs.statSync(currentBatch[0]).isDirectory()) {
                        targetInput = currentBatch[0];
                    } else {
                        // Stage ONLY the files belonging to this batch into an isolated batch source directory
                        stagedBatchDir = path.join(cacheDir, `batch_src_${batchHash}`);
                        fs.mkdirSync(stagedBatchDir, { recursive: true });
                        for (const f of currentBatch) {
                            if (fs.existsSync(f)) {
                                const dest = path.join(stagedBatchDir, path.basename(f));
                                if (!fs.existsSync(dest)) {
                                    fs.copyFileSync(f, dest);
                                }
                            }
                        }
                        targetInput = stagedBatchDir;
                    }

                    let parseRes;
                    if (install.isWsl) {
                        const wslInput = toWslPath(targetInput);
                        const wslCpg = toWslPath(batchCpgPath);
                        parseRes = await runWslCommand(`${install.binDir}/joern-parse`, [wslInput, '--output', wslCpg], { timeout: batchTimeout });
                    } else {
                        const parseBin = path.join(install.binDir, 'joern-parse');
                        parseRes = await runCommand(parseBin, [targetInput, '--output', batchCpgPath], { timeout: batchTimeout });
                    }

                    if (stagedBatchDir && fs.existsSync(stagedBatchDir)) {
                        fs.rmSync(stagedBatchDir, { recursive: true, force: true });
                        stagedBatchDir = null;
                    }

                    if (parseRes.exitCode === 0 && fs.existsSync(batchCpgPath)) {
                        cpgReady = true;
                    } else if (parseRes.timedOut) {
                        batchesTimedOut++;
                        timedOutFiles.push(...currentBatch);
                        continue;
                    } else {
                        batchesFailed++;
                        continue;
                    }
                } catch (batchErr) {
                    batchesFailed++;
                    continue;
                }
            }

            if (cpgReady) {
                artifacts.push(batchCpgPath);
                parsedFiles.push(...currentBatch);
                batchesSucceeded++;

                // Execute CPGQL query script
                try {
                    let queryRes;
                    if (install.isWsl) {
                        const wslScript = toWslPath(queryScriptSrc);
                        const wslCpg = toWslPath(batchCpgPath);
                        const wslOut = toWslPath(batchFindingsJson);
                        queryRes = await runWslCommand(`${install.binDir}/joern`, [
                            '--script', wslScript,
                            '--param', `cpgPath=${wslCpg}`,
                            '--param', `outFile=${wslOut}`
                        ], { timeout: batchTimeout });
                    } else {
                        const joernBin = path.join(install.binDir, 'joern');
                        queryRes = await runCommand(joernBin, [
                            '--script', queryScriptSrc,
                            '--param', `cpgPath=${batchCpgPath}`,
                            '--param', `outFile=${batchFindingsJson}`
                        ], { timeout: batchTimeout });
                    }

                    if (fs.existsSync(batchFindingsJson)) {
                        artifacts.push(batchFindingsJson);
                        const rawFindings = JSON.parse(fs.readFileSync(batchFindingsJson, 'utf-8'));
                        for (const item of rawFindings) {
                            const findingId = `JOERN-${crypto.randomBytes(4).toString('hex')}`;
                            const severity = item.severity === 'CRITICAL' ? Severity.CRITICAL :
                                             item.severity === 'HIGH' ? Severity.HIGH :
                                             item.severity === 'MEDIUM' ? Severity.MEDIUM : Severity.LOW;

                            let locPath = item.file;
                            const matchFile = currentBatch.find(f => f.endsWith(item.file) || path.basename(f) === path.basename(item.file));
                            if (matchFile) locPath = matchFile;

                            const evidenceObj = createEvidence({
                                id: `EV-${crypto.randomBytes(4).toString('hex')}`,
                                finding_id: findingId,
                                tool_name: "joern",
                                evidence_type: item.dataflow_reachable ? "DATAFLOW_TRACE" : "STATIC_AST_MATCH",
                                description: `Joern CPG Analysis: ${item.title} in method '${item.method}'. Dataflow reachable from input/param: ${item.dataflow_reachable}`,
                                artifact_path: batchCpgPath,
                                raw_evidence: item,
                                confidence: item.dataflow_reachable ? 0.85 : 0.65
                            });

                            const finding = createFinding({
                                id: findingId,
                                title: `[${item.cwe_id}] ${item.title}`,
                                description: `Joern detected dangerous code pattern in ${locPath}:${item.line}.\nMethod: ${item.method}\nCode snippet: \`${item.code}\`\nReachable from function input: ${item.dataflow_reachable}`,
                                severity,
                                confidence: item.dataflow_reachable ? 0.85 : 0.65,
                                source_tool: "joern",
                                source_locations: [{
                                    path: locPath,
                                    line: item.line || 1,
                                    snippet: item.code || ""
                                }],
                                evidence: [evidenceObj],
                                verification_state: VerificationState.CANDIDATE,
                                cwe_id: item.cwe_id
                            });

                            allFindings.push(finding);
                        }
                    }
                } catch (_) {}
            }
        }

        // Section 5 explicit status tracking: EXECUTED, TIMEOUT, FAILED, UNAVAILABLE, FALLBACK_USED
        let finalStatus = "SUCCESS";
        let bepStatus = "EXECUTED";
        if (batchesTimedOut > 0 && batchesSucceeded === 0) {
            finalStatus = "TIMEOUT";
            bepStatus = "TIMEOUT";
        } else if (batchesTimedOut > 0 && batchesSucceeded > 0) {
            finalStatus = "PARTIAL_TIMEOUT";
            bepStatus = "FALLBACK_USED";
        } else if (batchesFailed > 0 && batchesSucceeded === 0) {
            finalStatus = "ERROR";
            bepStatus = "FAILED";
        }

        let coverageLevel = "FULL_COVERAGE";
        if (parsedFiles.length === 0 && (batchesFailed > 0 || batchesTimedOut > 0)) {
            coverageLevel = "FAILED";
        } else if (parsedFiles.length < targetFiles.length) {
            coverageLevel = "PARTIAL_COVERAGE";
        }

        const primaryCpg = artifacts.find(a => a.endsWith('.bin'));

        return {
            status: finalStatus,
            findings: allFindings,
            artifacts,
            telemetry: {
                status: finalStatus,
                bep_status: bepStatus,
                coverage_level: coverageLevel,
                cpgGenerated: !!primaryCpg && fs.existsSync(primaryCpg),
                cpgSizeBytes: primaryCpg && fs.existsSync(primaryCpg) ? fs.statSync(primaryCpg).size : 0,
                batchesTotal: batches.length,
                batchesSucceeded,
                batchesTimedOut,
                batchesFailed,
                parsedFilesCount: parsedFiles.length,
                timedOutFilesCount: timedOutFiles.length,
                findingsCount: allFindings.length,
                durationMs: Date.now() - startTime
            }
        };
    }
}
