import { ToolAdapter } from '../../../tools/base.js';
import { runCommand, runWslCommand, toWslPath } from '../../../core/execUtils.js';
import { createFinding, Severity, VerificationState, createEvidence, createSourceLocation } from '../../../core/schema.js';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

export class CodeQLTool extends ToolAdapter {
    get name() {
        return "codeql";
    }

    get id() {
        return "codeql";
    }

    get capabilities() {
        return ["deep_dataflow", "taint_tracking"];
    }

    get supportedLanguages() {
        return ["python", "java", "c", "cpp", "go", "javascript"];
    }

    /**
     * Probes for CodeQL CLI installation across Windows PATH and WSL.
     */
    async checkInstalled() {
        const configured = this.config.tool_paths?.codeql || 'codeql';

        // 1. Probe native binary
        try {
            const res = await runCommand(configured, ['version', '--format=json'], { timeout: 8000 });
            if (res.exitCode === 0) {
                try {
                    const parsed = JSON.parse(res.stdout);
                    return { installed: true, version: parsed.version || 'CodeQL CLI', isWsl: false, cmd: configured };
                } catch {
                    return { installed: true, version: 'CodeQL CLI', isWsl: false, cmd: configured };
                }
            }
        } catch {}

        // 2. Probe WSL binary if on Windows
        if (process.platform === 'win32') {
            try {
                const wslRes = await runWslCommand('codeql', ['version', '--format=json'], { timeout: 8000 });
                if (wslRes.exitCode === 0) {
                    return { installed: true, version: 'CodeQL CLI (WSL)', isWsl: true, cmd: 'codeql' };
                }
            } catch {}
        }

        return { installed: false, error: 'CodeQL CLI not detected in system PATH or WSL' };
    }

    /**
     * Maps file extension to CodeQL language identifier.
     */
    _resolveCodeQLLanguage(ext) {
        switch (ext.toLowerCase()) {
            case '.py': return 'python';
            case '.java': return 'java';
            case '.c':
            case '.cpp':
            case '.cc':
            case '.cxx':
            case '.h':
            case '.hpp': return 'cpp';
            case '.go': return 'go';
            case '.js':
            case '.ts': return 'javascript';
            default: return null;
        }
    }

    /**
     * Computes a combined SHA-256 fingerprint for source files.
     */
    _computeSourceHash(files) {
        const hash = crypto.createHash('sha256');
        for (const file of files.slice().sort()) {
            if (fs.existsSync(file)) {
                hash.update(file);
                hash.update(fs.readFileSync(file));
            }
        }
        return hash.digest('hex');
    }

    /**
     * Parses standard SARIF v2.1.0 output into normalized HWSEC findings.
     */
    parseSarif(sarifContent, sarifPath, targetFiles = []) {
        let sarif;
        try {
            sarif = typeof sarifContent === 'string' ? JSON.parse(sarifContent) : sarifContent;
        } catch {
            return [];
        }

        const findings = [];
        const runs = sarif.runs || [];

        for (const run of runs) {
            const rules = new Map();
            for (const r of (run.tool?.driver?.rules || [])) {
                rules.set(r.id, r);
            }

            for (const result of (run.results || [])) {
                const ruleId = result.ruleId || 'codeql-finding';
                const rule = rules.get(ruleId) || {};
                const message = result.message?.text || rule.shortDescription?.text || ruleId;
                
                // Extract CWE if present in rule tags
                let cweId = null;
                for (const tag of (rule.properties?.tags || [])) {
                    const cweMatch = tag.match(/external\/cwe\/(cwe-\d+)/i);
                    if (cweMatch) {
                        cweId = cweMatch[1].toUpperCase();
                        break;
                    }
                }

                // Map severity level
                const sarifLevel = result.level || rule.defaultConfiguration?.level || 'warning';
                let severity = Severity.MEDIUM;
                if (sarifLevel === 'error') severity = Severity.HIGH;
                else if (sarifLevel === 'note' || sarifLevel === 'none') severity = Severity.LOW;

                // Extract physical locations
                const sourceLocations = [];
                for (const loc of (result.locations || [])) {
                    const phys = loc.physicalLocation;
                    if (phys) {
                        let uri = phys.artifactLocation?.uri || '';
                        uri = uri.replace(/^file:\/\/\/?/, '');
                        
                        // Try matching with input target files
                        const matchedFile = targetFiles.find(f => f.endsWith(uri) || path.basename(f) === path.basename(uri)) || uri;
                        const startLine = phys.region?.startLine || 1;
                        const endLine = phys.region?.endLine || startLine;
                        const snippet = phys.region?.snippet?.text || '';

                        sourceLocations.push(createSourceLocation({
                            path: matchedFile,
                            startLine,
                            endLine,
                            line: startLine,
                            startColumn: phys.region?.startColumn || 1,
                            endColumn: phys.region?.endColumn || 1
                        }));
                    }
                }

                const findingId = `CODEQL-${crypto.randomBytes(4).toString('hex')}`;
                const evidenceObj = createEvidence({
                    id: `EV-${crypto.randomBytes(4).toString('hex')}`,
                    finding_id: findingId,
                    tool_name: "codeql",
                    evidence_type: "SARIF_REPORT",
                    description: `CodeQL Static Analysis: ${message} (Rule: ${ruleId})`,
                    artifact_path: sarifPath,
                    raw_evidence: {
                        ruleId,
                        ruleName: rule.name,
                        message,
                        cwe: cweId,
                        sarifLevel
                    },
                    confidence: 0.80
                });

                findings.push(createFinding({
                    id: findingId,
                    title: `[${cweId || ruleId}] ${message.slice(0, 120)}`,
                    description: `CodeQL detected vulnerability rule ${ruleId}:\n${message}`,
                    severity,
                    confidence: 0.80,
                    source_tool: "codeql",
                    source_locations: sourceLocations,
                    evidence: [evidenceObj],
                    verification_state: VerificationState.CANDIDATE,
                    cwe_id: cweId
                }));
            }
        }

        return findings;
    }

    /**
     * Executes CodeQL database creation, query analysis, and SARIF normalization.
     */
    async run(params, legacyOutputDir, legacyOptions) {
        const startTime = Date.now();
        let files = [];
        let outputDir = legacyOutputDir;
        let timeout = 180000;

        if (Array.isArray(params)) {
            files = params;
            outputDir = legacyOutputDir || path.resolve('hwsec-output');
        } else if (params && typeof params === 'object') {
            files = params.files || [];
            outputDir = params.outputDir || legacyOutputDir || path.resolve('hwsec-output');
            timeout = params.timeout || timeout;
        }

        // 1. Availability check
        const check = await this.checkInstalled();
        if (!check.installed) {
            return {
                status: "UNAVAILABLE",
                findings: [],
                reason: check.error,
                telemetry: {
                    error: check.error,
                    checkedAt: new Date().toISOString()
                }
            };
        }

        // 2. Filter supported source files
        const supported = [];
        const detectedLangs = new Set();
        for (const f of files) {
            const lang = this._resolveCodeQLLanguage(path.extname(f));
            if (lang) {
                supported.push(f);
                detectedLangs.add(lang);
            }
        }

        if (supported.length === 0) {
            return {
                status: "SKIPPED",
                findings: [],
                reason: "No matching source files for CodeQL supported languages"
            };
        }

        const primaryLang = Array.from(detectedLangs)[0];
        const toolsDir = path.join(outputDir, 'tools', 'codeql');
        if (!fs.existsSync(toolsDir)) {
            fs.mkdirSync(toolsDir, { recursive: true });
        }

        const dbDir = path.join(toolsDir, `db_${primaryLang}`);
        const hashFile = path.join(dbDir, 'hwsec_source_hash.txt');
        const sarifPath = path.join(toolsDir, `codeql_${primaryLang}_results.sarif`);
        const currentHash = this._computeSourceHash(supported);

        // 3. Database caching check
        let dbCached = false;
        if (fs.existsSync(dbDir) && fs.existsSync(hashFile)) {
            const prevHash = fs.readFileSync(hashFile, 'utf-8').trim();
            if (prevHash === currentHash) {
                dbCached = true;
            }
        }

        try {
            const sourceRoot = path.dirname(supported[0]);

            // Create database if not cached
            if (!dbCached) {
                const createArgs = [
                    'database', 'create',
                    check.isWsl ? toWslPath(dbDir) : dbDir,
                    `--language=${primaryLang}`,
                    `--source-root=${check.isWsl ? toWslPath(sourceRoot) : sourceRoot}`,
                    '--overwrite'
                ];

                const createRes = check.isWsl
                    ? await runWslCommand('codeql', createArgs, { timeout })
                    : await runCommand(check.cmd, createArgs, { timeout });

                if (createRes.exitCode !== 0) {
                    return {
                        status: "ERROR",
                        findings: [],
                        telemetry: {
                            stage: "database_create",
                            error: createRes.stderr || createRes.stdout,
                            durationMs: Date.now() - startTime
                        }
                    };
                }

                fs.writeFileSync(hashFile, currentHash, 'utf-8');
            }

            // Analyze database
            const analyzeArgs = [
                'database', 'analyze',
                check.isWsl ? toWslPath(dbDir) : dbDir,
                '--format=sarif-latest',
                `--output=${check.isWsl ? toWslPath(sarifPath) : sarifPath}`
            ];

            const analyzeRes = check.isWsl
                ? await runWslCommand('codeql', analyzeArgs, { timeout })
                : await runCommand(check.cmd, analyzeArgs, { timeout });

            if (analyzeRes.exitCode !== 0 && !fs.existsSync(sarifPath)) {
                return {
                    status: "ERROR",
                    findings: [],
                    telemetry: {
                        stage: "database_analyze",
                        error: analyzeRes.stderr || analyzeRes.stdout,
                        durationMs: Date.now() - startTime
                    }
                };
            }

            // Parse SARIF
            const sarifData = fs.readFileSync(sarifPath, 'utf-8');
            const findings = this.parseSarif(sarifData, sarifPath, supported);

            return {
                status: "SUCCESS",
                findings,
                artifacts: [sarifPath],
                telemetry: {
                    dbCached,
                    language: primaryLang,
                    findingsCount: findings.length,
                    durationMs: Date.now() - startTime
                }
            };
        } catch (err) {
            return {
                status: "ERROR",
                findings: [],
                telemetry: {
                    error: err.message,
                    durationMs: Date.now() - startTime
                }
            };
        }
    }
}
