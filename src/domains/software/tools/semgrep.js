import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ToolAdapter } from '../../../tools/base.js';
import { runCommand } from '../../../core/execUtils.js';
import { createFinding, Severity } from '../../../core/schema.js';

// Deterministic pattern fallback for the 5 languages when semgrep CLI is unavailable
const BUILTIN_PATTERNS = [
    {
        id: "SEMGREP-C-BUFFER-OVERFLOW",
        lang: ["c", "cpp"],
        regex: /\b(strcpy|strcat|sprintf|gets|scanf)\s*\(/g,
        title: "Insecure Memory Function Call",
        cwe: "CWE-120",
        severity: Severity.HIGH,
        desc: "Use of dangerous C runtime function without bounds check."
    },
    {
        id: "SEMGREP-PY-CMD-INJECTION",
        lang: ["python"],
        regex: /\b(os\.system|subprocess\.Popen|subprocess\.call|eval|exec)\s*\(/g,
        title: "Potential Command / Code Injection",
        cwe: "CWE-78",
        severity: Severity.CRITICAL,
        desc: "Execution of dynamic shell command or evaluated code."
    },
    {
        id: "SEMGREP-PY-SQL-INJECTION",
        lang: ["python"],
        regex: /\b(execute|executemany)\s*\(/g,
        title: "Potential SQL Injection",
        cwe: "CWE-89",
        severity: Severity.HIGH,
        desc: "Database query execution with potential dynamic string formatting."
    },
    {
        id: "SEMGREP-PY-XSS",
        lang: ["python"],
        regex: /\b(render_template_string|mark_safe|HttpResponse)\s*\(/g,
        title: "Potential Cross-Site Scripting (XSS)",
        cwe: "CWE-79",
        severity: Severity.MEDIUM,
        desc: "Direct rendering of unescaped HTML content."
    },
    {
        id: "SEMGREP-PY-SSRF",
        lang: ["python"],
        regex: /\b(requests\.get|requests\.post|urlopen)\s*\(/g,
        title: "Potential Server-Side Request Forgery",
        cwe: "CWE-918",
        severity: Severity.HIGH,
        desc: "Outbound HTTP request with dynamic parameters."
    },
    {
        id: "SEMGREP-JAVA-DESERIALIZATION",
        lang: ["java"],
        regex: /\b(readObject|ObjectInputStream)\b/g,
        title: "Unsafe Java Object Deserialization",
        cwe: "CWE-502",
        severity: Severity.HIGH,
        desc: "Deserialization of untrusted data stream."
    },
    {
        id: "SEMGREP-JAVA-SQLI",
        lang: ["java"],
        regex: /\b(createQuery|createNativeQuery|execSQL|rawQuery|executeQuery|executeUpdate)\s*\(/g,
        title: "Potential SQL Injection",
        cwe: "CWE-89",
        severity: Severity.HIGH,
        desc: "Execution of database SQL statement."
    },
    {
        id: "SEMGREP-JAVA-CMDI",
        lang: ["java"],
        regex: /\b(Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(/g,
        title: "Potential Command Injection",
        cwe: "CWE-78",
        severity: Severity.CRITICAL,
        desc: "Execution of operating system command."
    },
    {
        id: "SEMGREP-JAVA-PATH-TRAVERSAL",
        lang: ["java"],
        regex: /\b(new\s+File|FileInputStream|FileOutputStream|Paths\.get|getCanonicalPath)\s*\(/g,
        title: "Potential Path Traversal / File Access",
        cwe: "CWE-22",
        severity: Severity.MEDIUM,
        desc: "File path construction or stream creation."
    },
    {
        id: "SEMGREP-JAVA-WEAK-CRYPTO",
        lang: ["java"],
        regex: /\bMessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1|SHA1)["']/gi,
        title: "Use of Weak Cryptographic Hash Algorithm",
        cwe: "CWE-327",
        severity: Severity.MEDIUM,
        desc: "Use of broken cryptographic hashing algorithm (MD5/SHA1)."
    },
    {
        id: "SEMGREP-JAVA-WEAK-RANDOM",
        lang: ["java"],
        regex: /\bnew\s+Random\s*\(/g,
        title: "Use of Insecure Pseudo-Random Number Generator",
        cwe: "CWE-330",
        severity: Severity.LOW,
        desc: "Use of java.util.Random for security-sensitive operations."
    },
    {
        id: "SEMGREP-JAVA-LDAP",
        lang: ["java"],
        regex: /\b(DirContext|InitialDirContext|LdapContext|\.search)\s*\(/g,
        title: "Potential LDAP Injection",
        cwe: "CWE-90",
        severity: Severity.HIGH,
        desc: "LDAP directory query execution."
    },
    {
        id: "SEMGREP-JAVA-XXE",
        lang: ["java"],
        regex: /\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(/g,
        title: "XML External Entity (XXE) Parsing",
        cwe: "CWE-611",
        severity: Severity.HIGH,
        desc: "XML parser initialization without explicit XXE protections."
    },
    {
        id: "SEMGREP-GO-HARDCODED-KEY",
        lang: ["go"],
        regex: /(api[_-]?key|secret|password)\s*[:=]\s*["`][a-zA-Z0-9_\-]{8,}["`]/gi,
        title: "Hardcoded Secret / Credential",
        cwe: "CWE-798",
        severity: Severity.MEDIUM,
        desc: "Hardcoded cryptographic secret or authentication token detected."
    },
    {
        id: "SEMGREP-GO-CMDI",
        lang: ["go"],
        regex: /\bexec\.Command\s*\(/g,
        title: "Command Execution",
        cwe: "CWE-78",
        severity: Severity.HIGH,
        desc: "Execution of OS command in Go."
    },
    {
        id: "SEMGREP-GO-SQLI",
        lang: ["go"],
        regex: /\b(db\.Query|db\.QueryRow|db\.Exec)\s*\(/g,
        title: "Database Query Execution",
        cwe: "CWE-89",
        severity: Severity.HIGH,
        desc: "Database SQL query execution."
    },
    {
        id: "SEMGREP-GENERIC-PATH-TRAVERSAL",
        lang: ["python", "java", "c", "cpp", "go"],
        regex: /\.\.\/|\.\.\\/g,
        title: "Static Path Traversal Sequence",
        cwe: "CWE-22",
        severity: Severity.MEDIUM,
        desc: "Directory traversal sequence detected in file handling."
    }
];

export class SemgrepTool extends ToolAdapter {
    get name() {
        return "semgrep";
    }

    get id() {
        return "semgrep";
    }

    get capabilities() {
        return ["sast_pattern_scan"];
    }

    get supportedLanguages() {
        return ["python", "java", "c", "cpp", "go"];
    }

    async checkInstalled() {
        const cmd = this.config.tool_paths?.semgrep || 'semgrep';
        const res = await runCommand(cmd, ['--version'], { timeout: 8000 });
        if (res.exitCode === 0) {
            return { installed: true, version: res.stdout.trim() };
        }
        return { installed: false, error: res.stderr || 'Semgrep CLI not found in PATH' };
    }

    async run(params) {
        const files = Array.isArray(params) ? params : (params.files || []);
        const outputDir = (params && params.outputDir) || 'hwsec-output/tools';
        const language = (params && params.language) || null;

        if (!fs.existsSync(outputDir)) {
            fs.mkdirSync(outputDir, { recursive: true });
        }

        const check = await this.checkInstalled();
        const telemetryPath = path.join(outputDir, 'semgrep_telemetry.json');

        if (check.installed) {
            // Run real Semgrep with structured JSON output
            const cmd = this.config.tool_paths?.semgrep || 'semgrep';
            const args = ['scan', '--json', '--quiet', ...files];
            const telemetry = await runCommand(cmd, args, { timeout: 120000 });

            fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');

            let parsedJson = null;
            try {
                parsedJson = JSON.parse(telemetry.stdout);
            } catch {
                parsedJson = { results: [] };
            }

            const findings = (parsedJson.results || []).map(r => createFinding({
                id: `SEMGREP-${crypto.randomBytes(4).toString('hex')}`,
                title: r.check_id || 'Semgrep Rule Violation',
                description: r.extra?.message || 'Pattern match found by Semgrep',
                severity: this._mapSeverity(r.extra?.severity),
                source_tool: this.name,
                source_locations: [{
                    path: r.path,
                    startLine: r.start?.line || 1,
                    endLine: r.end?.line || 1,
                    startColumn: r.start?.col || 1,
                    endColumn: r.end?.col || 1,
                    symbol: null
                }],
                evidence: [{
                    id: crypto.randomBytes(4).toString('hex'),
                    tool_name: this.name,
                    artifact_path: telemetryPath,
                    description: `Semgrep matched check ${r.check_id}`,
                    metadata: { rule_id: r.check_id, lines: r.extra?.lines }
                }],
                verification_state: "PROPOSED"
            }));

            return {
                status: telemetry.exitCode === 0 ? "SUCCESS" : "COMPLETED_WITH_FAILURES",
                findings,
                telemetry
            };
        } else {
            // High-fidelity fallback deterministic scanner
            const findings = [];
            const observations = [];

            const EXT_TO_LANG = {
                '.c': 'c',
                '.h': 'c',
                '.cpp': 'cpp',
                '.cc': 'cpp',
                '.cxx': 'cpp',
                '.hpp': 'cpp',
                '.py': 'python',
                '.java': 'java',
                '.go': 'go'
            };

            for (const filePath of files) {
                if (!fs.existsSync(filePath)) continue;
                const ext = path.extname(filePath).toLowerCase();
                const fileLang = EXT_TO_LANG[ext];
                const content = fs.readFileSync(filePath, 'utf-8');
                const lines = content.split('\n');

                for (const pattern of BUILTIN_PATTERNS) {
                    if (fileLang && !pattern.lang.includes(fileLang)) continue;
                    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
                        const line = lines[lineIdx];
                        pattern.regex.lastIndex = 0;
                        if (pattern.regex.test(line)) {
                            const lineNum = lineIdx + 1;
                            const evId = crypto.randomBytes(4).toString('hex');
                            findings.push(createFinding({
                                id: `SEMGREP-${crypto.randomBytes(4).toString('hex')}`,
                                title: `[${pattern.cwe}] ${pattern.title}`,
                                description: `${pattern.desc} Line ${lineNum}: \`${line.trim()}\``,
                                severity: pattern.severity,
                                source_tool: this.name,
                                source_locations: [{
                                    path: filePath,
                                    startLine: lineNum,
                                    endLine: lineNum,
                                    startColumn: 1,
                                    endColumn: line.length,
                                    symbol: null
                                }],
                                evidence: [{
                                    id: evId,
                                    tool_name: this.name,
                                    artifact_path: telemetryPath,
                                    description: `Pattern matched: ${pattern.title} at ${filePath}:${lineNum}`,
                                    metadata: { line: line.trim(), cwe: pattern.cwe }
                                }],
                                verification_state: "PROPOSED"
                            }));
                            observations.push({ file: filePath, line: lineNum, match: pattern.title });
                        }
                    }
                }
            }

            const telemetry = {
                mode: "builtin_sast_patterns",
                files_scanned: files.length,
                findings_count: findings.length,
                observations
            };
            fs.writeFileSync(telemetryPath, JSON.stringify(telemetry, null, 2), 'utf-8');

            return {
                status: "SUCCESS",
                findings,
                telemetry
            };
        }
    }

    _mapSeverity(semgrepSev) {
        switch ((semgrepSev || '').toUpperCase()) {
            case 'ERROR': return Severity.HIGH;
            case 'WARNING': return Severity.MEDIUM;
            case 'INFO': return Severity.LOW;
            default: return Severity.MEDIUM;
        }
    }
}
