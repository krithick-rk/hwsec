import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { spawnSync } from 'child_process';

const RULE_TO_CWE = {
    'java/path-injection': 'CWE-22',
    'java/command-line-injection': 'CWE-78',
    'java/sql-injection': 'CWE-89',
    'java/xss': 'CWE-79',
    'java/ldap-injection': 'CWE-90',
    'java/xml/xpath-injection': 'CWE-643'
};

export class CodeQLDiscoveryWorker {
    constructor(options = {}) {
        this.analyzerName = 'codeql';
        this.analyzerVersion = '2.26.4';
        this.wslDistro = options.wslDistro || 'Ubuntu';
        this.codeqlBin = options.codeqlBin || '/home/intern/tools/codeql/codeql';
        this.jdk21Home = options.jdk21Home || '/usr/lib/jvm/java-21-openjdk-amd64';
        this.dbPath = options.dbPath || '/home/intern/hwsec-workspace/codeql-java-db';
        this.sarifWslPath = options.sarifWslPath || '/home/intern/hwsec-workspace/codeql-results.sarif';
        this.sarifLocalPath = path.resolve(options.sarifLocalPath || 'prototype/artifacts/codeql-results.sarif');
        this.ramMb = options.ramMb || 8192;
        this.threads = options.threads || 2;
        this.cachedSarifResults = null;
    }

    async probeStatus() {
        try {
            const probeCmd = `JAVA_HOME=${this.jdk21Home} ${this.codeqlBin} version --format=json`;
            const res = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', probeCmd], {
                encoding: 'utf8',
                timeout: 5000
            });

            if (res.status === 0) {
                const parsed = JSON.parse(res.stdout);
                return {
                    available: true,
                    status: 'AVAILABLE',
                    version: parsed.version || '2.26.4',
                    isWsl: true,
                    jdk: 'Java 21 (OpenJDK 21.0.12)',
                    ram_mb: this.ramMb,
                    threads: this.threads
                };
            }
        } catch {}

        return {
            available: false,
            status: 'UNAVAILABLE',
            reason: 'CodeQL CLI is not installed on host or WSL environment',
            findings_generated: 0
        };
    }

    ensureSarifAnalysis() {
        if (this.cachedSarifResults) return this.cachedSarifResults;

        // Check if local cache file exists
        if (fs.existsSync(this.sarifLocalPath)) {
            try {
                const content = fs.readFileSync(this.sarifLocalPath, 'utf8');
                const sarifData = JSON.parse(content);
                this.cachedSarifResults = sarifData.runs?.[0]?.results || [];
                return this.cachedSarifResults;
            } catch (_) {}
        }

        // Check if SARIF file exists in WSL; if not, run analysis
        const checkCmd = `test -f ${this.sarifWslPath} && echo "EXISTS" || echo "MISSING"`;
        const checkRes = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', checkCmd], { encoding: 'utf8' });

        if (!checkRes.stdout.includes('EXISTS')) {
            // Ensure Database exists
            const dbCheck = `test -d ${this.dbPath} && echo "EXISTS" || echo "MISSING"`;
            const dbRes = spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', dbCheck], { encoding: 'utf8' });

            if (!dbRes.stdout.includes('EXISTS')) {
                const createCmd = `JAVA_HOME=${this.jdk21Home} ${this.codeqlBin} database create ${this.dbPath} --language=java --source-root=/home/intern/hwsec-workspace/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode --build-mode=none --ram=${this.ramMb} --threads=${this.threads} --overwrite`;
                spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', createCmd], {
                    encoding: 'utf8',
                    timeout: 180000
                });
            }

            const queryPacks = [
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-022/TaintedPath.ql',
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-078/ExecTainted.ql',
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-089/SqlTainted.ql',
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-079/XSS.ql',
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-090/LdapInjection.ql',
                '/home/intern/tools/codeql/qlpacks/codeql/java-queries/1.11.9/Security/CWE/CWE-643/XPathInjection.ql'
            ].join(' ');

            const analyzeCmd = `JAVA_HOME=${this.jdk21Home} ${this.codeqlBin} database analyze ${this.dbPath} ${queryPacks} --format=sarif-latest --output=${this.sarifWslPath} --ram=${this.ramMb} --threads=${this.threads}`;
            spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', analyzeCmd], {
                encoding: 'utf8',
                timeout: 180000
            });
        }

        // Copy to Windows local path for fast I/O
        fs.mkdirSync(path.dirname(this.sarifLocalPath), { recursive: true });
        spawnSync('wsl', ['-d', this.wslDistro, '--', 'bash', '-c', `cp ${this.sarifWslPath} /mnt/e/Intern/hwsec/prototype/artifacts/codeql-results.sarif`], {
            encoding: 'utf8'
        });

        if (fs.existsSync(this.sarifLocalPath)) {
            try {
                const content = fs.readFileSync(this.sarifLocalPath, 'utf8');
                const sarifData = JSON.parse(content);
                this.cachedSarifResults = sarifData.runs?.[0]?.results || [];
            } catch {
                this.cachedSarifResults = [];
            }
        } else {
            this.cachedSarifResults = [];
        }

        return this.cachedSarifResults;
    }

    async scanFile(caseObj, benchmarkRoot) {
        const probe = await this.probeStatus();
        if (!probe.available) {
            return {
                status: 'UNAVAILABLE',
                case_id: caseObj.case_id,
                analyzer: this.analyzerName,
                findings: [],
                telemetry: probe
            };
        }

        const sarifResults = this.ensureSarifAnalysis();
        const caseFileName = `${caseObj.case_id}.java`;
        const findings = [];

        for (const r of sarifResults) {
            const physLoc = r.locations?.[0]?.physicalLocation;
            const uri = physLoc?.artifactLocation?.uri || '';

            if (uri.endsWith(caseFileName) || uri.includes(caseObj.case_id)) {
                const ruleId = r.ruleId || 'unknown';
                const cwe = RULE_TO_CWE[ruleId] || caseObj.cwe;
                const line = physLoc?.region?.startLine || 1;
                const col = physLoc?.region?.startColumn || 1;
                const message = r.message?.text || 'CodeQL finding';

                const findingId = `FINDING-${caseObj.case_id}-${cwe}-codeql-${crypto.createHash('sha256').update(`${caseObj.case_id}:${line}:${ruleId}`).digest('hex').substring(0, 8)}`;

                const pathHint = [
                    caseObj.entrypoint_method || 'doPost',
                    `${caseFileName}:${line}`
                ];

                findings.push({
                    finding_id: findingId,
                    case_id: caseObj.case_id,
                    cwe: cwe,
                    analyzer: this.analyzerName,
                    analyzer_version: this.analyzerVersion,
                    source_file: caseObj.source_path.replace(/\\/g, '/'),
                    source_locations: [
                        {
                            path: caseObj.source_path.replace(/\\/g, '/'),
                            line: line,
                            column: col
                        }
                    ],
                    source_boundary: 'HttpServletRequest.getParameter',
                    sink: message.substring(0, 80),
                    path_hint: pathHint,
                    severity: 'HIGH',
                    confidence: 0.90,
                    rule_id: ruleId,
                    timestamp: new Date().toISOString()
                });
            }
        }

        return {
            status: 'SUCCESS',
            case_id: caseObj.case_id,
            analyzer: this.analyzerName,
            findings: findings,
            telemetry: probe
        };
    }
}
