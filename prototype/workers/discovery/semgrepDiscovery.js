import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

const SEMGREP_PATTERNS = [
    {
        id: 'JAVA-PATH-TRAVERSAL',
        cwe: 'CWE-22',
        regex: /(new\s+(java\.io\.)?File\s*\(|new\s+(java\.io\.)?FileInputStream\s*\(|new\s+(java\.io\.)?FileOutputStream\s*\(|(java\.nio\.file\.)?Paths\.get\s*\()/g,
        sinkType: 'java.io.File / Stream',
        severity: 'HIGH',
        confidence: 0.85
    },
    {
        id: 'JAVA-COMMAND-INJECTION',
        cwe: 'CWE-78',
        regex: /(Runtime\.getRuntime\(\)\.exec\s*\(|new\s+(java\.lang\.)?ProcessBuilder\s*\()/g,
        sinkType: 'java.lang.Runtime.exec / ProcessBuilder',
        severity: 'CRITICAL',
        confidence: 0.90
    },
    {
        id: 'JAVA-SQL-INJECTION',
        cwe: 'CWE-89',
        regex: /(\.executeQuery\s*\(|\.executeUpdate\s*\(|\.execute\s*\(|\.addBatch\s*\()/g,
        sinkType: 'java.sql.Statement / PreparedStatement',
        severity: 'HIGH',
        confidence: 0.85
    },
    {
        id: 'JAVA-XSS',
        cwe: 'CWE-79',
        regex: /(\.getWriter\(\)\.print(ln)?\s*\(|\.getWriter\(\)\.write\s*\()/g,
        sinkType: 'javax.servlet.http.HttpServletResponse.getWriter',
        severity: 'MEDIUM',
        confidence: 0.80
    },
    {
        id: 'JAVA-LDAP-INJECTION',
        cwe: 'CWE-90',
        regex: /(\.search\s*\([^,]+,[^,]+,[^,]+DirContext|\.search\s*\()/g,
        sinkType: 'javax.naming.directory.DirContext.search',
        severity: 'HIGH',
        confidence: 0.85
    },
    {
        id: 'JAVA-XPATH-INJECTION',
        cwe: 'CWE-643',
        regex: /(\.evaluate\s*\(|\.compile\s*\()/g,
        sinkType: 'javax.xml.xpath.XPath.evaluate',
        severity: 'HIGH',
        confidence: 0.85
    }
];

export class SemgrepDiscoveryWorker {
    constructor() {
        this.analyzerName = 'semgrep';
        this.analyzerVersion = '1.0.0-pattern';
    }

    async scanFile(caseObj, benchmarkRoot) {
        const fullPath = path.resolve(benchmarkRoot, caseObj.source_path);
        if (!fs.existsSync(fullPath)) {
            throw new Error(`Target source file not found: ${fullPath}`);
        }

        const content = fs.readFileSync(fullPath, 'utf8');
        const lines = content.split('\n');
        const findings = [];

        // Identify untrusted source entrypoint/boundaries
        let sourceBoundary = 'HttpServletRequest.getParameter';
        if (content.includes('request.getCookies')) {
            sourceBoundary = 'HttpServletRequest.getCookies';
        } else if (content.includes('request.getHeader')) {
            sourceBoundary = 'HttpServletRequest.getHeader';
        }

        for (const pattern of SEMGREP_PATTERNS) {
            for (let i = 0; i < lines.length; i++) {
                const lineContent = lines[i];
                pattern.regex.lastIndex = 0;
                const match = pattern.regex.exec(lineContent);
                if (match) {
                    const col = match.index + 1;
                    const findingId = `FINDING-${caseObj.case_id}-${pattern.cwe}-${crypto.createHash('sha256').update(`${caseObj.case_id}:${i + 1}:${pattern.id}`).digest('hex').substring(0, 8)}`;
                    
                    const pathHint = [];
                    pathHint.push(`${caseObj.entrypoint_method || 'doPost'}`);
                    pathHint.push(`${path.basename(caseObj.source_path)}:${i + 1}`);

                    findings.push({
                        finding_id: findingId,
                        case_id: caseObj.case_id,
                        cwe: pattern.cwe,
                        analyzer: this.analyzerName,
                        analyzer_version: this.analyzerVersion,
                        source_file: caseObj.source_path.replace(/\\/g, '/'),
                        source_locations: [
                            {
                                path: caseObj.source_path.replace(/\\/g, '/'),
                                line: i + 1,
                                column: col
                            }
                        ],
                        source_boundary: sourceBoundary,
                        sink: match[1].trim(),
                        path_hint: pathHint,
                        severity: pattern.severity,
                        confidence: pattern.confidence,
                        rule_id: pattern.id,
                        timestamp: new Date().toISOString()
                    });
                }
            }
        }

        return findings;
    }
}
