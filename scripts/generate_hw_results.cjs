const fs = require('fs');
const sqlite = require('node:sqlite');
const path = require('path');

function generateReport(runId) {
    try {
        fs.copyFileSync('hwsec-output/hwsec.db', 'hwsec-output/hwsec_copy.db');
        const db = new sqlite.DatabaseSync('hwsec-output/hwsec_copy.db');
        const vFiles = db.prepare("SELECT * FROM files WHERE language IN ('verilog', 'systemverilog') AND run_id = ?").all(runId);
        
        const toolRuns = db.prepare("SELECT tool_name, status, exit_code, capability FROM tool_runs WHERE run_id = ?").all(runId);
        const findings = db.prepare("SELECT type, COUNT(*) as count FROM findings WHERE run_id = ? GROUP BY type").all(runId);
        const allFindings = db.prepare("SELECT * FROM findings WHERE run_id = ?").all(runId);
        const verified = db.prepare("SELECT COUNT(*) as count FROM findings WHERE run_id = ? AND verification_state = 'VERIFIED'").get(runId).count;

        const hardwareTools = toolRuns.filter(t => ['verilator', 'yosys', 'symbiyosys', 'afl++', 'slang', 'semgrep', 'joern'].includes(t.tool_name));
        
        let md = '# HWSEC Hardware Benchmark Results\n\n';
        md += '## 1. File Discovery & Analysis\n';
        md += '- **Total Verilog / SystemVerilog Files Discovered:** ' + vFiles.length + '\n';
        
        md += '\n## 2. Hardware Tool Execution Summary\n';
        md += '| Tool Name | Capability | Status | Exit Code |\n';
        md += '|-----------|------------|--------|-----------|\n';
        hardwareTools.forEach(t => {
            md += '| ' + t.tool_name + ' | ' + t.capability + ' | ' + t.status + ' | ' + (t.exit_code !== null ? t.exit_code : 'N/A') + ' |\n';
        });
        
        md += '\n## 3. Detected Hardware Vulnerabilities\n';
        md += '| CWE ID / Type | Vulnerability Count |\n';
        md += '|---------------|---------------------|\n';
        if (findings.length === 0) {
            md += '| *Analysis in progress...* | - |\n';
        } else {
            findings.forEach(f => {
                md += '| ' + (f.type || 'UNKNOWN') + ' | ' + f.count + ' |\n';
            });
        }

        md += '\n**Total Hardware Findings Logged:** ' + allFindings.length + '\n';
        md += '**Total Verified Security Findings:** ' + verified + '\n';
        
        const outDir = 'quality-benchmark';
        if (!fs.existsSync(outDir)) {
            fs.mkdirSync(outDir, { recursive: true });
        }
        
        fs.writeFileSync(path.join(outDir, 'HARDWARE_BENCHMARK_RESULTS.md'), md, 'utf8');
        console.log('[+] Wrote quality-benchmark/HARDWARE_BENCHMARK_RESULTS.md');
    } catch (e) {
        console.error('Error generating report:', e.message);
    }
}
generateReport('20260908061929-d8e2b231');
