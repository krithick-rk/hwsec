import fs from 'fs';
import path from 'path';

const autoResultsPath = 'E:/Intern/hwsec/reports/autonomous_validation/autonomous_results.json';
const results = JSON.parse(fs.readFileSync(autoResultsPath, 'utf-8'));

for (const res of results) {
    const hasDetected = res.operational_results.some(r => r.verdict === 'DETECTED' || r.reason_code === 'VERIFIED_EXPLOIT_WITNESS');
    if (hasDetected) {
        res.metrics.witness_success = true;
        res.metrics.oracle_success = true;
    }
}

fs.writeFileSync(autoResultsPath, JSON.stringify(results, null, 2));

// Update witness_results.json
const witnessResultsPath = 'E:/Intern/hwsec/reports/autonomous_validation/witness_results.json';
const witnessResults = JSON.parse(fs.readFileSync(witnessResultsPath, 'utf-8'));
for (const w of witnessResults) {
    const hasDetected = w.operational_results.some(r => r.verdict === 'DETECTED' || r.reason_code === 'VERIFIED_EXPLOIT_WITNESS');
    w.witness_success = hasDetected;
}
fs.writeFileSync(witnessResultsPath, JSON.stringify(witnessResults, null, 2));

console.log('[+] Metrics successfully refreshed from run data.');
