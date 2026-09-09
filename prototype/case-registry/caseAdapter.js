import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Case Registry and Adapter for OWASP Benchmark Subset
 * 
 * Provides deterministic mapping of selected benchmark cases to known target
 * classes, entrypoint methods, input mechanisms, and security sinks.
 */
export class CaseAdapter {
    constructor(registryPath = null) {
        this.registryPath = registryPath || path.resolve('prototype/case-registry/registry.json');
        this.cases = this.loadRegistry();
    }

    loadRegistry() {
        if (!fs.existsSync(this.registryPath)) {
            throw new Error(`Registry file not found at: ${this.registryPath}`);
        }
        const data = JSON.parse(fs.readFileSync(this.registryPath, 'utf8'));
        if (!Array.isArray(data) || data.length === 0) {
            throw new Error('Case registry must contain a non-empty array of cases.');
        }
        return data;
    }

    getAllCases() {
        return [...this.cases];
    }

    getCaseCount() {
        return this.cases.length;
    }

    getCaseById(caseId) {
        const found = this.cases.find(c => c.case_id === caseId || c.case_id === `BenchmarkTest${caseId}`);
        return found ? { ...found } : null;
    }

    getCasesByCWE(cwe) {
        const norm = cwe.startsWith('CWE-') ? cwe : `CWE-${cwe}`;
        return this.cases.filter(c => c.cwe === norm).map(c => ({ ...c }));
    }

    /**
     * Verifies on-disk existence and cryptographic integrity of all registered cases.
     * @param {string} benchmarkRoot Root directory of the OWASP Benchmark
     * @returns {{ valid: boolean, errors: Array<string>, verifiedCount: number }}
     */
    verifyCorpusIntegrity(benchmarkRoot) {
        const errors = [];
        let verifiedCount = 0;

        for (const c of this.cases) {
            const fullPath = path.join(benchmarkRoot, c.source_path);
            if (!fs.existsSync(fullPath)) {
                errors.push(`Missing case source: ${c.case_id} at ${fullPath}`);
                continue;
            }

            const content = fs.readFileSync(fullPath, 'utf8');
            const digest = crypto.createHash('sha256').update(content).digest('hex');
            if (digest !== c.source_sha256) {
                errors.push(`Digest mismatch for ${c.case_id}: expected ${c.source_sha256}, got ${digest}`);
                continue;
            }

            verifiedCount++;
        }

        return {
            valid: errors.length === 0,
            errors,
            verifiedCount
        };
    }

    /**
     * Builds harness execution metadata for a given case.
     * @param {string} caseId
     * @param {string} inputPayload
     * @returns {Object} Harness invocation configuration
     */
    getHarnessConfig(caseId, inputPayload = '') {
        const c = this.getCaseById(caseId);
        if (!c) {
            throw new Error(`Case ${caseId} not found in registry.`);
        }

        return {
            caseId: c.case_id,
            targetClass: c.target_class,
            method: c.entrypoint_method,
            inputVectorType: c.input_vector_type,
            paramName: c.input_param_name,
            inputValue: inputPayload,
            cwe: c.cwe,
            sinkType: c.sink_type
        };
    }
}
