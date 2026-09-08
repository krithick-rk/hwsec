import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { HWSECQdrantMemory } from './qdrantClient.js';

/**
 * ProofMemoryStore
 * 
 * Implements Section 16 (Learning / Memory):
 * Persists proof outcomes into the local SQLite database and Qdrant memory.
 * Stores:
 * - successful proof strategies
 * - failed proof strategies
 * - proof types that work for each vulnerability class (CWE)
 * - required tool combinations
 * - typical runtime
 * - typical token cost
 * 
 * Provides recommendation retrieval to reduce repeated trial-and-error.
 */
export class ProofMemoryStore {
    /**
     * @param {Object} [db] Database instance
     * @param {Object} [config] Configuration object
     */
    constructor(db = null, config = {}) {
        this.db = db;
        this.config = config || {};
        this.inMemoryOutcomes = [];

        // Baseline knowledge of proven strategies per CWE / family
        this.baselineStrategies = [
            {
                cwe: 'CWE-119',
                domain: 'software',
                languages: ['c', 'cpp'],
                proof_type: 'MINIMAL_INPUT',
                tool_chain: ['gcc', 'asan'],
                avg_runtime_s: 12,
                avg_tokens: 4500,
                success_rate: 0.92,
                notes: 'AddressSanitizer compilation with minimal oversized input buffer trigger'
            },
            {
                cwe: 'CWE-120',
                domain: 'software',
                languages: ['c', 'cpp'],
                proof_type: 'MINIMAL_INPUT',
                tool_chain: ['gcc', 'asan'],
                avg_runtime_s: 10,
                avg_tokens: 4000,
                success_rate: 0.90,
                notes: 'Classic buffer copy overflow trigger via unbounded input'
            },
            {
                cwe: 'CWE-416',
                domain: 'software',
                languages: ['c', 'cpp'],
                proof_type: 'TARGETED_HARNESS',
                tool_chain: ['clang', 'asan'],
                avg_runtime_s: 18,
                avg_tokens: 6000,
                success_rate: 0.85,
                notes: 'Targeted callback invocation exercising freed pointer'
            },
            {
                cwe: 'CWE-78',
                domain: 'software',
                languages: ['python', 'java', 'go'],
                proof_type: 'REGRESSION_TEST',
                tool_chain: ['python3', 'pytest'],
                avg_runtime_s: 6,
                avg_tokens: 3500,
                success_rate: 0.95,
                notes: 'Local subprocess call with command injection payload to fixture file'
            },
            {
                cwe: 'CWE-22',
                domain: 'software',
                languages: ['python', 'java', 'c'],
                proof_type: 'REGRESSION_TEST',
                tool_chain: ['python3', 'pytest'],
                avg_runtime_s: 5,
                avg_tokens: 3000,
                success_rate: 0.94,
                notes: 'Relative path traversal directory escape probe inside fixture directory'
            },
            {
                cwe: 'CWE-1234',
                domain: 'hardware',
                languages: ['verilog', 'systemverilog'],
                proof_type: 'FORMAL_COUNTEREXAMPLE',
                tool_chain: ['sby', 'yosys'],
                avg_runtime_s: 25,
                avg_tokens: 5500,
                success_rate: 0.88,
                notes: 'SymbiYosys BMC depth=20 formal assertion violation generating VCD'
            },
            {
                cwe: 'CWE-1271',
                domain: 'hardware',
                languages: ['verilog', 'systemverilog'],
                proof_type: 'FORMAL_COUNTEREXAMPLE',
                tool_chain: ['sby', 'yosys'],
                avg_runtime_s: 20,
                avg_tokens: 4800,
                success_rate: 0.90,
                notes: 'Reset assertion check identifying uninitialized registers at step 0'
            },
            {
                cwe: 'CWE-1256',
                domain: 'hardware',
                languages: ['verilog', 'systemverilog'],
                proof_type: 'FORMAL_COUNTEREXAMPLE',
                tool_chain: ['sby', 'yosys', 'verilator'],
                avg_runtime_s: 30,
                avg_tokens: 6200,
                success_rate: 0.82,
                notes: 'Bus master privilege bypass counterexample trace'
            }
        ];

        // Initialize Qdrant if configured
        this.qdrant = null;
        if (config.qdrant?.enabled && config.qdrant?.url) {
            try {
                this.qdrant = new HWSECQdrantMemory(config.qdrant.url);
            } catch (e) {
                // Qdrant optional
            }
        }
    }

    /**
     * Records an executed proof outcome for future learning and optimization.
     * @param {Object} entry 
     */
    async recordOutcome(entry = {}) {
        const record = {
            id: entry.id || `MEM-${crypto.randomBytes(6).toString('hex')}`,
            cwe: entry.cwe || 'CWE-UNKNOWN',
            domain: entry.domain || 'software',
            language: entry.language || 'c',
            proof_type: entry.proof_type || 'REGRESSION_TEST',
            tool_chain: entry.tool_chain || [],
            success: !!entry.success,
            reproducibility_rate: entry.reproducibility_rate || '0/0',
            runtime_seconds: Number(entry.runtime_seconds) || 0,
            tokens_used: Number(entry.tokens_used) || 0,
            impact_class: entry.impact_class || 'INFORMATIONAL_ONLY',
            timestamp: new Date().toISOString()
        };

        this.inMemoryOutcomes.push(record);

        // Persist to audit_events in SQLite if available
        if (this.db && this.db.db) {
            try {
                const stmt = this.db.db.prepare(`
                    INSERT INTO audit_events (id, run_id, event_type, message, metadata, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                `);
                stmt.run(
                    record.id,
                    entry.run_id || 'global',
                    record.success ? 'PROOF_SUCCESS_MEMORY' : 'PROOF_FAILURE_MEMORY',
                    `Recorded proof outcome for ${record.cwe} (${record.proof_type}) with success=${record.success}`,
                    JSON.stringify(record),
                    record.timestamp
                );
            } catch (e) {
                // non-fatal
            }
        }

        // Sync to Qdrant if available
        if (this.qdrant && typeof this.qdrant.upsertHypothesis === 'function') {
            try {
                await this.qdrant.upsertHypothesis({
                    hypothesis_id: record.id,
                    cwe_id: record.cwe,
                    title: `Proof Pattern for ${record.cwe}`,
                    claim: `Strategy: ${record.proof_type}, Tools: ${record.tool_chain.join('+')}, Success: ${record.success}`,
                    severity: record.success ? 'HIGH' : 'LOW'
                });
            } catch (e) {
                // non-fatal
            }
        }

        return record.id;
    }

    /**
     * Retrieves the recommended proof strategy and tool chain for a CWE / vulnerability.
     * @param {string} cweId 
     * @param {string} domain 'software' | 'hardware'
     * @param {string} [language]
     * @returns {Object} StrategyRecommendation
     */
    getRecommendedStrategy(cweId, domain = 'software', language = null) {
        const cweNorm = (cweId || '').toUpperCase().trim();
        const langNorm = (language || '').toLowerCase().trim();

        // Check in-memory historical outcomes first
        const historicalMatches = this.inMemoryOutcomes.filter(o => 
            o.cwe === cweNorm && (domain ? o.domain === domain : true) && o.success
        );

        if (historicalMatches.length > 0) {
            const latest = historicalMatches[historicalMatches.length - 1];
            return {
                source: 'historical_memory',
                cwe: cweNorm,
                proof_type: latest.proof_type,
                tool_chain: latest.tool_chain,
                avg_runtime_s: latest.runtime_seconds,
                avg_tokens: latest.tokens_used,
                confidence: 0.95,
                notes: `Learned from previous successful reproduction (${latest.reproducibility_rate})`
            };
        }

        // Check baseline curated knowledge
        const baselineMatch = this.baselineStrategies.find(s => 
            s.cwe === cweNorm && s.domain === domain && (!langNorm || s.languages.includes(langNorm))
        );

        if (baselineMatch) {
            return {
                source: 'curated_baseline',
                cwe: baselineMatch.cwe,
                proof_type: baselineMatch.proof_type,
                tool_chain: baselineMatch.tool_chain,
                avg_runtime_s: baselineMatch.avg_runtime_s,
                avg_tokens: baselineMatch.avg_tokens,
                confidence: baselineMatch.success_rate,
                notes: baselineMatch.notes
            };
        }

        // Domain-based fallback
        if (domain === 'hardware') {
            return {
                source: 'domain_fallback',
                cwe: cweNorm || 'CWE-HARDWARE',
                proof_type: 'FORMAL_COUNTEREXAMPLE',
                tool_chain: ['sby', 'yosys'],
                avg_runtime_s: 25,
                avg_tokens: 5000,
                confidence: 0.70,
                notes: 'Default hardware formal bounded property check'
            };
        }

        return {
            source: 'domain_fallback',
            cwe: cweNorm || 'CWE-SOFTWARE',
            proof_type: 'REGRESSION_TEST',
            tool_chain: langNorm === 'c' || langNorm === 'cpp' ? ['gcc', 'asan'] : ['pytest'],
            avg_runtime_s: 10,
            avg_tokens: 3500,
            confidence: 0.70,
            notes: 'Default software minimal regression fixture'
        };
    }
}
