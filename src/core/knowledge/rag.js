import fs from 'fs';
import path from 'path';
import { HWSECQdrantMemory } from './qdrantClient.js';

/**
 * Three logically separated local knowledge stores for HWSEC
 */

export class SecurityKnowledgeStore {
    constructor() {
        this.records = [
            { id: "CWE-120", category: "Memory", title: "Buffer Copy without Checking Size of Input", languages: ["c", "cpp"], advice: "Replace strcpy/sprintf with bounds-checked variants." },
            { id: "CWE-78", category: "Injection", title: "Improper Neutralization of Special Elements in OS Command", languages: ["python", "go", "java"], advice: "Use execFile/array arguments, avoid shell=True." },
            { id: "CWE-502", category: "Deserialization", title: "Deserialization of Untrusted Data", languages: ["java", "python"], advice: "Do not deserialize untrusted streams via ObjectInputStream or pickle." },
            { id: "CWE-798", category: "Credentials", title: "Use of Hard-coded Credentials", languages: ["c", "cpp", "go", "python", "java", "verilog"], advice: "Extract credentials to environment variables or secret vaults." },
            { id: "CWE-22", category: "Path Traversal", title: "Improper Limitation of a Pathname to a Restricted Directory", languages: ["c", "cpp", "go", "python", "java"], advice: "Sanitize relative paths and validate against base root directory." },
            { id: "CWE-1234", category: "Hardware", title: "Hardware State Machine Desynchronization", languages: ["verilog"], advice: "Verify default states, synchronous resets, and illegal state traps." },
            { id: "CWE-1271", category: "Hardware", title: "Uninitialized Registers on Power-On", languages: ["verilog"], advice: "Ensure all registers and state variables have explicit reset clauses." },
            { id: "CWE-1256", category: "Hardware", title: "Improper Access Control for Hardware Reg/Bus", languages: ["verilog"], advice: "Verify bus master privilege checks before decoding CSR or memory writes." },
            { id: "CWE-1277", category: "Hardware", title: "Firmware / Hardware Trust Boundary Bypass", languages: ["verilog"], advice: "Validate clock domain crossing and trust boundary filters." },
            { id: "CWE-1189", category: "Hardware", title: "Improper Isolation of Shared Resources on SoC", languages: ["verilog"], advice: "Isolate shared buffers and clear pipeline stages between security contexts." },
            { id: "CWE-1300", category: "Hardware", title: "Improper Protection of Physical/Debug Interface", languages: ["verilog"], advice: "Disable JTAG/BIST debug modes during secure production mission state." }
        ];
    }

    query(queryText, language = null, limit = 3) {
        const q = queryText.toLowerCase();
        let matches = this.records.filter(r => {
            const langMatch = !language || r.languages.includes(language.toLowerCase());
            const textMatch = r.title.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.category.toLowerCase().includes(q);
            return langMatch && textMatch;
        });

        if (matches.length === 0 && language) {
            matches = this.records.filter(r => r.languages.includes(language.toLowerCase()));
        }

        return matches.slice(0, limit);
    }
}

export class ProjectKnowledgeStore {
    constructor() {
        this.docs = [];
    }

    indexRepository(repoDir) {
        this.docs = [];
        const candidateFiles = ['README.md', 'spec.md', 'ARCHITECTURE.md', 'SECURITY.md', 'API.md'];
        
        for (const f of candidateFiles) {
            const p = path.join(repoDir, f);
            if (fs.existsSync(p)) {
                try {
                    const rawContent = fs.readFileSync(p, 'utf-8');
                    const boundedContent = `<UNTRUSTED_REPOSITORY_CONTENT>\n<!-- File: ${f} -->\n${rawContent.slice(0, 5000)}\n</UNTRUSTED_REPOSITORY_CONTENT>`;
                    this.docs.push({ name: f, path: p, content: boundedContent });
                } catch {}
            }
        }
    }

    addSpecification(specPath) {
        if (specPath && fs.existsSync(specPath)) {
            try {
                const rawContent = fs.readFileSync(specPath, 'utf-8');
                const baseName = path.basename(specPath);
                const boundedContent = `<UNTRUSTED_REPOSITORY_CONTENT>\n<!-- File: ${baseName} -->\n${rawContent.slice(0, 10000)}\n</UNTRUSTED_REPOSITORY_CONTENT>`;
                this.docs.push({ name: baseName, path: specPath, content: boundedContent });
            } catch {}
        }
    }

    query(queryText, limit = 2) {
        const q = queryText.toLowerCase();
        return this.docs.filter(d => d.content.toLowerCase().includes(q) || d.name.toLowerCase().includes(q)).slice(0, limit);
    }
}

export class AuditMemoryStore {
    constructor(db = null) {
        this.db = db;
        this.memoryEntries = [];
    }

    addEntry(entry) {
        this.memoryEntries.push({
            ...entry,
            timestamp: new Date().toISOString()
        });
    }

    query(queryText, limit = 3) {
        const q = queryText.toLowerCase();
        const memMatches = this.memoryEntries.filter(m => (m.claim || m.title || '').toLowerCase().includes(q));
        if (this.db && this.db.db) {
            try {
                const dbRows = this.db.db.prepare(`
                    SELECT event_type as title, message as claim, timestamp 
                    FROM audit_events 
                    WHERE message LIKE ? OR event_type LIKE ?
                    LIMIT ?
                `).all(`%${queryText}%`, `%${queryText}%`, limit);
                return [...memMatches, ...dbRows].slice(0, limit);
            } catch {}
        }
        return memMatches.slice(0, limit);
    }
}

export class RAGEngine {
    constructor(db = null, config = {}) {
        if (db && typeof db.getProject === 'undefined' && typeof db.db === 'undefined' && !config.qdrant && (db.qdrant || db.llm_providers)) {
            config = db;
            db = null;
        }
        this.db = db;
        this.config = config || {};
        this.securityStore = new SecurityKnowledgeStore();
        this.projectStore = new ProjectKnowledgeStore();
        this.auditStore = new AuditMemoryStore(db);
        this.qdrant = new HWSECQdrantMemory(this.config);
    }

    /**
     * Populates initial security pattern vectors into Qdrant if available
     */
    async syncToQdrant() {
        if (!await this.qdrant.isAvailable()) return false;

        const points = this.securityStore.records.map(r => ({
            id: undefined,
            text: `${r.id} ${r.title} ${r.category} ${r.languages.join(' ')} ${r.advice}`,
            payload: {
                id: r.id,
                title: r.title,
                category: r.category,
                languages: r.languages,
                advice: r.advice,
                type: 'cwe_pattern'
            }
        }));

        await this.qdrant.upsertPoints('cwe_patterns', points);
        return true;
    }

    /**
     * Semantic vector search via Qdrant with metadata filters and fallback
     */
    async retrieveSemanticContext({ query, language = null, repoDir = null, specPath = null, limit = 3 }) {
        if (repoDir) this.projectStore.indexRepository(repoDir);
        if (specPath) this.projectStore.addSpecification(specPath);

        const qdrantAvailable = await this.qdrant.isAvailable();
        if (qdrantAvailable) {
            try {
                // Ensure initial vectors exist
                await this.syncToQdrant();

                // Vector search on CWE patterns
                const filter = language ? {
                    must: [{ key: 'languages', match: { value: language.toLowerCase() } }]
                } : null;

                const qdrantHits = await this.qdrant.search('cwe_patterns', {
                    queryText: query,
                    filter,
                    limit
                });

                if (qdrantHits.length > 0) {
                    const secKnowledge = qdrantHits.map(h => h.payload);
                    const projKnowledge = this.projectStore.query(query, 2);
                    const pastAudit = this.auditStore.query(query, 2);

                    return {
                        source: 'qdrant_vector',
                        security_knowledge: secKnowledge,
                        project_specifications: projKnowledge.map(p => ({ file: p.name, snippet: p.content.slice(0, 1000) })),
                        audit_memory: pastAudit
                    };
                }
            } catch {}
        }

        // Fallback to in-memory keyword matching
        return {
            source: 'in_memory_keyword',
            ...this.retrieveContext({ query, language, repoDir, specPath, limit })
        };
    }

    /**
     * Constructs a focused RAG context without dumping whole repositories (Synchronous / In-memory fallback).
     */
    retrieveContext({ query, language = null, repoDir = null, specPath = null, limit = 3 }) {
        if (repoDir) this.projectStore.indexRepository(repoDir);
        if (specPath) this.projectStore.addSpecification(specPath);

        const secKnowledge = this.securityStore.query(query, language, limit);
        const projKnowledge = this.projectStore.query(query, 2);
        const pastAudit = this.auditStore.query(query, 2);

        return {
            security_knowledge: secKnowledge,
            project_specifications: projKnowledge.map(p => ({ file: p.name, snippet: p.content.slice(0, 1000) })),
            audit_memory: pastAudit
        };
    }
}
