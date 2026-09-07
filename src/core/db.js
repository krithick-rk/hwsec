import { DatabaseSync } from 'node:sqlite';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

export class Database {
    /**
     * @param {string} [dbPath='hwsec-output/hwsec.db']
     */
    constructor(dbPath = 'hwsec-output/hwsec.db') {
        this.dbPath = dbPath;
        if (dbPath !== ':memory:') {
            const dir = path.dirname(path.resolve(dbPath));
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        }
        this.db = new DatabaseSync(dbPath);
        this.initSchema();
    }

    /**
     * Calculates the SHA-256 hash of a file.
     * @param {string} filePath 
     * @returns {string}
     */
    static computeFileHash(filePath) {
        if (!fs.existsSync(filePath)) return '';
        const buffer = fs.readFileSync(filePath);
        return crypto.createHash('sha256').update(buffer).digest('hex');
    }

    /**
     * Calculates the SHA-256 hash of a JavaScript object or string.
     * @param {any} data 
     * @returns {string}
     */
    static computeObjectHash(data) {
        const str = typeof data === 'string' ? data : JSON.stringify(data);
        return crypto.createHash('sha256').update(str).digest('hex');
    }

    initSchema() {
        this.db.exec('PRAGMA foreign_keys = ON;');
        this.db.exec(`
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analysis_runs (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                status TEXT NOT NULL,
                config_hash TEXT,
                repository_hash TEXT,
                budget_allocated REAL DEFAULT 0.0,
                budget_consumed REAL DEFAULT 0.0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                path TEXT NOT NULL,
                language TEXT,
                sha256_hash TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                loc INTEGER DEFAULT 0,
                modified_time TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_files_path_hash ON files(path, sha256_hash);

            CREATE TABLE IF NOT EXISTS tool_runs (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                capability TEXT NOT NULL,
                status TEXT NOT NULL,
                exit_code INTEGER,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                artifact_dir TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                tool_run_id TEXT,
                file_id TEXT,
                artifact_path TEXT,
                artifact_hash TEXT,
                observation TEXT,
                raw_evidence TEXT,
                validity_status TEXT DEFAULT 'VALID',
                created_at TEXT NOT NULL,
                FOREIGN KEY (tool_run_id) REFERENCES tool_runs(id),
                FOREIGN KEY (file_id) REFERENCES files(id)
            );

            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                claim TEXT NOT NULL,
                status TEXT NOT NULL,
                rationale TEXT,
                proposed_test TEXT,
                supporting_evidence TEXT,
                contradicting_evidence TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                title TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                verification_state TEXT NOT NULL,
                location TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS verification_results (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                level TEXT NOT NULL,
                status TEXT NOT NULL,
                justification TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );

            CREATE TABLE IF NOT EXISTS graph_nodes (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                type TEXT NOT NULL,
                label TEXT NOT NULL,
                metadata TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id),
                FOREIGN KEY (source_id) REFERENCES graph_nodes(id),
                FOREIGN KEY (target_id) REFERENCES graph_nodes(id)
            );

            CREATE TABLE IF NOT EXISTS token_ledger (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                task_type TEXT NOT NULL,
                model_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                prompt_tokens INTEGER DEFAULT 0,
                completion_tokens INTEGER DEFAULT 0,
                total_tokens INTEGER DEFAULT 0,
                estimated_cost REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                run_id TEXT,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                metadata TEXT,
                timestamp TEXT NOT NULL
            );
        `);
    }

    saveProject({ id, path: projPath, name }) {
        const stmt = this.db.prepare(`
            INSERT INTO projects (id, path, name, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET name = excluded.name
        `);
        stmt.run(id, projPath, name, new Date().toISOString());
        return id;
    }

    saveAnalysisRun({ id, projectId = null, status, configHash = null, repositoryHash = null, budgetAllocated = 0, budgetConsumed = 0 }) {
        const now = new Date().toISOString();
        const stmt = this.db.prepare(`
            INSERT INTO analysis_runs (id, project_id, status, config_hash, repository_hash, budget_allocated, budget_consumed, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET 
                status = excluded.status,
                budget_consumed = excluded.budget_consumed,
                updated_at = excluded.updated_at
        `);
        stmt.run(id, projectId || null, status, configHash, repositoryHash, budgetAllocated, budgetConsumed, now, now);
        return id;
    }

    updateAnalysisRunStatus(id, status, budgetConsumed = null) {
        const now = new Date().toISOString();
        if (budgetConsumed !== null) {
            const stmt = this.db.prepare(`UPDATE analysis_runs SET status = ?, budget_consumed = ?, updated_at = ? WHERE id = ?`);
            stmt.run(status, budgetConsumed, now, id);
        } else {
            const stmt = this.db.prepare(`UPDATE analysis_runs SET status = ?, updated_at = ? WHERE id = ?`);
            stmt.run(status, now, id);
        }
    }

    saveFile({ id, runId, path: filePath, language, sha256Hash, size = 0, loc = 0, modifiedTime = null }) {
        const stmt = this.db.prepare(`
            INSERT INTO files (id, run_id, path, language, sha256_hash, size, loc, modified_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(id, runId, filePath, language, sha256Hash, size, loc, modifiedTime || new Date().toISOString());
        return id;
    }

    /**
     * Checks if a file has an unchanged previous analysis in the database.
     * @param {string} filePath 
     * @param {string} currentHash 
     * @returns {{reusable: boolean, previousRunId: string|null, reason: string}}
     */
    checkIncrementalReuse(filePath, currentHash) {
        const stmt = this.db.prepare(`
            SELECT run_id, sha256_hash, modified_time FROM files 
            WHERE path = ? 
            ORDER BY rowid DESC 
            LIMIT 1
        `);
        const row = stmt.get(filePath);
        if (!row) {
            return { reusable: false, previousRunId: null, reason: 'First time file is seen (no prior analysis record)' };
        }
        if (row.sha256_hash === currentHash) {
            return { reusable: true, previousRunId: row.run_id, reason: 'SHA-256 hash matches previous run; content unchanged' };
        }
        return { reusable: false, previousRunId: row.run_id, reason: 'File content modified (SHA-256 hash mismatch)' };
    }

    /**
     * Prunes or invalidates findings and file records for files no longer present in current file set.
     * @param {string[]} currentFiles - Array of valid, existing file paths
     * @param {string} [runId] - Optional runId filter
     */
    pruneStaleFiles(currentFiles = [], runId = null) {
        if (!Array.isArray(currentFiles)) return;
        const placeholders = currentFiles.map(() => '?').join(',');

        if (currentFiles.length === 0) {
            if (runId) {
                this.db.prepare(`DELETE FROM verification_results WHERE finding_id IN (SELECT id FROM findings WHERE run_id = ?)`).run(runId);
                this.db.prepare(`DELETE FROM findings WHERE run_id = ?`).run(runId);
                this.db.prepare(`DELETE FROM files WHERE run_id = ?`).run(runId);
            } else {
                this.db.prepare(`DELETE FROM verification_results`).run();
                this.db.prepare(`DELETE FROM findings`).run();
                this.db.prepare(`DELETE FROM files`).run();
            }
            return;
        }

        if (runId) {
            this.db.prepare(`
                DELETE FROM verification_results 
                WHERE finding_id IN (SELECT id FROM findings WHERE run_id = ? AND location NOT IN (${placeholders}))
            `).run(runId, ...currentFiles);

            this.db.prepare(`
                DELETE FROM findings 
                WHERE run_id = ? AND location NOT IN (${placeholders})
            `).run(runId, ...currentFiles);

            this.db.prepare(`
                DELETE FROM files 
                WHERE run_id = ? AND path NOT IN (${placeholders})
            `).run(runId, ...currentFiles);
        } else {
            this.db.prepare(`
                DELETE FROM verification_results 
                WHERE finding_id IN (SELECT id FROM findings WHERE location IS NOT NULL AND location NOT IN (${placeholders}))
            `).run(...currentFiles);

            this.db.prepare(`
                DELETE FROM findings 
                WHERE location IS NOT NULL AND location NOT IN (${placeholders})
            `).run(...currentFiles);

            this.db.prepare(`
                DELETE FROM files 
                WHERE path NOT IN (${placeholders})
            `).run(...currentFiles);
        }
    }

    saveToolRun({ id, runId, toolName, capability, status, exitCode = null, startedAt, finishedAt = null, artifactDir = null }) {
        const stmt = this.db.prepare(`
            INSERT INTO tool_runs (id, run_id, tool_name, capability, status, exit_code, started_at, finished_at, artifact_dir)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET status = excluded.status, finished_at = excluded.finished_at
        `);
        stmt.run(id, runId, toolName, capability, status, exitCode, startedAt, finishedAt, artifactDir);
        return id;
    }

    saveEvidence({ id, toolRunId = null, fileId = null, artifactPath = null, artifactHash = null, observation = null, rawEvidence = null, validityStatus = 'VALID' }) {
        const stmt = this.db.prepare(`
            INSERT INTO evidence (id, tool_run_id, file_id, artifact_path, artifact_hash, observation, raw_evidence, validity_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET observation = excluded.observation, validity_status = excluded.validity_status
        `);
        stmt.run(
            id,
            toolRunId || null,
            fileId || null,
            artifactPath || null,
            artifactHash || null,
            observation || null,
            typeof rawEvidence === 'object' ? JSON.stringify(rawEvidence) : (rawEvidence || null),
            validityStatus || 'VALID',
            new Date().toISOString()
        );
        return id;
    }

    saveHypothesis({ id, runId, claim, status, rationale = null, proposedTest = null, supportingEvidence = null, contradictingEvidence = null }) {
        const stmt = this.db.prepare(`
            INSERT INTO hypotheses (id, run_id, claim, status, rationale, proposed_test, supporting_evidence, contradicting_evidence, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET 
                run_id = excluded.run_id,
                claim = excluded.claim,
                status = excluded.status,
                rationale = excluded.rationale,
                proposed_test = excluded.proposed_test
        `);
        stmt.run(
            id, runId, claim, status, rationale || null, proposedTest || null,
            Array.isArray(supportingEvidence) ? JSON.stringify(supportingEvidence) : (supportingEvidence || null),
            Array.isArray(contradictingEvidence) ? JSON.stringify(contradictingEvidence) : (contradictingEvidence || null),
            new Date().toISOString()
        );
        return id;
    }

    saveFinding({ id, runId = 'global', title, type, severity, confidence = 0.5, verificationState, location = null }) {
        this.db.prepare(`
            INSERT OR IGNORE INTO analysis_runs (id, status, created_at, updated_at)
            VALUES (?, 'RUNNING', datetime('now'), datetime('now'))
        `).run(runId);

        const stmt = this.db.prepare(`
            INSERT INTO findings (id, run_id, title, type, severity, confidence, verification_state, location, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET 
                title = excluded.title,
                verification_state = excluded.verification_state,
                confidence = excluded.confidence
        `);
        stmt.run(id, runId, title, type, severity, confidence, verificationState, location || null, new Date().toISOString());
        return id;
    }

    saveVerificationResult({ id, findingId, level, status, justification, runId = 'global' }) {
        const stmt = this.db.prepare(`
            INSERT INTO verification_results (id, finding_id, level, status, justification, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET level = excluded.level, status = excluded.status, justification = excluded.justification
        `);
        stmt.run(id, findingId, level, status, justification || null, new Date().toISOString());
        return id;
    }

    saveGraphNode({ id, runId, type, label, metadata = null }) {
        const stmt = this.db.prepare(`
            INSERT INTO graph_nodes (id, run_id, type, label, metadata)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET label = excluded.label, metadata = excluded.metadata
        `);
        stmt.run(id, runId, type, label, typeof metadata === 'object' ? JSON.stringify(metadata) : metadata);
        return id;
    }

    saveGraphEdge({ id, runId, sourceId, targetId, relation, weight = 1.0 }) {
        const stmt = this.db.prepare(`
            INSERT INTO graph_edges (id, run_id, source_id, target_id, relation, weight)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET weight = excluded.weight
        `);
        stmt.run(id, runId, sourceId, targetId, relation, weight);
        return id;
    }

    getGraphNodes(runId) {
        return this.db.prepare(`SELECT * FROM graph_nodes WHERE run_id = ?`).all(runId);
    }

    getGraphEdges(runId) {
        return this.db.prepare(`SELECT * FROM graph_edges WHERE run_id = ?`).all(runId);
    }

    recordTokenUsage(entry) {
        const stmt = this.db.prepare(`
            INSERT INTO token_ledger (id, run_id, task_type, model_id, provider, prompt_tokens, completion_tokens, total_tokens, estimated_cost, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            entry.id, entry.analysis_id, entry.task_type, entry.model_id, entry.provider,
            entry.prompt_tokens, entry.completion_tokens, entry.total_tokens, entry.estimated_cost, entry.timestamp
        );
        return entry.id;
    }

    recordAuditEvent(event = {}) {
        const id = event.id || `AUDIT-${crypto.randomBytes(4).toString('hex')}`;
        const runId = event.runId || event.run_id || event.analysisId || null;
        const eventType = event.eventType || event.event_type || event.category || 'SYSTEM';
        const message = event.message || (typeof event.details === 'string' ? event.details : (event.details?.taskType ? `LLM Task: ${event.details.taskType}` : 'Audit event'));
        const metadata = event.metadata !== undefined ? event.metadata : (event.details || null);

        const stmt = this.db.prepare(`
            INSERT INTO audit_events (id, run_id, event_type, message, metadata, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        `);
        stmt.run(id, runId, eventType, message, typeof metadata === 'object' ? JSON.stringify(metadata) : (metadata || null), new Date().toISOString());
        return id;
    }

    /**
     * Purges all database records associated with a specific analysis run.
     * @param {string} runId
     */
    deleteAnalysisRun(runId) {
        this.db.exec('BEGIN TRANSACTION;');
        try {
            this.db.prepare(`DELETE FROM graph_edges WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM graph_nodes WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM token_ledger WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM audit_events WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM verification_results WHERE finding_id IN (SELECT id FROM findings WHERE run_id = ?)`).run(runId);
            this.db.prepare(`DELETE FROM findings WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM hypotheses WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM evidence WHERE tool_run_id IN (SELECT id FROM tool_runs WHERE run_id = ?)`).run(runId);
            this.db.prepare(`DELETE FROM tool_runs WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM files WHERE run_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM analysis_runs WHERE id = ?`).run(runId);
            this.db.exec('COMMIT;');
        } catch (err) {
            this.db.exec('ROLLBACK;');
            throw err;
        }
    }

    close() {
        this.db.close();
    }
}
