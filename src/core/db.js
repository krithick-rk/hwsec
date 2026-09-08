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

            CREATE TABLE IF NOT EXISTS exploit_attempts (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                state TEXT NOT NULL,
                decision TEXT NOT NULL,
                provider TEXT,
                model TEXT,
                allocated_tokens INTEGER DEFAULT 0,
                used_tokens INTEGER DEFAULT 0,
                cost_usd REAL DEFAULT 0.0,
                duration_ms INTEGER DEFAULT 0,
                sandbox_profile TEXT DEFAULT 'strict',
                poc_path TEXT,
                poc_hash TEXT,
                exit_code INTEGER,
                reproduced INTEGER DEFAULT 0,
                evidence_id TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proof_records (
                proof_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                analysis_id TEXT NOT NULL,
                target_id TEXT,
                proof_type TEXT NOT NULL,
                proof_status TEXT NOT NULL,
                preflight_estimate TEXT,
                estimated_tokens INTEGER DEFAULT 0,
                estimated_runtime INTEGER DEFAULT 0,
                actual_tokens INTEGER DEFAULT 0,
                actual_runtime INTEGER DEFAULT 0,
                generated_artifact TEXT,
                artifact_hash TEXT,
                execution_environment TEXT,
                execution_command TEXT,
                observable_result TEXT,
                expected_result TEXT,
                actual_result TEXT,
                impact_class TEXT,
                reproducibility_count INTEGER DEFAULT 0,
                reproducibility_rate TEXT,
                reproducibility_attempts INTEGER DEFAULT 0,
                evidence_ids TEXT,
                verifier_level TEXT DEFAULT 'E0',
                failure_reason TEXT,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (analysis_id) REFERENCES analysis_runs(id),
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );

            CREATE INDEX IF NOT EXISTS idx_proof_finding ON proof_records(finding_id);
            CREATE INDEX IF NOT EXISTS idx_proof_analysis ON proof_records(analysis_id);
            CREATE INDEX IF NOT EXISTS idx_proof_status ON proof_records(proof_status);
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
        let runId = entry.analysis_id || entry.run_id || 'global';
        const runExists = this.db.prepare(`SELECT 1 FROM analysis_runs WHERE id = ?`).get(runId);
        if (!runExists) {
            const anyRun = this.db.prepare(`SELECT id FROM analysis_runs ORDER BY rowid DESC LIMIT 1`).get();
            if (anyRun) {
                runId = anyRun.id;
            } else {
                this.db.prepare(`INSERT OR IGNORE INTO projects (id, path, name) VALUES ('global-proj', '.', 'global')`).run();
                this.db.prepare(`INSERT OR IGNORE INTO analysis_runs (id, project_id, status) VALUES (?, 'global-proj', 'RUNNING')`).run(runId);
            }
        }
        const stmt = this.db.prepare(`
            INSERT INTO token_ledger (id, run_id, task_type, model_id, provider, prompt_tokens, completion_tokens, total_tokens, estimated_cost, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            entry.id, runId, entry.task_type, entry.model_id, entry.provider,
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
     * Records a scheduled or executed exploit verification attempt.
     * @param {Object} data
     * @returns {string} ID of recorded attempt
     */
    recordExploitAttempt(data = {}) {
        const id = data.id || `EXP-${crypto.randomBytes(6).toString('hex')}`;
        const stmt = this.db.prepare(`
            INSERT INTO exploit_attempts (
                id, run_id, finding_id, state, decision, provider, model,
                allocated_tokens, used_tokens, cost_usd, duration_ms,
                sandbox_profile, poc_path, poc_hash, exit_code, reproduced,
                evidence_id, error_message, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
            id,
            data.runId || data.run_id || 'global',
            data.findingId || data.finding_id || 'UNKNOWN',
            data.state || 'ATTEMPT_SCHEDULED',
            data.decision || 'MINIMAL_POC',
            data.provider || null,
            data.model || null,
            Number(data.allocatedTokens || data.allocated_tokens) || 0,
            Number(data.usedTokens || data.used_tokens) || 0,
            Number(data.costUsd || data.cost_usd) || 0.0,
            Number(data.durationMs || data.duration_ms) || 0,
            data.sandboxProfile || data.sandbox_profile || 'strict',
            data.pocPath || data.poc_path || null,
            data.pocHash || data.poc_hash || null,
            data.exitCode !== undefined ? data.exitCode : null,
            data.reproduced ? 1 : 0,
            data.evidenceId || data.evidence_id || null,
            data.errorMessage || data.error_message || null,
            new Date().toISOString()
        );
        return id;
    }

    /**
     * Updates an existing exploit attempt with execution results.
     * @param {string} id
     * @param {Object} updates
     */
    updateExploitAttempt(id, updates = {}) {
        const fields = [];
        const values = [];

        if (updates.state !== undefined) { fields.push('state = ?'); values.push(updates.state); }
        if (updates.usedTokens !== undefined) { fields.push('used_tokens = ?'); values.push(updates.usedTokens); }
        if (updates.costUsd !== undefined) { fields.push('cost_usd = ?'); values.push(updates.costUsd); }
        if (updates.durationMs !== undefined) { fields.push('duration_ms = ?'); values.push(updates.durationMs); }
        if (updates.pocPath !== undefined) { fields.push('poc_path = ?'); values.push(updates.pocPath); }
        if (updates.pocHash !== undefined) { fields.push('poc_hash = ?'); values.push(updates.pocHash); }
        if (updates.exitCode !== undefined) { fields.push('exit_code = ?'); values.push(updates.exitCode); }
        if (updates.reproduced !== undefined) { fields.push('reproduced = ?'); values.push(updates.reproduced ? 1 : 0); }
        if (updates.evidenceId !== undefined) { fields.push('evidence_id = ?'); values.push(updates.evidenceId); }
        if (updates.errorMessage !== undefined) { fields.push('error_message = ?'); values.push(updates.errorMessage); }

        if (fields.length === 0) return;
        values.push(id);
        const stmt = this.db.prepare(`UPDATE exploit_attempts SET ${fields.join(', ')} WHERE id = ?`);
        stmt.run(...values);
    }

    /**
     * Retrieves all exploit attempts for a given analysis run or finding.
     * @param {string} runId
     * @param {string} [findingId]
     * @returns {Array<Object>}
     */
    getExploitAttempts(runId, findingId = null) {
        if (findingId) {
            const stmt = this.db.prepare(`SELECT * FROM exploit_attempts WHERE run_id = ? AND finding_id = ? ORDER BY created_at ASC`);
            return stmt.all(runId, findingId);
        }
        const stmt = this.db.prepare(`SELECT * FROM exploit_attempts WHERE run_id = ? ORDER BY created_at ASC`);
        return stmt.all(runId);
    }

    /**
     * Saves or updates a structured proof record in the database.
     * @param {Object} data
     * @returns {string} proof_id
     */
    saveProofRecord(data = {}) {
        const id = data.proof_id || `PROOF-${crypto.randomBytes(6).toString('hex')}`;
        const stmt = this.db.prepare(`
            INSERT INTO proof_records (
                proof_id, finding_id, analysis_id, target_id, proof_type, proof_status,
                preflight_estimate, estimated_tokens, estimated_runtime, actual_tokens, actual_runtime,
                generated_artifact, artifact_hash, execution_environment, execution_command,
                observable_result, expected_result, actual_result, impact_class,
                reproducibility_count, reproducibility_rate, reproducibility_attempts,
                evidence_ids, verifier_level, failure_reason, created_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proof_id) DO UPDATE SET
                proof_status = excluded.proof_status,
                actual_tokens = excluded.actual_tokens,
                actual_runtime = excluded.actual_runtime,
                generated_artifact = excluded.generated_artifact,
                artifact_hash = excluded.artifact_hash,
                execution_command = excluded.execution_command,
                observable_result = excluded.observable_result,
                expected_result = excluded.expected_result,
                actual_result = excluded.actual_result,
                impact_class = excluded.impact_class,
                reproducibility_count = excluded.reproducibility_count,
                reproducibility_rate = excluded.reproducibility_rate,
                reproducibility_attempts = excluded.reproducibility_attempts,
                evidence_ids = excluded.evidence_ids,
                verifier_level = excluded.verifier_level,
                failure_reason = excluded.failure_reason,
                completed_at = excluded.completed_at
        `);

        stmt.run(
            id,
            data.finding_id || data.findingId || 'UNKNOWN',
            data.analysis_id || data.analysisId || data.runId || 'global',
            data.target_id || data.targetId || null,
            data.proof_type || data.proofType || 'REGRESSION_TEST',
            data.proof_status || data.proofStatus || 'QUEUED',
            typeof data.preflight_estimate === 'object' ? JSON.stringify(data.preflight_estimate) : (data.preflight_estimate || null),
            Number(data.estimated_tokens || data.estimatedTokens) || 0,
            Number(data.estimated_runtime || data.estimatedRuntime) || 0,
            Number(data.actual_tokens || data.actualTokens) || 0,
            Number(data.actual_runtime || data.actualRuntime) || 0,
            data.generated_artifact || data.generatedArtifact || null,
            data.artifact_hash || data.artifactHash || null,
            data.execution_environment || data.executionEnvironment || 'hwsec_isolated_sandbox',
            data.execution_command || data.executionCommand || null,
            typeof data.observable_result === 'object' ? JSON.stringify(data.observable_result) : (data.observable_result || null),
            typeof data.expected_result === 'object' ? JSON.stringify(data.expected_result) : (data.expected_result || null),
            typeof data.actual_result === 'object' ? JSON.stringify(data.actual_result) : (data.actual_result || null),
            data.impact_class || data.impactClass || 'INFORMATIONAL_ONLY',
            Number(data.reproducibility_count || data.reproducibilityCount) || 0,
            data.reproducibility_rate || data.reproducibilityRate || null,
            Number(data.reproducibility_attempts || data.reproducibilityAttempts) || 0,
            Array.isArray(data.evidence_ids) ? JSON.stringify(data.evidence_ids) : (data.evidence_ids || '[]'),
            data.verifier_level || data.verifierLevel || 'E0',
            data.failure_reason || data.failureReason || null,
            data.created_at || new Date().toISOString(),
            data.completed_at || null
        );
        return id;
    }

    /**
     * Retrieves a single proof record by ID.
     * @param {string} proofId
     * @returns {Object|null}
     */
    getProofRecord(proofId) {
        const stmt = this.db.prepare(`SELECT * FROM proof_records WHERE proof_id = ?`);
        const row = stmt.get(proofId);
        if (!row) return null;
        return this._deserializeProofRecord(row);
    }

    /**
     * Retrieves all proof records for an analysis run.
     * @param {string} analysisId
     * @returns {Array<Object>}
     */
    getProofRecordsForAnalysis(analysisId) {
        const stmt = this.db.prepare(`SELECT * FROM proof_records WHERE analysis_id = ? ORDER BY created_at ASC`);
        return stmt.all(analysisId).map(r => this._deserializeProofRecord(r));
    }

    /**
     * Retrieves the latest proof record for a specific finding.
     * @param {string} findingId
     * @returns {Object|null}
     */
    getProofRecordForFinding(findingId) {
        const stmt = this.db.prepare(`SELECT * FROM proof_records WHERE finding_id = ? ORDER BY created_at DESC LIMIT 1`);
        const row = stmt.get(findingId);
        if (!row) return null;
        return this._deserializeProofRecord(row);
    }

    /**
     * Updates fields on an existing proof record.
     * @param {string} proofId
     * @param {Object} updates
     */
    updateProofRecord(proofId, updates = {}) {
        const allowedCols = [
            'proof_status', 'actual_tokens', 'actual_runtime', 'generated_artifact',
            'artifact_hash', 'execution_command', 'observable_result', 'expected_result',
            'actual_result', 'impact_class', 'reproducibility_count', 'reproducibility_rate',
            'reproducibility_attempts', 'evidence_ids', 'verifier_level', 'failure_reason', 'completed_at'
        ];
        const fields = [];
        const values = [];

        for (const [k, v] of Object.entries(updates)) {
            const snakeKey = k.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
            if (allowedCols.includes(snakeKey)) {
                fields.push(`${snakeKey} = ?`);
                values.push(typeof v === 'object' && v !== null ? JSON.stringify(v) : v);
            }
        }

        if (fields.length === 0) return;
        values.push(proofId);
        const stmt = this.db.prepare(`UPDATE proof_records SET ${fields.join(', ')} WHERE proof_id = ?`);
        stmt.run(...values);
    }

    _deserializeProofRecord(row) {
        if (!row) return null;
        return {
            ...row,
            preflight_estimate: row.preflight_estimate ? JSON.parse(row.preflight_estimate) : null,
            observable_result: row.observable_result ? JSON.parse(row.observable_result) : null,
            expected_result: row.expected_result ? JSON.parse(row.expected_result) : null,
            actual_result: row.actual_result ? JSON.parse(row.actual_result) : null,
            evidence_ids: row.evidence_ids ? JSON.parse(row.evidence_ids) : []
        };
    }

    /**
     * Purges all database records associated with a specific analysis run.
     * @param {string} runId
     */
    deleteAnalysisRun(runId) {
        this.db.exec('BEGIN TRANSACTION;');
        try {
            this.db.prepare(`DELETE FROM proof_records WHERE analysis_id = ?`).run(runId);
            this.db.prepare(`DELETE FROM exploit_attempts WHERE run_id = ?`).run(runId);
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
