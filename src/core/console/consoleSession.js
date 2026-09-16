import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Database } from '../db.js';

export const ConsoleModes = ['FAST', 'STANDARD', 'DEEP', 'FORENSIC'];
export const LLMStrategies = ['OFF', 'SCOUT', 'SCOUT+CRITIC', 'ADAPTIVE', 'FULL'];
export const PovModes = ['ON-DETECTED', 'ALWAYS', 'NEVER'];
export const ApprovalPolicies = ['REQUIRED', 'OPTIONAL'];

export const SessionPhase = {
    INITIALIZED: 'INITIALIZED',
    PLANNED: 'PLANNED',
    APPROVED: 'APPROVED',
    RUNNING: 'RUNNING',
    COMPLETED: 'COMPLETED'
};

/**
 * ConsoleSession
 * 
 * Thin facade representing the active operator session state,
 * backed directly by SQLite without duplicating source-of-truth.
 */
export class ConsoleSession {
    constructor(data = {}) {
        const now = new Date();
        const dateStr = now.toISOString().slice(0, 10).replace(/-/g, '');
        const randStr = crypto.randomBytes(2).toString('hex');
        
        this.id = data.id || `HW-${dateStr}-${randStr}`;
        this.analysisId = data.analysisId || null;
        this.targetDir = data.targetDir || null;
        this.contextDir = data.contextDir || null;
        this.requirementsPath = data.requirementsPath || null;
        this.mode = (data.mode || 'STANDARD').toUpperCase();
        this.llmStrategy = (data.llmStrategy || 'ADAPTIVE').toUpperCase();
        this.povMode = (data.povMode || 'ON-DETECTED').toUpperCase();
        this.budget = data.budget !== undefined ? Number(data.budget) : 10.0;
        this.approvalPolicy = (data.approvalPolicy || 'REQUIRED').toUpperCase();
        this.status = data.status || SessionPhase.INITIALIZED;
        this.createdAt = data.createdAt || now.toISOString();
        this.updatedAt = data.updatedAt || now.toISOString();
        this.metadata = data.metadata || {};
        this.toolPaths = data.toolPaths || (this.metadata.toolPaths || {});
    }

    /**
     * Sets a session option with strict validation.
     * @param {string} key 
     * @param {string} value 
     */
    set(key, value) {
        if (!key) throw new Error("Option key must be specified. Usage: set <option> <value>");
        if (value === undefined || value === null || value === '') {
            throw new Error(`Value for '${key}' cannot be empty.`);
        }

        const normKey = key.toLowerCase();
        const strVal = String(value).trim();

        switch (normKey) {
            case 'target':
            case 'target_dir': {
                const resolved = path.resolve(strVal);
                if (!fs.existsSync(resolved)) {
                    throw new Error(`Target directory does not exist: '${resolved}'`);
                }
                if (!fs.statSync(resolved).isDirectory()) {
                    throw new Error(`Target path must be a directory: '${resolved}'`);
                }
                this.targetDir = resolved;
                break;
            }

            case 'context':
            case 'context_dir': {
                const resolved = path.resolve(strVal);
                if (!fs.existsSync(resolved)) {
                    throw new Error(`Context directory does not exist: '${resolved}'`);
                }
                this.contextDir = resolved;
                break;
            }

            case 'requirements':
            case 'spec': {
                const resolved = path.resolve(strVal);
                if (!fs.existsSync(resolved)) {
                    throw new Error(`Requirements file does not exist: '${resolved}'`);
                }
                this.requirementsPath = resolved;
                break;
            }

            case 'mode': {
                const upper = strVal.toUpperCase();
                if (!ConsoleModes.includes(upper)) {
                    throw new Error(`Invalid mode '${strVal}'. Allowed: ${ConsoleModes.join(', ')}`);
                }
                this.mode = upper;
                break;
            }

            case 'llm':
            case 'llm_strategy': {
                const upper = strVal.toUpperCase();
                if (!LLMStrategies.includes(upper)) {
                    throw new Error(`Invalid LLM strategy '${strVal}'. Allowed: ${LLMStrategies.join(', ')}`);
                }
                this.llmStrategy = upper;
                break;
            }

            case 'pov':
            case 'pov_mode': {
                const upper = strVal.toUpperCase();
                if (!PovModes.includes(upper)) {
                    throw new Error(`Invalid PoV mode '${strVal}'. Allowed: ${PovModes.join(', ')}`);
                }
                this.povMode = upper;
                break;
            }

            case 'budget': {
                const num = parseFloat(strVal);
                if (isNaN(num) || num <= 0) {
                    throw new Error(`Budget must be a positive number. Received: '${strVal}'`);
                }
                this.budget = num;
                break;
            }

            case 'approval':
            case 'approval_policy': {
                const upper = strVal.toUpperCase();
                if (!ApprovalPolicies.includes(upper)) {
                    throw new Error(`Invalid approval policy '${strVal}'. Allowed: ${ApprovalPolicies.join(', ')}`);
                }
                this.approvalPolicy = upper;
                break;
            }

            case 'workspace':
            case 'output':
            case 'output_dir': {
                const resolved = path.resolve(strVal);
                this.metadata = this.metadata || {};
                this.metadata.workspace = resolved;
                break;
            }

            case 'execution':
            case 'backend': {
                const upper = strVal.toUpperCase();
                const allowed = ['AUTO', 'NATIVE', 'WSL', 'CONTAINER'];
                if (!allowed.includes(upper)) {
                    throw new Error(`Invalid execution backend '${strVal}'. Allowed: ${allowed.join(', ')}`);
                }
                this.metadata = this.metadata || {};
                this.metadata.executionBackend = upper;
                break;
            }

            case 'oss_cad_suite':
            case 'yosyshq_root': {
                const resolved = path.resolve(strVal);
                process.env.OSS_CAD_SUITE = resolved;
                process.env.YOSYSHQ_ROOT = resolved;
                this.metadata = this.metadata || {};
                this.metadata.envOverrides = this.metadata.envOverrides || {};
                this.metadata.envOverrides[normKey.toUpperCase()] = resolved;
                break;
            }

            default: {
                if (normKey.startsWith('tool.') && normKey.endsWith('.path')) {
                    const parts = normKey.split('.');
                    const toolName = parts[1];
                    const resolved = path.resolve(strVal);
                    this.toolPaths = this.toolPaths || {};
                    this.toolPaths[toolName] = resolved;
                    this.metadata = this.metadata || {};
                    this.metadata.toolPaths = this.metadata.toolPaths || {};
                    this.metadata.toolPaths[toolName] = resolved;
                    break;
                }
                throw new Error(`Unknown option '${key}'. Valid options: target, context, requirements, mode, llm, pov, budget, approval, workspace, execution, tool.<tool>.path`);
            }
        }

        this.updatedAt = new Date().toISOString();
    }

    /**
     * Unsets an optional configuration value.
     * @param {string} key 
     */
    unset(key) {
        if (!key) throw new Error("Usage: unset <option>");
        const normKey = key.toLowerCase();

        switch (normKey) {
            case 'context':
            case 'context_dir':
                this.contextDir = null;
                break;
            case 'requirements':
            case 'spec':
                this.requirementsPath = null;
                break;
            case 'target':
                this.targetDir = null;
                break;
            case 'workspace':
            case 'output':
                if (this.metadata) delete this.metadata.workspace;
                break;
            case 'execution':
            case 'backend':
                if (this.metadata) delete this.metadata.executionBackend;
                break;
            default:
                if (normKey.startsWith('tool.') && normKey.endsWith('.path')) {
                    const toolName = normKey.split('.')[1];
                    if (this.toolPaths) delete this.toolPaths[toolName];
                    if (this.metadata?.toolPaths) delete this.metadata.toolPaths[toolName];
                    break;
                }
                throw new Error(`Cannot unset required option '${key}'. Use 'set ${key} <value>' to modify.`);
        }

        this.updatedAt = new Date().toISOString();
    }

    /**
     * Resets session state while preserving ID and creation timestamp.
     */
    reset() {
        this.targetDir = null;
        this.contextDir = null;
        this.requirementsPath = null;
        this.mode = 'STANDARD';
        this.llmStrategy = 'ADAPTIVE';
        this.povMode = 'ON-DETECTED';
        this.budget = 10.0;
        this.approvalPolicy = 'REQUIRED';
        this.status = SessionPhase.INITIALIZED;
        this.analysisId = null;
        this.metadata = {};
        this.toolPaths = {};
        this.updatedAt = new Date().toISOString();
    }

    toJSON() {
        return {
            id: this.id,
            analysisId: this.analysisId,
            targetDir: this.targetDir,
            contextDir: this.contextDir,
            requirementsPath: this.requirementsPath,
            mode: this.mode,
            llmStrategy: this.llmStrategy,
            povMode: this.povMode,
            budget: this.budget,
            approvalPolicy: this.approvalPolicy,
            status: this.status,
            createdAt: this.createdAt,
            updatedAt: this.updatedAt,
            metadata: {
                ...this.metadata,
                toolPaths: this.toolPaths
            },
            toolPaths: this.toolPaths
        };
    }
}

/**
 * SessionManager
 * 
 * Manages active session lifecycle, SQLite backing, and command history.
 */
export class SessionManager {
    /**
     * @param {Object} [options]
     * @param {string} [options.dbPath='hwsec-output/hwsec.db']
     */
    constructor(options = {}) {
        this.dbPath = options.dbPath || 'hwsec-output/hwsec.db';
        this.db = new Database(this.dbPath);
        this.activeSession = null;
    }

    /**
     * Gets or creates the active session.
     * @returns {ConsoleSession}
     */
    getActiveSession() {
        if (!this.activeSession) {
            // Check if there is an existing recent session in DB
            const existing = this.db.listConsoleSessions();
            if (existing.length > 0) {
                this.activeSession = new ConsoleSession(existing[0]);
            } else {
                this.activeSession = new ConsoleSession();
                this.persistActiveSession();
            }
        }
        return this.activeSession;
    }

    /**
     * Creates a new session and makes it active.
     * @param {Object} [data]
     * @returns {ConsoleSession}
     */
    createSession(data = {}) {
        this.activeSession = new ConsoleSession(data);
        this.persistActiveSession();
        return this.activeSession;
    }

    /**
     * Loads an existing session by ID and makes it active.
     * @param {string} id 
     * @returns {ConsoleSession}
     */
    loadSession(id) {
        const data = this.db.getConsoleSession(id);
        if (!data) {
            throw new Error(`Session not found: '${id}'`);
        }
        this.activeSession = new ConsoleSession(data);
        return this.activeSession;
    }

    /**
     * Lists all recorded sessions.
     * @returns {Array<Object>}
     */
    listSessions() {
        return this.db.listConsoleSessions();
    }

    /**
     * Persists active session state to SQLite.
     */
    persistActiveSession() {
        if (this.activeSession && !this.closed) {
            try {
                this.db.saveConsoleSession(this.activeSession);
            } catch {}
        }
    }

    /**
     * Records a command in session history.
     * @param {string} command 
     */
    recordHistory(command) {
        if (!this.activeSession || this.closed) return;
        try {
            this.db.recordConsoleHistory(this.activeSession.id, command);
        } catch {}
    }

    /**
     * Gets command history for active session.
     * @param {number} [limit=50]
     * @returns {Array<{command: string, timestamp: string}>}
     */
    getHistory(limit = 50) {
        if (!this.activeSession || this.closed) return [];
        try {
            return this.db.getConsoleHistory(this.activeSession.id, limit);
        } catch {
            return [];
        }
    }

    close() {
        if (!this.closed) {
            this.closed = true;
            try {
                this.db.close();
            } catch {}
        }
    }
}
