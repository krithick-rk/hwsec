import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { canonicalHash } from '../bep/evidenceDag.js';

/**
 * EntryPointInventory
 * 
 * Section 7: First-class entry-point inventory layer.
 * Discovers and caches real application entry points across languages.
 */
export class EntryPointInventory {
    constructor(options = {}) {
        this.version = '2.0.0';
        this.cache = new Map(); // entry_point_id -> EntryPoint
    }

    /**
     * Scans a target repository workspace to discover entry points.
     * @param {string} workspacePath 
     * @param {Object} [options]
     * @returns {Array<Object>} Discovered EntryPoints
     */
    discover(workspacePath, options = {}) {
        const entryPoints = [];
        if (!fs.existsSync(workspacePath)) return entryPoints;

        const walkDir = (dir) => {
            const entries = fs.readdirSync(dir, { withFileTypes: true });
            for (const ent of entries) {
                const fullPath = path.join(dir, ent.name);
                if (ent.isDirectory()) {
                    if (!['node_modules', '.git', 'target', 'build', 'dist', '.idea'].includes(ent.name)) {
                        walkDir(fullPath);
                    }
                } else if (ent.isFile()) {
                    const ext = path.extname(ent.name).toLowerCase();
                    if (['.java', '.py', '.c', '.cpp', '.go', '.js', '.ts', '.v'].includes(ext)) {
                        const fileEntries = this._scanFileForEntryPoints(fullPath, workspacePath);
                        entryPoints.push(...fileEntries);
                    }
                }
            }
        };

        walkDir(workspacePath);

        // Cache entries
        for (const ep of entryPoints) {
            this.cache.set(ep.id, ep);
        }

        return entryPoints;
    }

    _scanFileForEntryPoints(filePath, rootDir) {
        const relPath = path.relative(rootDir, filePath).replace(/\\/g, '/');
        const content = fs.readFileSync(filePath, 'utf8');
        const eps = [];
        const ext = path.extname(filePath).toLowerCase();

        // 1. Java Entry Points (Spring, Servlets, JAX-RS, main)
        if (ext === '.java') {
            // Spring Controller routes
            const springMatches = content.matchAll(/@(GetMapping|PostMapping|RequestMapping|PutMapping|DeleteMapping)\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g);
            for (const m of springMatches) {
                const method = m[1].replace('Mapping', '').toUpperCase();
                eps.push(this._createEntryPoint({
                    type: 'HTTP_ENDPOINT',
                    framework: 'Spring',
                    route: m[2],
                    http_method: method === 'REQUEST' ? 'ANY' : method,
                    file: relPath,
                    target_identifier: relPath
                }));
            }

            // HttpServlet doPost/doGet
            if (content.includes('extends HttpServlet') || content.includes('doPost') || content.includes('doGet')) {
                if (content.includes('doPost')) {
                    eps.push(this._createEntryPoint({
                        type: 'HTTP_SERVLET',
                        framework: 'Servlet',
                        method: 'doPost',
                        http_method: 'POST',
                        file: relPath,
                        target_identifier: relPath
                    }));
                }
                if (content.includes('doGet')) {
                    eps.push(this._createEntryPoint({
                        type: 'HTTP_SERVLET',
                        framework: 'Servlet',
                        method: 'doGet',
                        http_method: 'GET',
                        file: relPath,
                        target_identifier: relPath
                    }));
                }
            }

            // Java main
            if (/public\s+static\s+void\s+main\s*\(/.test(content)) {
                eps.push(this._createEntryPoint({
                    type: 'CLI_MAIN',
                    framework: 'JavaStandard',
                    file: relPath,
                    target_identifier: `${relPath}#main`
                }));
            }
        }

        // 2. Python Entry Points (Flask, FastAPI, Django, main)
        if (ext === '.py') {
            // Flask / FastAPI routes
            const pyRouteMatches = content.matchAll(/@(?:app|router)\.(get|post|route|put|delete)\s*\(\s*["']([^"']+)["']/g);
            for (const m of pyRouteMatches) {
                eps.push(this._createEntryPoint({
                    type: 'HTTP_ENDPOINT',
                    framework: 'PythonWeb',
                    route: m[2],
                    http_method: m[1].toUpperCase(),
                    file: relPath,
                    target_identifier: relPath
                }));
            }

            // Python CLI / main
            if (content.includes("if __name__ == '__main__':") || content.includes('if __name__ == "__main__":')) {
                eps.push(this._createEntryPoint({
                    type: 'CLI_MAIN',
                    framework: 'PythonStandard',
                    file: relPath,
                    target_identifier: `${relPath}#__main__`
                }));
            }
        }

        // 3. C/C++ Entry Points
        if (['.c', '.cpp'].includes(ext)) {
            if (/int\s+main\s*\(/.test(content)) {
                eps.push(this._createEntryPoint({
                    type: 'CLI_MAIN',
                    framework: 'C/C++Standard',
                    file: relPath,
                    target_identifier: `${relPath}#main`
                }));
            }
        }

        // 4. Go Entry Points
        if (ext === '.go') {
            if (/func\s+main\s*\(/.test(content)) {
                eps.push(this._createEntryPoint({
                    type: 'CLI_MAIN',
                    framework: 'GoStandard',
                    file: relPath,
                    target_identifier: `${relPath}#main`
                }));
            }
        }

        // 5. Verilog / RTL Top Module IO Ports
        if (ext === '.v') {
            const moduleMatch = content.match(/module\s+([a-zA-Z0-9_]+)/);
            if (moduleMatch) {
                eps.push(this._createEntryPoint({
                    type: 'HARDWARE_MODULE_IO',
                    framework: 'VerilogRTL',
                    module_name: moduleMatch[1],
                    file: relPath,
                    target_identifier: `${relPath}#${moduleMatch[1]}`
                }));
            }
        }

        return eps;
    }

    _createEntryPoint(fields) {
        const id = `EP-${canonicalHash(fields).substring(0, 12)}`;
        return {
            id,
            status: 'RESOLVED',
            ...fields,
            discovered_at: new Date().toISOString()
        };
    }

    /**
     * Resolves an entry point for a given hypothesis.
     * @param {Object} hypothesis 
     * @returns {Object} Resolved EntryPoint or Unresolved placeholder
     */
    resolveForHypothesis(hypothesis) {
        if (!hypothesis) {
            return { status: 'UNRESOLVED', reason: 'Null hypothesis provided' };
        }

        // Check if candidate path or source matches any cached entry point
        const candidateFiles = (hypothesis.candidate_path || []).map(p => p.split(':')[0]);
        for (const ep of this.cache.values()) {
            if (candidateFiles.includes(ep.file)) {
                return { ...ep, status: 'RESOLVED', resolution_type: 'DIRECT_FILE_MATCH' };
            }
        }

        // If no direct entry point found, return UNRESOLVED
        return {
            status: 'UNRESOLVED',
            reason: `No application HTTP/CLI/service entry point resolves to target path [${candidateFiles.join(', ')}]`,
            requires_synthetic_scope: true
        };
    }
}
