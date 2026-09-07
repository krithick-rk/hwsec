import fs from 'fs';
import path from 'path';

const DEFAULT_EXCLUDES = new Set([
    '.git', 'node_modules', 'build', 'target', 'out', 'dist', 
    '__pycache__', 'venv', 'env', '.venv', '.env', 'obj_dir', '.idea', '.vscode'
]);

const LANGUAGE_EXTENSIONS = {
    'python': ['.py'],
    'java': ['.java'],
    'c': ['.c', '.h'],
    'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.hxx'],
    'go': ['.go'],
    'verilog': ['.v', '.sv', '.vh', '.svh']
};

const BUILD_MANIFESTS = {
    'package.json': 'npm/yarn',
    'pom.xml': 'maven',
    'build.gradle': 'gradle',
    'requirements.txt': 'pip',
    'Pipfile': 'pipenv',
    'setup.py': 'setuptools',
    'Makefile': 'make',
    'CMakeLists.txt': 'cmake',
    'go.mod': 'go_modules'
};

function countLoc(filePath, maxFileSize = 10485760) {
    try {
        const stat = fs.statSync(filePath);
        if (stat.size > maxFileSize) {
            return 0; // Oversized file
        }
        const fd = fs.openSync(filePath, 'r');
        const buffer = Buffer.alloc(Math.min(stat.size, 1024 * 1024)); // Read up to 1MB
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
        fs.closeSync(fd);

        // Check for binary null byte
        for (let i = 0; i < bytesRead; i++) {
            if (buffer[i] === 0) return 0; // Binary file
        }

        const content = fs.readFileSync(filePath, 'utf-8');
        return content.split('\n').filter(line => line.trim().length > 0).length;
    } catch {
        return 0;
    }
}

export class RepositoryDiscovery {
    constructor(config = {}) {
        this.config = config;
        this.excludeDirs = new Set(config.exclude_dirs ? [...DEFAULT_EXCLUDES, ...config.exclude_dirs] : DEFAULT_EXCLUDES);
        this.maxDepth = config.max_directory_depth || 15;
        this.maxFileSize = config.max_file_size_bytes || 10485760; // 10MB default
        this.maxFiles = config.max_files || 10000;
    }

    discover(rootDir) {
        const resolvedRoot = path.resolve(rootDir);
        if (!fs.existsSync(resolvedRoot)) {
            throw new Error(`Repository directory not found: ${resolvedRoot}`);
        }

        const inventory = {
            root_dir: resolvedRoot,
            languages: {
                python: [],
                java: [],
                c: [],
                cpp: [],
                go: [],
                verilog: []
            },
            file_metadata: {},
            unsupported: [],
            manifests: [],
            total_files: 0,
            total_loc: 0
        };

        const visitedDirs = new Set();
        try {
            visitedDirs.add(fs.realpathSync(resolvedRoot).toLowerCase());
        } catch {}

        this._walk(resolvedRoot, resolvedRoot, inventory, 0, visitedDirs);

        const summary = {
            total_files: inventory.total_files,
            total_loc: inventory.total_loc,
            languages: {},
            manifests: inventory.manifests.map(m => ({ name: m.name, type: m.type, path: m.path })),
            unsupported_count: inventory.unsupported.length,
            likely_attack_surfaces: []
        };

        for (const [lang, files] of Object.entries(inventory.languages)) {
            if (files.length > 0) {
                const loc = files.reduce((acc, f) => acc + (inventory.file_metadata[f]?.loc || 0), 0);
                summary.languages[lang] = {
                    file_count: files.length,
                    loc_estimate: loc,
                    sample_files: files.slice(0, 5)
                };
            }
        }

        return { inventory, summary };
    }

    _walk(dir, rootDir, inventory, depth = 0, visitedDirs = new Set()) {
        if (depth > this.maxDepth) {
            return; // Enforce depth bound
        }
        if (inventory.total_files >= this.maxFiles) {
            return; // Enforce file count limit
        }

        let entries = [];
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch (e) {
            return;
        }

        for (const entry of entries) {
            if (inventory.total_files >= this.maxFiles) break;

            const fullPath = path.join(dir, entry.name);
            const relativePath = path.relative(rootDir, fullPath);

            // Check symlink boundary
            let isLink = false;
            try {
                const lstat = fs.lstatSync(fullPath);
                isLink = lstat.isSymbolicLink();
            } catch {}

            let realTarget = null;
            if (isLink) {
                try {
                    realTarget = fs.realpathSync(fullPath);
                    const realRoot = fs.realpathSync(rootDir);
                    // Ensure symlink target does not escape repository root
                    if (!realTarget.toLowerCase().startsWith(realRoot.toLowerCase())) {
                        continue; // Safely skip symlink pointing outside repository
                    }
                } catch {
                    continue; // Broken symlink
                }
            }

            if (entry.isDirectory() || (isLink && fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory())) {
                if (!this.excludeDirs.has(entry.name)) {
                    let realDir = fullPath;
                    try { realDir = fs.realpathSync(fullPath).toLowerCase(); } catch {}
                    if (!visitedDirs.has(realDir)) {
                        visitedDirs.add(realDir);
                        this._walk(fullPath, rootDir, inventory, depth + 1, visitedDirs);
                    }
                }
            } else if (entry.isFile() || (isLink && fs.existsSync(fullPath) && fs.statSync(fullPath).isFile())) {
                let fileSize = 0;
                try {
                    fileSize = fs.statSync(fullPath).size;
                } catch {}

                if (fileSize > this.maxFileSize) {
                    // Oversized file: skip from language inventory to prevent heap exhaustion
                    continue;
                }

                inventory.total_files++;
                const ext = path.extname(entry.name).toLowerCase();
                
                // Check if it's a build manifest
                if (BUILD_MANIFESTS[entry.name]) {
                    inventory.manifests.push({
                        path: fullPath,
                        relativePath,
                        name: entry.name,
                        type: BUILD_MANIFESTS[entry.name]
                    });
                }

                // Identify language
                let identifiedLang = null;
                for (const [lang, exts] of Object.entries(LANGUAGE_EXTENSIONS)) {
                    if (exts.includes(ext)) {
                        identifiedLang = lang;
                        break;
                    }
                }

                if (identifiedLang) {
                    inventory.languages[identifiedLang].push(fullPath);
                    const loc = countLoc(fullPath, this.maxFileSize);
                    inventory.total_loc += loc;
                    inventory.file_metadata[fullPath] = {
                        relativePath,
                        language: identifiedLang,
                        loc,
                        size: fileSize
                    };
                } else {
                    inventory.unsupported.push({
                        path: fullPath,
                        relativePath,
                        extension: ext
                    });
                }
            }
        }
    }
}

