import fs from 'fs';
import path from 'path';

/**
 * HWSEC Vulnerability Benchmark Framework Manager & High-Performance Crawler
 */

export class BenchmarkManager {
    constructor(configPath = null) {
        this.configPath = this._resolveConfigPath(configPath);
        this.config = this._loadConfig();
    }

    _resolveConfigPath(customPath) {
        if (customPath && fs.existsSync(customPath)) {
            return path.resolve(customPath);
        }
        const candidates = [
            path.resolve('manifests/benchmark_config.json'),
            path.resolve('quality-benchmark/manifests/benchmark_config.json')
        ];
        for (const c of candidates) {
            if (fs.existsSync(c)) return c;
        }
        throw new Error('benchmark_config.json not found in manifests/ or quality-benchmark/manifests/');
    }

    _loadConfig() {
        const raw = fs.readFileSync(this.configPath, 'utf8');
        return JSON.parse(raw);
    }

    /**
     * Retrieve all active / installed benchmark targets, ignoring any SKIPPED or DISABLED datasets.
     */
    getActiveBenchmarks() {
        const active = [];
        const languages = this.config.languages || {};

        for (const [lang, langData] of Object.entries(languages)) {
            const benchmarks = langData.benchmarks || {};
            for (const [key, bData] of Object.entries(benchmarks)) {
                const status = (bData.status || '').toUpperCase();
                const isExplicitlyDisabled = bData.enabled === false || status === 'SKIPPED' || status === 'DISABLED' || status === 'MANUAL_DOWNLOAD_REQUIRED';

                if (isExplicitlyDisabled) {
                    continue; // Cleanly ignore skipped datasets
                }

                // Check directory existence without throwing
                const resolvedPath = path.resolve(bData.path);
                const exists = fs.existsSync(resolvedPath);

                active.push({
                    key: `${lang}/${key}`,
                    language: lang,
                    name: key,
                    path: bData.path,
                    resolvedPath,
                    exists,
                    type: bData.type,
                    description: bData.description,
                    status: bData.status
                });
            }
        }
        return active;
    }

    /**
     * Retrieve list of skipped / excluded benchmark targets.
     */
    getSkippedBenchmarks() {
        const skipped = [];
        const languages = this.config.languages || {};

        for (const [lang, langData] of Object.entries(languages)) {
            const benchmarks = langData.benchmarks || {};
            for (const [key, bData] of Object.entries(benchmarks)) {
                const status = (bData.status || '').toUpperCase();
                const isSkipped = bData.enabled === false || status === 'SKIPPED' || status === 'DISABLED';
                if (isSkipped) {
                    skipped.push({
                        key: `${lang}/${key}`,
                        language: lang,
                        name: key,
                        path: bData.path,
                        status: bData.status,
                        skip_reason: bData.skip_reason || 'Dataset manual download excluded per configuration'
                    });
                }
            }
        }
        return skipped;
    }

    /**
     * Loads ground truth manifest.
     */
    loadGroundTruth(gtPath = null) {
        let resolvedGt = gtPath;
        if (!resolvedGt) {
            const candidates = [
                path.resolve('manifests/ground_truth.json'),
                path.resolve('quality-benchmark/manifests/ground_truth.json')
            ];
            for (const c of candidates) {
                if (fs.existsSync(c)) {
                    resolvedGt = c;
                    break;
                }
            }
        }
        if (!resolvedGt || !fs.existsSync(resolvedGt)) {
            throw new Error('ground_truth.json manifest not found.');
        }
        const data = JSON.parse(fs.readFileSync(resolvedGt, 'utf8'));
        return { path: resolvedGt, data };
    }

    /**
     * Validates that all file paths in ground truth exist on disk.
     */
    validateGroundTruth(gtPath = null) {
        const { path: resolvedGt, data } = this.loadGroundTruth(gtPath);
        const entries = data.entries || [];
        const breakdown = {};
        let valid = 0;
        let missing = 0;
        const missingPaths = [];

        for (const entry of entries) {
            const ds = entry.dataset || 'unknown';
            breakdown[ds] = breakdown[ds] || { total: 0, valid: 0, missing: 0 };
            breakdown[ds].total++;

            const targetPath = path.resolve(entry.path);
            if (fs.existsSync(targetPath)) {
                valid++;
                breakdown[ds].valid++;
            } else {
                missing++;
                breakdown[ds].missing++;
                if (missingPaths.length < 20) {
                    missingPaths.push(entry.path);
                }
            }
        }

        return {
            total_entries: entries.length,
            valid_entries: valid,
            missing_entries: missing,
            missing_paths: missingPaths,
            breakdown,
            passed: missing === 0
        };
    }
}

/**
 * Memory-efficient stream/iterative benchmark crawler
 */
export class BenchmarkCrawler {
    constructor(options = {}) {
        this.maxFileSize = options.maxFileSize || 10 * 1024 * 1024;
        this.excludeDirs = new Set(['.git', 'node_modules', '.idea', '.vscode', ...(options.excludeDirs || [])]);
    }

    /**
     * Crawls a specific directory iteratively, measuring heap and file stats.
     */
    crawlDirectory(targetDir, onFile = null) {
        const resolved = path.resolve(targetDir);
        if (!fs.existsSync(resolved)) {
            return {
                targetDir: resolved,
                exists: false,
                totalFiles: 0,
                memory: { startHeapMb: 0, peakHeapMb: 0, endHeapMb: 0 },
                elapsedMs: 0
            };
        }

        const startMem = process.memoryUsage();
        const t0 = Date.now();
        let totalFiles = 0;
        let peakHeap = startMem.heapUsed;

        // Iterative stack walk avoids call-stack overflow on deep structures
        const dirStack = [resolved];

        while (dirStack.length > 0) {
            const currentDir = dirStack.pop();
            let entries = [];
            try {
                entries = fs.readdirSync(currentDir, { withFileTypes: true });
            } catch {
                continue;
            }

            for (const entry of entries) {
                if (this.excludeDirs.has(entry.name)) continue;
                const fullPath = path.join(currentDir, entry.name);

                if (entry.isDirectory()) {
                    dirStack.push(fullPath);
                } else if (entry.isFile()) {
                    totalFiles++;
                    if (onFile) {
                        onFile(fullPath, entry.name);
                    }
                }
            }

            // Sample memory periodically
            if (totalFiles % 10000 === 0) {
                const currentHeap = process.memoryUsage().heapUsed;
                if (currentHeap > peakHeap) peakHeap = currentHeap;
            }
        }

        const endMem = process.memoryUsage();
        const elapsedMs = Date.now() - t0;

        return {
            targetDir: resolved,
            exists: true,
            totalFiles,
            memory: {
                startHeapMb: Math.round(startMem.heapUsed / 1024 / 1024),
                peakHeapMb: Math.round(peakHeap / 1024 / 1024),
                endHeapMb: Math.round(endMem.heapUsed / 1024 / 1024),
                rssMb: Math.round(endMem.rss / 1024 / 1024)
            },
            elapsedMs
        };
    }

    /**
     * Crawls all active benchmarks defined in BenchmarkManager.
     */
    crawlAllActive(manager = new BenchmarkManager()) {
        const active = manager.getActiveBenchmarks();
        const results = [];
        let totalFilesAll = 0;

        for (const benchmark of active) {
            const res = this.crawlDirectory(benchmark.resolvedPath);
            totalFilesAll += res.totalFiles;
            results.push({
                key: benchmark.key,
                language: benchmark.language,
                path: benchmark.path,
                type: benchmark.type,
                description: benchmark.description,
                ...res
            });
        }

        return {
            totalIndexedFiles: totalFilesAll,
            benchmarks: results
        };
    }
}
