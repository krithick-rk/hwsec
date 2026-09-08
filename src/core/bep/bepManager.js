import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { createBenchmarkManifest, computeSha256 } from './bepSchema.js';

/**
 * HWSEC BEP Bundle Manager
 * Manages creation, writing, hashing, and reading of self-contained evidence bundles.
 */

export class BEPManager {
    constructor(baseDir = 'quality-benchmark/evidence/runs') {
        this.baseDir = path.resolve(baseDir);
    }

    /**
     * Initializes a self-contained evidence bundle directory.
     */
    createBundle(benchmarkId, runId = null, customManifest = {}) {
        const timestamp = new Date().toISOString().replace(/[-:T.]/g, '').slice(0, 14);
        const cleanRunId = runId || `run_${timestamp}_${crypto.randomBytes(3).toString('hex')}`;
        const dirName = `run_${timestamp}_${benchmarkId}_${cleanRunId}`;
        const bundlePath = path.join(this.baseDir, dirName);

        fs.mkdirSync(bundlePath, { recursive: true });
        fs.mkdirSync(path.join(bundlePath, 'artifacts/proofs'), { recursive: true });
        fs.mkdirSync(path.join(bundlePath, 'artifacts/raw'), { recursive: true });

        const manifest = createBenchmarkManifest({
            benchmark_id: benchmarkId,
            run_id: cleanRunId,
            ...customManifest
        });

        fs.writeFileSync(
            path.join(bundlePath, 'manifest.json'),
            JSON.stringify(manifest, null, 2),
            'utf8'
        );

        return new BEPBundleWriter(bundlePath, manifest);
    }

    /**
     * Loads an existing bundle by path or directory name.
     */
    loadBundle(bundlePathOrName) {
        let fullPath = path.resolve(bundlePathOrName);
        if (!fs.existsSync(fullPath)) {
            fullPath = path.join(this.baseDir, bundlePathOrName);
        }
        if (!fs.existsSync(fullPath)) {
            throw new Error(`BEP evidence bundle not found: ${bundlePathOrName}`);
        }
        return new BEPBundleReader(fullPath);
    }
}

export class BEPBundleWriter {
    constructor(bundlePath, manifest) {
        this.bundlePath = bundlePath;
        this.manifest = manifest;
        this.streams = {};
    }

    _getStream(filename) {
        if (!this.streams[filename]) {
            const filePath = path.join(this.bundlePath, filename);
            this.streams[filename] = fs.createWriteStream(filePath, { flags: 'a', encoding: 'utf8' });
        }
        return this.streams[filename];
    }

    writeRecord(filename, record) {
        const stream = this._getStream(filename);
        stream.write(JSON.stringify(record) + '\n');
    }

    writeJson(filename, data) {
        const filePath = path.join(this.bundlePath, filename);
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
    }

    saveProofArtifact(proofId, fileName, content) {
        const proofDir = path.join(this.bundlePath, 'artifacts/proofs', proofId);
        fs.mkdirSync(proofDir, { recursive: true });
        const filePath = path.join(proofDir, fileName);
        fs.writeFileSync(filePath, content, 'utf8');
        return { path: filePath, sha256: computeSha256(content) };
    }

    saveRawArtifact(analyzerName, fileName, content) {
        const rawDir = path.join(this.bundlePath, 'artifacts/raw', analyzerName);
        fs.mkdirSync(rawDir, { recursive: true });
        const filePath = path.join(rawDir, fileName);
        fs.writeFileSync(filePath, content, 'utf8');
        return { path: filePath, sha256: computeSha256(content) };
    }

    async finalize(aggregateMetrics = {}, confusionMatrix = {}, ablationMetrics = {}) {
        // Close all open JSONL streams
        for (const [_, stream] of Object.entries(this.streams)) {
            await new Promise(resolve => stream.end(resolve));
        }

        this.writeJson('aggregate_metrics.json', aggregateMetrics);
        this.writeJson('confusion_matrix.json', confusionMatrix);
        this.writeJson('ablation_metrics.json', ablationMetrics);

        // Generate checksums.sha256
        const checksums = [];
        const files = this._listAllFiles(this.bundlePath);
        for (const file of files) {
            const relPath = path.relative(this.bundlePath, file).replace(/\\/g, '/');
            if (relPath === 'checksums.sha256') continue;
            const content = fs.readFileSync(file);
            const sha256 = crypto.createHash('sha256').update(content).digest('hex');
            checksums.push(`${sha256}  ${relPath}`);
        }

        fs.writeFileSync(path.join(this.bundlePath, 'checksums.sha256'), checksums.join('\n') + '\n', 'utf8');

        // Generate bundle README.md
        const readmeMd = `# HWSEC Evidence Bundle: ${this.manifest.benchmark_id}\n\n` +
            `- **Run ID**: \`${this.manifest.run_id}\`\n` +
            `- **Created At**: ${this.manifest.created_at}\n` +
            `- **HWSEC Revision**: \`${this.manifest.hwsec_revision}\`\n` +
            `- **Case Count**: ${this.manifest.case_count}\n` +
            `- **Proof Mode**: \`${this.manifest.proof_mode}\`\n\n` +
            `## Verification\n` +
            `Run integrity check via:\n` +
            `\`\`\`bash\nhwsec benchmark verify-evidence ${path.basename(this.bundlePath)}\n\`\`\`\n`;
        fs.writeFileSync(path.join(this.bundlePath, 'README.md'), readmeMd, 'utf8');

        return this.bundlePath;
    }

    _listAllFiles(dir) {
        let results = [];
        const list = fs.readdirSync(dir);
        for (const file of list) {
            const fullPath = path.join(dir, file);
            const stat = fs.statSync(fullPath);
            if (stat && stat.isDirectory()) {
                results = results.concat(this._listAllFiles(fullPath));
            } else {
                results.push(fullPath);
            }
        }
        return results;
    }
}

export class BEPBundleReader {
    constructor(bundlePath) {
        this.bundlePath = bundlePath;
        this.manifest = this.readJson('manifest.json');
    }

    readJson(filename) {
        const filePath = path.join(this.bundlePath, filename);
        if (!fs.existsSync(filePath)) return null;
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }

    readJsonl(filename) {
        const filePath = path.join(this.bundlePath, filename);
        if (!fs.existsSync(filePath)) return [];
        const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(l => l.trim().length > 0);
        return lines.map(l => JSON.parse(l));
    }
}
