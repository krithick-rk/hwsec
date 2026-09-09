import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * HWSEC Content-Addressed Cache Manager
 * 
 * Implements Phase 11:
 * - Cache by content/config/tool-version identity
 * - For every reused artifact record: cache key, producer version, input hash, cache creation time, reuse reason
 * - Granular file-level invalidation when source files change
 */
export class ContentAddressedCacheManager {
    /**
     * @param {string} [cacheDir]
     */
    constructor(cacheDir = path.resolve('.hwsec_cache')) {
        this.cacheDir = cacheDir;
        this.metadataFile = path.join(this.cacheDir, 'cache_index.json');
        this.index = { entries: {}, fileToKeys: {} };
        this._init();
    }

    _init() {
        if (!fs.existsSync(this.cacheDir)) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
        }
        if (fs.existsSync(this.metadataFile)) {
            try {
                this.index = JSON.parse(fs.readFileSync(this.metadataFile, 'utf8'));
            } catch (_) {
                this.index = { entries: {}, fileToKeys: {} };
            }
        }
    }

    _saveIndex() {
        try {
            fs.writeFileSync(this.metadataFile, JSON.stringify(this.index, null, 2), 'utf8');
        } catch (_) {}
    }

    /**
     * Computes the cryptographic hash of a file or string.
     */
    static hashContent(contentOrPath) {
        if (typeof contentOrPath === 'string' && fs.existsSync(contentOrPath)) {
            try {
                const buf = fs.readFileSync(contentOrPath);
                return crypto.createHash('sha256').update(buf).digest('hex');
            } catch (_) {}
        }
        const buf = Buffer.isBuffer(contentOrPath) ? contentOrPath : Buffer.from(String(contentOrPath), 'utf8');
        return crypto.createHash('sha256').update(buf).digest('hex');
    }

    /**
     * Computes a deterministic, content-addressed cache key.
     * @param {Object} params
     * @param {string[]} params.files
     * @param {Object} [params.config={}]
     * @param {string} [params.toolVersion='1.0.0']
     * @param {string} [params.toolId='generic']
     * @returns {string} SHA-256 Cache Key
     */
    computeCacheKey(params = {}) {
        const { files = [], config = {}, toolVersion = '1.0.0', toolId = 'generic' } = params;
        const hasher = crypto.createHash('sha256');

        hasher.update(`TOOL:${toolId}@${toolVersion}\n`);
        hasher.update(`CONFIG:${JSON.stringify(config)}\n`);

        const sortedFiles = [...files].sort();
        for (const f of sortedFiles) {
            const fileHash = ContentAddressedCacheManager.hashContent(f);
            hasher.update(`FILE:${path.resolve(f)}:${fileHash}\n`);
        }

        return hasher.digest('hex');
    }

    /**
     * Retrieves a cached artifact if valid and unmodified.
     * @param {string} cacheKey
     * @returns {Object|null}
     */
    get(cacheKey) {
        const meta = this.index.entries[cacheKey];
        if (!meta) return null;

        const artifactFile = path.join(this.cacheDir, `${cacheKey}.artifact`);
        if (!fs.existsSync(artifactFile)) {
            delete this.index.entries[cacheKey];
            this._saveIndex();
            return null;
        }

        // Verify that all input files are still unchanged
        for (const [filePath, storedHash] of Object.entries(meta.inputHashes || {})) {
            if (!fs.existsSync(filePath)) return null;
            const currentHash = ContentAddressedCacheManager.hashContent(filePath);
            if (currentHash !== storedHash) {
                this.invalidate(filePath);
                return null;
            }
        }

        try {
            const data = fs.readFileSync(artifactFile, 'utf8');
            return {
                data: JSON.parse(data),
                metadata: {
                    cache_key: cacheKey,
                    producer_version: meta.producer_version,
                    input_hash: meta.input_hash,
                    cache_creation_time: meta.created_at,
                    reuse_reason: 'CONTENT_AND_CONFIG_IDENTICAL_MATCH'
                }
            };
        } catch (_) {
            return null;
        }
    }

    /**
     * Stores an analysis artifact in the content-addressed cache.
     * @param {Object} params
     * @param {string} params.cacheKey
     * @param {string[]} params.files
     * @param {any} params.data
     * @param {string} [params.toolVersion='1.0.0']
     */
    set(params = {}) {
        const { cacheKey, files = [], data, toolVersion = '1.0.0' } = params;
        if (!cacheKey) return;

        const inputHashes = {};
        for (const f of files) {
            inputHashes[path.resolve(f)] = ContentAddressedCacheManager.hashContent(f);
        }

        const aggregateInputHash = crypto.createHash('sha256')
            .update(Object.values(inputHashes).join('|'))
            .digest('hex');

        const artifactFile = path.join(this.cacheDir, `${cacheKey}.artifact`);
        fs.writeFileSync(artifactFile, JSON.stringify(data), 'utf8');

        this.index.entries[cacheKey] = {
            cache_key: cacheKey,
            producer_version: toolVersion,
            input_hash: aggregateInputHash,
            inputHashes,
            created_at: new Date().toISOString()
        };

        for (const f of files) {
            const abs = path.resolve(f);
            if (!this.index.fileToKeys[abs]) {
                this.index.fileToKeys[abs] = [];
            }
            if (!this.index.fileToKeys[abs].includes(cacheKey)) {
                this.index.fileToKeys[abs].push(cacheKey);
            }
        }

        this._saveIndex();
    }

    /**
     * Invalidates all cache entries that depend on the specified modified file.
     * @param {string} filePath
     * @returns {number} Number of invalidated cache entries
     */
    invalidate(filePath) {
        const abs = path.resolve(filePath);
        const keysToEvict = this.index.fileToKeys[abs] || [];
        let evicted = 0;

        for (const key of keysToEvict) {
            if (this.index.entries[key]) {
                delete this.index.entries[key];
                evicted++;
            }
            const artifactFile = path.join(this.cacheDir, `${key}.artifact`);
            if (fs.existsSync(artifactFile)) {
                try { fs.unlinkSync(artifactFile); } catch (_) {}
            }
        }

        delete this.index.fileToKeys[abs];
        this._saveIndex();
        return evicted;
    }
}
