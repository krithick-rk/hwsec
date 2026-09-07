import { QdrantClient } from '@qdrant/js-client-rest';
import crypto from 'crypto';

export const VECTOR_DIMENSION = 128;

/**
 * Generates a deterministic normalized dense vector from text.
 * Uses SHA-256 token hashing and L2 normalization for cosine similarity.
 */
export function generateDeterministicEmbedding(text, dimension = VECTOR_DIMENSION) {
    const vec = new Float32Array(dimension);
    if (!text || typeof text !== 'string') return Array.from(vec);

    const tokens = text.toLowerCase().match(/\b\w+\b/g) || [text];
    for (const token of tokens) {
        const hash = crypto.createHash('sha256').update(token).digest();
        const bucket = (hash[0] | (hash[1] << 8)) % dimension;
        const sign = (hash[2] % 2 === 0) ? 1.0 : -1.0;
        const weight = 1.0 + (token.length > 5 ? 0.5 : 0.0);
        vec[bucket] += sign * weight;
    }

    // L2 Normalization
    let norm = 0.0;
    for (let i = 0; i < dimension; i++) {
        norm += vec[i] * vec[i];
    }
    norm = Math.sqrt(norm);
    if (norm > 0.0) {
        for (let i = 0; i < dimension; i++) {
            vec[i] /= norm;
        }
    }

    return Array.from(vec);
}

/**
 * HWSEC Qdrant Vector Memory Layer
 */
export class HWSECQdrantMemory {
    constructor(config = {}) {
        this.config = config;
        this.url = process.env.QDRANT_URL || config.qdrant?.url || 'http://localhost:6333';
        this.apiKey = process.env.QDRANT_API_KEY || config.qdrant?.api_key || undefined;
        this.enabled = config.qdrant?.enabled !== false;
        this.client = new QdrantClient({
            url: this.url,
            apiKey: this.apiKey,
            timeout: 5000
        });
        this.initializedCollections = new Set();
    }

    /**
     * Checks if Qdrant daemon is active and responsive.
     */
    async isAvailable() {
        if (!this.enabled) return false;
        try {
            await this.client.getCollections();
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Ensures target collection exists in Qdrant with Cosine distance.
     */
    async ensureCollection(collectionName, vectorSize = VECTOR_DIMENSION) {
        if (this.initializedCollections.has(collectionName)) return true;

        try {
            const existing = await this.client.getCollections();
            const exists = existing.collections.some(c => c.name === collectionName);
            if (!exists) {
                await this.client.createCollection(collectionName, {
                    vectors: {
                        size: vectorSize,
                        distance: 'Cosine'
                    }
                });
            }
            this.initializedCollections.add(collectionName);
            return true;
        } catch (err) {
            console.error(`[-] Failed to initialize Qdrant collection '${collectionName}': ${err.message}`);
            return false;
        }
    }

    /**
     * Inserts or updates vectors in a collection.
     */
    async upsertPoints(collectionName, points) {
        await this.ensureCollection(collectionName);

        const formattedPoints = points.map(p => ({
            id: p.id || crypto.randomUUID(),
            vector: p.vector || generateDeterministicEmbedding(p.text || JSON.stringify(p.payload)),
            payload: p.payload || {}
        }));

        try {
            await this.client.upsert(collectionName, {
                wait: true,
                points: formattedPoints
            });
            return { success: true, count: formattedPoints.length };
        } catch (err) {
            console.error(`[-] Qdrant upsert failed on '${collectionName}': ${err.message}`);
            return { success: false, error: err.message };
        }
    }

    /**
     * Performs semantic similarity search with optional metadata filtering.
     */
    async search(collectionName, { queryText, queryVector = null, filter = null, limit = 5 }) {
        await this.ensureCollection(collectionName);

        const vector = queryVector || generateDeterministicEmbedding(queryText);

        const searchParams = {
            query: vector,
            limit,
            with_payload: true
        };

        if (filter) {
            searchParams.filter = filter;
        }

        try {
            const res = await this.client.query(collectionName, searchParams);
            const hits = res.points || [];
            return hits.map(h => ({
                id: h.id,
                score: h.score,
                payload: h.payload
            }));
        } catch (err) {
            console.error(`[-] Qdrant search failed on '${collectionName}': ${err.message}`);
            return [];
        }
    }
}
