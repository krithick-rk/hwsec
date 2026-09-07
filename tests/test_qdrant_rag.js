import assert from 'assert';
import { HWSECQdrantMemory, generateDeterministicEmbedding } from '../src/core/knowledge/qdrantClient.js';
import { RAGEngine } from '../src/core/knowledge/rag.js';

console.log("=== Running Qdrant Semantic Memory & Vector RAG Tests ===");

// 1. Test Embedding Generator
console.log("[Test 1] Testing Deterministic Vector Generator...");
const v1 = generateDeterministicEmbedding("buffer copy strcpy overflow vulnerability");
const v2 = generateDeterministicEmbedding("buffer copy strcpy bounds checking memory");
const v3 = generateDeterministicEmbedding("unrelated hardware clock reset state");

assert.strictEqual(v1.length, 128, "Embedding vector length must be 128");

// Compute Cosine Similarity
function cosineSim(a, b) {
    let dot = 0.0;
    for (let i = 0; i < a.length; i++) dot += a[i] * b[i];
    return dot;
}

const simSimilar = cosineSim(v1, v2);
const simDifferent = cosineSim(v1, v3);
console.log(`  -> Similar text cosine: ${simSimilar.toFixed(3)}, Unrelated text cosine: ${simDifferent.toFixed(3)}`);
assert.ok(simSimilar > simDifferent, "Similar security texts must have higher cosine similarity than unrelated");
console.log("  -> Deterministic vectorization verified.");

// 2. Test Qdrant Client Availability
console.log("[Test 2] Testing Qdrant Server Availability on port 6333...");
const memory = new HWSECQdrantMemory({ qdrant: { url: 'http://localhost:6333' } });
const available = await memory.isAvailable();
console.log(`  -> Qdrant Available: ${available}`);
assert.strictEqual(available, true, "Qdrant daemon must be available on localhost:6333");

// 3. Test Collection Management & Vector Upsert Round Trip
console.log("[Test 3] Testing Collection Upsert and Semantic Search in Qdrant...");
const testCollection = 'test_security_vectors';

const points = [
    {
        id: "11111111-1111-1111-1111-111111111111",
        text: "CWE-120 Buffer copy without checking size using strcpy in C",
        payload: { cwe: "CWE-120", language: "c", title: "Buffer Copy" }
    },
    {
        id: "22222222-2222-2222-2222-222222222222",
        text: "CWE-78 Command injection via exec in Python",
        payload: { cwe: "CWE-78", language: "python", title: "Command Injection" }
    },
    {
        id: "33333333-3333-3333-3333-333333333333",
        text: "CWE-1234 Hardware state machine reset desynchronization in Verilog",
        payload: { cwe: "CWE-1234", language: "verilog", title: "Hardware FSM" }
    }
];

const upsertRes = await memory.upsertPoints(testCollection, points);
assert.strictEqual(upsertRes.success, true, "Upsert points to Qdrant must succeed");
console.log("  -> Points successfully inserted into Qdrant.");

// 4. Test Semantic Vector Search
console.log("[Test 4] Testing Semantic Vector Query...");
const hits = await memory.search(testCollection, {
    queryText: "memory buffer copy unsafe strcpy overflow",
    limit: 1
});
assert.ok(hits.length > 0, "Search must return results");
assert.strictEqual(hits[0].payload.cwe, "CWE-120", "Top hit for buffer copy must be CWE-120");
console.log(`  -> Top Hit: ${hits[0].payload.cwe} (${hits[0].payload.title}) with score ${hits[0].score.toFixed(3)}`);

// 5. Test Metadata Filtering
console.log("[Test 5] Testing Qdrant Metadata Filtering by Language...");
const filteredHits = await memory.search(testCollection, {
    queryText: "injection vulnerability execution",
    filter: {
        must: [{ key: "language", match: { value: "python" } }]
    },
    limit: 1
});
assert.strictEqual(filteredHits.length, 1, "Must return 1 match for filtered query");
assert.strictEqual(filteredHits[0].payload.language, "python", "Payload language must match filter");
assert.strictEqual(filteredHits[0].payload.cwe, "CWE-78", "Filtered hit must be CWE-78");
console.log("  -> Metadata filtering verified.");

// 6. Test RAGEngine Integration
console.log("[Test 6] Testing RAGEngine Semantic Retrieval Integration...");
const rag = new RAGEngine(null, { qdrant: { url: 'http://localhost:6333' } });
const ragResult = await rag.retrieveSemanticContext({
    query: "unsafe string copy memory bounds",
    language: "c",
    limit: 2
});
assert.strictEqual(ragResult.source, 'qdrant_vector', "RAG context source should be qdrant_vector");
assert.ok(ragResult.security_knowledge.length > 0, "Security knowledge must contain semantic hits");
const topCwe = ragResult.security_knowledge[0].id;
assert.strictEqual(topCwe, "CWE-120", "Top retrieved CWE from Qdrant must be CWE-120");
console.log(`  -> RAGEngine retrieved top CWE: ${topCwe}`);

console.log("\n[PASS] All Qdrant Semantic Memory tests passed successfully!\n");
