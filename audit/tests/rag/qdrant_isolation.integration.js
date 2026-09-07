import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { RAGEngine } from '../../../src/core/knowledge/rag.js';
import { HWSECQdrantMemory, generateDeterministicEmbedding } from '../../../src/core/knowledge/qdrantClient.js';

export async function runSuite() {
    const ctx = new AuditContext('Qdrant Vector Memory & RAG Isolation Integration Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const qdrant = new HWSECQdrantMemory();
    const isOnline = await qdrant.isAvailable();

    // 1. Daemon Availability
    ctx.recordResult({
        testName: 'Qdrant: Vector Daemon Online on Port 6333',
        category: 'RAG_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: isOnline,
        expected: 'Qdrant daemon reachable and healthy on port 6333',
        actual: `Available: ${isOnline}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    if (!isOnline) {
        return ctx.getSummary();
    }

    const rag = new RAGEngine();
    await rag.syncToQdrant();

    // 2. Semantic Synonym Retrieval Test
    // Lexically different concepts: "out-of-bounds heap memory corruption" vs "buffer overflow" (CWE-120/CWE-122)
    const hits = await qdrant.search('cwe_patterns', {
        queryText: 'out-of-bounds heap memory corruption copy',
        limit: 3
    });

    const foundBufferCwe = hits.some(h => h.payload?.id === 'CWE-120' || h.payload?.id === 'CWE-125');
    ctx.recordResult({
        testName: 'RAG: Semantic Retrieval on Lexical Synonyms',
        category: 'RAG_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: foundBufferCwe,
        expected: 'Query for memory corruption retrieves buffer overflow pattern (CWE-120)',
        actual: `Top hit: ${hits[0]?.payload?.id || 'None'} (score: ${hits[0]?.score?.toFixed(3)})`,
        severity: Severity.MEDIUM,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 3. Metadata Filtering Test (Language isolation)
    const verilogHits = await qdrant.search('cwe_patterns', {
        queryText: 'assertion violation',
        filter: {
            must: [{ key: 'languages', match: { value: 'verilog' } }]
        },
        limit: 5
    });

    const allVerilog = verilogHits.length > 0 && verilogHits.every(h => (h.payload?.languages || []).includes('verilog'));
    ctx.recordResult({
        testName: 'RAG: Qdrant Metadata Filtering by Language',
        category: 'RAG_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: allVerilog,
        expected: 'All retrieved points must contain requested language metadata filter',
        actual: `Hits: ${verilogHits.length}, allVerilog: ${allVerilog}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 4. Cross-Project Isolation in Vector Collections
    // Points stored for Project A must have project_id metadata and never bleed to Project B
    const collectionName = 'audit_project_isolation';
    await qdrant.client.recreateCollection(collectionName, {
        vectors: { size: 128, distance: 'Cosine' }
    }).catch(() => {});

    await qdrant.upsertPoints(collectionName, [
        {
            id: '11111111-1111-1111-1111-111111111111',
            text: 'Secret proprietary algorithm for Project Alpha',
            payload: { projectId: 'project-alpha', classification: 'TOP_SECRET' }
        },
        {
            id: '22222222-2222-2222-2222-222222222222',
            text: 'Public documentation for Project Beta',
            payload: { projectId: 'project-beta', classification: 'PUBLIC' }
        }
    ]);

    // Query from Project Beta scope
    const betaHits = await qdrant.search(collectionName, {
        queryText: 'algorithm',
        filter: {
            must: [{ key: 'projectId', match: { value: 'project-beta' } }]
        },
        limit: 5
    });

    const leaksAlpha = betaHits.some(h => h.payload?.projectId === 'project-alpha');
    ctx.recordResult({
        testName: 'RAG: Strict Cross-Project Vector Memory Isolation',
        category: 'RAG_INTEGRITY',
        tier: TestTier.ADVERSARIAL_TEST,
        passed: !leaksAlpha,
        expected: 'Project Beta must never retrieve Project Alpha vectors',
        actual: leaksAlpha ? 'VULNERABLE: Project Alpha vectors retrieved!' : 'Zero cross-project leakage',
        severity: Severity.CRITICAL,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    return ctx.getSummary();
}
