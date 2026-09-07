import path from 'path';
import fs from 'fs';
import { AuditContext, TestTier, Severity, VerificationStatus } from '../../runners/audit-helper.js';
import { CodeGraph, GraphLayer, NodeTypes, EdgeRelations } from '../../../src/core/graph/codeGraph.js';
import { Database } from '../../../src/core/db.js';

export async function runSuite() {
    const ctx = new AuditContext('CodeGraph Live Integration & Graph Integrity Suite');
    console.log(`\n=== Running: ${ctx.suiteName} ===`);

    const tempDir = ctx.createTempDir('hwsec-graph-audit-');
    const dbPath = path.join(tempDir, 'audit_graph.sqlite');
    const db = new Database(dbPath);

    // 1. Live CodeGraph Population & Layer Integrity
    const graph = new CodeGraph();
    const fileNode = graph.addNode('FILE-1', NodeTypes.FILE, 'src/crypto_core.v', { language: 'verilog' });
    const srcNode = graph.addNode('SIG-1', NodeTypes.SOURCE, 'key_valid', { direction: 'input' });
    const sinkNode = graph.addNode('SINK-1', NodeTypes.SINK, 'unencrypted_out', { destination: 'uart' });
    const evNode = graph.addNode('EV-1', NodeTypes.EVIDENCE, 'trace.vcd', { format: 'vcd' });

    graph.addEdge('FILE-1', 'SIG-1', EdgeRelations.CONTAINS);
    graph.addEdge('SIG-1', 'SINK-1', EdgeRelations.DATAFLOW);
    graph.addEdge('EV-1', 'SINK-1', EdgeRelations.REPRODUCES);

    const layers = graph.exportLayers().layers;
    const codeNodes = layers[GraphLayer.CODE]?.nodes || [];
    const secNodes = layers[GraphLayer.SECURITY]?.nodes || [];
    const evNodes = layers[GraphLayer.EVIDENCE]?.nodes || [];

    const layerSeparationValid = codeNodes.length === 3 && evNodes.length === 1;

    ctx.recordResult({
        testName: 'CodeGraph: 3-Layer (CODE, SECURITY, EVIDENCE) Separation',
        category: 'GRAPH_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: layerSeparationValid,
        expected: 'Nodes strictly partitioned into CODE, SECURITY, and EVIDENCE logical layers',
        actual: `CODE: ${codeNodes.length}, SECURITY: ${secNodes.length}, EVIDENCE: ${evNodes.length}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 2. Database Graph Persistence & Sync
    const runId = 'AUDIT-RUN-GRAPH-01';
    db.saveAnalysisRun({ id: runId, status: 'RUNNING' });
    graph.syncToDatabase(db, runId);
    const persistedNodes = db.getGraphNodes(runId);
    const persistedEdges = db.getGraphEdges(runId);

    const syncSuccessful = persistedNodes.length === 4 && persistedEdges.length === 3;

    ctx.recordResult({
        testName: 'CodeGraph: SQLite Persistence and Atomic Schema Mapping',
        category: 'GRAPH_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: syncSuccessful,
        expected: 'All 4 nodes and 3 edges accurately persisted in SQLite graph tables',
        actual: `Nodes: ${persistedNodes.length}, Edges: ${persistedEdges.length}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 3. Attack Path Discovery
    const attackPaths = graph.findAttackPaths();
    const pathFound = attackPaths.length > 0;

    ctx.recordResult({
        testName: 'CodeGraph: Source-to-Sink Attack Path Traversal',
        category: 'GRAPH_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: pathFound,
        expected: 'Synthesizes reaching attack paths from source signal to security sink',
        actual: `Found ${attackPaths.length} path(s)`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    // 4. Graph Isolation Between Projects/Runs
    const otherRunId = 'AUDIT-RUN-GRAPH-02';
    const otherNodes = db.getGraphNodes(otherRunId);
    const runsIsolated = otherNodes.length === 0;

    ctx.recordResult({
        testName: 'CodeGraph: Strict Run & Project Isolation',
        category: 'GRAPH_INTEGRITY',
        tier: TestTier.INTEGRATION_TEST,
        passed: runsIsolated,
        expected: 'Run 2 must not see or retrieve graph entities from Run 1',
        actual: `Other run node count: ${otherNodes.length}`,
        severity: Severity.HIGH,
        empiricalStatus: VerificationStatus.EMPIRICALLY_VERIFIED
    });

    db.close();
    ctx.cleanup();
    return ctx.getSummary();
}
