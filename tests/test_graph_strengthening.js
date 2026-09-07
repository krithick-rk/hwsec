import assert from 'assert';
import { CodeGraph, NodeTypes, EdgeRelations, GraphLayer } from '../src/core/graph/codeGraph.js';
import { Database } from '../src/core/db.js';
import path from 'path';
import fs from 'fs';

console.log("=== Running Graph Strengthening & Layer Separation Tests ===");

const graph = new CodeGraph();

// 1. Test Node Types & Logical Layer Separation
console.log("[Test 1] Testing Node Types and Logical Layer Assignment...");
const fNode = graph.addNode('file_1', NodeTypes.FILE, 'main.c');
const cNode = graph.addNode('call_1', NodeTypes.CALL, 'strcpy()');
const bNode = graph.addNode('boundary_1', NodeTypes.SECURITY_BOUNDARY, 'Network Perimeter');
const invNode = graph.addNode('inv_1', NodeTypes.INVARIANT, 'Buffer Never Overwritten');
const evNode = graph.addNode('ev_1', NodeTypes.EVIDENCE, 'VCD Counterexample Trace');

assert.strictEqual(fNode.layer, GraphLayer.CODE, "File must belong to CODE layer");
assert.strictEqual(cNode.layer, GraphLayer.CODE, "Call must belong to CODE layer");
assert.strictEqual(bNode.layer, GraphLayer.SECURITY, "Boundary must belong to SECURITY layer");
assert.strictEqual(invNode.layer, GraphLayer.SECURITY, "Invariant must belong to SECURITY layer");
assert.strictEqual(evNode.layer, GraphLayer.EVIDENCE, "Evidence must belong to EVIDENCE layer");
console.log("  -> Logical layer mapping verified.");

// 2. Test Explicit Relations
console.log("[Test 2] Testing Explicit Semantic Relations...");
graph.addEdge('ev_1', 'inv_1', EdgeRelations.CONTRADICTS);
graph.addEdge('ev_1', 'call_1', EdgeRelations.REPRODUCES);
graph.addEdge('call_1', 'boundary_1', EdgeRelations.REACHES);

const layers = graph.exportLayers();
assert.strictEqual(layers.layers[GraphLayer.CODE].nodes.length, 2);
assert.strictEqual(layers.layers[GraphLayer.SECURITY].nodes.length, 2);
assert.strictEqual(layers.layers[GraphLayer.EVIDENCE].nodes.length, 1);
assert.strictEqual(layers.edges.length, 3);
console.log("  -> Explicit relations (CONTRADICTS, REPRODUCES, REACHES) verified.");

// 3. Test External Tool Node Linking
console.log("[Test 3] Testing External Tool Node ID Linking...");
graph.linkExternalNode('joern', '10482', 'call_1');
graph.linkExternalNode('codeql', 'node_541', 'call_1');

assert.strictEqual(graph.resolveExternalNode('joern', '10482'), 'call_1', "Must resolve Joern node ID");
assert.strictEqual(graph.resolveExternalNode('codeql', 'node_541'), 'call_1', "Must resolve CodeQL node ID");
console.log("  -> Tool node ID resolution verified.");

// 4. Test SQLite Persistence
console.log("[Test 4] Testing SQLite Sync for Graph Nodes and Edges...");
const testDbPath = path.resolve('hwsec-output/test_graph.db');
if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);

const db = new Database(testDbPath);
db.saveProject({ id: 'test_proj', path: 'tests', name: 'Test' });
db.saveAnalysisRun({ id: 'run_graph_test', projectId: 'test_proj', status: 'RUNNING' });

const syncRes = graph.syncToDatabase(db, 'run_graph_test');
assert.strictEqual(syncRes, true, "Graph sync must return true");

const storedNodes = db.getGraphNodes('run_graph_test');
assert.strictEqual(storedNodes.length, 5, "Database must contain 5 graph nodes");
console.log(`  -> Database successfully persisted ${storedNodes.length} graph nodes with relations.`);

db.close();
console.log("\n[PASS] All Graph Strengthening tests passed successfully!\n");
