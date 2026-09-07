/**
 * Comprehensive Code, Security Knowledge & Evidence Graph for HWSEC
 */

export const NodeTypes = {
    FILE: "FILE",
    MODULE: "MODULE",
    FUNCTION: "FUNCTION",
    CALL: "CALL",
    VARIABLE: "VARIABLE",
    SYMBOL: "SYMBOL",
    SOURCE: "SOURCE",
    SINK: "SINK",
    SECURITY_BOUNDARY: "SECURITY_BOUNDARY",
    HYPOTHESIS: "HYPOTHESIS",
    INVARIANT: "INVARIANT",
    EVIDENCE: "EVIDENCE",
    FINDING: "FINDING"
};

export const EdgeRelations = {
    CONTAINS: "CONTAINS",
    CALLS: "CALLS",
    DATAFLOW: "DATAFLOW",
    CROSSES: "CROSSES",
    HYPOTHESIZES: "HYPOTHESIZES",
    EVIDENCES: "EVIDENCES",
    CORRELATES_WITH: "CORRELATES_WITH",
    SUPPORTS: "SUPPORTS",
    CONTRADICTS: "CONTRADICTS",
    DERIVED_FROM: "DERIVED_FROM",
    REPRODUCES: "REPRODUCES",
    REACHES: "REACHES"
};

export const GraphLayer = {
    CODE: "CODE",
    SECURITY: "SECURITY",
    EVIDENCE: "EVIDENCE"
};

export class CodeGraph {
    constructor() {
        this.nodes = new Map();
        this.edges = [];
        this.adjacency = new Map();
        this.externalNodeMapping = new Map(); // e.g. "joern:<id>" -> hwsecId
    }

    /**
     * Resolves the logical layer for a node type.
     */
    static getLayerForNodeType(type) {
        switch (type) {
            case NodeTypes.FILE:
            case NodeTypes.MODULE:
            case NodeTypes.FUNCTION:
            case NodeTypes.CALL:
            case NodeTypes.VARIABLE:
            case NodeTypes.SYMBOL:
            case NodeTypes.SOURCE:
            case NodeTypes.SINK:
                return GraphLayer.CODE;
            case NodeTypes.SECURITY_BOUNDARY:
            case NodeTypes.HYPOTHESIS:
            case NodeTypes.INVARIANT:
                return GraphLayer.SECURITY;
            case NodeTypes.EVIDENCE:
            case NodeTypes.FINDING:
                return GraphLayer.EVIDENCE;
            default:
                return GraphLayer.CODE;
        }
    }

    addNode(id, type, label, metadata = {}) {
        const layer = CodeGraph.getLayerForNodeType(type);
        const node = { id, type, label, layer, metadata };
        this.nodes.set(id, node);
        if (!this.adjacency.has(id)) {
            this.adjacency.set(id, []);
        }
        return node;
    }

    /**
     * Links an external tool node ID (e.g. from Joern or CodeQL) to an internal HWSEC node.
     */
    linkExternalNode(toolName, externalId, hwsecNodeId) {
        const key = `${toolName}:${externalId}`;
        this.externalNodeMapping.set(key, hwsecNodeId);
    }

    resolveExternalNode(toolName, externalId) {
        return this.externalNodeMapping.get(`${toolName}:${externalId}`) || null;
    }

    addEdge(sourceId, targetId, relation, weight = 1.0, metadata = {}) {
        if (!this.nodes.has(sourceId)) {
            this.addNode(sourceId, NodeTypes.VARIABLE, sourceId);
        }
        if (!this.nodes.has(targetId)) {
            this.addNode(targetId, NodeTypes.VARIABLE, targetId);
        }

        const edge = { sourceId, targetId, relation, weight, metadata };
        this.edges.push(edge);

        if (!this.adjacency.has(sourceId)) this.adjacency.set(sourceId, []);
        this.adjacency.get(sourceId).push({ targetId, relation, weight, metadata });
        return edge;
    }

    getNode(id) {
        return this.nodes.get(id) || null;
    }

    getNeighbors(id) {
        return this.adjacency.get(id) || [];
    }

    /**
     * Discovers directed paths from sourceId to targetId up to maxDepth.
     */
    findPaths(sourceId, targetId, maxDepth = 6) {
        const results = [];
        const visited = new Set();

        const dfs = (current, path, depth) => {
            if (depth > maxDepth) return;
            if (current === targetId) {
                results.push([...path]);
                return;
            }

            visited.add(current);
            const neighbors = this.getNeighbors(current);
            for (const edge of neighbors) {
                if (!visited.has(edge.targetId)) {
                    path.push({ node: edge.targetId, relation: edge.relation, metadata: edge.metadata });
                    dfs(edge.targetId, path, depth + 1);
                    path.pop();
                }
            }
            visited.delete(current);
        };

        dfs(sourceId, [{ node: sourceId, relation: 'START' }], 0);
        return results;
    }

    /**
     * Identifies potential attack paths from any SOURCE node to any SINK node.
     */
    findAttackPaths(maxDepth = 6) {
        const sources = Array.from(this.nodes.values()).filter(n => n.type === NodeTypes.SOURCE);
        const sinks = Array.from(this.nodes.values()).filter(n => n.type === NodeTypes.SINK);

        const attackPaths = [];
        for (const src of sources) {
            for (const snk of sinks) {
                const paths = this.findPaths(src.id, snk.id, maxDepth);
                for (const p of paths) {
                    attackPaths.push({
                        source: src,
                        sink: snk,
                        path: p.map(step => step.node),
                        steps: p,
                        length: p.length
                    });
                }
            }
        }

        return attackPaths;
    }

    /**
     * Exports logically separated layers of the graph.
     */
    exportLayers() {
        const codeNodes = [];
        const securityNodes = [];
        const evidenceNodes = [];

        for (const node of this.nodes.values()) {
            if (node.layer === GraphLayer.CODE) codeNodes.push(node);
            else if (node.layer === GraphLayer.SECURITY) securityNodes.push(node);
            else if (node.layer === GraphLayer.EVIDENCE) evidenceNodes.push(node);
        }

        return {
            layers: {
                [GraphLayer.CODE]: { nodes: codeNodes },
                [GraphLayer.SECURITY]: { nodes: securityNodes },
                [GraphLayer.EVIDENCE]: { nodes: evidenceNodes }
            },
            totalNodes: this.nodes.size,
            totalEdges: this.edges.length,
            edges: this.edges
        };
    }

    /**
     * Persists graph nodes and edges into SQLite database.
     */
    syncToDatabase(db, runId = 'global') {
        if (!db || typeof db.saveGraphNode !== 'function') return false;

        for (const node of this.nodes.values()) {
            try {
                db.saveGraphNode({
                    id: node.id,
                    runId,
                    type: node.type,
                    label: node.label,
                    metadata: { ...node.metadata, layer: node.layer }
                });
            } catch {}
        }

        for (let i = 0; i < this.edges.length; i++) {
            const edge = this.edges[i];
            try {
                db.saveGraphEdge({
                    id: `EDGE-${runId}-${i}`,
                    runId,
                    sourceId: edge.sourceId,
                    targetId: edge.targetId,
                    relation: edge.relation,
                    weight: edge.weight
                });
            } catch {}
        }

        return true;
    }
}
