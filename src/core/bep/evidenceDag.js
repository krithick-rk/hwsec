import crypto from 'crypto';

/**
 * HWSEC Content-Addressed Typed Evidence DAG & Pure EvidenceAuthority
 * 
 * Implements Section 14 & 15 of the Post-AI4 Redesign Specification.
 */

export const EvidenceNodeType = {
    HYPOTHESIS: 'hypothesis',
    FINDING: 'finding',
    ENTRY_POINT: 'entry_point',
    SLICE: 'slice',
    HARNESS: 'harness',
    WITNESS_INPUT: 'witness_input',
    SOLVER_MODEL: 'solver_model',
    RUNTIME_TRACE: 'runtime_trace',
    SINK_EVENT: 'sink_event',
    SECURITY_ORACLE_RESULT: 'security_oracle_result',
    NEGATIVE_CONTROL: 'negative_control',
    PATCH_RESULT: 'patch_result',
    PROVENANCE_MANIFEST: 'provenance_manifest'
};

export const EvidenceEdgeRelation = {
    DERIVED_FROM: 'derived_from',
    SUPPORTS: 'supports',
    REFUTES: 'refutes',
    REPLAYED_BY: 'replayed_by',
    OBSERVED_IN: 'observed_in',
    SAME_ENVIRONMENT_AS: 'same_environment_as'
};

export const VerdictType = {
    DETECTED: 'DETECTED',
    NOT_DETECTED: 'NOT_DETECTED',
    INCONCLUSIVE: 'INCONCLUSIVE'
};

export const InconclusiveReason = {
    ENGINE_UNAVAILABLE: 'ENGINE_UNAVAILABLE',
    ENTRYPOINT_UNRESOLVED: 'ENTRYPOINT_UNRESOLVED',
    SEARCH_BUDGET_EXHAUSTED: 'SEARCH_BUDGET_EXHAUSTED',
    ORACLE_NOT_TRIGGERED: 'ORACLE_NOT_TRIGGERED',
    CONTROL_INVALID: 'CONTROL_INVALID',
    REPLAY_FAILURE: 'REPLAY_FAILURE',
    MODEL_MISSING: 'MODEL_MISSING',
    ENVIRONMENT_MISMATCH: 'ENVIRONMENT_MISMATCH',
    UNSUPPORTED_FRAMEWORK: 'UNSUPPORTED_FRAMEWORK',
    SOURCE_NOT_OBSERVED: 'SOURCE_NOT_OBSERVED',
    SINK_NOT_OBSERVED: 'SINK_NOT_OBSERVED',
    TAMPER_DETECTED: 'TAMPER_DETECTED'
};

/**
 * Computes canonical deterministic SHA-256 hash of an object.
 */
export function canonicalHash(obj) {
    const stringify = (val) => {
        if (val === null || typeof val !== 'object') {
            return JSON.stringify(val);
        }
        if (Array.isArray(val)) {
            return '[' + val.map(stringify).join(',') + ']';
        }
        const keys = Object.keys(val).sort();
        return '{' + keys.map(k => JSON.stringify(k) + ':' + stringify(val[k])).join(',') + '}';
    };
    return crypto.createHash('sha256').update(stringify(obj)).digest('hex');
}

/**
 * EvidenceDAG: Immutable, content-addressed DAG of verified security evidence.
 */
export class EvidenceDag {
    constructor(metadata = {}) {
        this.dag_version = '2.0.0';
        this.run_id = metadata.run_id || `RUN-${crypto.randomBytes(4).toString('hex')}`;
        this.created_at = new Date().toISOString();
        this.nodes = new Map(); // id -> EvidenceNode
        this.edges = [];        // EvidenceEdge[]
    }

    addNode(type, data, explicitId = null) {
        if (!Object.values(EvidenceNodeType).includes(type)) {
            throw new Error(`Invalid EvidenceNodeType: ${type}`);
        }
        const contentHash = canonicalHash(data);
        const id = explicitId || `${type}:${contentHash.substring(0, 16)}`;
        
        const node = {
            id,
            type,
            data: JSON.parse(JSON.stringify(data)),
            content_hash: contentHash,
            created_at: new Date().toISOString()
        };

        this.nodes.set(id, node);
        return node;
    }

    addEdge(sourceId, targetId, relation, metadata = {}) {
        if (!this.nodes.has(sourceId)) {
            throw new Error(`Source node not found in DAG: ${sourceId}`);
        }
        if (!this.nodes.has(targetId)) {
            throw new Error(`Target node not found in DAG: ${targetId}`);
        }
        if (!Object.values(EvidenceEdgeRelation).includes(relation)) {
            throw new Error(`Invalid EvidenceEdgeRelation: ${relation}`);
        }

        const edge = {
            source_id: sourceId,
            target_id: targetId,
            relation,
            metadata: { ...metadata },
            edge_hash: canonicalHash({ sourceId, targetId, relation, metadata })
        };

        this.edges.push(edge);
        return edge;
    }

    getNode(id) {
        return this.nodes.get(id) || null;
    }

    findNodesByType(type) {
        const out = [];
        for (const node of this.nodes.values()) {
            if (node.type === type) out.push(node);
        }
        return out;
    }

    getIncomingEdges(targetId) {
        return this.edges.filter(e => e.target_id === targetId);
    }

    getOutgoingEdges(sourceId) {
        return this.edges.filter(e => e.source_id === sourceId);
    }

    computeDagHash() {
        const nodeHashes = Array.from(this.nodes.values()).map(n => n.content_hash).sort();
        const edgeHashes = this.edges.map(e => e.edge_hash).sort();
        return canonicalHash({ nodes: nodeHashes, edges: edgeHashes });
    }

    verifyIntegrity() {
        // 1. Verify every node's content hash
        for (const [id, node] of this.nodes.entries()) {
            const recomputed = canonicalHash(node.data);
            if (recomputed !== node.content_hash) {
                return { valid: false, error: `Node ${id} hash mismatch (tampered data)` };
            }
        }
        // 2. Verify all edges point to existing nodes
        for (const edge of this.edges) {
            if (!this.nodes.has(edge.source_id)) {
                return { valid: false, error: `Dangling edge source: ${edge.source_id}` };
            }
            if (!this.nodes.has(edge.target_id)) {
                return { valid: false, error: `Dangling edge target: ${edge.target_id}` };
            }
        }
        return { valid: true, dag_hash: this.computeDagHash() };
    }

    toJSON() {
        return {
            dag_version: this.dag_version,
            run_id: this.run_id,
            created_at: this.created_at,
            dag_hash: this.computeDagHash(),
            nodes: Array.from(this.nodes.values()).map(n => ({
                id: n.id,
                type: n.type,
                data: JSON.parse(JSON.stringify(n.data)),
                content_hash: n.content_hash,
                created_at: n.created_at
            })),
            edges: this.edges.map(e => ({ ...e, metadata: { ...e.metadata } }))
        };
    }

    static fromJSON(jsonObj) {
        const dag = new EvidenceDag({ run_id: jsonObj.run_id });
        dag.dag_version = jsonObj.dag_version || '2.0.0';
        dag.created_at = jsonObj.created_at || new Date().toISOString();

        if (Array.isArray(jsonObj.nodes)) {
            for (const node of jsonObj.nodes) {
                dag.nodes.set(node.id, {
                    id: node.id,
                    type: node.type,
                    data: node.data,
                    content_hash: node.content_hash,
                    created_at: node.created_at
                });
            }
        }

        if (Array.isArray(jsonObj.edges)) {
            dag.edges = jsonObj.edges.map(e => ({ ...e }));
        }

        const integrity = dag.verifyIntegrity();
        if (!integrity.valid) {
            throw new Error(`Loaded Evidence DAG failed integrity check: ${integrity.error}`);
        }

        return dag;
    }
}

/**
 * Pure Deterministic Evidence Authority Reducer
 * Evaluates whether required evidence obligations for a hypothesis are satisfied.
 */
export class EvidenceAuthority {
    /**
     * Reduces the DAG to a final bounded verdict for a given hypothesis.
     * @param {EvidenceDag} dag 
     * @param {string} hypothesisId 
     * @returns {Object} VerdictEnvelope
     */
    static reduce(dag, hypothesisId) {
        if (!(dag instanceof EvidenceDag)) {
            throw new Error('dag must be an instance of EvidenceDag');
        }

        const integrity = dag.verifyIntegrity();
        if (!integrity.valid) {
            return {
                verdict: VerdictType.INCONCLUSIVE,
                reason_code: InconclusiveReason.TAMPER_DETECTED,
                reasons: [integrity.error],
                dag_hash: null,
                obligations: {}
            };
        }

        const hypothesisNode = dag.getNode(hypothesisId);
        if (!hypothesisNode || hypothesisNode.type !== EvidenceNodeType.HYPOTHESIS) {
            return {
                verdict: VerdictType.INCONCLUSIVE,
                reason_code: InconclusiveReason.ENTRYPOINT_UNRESOLVED,
                reasons: [`Hypothesis node not found: ${hypothesisId}`],
                dag_hash: dag.computeDagHash(),
                obligations: {}
            };
        }

        const hypData = hypothesisNode.data;
        const incomingEdges = dag.getIncomingEdges(hypothesisId);
        const outgoingEdges = dag.getOutgoingEdges(hypothesisId);

        // Find connected nodes
        const supportedByNodes = [];
        const refutedByNodes = [];
        const entryPointNodes = [];
        const provenanceNodes = dag.findNodesByType(EvidenceNodeType.PROVENANCE_MANIFEST);

        for (const edge of incomingEdges) {
            const src = dag.getNode(edge.source_id);
            if (!src) continue;
            if (edge.relation === EvidenceEdgeRelation.SUPPORTS) {
                supportedByNodes.push(src);
            } else if (edge.relation === EvidenceEdgeRelation.REFUTES) {
                refutedByNodes.push(src);
            }
        }

        for (const edge of outgoingEdges) {
            const tgt = dag.getNode(edge.target_id);
            if (!tgt) continue;
            if (tgt.type === EvidenceNodeType.ENTRY_POINT) {
                entryPointNodes.push(tgt);
            }
        }

        // Check entry points
        const entryPointResolved = entryPointNodes.length > 0 && entryPointNodes.some(ep => ep.data.status !== 'UNRESOLVED');
        
        // Find oracle results, witness inputs, and controls
        const oracleResults = supportedByNodes.filter(n => n.type === EvidenceNodeType.SECURITY_ORACLE_RESULT);
        const witnessInputs = supportedByNodes.filter(n => n.type === EvidenceNodeType.WITNESS_INPUT);
        const negativeControls = supportedByNodes.filter(n => n.type === EvidenceNodeType.NEGATIVE_CONTROL);
        const runtimeTraces = supportedByNodes.filter(n => n.type === EvidenceNodeType.RUNTIME_TRACE);

        // Obligations Checklist
        const obligations = {
            hypothesis_valid: true,
            entry_point_resolved: entryPointResolved,
            witness_input_generated: witnessInputs.length > 0,
            concrete_execution_succeeded: runtimeTraces.some(t => t.data.exit_code === 0 && !t.data.timeout),
            security_oracle_fired: oracleResults.some(o => o.data.condition_satisfied === true),
            negative_control_passed: negativeControls.length > 0 && negativeControls.every(c => c.data.passed === true),
            provenance_manifest_verified: provenanceNodes.length > 0 && provenanceNodes.every(p => p.data.verified === true)
        };

        // If explicit refutation exists (e.g. concolic UNSAT or provable safe invariant)
        if (refutedByNodes.length > 0 && refutedByNodes.some(r => r.data.refuted === true)) {
            return {
                verdict: VerdictType.NOT_DETECTED,
                reason_code: 'BOUNDED_EXPLICIT_REFUTATION',
                reasons: ['Explicit refutation evidence demonstrated absence within declared scope'],
                dag_hash: dag.computeDagHash(),
                obligations
            };
        }

        // DETECTED condition: ALL 7 obligations must be strictly met
        const allMet = Object.values(obligations).every(Boolean);
        if (allMet) {
            return {
                verdict: VerdictType.DETECTED,
                reason_code: 'VERIFIED_EXPLOIT_WITNESS',
                reasons: ['Valid replayable attack witness confirmed with security oracle and negative control'],
                dag_hash: dag.computeDagHash(),
                provenance_hash: provenanceNodes[0]?.content_hash || null,
                witness_input: witnessInputs[0]?.data || null,
                obligations
            };
        }

        // Otherwise: Deterministic INCONCLUSIVE with machine-readable reasons
        const missingReasons = [];
        if (!obligations.entry_point_resolved) missingReasons.push(InconclusiveReason.ENTRYPOINT_UNRESOLVED);
        if (!obligations.witness_input_generated) missingReasons.push(InconclusiveReason.SEARCH_BUDGET_EXHAUSTED);
        if (!obligations.concrete_execution_succeeded) missingReasons.push(InconclusiveReason.REPLAY_FAILURE);
        if (!obligations.security_oracle_fired) missingReasons.push(InconclusiveReason.ORACLE_NOT_TRIGGERED);
        if (!obligations.negative_control_passed) missingReasons.push(InconclusiveReason.CONTROL_INVALID);
        if (!obligations.provenance_manifest_verified) missingReasons.push(InconclusiveReason.ENVIRONMENT_MISMATCH);

        return {
            verdict: VerdictType.INCONCLUSIVE,
            reason_code: missingReasons[0] || InconclusiveReason.SEARCH_BUDGET_EXHAUSTED,
            reasons: missingReasons,
            dag_hash: dag.computeDagHash(),
            obligations
        };
    }
}
