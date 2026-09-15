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
    PROVENANCE_MANIFEST: 'provenance_manifest',
    POV_ARTIFACT: 'pov_artifact',
    POV_REPLAY: 'pov_replay',
    POV_VERIFICATION: 'pov_verification'
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
        const cleanData = JSON.parse(JSON.stringify(data || {}));
        const contentHash = canonicalHash(cleanData);
        const id = explicitId || `${type}:${contentHash.substring(0, 16)}`;
        
        const node = {
            id,
            type,
            data: cleanData,
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

    /**
     * Attaches typed PoV evidence nodes to a hypothesis in the DAG.
     * @param {string} hypothesisId
     * @param {Object} pov ProofOfVulnerability or raw PoV record
     * @param {Object} [replayLog] Optional replay verification log
     * @returns {{ artifactNode: Object, replayNode: Object|null, verificationNode: Object|null }}
     */
    attachPoV(hypothesisId, pov, replayLog = null) {
        if (!this.nodes.has(hypothesisId)) {
            throw new Error(`Hypothesis node ${hypothesisId} not found in DAG.`);
        }

        const povData = typeof pov.toJSON === 'function' ? pov.toJSON() : pov;
        const artifactNode = this.addNode(EvidenceNodeType.POV_ARTIFACT, {
            pov_id: povData.pov_id,
            bundle_path: povData.bundle_path,
            bundle_hash: povData.bundle_hash,
            status: povData.status,
            reproduction_command: povData.reproduction?.command,
            vulnerability_class: povData.vulnerability_class
        });
        this.addEdge(hypothesisId, artifactNode.id, EvidenceEdgeRelation.SUPPORTS);

        let replayNode = null;
        let verificationNode = null;

        if (replayLog) {
            replayNode = this.addNode(EvidenceNodeType.POV_REPLAY, {
                pov_id: povData.pov_id,
                execution: replayLog.execution,
                exit_code: replayLog.execution?.exit_code,
                duration_ms: replayLog.execution?.duration_ms,
                timestamp: replayLog.timestamp
            });
            this.addEdge(artifactNode.id, replayNode.id, EvidenceEdgeRelation.DERIVED_FROM);

            verificationNode = this.addNode(EvidenceNodeType.POV_VERIFICATION, {
                pov_id: povData.pov_id,
                verified: replayLog.verified,
                pov_status: replayLog.pov_status,
                reason_code: replayLog.reason_code,
                security_effect_occurred: replayLog.observations?.security_effect_occurred,
                negative_control_passed: replayLog.observations?.negative_control_passed
            });
            this.addEdge(
                hypothesisId,
                verificationNode.id,
                replayLog.verified ? EvidenceEdgeRelation.SUPPORTS : EvidenceEdgeRelation.REFUTES
            );
        }

        return { artifactNode, replayNode, verificationNode };
    }

    getRootHash() {
        return this.computeDagHash();
    }

    exportDAG() {
        return this.toJSON();
    }

    toJSON() {
        const hash = this.computeDagHash();
        return {
            dag_version: this.dag_version,
            run_id: this.run_id,
            created_at: this.created_at,
            root_hash: hash,
            dag_hash: hash,
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

        const connectedEdges = [...incomingEdges, ...outgoingEdges];
        for (const edge of connectedEdges) {
            const otherId = (edge.source_id === hypothesisId) ? edge.target_id : edge.source_id;
            const node = dag.getNode(otherId);
            if (!node) continue;
            if (edge.relation === EvidenceEdgeRelation.SUPPORTS) {
                if (!supportedByNodes.includes(node)) supportedByNodes.push(node);
            } else if (edge.relation === EvidenceEdgeRelation.REFUTES) {
                if (!refutedByNodes.includes(node)) refutedByNodes.push(node);
            }
            if (node.type === EvidenceNodeType.ENTRY_POINT) {
                if (!entryPointNodes.includes(node)) entryPointNodes.push(node);
            }
        }

        // Check entry points
        const entryPointResolved = entryPointNodes.length > 0 && entryPointNodes.some(ep => ep.data.status !== 'UNRESOLVED');
        
        // Find oracle results, witness inputs, controls, and traces
        const oracleResults = dag.findNodesByType(EvidenceNodeType.SECURITY_ORACLE_RESULT);
        const witnessInputs = supportedByNodes.filter(n => n.type === EvidenceNodeType.WITNESS_INPUT);
        const negativeControls = supportedByNodes.filter(n => n.type === EvidenceNodeType.NEGATIVE_CONTROL);
        const runtimeTraces = dag.findNodesByType(EvidenceNodeType.RUNTIME_TRACE);

        // Obligations Checklist
        const obligations = {
            hypothesis_valid: true,
            entry_point_resolved: entryPointResolved,
            witness_input_generated: witnessInputs.length > 0,
            concrete_execution_succeeded: runtimeTraces.some(t => {
                const exit = t.data.exit_code !== undefined ? t.data.exit_code : (t.data.exitCode !== undefined ? t.data.exitCode : t.data.raw_execution?.exitCode);
                const timedOut = Boolean(t.data.timeout || t.data.timedOut || t.data.raw_execution?.timedOut);
                return exit === 0 && !timedOut;
            }),
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
