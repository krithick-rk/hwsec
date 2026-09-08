import crypto from 'crypto';
import path from 'path';
import fs from 'fs';
import { NodeTypes, EdgeRelations } from '../core/graph/codeGraph.js';
import { Severity, createFinding } from '../core/schema.js';

/**
 * HWSEC Candidate Generation & Graph Escalation Layer
 * Pools SAST rules, dataflow reachability, dangerous APIs, security boundaries,
 * and analyzer disagreements into a unified candidate pool.
 */

export class CandidateGenerator {
    /**
     * @param {Object} [codeGraph]
     * @param {Object} [coverageMatrix]
     */
    constructor(codeGraph = null, coverageMatrix = null) {
        this.codeGraph = codeGraph;
        this.coverageMatrix = coverageMatrix;
    }

    /**
     * Generates and escalates candidates from all available static and graph evidence.
     * @param {Object} params
     * @param {Array<Object>} params.files - Array of { path, language }
     * @param {Array<Object>} params.deterministicFindings
     * @param {Array<string>} [params.executedTools=[]]
     * @returns {Array<Object>} Unified candidate pool
     */
    generateCandidates({ files = [], deterministicFindings = [], executedTools = [] }) {
        const candidatePool = [];
        const seenLocations = new Set();

        // 1. Ingest Deterministic Tool Findings into Candidate Pool
        for (const finding of deterministicFindings) {
            const candidate = {
                id: finding.id || `CAND-${crypto.randomBytes(4).toString('hex')}`,
                source: "deterministic_tool",
                sourceTool: finding.source_tool || "unknown",
                title: finding.title,
                cwe: finding.cwe_id || finding.title?.match(/CWE-\d+/)?.[0] || "CWE-Unknown",
                severity: finding.severity || Severity.MEDIUM,
                confidence: finding.confidence || 0.6,
                sourceLocations: finding.source_locations || [],
                evidence: finding.evidence || [],
                dataflowReachable: finding.dataflow_reachable || false,
                escalationLevel: finding.dataflow_reachable ? "DEEP_DATAFLOW" : "BASELINE",
                rawFinding: finding
            };

            candidatePool.push(candidate);

            for (const loc of candidate.sourceLocations) {
                const locKey = `${loc.path}:${loc.startLine || 1}`;
                seenLocations.add(locKey);

                // Add to CodeGraph if present
                if (this.codeGraph) {
                    const findingNodeId = `finding:${candidate.id}`;
                    this.codeGraph.addNode(findingNodeId, NodeTypes.FINDING, candidate.title, {
                        cwe: candidate.cwe,
                        severity: candidate.severity
                    });
                    const fileNodeId = path.resolve(loc.path);
                    this.codeGraph.addEdge(findingNodeId, fileNodeId, EdgeRelations.EVIDENCES);
                }
            }

            // Update coverage matrix
            if (this.coverageMatrix) {
                const lang = finding.source_locations?.[0]?.path ? path.extname(finding.source_locations[0].path).slice(1) : null;
                this.coverageMatrix.recordAnalysis({
                    cwe: candidate.cwe,
                    language: lang,
                    tool: candidate.sourceTool,
                    filePath: finding.source_locations?.[0]?.path,
                    findingsCount: 1
                });
            }
        }

        // 2. Discover Dangerous API Call & Security Boundary Crossings
        for (const fileObj of files) {
            const filePath = fileObj.path || fileObj;
            const lang = fileObj.language || path.extname(filePath).slice(1).toLowerCase();

            let content = "";
            try {
                content = fs.readFileSync(filePath, 'utf8');
            } catch {
                continue;
            }

            const boundaryPatterns = [
                { regex: /\b(request\.(getParameter|args|form|GET|POST)|req\.(body|query|params))\b/g, label: "HTTP User Input" },
                { regex: /\b(socket|connect|listen|recv|read)\s*\(/g, label: "Network Socket Boundary" },
                { regex: /\b(FileInputStream|open|fopen|readFile)\b/g, label: "Filesystem Input Boundary" }
            ];

            let hasBoundary = false;
            for (const bp of boundaryPatterns) {
                if (bp.regex.test(content)) {
                    hasBoundary = true;
                    if (this.codeGraph) {
                        const boundaryNodeId = `boundary:${path.basename(filePath)}:${bp.label}`;
                        this.codeGraph.addNode(boundaryNodeId, NodeTypes.SECURITY_BOUNDARY, bp.label, {
                            file: filePath
                        });
                        this.codeGraph.addEdge(boundaryNodeId, path.resolve(filePath), EdgeRelations.CROSSES);
                    }
                }
            }

            // If file crosses security boundaries and has dangerous sinks, escalate
            if (hasBoundary) {
                const sinkPatterns = [
                    { regex: /\b(system|exec|popen|execve|Runtime\.getRuntime\(\)\.exec)\s*\(/g, cwe: "CWE-78", title: "Potential Command Injection Boundary Crossing" },
                    { regex: /\b(createQuery|executeQuery|execSQL|rawQuery)\s*\(/g, cwe: "CWE-89", title: "Potential SQL Injection Boundary Crossing" },
                    { regex: /\b(strcpy|sprintf|gets|scanf)\s*\(/g, cwe: "CWE-120", title: "Unbounded Buffer Operation at Security Boundary" },
                    { regex: /\b(readObject|ObjectInputStream)\b/g, cwe: "CWE-502", title: "Deserialization at Untrusted Input Boundary" }
                ];

                for (const sp of sinkPatterns) {
                    const match = sp.regex.exec(content);
                    if (match) {
                        const locKey = `${filePath}:1`;
                        if (!seenLocations.has(locKey)) {
                            seenLocations.add(locKey);
                            const boundaryCand = {
                                id: `CAND-BOUND-${crypto.randomBytes(4).toString('hex')}`,
                                source: "security_boundary_escalation",
                                sourceTool: "candidate_generator",
                                title: sp.title,
                                cwe: sp.cwe,
                                severity: Severity.HIGH,
                                confidence: 0.75,
                                sourceLocations: [{ path: filePath, startLine: 1, endLine: 1 }],
                                evidence: [],
                                dataflowReachable: true,
                                escalationLevel: "TARGETED_FORMAL_LLM"
                            };
                            candidatePool.push(boundaryCand);
                        }
                    }
                }
            }
        }

        // 3. Analyzer Disagreement Escalation
        if (executedTools.length > 1) {
            const toolHits = new Map(); // file -> Set<tool>
            for (const finding of deterministicFindings) {
                const loc = finding.source_locations?.[0]?.path;
                if (!loc) continue;
                if (!toolHits.has(loc)) toolHits.set(loc, new Set());
                toolHits.get(loc).add(finding.source_tool);
            }

            for (const [fileLoc, toolsFound] of toolHits.entries()) {
                const missingTools = executedTools.filter(t => !toolsFound.has(t));
                if (missingTools.length > 0 && toolsFound.size >= 1) {
                    const disagreementCand = {
                        id: `CAND-DISAGREE-${crypto.randomBytes(4).toString('hex')}`,
                        source: "analyzer_disagreement",
                        sourceTool: "disagreement_controller",
                        title: `Analyzer Disagreement on ${path.basename(fileLoc)}: [${Array.from(toolsFound).join(', ')}] reported findings vs [${missingTools.join(', ')}] clean`,
                        cwe: "CWE-Disagreement",
                        severity: Severity.MEDIUM,
                        confidence: 0.65,
                        sourceLocations: [{ path: fileLoc, startLine: 1, endLine: 1 }],
                        evidence: [],
                        escalationLevel: "DEEP_DATAFLOW"
                    };
                    candidatePool.push(disagreementCand);
                }
            }
        }

        return candidatePool;
    }
}
