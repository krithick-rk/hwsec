import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { CaseAdapter } from '../../case-registry/caseAdapter.js';

export class SymbolicTargetGenerator {
    constructor() {
        this.caseAdapter = new CaseAdapter();
        this.defaultLimits = {
            max_paths: 100,
            max_depth: 20,
            solver_timeout_ms: 10000,
            wall_timeout_ms: 30000
        };
    }

    getSecurityCondition(cwe) {
        switch (cwe) {
            case 'CWE-22':
                return 'canonicalPath.startsWith(baseDir) == false';
            case 'CWE-78':
                return 'commandTokens.length > 1 || containsShellMetachars(command)';
            case 'CWE-89':
                return 'sqlAst.hasInjectedClauses == true || querySemanticsAltered == true';
            case 'CWE-79':
                return 'unescapedHtmlRender == true';
            case 'CWE-90':
                return 'filterStructureModified == true';
            case 'CWE-643':
                return 'xpathSyntaxModified == true';
            default:
                return 'untrustedInputReachesSink(sink, input) == true';
        }
    }

    generateTargetsFromFindings(findings) {
        const targets = [];
        const seenCases = new Set();

        for (const finding of findings) {
            const caseObj = this.caseAdapter.getCaseById(finding.case_id);
            if (!caseObj) continue;

            const targetKey = `${finding.case_id}-${finding.cwe}`;
            if (seenCases.has(targetKey)) continue;
            seenCases.add(targetKey);

            const entrypoint = `${caseObj.target_class}.${caseObj.entrypoint_method || 'doPost'}`;
            const symbolicInputs = [caseObj.input_param_name || 'vector'];
            const source = `${finding.source_boundary || 'request.getParameter'}("${caseObj.input_param_name || 'vector'}")`;
            const sink = caseObj.sink_type || finding.sink || 'targetSink';
            const pathHint = finding.path_hint || [caseObj.entrypoint_method || 'doPost'];
            const securityCondition = this.getSecurityCondition(finding.cwe);

            const target = {
                case_id: caseObj.case_id,
                entrypoint: entrypoint,
                symbolic_inputs: symbolicInputs,
                source: source,
                sink: sink,
                path_hint: pathHint,
                security_condition: securityCondition,
                limits: { ...this.defaultLimits }
            };

            targets.push(target);
        }

        return targets;
    }

    generateAndSave(findingsPath = 'prototype/artifacts/findings.json') {
        if (!fs.existsSync(findingsPath)) {
            throw new Error(`Findings file not found at: ${findingsPath}`);
        }

        const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
        const targets = this.generateTargetsFromFindings(findings);

        const artifactsDir = path.resolve('prototype/artifacts');
        if (!fs.existsSync(artifactsDir)) {
            fs.mkdirSync(artifactsDir, { recursive: true });
        }

        const outputPath = path.join(artifactsDir, 'symbolic_targets.json');
        const serialized = JSON.stringify(targets, null, 2);
        fs.writeFileSync(outputPath, serialized, 'utf8');

        const sha256 = crypto.createHash('sha256').update(serialized).digest('hex');

        return {
            targets: targets,
            count: targets.length,
            artifact_path: 'prototype/artifacts/symbolic_targets.json',
            sha256: sha256
        };
    }
}
