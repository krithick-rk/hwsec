/**
 * HWSEC PoV Subsystem - Packager
 * 
 * Packages verified PoVs into standardized, portable, content-addressed
 * directory bundles with full reproducibility metadata, README, and provenance.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { ProofOfVulnerability } from './povTypes.js';

export class PovPackager {
    /**
     * Computes the SHA-256 hash of a file or string.
     */
    static computeHash(contentOrPath) {
        if (typeof contentOrPath === 'string' && fs.existsSync(contentOrPath) && fs.statSync(contentOrPath).isFile()) {
            const buf = fs.readFileSync(contentOrPath);
            return crypto.createHash('sha256').update(buf).digest('hex');
        }
        const buf = Buffer.isBuffer(contentOrPath) ? contentOrPath : Buffer.from(String(contentOrPath), 'utf-8');
        return crypto.createHash('sha256').update(buf).digest('hex');
    }

    /**
     * Packages a ProofOfVulnerability instance into an isolated bundle directory.
     * @param {ProofOfVulnerability} pov
     * @param {string} destinationDir
     * @param {Object} [options]
     * @returns {string} Absolute path to the packaged PoV bundle
     */
    static packageBundle(pov, destinationDir, options = {}) {
        if (!pov || !(pov instanceof ProofOfVulnerability)) {
            throw new Error('[PovPackager] Invalid ProofOfVulnerability object provided.');
        }

        const bundleDir = path.resolve(destinationDir, pov.pov_id);
        fs.mkdirSync(bundleDir, { recursive: true });

        const subdirs = ['input', 'expected', 'evidence', 'provenance'];
        for (const s of subdirs) {
            fs.mkdirSync(path.join(bundleDir, s), { recursive: true });
        }

        // 1. Write Input Files
        const inputData = {
            witness_input: pov.witness_input,
            negative_control: pov.negative_control?.input || null,
            target_entry_point: pov.target?.entry_point || null
        };
        fs.writeFileSync(
            path.join(bundleDir, 'input', 'witness.json'),
            JSON.stringify(inputData, null, 2),
            'utf-8'
        );

        // 2. Write Expected Security Effect
        const expectedData = {
            vulnerability_class: pov.vulnerability_class,
            expected_security_effect: pov.security_effect?.expected || '',
            oracle_cwe: pov.security_effect?.oracle_cwe || pov.vulnerability_class,
            negative_control_expected: 'Security condition remains unviolated'
        };
        fs.writeFileSync(
            path.join(bundleDir, 'expected', 'effect.json'),
            JSON.stringify(expectedData, null, 2),
            'utf-8'
        );

        // 3. Write Evidence Linkage
        const evidenceData = {
            finding_id: pov.finding_id,
            hypothesis_id: pov.hypothesis_id,
            run_id: pov.run_id,
            dag_hash: options.dagHash || null,
            attached_nodes: options.evidenceNodes || []
        };
        fs.writeFileSync(
            path.join(bundleDir, 'evidence', 'dag_snapshot.json'),
            JSON.stringify(evidenceData, null, 2),
            'utf-8'
        );

        // 4. Write Provenance Manifest
        const provenanceData = {
            pov_id: pov.pov_id,
            created_at: pov.provenance?.generated_at || new Date().toISOString(),
            generator_type: pov.provenance?.generator_type || 'deterministic',
            target: pov.target,
            system_info: {
                platform: process.platform,
                node_version: process.version
            },
            sandbox_constraints: {
                timeout_ms: pov.reproduction?.timeout_ms || 25000,
                output_limits_bytes: pov.reproduction?.output_limits_bytes || 131072,
                network: 'localhost_only_when_explicit',
                credentials_stripped: true
            }
        };
        fs.writeFileSync(
            path.join(bundleDir, 'provenance', 'manifest.json'),
            JSON.stringify(provenanceData, null, 2),
            'utf-8'
        );

        // 5. Write Domain Reproduction Script
        const scriptName = pov.reproduction?.entry_script || 'reproduce.sh';
        const scriptContent = options.scriptContent || `#!/bin/sh\n# PoV Reproduction for ${pov.pov_id}\n${pov.reproduction?.command || 'echo "No reproduction script defined"'}\n`;
        const scriptPath = path.join(bundleDir, scriptName);
        fs.writeFileSync(scriptPath, scriptContent, 'utf-8');

        // Make executable if on Unix
        if (process.platform !== 'win32' && scriptName.endsWith('.sh')) {
            try { fs.chmodSync(scriptPath, 0o755); } catch {}
        }

        // 6. Generate README.md
        const readmeContent = this._generateReadme(pov, scriptName);
        fs.writeFileSync(path.join(bundleDir, 'README.md'), readmeContent, 'utf-8');

        // 7. Compute Hash of all bundle files and write metadata.json
        pov.bundle_path = bundleDir;
        pov.reproduction.entry_script = scriptName;
        
        const fileHashes = {};
        const walk = (d) => {
            for (const f of fs.readdirSync(d)) {
                const p = path.join(d, f);
                if (fs.statSync(p).isDirectory()) {
                    walk(p);
                } else if (f !== 'metadata.json') {
                    const rel = path.relative(bundleDir, p).replace(/\\/g, '/');
                    fileHashes[rel] = this.computeHash(p);
                }
            }
        };
        walk(bundleDir);

        const manifestHash = crypto.createHash('sha256').update(JSON.stringify(fileHashes)).digest('hex');
        pov.bundle_hash = manifestHash;

        const metadata = {
            ...pov.toJSON(),
            bundle_manifest_hash: manifestHash,
            file_hashes: fileHashes
        };

        fs.writeFileSync(
            path.join(bundleDir, 'metadata.json'),
            JSON.stringify(metadata, null, 2),
            'utf-8'
        );

        return bundleDir;
    }

    static _generateReadme(pov, scriptName) {
        return `# Proof of Vulnerability (PoV) Artifact: ${pov.pov_id}

**Vulnerability Class**: \`${pov.vulnerability_class}\`  
**Domain**: \`${pov.domain.toUpperCase()}\`  
**Status**: \`${pov.status}\`  
**Created At**: \`${pov.provenance?.generated_at}\`  

---

## 1. Description
This artifact demonstrates an independently verifiable security flaw observed by the HWSEC framework.
It demonstrates the security consequence with the **minimum necessary effect** and contains **no weaponized, persistent, or destructive capabilities**.

## 2. Target Information
- **Target File**: \`${pov.target?.path}\`
- **Entry Point**: \`${JSON.stringify(pov.target?.entry_point || 'Direct Execution')}\`
- **Content SHA-256**: \`${pov.target?.content_hash || 'Recorded in manifest'}\`

## 3. Observed Security Effect
> ${pov.security_effect?.expected || 'Security boundary condition violated.'}

## 4. Reproduction Instructions
To independently verify this vulnerability on an authorized test system:
\`\`\`bash
cd $(dirname "$0")
${pov.reproduction?.command || `node ${scriptName}`}
\`\`\`

## 5. Negative Control Verification
A paired benign control is provided in \`input/witness.json\`. Executing the negative control confirms that non-malicious input remains safe.

## 6. Provenance & Cryptographic Hashes
- **Bundle Manifest Hash**: \`${pov.bundle_hash || 'Computed on package'}\`
- All contents are content-addressed and verifiable via \`metadata.json\`.
`;
    }
}
