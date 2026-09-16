/**
 * HWSEC Proof-of-Vulnerability (PoV) Subsystem - Types & Constants
 * 
 * Defines first-class typed PoV data structures, lifecycle states,
 * operating policies, and metadata schemas.
 */

import crypto from 'crypto';

/**
 * PoV Lifecycle Status Model (Section 4)
 * Explicit, machine-readable states ensuring zero silent verification claims.
 */
export const PovStatus = {
    NOT_REQUESTED: 'NOT_REQUESTED',
    GENERATING: 'GENERATING',
    GENERATED: 'GENERATED',
    REPLAYING: 'REPLAYING',
    VERIFIED: 'VERIFIED',
    FAILED: 'FAILED',
    UNVERIFIED: 'UNVERIFIED',
    UNSAFE_TO_GENERATE: 'UNSAFE_TO_GENERATE'
};

/**
 * PoV Generation Policy (Section 16)
 */
export const PovMode = {
    DISABLED: 'disabled',
    ON_DETECTED: 'on-detected',       // Default conservative: only generate when DETECTED
    ALWAYS_ELIGIBLE: 'always-eligible',
    MANUAL: 'manual'
};

/**
 * Target Domain Classification
 */
export const PovDomain = {
    PYTHON: 'python',
    JAVA: 'java',
    C_CPP: 'c_cpp',
    VERILOG: 'verilog'
};

/**
 * Canonical ProofOfVulnerability Typed Artifact (Section 2 & 5)
 */
export class ProofOfVulnerability {
    constructor(data = {}) {
        this.pov_version = '1.0.0';
        this.pov_id = data.pov_id || `POV-${crypto.randomBytes(6).toString('hex')}`;
        this.finding_id = data.finding_id || null;
        this.hypothesis_id = data.hypothesis_id || null;
        this.run_id = data.run_id || 'global';
        this.domain = data.domain || PovDomain.PYTHON;
        this.vulnerability_class = data.vulnerability_class || 'CWE-UNKNOWN';
        this.target = {
            path: data.target?.path || '',
            entry_point: data.target?.entry_point || null,
            content_hash: data.target?.content_hash || null,
            revision: data.target?.revision || null
        };
        this.status = data.status || PovStatus.NOT_REQUESTED;
        this.security_effect = {
            expected: data.security_effect?.expected || '',
            observed: data.security_effect?.observed || null,
            oracle_cwe: data.security_effect?.oracle_cwe || this.vulnerability_class,
            oracle_verified: Boolean(data.security_effect?.oracle_verified)
        };
        this.witness_input = data.witness_input || null;
        this.negative_control = {
            input: data.negative_control?.input || null,
            passed: Boolean(data.negative_control?.passed),
            observed_effect: data.negative_control?.observed_effect || null
        };
        this.reproduction = {
            command: data.reproduction?.command || '',
            entry_script: data.reproduction?.entry_script || '',
            timeout_ms: data.reproduction?.timeout_ms || 25000,
            output_limits_bytes: data.reproduction?.output_limits_bytes || 131072,
            environment_requirements: data.reproduction?.environment_requirements || []
        };
        this.replay_results = data.replay_results || [];
        this.bundle_path = data.bundle_path || null;
        this.bundle_hash = data.bundle_hash || null;
        this.provenance = {
            generated_at: data.provenance?.generated_at || new Date().toISOString(),
            verified_at: data.provenance?.verified_at || null,
            generator_type: data.provenance?.generator_type || 'deterministic', // 'deterministic' | 'llm_assisted'
            generator_model: data.provenance?.generator_model || null,
            system_info: data.provenance?.system_info || {
                platform: process.platform,
                node_version: process.version
            }
        };
    }

    toJSON() {
        return {
            pov_version: this.pov_version,
            pov_id: this.pov_id,
            finding_id: this.finding_id,
            hypothesis_id: this.hypothesis_id,
            run_id: this.run_id,
            domain: this.domain,
            vulnerability_class: this.vulnerability_class,
            target: this.target,
            status: this.status,
            security_effect: this.security_effect,
            witness_input: this.witness_input,
            negative_control: this.negative_control,
            reproduction: this.reproduction,
            replay_results: this.replay_results,
            bundle_path: this.bundle_path,
            bundle_hash: this.bundle_hash,
            provenance: this.provenance
        };
    }
}
