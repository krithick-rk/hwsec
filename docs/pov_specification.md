# HWSEC Proof-of-Vulnerability (PoV) Subsystem Specification

## 1. What a PoV Is
A **Proof-of-Vulnerability (PoV)** in HWSEC is a first-class, typed, content-addressed, and portable reproduction artifact generated after a security finding has been verified with sufficient evidence. It packages the minimal necessary inputs, reproduction harness, execution commands, and security assertions required to independently demonstrate an already-observed security effect against an authorized local target.

## 2. Difference Between Witness and PoV
- **Witness**: A raw input, payload, or probe sequence generated or discovered during the exploration/investigation phase (e.g. by `WitnessSearchEngine` or `ConstraintRefinementProvider`). It is an internal investigation mechanism used to trigger potential vulnerabilities.
- **PoV**: A packaged, self-contained, standalone reproducible bundle that allows an external security analyst or CI/CD regression suite to independently replay, observe, and verify the security violation without re-running the entire discovery pipeline.
- **Final Verdict Authority**: The final security verdict (`DETECTED`, `NOT_DETECTED`, `INCONCLUSIVE`) is determined exclusively by `EvidenceAuthority` reducing the content-addressed Evidence DAG—never by the PoV itself and never by an LLM.

## 3. Difference Between PoV and Weaponized Exploit
HWSEC enforces strict ethical, safety, and non-weaponization boundaries (Sections 7 & 25):
- **Local Scope**: PoVs operate solely on local targets or authorized localhost loopbacks.
- **Controlled Side-Effects**: For arbitrary execution flaws (such as OS command injection), PoVs use bounded side effects (e.g., creating a local temporary marker file or exercising a safe test stub) rather than interactive reverse shells, remote command execution, or system tampering.
- **No Malicious Payloads**: PoVs strictly forbid:
  - Reverse shells / interactive connect-backs
  - Outbound network connections to remote internet addresses
  - Destructive file system modifications (`rm -rf /`, `mkfs`, raw device writes)
  - Credential theft, harvesting (`/etc/shadow`, SSH keys)
  - Persistence mechanisms (cron modifications, registry run keys)
  - Evasion, obfuscation, or anti-analysis techniques

## 4. How PoV Generation Works
1. **Evidence Threshold**: PoV generation triggers only when the investigation establishes sufficient evidence (defaulting to when `EvidenceAuthority` reaches `DETECTED` under `POV_MODE=on-detected`).
2. **Domain-Aware Synthesis**: `PovGenerator` classifies the target source language (Python, Java, C/C++, Verilog/SystemVerilog) and synthesizes a domain-tailored reproduction harness.
3. **Safety Policy Validation**: Prior to file writing or execution, `PovSafetyValidator` statically inspects commands and payloads against safety regular expressions and semantic rules.
4. **Content Packaging**: `PovPackager` creates a structured bundle directory containing inputs, expected effects, DAG references, provenance metadata, reproduction scripts, and SHA-256 hashes of all components.

## 5. How PoV Verification Works
1. **Isolated Sandbox Execution**: `PovVerifier` runs the reproduction script inside `ProofSandbox` with argv arrays (no shell interpolation), stripped sensitive environment variables (e.g., removing API keys), bounded timeouts (25s), and memory/output limits.
2. **Untrusted Artifact Principle**: A PoV cannot self-certify its success. Self-asserted strings such as `POV_RESULT=PASS` inside stdout are explicitly untrusted.
3. **Multi-Factor Independent Observation**: Verification requires:
   - Clean process exit (exit code 0 without timeout)
   - Independent verification of the security effect oracle
   - Negative/causal control verification (benign inputs must remain safe)
   - Cryptographic integrity check of the PoV bundle manifest hash
4. **Lifecycle State Transition**: Only upon satisfying all independent criteria is the artifact status marked `VERIFIED`.

## 6. Safety Boundaries
The `PovSafetyValidator` automatically rejects proposals containing:
- Reverse shell commands: `nc -e`, `/dev/tcp/*`, `bash -i`, base64 encoded PowerShell scripts
- External network requests: `curl`, `wget`, `http://`, `https://` targeting non-localhost endpoints
- Dangerous filesystem deletion or disk overwrites: `rm -rf /`, `dd of=/dev/...`
- Privilege escalation or secret harvesting: `/etc/shadow`, `id_rsa`, `id_ed25519`

## 7. CLI Usage

### Analyze and Plan with PoV Generation
```bash
# Discover and plan with PoV generation enabled
hwsec analyze ./target --generate-pov

# Configure specific PoV policy (disabled, on-detected, always-eligible, manual)
hwsec analyze ./target --pov-mode on-detected
```

### Approve and Execute
```bash
hwsec proceed <analysis-id> --generate-pov
```

### Independently Replay & Verify a PoV Bundle
```bash
# Verify vulnerable target reproduction
hwsec verify-pov hwsec-output/pov/POV-PYTHON-a1b2c3d4

# Verify against a fixed target (confirms remediation: exploit is blocked)
hwsec verify-pov hwsec-output/pov/POV-PYTHON-a1b2c3d4 --fixed --target-override ./target_fixed
```

## 8. Artifact Structure
Every packaged PoV adheres to the standardized directory layout:
```text
pov/<pov-id>/
├── README.md                      # Human-readable instructions, target info, and replay commands
├── metadata.json                  # Machine-readable schema, status, hashes, and replay history
├── reproduce.py | .java | .c | .sv# Domain-specific reproduction harness
├── input/
│   └── witness.json               # Witness input payload and negative control input
├── expected/
│   └── effect.json                # Expected security condition violation and oracle CWE
├── evidence/
│   └── dag_snapshot.json          # Linkage to originating finding, hypothesis, and DAG hash
└── provenance/
    └── manifest.json              # Toolchain version, OS details, timestamp, sandbox constraints
```

## 9. Domain Example: Python
- **Harness**: `reproduce.py`
- **Mechanism**: Local subprocess invocation passing the discovered witness string as an argv argument.
- **Oracle**: Observes stdout for sink execution marker (`[APP_EXEC]`) or exit status.
- **Execution**: `python3 reproduce.py`

## 10. Domain Example: Java
- **Harness**: `Reproduce.java`
- **Mechanism**: Minimal driver calling the vulnerable entry method with structured serialized or command parameters.
- **Oracle**: Verifies that the sensitive sink method is reached or security exception is thrown.
- **Execution**: `javac Reproduce.java && java Reproduce`

## 11. Domain Example: C/C++
- **Harness**: `reproduce.c`
- **Mechanism**: Standalone harness passing bounded or oversized buffer payloads to test boundary checks.
- **Oracle**: Confirms memory boundary violation, sanitizer fault, or buffer capacity overflow.
- **Execution**: `gcc -O0 reproduce.c -o reproduce_bin && ./reproduce_bin`

## 12. Domain Example: Verilog / SystemVerilog
- **Harness**: `reproduce.sv`
- **Mechanism**: Simulation testbench providing clock, reset, and cycle-accurate stimulus matching the formal counterexample.
- **Oracle**: Evaluates assert violation or privilege escalation signal state.
- **Execution**: `iverilog -g2012 -o reproduce_sim reproduce.sv && vvp reproduce_sim`

## 13. Troubleshooting
- **`TAMPER_DETECTED`**: The cryptographic hash of files in the bundle directory does not match `bundle_manifest_hash` in `metadata.json`. Ensure files have not been modified outside `hwsec`.
- **`ENTRY_SCRIPT_MISSING`**: The reproduction script declared in `reproduction.entry_script` was deleted or renamed.
- **`REPLAY_TIMEOUT`**: Execution exceeded the configured timeout (default: 25,000 ms). Use `--timeout <ms>` to increase limit for heavy compilation steps.
- **`NONZERO_EXIT_CODE`**: The harness exited with an unexpected failure without triggering the security effect oracle.
- **`UNSAFE_TO_GENERATE`**: The proposal was halted because it contained forbidden payload constructs (reverse shell, remote IP, destructive commands).

## 14. How to Verify a PoV Manually
1. Open the PoV bundle directory: `cd hwsec-output/pov/<pov-id>/`.
2. Inspect `README.md` and `metadata.json` for target path and reproduction commands.
3. Review the reproduction script (e.g. `reproduce.py`) to confirm local safety constraints.
4. Execute the command specified in `README.md` in a controlled local terminal:
   ```bash
   python3 reproduce.py
   ```
5. Confirm that the security effect occurs on the vulnerable target, and that benign inputs do not trigger the effect.

## 15. How PoV Evidence Connects to Evidence DAG
The PoV connects directly into the existing immutable, content-addressed Evidence DAG:
```text
HypothesisNode (HYPOTHESIS)
       │
       ├──[SUPPORTS]──────> EntryPointNode (ENTRY_POINT)
       ├──[SUPPORTS]──────> WitnessInputNode (WITNESS_INPUT)
       │                         │
       │                   [OBSERVED_IN]
       │                         ▼
       │                    RuntimeTraceNode (RUNTIME_TRACE)
       │                         │
       │                   [OBSERVED_IN]
       │                         ▼
       │                    SinkEventNode (SINK_EVENT)
       │
       ├──[SUPPORTS]──────> SecurityOracleNode (SECURITY_ORACLE_RESULT)
       ├──[SUPPORTS]──────> NegativeControlNode (NEGATIVE_CONTROL)
       ├──[SUPPORTS]──────> PovArtifactNode (POV_ARTIFACT)
       │                         │
       │                   [DERIVED_FROM]
       │                         ▼
       │                    PovReplayNode (POV_REPLAY)
       │
       └──[SUPPORTS]──────> PovVerificationNode (POV_VERIFICATION)
                                 │
                                 ▼
                         EvidenceAuthority.reduce()
                                 │
                                 ▼
                     DETECTED + VERIFIED_POV
```
The PoV nodes are typed evidence elements. They provide full provenance tracing back to the original finding while preserving `EvidenceAuthority` as the sole arbiter of the final security verdict.
