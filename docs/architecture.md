# HWSEC Architecture

HWSEC is an **evidence-driven security analysis framework**. It unifies deterministic static analysis, formal verification, symbolic reasoning, and LLM-assisted vulnerability discovery across mixed-domain codebases containing both software (C, C++, Python, Java, Go) and hardware description languages (Verilog, SystemVerilog).

The core design principle: **LLMs are hypothesis generators, not verdict authorities.** Only concrete, executable technical counterexamples promote a finding to `DETECTED`.

---

## 1. High-Level Pipeline

```
Target Repository
       │
       ▼
┌──────────────────┐
│  EntryPointInventory  │  Scans for CLI entry points, HTTP routes, hardware modules
└──────────┬───────┘
           │
           ▼
┌──────────────────┐
│  AnalysisBroker  │  Dispatches to deterministic tools (Semgrep, Joern, CodeQL,
│  (Tool Dispatch) │  Verilator, Yosys, SymbiYosys, AFL++, Spike)
└──────────┬───────┘
           │
           ▼
┌──────────────────────┐
│ VulnerabilityHypothesis │  Each tool finding is promoted to a falsifiable hypothesis
│ (Falsifiable Claims) │   with a declared CWE, source, sink, and attack surface
└──────────┬───────────┘
           │
           ▼
┌─────────────────────┐
│  WitnessSearchEngine │  Active witness search: generates concrete probe inputs,
│  (Probe Generation) │  executes them against the target, evaluates oracle satisfaction
└──────────┬──────────┘
           │  WITNESS_FOUND / SEARCH_BUDGET_EXHAUSTED
           ▼
┌──────────────────────────┐
│  CausalControlEngine     │  Runs paired benign negative control to prove
│  (Negative Control Test) │  the effect is causally linked to the tainted input
└──────────┬───────────────┘
           │
           ▼
┌────────────────────┐
│  Evidence DAG      │  Content-addressed, tamper-evident directed acyclic graph
│  (Assembly)        │  of all evidence nodes: hypothesis, entry point, witness,
│                    │  runtime trace, oracle result, negative control, provenance
└──────────┬─────────┘
           │
           ▼
┌──────────────────────┐
│  EvidenceAuthority   │  Deterministic reduction — no LLM involved
│  (Verdict Reduction) │
└──────────┬───────────┘
           │
           ▼
    DETECTED | NOT_DETECTED | INCONCLUSIVE
```

---

## 2. Evidence Nodes (DAG Node Types)

| Node Type | Description |
|---|---|
| `HYPOTHESIS` | Falsifiable claim: CWE + source → sink path |
| `ENTRY_POINT` | Resolved CLI/HTTP/hardware entry point |
| `WITNESS_INPUT` | Concrete probe value that triggers the oracle |
| `RUNTIME_TRACE` | Execution result (exit code, stdout, stderr) |
| `SECURITY_ORACLE_RESULT` | Boolean: did the oracle condition fire? |
| `NEGATIVE_CONTROL` | Paired benign input result (causal proof) |
| `PROVENANCE_MANIFEST` | Toolchain version, environment, timestamp |

---

## 3. E0–E5 Verification Ladder

HWSEC uses a six-level evidence ladder to communicate finding confidence:

| Level | Label | Meaning |
|---|---|---|
| **E0** | Raw Signal | Tool output or LLM observation — not verified |
| **E1** | Candidate | Static analysis confirmed reachable path |
| **E2** | Hypothesis | Formally structured falsifiable claim |
| **E3** | Witness Found | Concrete probe input discovered |
| **E4** | Oracle Satisfied | Security oracle condition confirmed |
| **E5** | Verified | Causal negative control passed — fully reproducible |

Only E5 evidence promotes a finding to `DETECTED` verdict.

---

## 4. Verdict Types

| Verdict | Meaning |
|---|---|
| `DETECTED` | Full evidence chain: Witness + Oracle + Causal Control all confirmed |
| `NOT_DETECTED` | Explicit refutation: search exhausted, oracle not triggered, or control failed |
| `INCONCLUSIVE` | Fail-closed: missing evidence stage, tamper detected, or budget exhausted |

> **`INCONCLUSIVE` is a first-class operational result** — it is not a failure. It means the framework could not assemble sufficient evidence within the declared scope and budget.

---

## 5. LLM Gateway Architecture

LLMs are used **exclusively** for hypothesis generation and triage. They never write final verdicts.

```
LLMGateway
├── GeminiProvider    (multi-key pool, round-robin)
├── NvidiaProvider    (primary deep reasoning)
└── OpenRouterProvider (specialist fallback)
```

Failover chain: `nvidia → gemini → openrouter`

- Provider pool is for **authorized redundancy**, not quota evasion
- All LLM outputs are treated as `E0` (unverified hypothesis)
- The `EvidenceAuthority` reducer is deterministic code — no LLM

---

## 6. Security Guardrails

| Guardrail | Implementation |
|---|---|
| **Human Approval Gate** | `hwsec analyze` generates a plan; execution is blocked until `hwsec proceed` is called |
| **Zero Self-Certification** | LLM output classified as E0/E1; cannot self-promote to DETECTED |
| **Anti-Exploit Principle** | `ProofSandbox` rejects shellcode, remote shells, persistence mechanisms |
| **Credential Stripping** | Sandbox strips all `*KEY*`, `*TOKEN*`, `*SECRET*`, `*AUTH*`, `*PASS*` env vars from child processes |
| **Network Neutralization** | Proxy vars set to `http://127.0.0.1:0`; cloud endpoints explicitly blocked |
| **DAG Tamper Detection** | Every evidence node is content-addressed (SHA-256); tampering triggers `INCONCLUSIVE` |

---

## 7. State Machine

Analysis lifecycle states:

```
PLANNED → APPROVED → RUNNING → COMPLETED
                             → FAILED
```

`assertTransition()` in `src/core/state.js` enforces legal transitions and prevents double-execution.

---

## 8. Key Source Files

| File | Purpose |
|---|---|
| `src/index.js` | CLI entry point — all commands (analyze, proceed, status, findings) |
| `src/core/bep/evidenceDag.js` | Evidence DAG, `EvidenceAuthority.reduce()`, `VerdictType` |
| `src/core/inventory/entryPointInventory.js` | Entry point discovery for all languages |
| `src/core/hypothesis/vulnerabilityHypothesis.js` | Falsifiable hypothesis data model |
| `src/core/witness/witnessSearch.js` | Witness probe generation and search engine |
| `src/core/controls/causalControls.js` | Negative control execution |
| `src/core/observation/runtimeObservationProvider.js` | Runtime trace capture |
| `src/core/oracles/cweOracles.js` | CWE-specific oracle conditions |
| `src/core/llm/gateway.js` | Multi-provider LLM gateway with failover |
| `src/core/proofSandbox.js` | Isolated execution sandbox |
| `src/core/broker.js` | `AnalysisBroker` — central capability dispatcher |
