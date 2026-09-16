# HWSEC: Multi-Language Evidence-Driven Security Analysis Framework

**HWSEC** is an enterprise-grade hybrid hardware/software security analysis and proof-of-impact validation platform. It unifies deterministic static analysis, formal verification, symbolic reasoning, and LLM-assisted vulnerability discovery across mixed-domain codebases containing both software (C, C++, Python, Java, Go) and hardware description languages (Verilog, SystemVerilog).

**Core principle**: LLMs are hypothesis generators, not verdict authorities. Only concrete, executable technical counterexamples — witness inputs that trigger a security oracle plus a passing causal negative control — can promote a finding to `DETECTED`.

---

## Documentation

| Document | Description |
|---|---|
| [docs/getting-started.md](docs/getting-started.md) | Installation, configuration, and first analysis walkthrough |
| [docs/architecture.md](docs/architecture.md) | Evidence pipeline, E0–E5 ladder, LLM gateway, security guardrails |
| [docs/cli-reference.md](docs/cli-reference.md) | All CLI commands with options and examples |
| [docs/configuration.md](docs/configuration.md) | Full `config.json` and `.env` reference |
| [docs/benchmarks.md](docs/benchmarks.md) | Benchmark suites, CWE coverage, re-running evaluations |
| [requirements.md](requirements.md) | Detailed prerequisites, tool matrix, and installation guide |
| [implementation.md](implementation.md) | Deep architectural specification and data flow |
| [walkthrough.md](walkthrough.md) | Mixed-repository execution examples and debugging guide |
| [DECISIONS.md](DECISIONS.md) | Architectural Decision Records (ADR-001 through ADR-010) |

---

## Interactive Console (Recommended Operator Workflow)

The primary operator interface for HWSEC is the **Metasploit-style Interactive Security Operations Console**:

```bash
hwsec console
# Or: node src/index.js console
```

### Visual Opening & Startup Readiness

Upon launch, `hwsec console` presents the key-motif ASCII branding and real subsystem readiness checks:

```text
 ______________________
/                      \
/   H W S E C  )====>   |
|                       |
\______________________/
  \                  /
   \__________/

============================================================
HWSEC SECURITY OPERATIONS CONSOLE
============================================================
[+] HWSEC engine READY
[+] EvidenceAuthority READY
[+] Execution Broker READY
[+] Provider Pool READY
[+] Workspace Manager READY

hwsec >
```

### Guided Session Onboarding & Menus

New operators can use guided setup (`menu`) or configure via numbered menus:

```text
hwsec > menu
HWSEC SESSION SETUP
-------------------
1. Target / scope
2. Context / requirements
3. Analysis mode
4. LLM / provider configuration
5. PoV policy
6. Execution policy
7. Budget
8. Tool status
9. Start with defaults
0. Exit setup

Select option [9]:
```

### Canonical Configuration (`set` / `show options`)

Operators can use direct commands or open the interactive settings menu by typing `set`:

```text
hwsec > set target E:\projects\myapp
hwsec > set context E:\projects\context
hwsec > set mode DEEP
hwsec > set llm ADAPTIVE
hwsec > set pov ON-DETECTED
hwsec > set budget 20
hwsec > set approval REQUIRED
hwsec > set tool.yosys.path E:\tools\oss-cad-suite\bin\yosys.exe
hwsec > show options
```

### Tool Status Center (`tools` & `doctor`)

Inspect real toolchain capabilities across Core, Software, Hardware, and Infrastructure:

```text
hwsec > tools
HWSEC TOOLCHAIN STATUS
======================

CORE
----
Node.js READY
SQLite READY
EvidenceAuthority READY
Execution Broker READY

SOFTWARE
--------
Python READY native
Java READY native
GCC READY WSL
G++ READY WSL
Clang READY WSL
AFL++ READY WSL
Semgrep READY WSL
Joern MISSING optional
CodeQL MISSING optional

HARDWARE
--------
Yosys READY native
Verilator READY native
SymbiYosys READY native
Icarus Verilog READY WSL
Spike READY WSL

INFRASTRUCTURE
--------------
Docker READY
Qdrant AVAILABLE / OFFLINE / NOT CONFIGURED
WSL2 READY

Use `doctor <tool>` for details.
```

Inspect and test specific tools:
```text
hwsec > doctor yosys
hwsec > doctor yosys --test
hwsec > tools config
```

### Zero-Key Operational Mode (`LLM=OFF`)

API keys are **strictly optional**. HWSEC functions out of the box with zero LLM API keys configured:

```text
hwsec > set llm OFF
```

Deterministic static analysis, AST parsing, ProofSandbox execution, EvidenceAuthority verification, and PoV replay remain fully functional without LLM keys. Raw API keys are **never** logged, saved in SQLite history, or output in report files.

### Dynamic Provider Management & Masked Rotation

Manage provider credentials dynamically inside `hwsec console`:

- `providers`: Display safe health, role, and model configuration state for all provider accounts.
- `providers configure`: Numbered interactive provider configuration menu.
- `providers rotate <id>`: Safely update or rotate API key with masked input (`> ********`).
- `providers test [id]`: Run live health checks against provider endpoints.
- `providers disable <id>` / `providers enable <id>`: Toggle provider endpoints.

### LLM Brain Visibility & Session Health (`status`)

Inspect operational brain metadata without exposing private prompts or hidden chain-of-thought:

```text
hwsec > status
BRAIN / ORCHESTRATION
---------------------
Mode : ADAPTIVE
Current phase : INVESTIGATING
Active hypothesis : HYP-001

Scout : Gemini-1 / HEALTHY
Critic : Gemini-2 / HEALTHY
Redundant scout : Gemini-3 / DISABLED
Deep reasoner : NVIDIA / HEALTHY
Fallback : OpenRouter / HEALTHY

Worker activity
Semgrep DONE
Joern DONE
CodeQL DONE
Runtime witness PENDING
PoV PENDING

Operational state
hypotheses : 4
escalations : 0
disagreements : 1
evidence items : 8

SESSION
-------
ID : HW-20260916-001
TARGET : E:\projects\myapp
PHASE : PLANNED
APPROVAL : REQUIRED
MODE : STANDARD
LLM : ADAPTIVE
POV : ON-DETECTED
BUDGET : $10.00

EXECUTION
---------
Python : native / READY
Java : native / READY
C/C++ : WSL / READY
Verilog : native / READY
Yosys : native / READY
SymbiYosys : native / READY

SECURITY
--------
Network : BLOCKED
Shell : DISABLED
Credential scrub: ENABLED
Evidence DAG : ENABLED
PoV integrity : ENABLED
```

---

## Clean-Clone Reproducibility & Manual Test Pack

HWSEC includes a dedicated, repository-tracked manual testing workspace at [`manual_tests/`](manual_tests/README.md) containing curated, safe, reproducible test targets across Python, C/C++, Java, Verilog, and SystemVerilog.

### Clean-Clone Quickstart

```bash
git clone https://github.com/krithick-rk/hwsec.git
cd hwsec
npm install

# 1. Run environment check
./manual_tests/scripts/setup.sh    # Linux/WSL
# Or PowerShell: .\manual_tests\scripts\setup.ps1

# 2. Run automated manual smoke test pack
./manual_tests/scripts/run_smoke.sh
# Or PowerShell: .\manual_tests\scripts\run_smoke.ps1
```

For complete step-by-step interpretation guidance and ground truth expected verdicts, refer to [`manual_tests/QUICKSTART.md`](manual_tests/QUICKSTART.md) and [`manual_tests/expected/interpretation/README.md`](manual_tests/expected/interpretation/README.md).

---

## Scriptable CLI Usage (Automated CI/CD Pipelines)

Non-interactive scriptable CLI commands remain fully supported:

### 1. Plan Analysis (Non-Destructive)

```bash
node src/index.js analyze ./example-project --proof-mode standard
```

Review generated plan:
```bash
cat hwsec-output/<analysis-id>/plan.md
```

### 2. Approve and Execute

```bash
node src/index.js proceed <analysis-id> --mode standard
```

### 3. View Findings & Reports

```bash
node src/index.js report <analysis-id>
node src/index.js findings <analysis-id>
node src/index.js dossier <analysis-id>
```

---

## Security Guardrails

| Guardrail | Description |
|---|---|
| **Human Approval Gate** | `hwsec analyze` generates a plan — execution blocked until `hwsec proceed` is explicitly called |
| **Zero Self-Certification** | LLM output classified as E0 (unverified) — cannot self-promote to `DETECTED` |
| **Anti-Exploit Principle** | Proof sandbox refuses to generate shellcode, remote shells, or persistence mechanisms |
| **Credential Stripping** | Sandbox strips all `*KEY*`, `*TOKEN*`, `*SECRET*`, `*AUTH*`, `*PASS*` env vars from child processes |
| **Network Neutralization** | Proxy vars redirected to `http://127.0.0.1:0`; cloud endpoints blocked |
| **DAG Tamper Detection** | Evidence DAG nodes are content-addressed (SHA-256); tampering forces `INCONCLUSIVE` |

---

## Benchmark Suites

Four curated ground-truth benchmark suites are included:

| Suite | Languages | Cases | Purpose |
|---|---|---|---|
| `hwsec_verilog_benchmark/` | Verilog, SystemVerilog | 12 | RTL hardware security (CWE-269, CWE-1231, CWE-1234, etc.) |
| `hwsec_c_benchmark/` | C | 12 | Memory safety (heap overflow, format string, UAF) |
| `hwsec_java_benchmark/` | Java | 12 | Software security (injection, deserialization, path traversal) |
| `hwsec_artificial_benchmark/` | Multi-domain | — | Pipeline regression and evidence DAG validation |

Re-run any benchmark:
```bash
node tests/experimental/evaluate_verilog_benchmark.mjs
node tests/experimental/evaluate_c_benchmark.mjs
node tests/experimental/evaluate_java_benchmark.mjs
```

---

## Repository Structure

```
hwsec/
├── src/                         # Production source (core framework, domain adapters, workers)
│   ├── core/                    # Evidence DAG, LLM gateway, broker, hypothesis, state machine
│   ├── domains/                 # Hardware and software tool adapters
│   └── workers/                 # Verifier, correlator, hypothesis generator, proof verifier
├── tests/                       # Centralized test suite (25 suites + fixtures)
├── audit/                       # Adversarial security validation engine (50 security invariants)
├── docs/                        # Engineering documentation
├── scripts/                     # Benchmark evaluation and preflight scripts
├── manifests/                   # Benchmark ground-truth datasets
├── hwsec_verilog_benchmark/     # Verilog RTL security benchmark suite
├── hwsec_c_benchmark/           # C memory-safety benchmark suite
├── hwsec_java_benchmark/        # Java security benchmark suite
├── hwsec_artificial_benchmark/  # Algorithmic/behavioral benchmark suite
├── example-project/             # Sample target repository for demonstrations
├── prototype/                   # Java-based early prototype (reference only)
├── requirements.md              # Prerequisites and installation guide
├── implementation.md            # Deep technical architecture specification
├── walkthrough.md               # Engineer walkthrough with execution traces
├── DECISIONS.md                 # Architectural Decision Records (ADR-001 to ADR-010)
├── .env.example                 # Environment variable template
└── config.example.json          # Configuration file template
```

---

## License

ISC License. See [LICENSE](LICENSE) for details.
