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

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/krithick-rk/hwsec.git
cd hwsec
npm install
```

### 2. Configure

```bash
cp .env.example .env
cp config.example.json config.json
# Edit .env — add at least one LLM API key
```

**Minimum**: one of `GEMINI_API_KEY`, `NVIDIA_API_KEY`, or `OPENROUTER_API_KEY`.

For hardware verification (Verilog/Yosys/Verilator), also set:
```bash
# In .env:
OSS_CAD_SUITE=/path/to/oss-cad-suite
```

### 3. Start Optional Vector Memory (Docker)

```bash
docker run -d --name hwsec-qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

### 4. Verify & Run Tests

```bash
npm test                          # 25 test suites
node audit/runners/main-runner.js --profile full   # 50 adversarial security invariants
```

---

## Basic Usage

### Step 1: Plan (Non-Destructive)

```bash
node src/index.js analyze ./example-project --proof standard
```

Review the generated plan:
```bash
cat hwsec-output/<analysis-id>/plan.md
```

### Step 2: Approve and Execute

```bash
node src/index.js proceed <analysis-id> --mode standard
```

### Step 3: View Results

```bash
# Final report
cat hwsec-output/<analysis-id>/report/final.md

# Structured findings
node src/index.js findings <analysis-id>

# Analyst dossier for a specific case
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
