# HWSEC: Multi-Language Evidence-Driven Security Analysis Framework

**HWSEC** is an enterprise-grade hybrid hardware/software security analysis and proof-of-impact validation platform. It unifies deterministic static analysis, formal verification, symbolic reasoning, and LLM-assisted vulnerability discovery across mixed-domain codebases containing both software (C, C++, Python, Java, Go) and hardware description languages (Verilog, SystemVerilog).

---

## Authoritative Documentation

Detailed technical documentation is organized into four authoritative documents:

1. **[requirements.md](file:///e:/Intern/hwsec/requirements.md)**: Definitive installation, operating environments, software matrix, tool statuses, credential setup, and resource requirements.
2. **[implementation.md](file:///e:/Intern/hwsec/implementation.md)**: Deep architectural specification, data flow, state machine, tool brokers, database schemas, RAG vector memory, LLM gateway, and E0–E5 verification ladder.
3. **[walkthrough.md](file:///e:/Intern/hwsec/walkthrough.md)**: Practical engineer walkthrough, mixed repository examples, execution lifecycles, database traces, debugging guide, and terminology glossary.
4. **[DECISIONS.md](file:///e:/Intern/hwsec/DECISIONS.md)**: Architectural Decision Records (ADR-001 through ADR-010) documenting design decisions, multi-provider gateway failover, and proof sandbox sandboxing.

---

## Quick Start Guide

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/krithick-rk/hwsec.git
cd hwsec
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
cp config.example.json config.json
# Edit .env to add your API credentials (NVIDIA, Gemini, and/or OpenRouter)
```

### 3. Start Optional Vector Memory Daemon (Docker)
```bash
docker run -d --name hwsec-qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

### 4. Verify System & Run Regression Tests
```bash
# Run the master regression suite (25 test suites, 100% pass)
npm test

# Run the full adversarial security audit suite (50 security invariants)
node audit/runners/main-runner.js --profile full
```

---

## Basic Usage

### Step 1: Discover and Plan Analysis (Non-Destructive)
`analyze` scans target files, detects languages, selects matching analyzers, estimates token budgets, and generates `plan.md`. **Execution is strictly blocked until approval.**

```bash
node src/index.js analyze ./example-project --proof standard
```

Review the generated plan:
```bash
cat hwsec-output/<analysis-id>/plan.md
```

### Step 2: Approve and Execute Analysis
`proceed` validates the human approval boundary, executes deterministic tools, runs formal verification, queries the LLM gateway, and verifies findings through ephemeral sandbox proof execution.

```bash
node src/index.js proceed <analysis-id> --proof standard
```

View the final audit report:
```bash
cat hwsec-output/<analysis-id>/report/final.md
```

### Step 3: Inspect Proof Status & Cryptographic Provenance
```bash
node src/index.js proof-status PROOF-<proof-id>
```

---

## Core Security Guardrails

- **Human Approval Gate**: Analysis plans require explicit human approval via `hwsec proceed` before executing expensive tools or invoking LLMs.
- **Anti-Exploit Principle**: The proof validation engine only generates minimal unit regression tests and formal assertions. It strictly refuses to synthesize weaponized exploits, shellcode, or persistence mechanisms.
- **Isolated Ephemeral Sandbox**: All dynamic test reproductions execute in an isolated workspace with credentials stripped, network access neutralized (`http://127.0.0.1:0`), and external cloud destinations blocked.
- **Zero Self-Certification**: LLM output is treated as untrusted hypothesis. Only concrete executed technical counterexamples (AddressSanitizer crashes, formal BMC traces, reproducible assertion failures) can promote findings to Verified status.

---

## Repository Structure Overview

```
HWSEC/
├── src/                    # Production codebase (core framework, domain adapters, workers)
├── tests/                  # Centralized test suite (25 suites, fixtures, demos, helpers)
├── audit/                  # Adversarial security validation engine (50 security invariants)
├── scripts/                # Benchmark evaluation and ground truth metrics
├── manifests/              # Benchmark ground-truth datasets and manifests
├── quality-benchmark/      # Hardware and software multi-language benchmark repos
├── requirements.md         # Prerequisites, tool requirements, and installation
├── implementation.md       # Technical architecture and implementation guide
├── walkthrough.md          # Step-by-step practical guide for engineers
├── DECISIONS.md            # Architectural Decision Records (ADRs)
├── IMPLEMENTATION_STATUS.md# Component status tracking
├── .env.example            # Environment variable template with placeholders
├── config.example.json     # Configuration file template
└── package.json            # Node.js project manifest and test scripts
```

---

## License
ISC License. See [LICENSE](file:///e:/Intern/hwsec/LICENSE) for details.
