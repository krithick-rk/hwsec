# HWSEC — System Installation & Runtime Requirements

**Authoritative Requirements Document for the HWSEC Security Analysis Framework**  
*Document Version: 1.0.0 | Environment Validated: 2026-09-08*

---

## 1. System Overview

**HWSEC** is an enterprise-grade, hybrid hardware/software security analysis and proof-of-impact validation platform. It unifies static analysis, formal verification, symbolic reasoning, and LLM-assisted vulnerability discovery across mixed-domain codebases containing both software (C, C++, Python, Java, Go) and hardware description languages (Verilog, SystemVerilog).

### Core Capabilities
- **Multi-Language Repository Discovery**: Automatic fingerprinting, language classification, recursive source tree indexing, and cryptographic file hashing.
- **Hybrid Domain Analysis**:
  - *Hardware Domain*: RTL linting (Verilator), formal synthesis and property checking (Yosys), bounded model checking (SymbiYosys), and hardware model fuzzing (AFL++).
  - *Software Domain*: AST pattern scanning (Semgrep), Code Property Graph dataflow traversal (Joern), and static analysis framework hooks.
- **Evidence-Driven Verification (E0–E5)**: Strict technical ladder requiring concrete counterexamples (AddressSanitizer crashes, formal BMC traces, reproducible assertion failures) to promote candidate findings. Rejects LLM self-certification.
- **Controlled Proof-of-Impact Validation**: Isolated ephemeral sandbox executing minimal deterministic regression tests and formal assertions under the Anti-Exploit Principle (no weaponized payloads).
- **Intelligent Orchestration & Scheduling**: Suspicion scoring, analyzer disagreement detection, token-aware pre-flight budgeting, and a 3-provider LLM gateway (NVIDIA NIM → Google Gemini → OpenRouter).

---

## 2. Supported Operating Environments

HWSEC is engineered for cross-platform operation with specific host and subsystem roles:

| Environment | Role / Purpose | Minimum / Validated Version |
| :--- | :--- | :--- |
| **Windows Host** | Primary CLI runtime, orchestrator, SQLite database, Docker host | Windows 11 Build 22631+ |
| **WSL2 (Ubuntu/Debian)** | Linux subsystem for Joern CPG generation, AFL++ compilation, Linux toolchains | Ubuntu 22.04 LTS / 24.04 LTS |
| **Docker Engine / Desktop** | Containerized Qdrant vector database daemon | Docker 29.7.2+ |
| **Node.js Runtime** | Core framework, CLI, brokers, workers, state machine | Node.js v24.20.0 (v20+ LTS supported) |
| **npm** | Package management and script orchestration | npm 11.19.0+ |
| **Python** | Local sandbox execution, pytest harness, helper scripts | Python 3.13.3 (accessed via `py` launcher or `python`) |
| **Java / OpenJDK** | Dependency for Joern Scala CPG extractor and Java AST analysis | OpenJDK 17 or 21 LTS |

---

## 3. Software Requirements Matrix

Every dependency and tool is classified according to its operational necessity:

| Software / Tool | Category | Status on Host | Purpose & Behavior |
| :--- | :--- | :--- | :--- |
| **Node.js** | **REQUIRED** | Installed (`v24.20.0`) | Primary application engine. Runs CLI, orchestrator, and database. |
| **npm** | **REQUIRED** | Installed (`11.19.0`) | Dependency manager and test runner (`npm test`). |
| **SQLite (`better-sqlite3`)** | **REQUIRED** | Installed (`^13.0.3`) | Structured storage for runs, file metadata, tool telemetry, hypotheses, findings, and proof records. |
| **Git** | **REQUIRED** | Installed (`2.55.0`) | Source tracking, repository discovery, and version control. |
| **Python** | **REQUIRED** | Installed (`3.13.3`) | Proof sandbox test execution (`pytest`, `unittest`) and ASan scripts. |
| **Docker Desktop** | **OPTIONAL** | Installed (`29.7.2`) | Hosts local containerized Qdrant vector memory daemon. |
| **Qdrant** | **OPTIONAL** | Configured (`hwsec-qdrant`) | Vector database for RAG context and semantic proof memory. Graceful fallback if offline. |
| **WSL2** | **DOMAIN-SPECIFIC** | Installed (Ubuntu) | Executes Joern CPG pipelines and Linux-native fuzzing harnesses. |
| **Java / OpenJDK** | **DOMAIN-SPECIFIC** | Installed in WSL | Required by Joern CLI (`c2cpg.sh`, `javasrc2cpg`). |
| **OSS CAD Suite** | **DOMAIN-SPECIFIC** | Installed (`E:\Intern\krithick\Downloads\oss-cad-suite`) | Hardware tool suite providing Yosys, SBY, and Verilator. |
| **Yosys** | **DOMAIN-SPECIFIC** | Installed (`0.68+136`) | RTL synthesis, netlist elaboration, and formal property checks. |
| **SymbiYosys (SBY)** | **DOMAIN-SPECIFIC** | Installed (`v0.68`) | Bounded Model Checking (BMC depth=20) and formal safety proofs. |
| **Verilator** | **DOMAIN-SPECIFIC** | Installed (`5.051 devel`) | RTL linting and C++ cycle-accurate simulation harness generation. |
| **Joern** | **DOMAIN-SPECIFIC** | Installed (`v4.0.620` in WSL) | Code Property Graph (CPG) AST/CFG/PDG taint analysis. |
| **Semgrep** | **DOMAIN-SPECIFIC** | Adapter Configured | AST pattern-based rule matching across software languages. |
| **AFL++** | **DOMAIN-SPECIFIC** | Adapter Configured | Hardware simulation fuzzing via Verilated C++ harnesses. |
| **CodeQL** | **UNAVAILABLE FALLBACK** | Not Installed | CodeQL CLI not present; adapter safely returns `UNAVAILABLE` without fabricating data. |
| **Spike** | **UNAVAILABLE FALLBACK** | Not Installed | RISC-V ISA simulator; adapter safely returns `UNAVAILABLE` without fabricating data. |

---

## 4. Language Support Matrix

| Target Language | File Extensions | Primary Analyzer | Secondary Analyzer / Verifier | Proof Execution Toolchain |
| :--- | :--- | :--- | :--- | :--- |
| **C** | `.c`, `.h` | Joern (CPG Dataflow) | Semgrep SAST | Clang / GCC with `-fsanitize=address,undefined` |
| **C++** | `.cpp`, `.cc`, `.hpp` | Joern (CPG Dataflow) | Semgrep SAST | Clang / G++ with `-fsanitize=address,undefined` |
| **Python** | `.py` | Semgrep (AST Rules) | Candidate Generator | Native Python `unittest` / `pytest` in sandbox |
| **Java** | `.java` | Semgrep (AST Rules) | Joern (`javasrc2cpg`) | JUnit runner / isolated Java bytecode execution |
| **Go** | `.go` | Semgrep (AST Rules) | Candidate Generator | Go test harness in isolated sandbox |
| **Verilog** | `.v`, `.vh` | Verilator (Linting) | Yosys (Formal Synthesis) | SymbiYosys (`sby` BMC depth=20) |
| **SystemVerilog** | `.sv`, `.svh` | Verilator (Linting) | SymbiYosys (SVA BMC) | SymbiYosys (`read -formal -sv`) with VCD counterexamples |

---

## 5. External Services & Remote Dependencies

HWSEC supports both fully offline operation and cloud-assisted reasoning:

| Service | Mode | Protocol / Endpoint | Operational Fallback |
| :--- | :--- | :--- | :--- |
| **Qdrant Vector DB** | Local (Docker) | `http://localhost:6333` | If offline, RAG engine gracefully uses SQLite-backed lexical search and local heuristics. |
| **NVIDIA NIM** | Remote (HTTPS) | `https://integrate.api.nvidia.com/v1` | Priority 1 LLM provider. If rate-limited or unavailable, fails over to Gemini. |
| **Google Gemini** | Remote (HTTPS) | Google Generative AI REST / SDK | Priority 2 LLM provider with multi-key pool (`GEMINI_API_KEY`, `GEMINI_API_KEY_2`). |
| **OpenRouter** | Remote (HTTPS) | `https://openrouter.ai/api/v1` | Priority 3 LLM provider for proof artifact writing and capacity balancing (20 RPM limit). |

> [!NOTE]
> HWSEC does **NOT** require remote LLM services for deterministic phases. All static analysis, formal verification, AST scans, and local sandbox proofs operate 100% offline.

---

## 6. Credentials & Environment Variables

All secrets are provisioned strictly via environment variables or a local `.env` file excluded from version control. **Never commit real secrets.**

### `.env` Template
```bash
# ======================================================
# HWSEC CREDENTIAL CONFIGURATION TEMPLATE (.env)
# ======================================================

# Provider 1: NVIDIA NIM (Primary Reasoning Engine)
NVIDIA_API_KEY=your_nvidia_api_key_here

# Provider 2: Google Gemini (Triage & Verification Pool)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_API_KEY_2=your_gemini_backup_key_here

# Provider 3: OpenRouter (Proof Code Generation)
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Optional: Vector Database (Local or Hosted)
QDRANT_URL=http://localhost:6333
QDRANT_API_KEY=your_optional_qdrant_key_here

# Optional: Custom Tool Paths (Overrides system PATH)
# OSS_CAD_SUITE=E:/Intern/krithick/Downloads/oss-cad-suite
```

---

## 7. Installation Guide (Clean Machine)

### Step 1: Clone Repository & Install Node Dependencies
```bash
git clone https://github.com/krithick-rk/hwsec.git
cd hwsec
npm install
```

### Step 2: Configure Environment
```bash
cp .env.example .env
cp config.example.json config.json
# Edit .env to add your API credentials
```

### Step 3: Start Qdrant Vector Daemon (Optional)
```bash
docker run -d --name hwsec-qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

### Step 4: Configure OSS CAD Suite Path (For Hardware Verification)
Add your OSS CAD Suite path to `config.json` or ensure `OSS_CAD_SUITE` environment variable points to your installation directory (e.g. `E:/Intern/krithick/Downloads/oss-cad-suite`).

---

## 8. Configuration Architecture (`config.json`)

`config.json` controls tool paths, provider parameters, and budget thresholds:

```json
{
  "llm_providers": {
    "default": {
      "provider": "gemini",
      "model": "gemini-2.5-flash"
    },
    "openrouter": {
      "model": "meta-llama/llama-3.3-70b-instruct"
    }
  },
  "model_routing": {
    "planner": { "model": "gemini-2.5-pro" },
    "worker": { "model": "gemini-2.5-flash" },
    "proof_writer": { "model": "meta-llama/llama-3.3-70b-instruct" },
    "verifier": { "model": "gemini-2.5-pro" }
  },
  "tool_paths": {
    "yosys": "E:/Intern/krithick/Downloads/oss-cad-suite/bin/yosys.exe",
    "sby": "E:/Intern/krithick/Downloads/oss-cad-suite/bin/sby.exe",
    "verilator": "E:/Intern/krithick/Downloads/oss-cad-suite/bin/verilator_bin.exe"
  },
  "token_budgets": {
    "max_cost_usd": 10.0,
    "max_tokens_per_run": 500000
  }
}
```

---

## 9. Verification Commands

Verify all dependencies before executing analysis:

```bash
# 1. Run the master test runner (All 25 test suites)
npm test

# 2. Run the adversarial security validation engine (100% Invariant Check)
node audit/runners/main-runner.js --profile full

# 3. Verify tool connectivity and status
node -e "import('./src/domains/hardware/tools/yosys.js').then(m => new m.YosysTool().checkInstalled()).then(console.log)"
node -e "import('./src/domains/hardware/tools/symbiyosys.js').then(m => new m.SymbiYosysTool().checkInstalled()).then(console.log)"
node -e "import('./src/domains/software/tools/joern.js').then(m => new m.JoernTool().checkInstalled()).then(console.log)"
```

---

## 10. Minimal First Run

Run an initial non-destructive planning pass and inspect the output:

```bash
# 1. Discover target and generate analysis plan
node src/index.js analyze ./example-project --proof standard

# 2. Inspect generated plan
cat hwsec-output/<analysis-id>/plan.md

# 3. Check status
node src/index.js status <analysis-id>
```

---

## 11. Full Production Run

Execute approved end-to-end analysis with proof-of-impact validation:

```bash
# 1. Plan analysis
node src/index.js analyze ./target-repo --novelty standard --proof standard

# 2. Review and approve execution
node src/index.js proceed <analysis-id> --proof standard

# 3. Inspect final report
cat hwsec-output/<analysis-id>/report/final.md

# 4. Inspect proof status of any candidate finding
node src/index.js proof-status PROOF-<proof-id>
```

---

## 12. Troubleshooting Guide

| Issue / Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| `Qdrant: Vector Daemon Online: false` | Docker container stopped or port 6333 blocked | Run `docker start hwsec-qdrant`. HWSEC continues via SQLite fallback if omitted. |
| `SymbiYosys (sby) not found` | OSS CAD Suite missing from PATH or config | Set `OSS_CAD_SUITE` environment variable or specify path in `config.json`. |
| `Provider 'nvidia' failed HTTP 404/401` | NVIDIA NIM endpoint outage or quota limit | Automatic failover triggers; Gemini or OpenRouter will handle the request seamlessly. |
| `Python script fails with exit code 9009` | Windows App Execution Alias intercepting `python` | HWSEC automatically falls back to `py.exe` launcher. |
| `Joern CPG extraction failed` | WSL2 not running or Java missing in WSL | Ensure WSL2 is active (`wsl -l -v`) and OpenJDK 17/21 is installed in WSL. |
| `Command rejected: target contains external cloud` | Proof sandbox blocked malicious or remote destination | Safety guardrail working as intended. Sandbox only permits local loopback targets. |

---

## 13. Resource Requirements

| Resource | Minimum Spec | Recommended Production Spec | Observed Usage |
| :--- | :--- | :--- | :--- |
| **CPU** | 4 Cores (x86_64) | 8+ Cores (for parallel formal solvers & CPG generation) | 2–4 cores during SBY BMC solvers |
| **RAM** | 8 GB | 16–32 GB (Joern CPG can consume 4–8 GB on large codebases) | ~2.5 GB peak on medium repositories |
| **Disk Space** | 10 GB free | 50 GB free (Docker images, OSS CAD Suite, CPG databases) | ~4 GB for tools and runtime cache |
| **Network** | Offline capable | Broadband connection (if using remote LLM providers) | < 5 MB per analysis run |
