# HWSEC: Multi-Language Evidence-Driven Security Analysis Framework

HWSEC is a unified, evidence-driven security analysis platform for hardware designs (Verilog/SystemVerilog) and software applications (Python, Java, C, C++, Go). It pairs deterministic static and formal verification engines with task-routed Large Language Models (NVIDIA NIM / Gemini) governed by a strict human-in-the-loop approval gate and technical verification ladder.

---

## Key Features

1. **Strict Human Approval Gate**: 
   - `hwsec analyze` is completely isolated and cheap: it discovers files, hashes source trees, probes tool availability, calculates token/cost budgets, and generates `plan.md`. It **never** executes expensive tools or queries LLMs without explicit human consent.
   - `hwsec proceed <analysis-id>` transitions the plan into execution.

2. **Multi-Language Analysis Platform**:
   - **Hardware (RTL)**: Verilog, SystemVerilog via Verilator (linting), Yosys (formal synthesis), SymbiYosys (bounded model checking & counterexample extraction), AFL++ (fuzzing), and Spike (RISC-V ISA golden model simulation).
   - **Software**: C, C++, Python, Java, Go via Semgrep (lightweight AST pattern matching), Joern (Code Property Graph dataflow in native/WSL), and CodeQL (deep semantic dataflow & taint tracking).

3. **Grounded Technical Verification Ladder (E0–E5)**:
   - **E0 (Claim Only)**: Unsubstantiated hypotheses are refuted.
   - **E1 (Static Observation)**: Tool alerts held at Candidate status without an execution artifact.
   - **E2 (Reproducible Artifact)**: Concrete test harness/log present without triggering a failure.
   - **E3 (Semantic Match)**: Reproducible counterexample trace (e.g. SBY `trace.vcd` or crash log) confirming the bug.
   - **E4 (Security Relevance)**: Proven impact against a security boundary or invariant.
   - **E5 (Attacker Reachability)**: Source-to-sink dataflow trace from untrusted external input to vulnerable sink.
   - **No Hallucinations**: String matching or LLM speculation is strictly barred from promoting findings to `VERIFIED`.

4. **Adaptive Suspicion & Disagreement Engine**:
   - Scores files dynamically based on deterministic finding density, keyword concentration, and graph boundaries.
   - Escalates suspicion when tools disagree (e.g. Semgrep reports a vulnerability that dataflow analyzers missed).
   - Dynamically selects analysis depth: `BASELINE_ONLY`, `CHEAP_DETERMINISTIC`, `DEEP_DATAFLOW`, or `TARGETED_FORMAL_LLM`.

5. **Local Persistent SQLite Database & Qdrant Semantic Memory**:
   - Zero-dependency SQLite (`node:sqlite`) storing 12 tables: projects, analysis runs, files, tool runs, evidence, hypotheses, findings, verification results, graph nodes, graph edges, token ledgers, and audit events.
   - Incremental SHA-256 caching for instantaneous re-analysis of unmodified files.
   - Qdrant vector database (`localhost:6333`) storing 128-dimensional security embeddings for semantic CWE pattern retrieval.

6. **Unified LLM Gateway & Budget Controller**:
   - Automatically routes tasks (`PLANNING`, `HYPOTHESIS_GENERATION`, `INVARIANT_SYNTHESIS`, `VERIFICATION`, `SUMMARY`) to the optimal model based on reasoning requirements, code understanding, and context length.
   - Strict budget cutoffs: throttles exploratory generation at 80% budget, cuts novelty at 90%, and blocks non-critical calls at 100%.

---

## Installation & Setup

### Prerequisites
- **Node.js**: v22+ or v24+ (uses built-in `node:sqlite`)
- **Python**: 3.10+
- **WSL2** (optional, recommended for Joern on Windows): Ubuntu with Joern CLI installed.
- **OSS CAD Suite** (optional, for SymbiYosys / Yosys / Verilator): Installed locally.
- **Docker** (optional, for Qdrant vector memory): `docker run -p 6333:6333 qdrant/qdrant`

### Setup
```bash
# Clone the repository
git clone <repo-url>
cd hwsec

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env and supply your NVIDIA_API_KEY or GEMINI_API_KEY
```

---

## Configuration (`config.json` & `.env`)

Credentials and tool paths are managed cleanly via environment variables and interpolated into `config.json`:

```json
{
  "llm_providers": {
    "nvidia": {
      "api_key": "${NVIDIA_API_KEY}",
      "base_url": "https://integrate.api.nvidia.com/v1"
    },
    "gemini": {
      "api_key": "${GEMINI_API_KEY}"
    }
  },
  "tool_paths": {
    "joern": "wsl:/home/intern/bin/joern/joern-cli",
    "sby": "E:\\Intern\\krithick\\Downloads\\oss-cad-suite\\bin\\sby.exe",
    "verilator": "verilator",
    "semgrep": "semgrep",
    "codeql": "codeql",
    "spike": "spike"
  },
  "token_budgets": {
    "max_cost_usd": 10.0,
    "warning_threshold": 0.8
  }
}
```

---

## CLI Reference

### 1. Analyze (Lightweight Planning)
Discovers repository inventory, probes tools, computes budget, and generates `plan.md` without running expensive tools.
```bash
node src/index.js analyze <target-dir> [--novelty standard|off|deep] [--output-dir hwsec-output]
```

### 2. Proceed (Execution After Approval)
Approves and executes the planned pipeline.
```bash
node src/index.js proceed <analysis-id> [--output-dir hwsec-output]
```

### 3. Status
Checks live progress, status, tokens consumed, and findings counts.
```bash
node src/index.js status <analysis-id>
```

### 4. Findings
Displays structured verified and candidate findings with severity and source locations.
```bash
node src/index.js findings <analysis-id>
```

### 5. Verify
Inspects evidence and verification traces for a specific finding.
```bash
node src/index.js verify <finding-id>
```

### 6. Report
Outputs the final executive report with attack paths and concrete evidence links.
```bash
node src/index.js report <analysis-id>
```

### 7. Reset
Resets an analysis run or purges database records and workspace files.
```bash
# Soft reset: purges SQLite records and resets workspace status to PLANNED
node src/index.js reset <analysis-id>

# Hard reset: purges SQLite records and permanently removes workspace directory on disk
node src/index.js reset <analysis-id> --delete-files
```

---

## Tool Integration Matrix

| Tool | Domain | Primary Capabilities | Host Environment | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Joern** | Software | `graph_dataflow`, `code_property_graph` | WSL / Native | Genuine (v4.0.620) |
| **SymbiYosys** | Hardware | `formal_invariant_verification`, `bounded_model_check` | OSS CAD Suite | Genuine (BMC & VCD) |
| **Semgrep** | Software | `sast_pattern_scan` | Native / Bundled fallback | Genuine |
| **Verilator** | Hardware | `rtl_lint` | Native / OSS CAD Suite | Genuine |
| **Yosys** | Hardware | `rtl_formal` | Native / OSS CAD Suite | Genuine |
| **AFL++** | Hardware | `rtl_fuzz` | Native / WSL | Genuine |
| **CodeQL** | Software | `deep_dataflow`, `taint_tracking` | Native / WSL | Genuine (Clean `UNAVAILABLE` when CLI absent) |
| **Spike** | Hardware | `reference_model`, `isa_simulation` | Native / WSL | Genuine (Clean `UNAVAILABLE` when CLI absent) |
| **Qdrant** | Memory | Vector Similarity Search (128-dim) | Docker (`:6333`) | Genuine |

---

## Running Tests

HWSEC includes 18 comprehensive, isolated unit and integration test suites:

```bash
# Run all 18 test suites
node tests/run_all_tests.js
```

### Test Suite Overview
1. `test_wp1_planning_gate.js`: State transition invariants and planning isolation.
2. `test_wp2_nvidia_llm.js`: Model registry and budget thresholds.
3. `test_wp3_sqlite_db.js`: SQLite schema tables and SHA-256 fingerprinting.
4. `test_wp4_broker_multilang.js`: AnalysisBroker capability matching and security guardrails.
5. `test_wp6_schema.js`: Versioned Schema 2.0.0 migration and source locations.
6. `test_wp7_verifier.js`: Layered verifier rejecting substring matches.
7. `test_wp8_wp11_intelligence.js`: Suspicion scoring, hypothesis generation, and invariant synthesis.
8. `test_wp12_gateway.js`: Unified LLMGateway and credential redaction.
9. `test_joern_adapter.js`: Joern CPG generation and query execution on real C code.
10. `test_codeql_adapter.js`: CodeQL SARIF v2.1.0 parsing and clean unavailable handling.
11. `test_symbiyosys_adapter.js`: SymbiYosys BMC and VCD counterexample trace extraction.
12. `test_spike_adapter.js`: Spike commit log parsing and co-simulation divergence checks.
13. `test_qdrant_rag.js`: Qdrant vector embedding, filtering, and RAG retrieval.
14. `test_graph_strengthening.js`: CodeGraph logical layers (`CODE`, `SECURITY`, `EVIDENCE`) and SQLite sync.
15. `test_e0_e5_verifier.js`: Full 6-level E0 to E5 verification ladder.
16. `test_adaptive_suspicion.js`: Dynamic analysis depth selection and disagreement escalation.
17. `test_cli_commands.js`: End-to-end CLI commands (`analyze`, `proceed`, `status`, `findings`, `verify`, `report`, `reset`).
18. `test_e2e_multilang.js`: End-to-end multi-language pipeline smoke test across C, Python, and Verilog.

---

## Architecture & Design Decisions

All major architectural milestones, trade-offs, and design rationales are documented in [DECISIONS.md](DECISIONS.md).
