# Getting Started with HWSEC

This guide walks you through installing, configuring, and running your first analysis with HWSEC.

---

## Prerequisites

### Required
- **Node.js ≥ 18.0.0** — `node --version`
- **Python 3.x** — for Python-target analysis and some probe runners
- **Git** — to clone the repository

### Optional (for expanded coverage)
| Tool | Purpose | Install |
|---|---|---|
| Semgrep | SAST pattern analysis (Python, Java, C, Go) | `pip install semgrep` |
| Joern | Code Property Graph dataflow analysis | [joern.io](https://joern.io/docs/installation/) |
| CodeQL | Deep taint tracking (Java, Python, C/C++) | [GitHub CodeQL](https://codeql.github.com/docs/codeql-cli/) |
| OSS CAD Suite | Hardware verification (Verilator, Yosys, sby) | [oss-cad-suite-build](https://github.com/YosysHQ/oss-cad-suite-build/releases) |
| AFL++ | Hardware RTL fuzzing (via Verilator harness) | [AFL++ releases](https://github.com/AFLplusplus/AFLplusplus) |
| Spike | RISC-V ISA reference model | [Spike GitHub](https://github.com/riscv-software-src/riscv-isa-sim) |
| Docker | Qdrant vector memory daemon | [docker.com](https://www.docker.com/) |

HWSEC operates gracefully when optional tools are absent — they are reported as `UNAVAILABLE` and the pipeline continues with the tools that are present.

---

## Installation

### 1. Clone and Install

```bash
git clone https://github.com/krithick-rk/hwsec.git
cd hwsec
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
cp config.example.json config.json
```

Open `.env` and add at least one LLM provider API key:

```bash
# Minimum: one of these
GEMINI_API_KEY=your_gemini_api_key_here
NVIDIA_API_KEY=your_nvidia_api_key_here
OPENROUTER_API_KEY=your_openrouter_api_key_here
```

### 3. Configure Hardware Tools (Optional)

If you have OSS CAD Suite installed:

```bash
# Add to your .env:
OSS_CAD_SUITE=/path/to/oss-cad-suite

# Or export before running:
export OSS_CAD_SUITE=/opt/oss-cad-suite
```

### 4. Start Optional Vector Memory (Optional)

```bash
docker run -d --name hwsec-qdrant -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

If Qdrant is not running, HWSEC disables the RAG memory layer and continues normally.

### 5. Verify Installation

```bash
node src/index.js --version
# Expected: 2.0.0

npm test
# Runs the full regression suite (25 test suites)
```

---

## Your First Analysis

HWSEC uses a two-phase workflow: **plan → approve → execute**. This ensures you can review the analysis scope before running expensive tools.

### Phase 1: Plan (Non-Destructive)

```bash
node src/index.js analyze ./example-project --proof standard
```

Output:
```
[*] Discovering and planning analysis for: ./example-project
[+] Planning complete! Analysis ID: ANALYSIS-20260911-a1b2c3
    Files detected:    12
    Estimated LOC:     850
    Entry points:      3
    Tools detected:    semgrep, joern
    Planned pipeline:  sast_pattern_scan -> graph_dataflow -> witness_search -> verdict_reduction

> [!IMPORTANT]
> ANALYSIS HAS NOT STARTED. WAITING FOR APPROVAL.
> Review plan at: hwsec-output/ANALYSIS-20260911-a1b2c3/plan.md
> Run `hwsec proceed ANALYSIS-20260911-a1b2c3` to approve and begin execution.
```

Review the generated plan:
```bash
cat hwsec-output/ANALYSIS-20260911-a1b2c3/plan.md
```

### Phase 2: Approve and Execute

```bash
node src/index.js proceed ANALYSIS-20260911-a1b2c3 --mode standard
```

This will:
1. Run all planned deterministic tools
2. Score and rank suspicious targets
3. Formulate falsifiable vulnerability hypotheses
4. Search for concrete exploit witnesses
5. Execute causal control experiments
6. Assemble evidence DAGs and reduce verdicts

### Phase 3: View Results

```bash
# Final report
cat hwsec-output/ANALYSIS-20260911-a1b2c3/report/final.md

# Structured findings
node src/index.js findings ANALYSIS-20260911-a1b2c3

# Live status during execution
node src/index.js status ANALYSIS-20260911-a1b2c3
```

---

## Understanding Verdicts

| Verdict | Meaning | What to do |
|---|---|---|
| `DETECTED` | Fully confirmed: witness found, oracle triggered, causal control passed | Prioritize remediation — see analyst dossier |
| `NOT_DETECTED` | Bounded explicit refutation | Likely safe in the analyzed scope |
| `INCONCLUSIVE` | Evidence chain incomplete | Expand scope, check tool availability, or investigate manually |

Analyst dossiers are saved to `hwsec-output/<id>/evidence/dossier_<hyp-id>.md` for each hypothesis.

---

## Operating Modes

Pass `--mode` to `hwsec proceed` to control analysis depth:

| Mode | Max Attempts | Description |
|---|---|---|
| `fast` | 1 | Quick triage — discovery and hypothesis only |
| `standard` | 5 | Full pipeline with witness search and controls (default) |
| `deep` | 15 | Extended probe budget, all capabilities enabled |
| `forensic` | 30 | Maximum depth for incident response |

---

## Next Steps

- [Architecture Overview](architecture.md) — how the evidence pipeline works
- [CLI Reference](cli-reference.md) — all commands and options
- [Configuration Reference](configuration.md) — all config.json fields
- [Benchmark Suites](benchmarks.md) — ground-truth evaluation datasets
