# HWSEC Architecture Status

Generated: 2026-09-08T10:54:09+05:30

## Summary

HWSEC is an evidence-driven, coverage-directed security analysis platform for hardware and software.
This document reflects the current implementation state following the Improved Architecture upgrade.

---

## Component Status

| Component | Status | Notes |
|---|---|---|
| CLI (src/index.js) | ✅ OPERATIONAL | analyze, proceed, plan commands |
| Planner (src/core/planner.js) | ✅ OPERATIONAL | Coverage matrix integration |
| Broker (src/core/broker.js) | ✅ OPERATIONAL | Multi-tool dispatch |
| CoverageMatrix (src/core/coverageMatrix.js) | ✅ OPERATIONAL | 14 CWE families, 6 languages |
| CandidateGenerator (src/workers/candidateGenerator.js) | ✅ OPERATIONAL | SAST+boundary+sink+disagreement pool |
| SuspicionEngine (src/core/suspicion/engine.js) | ✅ OPERATIONAL | 5-signal scoring + target ranking |
| AdaptiveEscalation (src/core/escalation/adaptiveEscalation.js) | ✅ OPERATIONAL | 6 levels, budget/novelty gating |
| HypothesisGenerator (src/workers/hypothesisGenerator.js) | ✅ OPERATIONAL | Qdrant RAG-connected |
| LayeredVerifier (src/workers/verifier.js) | ✅ OPERATIONAL | E0-E5 strict evidence chain |
| EvidenceCorrelationEngine | ✅ OPERATIONAL | Attack path correlation |

---

## LLM Gateway & Provider Status

| Provider | Status | Notes |
|---|---|---|
| NVIDIA NIM | ✅ Configured | NVIDIA_API_KEY set; models: llama-3.3-70b, nemotron-70b, codestral, deepseek-r1 |
| Gemini (pool) | ✅ Configured | GEMINI_API_KEY + GEMINI_API_KEY_2; multi-key round-robin with auth rotation |
| OpenRouter | ✅ Configured | OPENROUTER_API_KEY set; models: llama-3.3-70b, claude-3.5-sonnet, gemini-flash-1.5 |
| Fallback Chain | ✅ OPERATIONAL | nvidia → gemini → openrouter (priority order) |
| Budget Controller | ✅ OPERATIONAL | SQLite-persisted ledger; tiered thresholds at 70/80/90/100% |

---

## Tool Adapter Status

| Tool | Status | Notes |
|---|---|---|
| Semgrep | ✅ AVAILABLE | Primary deterministic SAST (all languages) |
| Joern | ✅ AVAILABLE | WSL /home/intern/bin/joern/joern-cli; full-repo common ancestor |
| Yosys | ✅ AVAILABLE | RTL synthesis analysis |
| SymbiYosys | ✅ AVAILABLE | Formal property verification for RTL |
| AFL++ | ✅ AVAILABLE | Fuzz testing |
| Verilator | ✅ AVAILABLE | RTL linting and simulation |
| CodeQL | ⚠️ UNAVAILABLE | CLI not installed; returns UNAVAILABLE cleanly |
| Spike | ⚠️ UNAVAILABLE | RISC-V simulator not installed; handled gracefully |

---

## Graph & RAG Status

| Component | Status | Notes |
|---|---|---|
| CodeGraph (src/core/graph/) | ✅ OPERATIONAL | In-memory graph, Joern-backed queries |
| Qdrant Vector Store | ⚠️ CONDITIONAL | Available when Docker running on port 6333; falls back to in-memory keyword store |
| HWSECQdrantMemory | ✅ OPERATIONAL | isAvailable() checks live; graceful fallback |
| SecurityKnowledgeStore | ✅ OPERATIONAL | In-memory fallback for RAG when Qdrant offline |

---

## Adaptive Escalation Levels

| Level | Label | Trigger Condition |
|---|---|---|
| 0 | BASELINE | suspicion < 0.20 |
| 1 | STATIC_DEEPENING | suspicion ≥ 0.20 |
| 2 | GRAPH_REACHABILITY | suspicion ≥ 0.35 OR coverage gap |
| 3 | SEMANTIC_REASONING | suspicion ≥ 0.50 OR analyzer disagreement |
| 4 | TARGETED_DYNAMIC_FORMAL | suspicion ≥ 0.65 |
| 5 | NOVELTY_EXPLORATION | suspicion ≥ 0.80 AND budget < 80% AND novelty ≥ standard |

Budget caps: ≥ 90% → max GRAPH_REACHABILITY; ≥ 100% → BASELINE only.
Novelty mode gates: off → max GRAPH_REACHABILITY; minimal → max SEMANTIC_REASONING.

---

## Benchmark Baseline

From previous evaluation run:

| Benchmark | Precision | Recall | F1 |
|---|---|---|---|
| OWASP Benchmark Java | 57.6% | 23.3% | 0.331 |
| NIST Juliet C v1.3 | 100.0% | 26.6% | 0.420 |
| NIST Juliet C++ v1.3 | 100.0% | 10.2% | 0.185 |
| Vul4J Reproducible Vulns | 100.0% | 92.2% | 0.960 |
| OWASP WebGoat | 100.0% | 23.7% | 0.383 |
| SasanLabs VulnerableApp | 100.0% | 11.8% | 0.211 |
| OWASP Go Test Bench | 100.0% | 3.6% | 0.070 |
| OWASP PyGoat | 100.0% | 14.3% | 0.250 |
| **OVERALL** | **78.1%** | **22.4%** | **0.348** |

---

## Known Constraints

- Three manual benchmark datasets skipped: c/bigvul/, c/diversevul/, java/juliet/ (SKIPPED status)
- Cross-language true dataflow not modeled (unknown boundaries represented explicitly)
- RAG only active when Qdrant Docker is running
- CodeQL unavailable — no results fabricated, returns UNAVAILABLE cleanly
