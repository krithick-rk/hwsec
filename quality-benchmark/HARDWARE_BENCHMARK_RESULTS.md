# HWSEC Hardware Benchmark Results

**Analysis ID**: `20260908073420-4aa410d0`  
**Target Suite**: `quality-benchmark/hardware/verification-benchmarks`  
**Completion Date**: 2026-09-08  
**Novelty Mode**: `STANDARD`

---

## 1. File Discovery & Inventory
- **Total Files Scanned**: 5,077
- **Estimated Lines of Code (LOC)**: 543,663
- **Hardware Verilog / SystemVerilog Files Discovered**: 1,799
- **Software / Driver Files Discovered (C/C++, Python, Headers)**: 3,278

---

## 2. Hardware Tool Execution Summary
| Tool Name | Capability | Status | Exit Code / Result |
|-----------|------------|--------|---------------------|
| `symbiyosys` | `formal_invariant_verification` | **SUCCESS** | 0 (Clean Execution & SBY Path Resolution) |
| `verilator` | `rtl_lint` | **SUCCESS** | 0 (Completed Analysis & C++ Model Gen) |
| `yosys` | `rtl_formal` | **SUCCESS** | 0 (AST & Synthesis Passes Completed) |
| `afl++` | `rtl_fuzz` | **SUCCESS** | 0 (Fuzz Harness Gen & Instrument Passing) |
| `semgrep` | `sast_pattern_scan` | **SUCCESS** | 0 (148 Software SAST Patterns Found) |
| `joern` | `graph_dataflow` | **SUCCESS** | 0 (Code Property Graph Built) |

---

## 3. Live LLM Security Reasoning Breakdown
| Metric | Value |
|--------|-------|
| **Active Primary Provider** | Google AI Studio (`gemini-2.5-flash` / `gemini-1.5-pro` API) |
| **Secondary Failover Provider** | OpenRouter (`meta-llama/llama-3.3-70b-instruct`) |
| **HTTP API Response Status** | **200 OK** (Zero 404 / 500 Failures) |
| **LLM Reasoning Hypotheses Formulated** | 2 Grounded Security Hypotheses |
| **Tokens Consumed** | 21,108 Tokens |
| **Total LLM Execution Cost** | $0.011327 USD |
| **Budget Policy Enforcement** | Passed (0.11% of $10.00 Budget Allocated) |

---

## 4. Detected Security Vulnerabilities & Findings
| CWE ID / Category | Vulnerability Count | Description |
|-------------------|---------------------|-------------|
| `CWE-78` | 13 | Potential Command / Code Injection in tool scripts |
| `CWE-89` | 6 | Potential SQL Injection in database generator scripts |
| `CWE-120` | 33 | Buffer copy without bounds checking (`strcpy`, `sprintf`) |
| `CWE-22` | 16 | Path Traversal Sequences in include/config handling |
| `CWE-1234` / Hardware Invariants | 2 | Hardware Formal Invariants & State Transition Claims |
| `Multi-Evidence Disagreements` | 104 | Analyzer cross-validation candidate observations |

- **Total Deterministic Findings Collected**: 151
- **Total Prioritized Suspicious Targets**: 609
- **Total Candidate Pool Escalated**: 191
- **Total Candidate Findings Verified (E1-E2)**: 174
- **Total Formally Verified Findings (E3+)**: 0
- **Correlated Evidence Clusters**: 136
- **Synthesized Attack Paths**: 33

