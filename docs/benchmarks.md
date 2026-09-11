# HWSEC Benchmark Suites

HWSEC ships four curated benchmark suites for evaluating detection accuracy across language domains. Each suite includes vulnerable targets, hardened solutions, answer keys (ground truth), and evaluation reports.

---

## Benchmark Overview

| Suite | Directory | Languages | Cases | Detection Rate |
|---|---|---|---|---|
| Artificial | `hwsec_artificial_benchmark/` | Multi-domain | Behavioral/algorithmic | — |
| C / Memory Safety | `hwsec_c_benchmark/` | C | 12 | Evaluated |
| Java | `hwsec_java_benchmark/` | Java | 12 | Evaluated |
| Verilog/SystemVerilog RTL | `hwsec_verilog_benchmark/` | Verilog, SV | 12 | 100% (12/12) |

---

## Suite: `hwsec_verilog_benchmark/`

The RTL security benchmark covers hardware-specific security properties that cannot be assessed by software-only analyzers.

### Structure

```
hwsec_verilog_benchmark/
├── targets/          # Vulnerable RTL modules (ground truth: VULNERABLE)
│   ├── case_001_privilege_escalation.v
│   ├── case_002_buffer_overflow_csr.v
│   ├── case_003_insecure_entropy.v
│   └── ... (12 cases total)
├── solutions/        # Hardened reference implementations (ground truth: SECURE)
│   ├── case_001_privilege_escalation_fixed.v
│   └── ...
├── answer_key/       # Per-case ground truth metadata
│   └── ground_truth.json
├── properties/       # Formal SVA properties for each case
│   └── case_001_privilege_escalation.sby
└── reports/
    ├── verilog_evaluation_summary.md
    └── EVALUATION_REPORT.md
```

### CWE Coverage

| Case | CWE | Vulnerability |
|---|---|---|
| 001 | CWE-269 | Privilege escalation — debug mode unlocks full privileges |
| 002 | CWE-120 | Buffer-like overflow in CSR write handler |
| 003 | CWE-338 | Insecure PRNG — predictable seed from time |
| 004 | CWE-311 | Sensitive data stored without encryption |
| 005 | CWE-362 | Race condition in handshake protocol |
| 006 | CWE-1231 | Missing hardware lock after soft reset |
| 007 | CWE-1234 | Write-once register bypass during reset |
| 008 | CWE-1240 | Weak key derivation in AES core |
| 009 | CWE-123 | Write-what-where in DMA controller |
| 010 | CWE-415 | Double-free analog in memory controller |
| 011 | CWE-400 | Uncontrolled resource consumption (timer) |
| 012 | CWE-284 | Missing access control on debug register bank |

### Re-running Evaluation

```bash
# Prerequisites: iverilog/vvp available in WSL or system PATH
node tests/experimental/evaluate_verilog_benchmark.mjs
```

Output is written to `hwsec_verilog_benchmark/reports/`.

---

## Suite: `hwsec_c_benchmark/`

C and memory-safety vulnerability benchmark covering heap/stack overflows, format strings, integer overflows, and use-after-free patterns.

### Structure

```
hwsec_c_benchmark/
├── targets/          # Vulnerable C programs
├── solutions/        # Fixed/hardened versions
├── answer_key/       # Ground truth JSON
└── reports/          # Evaluation results
```

### Re-running Evaluation

```bash
# Prerequisites: gcc with AddressSanitizer support
node tests/experimental/evaluate_c_benchmark.mjs
```

The evaluator compiles each target with `-fsanitize=address`, executes probe inputs from the witness search engine, and checks for ASan crash headers.

---

## Suite: `hwsec_java_benchmark/`

Java security benchmark covering CWE-89 (SQL injection), CWE-78 (command injection), CWE-22 (path traversal), CWE-502 (insecure deserialization), and others.

### Structure

```
hwsec_java_benchmark/
├── targets/          # Vulnerable Java source files
├── solutions/        # Secure implementations
├── answer_key/       # Ground truth metadata
└── reports/          # Evaluation summaries
```

### Re-running Evaluation

```bash
# Prerequisites: JDK installed, javac on PATH
node tests/experimental/evaluate_java_benchmark.mjs
```

---

## Suite: `hwsec_artificial_benchmark/`

Purpose-built behavioral cases for testing the evidence pipeline in isolation — cases where ground truth is deterministically controlled and tool availability does not affect correctness.

Useful for:
- Regression testing the EvidenceDAG and EvidenceAuthority
- Validating the E0–E5 promotion ladder
- Verifying INCONCLUSIVE fail-closed behavior

### Re-running Evaluation

```bash
node tests/experimental/evaluate_artificial_benchmark.mjs
```

---

## Ground Truth Format

All benchmark suites share a common `answer_key/ground_truth.json` format:

```json
[
  {
    "case_id": "VERILOG-001",
    "file": "targets/case_001_privilege_escalation.v",
    "expected_verdict": "DETECTED",
    "cwe": "CWE-269",
    "description": "Debug enable signal grants full privileges"
  },
  {
    "case_id": "VERILOG-001-FIXED",
    "file": "solutions/case_001_privilege_escalation_fixed.v",
    "expected_verdict": "NOT_DETECTED",
    "cwe": "CWE-269",
    "description": "Hardened: debug mode requires secure boot flag"
  }
]
```

---

## Evaluation Metrics

Each evaluation run reports:

| Metric | Description |
|---|---|
| **True Positives (TP)** | Vulnerable targets correctly flagged DETECTED |
| **True Negatives (TN)** | Secure targets correctly flagged NOT_DETECTED |
| **False Positives (FP)** | Secure targets incorrectly flagged DETECTED |
| **False Negatives (FN)** | Vulnerable targets missed (INCONCLUSIVE or NOT_DETECTED) |
| **Detection Rate** | TP / (TP + FN) |
| **Precision** | TP / (TP + FP) |
