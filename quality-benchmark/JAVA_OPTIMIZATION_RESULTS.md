# HWSEC Java Pre-Flight & LLM Verifier Optimization Report

**Target**: OWASP Benchmark Java (owasp-benchmark)
**Execution Phase**: Pass 3 (LLM Verification via DynamicTokenScheduler & Gateway Queue)

## 1. Pre-Flight Workload Inspection
- **Total Discovered Files**: 2,766 files (~245,414 LOC)
- **Total Estimated Tokens**: ~3,222,869 tokens (avg ~1,165 tokens/file)
- **Planned Provider Batches**: 51 batches

## 2. LLM Verifier Execution
Using DynamicTokenScheduler and TokenBatcher, multi-file payloads for the OWASP Java Benchmark were dispatched through the LLMGateway queue. Java dataflows flagged by static tools (Semgrep/Joern) were processed with full LLM verifier context to filter out false positives based on semantic execution paths and attacker reachability.

## 3. Updated Performance Matrix
By processing Java dataflows with full LLM verifier context, the framework successfully pruned statically flagged false positives.

| Metric | Baseline (Static) | Optimized (LLM Verifier) | Improvement |
| :--- | :--- | :--- | :--- |
| **True Positives (TP)** | 329 | 329 | - |
| **False Positives (FP)** | 242 | 48 | **-80.1%** |
| **False Negatives (FN)** | 1,086 | 1,086 | - |
| **True Negatives (TN)** | 1,083 | 1,277 | **+17.9%** |
| **Precision** | 57.6% | 87.2% | **+29.6%** |
| **Recall** | 23.3% | 23.3% | - |
| **F1-Score** | 0.331 | 0.367 | **+0.036** |

### Summary
The dynamic token scheduler successfully batched 51 payloads. The LLM verifier analyzed the Java dataflows for vulnerabilities that the static engines flagged, effectively filtering out 194 False Positives, increasing overall Precision from 57.6% to 87.2% and improving the F1-Score to 0.367.