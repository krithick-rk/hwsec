# HWSEC Artificial Vulnerability Benchmark — Framework Evaluation Report

**Evaluation Timestamp:** 2026-09-10T11:27:38.954Z  
**Benchmark Version:** 1.0  
**Operating System:** Windows host with WSL2 Ubuntu Linux (Python 3.14.4, Flask 3.1.3, Pytest 9.1.1, lxml 6.1.3)  
**Security Framework:** HWSEC Multi-Language Evidence-Driven Operational Security Framework  

---

## Executive Summary

The HWSEC security framework was evaluated against the **HWSEC Artificial Vulnerability Benchmark**, consisting of **9 intentionally vulnerable target projects** and **9 companion fixed reference solutions** across Easy, Medium, and Hard difficulty tiers.

The evaluation verified:
1. Deterministic EntryPoint discovery across all web/API interfaces via `EntryPointInventory`.
2. SAST static vulnerability pattern detection using **Semgrep CLI 1.176.1** in WSL.
3. Automated **VulnerabilityHypothesis** formulation.
4. Positive **Exploit Witness execution** and **Runtime Observation** against the active target applications.
5. Benign **Causal Negative Control execution** confirming causal attribution (no spurious side-effects).
6. Cryptographic **Evidence DAG assembly** and **EvidenceAuthority** deterministic verdict reduction.
7. Verification against **Fixed Solutions** to measure false-positive resistance.

### Quantitative Performance Metrics

| Metric | Value | Percentage |
| :--- | :--- | :--- |
| **Vulnerable Targets Evaluated** | 9 | 100.0% |
| **True Positives (TP)** | 9 / 9 | 100.0% |
| **False Negatives (FN)** | 0 / 9 | 0.0% |
| **Fixed Solutions Evaluated** | 9 | 100.0% |
| **True Negatives (TN)** | 9 / 9 | 100.0% |
| **False Positives (FP)** | 0 / 9 | 0.0% |
| **Precision** | 1 | **100.0%** |
| **Recall (Sensitivity)** | 1 | **100.0%** |
| **F1 Score** | 1 | **100.0%** |
| **Overall Accuracy** | 1 | **100.0%** |

---

## Case-by-Case Comparison: Actual Framework Output vs. Ground Truth Answer Key

| Case ID | Difficulty | CWE / Vulnerability Class | Entry Point Identified | Witness Triggered | Control Passed | Expected Result | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **CASE-E01** | `easy` | CWE-78 OS Command Injection | `POST /api/diagnostic/ping` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-E02** | `easy` | CWE-89 SQL Injection | `GET /api/users/search?username=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-E03** | `easy` | CWE-22 Path Traversal | `GET /api/files/download?filename=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-M01** | `medium` | CWE-79 Cross-Site Scripting (Reflected) | `GET /search?q=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-M02** | `medium` | CWE-89 SQL Injection | `GET /api/users/search?pattern=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-M03** | `medium` | CWE-78 OS Command Injection | `POST /api/diagnostic/run (tool=ping)` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H01** | `hard` | CWE-22 Path Traversal | `GET /api/files/download?filename=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H02** | `hard` | CWE-90 LDAP Injection | `POST /api/auth/login` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H03** | `hard` | CWE-643 XPath Injection | `GET /api/user/search?username=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |

---

## Fixed Solutions Evaluation (False Positive Resistance)

| Case ID | Solution Path | Exploit Blocked | Benign Functionality Preserved | Expected Result | Actual Result | FP Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **CASE-E01** | `solutions/easy/CASE-E01-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-E02** | `solutions/easy/CASE-E02-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-E03** | `solutions/easy/CASE-E03-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-M01** | `solutions/medium/CASE-M01-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-M02** | `solutions/medium/CASE-M02-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-M03** | `solutions/medium/CASE-M03-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-H01** | `solutions/hard/CASE-H01-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-H02** | `solutions/hard/CASE-H02-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |
| **CASE-H03** | `solutions/hard/CASE-H03-...` | Yes | Yes | **NOT_DETECTED** | **NOT_DETECTED** | ✅ PASS |

---

## Detailed Case Analysis & Evidence Traces

### CASE-E01 — CWE-78 OS Command Injection (EASY)

- **Target Architecture & Entry Point:** `POST /api/diagnostic/ping`
- **SAST Static Pattern Matches:** 4 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `d346c54552f166efb91bea5cc61a9b9a125b375a55ea35e3f277a93c31f32c5c`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-E02 — CWE-89 SQL Injection (EASY)

- **Target Architecture & Entry Point:** `GET /api/users/search?username=`
- **SAST Static Pattern Matches:** 4 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `6b2be5b2431989c106ccfd430d1604f2743a8f72a207139260a71e7cceca8128`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-E03 — CWE-22 Path Traversal (EASY)

- **Target Architecture & Entry Point:** `GET /api/files/download?filename=`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `3376eb15d680cb309ddd4125e0ae7742a6ddc5fab9c39f2425025e658bfb3852`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-M01 — CWE-79 Cross-Site Scripting (Reflected) (MEDIUM)

- **Target Architecture & Entry Point:** `GET /search?q=`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `29ca05d3519b497892dca29f29a8b19cf609fa666de659bc5c8d09729e7c6989`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-M02 — CWE-89 SQL Injection (MEDIUM)

- **Target Architecture & Entry Point:** `GET /api/users/search?pattern=`
- **SAST Static Pattern Matches:** 2 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `5514763fbca39198f9b4eb28fc07cebd8cd396ea40066f01f4c47953387295b6`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-M03 — CWE-78 OS Command Injection (MEDIUM)

- **Target Architecture & Entry Point:** `POST /api/diagnostic/run (tool=ping)`
- **SAST Static Pattern Matches:** 2 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `47dd07d4ac7fe0aded2b1542687ab887108a1081be1eb252551d16984c0ac852`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-H01 — CWE-22 Path Traversal (HARD)

- **Target Architecture & Entry Point:** `GET /api/files/download?filename=`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `50da85d156b797883f7792682ded69e09640883995ca0a926c1d07417c21003d`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-H02 — CWE-90 LDAP Injection (HARD)

- **Target Architecture & Entry Point:** `POST /api/auth/login`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `cae8e37abafbb49642bb837be47a7965efcf00dc5dcf012e8c0e5ba7c2f9b3ba`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

### CASE-H03 — CWE-643 XPath Injection (HARD)

- **Target Architecture & Entry Point:** `GET /api/user/search?username=`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `8a4155b15d2067057439398eeea3fdffb0b71c2082eb2f09fa048a3d055a00ca`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked (400/401/403/escaped) -> `NOT_DETECTED`

---

## Verification & Environment Checklist

- [x] Python 3.14.4 (WSL) runtime active
- [x] Flask 3.1.3 & Pytest 9.1.1 test client operational
- [x] Semgrep CLI 1.176.1 active and generating structured findings
- [x] CodeQL CLI 2.26.4 resolved and operational
- [x] Joern CLI operational
- [x] All 18 benchmark test suites passing (18/18 safe checks in `run_all_safe_checks.sh`)
- [x] EvidenceAuthority deterministic state reduction verified without mocks
