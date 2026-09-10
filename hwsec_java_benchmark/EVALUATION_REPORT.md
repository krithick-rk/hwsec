# HWSEC Java / Spring Boot 3 Vulnerability Benchmark — Framework Evaluation Report

**Evaluation Timestamp:** 2026-09-10T11:48:58.716Z  
**Benchmark Version:** 1.0-java  
**Runtime Environment:** Java 21 LTS (OpenJDK 64-Bit Server VM), Maven 3.9.12, Spring Boot 3.2.0  
**Security Framework:** HWSEC Multi-Language Evidence-Driven Operational Security Framework  

---

## Executive Summary

The HWSEC security framework was evaluated against the **HWSEC Java Spring Boot Artificial Vulnerability Benchmark**, consisting of **9 advanced vulnerable Spring Boot applications** and **9 companion fixed reference solutions** across Easy, Medium, and Hard difficulty tiers.

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
| **CASE-M01** | `medium` | CWE-79 XSS (Stored) | `POST /api/messages -> GET /api/messages/{id}` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-M02** | `medium` | CWE-90 LDAP Injection | `GET /api/auth/lookup?username=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-M03** | `medium` | CWE-643 XPath Injection | `GET /api/xml/search?username=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H01** | `hard` | CWE-94 Code Injection (SpEL) | `POST /api/rules/evaluate` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H02** | `hard` | CWE-89 SQL Injection (HQL) | `GET /api/products/search?name=` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |
| **CASE-H03** | `hard` | CWE-611 XXE | `POST /api/xml/parse` | Yes | Yes | **DETECTED** | **DETECTED** | ✅ MATCH |

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
- **SAST Static Pattern Matches:** 0 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `2d2133158bdd2d3461a2f23e3121c163c320181d07c24f26324eada095f204b4`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-E02 — CWE-89 SQL Injection (EASY)

- **Target Architecture & Entry Point:** `GET /api/users/search?username=`
- **SAST Static Pattern Matches:** 2 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `43d99efa03cc7badd9c884aeaf6e113a4216ea7a904b6c0c4b66409d213d011d`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-E03 — CWE-22 Path Traversal (EASY)

- **Target Architecture & Entry Point:** `GET /api/files/download?filename=`
- **SAST Static Pattern Matches:** 0 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `e88fe0ffc12377a7a2f8d2559e076145da26bb04721ecf7d5272e00f66e9d86e`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-M01 — CWE-79 XSS (Stored) (MEDIUM)

- **Target Architecture & Entry Point:** `POST /api/messages -> GET /api/messages/{id}`
- **SAST Static Pattern Matches:** 0 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `bad4c9fa1160073380a30d64945895527913e22cf9e4ee51c5808168f37b024a`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-M02 — CWE-90 LDAP Injection (MEDIUM)

- **Target Architecture & Entry Point:** `GET /api/auth/lookup?username=`
- **SAST Static Pattern Matches:** 0 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `4f67fdb9ffb98ca1a7af713145a3f1d7bad48584e0cf270d60dee036d2b10295`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-M03 — CWE-643 XPath Injection (MEDIUM)

- **Target Architecture & Entry Point:** `GET /api/xml/search?username=`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `7fb8afd5caa58b39e0c49096bf63b58d856ffe2258b5868d21a20591d2e910d5`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-H01 — CWE-94 Code Injection (SpEL) (HARD)

- **Target Architecture & Entry Point:** `POST /api/rules/evaluate`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `edd1d82c18f35d4c35895d0f0a237986f25cc77c776f71aea75e64143293599b`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-H02 — CWE-89 SQL Injection (HQL) (HARD)

- **Target Architecture & Entry Point:** `GET /api/products/search?name=`
- **SAST Static Pattern Matches:** 2 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `51ccf5d9f6c934c6c50c6e9343e008cbbab607ef23f6422b0558e5cb841303ed`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

### CASE-H03 — CWE-611 XXE (HARD)

- **Target Architecture & Entry Point:** `POST /api/xml/parse`
- **SAST Static Pattern Matches:** 1 finding(s) detected by Semgrep CLI
- **Witness Verification:** Successfully demonstrated live exploit trigger
- **Causal Negative Control:** Benign input executed without side effect (causal link proven)
- **Cryptographic DAG Hash:** `057e72a70b702d407cc67241da99d304aad63a56eefd7b64b29dff7d5bca4d0b`
- **EvidenceAuthority Verdict:** `DETECTED` (Expected: `DETECTED`)
- **Regression on Solution:** Exploit rejected / blocked -> `NOT_DETECTED`

