# HWSEC Vulnerability Benchmark Manual Handoff & Setup Guide

This document accompanies the automated benchmark fetch script (`fetch_benchmarks.js` / `fetch_benchmarks.sh`). It details automated dataset ingestion as well as manual instructions for large, authenticated, or form-protected benchmark datasets.

---

## 1. Automated Successes

The automated script (`fetch_benchmarks.js` / `fetch_benchmarks.sh`) handles directory tree initialization and public git dataset clones:

| Benchmark Target | Language | Method | Target Directory |
| :--- | :--- | :--- | :--- |
| **OWASP Benchmark Java** | Java | `git clone --depth 1` | `quality-benchmark/java/owasp-benchmark/` |
| **Vul4J Reproducible Vulnerabilities** | Java | `git clone --depth 1` | `quality-benchmark/java/vul4j/` |
| **OWASP WebGoat** | Java | `git clone --depth 1` | `quality-benchmark/java/webgoat/` |
| **SasanLabs VulnerableApp** | Java | `git clone --depth 1` | `quality-benchmark/java/vulnerableapp/` |
| **OWASP Go Test Bench** | Go | `git clone --depth 1` | `quality-benchmark/go/go-test-bench/` |
| **OWASP PyGoat** | Python | `git clone --depth 1` | `quality-benchmark/python/pygoat/` |

---

## 2. Manual Action Required

The following datasets require manual download due to file size, archive compression, or authentication/form requirements:

- **NIST Juliet Test Suite v1.3 for C/C++** (Large zip archive ~280 MB, 64,000+ test cases)
- **NIST Juliet Test Suite v1.3 for Java** (Large zip archive ~100 MB, 28,000+ test cases)
- **Big-Vul C/C++ Vulnerability Dataset** (Zenodo CSV download ~300 MB, 10,900+ commits)
- **DiverseVul C/C++ Dataset** (Zenodo / Google Drive download ~500 MB, 18,900+ vulnerable functions)

---

## 3. Manual Download & Extraction Instructions

### 3.1 NIST Juliet Test Suite v1.3 (C/C++)

- **Download Page:** [NIST SAMATE Juliet C/C++ v1.3](https://samate.nist.gov/SARD/test-suites/112)
- **Direct Zip URL:** `https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-c-cplusplus-v1-3.zip`
- **Extraction Targets:**
  - Extract C test cases to: `quality-benchmark/c/juliet/`
  - Extract C++ test cases to: `quality-benchmark/cpp/juliet/`

#### Instructions:
1. Download `2017-10-01-juliet-c-cplusplus-v1-3.zip` from the URL above.
2. Unzip the contents.
3. Move `C/testcases` into `quality-benchmark/c/juliet/`.
4. Move `C++/testcases` into `quality-benchmark/cpp/juliet/`.

---

### 3.2 NIST Juliet Test Suite v1.3 (Java)

- **Download Page:** [NIST SAMATE Juliet Java v1.3](https://samate.nist.gov/SARD/test-suites/113)
- **Direct Zip URL:** `https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-java-v1-3.zip`
- **Extraction Target:** `quality-benchmark/java/juliet/`

#### Instructions:
1. Download `2017-10-01-juliet-java-v1-3.zip` from the URL above.
2. Unzip the contents.
3. Copy the `src/testcases` folder into `quality-benchmark/java/juliet/`.

---

### 3.3 Big-Vul C/C++ Vulnerability Dataset

- **Publication:** Fan et al., *"A C/C++ Code Vulnerability Dataset with Code Changes and Commit Messages"* (MSR 2020)
- **Repository:** [CenturioSam/Big-Vul GitHub](https://github.com/CenturioSam/Big-Vul)
- **Data Archive (Zenodo):** [Zenodo Record 3745284](https://zenodo.org/record/3745284)
- **Direct Download:** `https://zenodo.org/record/3745284/files/MSR_data_cleaned.csv`
- **Extraction Targets:**
  - Place copy in: `quality-benchmark/c/bigvul/`
  - Place copy in: `quality-benchmark/cpp/bigvul/`

#### Instructions:
1. Download `MSR_data_cleaned.csv` from Zenodo.
2. Place `MSR_data_cleaned.csv` into `quality-benchmark/c/bigvul/MSR_data_cleaned.csv` and `quality-benchmark/cpp/bigvul/MSR_data_cleaned.csv`.

---

### 3.4 DiverseVul C/C++ Dataset

- **Publication:** Zhou et al., *"DiverseVul: A New Vulnerable Source Code Dataset for Deep Learning Based Vulnerability Detection"* (RAID 2023)
- **Repository:** [wukong-lab/DiverseVul GitHub](https://github.com/wukong-lab/DiverseVul)
- **Data Archive (Zenodo):** [Zenodo Record 8086487](https://zenodo.org/records/8086487)
- **Extraction Targets:**
  - Place dataset in: `quality-benchmark/c/diversevul/`
  - Place dataset in: `quality-benchmark/cpp/diversevul/`

#### Instructions:
1. Download `diversevul.json` from the Zenodo link above.
2. Place `diversevul.json` into `quality-benchmark/c/diversevul/` and `quality-benchmark/cpp/diversevul/`.

---

## 4. Verification Check

After completing automated and manual steps, run the verification check script to ensure all paths are populated:

```bash
# Node.js execution
node quality-benchmark/fetch_benchmarks.js

# Or Bash execution
bash quality-benchmark/fetch_benchmarks.sh
```
