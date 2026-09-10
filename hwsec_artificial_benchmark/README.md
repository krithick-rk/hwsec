# HWSEC Artificial Vulnerability Benchmark

A self-contained, reproducible set of intentionally vulnerable projects
for manual operational testing of the HWSEC security-operations framework.

## Structure

benchmark_targets/   — Vulnerable projects (HWSEC scans ONLY this directory)
solutions/            — Fixed versions of each project
answer_key/           — Manifest, expected findings, witness catalog
scripts/              — Validation and run-all scripts

## Quick Start

cd hwsec_artificial_benchmark
bash scripts/run_all_safe_checks.sh

## Difficulty Levels

- easy/   — Direct source-to-sink dataflow
- medium/ — Indirection through services/repositories
- hard/   — Multi-layer applications with false-positive traps

## Case Inventory

| Case ID    | Difficulty | Class               |
|------------|------------|---------------------|
| CASE-E01   | Easy       | OS Command Injection|
| CASE-E02   | Easy       | SQL Injection       |
| CASE-E03   | Easy       | Path Traversal      |
| CASE-M01   | Medium     | XSS                 |
| CASE-M02   | Medium     | SQL Injection       |
| CASE-M03   | Medium     | Command Injection   |
| CASE-H01   | Hard       | Path Traversal      |
| CASE-H02   | Hard       | LDAP Injection      |
| CASE-H03   | Hard       | XPath Injection     |

## Requirements

- Python 3.11+
- Linux (uses ping, touch, /tmp)
- See each case's requirements.txt
