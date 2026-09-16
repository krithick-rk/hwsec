# HWSEC Manual Testing Workspace

This directory contains repository-tracked, human-interpretable, safe test targets and execution scripts for evaluating the HWSEC Security Operations Console (`hwsec console`).

## Scope & Purpose

> [!NOTE]
> The test cases in this directory are designed for **mechanics and workflow validation**, reproducible human walkthroughs, and provider configuration testing. They prove that the analysis pipeline, execution capabilities (compilers, simulators, verifiers), ProofSandbox, EvidenceAuthority, and PoV synthesis function correctly. They do **not** serve as a benchmark for general vulnerability detection statistics.

## Directory Structure

- `targets/`: Sample source code targets organized by technology stack:
  - `software/python/`: Command injection (vulnerable & fixed)
  - `software/c_cpp/`: Buffer overflow (vulnerable & fixed)
  - `software/java/`: Path traversal (vulnerable & fixed)
  - `hardware/verilog/`: RTL bus secret leakage (vulnerable & fixed)
  - `hardware/systemverilog/`: SystemVerilog interface isolation
- `cases/`: Categorized test case links (vulnerable, fixed, safe, ambiguous)
- `expected/`: Ground truth expected verdicts and human interpretation guides
- `scripts/`: Shell and PowerShell scripts for smoke testing (`run_smoke.ps1`, `run_smoke.sh`)
- `docs/`: Step-by-step workflow guide (`WORKFLOW.md`) and troubleshooting (`TROUBLESHOOTING.md`)

## Quick Execution

### Windows (PowerShell)
```powershell
.\manual_tests\scripts\setup.ps1
.\manual_tests\scripts\run_smoke.ps1
```

### Linux / WSL (Bash)
```bash
./manual_tests/scripts/setup.sh
./manual_tests/scripts/run_smoke.sh
```
