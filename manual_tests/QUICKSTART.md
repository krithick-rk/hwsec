# HWSEC Manual Test Quickstart Guide

This quickstart guides you through launching `hwsec console`, configuring target parameters, running deterministic & LLM-assisted analysis, and inspecting evidence artifacts.

## Prerequisites Check

Ensure Node.js (v18+) is installed:
```bash
node -v
npm -v
```

Optional execution toolchain dependencies (will degrade gracefully if absent):
- Python 3.10+
- GCC / G++ or Clang
- Java OpenJDK 17+
- Icarus Verilog (`iverilog`) or Verilator
- Yosys / SymbiYosys (for formal HDL verification)

## Step-by-Step Operator Walkthrough

### 1. Launch Interactive Console
```bash
hwsec console
```
Observe the key-style HWSEC ASCII banner and real readiness summary (`HWSEC engine READY`, `EvidenceAuthority READY`, `Execution Broker READY`, `Provider Pool READY`, `Workspace Manager READY`).

### 2. Guided Navigation
```text
hwsec > menu
```
Navigate session setup (1. Target / scope, 2. Context, 3. Mode, etc.) or choose 9 to start with defaults.

### 3. Tool Health & Diagnostics
Inside the console prompt (`hwsec >`):
```text
hwsec > tools
hwsec > doctor yosys
hwsec > doctor execution
hwsec > providers
```

### 4. Configure Session Options
```text
hwsec > set target manual_tests/targets/software/python/vulnerable
hwsec > set mode STANDARD
hwsec > set llm OFF
hwsec > set pov ON-DETECTED
hwsec > set approval REQUIRED
hwsec > show options
```

### 5. Generate and Approve Plan
```text
hwsec > run
hwsec > plan
hwsec > inspect plan
hwsec > approve
```

### 6. Execute Analysis Pipeline
```text
hwsec > proceed
```

### 7. Inspect Analysis Results
```text
hwsec > status
hwsec > inspect hypothesis
hwsec > inspect evidence
hwsec > dossier
hwsec > report
```

### 8. Repeat for Fixed Target
```text
hwsec > set target manual_tests/targets/software/python/fixed
hwsec > run
hwsec > approve
hwsec > proceed
hwsec > status
```
