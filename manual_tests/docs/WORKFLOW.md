# HWSEC Console Manual Smoke Test & Workflow Guide

This document outlines the standard 10-step operator workflow for evaluating HWSEC targets.

## Step-by-Step Interactive Workflow

### Step A: Start Interactive Console
Launch the HWSEC Interactive Security Operations Console:
```bash
hwsec console
```

### Step B: Diagnostics & Toolchain Health Check
Inspect system execution backends and provider statuses:
```text
hwsec > doctor
hwsec > doctor execution
hwsec > providers
```

### Step C: Target & Analysis Configuration
Set target path and analysis parameters:
```text
hwsec > set target manual_tests/targets/software/python/vulnerable
hwsec > set mode STANDARD
hwsec > set pov ON-DETECTED
hwsec > set approval REQUIRED
```

### Step D: Select LLM Mode
Operate in Zero-Key mode:
```text
hwsec > set llm OFF
```
Or configure keys interactively:
```text
hwsec > providers configure
```

### Step E: Prepare & Inspect Plan
Generate analysis inventory and inspection plan:
```text
hwsec > run
hwsec > plan
hwsec > inspect plan
```

### Step F: Operator Approval
Approve plan before sandbox execution:
```text
hwsec > approve
```

### Step G: Execute Pipeline
Proceed with live execution:
```text
hwsec > proceed
```

### Step H: Inspect Findings & Evidence Artifacts
Review status, evidence DAG, analyst dossier, and report:
```text
hwsec > status
hwsec > inspect hypothesis
hwsec > inspect evidence
hwsec > dossier
hwsec > report
```

### Step I: Verify Verdict Against Ground Truth
Compare generated verdict with [`manual_tests/expected/interpretation/verdicts.json`](file:///e:/Intern/hwsec/manual_tests/expected/interpretation/verdicts.json).

### Step J: Reset or Exit
```text
hwsec > reset
hwsec > exit
```
