# HWSEC CLI Reference

HWSEC is invoked as `node src/index.js <command> [options]`.

If installed globally (`npm install -g .`), use `hwsec <command>`.

---

## Global Options

| Option | Description |
|---|---|
| `--version` | Print version number |
| `--help` | Show help for a command |

---

## `hwsec analyze <directory>`

Scan a target repository, detect languages, select analyzers, and generate an analysis plan. **Execution is strictly blocked — no tools are run until `hwsec proceed` is called.**

```bash
node src/index.js analyze ./my-project
node src/index.js analyze ./my-project --proof deep --novelty standard
```

| Option | Default | Description |
|---|---|---|
| `-c, --config <path>` | `config.json` | Path to configuration file |
| `-s, --spec <path>` | — | Path to specification file (SVA / security spec) |
| `-n, --novelty <mode>` | `standard` | Novelty exploration mode: `off`, `minimal`, `standard`, `deep` |
| `-p, --proof <mode>` | `standard` | Proof-of-impact mode: `off`, `minimal`, `standard`, `deep` |
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

**Output**: Analysis ID, file counts, detected tools, planned pipeline, path to `plan.md`.

---

## `hwsec proceed <analysis-id>`

Validate human approval, execute all planned tools, run the evidence pipeline, and produce the final report.

```bash
node src/index.js proceed ANALYSIS-20260911-a1b2c3
node src/index.js proceed ANALYSIS-20260911-a1b2c3 --mode deep
```

| Option | Default | Description |
|---|---|---|
| `-c, --config <path>` | `config.json` | Path to configuration file |
| `-m, --mode <mode>` | `standard` | Operational mode: `fast`, `standard`, `deep`, `forensic` |
| `-p, --proof <mode>` | — | Override proof mode from analyze phase |
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |
| `--legacy-verifier` | `false` | Run legacy layered verifier in parallel for comparison |

**Output**: DETECTED / NOT_DETECTED / INCONCLUSIVE verdict summary, final report at `hwsec-output/<id>/report/final.md`.

---

## `hwsec status <analysis-id>`

Display live status and metadata for an analysis run.

```bash
node src/index.js status ANALYSIS-20260911-a1b2c3
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec findings <analysis-id>`

Display structured VERIFIED and CANDIDATE findings from a completed analysis.

```bash
node src/index.js findings ANALYSIS-20260911-a1b2c3
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec verify <finding-id>`

Inspect verification evidence and the analyst dossier for a specific finding ID.

```bash
node src/index.js verify FINDING-abc123def456
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec dossier <analysis-id> [case-id]`

Display the 10-question Analyst Dossier for all or a specific operational case.

```bash
# All dossiers in an analysis run
node src/index.js dossier ANALYSIS-20260911-a1b2c3

# Specific case
node src/index.js dossier ANALYSIS-20260911-a1b2c3 HYP-001
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec report <analysis-id>`

Print the final human-readable security report to stdout.

```bash
node src/index.js report ANALYSIS-20260911-a1b2c3
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec proof <id>`

Run or inspect controlled proof-of-impact validation. Accepts either an analysis ID (runs all candidate findings) or a specific finding ID.

```bash
# Validate all candidates in a run
node src/index.js proof ANALYSIS-20260911-a1b2c3 --mode standard

# Validate a specific finding
node src/index.js proof FINDING-abc123def456
```

| Option | Default | Description |
|---|---|---|
| `-c, --config <path>` | `config.json` | Path to configuration file |
| `-m, --mode <mode>` | `standard` | Proof mode: `minimal`, `standard`, `deep` |
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec proof-status <proof-id>`

Display cryptographic provenance, artifact hashes, and sandbox details for a proof record.

```bash
node src/index.js proof-status PROOF-abc123
```

| Option | Default | Description |
|---|---|---|
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec reset <analysis-id>`

Reset an analysis run back to `PLANNED` state, or permanently delete its workspace.

```bash
# Reset to PLANNED (re-run proceed without re-running analyze)
node src/index.js reset ANALYSIS-20260911-a1b2c3

# Permanently delete all files
node src/index.js reset ANALYSIS-20260911-a1b2c3 --delete-files
```

| Option | Default | Description |
|---|---|---|
| `--delete-files` | `false` | Delete workspace directory (irreversible) |
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec refine <analysis-id>`

Generate fuzzer dictionary from refuted hypotheses (for AFL++ input corpus generation).

```bash
node src/index.js refine ANALYSIS-20260911-a1b2c3
```

| Option | Default | Description |
|---|---|---|
| `-c, --config <path>` | `config.json` | Path to configuration file |
| `-o, --output-dir <path>` | `hwsec-output` | Base output directory |

---

## `hwsec benchmark` — BEP Subsystem

The `benchmark` command group manages the Reproducible Benchmark Evidence Package (BEP) subsystem for evaluating framework accuracy on ground-truth datasets.

### `hwsec benchmark run`

Run a benchmark and emit a cryptographically-signed evidence package.

```bash
node src/index.js benchmark run --benchmark owasp-benchmark --config full
```

| Option | Default | Description |
|---|---|---|
| `-b, --benchmark <id>` | — | Benchmark dataset ID |
| `-c, --config <mode>` | `full` | Run mode: `full`, `pilot` |
| `-e, --evidence-out <path>` | `quality-benchmark/evidence/runs` | Evidence output base directory |
| `-r, --resume <path>` | — | Resume from existing evidence bundle |
| `-m, --max-cases <n>` | — | Limit cases for pilot runs |

### `hwsec benchmark verify-evidence <run-id>`

Verify SHA-256 integrity of all artifacts in an evidence bundle.

```bash
node src/index.js benchmark verify-evidence BEP-20260911-abc123
```

### `hwsec benchmark replay <run-id>`

Recompute all metrics from immutable case records and verify they match stored aggregates. Cryptographic replay guard.

```bash
node src/index.js benchmark replay BEP-20260911-abc123
```

### `hwsec benchmark audit-transitions <run-id>`

Audit classification state transitions (PROPOSED → CANDIDATE → DETECTED/NOT_DETECTED).

### `hwsec benchmark diff <run_a> <run_b>`

Compute ablation diff between two benchmark runs (FP→TN and FN→TP changes).

### `hwsec benchmark audit-fp-reduction <run-id>`

Audit FP reduction claims — classifies each FP→TN transition as PROOF_CONFIRMED, HYBRID_CONFIRMED, or LLM_ONLY.

### `hwsec benchmark case <run-id> <case-id>`

Generate an analyst dossier for a specific benchmark test case.

### `hwsec benchmark summarize <run-id>`

Display aggregate metrics (TP, FP, TN, FN, Precision, Recall, F1) from a completed run.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Fatal error (config missing, tool crash, integrity failure) |
