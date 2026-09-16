# HWSEC Troubleshooting & Diagnostics Guide

This guide covers common operator setup issues, provider configuration troubleshooting, and toolchain resolution fallback behavior.

## 1. Missing Compiler or Execution Toolchain

### Symptoms
- `doctor execution` shows `unavailable` or `mock` for Python, GCC, Java, Verilog, or Yosys.

### Cause & Resolution
- HWSEC is designed to degrade gracefully. When an execution tool is absent from system `PATH`, HWSEC falls back to static AST analysis and mock sandbox verification.
- To enable native compilation & runtime verification:
  - **Python**: Install Python 3.10+ and add `python` / `python3` to system PATH.
  - **C/C++**: Install GCC / MinGW on Windows (`choco install mingw`) or `build-essential` on Linux (`sudo apt install build-essential`).
  - **Java**: Install OpenJDK 17+ (`sudo apt install openjdk-17-jdk`).
  - **Verilog / SystemVerilog**: Install Icarus Verilog (`iverilog`) or Verilator (`sudo apt install verilator iverilog`).

## 2. LLM Provider Failures & Rate Limits

### Symptoms
- Provider state shows `DEGRADED`, `CIRCUIT_OPEN`, or `UNAVAILABLE`.

### Resolution
1. Verify API key configuration using `providers status` or `providers test`.
2. Disable rate-limited provider explicitly:
   ```text
   hwsec > providers disable gemini-3
   ```
3. Rotate or update API key:
   ```text
   hwsec > providers rotate gemini-1
   ```
4. If all LLM providers are unavailable, switch to Zero-Key mode:
   ```text
   hwsec > set llm OFF
   ```
   Deterministic analysis, static heuristics, ProofSandbox, and EvidenceAuthority will continue operating normally.

## 3. Sandboxing & Permission Issues

### Symptoms
- `ProofSandbox` reports `Permission denied` or fails workspace creation.

### Resolution
1. Ensure the output directory (`hwsec-output/`) is writable by the current user process.
2. In Windows PowerShell, ensure execution policy permits script execution or run `powershell -ExecutionPolicy Bypass`.
3. If running inside Docker/WSL, verify mount permissions and ensure host paths use forward slashes or POSIX paths.

## 4. SQLite Session Lock / Database Errors

### Symptoms
- `SQLITE_BUSY` or `database is locked` error on console launch.

### Resolution
- Ensure no competing `hwsec console` instance is open on the same database file (`hwsec-output/hwsec.db`).
- Close duplicate console sessions or pass a distinct `--output <dir>` option.
