#!/usr/bin/env bash
# HWSEC Manual Test Environment Setup Script (Linux / WSL)

echo "=========================================================="
echo "       HWSEC Manual Test Environment Setup Check           "
echo "=========================================================="

if command -v node >/dev/null 2>&1; then
    echo "[+] Node.js detected: $(node -v)"
else
    echo "[-] Node.js NOT found! Please install Node.js v18+"
    exit 1
fi

echo ""
echo "Optional Execution Toolchain Capabilities:"

check_tool() {
    local name="$1"
    local cmd="$2"
    if command -v "$cmd" >/dev/null 2>&1; then
        echo "  * [AVAILABLE]   $name"
    else
        echo "  * [UNAVAILABLE] $name (Not in PATH - fallback to mock/static)"
    fi
}

check_tool "Python 3" "python3"
check_tool "GCC Compiler" "gcc"
check_tool "Java Runtime" "java"
check_tool "Icarus Verilog" "iverilog"
check_tool "Yosys" "yosys"
check_tool "SymbiYosys" "sby"

echo ""
echo "[+] Setup check complete. You can run './manual_tests/scripts/run_smoke.sh' or 'hwsec console'."
