#!/usr/bin/env bash
# HWSEC Manual Smoke Test Script (Linux / WSL)

echo "=========================================================="
echo "         HWSEC Manual Smoke Test Walkthrough              "
echo "=========================================================="

BASE_DIR="$(pwd)"
VUN_TARGET="${BASE_DIR}/manual_tests/targets/software/python/vulnerable"
FIXED_TARGET="${BASE_DIR}/manual_tests/targets/software/python/fixed"
OUT_DIR="${BASE_DIR}/manual_tests/runs/smoke-run"

echo ""
echo "[*] 1. Running Zero-Key Deterministic Analysis on Vulnerable Target..."
node src/index.js analyze "${VUN_TARGET}" --output-dir "${OUT_DIR}"

if [ $? -eq 0 ]; then
    echo "[+] Vulnerable target analysis completed successfully."
else
    echo "[-] Smoke test failed on vulnerable target!"
    exit 1
fi

echo ""
echo "[*] 2. Running Analysis on Fixed Target..."
node src/index.js analyze "${FIXED_TARGET}" --output-dir "${OUT_DIR}"

if [ $? -eq 0 ]; then
    echo "[+] Fixed target analysis completed successfully."
else
    echo "[-] Smoke test failed on fixed target!"
    exit 1
fi

echo ""
echo "[=== SMOKE TEST SUITE PASSED SUCCESSFULLY ===]"
