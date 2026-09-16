# Proof of Vulnerability (PoV) Artifact: POV-PYTHON-d00eda9f

**Vulnerability Class**: `CWE-78`  
**Domain**: `PYTHON`  
**Status**: `GENERATED`  
**Created At**: `2026-09-15T06:19:59.578Z`  

---

## 1. Description
This artifact demonstrates an independently verifiable security flaw observed by the HWSEC framework.
It demonstrates the security consequence with the **minimum necessary effect** and contains **no weaponized, persistent, or destructive capabilities**.

## 2. Target Information
- **Target File**: `E:\Intern\hwsec\tests\fixtures\multilang_project\server.py`
- **Entry Point**: `{"status":"UNRESOLVED","reason":"Entry point not yet resolved by inventory"}`
- **Content SHA-256**: `1b6c93d6e5063f613979547996a9696d330eabd2a37e335e8c94f63d534595e0`

## 3. Observed Security Effect
> Execution with payload "; touch hwsec_marker.tmp" reproduces unvalidated command/data execution.

## 4. Reproduction Instructions
To independently verify this vulnerability on an authorized test system:
```bash
cd $(dirname "$0")
python3 reproduce.py
```

## 5. Negative Control Verification
A paired benign control is provided in `input/witness.json`. Executing the negative control confirms that non-malicious input remains safe.

## 6. Provenance & Cryptographic Hashes
- **Bundle Manifest Hash**: `Computed on package`
- All contents are content-addressed and verifiable via `metadata.json`.
