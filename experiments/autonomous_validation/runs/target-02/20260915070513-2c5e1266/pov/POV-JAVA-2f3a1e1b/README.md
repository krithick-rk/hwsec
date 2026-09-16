# Proof of Vulnerability (PoV) Artifact: POV-JAVA-2f3a1e1b

**Vulnerability Class**: `CWE-78: IMPROPER NEUTRALIZATION OF SPECIAL ELEMENTS USED IN AN OS COMMAND ('OS COMMAND INJECTION')`  
**Domain**: `JAVA`  
**Status**: `GENERATED`  
**Created At**: `2026-09-15T07:05:52.989Z`  

---

## 1. Description
This artifact demonstrates an independently verifiable security flaw observed by the HWSEC framework.
It demonstrates the security consequence with the **minimum necessary effect** and contains **no weaponized, persistent, or destructive capabilities**.

## 2. Target Information
- **Target File**: `E:\Intern\hwsec\experiments\autonomous_validation\targets\java\target-02\DiagnosticController.java`
- **Entry Point**: `{"id":"EP-b4acecfa6494","status":"RESOLVED","type":"CLI_MAIN","framework":"JavaStandard","file":"DiagnosticController.java","target_identifier":"DiagnosticController.java#main","discovered_at":"2026-09-15T07:05:50.340Z","resolution_type":"DIRECT_FILE_MATCH"}`
- **Content SHA-256**: `e2ad1264fac8fbb4d400c728cde8dffb00799a14c8d3cc86d66bfad9bdc1ca5a`

## 3. Observed Security Effect
> Java target sink successfully triggered by structured witness input.

## 4. Reproduction Instructions
To independently verify this vulnerability on an authorized test system:
```bash
cd $(dirname "$0")
javac Reproduce.java && java Reproduce
```

## 5. Negative Control Verification
A paired benign control is provided in `input/witness.json`. Executing the negative control confirms that non-malicious input remains safe.

## 6. Provenance & Cryptographic Hashes
- **Bundle Manifest Hash**: `Computed on package`
- All contents are content-addressed and verifiable via `metadata.json`.
