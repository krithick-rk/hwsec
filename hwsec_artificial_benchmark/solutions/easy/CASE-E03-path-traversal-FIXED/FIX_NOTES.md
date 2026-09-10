# Fix Notes — CASE-E03

## Root Cause
User-controlled filename was joined with the base directory path using
os.path.join without verifying the resolved path stays within the base
directory, allowing path traversal via ../ sequences.

## Exact Remediation
- Added safe_resolve_path() that uses os.path.realpath to resolve
  the full path and then verifies it starts with the base directory
- If the resolved path escapes the base directory, the request is
  rejected with 403 Forbidden
- Uses os.path.realpath to handle symlinks and ../ sequences

## Why the Exploit No Longer Works
The input "../../../../etc/hostname" resolves to a path outside the
FILES_DIR, which is detected by the prefix check, resulting in a 403.

## Trade-offs
- realpath resolves symlinks, which could reject legitimate symlinks
  inside the files directory (acceptable for a file download service)
