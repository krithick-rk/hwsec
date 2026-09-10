# Fix Notes — CASE-H01

## Root Cause
The StorageAdapter.read() method called PathUtils.join_path() which
used os.path.join() without validating the resolved path. The read_preview()
method used the safe variant join_path_safe(), but read() did not. This
inconsistency allowed path traversal through the download endpoint.

## Exact Remediation
- Changed StorageAdapter.read() to use join_path_safe() instead of
  join_path(), matching the validation already present in read_preview()
- Both read and preview paths now use realpath-based validation
- join_path() still exists for non-security-critical uses

## Why the Exploit No Longer Works
The input "../../../../etc/hostname" resolves to a path outside the
base directory, which is detected by join_path_safe()'s prefix check,
resulting in a 403 Forbidden response.

## Trade-offs
- realpath resolves symlinks, which could reject legitimate symlinks
  inside the storage directory (acceptable for security)
