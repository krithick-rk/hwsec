# Fix Notes — CASE-E01

## Root Cause
User-controlled input was interpolated into a shell command string passed
to subprocess.run with shell=True, allowing shell metacharacter injection.

## Exact Remediation
- Replaced shell=True with an argument list (shell=False)
- Added input validation: host must match ^[a-zA-Z0-9.\-]+$ and be <= 255 chars
- The argument list form prevents shell interpretation of metacharacters

## Why the Exploit No Longer Works
The input "127.0.0.1; touch /tmp/marker" fails validation (semicolon not
in allowed character set) and even if it passed, the argument list form
passes it as a single literal argument to ping, not to the shell.

## Trade-offs
- Hostnames with underscores are rejected (rare but valid)
- IPv6 addresses not supported by the current regex (could be extended)
