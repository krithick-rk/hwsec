# Fix Notes — CASE-M03

## Root Cause
The _run_ping() method used shell=True with a string-interpolated
command, while _run_traceroute() and _run_dns_lookup() used argument
lists. The vulnerability was conditional on selecting the 'ping' tool.

## Exact Remediation
- Changed _run_ping() to use subprocess.run with an argument list
  (shell=False), matching the pattern already used by traceroute
- Added input validation (regex + length check) at the service level
  for all tools, rejecting input with shell metacharacters

## Why the Exploit No Longer Works
The input "127.0.0.1; touch /tmp/marker" fails the regex validation
(semicolon not allowed), so the diagnostic is never executed. Even if
validation were bypassed, the argument list form prevents shell
interpretation.

## Trade-offs
- Hostnames with underscores are rejected (rare but valid)
