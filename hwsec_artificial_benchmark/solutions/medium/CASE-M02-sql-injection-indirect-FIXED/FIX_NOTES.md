# Fix Notes — CASE-M02

## Root Cause
The UserRepository.search_users() method concatenated user input
(transformed by UserService) directly into an SQL LIKE query string.
The UserService added '%' wildcards but did not prevent SQL injection,
and the repository used string concatenation instead of parameterization.

## Exact Remediation
- Changed UserRepository.search_users() to use a parameterized query
  with the LIKE operator and a ? placeholder
- Removed the string concatenation in the repository
- The LIKE wildcards (%) are now part of the parameter value, not the
  SQL string, so they cannot alter query structure

## Why the Exploit No Longer Works
The UNION SELECT injection payload is treated as a literal search string.
No users match the literal string "' UNION SELECT ...", so zero results
are returned.

## Trade-offs
- The LIKE operator with parameterized input may perform differently
  if the input contains % characters, but this is standard behavior
