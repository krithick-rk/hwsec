# Fix Notes — CASE-E02

## Root Cause
User input was concatenated directly into an SQL query string,
allowing SQL injection via crafted username parameters.

## Exact Remediation
- Replaced string concatenation with parameterized query using
  placeholder (?) syntax
- The database engine now treats the input as a literal value,
  not as SQL syntax

## Why the Exploit No Longer Works
The input "' OR '1'='1" is treated as a literal string value
for the username column comparison. No rows match this literal
username, so zero results are returned.

## Trade-offs
None. Parameterized queries are the standard fix and preserve
all normal functionality.
