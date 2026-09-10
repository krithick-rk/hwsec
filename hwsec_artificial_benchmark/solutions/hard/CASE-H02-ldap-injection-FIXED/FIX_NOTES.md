# Fix Notes — CASE-H02

## Root Cause
The AuthService.authenticate() method built an LDAP filter by
concatenating user input directly into the filter string:
  (&(cn={username})(userPassword={password}))
This allowed LDAP injection to bypass the password check.

## Exact Remediation
- Separated authentication into two steps:
  1. Search for user by cn (with input validation)
  2. Verify password programmatically against the found entry
- Added LDAPService.build_filter() that validates input against
  a safe character set (alphanumerics, dots, hyphens, underscores, @)
- If input contains special characters, the filter is not built
  and authentication fails

## Why the Exploit No Longer Works
The input "admin)(|(userPassword=*" contains parentheses and
asterisks, which fail the SAFE_CHARS regex. The filter is not
built, search returns empty, and authentication fails with 401.

## Trade-offs
- Usernames with special characters (e.g., spaces) are rejected
  (acceptable for cn-based lookups)
- Password verification is now application-side rather than
  filter-side, which is actually more secure
