# Expected Findings

## Summary Table

| Case ID  | Difficulty | CWE    | Vulnerability        | Entry Point                          | Expected HWSEC Result |
|----------|------------|--------|----------------------|--------------------------------------|-----------------------|
| CASE-E01 | Easy       | CWE-78 | Command Injection    | POST /api/diagnostic/ping            | DETECTED              |
| CASE-E02 | Easy       | CWE-89 | SQL Injection        | GET /api/users/search                | DETECTED              |
| CASE-E03 | Easy       | CWE-22 | Path Traversal       | GET /api/files/download              | DETECTED              |
| CASE-M01 | Medium     | CWE-79 | XSS (Reflected)      | GET /search                          | DETECTED              |
| CASE-M02 | Medium     | CWE-89 | SQL Injection        | GET /api/users/search (indirect)    | DETECTED              |
| CASE-M03 | Medium     | CWE-78 | Command Injection   | POST /api/diagnostic/run (ping)     | DETECTED              |
| CASE-H01 | Hard       | CWE-22 | Path Traversal       | GET /api/files/download (layered)    | DETECTED              |
| CASE-H02 | Hard       | CWE-90 | LDAP Injection       | POST /api/auth/login                 | DETECTED              |
| CASE-H03 | Hard       | CWE-643| XPath Injection      | GET /api/user/search                 | DETECTED              |

## Fixed Solutions

| Fixed Case      | Expected HWSEC Result |
|-----------------|-----------------------|
| E01-FIXED       | NOT_DETECTED          |
| E02-FIXED       | NOT_DETECTED          |
| E03-FIXED       | NOT_DETECTED          |
| M01-FIXED       | NOT_DETECTED          |
| M02-FIXED       | NOT_DETECTED          |
| M03-FIXED       | NOT_DETECTED          |
| H01-FIXED       | NOT_DETECTED          |
| H02-FIXED       | NOT_DETECTED          |
| H03-FIXED       | NOT_DETECTED          |
