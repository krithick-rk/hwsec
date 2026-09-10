# Fix Notes — CASE-H03

## Root Cause
The QueryBuilder built XPath query strings by interpolating user input:
  //user[name='{username}']
The UserService passed user input through QueryBuilder to XMLRepository,
which executed the raw XPath. This allowed XPath injection via quotes
and boolean operators.

## Exact Remediation
- Replaced string-interpolated XPath queries with direct element
  comparison using lxml's find/findall API
- XMLRepository.find_by_field() iterates user elements and compares
  the field text directly, avoiding XPath injection
- find_by_id() uses int() conversion before building the XPath,
  ensuring only numeric values reach the query
- QueryBuilder is deprecated but kept for API compatibility

## Why the Exploit No Longer Works
The input "' or '1'='1" is compared literally against each <name>
element's text content. No user has that literal name, so no match
is found and the response returns found: false.

## Trade-offs
- Slightly slower for large XML files (iterative scan vs XPath engine)
  but acceptable for the dataset size in this application
