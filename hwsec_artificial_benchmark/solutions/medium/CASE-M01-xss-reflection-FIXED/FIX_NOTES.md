# Fix Notes — CASE-M01

## Root Cause
The template used the Jinja2 `| safe` filter to render user input
without escaping, combined with an incomplete sanitizer that only
stripped <script> tags but not other HTML event handlers.

## Exact Remediation
- Removed the `| safe` filter from the template, allowing Jinja2's
  default auto-escaping to handle all user input
- Removed the incomplete _sanitize() method from SearchService since
  Jinja2 auto-escaping provides complete protection
- The query is now rendered as escaped text, not raw HTML

## Why the Exploit No Longer Works
The payload `<img src=x onerror=alert(1)>` is rendered as escaped
HTML entities: `&lt;img src=x onerror=alert(1)&gt;`, which the browser
displays as text rather than executing as HTML.

## Trade-offs
- Users can no longer legitimately include HTML in search queries
  (acceptable for a search interface)
