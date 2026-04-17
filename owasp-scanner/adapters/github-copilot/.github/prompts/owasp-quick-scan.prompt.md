---
description: "Fast triage scan: top 23 most critical vulnerability patterns in under 5 minutes"
---

# OWASP Quick Security Scan

A fast triage scan focusing on the most critical and common vulnerabilities. Check the top 23 highest-impact patterns.

## CRITICAL (check these first)

1. **SQL Injection**: String concatenation in SQL queries — `"SELECT ... " + variable`, template literals with SQL
2. **OS Command Injection**: `Runtime.exec()`, `child_process.exec()`, `os.system()` with user input
3. **Hardcoded Credentials**: `password = "..."`, `api_key = "..."`, `secret = "..."` in source code
4. **Unsafe Deserialization**: `ObjectInputStream.readObject()`, `XMLDecoder`, `pickle.load()` on untrusted data
5. **XXE**: XML parsers without DTD disabled — `DocumentBuilderFactory.newInstance()` without security features
6. **JWT None Algorithm**: `Algorithm.none()`, `"alg": "none"` in token handling
7. **Hardcoded Encryption Keys**: Private keys or symmetric keys embedded in source code

## HIGH (check next)

8. **XSS via innerHTML**: `innerHTML = userInput`, `dangerouslySetInnerHTML` without sanitization
9. **Angular Security Bypass**: `bypassSecurityTrustHtml()`, `bypassSecurityTrustScript()`
10. **SSRF**: User-controlled URLs passed to server-side HTTP clients
11. **Weak Password Hashing**: MD5, SHA-1, low-iteration PBKDF2 for passwords
12. **Missing Authorization**: Endpoints without auth annotations or middleware
13. **Private Keys Committed**: `-----BEGIN RSA PRIVATE KEY-----` in repository
14. **Weak Crypto**: DES, 3DES, RC4, ECB mode usage

## MEDIUM (check if time permits)

15. **CSRF Disabled**: `csrf().disable()`, CSRF middleware removed
16. **CORS Wildcard**: `Access-Control-Allow-Origin: *` with credentials
17. **Missing Security Headers**: No CSP, no HSTS configured
18. **Docker Root**: Dockerfile without `USER` directive
19. **Mass Assignment**: Entity as `@RequestBody` without DTO
20. **Token in localStorage**: `localStorage.setItem("token", ...)`
21. **Prompt Injection**: User input concatenated into LLM prompts
22. **LLM API Keys Exposed**: OpenAI/Anthropic keys in source code
23. **LLM Output in eval()**: AI response passed to code execution

## Instructions

1. Search for the patterns above across the entire project
2. Report any matches using the format in `owasp-scanner/core/reporting/format.md`
3. For CRITICAL and HIGH findings, include a non-destructive proof of concept (curl, grep, or short script) adapted from the PoC templates in the rule definitions
4. Include a summary count by severity
5. Recommend running the full scan prompt (`owasp-scan-all`) for comprehensive coverage
