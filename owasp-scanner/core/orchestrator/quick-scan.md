# Quick Security Scan

A fast triage scan focusing on the most critical and common vulnerabilities. Designed to run in under 5 minutes by checking only the highest-impact patterns.

## Top 20 Critical Patterns to Check

### CRITICAL (check these first)
1. **SQL Injection**: String concatenation in SQL queries (RULE-INJ-001, RULE-INJ-002)
2. **OS Command Injection**: `Runtime.exec()`, `ProcessBuilder` with user input (RULE-INJ-004)
3. **Hardcoded Credentials**: Passwords, API keys, tokens in source code (RULE-SC-001, RULE-AUTH-002)
4. **Unsafe Deserialization**: `ObjectInputStream.readObject()`, `XMLDecoder` (RULE-INJ-008, RULE-INJ-007)
5. **XXE**: XML parsers without DTD disabled (RULE-INJ-006)
6. **JWT None Algorithm**: `Algorithm.none()` (RULE-AUTH-003)
7. **Hardcoded Keys**: Encryption keys in source (RULE-SC-009)

### HIGH (check next)
8. **XSS via innerHTML**: `innerHTML = userInput`, `dangerouslySetInnerHTML` (RULE-XSS-001, RULE-XSS-004)
9. **Angular Security Bypass**: `bypassSecurityTrust*` (RULE-XSS-005)
10. **SSRF**: User URLs passed to HTTP clients (RULE-API-001)
11. **Weak Password Hashing**: MD5, SHA1 for passwords (RULE-AUTH-001)
12. **Missing Authorization**: Endpoints without auth checks (RULE-AUTH-007)
13. **Private Keys Committed**: RSA/SSH keys in repo (RULE-SC-001)
14. **Weak Crypto**: DES, 3DES, RC4, ECB mode (RULE-SC-003, RULE-SC-004)

### MEDIUM (check if time permits)
15. **CSRF Disabled**: `csrf().disable()` (RULE-CFG-004)
16. **CORS Wildcard**: `Access-Control-Allow-Origin: *` (RULE-CFG-003)
17. **Missing Security Headers**: No CSP, no HSTS (RULE-CFG-001)
18. **Docker Root**: No USER directive (RULE-CFG-009)
19. **Mass Assignment**: Entity as @RequestBody (RULE-API-002)
20. **Token in localStorage**: `localStorage.setItem("token")` (RULE-AUTH-005)
21. **Prompt Injection**: User input concatenated into LLM prompts (RULE-AIS-001)
22. **LLM API Keys Exposed**: OpenAI/Anthropic keys in source code (RULE-AIS-006)
23. **LLM Output in eval()**: AI response passed to code execution (RULE-AIS-003)

## Instructions

1. Search for the patterns above across the entire project
2. Report any matches using `core/reporting/format.md`
3. For CRITICAL and HIGH findings, include a non-destructive proof of concept (curl, grep, or short script) adapted from the PoC templates in the rule definitions
4. Include a summary count by severity
5. Recommend running a full scan (`full-scan.md`) for comprehensive coverage
