# OWASP Security Scanner Instructions

When asked to perform a security scan, review code for vulnerabilities, or check security, follow the OWASP scanner rules.

## Scanner Rules Location

The scanning rules are in `owasp-scanner/core/scanners/`. Each domain has:
- `rules.md` -- structured vulnerability patterns with rule IDs, CWEs, and fixes
- `patterns/` -- language-specific detection patterns (java-spring.md, python.md, nodejs-express.md, angular.md, generic.md)
- `prompt.md` -- detailed scanning instructions

## Available Scan Domains

| Domain | Rules File | Focus |
|--------|-----------|-------|
| injection | `core/scanners/injection/rules.md` | SQL, OS command, LDAP, XXE, deserialization |
| xss | `core/scanners/xss/rules.md` | XSS, DOM XSS, CSP, prototype pollution |
| config | `core/scanners/config/rules.md` | HTTP headers, CORS, CSRF, Docker, K8s |
| auth | `core/scanners/auth/rules.md` | Authentication, JWT, sessions, authorization |
| api | `core/scanners/api/rules.md` | SSRF, mass assignment, file upload, GraphQL |
| supply-chain | `core/scanners/supply-chain/rules.md` | Secrets, crypto, dependencies, CI/CD |
| ai-security | `core/scanners/ai-security/rules.md` | Prompt injection, LLM output validation, agent security |

## How to Scan

1. Detect the project's technology stack (Java/Spring, Python/Django/Flask/FastAPI, Node.js/Express, Angular, etc.)
2. Read the relevant `rules.md` files for the requested scan domains
3. Load the appropriate `patterns/*.md` file for the detected language
4. Search the code for dangerous patterns listed in the rules
5. Report findings with: Rule ID, severity, CWE, file:line, code snippet, fix

## Finding Format

```
**RULE-INJ-001** (CRITICAL, CWE-89): SQL Injection
File: src/UserDAO.java:42
Code: `String query = "SELECT * FROM users WHERE id = " + id;`
Fix: Use PreparedStatement with ? placeholders
```

## Severity Levels
- **CRITICAL**: RCE, SQLi, auth bypass, hardcoded credentials
- **HIGH**: XSS, SSRF, XXE, broken access control
- **MEDIUM**: Missing headers, CSRF disabled, weak config
- **LOW**: Best practice improvements

## Reference Cheatsheets

Full OWASP cheatsheets are in `owasp-scanner/core/reference/cheatsheets/` for deeper remediation guidance.
