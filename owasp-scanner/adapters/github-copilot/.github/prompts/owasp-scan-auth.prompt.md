---
description: "Scan for authentication and authorization issues: password hashing, JWT, sessions, IDOR"
---

# OWASP Authentication & Authorization Scan

Scan the current project for authentication, authorization, and session management vulnerabilities.

## Instructions

1. **Detect stack**: Identify the auth framework (Spring Security, Passport.js, Django Auth, etc.)
2. **Load rules**: Read `owasp-scanner/core/scanners/auth/rules.md` for the full 16-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/auth/patterns/`:
   - `java-spring.md` for Spring Security
   - `nodejs-express.md` for Passport.js, express-session
   - `python.md` for Django Auth, Flask-Login
   - `generic.md` for other frameworks
4. **Scan**: Check all authentication, authorization, and session management code
5. **Report**: Use the format in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-AUTH-001: Weak password hashing (MD5, SHA-1, low-iteration PBKDF2)
- RULE-AUTH-002: Hardcoded credentials
- RULE-AUTH-003/004: JWT algorithm none, missing JWT claim validation
- RULE-AUTH-005: Session tokens in localStorage
- RULE-AUTH-006: Session fixation
- RULE-AUTH-007: Missing authorization checks
- RULE-AUTH-008: IDOR (Insecure Direct Object Reference)
- RULE-AUTH-009: User enumeration via error messages
- RULE-AUTH-010 through AUTH-016: Session config, rate limiting, MFA bypass, privilege escalation

Present findings sorted by severity with code snippets and fixes.
For CRITICAL and HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules.
