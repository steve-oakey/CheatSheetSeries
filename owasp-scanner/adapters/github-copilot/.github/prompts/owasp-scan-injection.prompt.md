---
description: "Scan for injection vulnerabilities: SQL, OS command, LDAP, XXE, deserialization, NoSQL"
---

# OWASP Injection Scan

Scan the current project for injection vulnerabilities.

## Instructions

1. **Detect stack**: Identify the project language and framework
2. **Load rules**: Read `owasp-scanner/core/scanners/injection/rules.md` for the full 15-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/injection/patterns/`:
   - `java-spring.md` for Java/Spring Boot
   - `python.md` for Django/Flask/FastAPI
   - `nodejs-express.md` for Node.js/Express
   - `angular.md` for Angular
   - `generic.md` for other languages
4. **Scan**: Search all source files for the dangerous patterns listed in the rules
5. **Report**: Use the format in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-INJ-001 through INJ-003: SQL Injection (string concatenation, non-parameterized statements, ORM injection)
- RULE-INJ-004: OS Command Injection
- RULE-INJ-005: LDAP Injection
- RULE-INJ-006/007: XXE and XMLDecoder
- RULE-INJ-008/009/010: Unsafe Deserialization (Java, Python, Jackson)
- RULE-INJ-011: Server-Side Template Injection (SSTI)
- RULE-INJ-012: NoSQL Injection
- RULE-INJ-013: XPath Injection
- RULE-INJ-014: Header Injection / HTTP Response Splitting
- RULE-INJ-015: Log Injection

Present findings sorted by severity with code snippets and fixes.
For CRITICAL and HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules.
