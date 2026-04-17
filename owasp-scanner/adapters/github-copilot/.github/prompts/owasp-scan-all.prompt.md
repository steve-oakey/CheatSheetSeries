---
description: "Run a comprehensive OWASP security scan across all 7 vulnerability domains"
---

# OWASP Full Security Scan

Run a comprehensive security scan against the current project using all 7 OWASP scanner domains.

## Step 1: Detect Project Stack

Identify the technology stack:
- **Java/Spring Boot**: `pom.xml`, `build.gradle`, `*.java`, `@SpringBootApplication`
- **Angular**: `angular.json`, `@angular/*` in `package.json`
- **Node.js**: `package.json` with Express, Fastify, NestJS
- **Python**: `requirements.txt`, `setup.py`, `manage.py` (Django/Flask/FastAPI)
- **Docker**: `Dockerfile`, `docker-compose.yml`
- **Kubernetes**: `k8s/`, `helm/`, deployment YAML files
- **CI/CD**: `.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`

## Step 2: Run All 7 Scanners

For each scanner, read the full rules and apply the language-specific patterns for the detected stack:

1. **Injection** — Read `owasp-scanner/core/scanners/injection/rules.md` and `patterns/` for the detected language. Scan for SQL injection, OS command injection, LDAP injection, XXE, deserialization, NoSQL injection.

2. **XSS** — Read `owasp-scanner/core/scanners/xss/rules.md` and `patterns/`. Scan for reflected/stored/DOM XSS, framework escape hatches, CSP issues, prototype pollution.

3. **Configuration** — Read `owasp-scanner/core/scanners/config/rules.md` and `patterns/`. Scan for missing headers, CORS, CSRF, cookies, TLS, Docker, Kubernetes misconfigurations.

4. **Authentication & Authorization** — Read `owasp-scanner/core/scanners/auth/rules.md` and `patterns/`. Scan for weak hashing, JWT issues, session management, authorization, IDOR.

5. **API Security** — Read `owasp-scanner/core/scanners/api/rules.md` and `patterns/`. Scan for SSRF, mass assignment, file upload, GraphQL, WebSocket issues.

6. **Supply Chain** — Read `owasp-scanner/core/scanners/supply-chain/rules.md` and `patterns/`. Scan for secrets, weak crypto, dependencies, CI/CD, key management.

7. **AI Security** — Read `owasp-scanner/core/scanners/ai-security/rules.md` and `patterns/`. Scan for prompt injection, output validation, agent security, LLM API key exposure.

## Step 3: Generate Report

Use the format defined in `owasp-scanner/core/reporting/format.md`. Present results as:

```
## Security Scan Results

**Project**: [name]
**Scanned**: [date]
**Technology Stack**: [detected stack]

| Severity | Count |
|----------|-------|
| CRITICAL | N     |
| HIGH     | N     |
| MEDIUM   | N     |
| LOW      | N     |
| **Total** | **N** |
```

Then list all findings sorted by severity (CRITICAL first), using the standard finding format:
- Rule ID, Severity, CWE
- File:line
- Vulnerable code snippet
- Recommended fix
- OWASP reference

End with a **Remediation Priority** section: CRITICAL with easiest fixes first, then CRITICAL requiring code changes, then HIGH findings.
