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

Generate the final report by following **both** format specifications exactly:

1. **Report structure**: Read `owasp-scanner/core/reporting/report-template.md` and reproduce its structure verbatim. Only replace the `{{...}}` placeholders with actual values.
2. **Individual findings**: Format every finding exactly as specified in `owasp-scanner/core/reporting/format.md`. Copy the finding template verbatim — only replace `{{...}}` placeholders. Follow the Format Rules and DO/DO NOT lists in that file.
3. **PoC**: Include the Proof of Concept section only for CRITICAL and HIGH findings. Omit it entirely for MEDIUM, LOW, and INFO.

Do not paraphrase, reorder, or add extra sections beyond what the templates specify.
