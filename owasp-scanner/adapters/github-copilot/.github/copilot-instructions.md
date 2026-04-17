<!-- OWASP-SCANNER-START -->
# OWASP Security Scanner

This project has the OWASP Security Scanner installed — 103 rules across 7 vulnerability domains, derived from the OWASP Cheat Sheet Series.

## Available Prompt Commands

Use these reusable prompts from the `.github/prompts/` directory:
- **owasp-scan-all** — Full security scan across all 7 domains
- **owasp-scan-injection** — SQL, OS command, LDAP, XXE, deserialization
- **owasp-scan-xss** — DOM XSS, framework escapes, CSP, prototype pollution
- **owasp-scan-config** — Headers, CORS, CSRF, cookies, TLS, Docker, K8s
- **owasp-scan-auth** — Password hashing, JWT, sessions, authorization, IDOR
- **owasp-scan-api** — SSRF, mass assignment, file upload, GraphQL, WebSocket
- **owasp-scan-supply-chain** — Secrets, weak crypto, dependencies, CI/CD
- **owasp-scan-ai-security** — Prompt injection, LLM output, agent permissions
- **owasp-quick-scan** — Fast triage: top 23 critical patterns
- **owasp-pr-review** — Security review of changed files only

## Custom Agent

Use `@owasp-security-scanner` to invoke the dedicated security scanner agent.

## Auto-Active Instructions

Path-specific security instructions in `.github/instructions/` automatically activate when editing relevant files (e.g., injection checks for `*.java`, XSS checks for `*.tsx`).

## Scanner Rules Location

Full rules are in `owasp-scanner/core/scanners/<domain>/rules.md`. Language-specific patterns are in `owasp-scanner/core/scanners/<domain>/patterns/`. Report format is in `owasp-scanner/core/reporting/format.md`. OWASP reference cheatsheets are in `owasp-scanner/core/reference/cheatsheets/`.
<!-- OWASP-SCANNER-END -->
