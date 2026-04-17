# Full Security Scan Orchestrator

Run a comprehensive OWASP security scan against the target project using all 7 scanner domains.

## Workflow

### Step 1: Detect Project Stack

Identify the technology stack of the target project:
- **Java/Spring Boot**: Look for `pom.xml`, `build.gradle`, `*.java` files, `@SpringBootApplication`
- **Angular**: Look for `angular.json`, `@angular/*` in `package.json`
- **Node.js**: Look for `package.json` with server-side frameworks (Express, Fastify, NestJS)
- **Python**: Look for `requirements.txt`, `setup.py`, `manage.py`
- **Docker**: Look for `Dockerfile`, `docker-compose.yml`
- **Kubernetes**: Look for `k8s/`, `helm/`, deployment YAML files
- **CI/CD**: Look for `.github/workflows/`, `Jenkinsfile`, `.gitlab-ci.yml`

### Step 2: Dispatch Scanners

Run all 6 scanners, each following its `prompt.md` instructions:

1. **Injection Scanner** (`core/scanners/injection/prompt.md`)
   - Always runs. Covers SQL, OS command, LDAP, XXE, deserialization, NoSQL injection.

2. **XSS Scanner** (`core/scanners/xss/prompt.md`)
   - Runs for web projects. Covers reflected/stored/DOM XSS, framework escape hatches, CSP, prototype pollution.

3. **Configuration Scanner** (`core/scanners/config/prompt.md`)
   - Always runs. Covers HTTP headers, CORS, CSRF, cookies, TLS, Docker, Kubernetes.

4. **Auth Scanner** (`core/scanners/auth/prompt.md`)
   - Runs if auth-related code is detected. Covers password hashing, JWT, sessions, authorization, IDOR.

5. **API Scanner** (`core/scanners/api/prompt.md`)
   - Runs if API endpoints are detected. Covers SSRF, mass assignment, file upload, GraphQL, WebSocket.

6. **Supply Chain Scanner** (`core/scanners/supply-chain/prompt.md`)
   - Always runs. Covers secrets, weak crypto, dependencies, CI/CD, key management.

7. **AI Security Scanner** (`core/scanners/ai-security/prompt.md`)
   - Runs if AI/LLM usage is detected (OpenAI, Anthropic, LangChain, Spring AI, etc.). Covers prompt injection, output validation, agent security, model ops, API key exposure.

**Parallel execution**: If the agent platform supports it, run all 7 scanners in parallel for speed.

### Step 3: Generate Report

After all scanners complete, compile findings into a unified report.

The report **MUST** follow the structure in `core/reporting/report-template.md` exactly — copy the template verbatim and only replace `{{...}}` placeholders. Each individual finding **MUST** follow the finding template in `core/reporting/format.md` exactly — copy it verbatim and only replace `{{...}}` placeholders. Read the DO/DO NOT format rules in `core/reporting/format.md` before generating output. Do not paraphrase, reorder, or add extra sections beyond what the templates specify.

#### Executive Summary

Use the executive summary table from `core/reporting/report-template.md`.

#### Findings (sorted by severity)

List all findings using the finding template from `core/reporting/format.md`, grouped by severity (CRITICAL first).

Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in `core/scanners/<domain>/rules.md` to the actual code found.

#### Remediation Priority

Suggest order of remediation:
1. CRITICAL findings with easiest fixes first (e.g., updating a config value)
2. CRITICAL findings requiring code changes
3. HIGH findings
4. Group related findings (e.g., all missing security headers together)

#### OWASP References

List all unique OWASP cheatsheets referenced in findings, with links to the full cheatsheet for further reading.

## Arguments

- `--focus <domain>`: Run only one scanner (injection, xss, config, auth, api, supply-chain)
- `--path <dir>`: Scan a specific subdirectory instead of the project root
- `--severity <level>`: Only report findings at or above this severity (CRITICAL, HIGH, MEDIUM, LOW)
