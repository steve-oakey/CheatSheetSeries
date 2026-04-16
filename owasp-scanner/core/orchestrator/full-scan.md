# Full Security Scan Orchestrator

Run a comprehensive OWASP security scan against the target project using all 6 scanner domains.

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

**Parallel execution**: If the agent platform supports it, run all 6 scanners in parallel for speed.

### Step 3: Generate Report

After all scanners complete, compile findings into a unified report:

#### Executive Summary
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
| INFO     | N     |
| **Total** | **N** |
```

#### Findings (sorted by severity)

List all findings using the format in `core/reporting/format.md`, grouped by severity (CRITICAL first).

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
