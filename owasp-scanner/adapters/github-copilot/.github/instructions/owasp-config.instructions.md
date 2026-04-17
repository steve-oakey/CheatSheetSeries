---
applyTo: "**/Dockerfile,**/docker-compose.yml,**/docker-compose.yaml,**/*.yaml,**/*.yml,**/nginx.conf,**/*.toml,**/*.conf,**/application.properties,**/application.yml,**/*Security*.java,**/*Config*.java,**/*config*.py,**/*config*.ts,**/*config*.js"
---

# OWASP Configuration Security Checks

When reviewing or generating configuration files, watch for security misconfigurations. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Missing Security Headers (RULE-CFG-001, CWE-693)
Check for absence of:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY` or `SAMEORIGIN`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`
- **Fix**: Configure all security headers in server config or application framework

### Overly Permissive CORS (RULE-CFG-003, CWE-346)
- `Access-Control-Allow-Origin: *`
- `allowedOrigins("*")` (Spring)
- `cors: { origin: '*' }` or `cors: { origin: true }` (Express)
- `Access-Control-Allow-Credentials: true` with wildcard origin
- **Fix**: Specify exact allowed origins. Never use wildcard with credentials.

### CSRF Protection Disabled (RULE-CFG-004, CWE-352)
- `csrf().disable()` or `csrf(csrf -> csrf.disable())` (Spring Security)
- `csrf_protect` middleware removed (Django)
- **Fix**: Enable CSRF protection. Use synchronizer tokens or SameSite cookies.

### Insecure Cookie Configuration (RULE-CFG-005, CWE-614)
- Session cookies without `Secure` flag
- Session cookies without `HttpOnly` flag
- Missing `SameSite` attribute
- **Fix**: Set `Secure; HttpOnly; SameSite=Strict` (or `Lax`) on all session cookies

### Weak TLS Configuration (RULE-CFG-007, CWE-326)
- `SSLv3`, `TLSv1`, `TLSv1.1` enabled
- Cipher suites containing `DES`, `3DES`, `RC4`, `MD5`, `NULL`, `EXPORT`
- **Fix**: Enable only TLS 1.2+ with strong cipher suites. Prefer TLS 1.3.

### Docker Running as Root (RULE-CFG-009, CWE-250)
- Dockerfile without `USER` directive
- `USER root` in Dockerfile
- `docker run --privileged`
- `docker.sock` mounted as volume
- **Fix**: Add `USER nonroot` directive. Drop all capabilities. Never mount Docker socket.

### Kubernetes Security Misconfigurations (RULE-CFG-010, CWE-250)
- `privileged: true` in pod spec
- `runAsUser: 0` (root)
- Missing `securityContext`
- `hostNetwork: true`, `hostPID: true`
- **Fix**: Set `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, drop all capabilities

### Debug/Dev Mode in Production (RULE-CFG-012, CWE-489)
- `DEBUG = True` (Django)
- `spring.profiles.active=dev` in production config
- `server.error.include-stacktrace=always` (Spring Boot)
- **Fix**: Ensure debug mode is disabled in production configs

## Proof of Concept

For HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rule definitions. Use benign payloads that prove the vulnerability exists without causing damage.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/config/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/config/patterns/`.
