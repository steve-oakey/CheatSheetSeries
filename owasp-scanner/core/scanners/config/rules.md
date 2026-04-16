# Configuration Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting security misconfigurations.

## RULE-CFG-001: Missing Security Headers
- **Severity**: MEDIUM
- **CWE**: CWE-693 (Protection Mechanism Failure)
- **What to find**: Security response headers not configured in application or web server
- **Check for absence of**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY` or `SAMEORIGIN`
  - `Content-Security-Policy` (any valid policy)
  - `Strict-Transport-Security` (HSTS)
  - `Referrer-Policy`
  - `Permissions-Policy`
  - `Cross-Origin-Opener-Policy`
  - `Cross-Origin-Resource-Policy`
- **Fix**: Configure all security headers in server config or application framework
- **Reference**: HTTP_Headers_Cheat_Sheet.md

## RULE-CFG-002: Information Disclosure Headers
- **Severity**: LOW
- **CWE**: CWE-200 (Information Exposure)
- **What to find**: Response headers that reveal server technology or version
- **Patterns**:
  - `Server:` header with detailed version info (e.g., `Apache/2.4.51`)
  - `X-Powered-By:` header present (reveals framework)
  - `X-AspNet-Version:` header present
  - `X-AspNetMvc-Version:` header present
- **Fix**: Remove or set to non-informative values. Suppress in server config.
- **Reference**: HTTP_Headers_Cheat_Sheet.md

## RULE-CFG-003: Overly Permissive CORS
- **Severity**: MEDIUM
- **CWE**: CWE-346 (Origin Validation Error)
- **What to find**: CORS configuration that allows requests from any origin
- **Patterns**:
  - `Access-Control-Allow-Origin: *`
  - `allowedOrigins("*")` (Spring)
  - `@CrossOrigin("*")` or `@CrossOrigin` with no origin restriction
  - `cors: { origin: '*' }` or `cors: { origin: true }` (Express)
  - `Access-Control-Allow-Credentials: true` with wildcard origin
- **Fix**: Specify exact allowed origins. Never use wildcard with credentials.
- **Reference**: HTTP_Headers_Cheat_Sheet.md

## RULE-CFG-004: CSRF Protection Disabled
- **Severity**: MEDIUM
- **CWE**: CWE-352 (Cross-Site Request Forgery)
- **What to find**: CSRF protection explicitly disabled in framework configuration
- **Patterns**:
  - `csrf().disable()` or `csrf(csrf -> csrf.disable())` (Spring Security)
  - `csrf_protect` middleware removed (Django)
  - `'csrf' => false` or `VerifyCsrfToken` middleware removed (Laravel)
  - CSRF token not included in state-changing forms
  - State-changing operations using GET method
- **Fix**: Enable CSRF protection. Use synchronizer tokens or SameSite cookies.
- **Reference**: Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md

## RULE-CFG-005: Insecure Cookie Configuration
- **Severity**: MEDIUM
- **CWE**: CWE-614 (Sensitive Cookie without Secure Flag)
- **What to find**: Cookies set without security attributes
- **Patterns**:
  - `Set-Cookie` without `Secure` flag (session/auth cookies)
  - `Set-Cookie` without `HttpOnly` flag (session cookies)
  - `Set-Cookie` without `SameSite` attribute
  - `SameSite=None` without `Secure`
  - Session cookies with overly long `Max-Age` or `Expires`
- **Fix**: Set `Secure; HttpOnly; SameSite=Strict` (or `Lax`) on all session cookies
- **Reference**: Cookie_Theft_Mitigation_Cheat_Sheet.md

## RULE-CFG-006: Missing HSTS
- **Severity**: MEDIUM
- **CWE**: CWE-295 (Improper Certificate Validation)
- **What to find**: No Strict-Transport-Security header configured
- **Patterns**:
  - No `Strict-Transport-Security` in response headers config
  - `max-age` less than 31536000 (one year)
  - Missing `includeSubDomains` directive
- **Fix**: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`
- **Reference**: HTTP_Strict_Transport_Security_Cheat_Sheet.md

## RULE-CFG-007: Weak TLS Configuration
- **Severity**: HIGH
- **CWE**: CWE-326 (Inadequate Encryption Strength)
- **What to find**: TLS configuration allowing weak protocols or cipher suites
- **Patterns**:
  - `SSLv3`, `TLSv1`, `TLSv1.1` enabled
  - `TLSv1.0` enabled
  - Cipher suites containing `DES`, `3DES`, `RC4`, `MD5`, `NULL`, `EXPORT`
  - `ssl_protocols` including anything below TLSv1.2
  - Missing forward secrecy ciphers (no ECDHE/DHE)
- **Fix**: Enable only TLS 1.2+ with strong cipher suites. Prefer TLS 1.3.
- **Reference**: Transport_Layer_Security_Cheat_Sheet.md

## RULE-CFG-008: Clickjacking Vulnerability
- **Severity**: MEDIUM
- **CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers)
- **What to find**: Missing frame protection headers
- **Patterns**:
  - No `X-Frame-Options` header
  - No `frame-ancestors` in CSP
  - `X-Frame-Options: ALLOW-FROM` (obsolete, not supported by modern browsers)
  - Frame protection in `<meta>` tag (ineffective)
- **Fix**: Set both `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`
- **Reference**: Clickjacking_Defense_Cheat_Sheet.md

## RULE-CFG-009: Docker Running as Root
- **Severity**: MEDIUM
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **What to find**: Docker containers configured to run as root user
- **Patterns**:
  - Dockerfile without `USER` directive
  - `USER root` in Dockerfile
  - `docker run --privileged`
  - Missing `--cap-drop all`
  - `docker.sock` mounted as volume
- **Fix**: Add `USER nonroot` directive. Drop all capabilities. Never mount Docker socket.
- **Reference**: Docker_Security_Cheat_Sheet.md

## RULE-CFG-010: Docker Image Security
- **Severity**: LOW
- **CWE**: CWE-426 (Untrusted Search Path)
- **What to find**: Insecure Docker image practices
- **Patterns**:
  - `FROM image:latest` or `FROM image` (unpinned tag)
  - `ADD` used instead of `COPY` for local files
  - Secrets in `RUN` commands or `ARG`/`ENV` for passwords
  - `RUN curl ... | bash` (pipe to shell pattern)
  - Port binding to `0.0.0.0` instead of `127.0.0.1`
- **Fix**: Pin images to SHA digest. Use COPY. Use Docker secrets for credentials.
- **Reference**: Docker_Security_Cheat_Sheet.md

## RULE-CFG-011: Kubernetes Privileged Container
- **Severity**: HIGH
- **CWE**: CWE-250
- **What to find**: Kubernetes pods running with elevated privileges
- **Patterns**:
  - `privileged: true` in securityContext
  - `runAsUser: 0` (root)
  - Missing `runAsNonRoot: true`
  - `allowPrivilegeEscalation: true` or not set to false
  - `readOnlyRootFilesystem: false` or absent
  - Missing `drop: ["ALL"]` in capabilities
  - `hostNetwork: true`, `hostPID: true`, `hostIPC: true`
- **Fix**: Set restrictive securityContext: runAsNonRoot, drop ALL caps, readOnlyRootFilesystem
- **Reference**: Kubernetes_Security_Cheat_Sheet.md

## RULE-CFG-012: Missing Network Policy
- **Severity**: MEDIUM
- **CWE**: CWE-284 (Improper Access Control)
- **What to find**: Kubernetes namespaces without NetworkPolicy restricting traffic
- **Patterns**:
  - No `NetworkPolicy` resources in namespace
  - NetworkPolicy with empty `ingress` (allows all)
  - Missing egress restrictions
- **Fix**: Define restrictive NetworkPolicy for each namespace. Default-deny ingress and egress.
- **Reference**: Kubernetes_Security_Cheat_Sheet.md

## RULE-CFG-013: Verbose Error Responses
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Information Exposure Through Error Message)
- **What to find**: Error handlers that expose internal details
- **Patterns**:
  - `e.printStackTrace()` in response handling
  - `e.getMessage()` or `e.getStackTrace()` returned in API response
  - `DEBUG = True` in production config (Django)
  - `server.error.include-stacktrace=always` (Spring Boot)
  - `app.use(errorHandler({ dumpExceptions: true }))` (Express)
- **Fix**: Return generic error messages. Log details server-side only.
- **Reference**: Error_Handling_Cheat_Sheet.md

## RULE-CFG-014: Missing Security Logging
- **Severity**: LOW
- **CWE**: CWE-778 (Insufficient Logging)
- **What to find**: Security-relevant events not being logged
- **Check for absence of logging on**:
  - Authentication successes and failures
  - Authorization failures (403 responses)
  - Input validation failures
  - Application errors and exceptions
  - Session management events
- **Fix**: Log all security events with sufficient detail for forensics. Use structured logging.
- **Reference**: Logging_Cheat_Sheet.md

## RULE-CFG-015: Sensitive Data Caching
- **Severity**: MEDIUM
- **CWE**: CWE-525 (Information Exposure Through Browser Caching)
- **What to find**: Missing cache control on responses containing sensitive data
- **Patterns**:
  - No `Cache-Control` header on authenticated endpoints
  - `Cache-Control: public` on sensitive responses
  - Missing `Cache-Control: no-store` on PII/financial data responses
  - Missing `Pragma: no-cache` for HTTP/1.0 compatibility
- **Fix**: Set `Cache-Control: no-store` on all responses containing sensitive data
- **Reference**: HTTP_Headers_Cheat_Sheet.md

## RULE-CFG-016: Infrastructure as Code Security Misconfiguration
- **Severity**: HIGH
- **CWE**: CWE-284 (Improper Access Control)
- **What to find**: Insecure defaults in Terraform, CloudFormation, or Kubernetes manifests
- **Patterns**:
  - Security groups with `0.0.0.0/0` ingress on sensitive ports (22, 3389, 3306, 5432)
  - S3 buckets with public access: `acl = "public-read"`, `block_public_acls = false`
  - RDS/database instances with `publicly_accessible = true`
  - IAM policies with `"Action": "*"` or `"Resource": "*"` (overly permissive)
  - Missing encryption at rest: `encrypted = false`, no `kms_key_id`
  - Missing logging/monitoring: no CloudTrail, no flow logs
- **Fix**: Apply least privilege. Encrypt data at rest and in transit. Restrict network access. Enable logging.
- **Reference**: Infrastructure_as_Code_Security_Cheat_Sheet.md

## RULE-CFG-017: Weak TLS Cipher Suites
- **Severity**: HIGH
- **CWE**: CWE-326 (Inadequate Encryption Strength)
- **What to find**: Deprecated or weak cipher suites in TLS configuration
- **Patterns**:
  - Cipher suites with `NULL`, `EXPORT`, `anon`, `RC4`, `DES`, `3DES`, `MD5`
  - Cipher suites without forward secrecy (no `ECDHE`/`DHE`)
  - TLS 1.0 or TLS 1.1 enabled alongside TLS 1.2+
  - Cipher order not enforced server-side (`ssl_prefer_server_ciphers off`)
  - RSA key exchange without PFS (e.g., `TLS_RSA_WITH_AES_*`)
- **Fix**: Use only TLS 1.2+ with AEAD cipher suites (GCM/ChaCha20). Enforce server cipher order. Prefer ECDHE key exchange.
- **Reference**: TLS_Cipher_String_Cheat_Sheet.md, Transport_Layer_Security_Cheat_Sheet.md

## RULE-CFG-018: Access Control Gaps
- **Severity**: MEDIUM
- **CWE**: CWE-862 (Missing Authorization)
- **What to find**: Endpoints or resources without proper access control enforcement
- **Patterns**:
  - `permitAll()` on non-public endpoints (admin, API, user profile)
  - Missing `@PreAuthorize`/`@Secured`/`@RolesAllowed` on state-changing endpoints
  - Deny-by-default not configured: `anyRequest().authenticated()` missing
  - Role hierarchy not configured when needed
  - Hard-coded role checks: `if (role == "admin")` instead of framework annotations
  - Missing method-level security: `@EnableMethodSecurity` absent
- **Fix**: Use deny-by-default. Apply `@PreAuthorize` on all endpoints. Enable method-level security. Use role hierarchy where appropriate.
- **Reference**: Access_Control_Cheat_Sheet.md

## RULE-CFG-016: Infrastructure as Code Security Misconfiguration
- **Severity**: HIGH
- **CWE**: CWE-284 (Improper Access Control)
- **What to find**: Insecure defaults in Terraform, CloudFormation, or Kubernetes manifests
- **Patterns**:
  - Security groups with `0.0.0.0/0` ingress on sensitive ports (22, 3389, 3306, 5432)
  - S3 buckets with public access: `acl = "public-read"`, `block_public_acls = false`
  - RDS/database instances with `publicly_accessible = true`
  - IAM policies with `"Action": "*"` or `"Resource": "*"` (overly permissive)
  - Missing encryption at rest: `encrypted = false`, no `kms_key_id`
  - Missing logging/monitoring: no CloudTrail, no flow logs
- **Fix**: Apply least privilege. Encrypt data at rest and in transit. Restrict network access. Enable logging.
- **Reference**: Infrastructure_as_Code_Security_Cheat_Sheet.md

## RULE-CFG-017: Weak TLS Cipher Suites
- **Severity**: HIGH
- **CWE**: CWE-326 (Inadequate Encryption Strength)
- **What to find**: Deprecated or weak cipher suites in TLS configuration
- **Patterns**:
  - Cipher suites with `NULL`, `EXPORT`, `anon`, `RC4`, `DES`, `3DES`, `MD5`
  - Cipher suites without forward secrecy (no `ECDHE`/`DHE`)
  - TLS 1.0 or TLS 1.1 enabled alongside TLS 1.2+
  - Cipher order not enforced server-side (`ssl_prefer_server_ciphers off`)
  - RSA key exchange without PFS (e.g., `TLS_RSA_WITH_AES_*`)
- **Fix**: Use only TLS 1.2+ with AEAD cipher suites (GCM/ChaCha20). Enforce server cipher order. Prefer ECDHE key exchange.
- **Reference**: TLS_Cipher_String_Cheat_Sheet.md, Transport_Layer_Security_Cheat_Sheet.md

## RULE-CFG-018: Access Control Gaps
- **Severity**: MEDIUM
- **CWE**: CWE-862 (Missing Authorization)
- **What to find**: Endpoints or resources without proper access control enforcement
- **Patterns**:
  - `permitAll()` on non-public endpoints (admin, API, user profile)
  - Missing `@PreAuthorize`/`@Secured`/`@RolesAllowed` on state-changing endpoints
  - Deny-by-default not configured: `anyRequest().authenticated()` missing
  - Role hierarchy not configured when needed
  - Hard-coded role checks: `if (role == "admin")` instead of framework annotations
  - Missing method-level security: `@EnableMethodSecurity` absent
- **Fix**: Use deny-by-default. Apply `@PreAuthorize` on all endpoints. Enable method-level security. Use role hierarchy where appropriate.
- **Reference**: Access_Control_Cheat_Sheet.md
