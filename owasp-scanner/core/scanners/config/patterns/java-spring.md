# Configuration Patterns: Java / Spring Boot

## Spring Security Headers
```
\.headers\(\)\.disable\(\)              # Disabling ALL security headers
\.headers\(\)\.defaultsDisabled\(\)     # Disabling defaults
frameOptions\(\)\.disable\(\)          # Disabling X-Frame-Options
contentTypeOptions\(\)\.disable\(\)    # Disabling X-Content-Type-Options
xssProtection\(\)\.disable\(\)        # Disabling XSS protection
```

## CORS Configuration

### Dangerous: Overly permissive CORS
```
@CrossOrigin\(\s*\)                     # No origin restriction (defaults to *)
@CrossOrigin\(.*origins\s*=\s*"\*"      # Wildcard origin
allowedOrigins\(\s*"\*"\s*\)           # Wildcard in CorsRegistry
CorsConfiguration.*setAllowedOrigins.*\*
allowCredentials\(true\)               # Check if used with wildcard
```

### Dangerous: Origin reflection patterns in Spring
```
CorsConfiguration.*addAllowedOrigin\(request\.getHeader  # Reflecting request origin
setAllowedOriginPatterns\("\*"\)       # Wildcard pattern (Spring 5.3+)
```

### CORS + Credentials compound check
When `allowCredentials(true)` is present, verify `allowedOrigins` is NOT `*`:
```
allowCredentials\(true\).*allowedOrigins\("\*"  # CRITICAL: wildcard + credentials
@CrossOrigin\(.*allowCredentials.*true.*origins.*\*  # CRITICAL combination
```
Spring will throw an error for wildcard+credentials, but `allowedOriginPatterns("*")` bypasses this — flag it.

### Safe: Restricted CORS in Spring
```
allowedOrigins\("https://               # Specific origin (good)
CorsConfigurationSource.*allowedOrigins.*Arrays\.asList  # Explicit list (good)
@CrossOrigin\(origins\s*=\s*"https://   # Specific origin annotation (good)
```

## CSRF Protection

### Dangerous: CSRF disabled
```
csrf\(\)\.disable\(\)                   # Spring Security 5.x
csrf\(csrf\s*->\s*csrf\.disable\(\)\)  # Spring Security 6.x lambda
csrf\(AbstractHttpConfigurer::disable\) # Spring Security 6.x method ref
```

### csrf().disable() analysis guidance
Disabling CSRF is **justified** when:
1. API is purely stateless (JWT tokens, no cookies) AND `SessionCreationPolicy.STATELESS` is set
2. API serves only non-browser clients (machine-to-machine)
3. API uses custom token-based auth via headers (not cookies)

Disabling CSRF is **dangerous** when:
1. Session cookies are used for authentication
2. `@SessionAttributes` or `HttpSession` is used
3. `allowCredentials(true)` is configured in CORS
4. Form-based login is configured: `formLogin()`

### Compound check: CSRF disabled + session-based auth
```
csrf.*disable.*(?!.*STATELESS)          # CSRF disabled without stateless session
csrf.*disable.*formLogin                # CSRF disabled with form login (CRITICAL)
csrf.*disable.*session\.setAttribute    # CSRF disabled with session usage
```

### Safe: CSRF properly configured
```
csrf\(\)                                # CSRF enabled (default — good)
CsrfTokenRepository                     # Custom CSRF token repo
CookieCsrfTokenRepository               # Cookie-based CSRF token
CsrfTokenRequestAttributeHandler        # Spring 6 CSRF handler
csrf.*csrfTokenRepository               # Explicit CSRF config
```

## Cookie Configuration
```
setHttpOnly\(false\)                    # Disabling HttpOnly
setSecure\(false\)                      # Disabling Secure
setSameSite\(.*None\)                  # SameSite=None
server\.servlet\.session\.cookie\.http-only=false
server\.servlet\.session\.cookie\.secure=false
```

## TLS Configuration
```
server\.ssl\.enabled-protocols.*TLSv1[^.]   # Old TLS
server\.ssl\.ciphers.*DES|3DES|RC4
NoopHostnameVerifier                         # Disabling hostname verification
TrustAllStrategy                             # Trusting all certificates
setHostnameVerifier\(.*ALLOW_ALL             # Accepting any hostname
X509TrustManager.*return                     # Empty trust manager
```

## Error Handling

### Dangerous: Error details in production
```
server\.error\.include-stacktrace=always
server\.error\.include-message=always
server\.error\.include-binding-errors=always
e\.printStackTrace\(\)                  # In controller/service code
e\.getMessage\(\).*ResponseEntity       # Leaking error details
e\.getStackTrace\(\).*response
```

### printStackTrace() in Spring context
```
# CRITICAL: In web-facing code
@Controller[\s\S]*?printStackTrace     # Controller with printStackTrace
@RestController[\s\S]*?printStackTrace # REST controller with printStackTrace
@ControllerAdvice[\s\S]*?printStackTrace # Error handler using printStackTrace
Filter[\s\S]*?printStackTrace          # Servlet filter with printStackTrace

# Should use structured logging instead:
logger\.error\(".*", e\)               # Correct: SLF4J with exception (good)
log\.error\(".*", e\)                  # Correct: logging framework (good)
```

### Safe: Spring error handling
```
@ControllerAdvice                       # Global error handler (good)
@ExceptionHandler                       # Per-controller handler (good)
ResponseEntityExceptionHandler          # Standard Spring handler (good)
server\.error\.include-stacktrace=never # Stacktrace hidden (good)
server\.error\.include-message=never    # Message hidden (good)
ProblemDetail\.forStatusAndDetail       # RFC 7807 error response (good)
```

## Application Properties
```
spring\.jpa\.show-sql=true              # SQL logging in production
logging\.level\.org\.hibernate\.SQL=DEBUG
management\.endpoints\.web\.exposure\.include=\*  # Exposing all actuator endpoints
management\.endpoint\.health\.show-details=always
```

## Safe Spring Security Configuration
```
\.headers\(\)
\.contentSecurityPolicy\("
\.frameOptions\(\)\.deny\(\)
\.httpStrictTransportSecurity\(\)
\.referrerPolicy\(
csrf\(\)                                # CSRF enabled (default)
```

## Missing Security Logging (RULE-CFG-014)

### Dangerous: Spring auth/security code without logging

Search for auth controller methods lacking logger calls:
```
@PostMapping.*login|@PostMapping.*authenticate
(?!.*logger\.|.*log\.|.*LOG\.)         # No logging in method body

@ExceptionHandler.*AuthenticationException
(?!.*logger\.|.*log\.)                 # Exception handler without logging

AuthenticationFailureHandler            # Check impl has logging
(?!.*logger\.warn|.*logger\.error)     # No failure logging

AccessDeniedHandler                     # Check impl has logging
(?!.*logger\.warn|.*logger\.error)     # No access-denied logging
```

### Security logging that SHOULD be present
```
logger\.(info|warn).*login              # Login event logging
logger\.(info|warn).*authenticat        # Authentication logging
logger\.(warn|error).*denied            # Access denied logging
logger\.(warn|error).*unauthorized      # Unauthorized access logging
logger\.warn.*failed.*attempt           # Failed attempt logging
logger\.info.*logout                    # Logout logging
logger\.warn.*session.*expir            # Session expiry logging
logger\.error.*csrf                     # CSRF violation logging
```

### Spring Security audit integration (preferred)
```
AbstractAuthenticationAuditListener     # Custom audit listener
AuditEventRepository                    # Audit event storage
@EventListener.*AuthenticationSuccess   # Login success listener
@EventListener.*AuthenticationFailure   # Login failure listener
@EventListener.*AuthorizationDenied     # Authorization denied listener
ActuatorAuditListener                   # Actuator audit integration
MDC\.put\(                              # Correlation ID in logs (good)
SecurityContextHolder.*getName\(\).*log # Logging authenticated user
```

Absence of security audit listeners AND manual security logging is a finding.

## Infrastructure as Code Security Misconfiguration (RULE-CFG-016)

Scan `*.tf`, `*.tfvars`, `*.yaml` (CloudFormation), `*.json` (ARM templates) in project:
```
# Terraform
resource.*aws_security_group.*ingress.*0\.0\.0\.0/0  # Open SG
resource.*aws_s3_bucket.*acl.*public                  # Public bucket
resource.*aws_db_instance.*publicly_accessible.*true   # Public DB
resource.*aws_iam_policy.*Action.*\*                   # Wildcard IAM

# Spring Cloud AWS / Azure configuration
cloud\.aws\.s3\.public-access=true                     # Public S3 from Spring
spring\.cloud\.azure\.storage\.blob\..*public           # Public Azure blob
```

## Weak TLS Cipher Suites (RULE-CFG-017)

### Dangerous: Weak cipher config in Spring Boot
```
server\.ssl\.ciphers=.*RC4               # RC4 in cipher list
server\.ssl\.ciphers=.*DES               # DES in cipher list
server\.ssl\.ciphers=.*3DES              # 3DES in cipher list
server\.ssl\.ciphers=.*NULL              # NULL cipher
server\.ssl\.ciphers=.*EXPORT            # Export cipher
server\.ssl\.ciphers=.*MD5               # MD5 cipher MAC
server\.ssl\.enabled-protocols=.*TLSv1[^.] # TLS 1.0 or 1.1
server\.ssl\.enabled-protocols(?!.*TLSv1\.3)  # Missing TLS 1.3
```

### Safe: Strong TLS cipher config in Spring Boot
```
server\.ssl\.ciphers=.*ECDHE.*GCM        # PFS with AEAD (good)
server\.ssl\.ciphers=.*CHACHA20          # ChaCha20 (good)
server\.ssl\.enabled-protocols=TLSv1\.2,TLSv1\.3  # Modern TLS only
server\.ssl\.protocol=TLS                # TLS enabled
```

## Access Control Gaps (RULE-CFG-018)

### Dangerous: Permissive Spring Security authorization
```
http\.authorizeRequests\(\).*\.anyRequest\(\)\.permitAll  # Everything open
\.requestMatchers\("/admin/.*"\)\.permitAll              # Admin endpoints open
\.requestMatchers\("/api/.*"\)\.permitAll                # API endpoints open
\.requestMatchers\("/user/.*"\)\.permitAll               # User endpoints open
http\.authorizeHttpRequests(?!.*anyRequest.*authenticated) # Missing deny-by-default
```

### Dangerous: Missing method-level security
```
@RestController(?!.*@PreAuthorize|.*@Secured|.*@RolesAllowed)  # Controller without authz
@PutMapping|@PostMapping|@DeleteMapping(?!.*@PreAuthorize)     # State-changing without authz
```
Verify `@EnableMethodSecurity` or `@EnableGlobalMethodSecurity` is present in config class.

### Safe: Proper Spring Security access control
```
@EnableMethodSecurity                   # Method security enabled
@EnableMethodSecurity\(prePostEnabled\s*=\s*true\)  # Pre/post authorization
\.anyRequest\(\)\.authenticated\(\)     # Deny-by-default
\.anyRequest\(\)\.denyAll\(\)           # Explicit deny-all fallback
@PreAuthorize\(.*hasRole.*ADMIN         # Admin role check
@PreAuthorize\(.*hasAuthority            # Authority-based check
RoleHierarchy|roleHierarchy              # Role hierarchy configured
```
