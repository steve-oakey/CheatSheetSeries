# Configuration Patterns: Language-Agnostic

## Security Headers (check response configuration)
```
X-Content-Type-Options.*nosniff         # Should be present
X-Frame-Options.*(DENY|SAMEORIGIN)      # Should be present
Strict-Transport-Security.*max-age      # Should be present
Content-Security-Policy                 # Should be present
Referrer-Policy                         # Should be present
Permissions-Policy                      # Should be present
```

## Information Disclosure (should NOT be present)
```
X-Powered-By
X-AspNet-Version
X-AspNetMvc-Version
Server:.*Apache/\d
Server:.*nginx/\d
Server:.*Microsoft-IIS/\d
```

## CORS Issues

### Dangerous: Overly permissive CORS
```
Access-Control-Allow-Origin:\s*\*
Access-Control-Allow-Credentials.*true.*Allow-Origin.*\*
origin:\s*['"']?\*['"']?
allowedOrigins\(\s*["']\*["']\s*\)
```

### Dangerous: Origin reflection (mirrors request origin)
```
Access-Control-Allow-Origin.*request\.getHeader\("Origin"  # Reflecting origin
Access-Control-Allow-Origin.*req\.headers\.origin          # Reflecting origin
res\.setHeader\(["']Access-Control-Allow-Origin["'].*origin  # Dynamic reflection
cors.*origin.*true                      # Some frameworks reflect origin when set to true
```

### Dangerous: Credentials with wildcard (browser blocks but server misconfigured)
```
Access-Control-Allow-Credentials.*true  # When used, origin MUST NOT be *
withCredentials.*true                   # Client expects credentials — verify server origin restriction
```

### CORS analysis checklist
- If `Access-Control-Allow-Origin: *` — verify no cookies/auth tokens are sent
- If `Access-Control-Allow-Credentials: true` — verify origin is from a strict allowlist
- If origin is reflected from request — verify it's validated against an allowlist
- Check `Access-Control-Allow-Methods` doesn't include unnecessary methods (PUT, DELETE)
- Check `Access-Control-Expose-Headers` doesn't leak sensitive custom headers

### Safe: Restricted CORS
```
Access-Control-Allow-Origin:\s*https://   # Specific origin (good)
allowedOrigins\("https://.*\.example\.com"  # Domain-scoped (good)
corsConfigurationSource.*allowedOrigins.*Arrays\.asList  # Explicit list (good)
```

## Cookie Issues
```
Set-Cookie:.*(?!.*Secure)
Set-Cookie:.*(?!.*HttpOnly)
Set-Cookie:.*(?!.*SameSite)
SameSite=None(?!.*Secure)
```

## TLS Issues
```
SSLv3
TLSv1\.0
TLSv1\.1
ssl_protocols.*TLSv1[^.]
DES|3DES|RC4|MD5|NULL|EXPORT
```

## Docker Issues
```
^FROM.*:latest
^FROM\s+\w+\s*$                        # No tag at all
^USER\s+root
--privileged
docker\.sock
^ADD\s+                                 # Should use COPY
curl.*\|\s*bash
curl.*\|\s*sh
```

## Kubernetes Issues
```
privileged:\s*true
runAsUser:\s*0
allowPrivilegeEscalation:\s*true
readOnlyRootFilesystem:\s*false
hostNetwork:\s*true
hostPID:\s*true
hostIPC:\s*true
```

## Error Handling

### Dangerous: Stack trace / error detail exposure
```
printStackTrace\(\)
stackTrace
\.stack\b.*response
DEBUG\s*=\s*True
include-stacktrace.*always
dumpExceptions.*true
```

### printStackTrace() analysis guidance
`printStackTrace()` has two distinct risks:
1. **Information disclosure**: Stack traces reveal internal paths, library versions, and architecture
2. **Log noise / missing alerting**: Using stderr instead of structured logging loses context

```
# HIGH RISK: In web-facing code (controllers, filters, servlets)
catch.*\{[^}]*printStackTrace\(\)      # In catch block in controller/service
@Controller.*printStackTrace            # In controller class
@RestController.*printStackTrace        # In REST controller
Filter.*printStackTrace                 # In servlet filter
Servlet.*printStackTrace                # In servlet

# MEDIUM RISK: In service/business layer
@Service.*printStackTrace               # In service class
@Component.*printStackTrace             # In component class

# LOW RISK: In test/CLI code (acceptable)
@Test.*printStackTrace                  # In test (acceptable)
public static void main.*printStackTrace # In CLI (acceptable)
```

### Dangerous: Error details in responses
```
e\.getMessage\(\).*response             # Exception message in HTTP response
e\.getStackTrace\(\).*response          # Stack trace in response
e\.toString\(\).*response               # Exception string in response
"error":\s*".*Exception                 # Exception class name in JSON response
"trace":\s*".*at\s+                    # Stack trace in JSON response
```

### Safe: Proper error handling
```
logger\.(error|warn)\(.*e\)            # Log the exception (good)
logger\.(error|warn)\(".*", e\)        # Structured logging with exception (good)
@ControllerAdvice                       # Global error handler (good)
@ExceptionHandler                       # Exception handler (good)
ResponseEntityExceptionHandler          # Spring standard handler (good)
GenericErrorMessage|"An error occurred" # Generic user-facing message (good)
```

## Cache Control
```
Cache-Control:.*public                  # Dangerous on sensitive endpoints
```

## Missing Security Logging (RULE-CFG-014)

### Security events that MUST be logged
Verify logging is present for each of these event types:
```
# Authentication events
login.*log|log.*login                   # Login success/failure logging
authenticat.*log|log.*authenticat       # Authentication event logging
logout.*log|log.*logout                 # Logout event logging

# Authorization events
authoriz.*denied.*log|log.*access.*denied  # Access denied logging
forbidden.*log|log.*forbidden           # 403 event logging
permission.*denied.*log                 # Permission denial logging

# Security violation events
invalid.*token.*log|log.*invalid.*token # Invalid token logging
session.*expir.*log|log.*session.*expir # Session expiry logging
csrf.*log|log.*csrf                     # CSRF violation logging
```

### Dangerous: Exception handlers without logging
```
catch\s*\(.*Exception                  # In exception handlers...
(?!.*log\.|.*logger\.|.*LOG\.)         # ...verify logging is present
try\s*\{.*\}\s*catch.*\{\s*\}        # Empty catch blocks
catch.*\{\s*return                     # Catch-and-return without logging
```

Absence of security event logging in auth controllers and security filters is a finding.

## Infrastructure as Code Security Misconfiguration (RULE-CFG-016)

### Dangerous: Terraform / CloudFormation patterns
```
ingress.*0\.0\.0\.0/0                   # Security group open to world
cidr_blocks.*0\.0\.0\.0/0.*22           # SSH open to internet
cidr_blocks.*0\.0\.0\.0/0.*3389         # RDP open to internet
cidr_blocks.*0\.0\.0\.0/0.*3306         # MySQL open to internet
cidr_blocks.*0\.0\.0\.0/0.*5432         # PostgreSQL open to internet
acl\s*=\s*"public-read"                 # Public S3 bucket
block_public_acls\s*=\s*false           # Public access not blocked
publicly_accessible\s*=\s*true          # Database publicly accessible
"Action":\s*"\*"                        # IAM wildcard action
"Resource":\s*"\*"                      # IAM wildcard resource
encrypted\s*=\s*false                   # Missing encryption at rest
storage_encrypted\s*=\s*false           # RDS unencrypted
```

### Safe: Secure IaC patterns
```
block_public_acls\s*=\s*true            # Public access blocked
block_public_policy\s*=\s*true          # Public policy blocked
encrypted\s*=\s*true                    # Encryption enabled
kms_key_id|kms_key_arn                  # KMS key configured
enable_logging\s*=\s*true               # Logging enabled
```

## Weak TLS Cipher Suites (RULE-CFG-017)

### Dangerous: Deprecated cipher components
```
NULL|EXPORT|anon                        # Null/export/anonymous ciphers
RC4|RC2|DES(?!ede)|3DES|DESede          # Broken ciphers
MD5(?!.*password)                       # MD5 in cipher suite
TLS_RSA_WITH_(?!.*DHE)                  # RSA key exchange without PFS
ssl_prefer_server_ciphers\s+off         # Server cipher preference disabled
ssl_ciphers.*LOW|ssl_ciphers.*MEDIUM    # Weak cipher categories in nginx
```

### Safe: Modern cipher suites
```
TLS_AES_128_GCM_SHA256                  # TLS 1.3 cipher
TLS_AES_256_GCM_SHA384                  # TLS 1.3 cipher
TLS_CHACHA20_POLY1305_SHA256            # TLS 1.3 cipher
ECDHE.*GCM|ECDHE.*CHACHA20              # TLS 1.2 with PFS + AEAD
ssl_prefer_server_ciphers\s+on          # Server cipher preference enabled
```

## Access Control Gaps (RULE-CFG-018)

### Dangerous: Missing or weak access control
```
permitAll\(\)                           # Check what's being permitted
anyRequest\(\)\.permitAll\(\)           # Everything permitted (no auth required)
\.anonymous\(\)                         # Anonymous access allowed
http\.authorizeRequests\(\).*permitAll  # Permissive authorization
```

### Safe: Proper access control
```
anyRequest\(\)\.authenticated\(\)       # Deny-by-default (good)
anyRequest\(\)\.denyAll\(\)             # Explicit deny-all fallback (good)
@EnableMethodSecurity                   # Method-level security enabled
@EnableGlobalMethodSecurity             # Legacy method security enabled
@PreAuthorize|@Secured|@RolesAllowed    # Endpoint-level authorization
```
