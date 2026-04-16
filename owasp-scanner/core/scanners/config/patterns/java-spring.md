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
```
@CrossOrigin\(\s*\)                     # No origin restriction
@CrossOrigin\(.*origins\s*=\s*"\*"      # Wildcard origin
allowedOrigins\(\s*"\*"\s*\)           # Wildcard in CorsRegistry
CorsConfiguration.*setAllowedOrigins.*\*
allowCredentials\(true\)               # Check if used with wildcard
```

## CSRF Protection
```
csrf\(\)\.disable\(\)                   # Spring Security 5.x
csrf\(csrf\s*->\s*csrf\.disable\(\)\)  # Spring Security 6.x lambda
csrf\(AbstractHttpConfigurer::disable\) # Spring Security 6.x method ref
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
```
server\.error\.include-stacktrace=always
server\.error\.include-message=always
server\.error\.include-binding-errors=always
e\.printStackTrace\(\)                  # In controller/service code
e\.getMessage\(\).*ResponseEntity       # Leaking error details
e\.getStackTrace\(\).*response
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
