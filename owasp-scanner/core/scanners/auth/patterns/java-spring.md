# Auth Patterns: Java / Spring Boot

## Password Hashing
```
MessageDigest\.getInstance\("MD5"\)     # Weak
MessageDigest\.getInstance\("SHA-1"\)   # Weak
MessageDigest\.getInstance\("SHA-256"\) # Weak for passwords (no iterations)
BCryptPasswordEncoder\(\s*[0-8]\s*\)    # bcrypt work factor < 10
new BCryptPasswordEncoder\(\)           # Default (10) is acceptable
Pbkdf2PasswordEncoder.*iterations.*[0-5]\d{5}  # < 600000 iterations
String\s+password                       # Password as String (should be char[])
```

## Spring Security Authorization
```
@RequestMapping.*(?!.*@PreAuthorize|@Secured|@RolesAllowed)  # Missing authz
\.permitAll\(\)                         # Check what's permitted
\.antMatchers\(".*"\)\.permitAll\(\)    # Sensitive endpoints permitted?
\.requestMatchers\(".*"\)\.permitAll\(\)
http\.authorizeRequests\(\).*\.anyRequest\(\)\.permitAll\(\)  # Everything permitted
```

## Session Management
```
session\.invalidate\(\)                 # Should be called on login (good)
request\.getSession\(true\)            # New session after invalidate (good)
SessionCreationPolicy\.STATELESS       # For JWT-based (no session fixation issue)
session\.setAttribute.*(?!.*invalidate) # Setting attrs without regenerating
server\.servlet\.session\.timeout=     # Check timeout value
```

## JWT Configuration
```
Algorithm\.HMAC256\(                    # Check secret length
JWTVerifier.*build\(\)                 # Should include issuer/audience
\.withIssuer\(                         # Good - validates issuer
\.withAudience\(                       # Good - validates audience
\.withExpiresAt\(                      # Good - validates expiration
JWT\.decode\(                          # Should use verify, not just decode
```

## OAuth2 Spring
```
\.oauth2Login\(                        # Check redirect URI validation
\.oauth2Client\(                       # Check state parameter
redirect-uri.*\{baseUrl\}             # Check if validated
```

## Safe Patterns
```
@PreAuthorize\("hasRole\(              # Role-based access control
@PreAuthorize\("hasAuthority\(         # Authority-based
@Secured\("ROLE_                       # Spring Secured
@RolesAllowed\("                       # JSR-250
PasswordEncoder.*encode\(              # Using encoder (good)
Argon2PasswordEncoder                  # Best choice
BCryptPasswordEncoder                  # Good choice
```
