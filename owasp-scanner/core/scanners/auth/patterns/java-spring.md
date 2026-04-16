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

### BCryptPasswordEncoder analysis guidance
BCrypt is a good choice but verify configuration:
```
# Work factor checks
BCryptPasswordEncoder\(\s*4\s*\)        # TOO WEAK: factor 4 (16 iterations)
BCryptPasswordEncoder\(\s*[5-9]\s*\)    # WEAK: factor 5-9 (below minimum 10)
BCryptPasswordEncoder\(\s*1[0-1]\s*\)   # ACCEPTABLE: factor 10-11 (default)
BCryptPasswordEncoder\(\s*1[2-4]\s*\)   # GOOD: factor 12-14 (recommended)
BCryptPasswordEncoder\(\s*1[5-9]\s*\)   # CAUTION: factor 15+ (may cause DoS from slow hashing)
```

### BCrypt pitfalls
```
BCryptPasswordEncoder.*\\.encode\(.*\+   # Concatenating values before encoding (wrong usage)
BCryptPasswordEncoder.*72               # BCrypt truncates at 72 bytes \u2014 verify long passwords
password\\.equals\(                      # Raw comparison instead of passwordEncoder.matches()
encoder\\.encode\(.*\)\\.equals\(       # Double-encoding comparison (wrong)
```

### Safe password hashing patterns
```
Argon2PasswordEncoder                   # Best choice (memory-hard)
BCryptPasswordEncoder\(\s*1[2-4]        # Good BCrypt strength
SCryptPasswordEncoder                   # Good choice (memory-hard)
Pbkdf2PasswordEncoder.*600000           # PBKDF2 with 600k+ iterations
DelegatingPasswordEncoder               # Multi-format (good for migration)
passwordEncoder\\.matches\\(            # Correct comparison method
```

### java.util.Random analysis guidance
`java.util.Random` is NOT cryptographically secure. Flag in security contexts:
```
# CRITICAL: Random used for security tokens/secrets
new Random\\(\\).*token                  # Predictable token generation
new Random\\(\\).*secret                 # Predictable secret
new Random\\(\\).*key                    # Predictable key
new Random\\(\\).*nonce                  # Predictable nonce
new Random\\(\\).*salt                   # Predictable salt
new Random\\(\\).*otp|new Random\\(\\).*code  # Predictable OTP
Random.*password.*generat               # Predictable password generation
Random.*session                         # Predictable session ID
Math\\.random\\(\\).*token               # JavaScript weak random for token
Math\\.random\\(\\).*secret              # JavaScript weak random for secret

# ACCEPTABLE: Random for non-security purposes
new Random\\(\\).*test                   # Test data (acceptable)
new Random\\(\\).*shuffle               # Shuffling display (acceptable)
new Random\\(\\).*delay|new Random\\(\\).*jitter  # Jitter (acceptable)
```

### Safe: Cryptographic random
```
SecureRandom                            # Java CSPRNG
new SecureRandom\\(\\)                   # CSPRNG instance
SecureRandom\\.getInstanceStrong\\(\\)   # Strong CSPRNG
ThreadLocalRandom(?!.*token|.*secret)   # OK for non-security (faster)
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

## Missing Rate Limiting on Auth Endpoints (RULE-AUTH-013)

### Dangerous: Spring auth endpoints without brute-force protection
```
@PostMapping\(.*"/login"               # Login endpoint
@PostMapping\(.*"/authenticate"        # Auth endpoint
@PostMapping\(.*"/signin"              # Sign-in endpoint
@PostMapping\(.*"/register"            # Registration endpoint
@PostMapping\(.*"/reset-password"      # Password reset
@PostMapping\(.*"/forgot-password"     # Forgot password
@PostMapping\(.*"/verify-otp"          # OTP verification
@PostMapping\(.*"/verify-mfa"          # MFA verification
@PostMapping\(.*"/oauth/token"         # OAuth token endpoint
```

For each auth endpoint, verify the method or class has rate limiting:
```
@RateLimiter\(name\s*=                 # Resilience4j rate limiter annotation
RateLimiterConfig\.custom\(            # Resilience4j programmatic config
\.tryConsume\(                          # Bucket4j token bucket check
Bucket4j|bucket4j                       # Bucket4j dependency present
GuavaRateLimiter|RateLimiter\.create\(  # Guava rate limiter
```

### Account lockout patterns (should be present in auth service)
```
failedAttempts|failedLoginAttempts      # Track failed attempts
accountLocked|isLocked|lockAccount      # Account lock check
lock.*expir|lockout.*expir              # Lock expiry mechanism
MAX_FAILED_ATTEMPTS|maxAttempts         # Configurable attempt limit
unlockAccount|resetFailedAttempts       # Unlock mechanism after timeout
```
Absence of ALL lockout patterns in authentication service code is a finding.

## Insecure Password Reset Token (RULE-AUTH-014)

### Dangerous: Spring password reset with weak tokens
```
UUID\.randomUUID\(\)\.toString\(\).*reset   # UUID as reset token (predictable)
new Random\(\).*reset.*token             # Weak RNG for reset token
repository\.findByResetToken\(token\)    # Plaintext token lookup (should be hashed)
repository\.findByToken\(token\)         # Plaintext token DB query
token\.equals\(storedToken\)             # Non-constant-time comparison
```

### Dangerous: Missing expiry on reset tokens
```
@Entity.*PasswordReset(?!.*expir|.*ttl|.*validUntil)   # Entity without expiry field
saveResetToken\(.*\)(?!.*expir)         # Save without expiry
```

### Safe: Secure reset token handling in Spring
```
new SecureRandom\(\).*token              # CSPRNG token generation
passwordEncoder\.encode\(.*token         # Hash token before storage
passwordEncoder\.matches\(.*token        # Constant-time comparison
LocalDateTime\.now\(\)\.plusMinutes\(    # Token expiry set
token.*isExpired\(\)|token.*hasExpired   # Expiry check on verification
session\.invalidate\(\).*passwordReset   # Session invalidation on password reset
```

## Missing MFA on Sensitive Operations (RULE-AUTH-015)

### Dangerous: Sensitive operations without MFA/reauthentication
```
@PostMapping.*"/change-password"(?!.*mfa|.*reauthenticat|.*verifyOtp|.*verifyToken)
@PostMapping.*"/change-email"(?!.*mfa|.*reauthenticat|.*verifyOtp)
@PostMapping.*"/change-phone"(?!.*mfa|.*reauthenticat|.*verifyOtp)
@PutMapping.*"/admin/"(?!.*mfa|.*reauthenticat|.*stepUp)
@PostMapping.*"/api-key"(?!.*mfa|.*reauthenticat)
@PostMapping.*"/transfer"(?!.*mfa|.*reauthenticat|.*verifyOtp)
@DeleteMapping.*"/account"(?!.*mfa|.*reauthenticat)
```

### Safe: MFA/step-up authentication present
```
@MfaRequired|@RequireMfa                # Custom MFA annotation
mfaService\.verify|otpService\.verify    # MFA verification call
reauthenticate\(|verifyCurrentPassword   # Reauthentication check
stepUpAuth|StepUpAuthentication          # Step-up authentication
TotpService|totpValidator                # TOTP verification
```

## Sensitive Data in Log Output (RULE-AUTH-016)

### Dangerous: Logging sensitive data in Spring
```
logger\.(debug|info|warn|error)\(.*password    # Password in log
logger\.(debug|info|warn|error)\(.*token       # Token in log
logger\.(debug|info|warn|error)\(.*otp         # OTP in log
logger\.(debug|info|warn|error)\(.*secret      # Secret in log
logger\.(debug|info|warn|error)\(.*apiKey      # API key in log
logger\.(debug|info)\(.*request\.getHeader\("Authorization  # Auth header logged
logger\.(debug|info)\(.*credentials            # Credentials in log
log\.debug\(".*\{\}".*,.*getPassword\(\)       # SLF4J placeholder with password
```

### Safe: Proper logging without sensitive data
```
logger\.info.*userId|logger\.info.*username     # Log identifiers only
logger\.info.*\.getId\(\)                       # Log IDs (safe)
@ToString\.Exclude.*password                   # Lombok: exclude from toString
@JsonIgnore.*password                          # Jackson: exclude from serialization
MaskingPatternLayout|MaskingConverter           # Logback masking converter
StructuredArguments\.keyValue\(                 # Structured logging
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
