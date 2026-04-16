# Auth Patterns: Language-Agnostic

## Weak Password Hashing
```
md5\(.*password
sha1\(.*password
sha256\(.*password
MessageDigest\.getInstance\("MD5"\)
MessageDigest\.getInstance\("SHA-1"\)
hashlib\.md5\(
hashlib\.sha1\(
hash\(.*'md5'
hash\(.*'sha1'
```

## Hardcoded Credentials
```
password\s*[:=]\s*["'][^"']+["']
api[_-]?key\s*[:=]\s*["'][^"']+["']
secret\s*[:=]\s*["'][^"']+["']
token\s*[:=]\s*["'][^"']+["']
BEGIN RSA PRIVATE KEY
BEGIN OPENSSH PRIVATE KEY
BEGIN EC PRIVATE KEY
BEGIN PGP PRIVATE KEY
AWS_SECRET_ACCESS_KEY\s*=
PRIVATE_KEY\s*=
```

## JWT Issues
```
alg.*none
Algorithm\.none\(\)
decode\(.*verify.*false
decode\((?!.*verify)
jwt\.decode\((?!.*algorithms)
```

## Token Storage
```
localStorage\.setItem\(["']token
localStorage\.setItem\(["']jwt
localStorage\.setItem\(["']auth
localStorage\.setItem\(["']session
localStorage\.setItem\(["']access
sessionStorage\.setItem\(["']token
```

## User Enumeration
```
"Invalid username"
"User not found"
"Account does not exist"
"No account with that email"
"Unknown user"
```

## Session Issues
```
JSESSIONID|PHPSESSID|ASP\.NET_SessionId   # Identifiable session names
session.*URL|url.*session                  # Session in URL
```

## Missing Rate Limiting on Auth Endpoints (RULE-AUTH-013)

### Dangerous: Auth endpoints without brute-force protection
```
/login|/signin|/authenticate              # Login endpoints — verify rate limiting present
/register|/signup|/create-account          # Registration endpoints — verify rate limiting
/reset-password|/forgot-password           # Password reset — verify rate limiting
/verify-otp|/verify-mfa|/verify-token      # MFA verification — verify rate limiting
/api/auth|/api/token|/oauth/token          # API auth endpoints — verify rate limiting
```

For each auth endpoint found, verify at least ONE of these protections exists:
```
rateLimit|rate-limit|rate_limit            # Rate limiting middleware/config
throttle|Throttle                          # Throttling
account.*lock|lockout|lock_account         # Account lockout mechanism
failedAttempts|failed_attempts|login_attempts  # Failed attempt tracking
captcha|CAPTCHA|recaptcha|reCAPTCHA        # CAPTCHA after failures
delay|backoff|progressive                  # Progressive delays
max.*attempts|maxAttempts|MAX_ATTEMPTS     # Attempt limits
```

Absence of ALL protections on an auth endpoint is a finding.

## Insecure Password Reset Token (RULE-AUTH-014)

### Dangerous: Weak token generation
```
Math\.random\(\).*token                 # Weak RNG for token
java\.util\.Random.*token               # Weak RNG for token
UUID\.randomUUID\(\).*reset             # UUID without hashing (predictable entropy)
random\.random\(\).*token               # Python weak RNG for token
```

### Dangerous: Plaintext token storage and comparison
```
resetToken\s*=\s*token                  # Storing token without hashing
findByResetToken\(token\)               # Querying plaintext token from DB
findByToken\(token\)                    # Plaintext token lookup
dbToken\.equals\(userToken\)            # Plaintext comparison (timing attack)
token\s*==\s*storedToken                # Equality check without constant-time
```

### Dangerous: Missing token expiry
Verify reset token has expiry configured:
```
expiresAt|expiry|ttl|TTL|validUntil     # Should be present near token creation
setExpiration|setExpiresAt               # Should be present
```
Absence of expiry fields near password reset token creation is a finding.

### Safe: Secure token handling
```
SecureRandom.*token                     # CSPRNG for token generation
secrets\.token_urlsafe                  # Python secrets module
crypto\.randomBytes                     # Node.js CSPRNG
MessageDigest.*SHA-256.*token           # Hash before storage
passwordEncoder\.matches\(.*token       # Constant-time comparison
MessageDigest\.isEqual\(                # Constant-time byte comparison
```

## Sensitive Data in Log Output (RULE-AUTH-016)

### Dangerous: Logging sensitive values
```
log.*(password|passwd|pwd)              # Password in log
log.*(token|jwt|bearer)                 # Token in log
log.*(otp|one.time|mfa.code)            # OTP/MFA code in log
log.*(secret|apiKey|api_key)            # Secret/API key in log
log.*(creditCard|credit_card|ccNumber)  # Credit card in log
log.*(ssn|socialSecurity|social_security) # SSN in log
log.*(authorization|Authorization).*:   # Auth header value in log
logger.*request\.getHeader\("Authorization  # Auth header logged
logger.*toString\(\).*[Uu]ser           # User object toString may contain sensitive data
```

### Safe: Redacted logging
```
redact|REDACT|mask|MASK                 # Redaction present
\*\*\*|\[REDACTED\]|\[MASKED\]          # Masked values in log format
logger.*userId|logger.*username         # Logging identifiers (not credentials)
logger.*\.getId\(\)                     # Logging IDs (safe)
@ToString\.Exclude                      # Lombok exclude from toString
@JsonIgnore.*password                   # Excluded from serialization
```
