# Authentication Patterns: Node.js / Express

## Passport.js Authentication

### Dangerous: Insecure Passport config
```
passport\.authenticate\(.*\{.*session:\s*false.*failureRedirect.*(?!.*) # No failure handling
serializeUser\(.*function.*user\.password # Serializing password in session
LocalStrategy\(.*function.*(?!.*bcrypt|.*argon|.*scrypt) # Password check without hashing
```

### Safe: Passport.js
```
passport\.authenticate\(["']\w+["'],\s*\{ # Passport authentication (good)
passport\.use\(new \w+Strategy\(         # Strategy registration (good)
serializeUser\(.*user\.id\)              # Serialize only ID (good)
failureRedirect:\s*["']/login            # Failure redirect (good)
```

## Password Hashing

### Dangerous: Weak password hashing
```
crypto\.createHash\(["']md5["']\).*password # MD5 for passwords
crypto\.createHash\(["']sha1["']\).*password # SHA1 for passwords
crypto\.createHash\(["']sha256["']\).*password # SHA256 without salt/iterations
password\s*===\s*|password\s*==\s*       # Direct password comparison
```

### Safe: Strong password hashing
```
bcrypt\.hash\(|bcrypt\.compare\(         # bcrypt (good)
argon2\.hash\(|argon2\.verify\(          # Argon2 (good)
scrypt\(|crypto\.scryptSync\(            # scrypt (good)
bcryptjs\.hash\(|bcryptjs\.compare\(     # bcryptjs (good)
```

## JWT Authentication

### Dangerous: Insecure JWT
```
jwt\.verify\(.*\{.*algorithms:\s*\[["']none # "none" algorithm accepted
jwt\.decode\((?!.*jwt\.verify)           # Decode without verify
jwt\.sign\(.*secret.*["'][a-z]{1,10}["'] # Short/weak JWT secret
jwt\.sign\(.*expiresIn:\s*["']\d+d       # Very long expiry (review)
jsonwebtoken.*verify.*\{(?!.*algorithms) # Verify without algorithm restriction
```

### Safe: Secure JWT
```
jwt\.verify\(.*\{.*algorithms:\s*\[["']RS256 # RSA verification (good)
jwt\.verify\(.*process\.env\.\w+SECRET   # Secret from environment (good)
expiresIn:\s*["'](15m|1h|30m)           # Short expiry (good)
passport-jwt|JwtStrategy                # Passport JWT strategy (good)
```

## Session Management

### Dangerous: Insecure sessions
```
express-session.*MemoryStore             # MemoryStore (leaks, not for production)
session\(\{(?!.*store:)                  # No external session store
cookie:\s*\{(?!.*maxAge)                 # No session expiry
rolling:\s*false.*(?=.*maxAge)           # Session not extended on activity
```

### Safe: Secure sessions
```
store:\s*new (Redis|Mongo|Pg)Store       # External session store (good)
cookie:.*maxAge:\s*\d{6,8}\b            # Reasonable session lifetime (good)
rolling:\s*true                          # Session extended on activity (good)
name:\s*["'][^s][^e][^s][^s]             # Custom session cookie name (good)
```

## OAuth/OIDC

### Dangerous: Insecure OAuth implementation
```
passport-oauth2.*(?!.*state)             # OAuth without state parameter
callbackURL.*http://(?!localhost)        # Non-HTTPS callback URL
verify\(.*function.*(?!.*profile\.id)    # Callback without ID verification
grant_type.*password.*(?!.*localhost)    # Password grant in production
```

### Safe: Secure OAuth
```
passport-google-oauth20|passport-github2 # Established OAuth strategies (good)
openid-client|oidc-client                # OIDC client libraries (good)
state:\s*true|passReqToCallback          # State parameter enabled (good)
nonce.*=.*crypto\.randomBytes\(          # Cryptographic nonce (good)
```

## Rate Limiting on Auth Endpoints

### Dangerous: No rate limiting on auth
```
router\.(post|put)\(["']/login(?!.*rateLimit|.*limiter) # Login without rate limit
router\.(post|put)\(["']/auth(?!.*rateLimit|.*limiter)  # Auth without rate limit
router\.post\(["']/register(?!.*rateLimit)               # Register without rate limit
router\.post\(["']/forgot-password(?!.*rateLimit)        # Reset without rate limit
```

### Safe: Rate-limited auth
```
rateLimit\(.*windowMs.*max:\s*\d{1,2}\b.*login # Rate-limited login (good)
app\.use\(["']/auth.*limiter\)           # Limiter on auth routes (good)
express-brute|rate-limiter-flexible      # Rate limiting libraries (good)
express-bouncer                          # IP-based brute-force prevention (good)
express-rate-limit.*windowMs             # Express rate limiter config (good)
svg-captcha|svgCaptcha\.create\(         # CAPTCHA on auth endpoints (good)
```

## CSRF Protection

### Dangerous: Missing CSRF on state changes
```
app\.post\((?!.*csurf|.*csrf|.*csrfToken) # POST without CSRF
app\.put\((?!.*csurf|.*csrf)             # PUT without CSRF
app\.delete\((?!.*csurf|.*csrf)          # DELETE without CSRF
```

### Safe: CSRF protection
```
csurf\(\)|csrf\(\)                       # CSRF middleware (good)
lusca\.csrf\(                            # Lusca CSRF (good)
csrfToken|req\.csrfToken\(\)             # CSRF token usage (good)
csrf-csrf                                # csrf-csrf library (good)
```

## Multi-Factor Authentication

### Safe: MFA implementations
```
speakeasy\.totp\.verify\(               # TOTP verification (good)
otplib\.authenticator\.verify\(          # OTPLib verification (good)
node-2fa|notp\.totp\.verify              # 2FA libraries (good)
authenticator\.generateSecret\(          # Secret generation (good)
```

## Account Lockout

### Dangerous: No lockout mechanism
Absence of account lockout after failed login attempts is a finding.

### Safe: Account lockout
```
maxLoginAttempts|loginAttempts            # Login attempt tracking (good)
lockUntil|isLocked|accountLocked         # Account lockout fields (good)
express-brute                            # Brute force protection (good)
```

## Authorization Middleware

### Dangerous: Missing authorization
```
router\.\w+\(["']/admin(?!.*isAdmin|.*authorize|.*role) # Admin route without auth check
router\.\w+\(["']/api(?!.*authenticate|.*auth|.*guard)  # API without auth middleware
```

### Safe: Authorization checks
```
(req,\s*res,\s*next).*req\.user\.role    # Role-based check (good)
authorize\(["']\w+["']\)|hasRole\(       # Authorization function (good)
req\.user\.\w+\s*===                     # User attribute check (good)
casl|accesscontrol|connect-roles         # RBAC/ABAC libraries (good)
```

## Token Storage

### Dangerous: Insecure token storage
```
localStorage\.setItem\(.*token           # Token in localStorage (XSS risk)
sessionStorage\.setItem\(.*token         # Token in sessionStorage
document\.cookie.*token.*=               # Token in non-HttpOnly cookie
```

### Safe: Secure token storage
```
httpOnly:\s*true.*token|token.*httpOnly  # HttpOnly cookie for tokens (good)
secure:\s*true.*sameSite                 # Secure + SameSite (good)
```

## NestJS Authentication

### Safe: NestJS auth patterns
```
@UseGuards\(AuthGuard\(["']jwt["']\)\)  # JWT guard (good)
@UseGuards\(LocalAuthGuard\)            # Local auth guard (good)
@UseGuards\(RolesGuard\)                # Roles guard (good)
@Roles\(["']\w+["']\)                   # Role decorator (good)
CanActivate.*implements                  # Custom guard (good)
```
