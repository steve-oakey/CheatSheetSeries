# Authentication Patterns: Python (Django / Flask / FastAPI)

## Django Authentication

### Dangerous: Custom auth bypasses
```
@login_required.*(?=.*EXEMPT)           # Login required with exemptions
AUTHENTICATION_BACKENDS.*AllowAll       # Permissive auth backend
authenticate\(.*\)(?!.*if.*None)        # authenticate() without null check
login\(request,.*\)(?!.*authenticate)   # login() without prior authenticate()
@csrf_exempt                            # CSRF protection disabled
```

### Safe: Django auth
```
@login_required                          # Login required decorator (good)
LoginRequiredMixin                       # CBV login mixin (good)
PermissionRequiredMixin                  # Permission mixin (good)
@permission_required\(                   # Permission decorator (good)
from django\.contrib\.auth import authenticate # Standard auth (good)
```

## Django Password Configuration

### Dangerous: Weak password settings
```
AUTH_PASSWORD_VALIDATORS\s*=\s*\[\]     # No password validators
PASSWORD_HASHERS.*MD5|PASSWORD_HASHERS.*SHA1 # Weak hashers
PBKDF2PasswordHasher.*iterations.*\d{1,4}\b # Low PBKDF2 iterations
```

### Safe: Strong password settings
```
AUTH_PASSWORD_VALIDATORS.*MinimumLength  # Minimum length validator (good)
AUTH_PASSWORD_VALIDATORS.*CommonPassword # Common password validator (good)
AUTH_PASSWORD_VALIDATORS.*NumericPassword # Numeric password validator (good)
PASSWORD_HASHERS.*Argon2|PASSWORD_HASHERS.*BCrypt # Strong hashers (good)
PASSWORD_HASHERS.*PBKDF2.*(?=.*iterations.*\d{5,}) # High iteration PBKDF2 (good)
```

## Flask Authentication (Flask-Login)

### Dangerous: Insecure session/auth
```
login_manager\.session_protection\s*=\s*None  # No session protection
REMEMBER_COOKIE_SECURE\s*=\s*False      # Remember-me cookie not HTTPS
REMEMBER_COOKIE_HTTPONLY\s*=\s*False     # Remember-me accessible to JS
@login_manager\.unauthorized_handler.*redirect.*(?!.*login) # Bad redirect
```

### Safe: Flask-Login
```
@login_required                          # Login required decorator (good)
login_manager\.session_protection\s*=.*strong # Strong session protection (good)
login_user\(.*remember=False             # No persistent login (good)
REMEMBER_COOKIE_SECURE\s*=\s*True       # Secure remember cookie (good)
current_user\.is_authenticated           # Proper auth check (good)
```

## FastAPI Authentication

### Dangerous: Missing auth on endpoints
```
@app\.(get|post|put|delete|patch)\((?!.*dependencies) # Endpoint without dependencies
async def \w+\((?!.*Depends\(|.*current_user)         # Handler without auth dependency
```

### Safe: FastAPI auth
```
Depends\(get_current_user\)             # Auth dependency injection (good)
OAuth2PasswordBearer\(                   # OAuth2 bearer scheme (good)
HTTPBearer\(\)                           # HTTP bearer auth (good)
Security\(                               # Security dependency (good)
```

## JWT Token Handling

### Dangerous: Insecure JWT
```
jwt\.decode\(.*verify=False|jwt\.decode\(.*options=\{.*"verify.*False # Unverified JWT
jwt\.decode\(.*algorithms=\["none"\]    # "none" algorithm accepted
jwt\.encode\(.*algorithm=.HS256.*SECRET.*["'][a-z]{1,8}["'] # Weak HS256 secret
```

### Safe: Secure JWT
```
jwt\.decode\(.*algorithms=\["RS256"\]   # RSA verification (good)
jwt\.decode\(.*verify=True              # Verification enabled (good)
jwt\.decode\(.*key=.*public_key         # Public key verification (good)
PyJWT|python-jose|authlib               # Established JWT libraries (good)
```

## Session Management

### Django sessions
```
SESSION_ENGINE.*file|SESSION_ENGINE.*cookie # File/cookie sessions (review)
SESSION_COOKIE_AGE.*\d{7,}              # Very long session lifetime
SESSION_EXPIRE_AT_BROWSER_CLOSE.*False  # Sessions persist after close
SESSION_SAVE_EVERY_REQUEST.*False        # Session fixation risk
```

### Flask sessions
```
PERMANENT_SESSION_LIFETIME.*timedelta\(days=\d{2,} # Very long session
app\.permanent_session_lifetime.*\d{7,}  # Very long session (seconds)
session\.permanent\s*=\s*False           # Non-permanent sessions
```

### Safe: Session config
```
SESSION_ENGINE.*cache|SESSION_ENGINE.*db  # Server-side sessions (good)
SESSION_COOKIE_AGE.*\d{3,5}\b            # Reasonable session lifetime (good)
SESSION_EXPIRE_AT_BROWSER_CLOSE.*True    # Close on browser close (good)
```

## Rate Limiting

### Django rate limiting (django-ratelimit / DRF throttling)
```
# Verify rate limiting exists on auth endpoints:
DEFAULT_THROTTLE_RATES                   # DRF throttle rates defined (good)
@ratelimit\(                             # django-ratelimit decorator (good)
UserRateThrottle|AnonRateThrottle        # DRF throttle classes (good)
```

### Flask rate limiting (Flask-Limiter)
```
Limiter\(app                             # Flask-Limiter configured (good)
@limiter\.limit\(                        # Rate limit decorator (good)
```

### FastAPI rate limiting
```
slowapi\.Limiter|from slowapi            # slowapi rate limiter (good)
@limiter\.limit\(                        # Rate limit decorator (good)
```

Absence of rate limiting on `/login`, `/auth`, `/token`, or `/api/token` endpoints is a finding.

## Multi-Factor Authentication

### Django MFA (django-otp / django-mfa2)
```
django_otp|django_mfa                   # MFA libraries present (good)
OTPMiddleware                            # OTP middleware enabled (good)
verify_token\(|verify_is_otp            # Token verification (good)
```

### Safe: MFA verification
```
totp\.verify\(|\.verify_token\(         # TOTP verification (good)
pyotp\.TOTP\(                            # PyOTP TOTP (good)
```

## Password Hashing (non-Django)

### Dangerous: Weak hashing
```
hashlib\.md5\(|hashlib\.sha1\(           # Weak hash for passwords
hashlib\.sha256\(.*password              # SHA256 for passwords (no salt/iterations)
hmac\.new\(.*md5|hmac\.new\(.*sha1       # Weak HMAC
```

### Safe: Strong password hashing
```
bcrypt\.hashpw\(|bcrypt\.gensalt\(      # bcrypt (good)
argon2\.PasswordHasher\(\)              # Argon2 (good)
passlib\.hash\.\w+\.hash\(              # passlib hashing (good)
scrypt\(|hashlib\.scrypt\(              # scrypt (good)
```

## OAuth/OIDC

### Dangerous: Insecure OAuth
```
verify=False.*token|token.*verify=False  # Unverified token
state=None|state=""                      # Missing OAuth state parameter
OAUTHLIB_INSECURE_TRANSPORT.*1          # Insecure transport allowed
os\.environ\[.OAUTHLIB_INSECURE        # Insecure transport env var
```

### Safe: Secure OAuth
```
authlib\.integrations                    # Authlib integration (good)
from social_django|social_core          # Python Social Auth (good)
flow\.fetch_token\(.*authorization_response # OAuth code exchange (good)
```
