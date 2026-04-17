# Configuration Patterns: Python (Django / Flask / FastAPI)

## Django Security Settings (settings.py)

### Dangerous: Insecure settings
```
DEBUG\s*=\s*True                        # Debug mode enabled
SECRET_KEY\s*=\s*["'][^$\{]            # Hardcoded secret key (not from env)
ALLOWED_HOSTS\s*=\s*\[["']\*["']\]     # Wildcard allowed hosts
ALLOWED_HOSTS\s*=\s*\[\]               # Empty allowed hosts (allows all in DEBUG)
SESSION_COOKIE_SECURE\s*=\s*False       # Session cookie not HTTPS-only
CSRF_COOKIE_SECURE\s*=\s*False          # CSRF cookie not HTTPS-only
SESSION_COOKIE_HTTPONLY\s*=\s*False      # Session cookie accessible to JS
SECURE_SSL_REDIRECT\s*=\s*False         # HTTPS redirect disabled
SECURE_HSTS_SECONDS\s*=\s*0             # HSTS disabled
SECURE_BROWSER_XSS_FILTER\s*=\s*False   # XSS filter disabled
X_FRAME_OPTIONS\s*=.*ALLOWALL           # Clickjacking protection disabled
SECURE_CONTENT_TYPE_NOSNIFF\s*=\s*False # Content-type sniffing allowed
```

### Safe: Secure settings (verify these are present)
```
DEBUG\s*=\s*False                        # Debug disabled (good)
SECRET_KEY\s*=\s*os\.environ|config\(   # Key from environment (good)
SESSION_COOKIE_SECURE\s*=\s*True        # HTTPS-only session cookie (good)
CSRF_COOKIE_SECURE\s*=\s*True           # HTTPS-only CSRF cookie (good)
SESSION_COOKIE_HTTPONLY\s*=\s*True       # HttpOnly cookie (good)
SECURE_SSL_REDIRECT\s*=\s*True          # HTTPS redirect (good)
SECURE_HSTS_SECONDS\s*=\s*\d{5,}        # HSTS with reasonable duration (good)
```

### Missing security middleware check
```
# Verify these are in MIDDLEWARE:
SecurityMiddleware                       # Django security middleware
CsrfViewMiddleware                       # CSRF protection
XFrameOptionsMiddleware                  # Clickjacking protection
```

## Flask Security Configuration

### Dangerous: Insecure Flask config
```
app\.debug\s*=\s*True                   # Debug mode enabled
app\.config\[.SECRET_KEY.\]\s*=\s*["'][^$] # Hardcoded secret key
app\.secret_key\s*=\s*["']              # Hardcoded secret key
SESSION_COOKIE_SECURE.*False             # Insecure session cookie
SESSION_COOKIE_HTTPONLY.*False            # Non-HttpOnly cookie
```

### Safe: Secure Flask config
```
app\.config\.from_envvar\(              # Config from environment (good)
os\.environ\.get\(.SECRET_KEY           # Key from environment (good)
Talisman\(app                           # Flask-Talisman security headers (good)
SESSION_COOKIE_SECURE.*True              # HTTPS session cookie (good)
```

## FastAPI Security Configuration

### Dangerous: Insecure FastAPI config
```
CORSMiddleware.*allow_origins=\["?\*    # Wildcard CORS origin
CORSMiddleware.*allow_credentials=True.*allow_origins=\["?\* # Wildcard + credentials
allow_methods=\["?\*                    # All methods allowed
allow_headers=\["?\*                    # All headers allowed
```

### Safe: Restrictive CORS
```
allow_origins=\[("https|"http://localhost) # Specific origins only (good)
allow_methods=\["(GET|POST|PUT)          # Specific methods (good)
```

## CORS Configuration (all frameworks)

### Django CORS (django-cors-headers)
```
CORS_ALLOW_ALL_ORIGINS\s*=\s*True       # Wildcard CORS (dangerous)
CORS_ORIGIN_ALLOW_ALL\s*=\s*True        # Legacy wildcard CORS (dangerous)
CORS_ALLOW_CREDENTIALS\s*=\s*True.*CORS_ALLOW_ALL # Credentials + wildcard
CORS_ALLOW_HEADERS.*\*                  # All headers allowed
```

### Safe: Django CORS
```
CORS_ALLOWED_ORIGINS\s*=\s*\[           # Explicit origin list (good)
CORS_ORIGIN_WHITELIST\s*=\s*\[          # Legacy explicit list (good)
```

## Secret Management

### Dangerous: Hardcoded secrets in Python code
```
["'](password|secret|api_key|token|aws_)\w*["']\s*[:=]\s*["'][^"'$\{] # Hardcoded secret
DATABASE_URL\s*=\s*["']postgres          # Hardcoded database URL
AWS_ACCESS_KEY_ID\s*=\s*["']AKIA        # Hardcoded AWS key
DATABASES\s*=.*PASSWORD.*["'][A-Za-z0-9] # Hardcoded DB password
```

### Safe: Environment-based secrets
```
os\.environ\.get\(|os\.getenv\(         # Environment variable (good)
from decouple import config             # python-decouple (good)
config\(["'](SECRET|PASSWORD|KEY)       # Decouple config (good)
settings\.\w+_KEY|settings\.\w+_SECRET  # Settings module reference (good)
```

## Logging Configuration

### Dangerous: Logging sensitive data
```
logger\.\w+\(.*password|logging\.\w+\(.*password  # Logging passwords
logger\.\w+\(.*secret|logging\.\w+\(.*token        # Logging secrets
logger\.\w+\(.*request\.META\[.HTTP_AUTHORIZATION   # Logging auth headers
print\(.*password|print\(.*secret|print\(.*token    # Print sensitive data
```

### Safe: Structured logging
```
import structlog                        # Structured logging library (good)
structlog\.get_logger\(                 # Structured logger (good)
logging\.config\.dictConfig\(           # Centralized logging config (good)
```

## Database Configuration

### Dangerous: Insecure database settings
```
DATABASES.*sqlite3.*(?=.*production)    # SQLite in production
CONN_MAX_AGE.*None                      # Unlimited connection lifetime
sslmode.*disable|ssl.*False             # SSL disabled for DB connection
```

### Safe: Secure database config
```
sslmode.*require|ssl.*True              # SSL enabled (good)
CONN_MAX_AGE.*\d+                       # Connection timeout set (good)
dj_database_url\.config\(              # Database URL from env (good)
```

## File Upload Configuration

### Dangerous: Unrestricted file uploads
```
FILE_UPLOAD_MAX_MEMORY_SIZE.*\d{9,}     # Very large upload limit
DATA_UPLOAD_MAX_MEMORY_SIZE.*None        # No upload size limit
MEDIA_ROOT.*=.*BASE_DIR                  # Media in project root
```

### Safe: Restricted file uploads
```
FILE_UPLOAD_MAX_MEMORY_SIZE.*\d{6,8}    # Reasonable upload limit (good)
content_type.*in.*ALLOWED_TYPES          # Content-type validation (good)
FileExtensionValidator\(                 # Extension validation (good)
```

## Error Handling Configuration

### Dangerous: Verbose errors in production
```
DEBUG\s*=\s*True.*(?=.*production)       # Debug in production
PROPAGATE_EXCEPTIONS.*True               # Exceptions propagated
app\.config\[.PROPAGATE_EXCEPTIONS.\]\s*=\s*True # Flask verbose errors
```

### Safe: Error handling
```
@app\.errorhandler\(\d+\)               # Flask error handlers (good)
handler\d+\s*=\s*                        # Django error handler views (good)
ADMINS\s*=\s*\[                          # Admin notification list (good)
```
