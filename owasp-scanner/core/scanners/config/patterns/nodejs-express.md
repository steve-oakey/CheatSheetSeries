# Configuration Patterns: Node.js / Express

## Express Security Headers (Helmet)

### Dangerous: Missing or disabled headers
```
app\.disable\(["']x-powered-by["']\)     # Only hides Express (Helmet does more)
contentSecurityPolicy:\s*false           # CSP disabled
crossOriginEmbedderPolicy:\s*false       # COEP disabled
crossOriginOpenerPolicy:\s*false         # COOP disabled
crossOriginResourcePolicy:\s*false       # CORP disabled
hsts:\s*false|hsts:.*maxAge:\s*0         # HSTS disabled
```

### Safe: Helmet defaults
```
app\.use\(helmet\(\)\)                    # Helmet with defaults (good)
helmet\(\{.*\}\)                          # Helmet with custom config (review)
```

Absence of `helmet` in Express apps is a finding.

## CORS Configuration

### Dangerous: Overly permissive CORS
```
cors\(\)(?!\(\{)                          # cors() with no options (allows all origins)
origin:\s*true|origin:\s*\*|origin:\s*["']\* # Wildcard origin
credentials:\s*true.*origin:\s*true      # Credentials + reflect origin
Access-Control-Allow-Origin.*\*          # Manual wildcard header
```

### Safe: Restrictive CORS
```
origin:\s*\[["']https://                 # Explicit origin list (good)
origin:\s*["']https://\w+                # Single specific origin (good)
origin:\s*function|origin:\s*\(          # Dynamic origin validation (review)
```

## Session Configuration

### Dangerous: Insecure session config
```
secret:\s*["'][a-z]{1,10}["']            # Weak session secret
secret:\s*["']secret["']|secret:\s*["']password # Common weak secrets
resave:\s*true                           # Session resave enabled
saveUninitialized:\s*true                # Uninitialized sessions saved
cookie:\s*\{(?!.*secure)                 # Cookie without secure flag
cookie:.*secure:\s*false                 # Secure flag disabled
store:\s*undefined|(?!.*store:)          # Missing session store (uses MemoryStore)
```

### Safe: Secure session config
```
secret:\s*process\.env\.|secret:\s*config\. # Secret from environment (good)
resave:\s*false                           # No unnecessary resave (good)
saveUninitialized:\s*false                # No empty sessions (good)
cookie:.*secure:\s*true                   # Secure cookie (good)
cookie:.*httpOnly:\s*true                 # HttpOnly cookie (good)
cookie:.*sameSite:\s*["'](strict|lax)     # SameSite policy (good)
store:\s*new \w+Store\(                   # External session store (good)
connect-redis|connect-mongo|connect-pg    # Production session store (good)
```

## Environment & Secret Management

### Dangerous: Hardcoded secrets
```
["'](password|secret|api_key|token)\w*["']\s*[:=]\s*["'][^"'$] # Hardcoded secret
JWT_SECRET\s*=\s*["'][a-zA-Z0-9]{1,20}["'] # Short JWT secret
DB_PASSWORD\s*=\s*["'][^"']+["']         # Hardcoded DB password
mongodb\+srv://\w+:\w+@                  # Hardcoded MongoDB connection string
```

### Safe: Environment-based secrets
```
process\.env\.                            # Environment variable (good)
dotenv\.config\(\)|require\(["']dotenv   # dotenv loaded (good)
config\(\)\.get\(|config\.\w+\.secret    # Config module (good)
```

## Rate Limiting

### Dangerous: No rate limiting
Absence of rate limiting middleware on authentication endpoints is a finding.

### Safe: Rate limiting
```
express-rate-limit|rateLimit\(           # express-rate-limit (good)
app\.use\(.*limiter\)|app\.use\(.*rateLimit # Rate limiter applied (good)
windowMs:.*max:                           # Rate limit config (good)
```

## Body Parser Configuration

### Dangerous: Overly permissive body parsing
```
express\.json\(\{.*limit:\s*["']\d+mb   # Review if limit is very large
express\.urlencoded\(\{.*extended:\s*true.*limit:\s*["']\d+mb # Large limit
bodyParser\.raw\(\)                      # Raw body parsing (review need)
```

### Safe: Restrictive body parsing
```
express\.json\(\{.*limit:\s*["'](100kb|1mb|10kb) # Reasonable limit (good)
express\.urlencoded\(\{.*extended:\s*false # Simple URL encoding (good)
```

## HTTPS / TLS Configuration

### Dangerous: Insecure TLS
```
https\.createServer\(.*rejectUnauthorized:\s*false # Skip TLS verification
NODE_TLS_REJECT_UNAUTHORIZED.*0          # Disable TLS verification globally
process\.env\.NODE_TLS_REJECT_UNAUTHORIZED # Disabling TLS verification
```

### Safe: Secure TLS
```
app\.use\(.*enforce\.HTTPS\(\)           # HTTPS enforcement (good)
hsts\(.*maxAge:\s*\d{7,}                # HSTS with long max-age (good)
trust proxy.*1|trust proxy.*loopback    # Trust proxy behind LB (good)
```

## Error Handling

### Dangerous: Verbose errors
```
app\.use\(.*err.*res\.send\(.*err\.stack # Stack trace in response
app\.use\(.*err.*res\.json\(.*message:\s*err\.message # Error message exposed
res\.status\(500\)\.send\(.*err          # Raw error sent to client
```

### Safe: Error handling
```
app\.use\(.*err.*res\.status\(500\).*json\(\{.*error.*"Internal # Generic error (good)
express-async-errors                      # Async error handling (good)
process\.on\(["']uncaughtException       # Uncaught exception handler (good)
process\.on\(["']unhandledRejection      # Unhandled rejection handler (good)
```

## Logging Configuration

### Dangerous: Logging sensitive data
```
console\.log\(.*password|console\.log\(.*secret # Logging secrets
console\.log\(.*req\.headers\[["']authorization # Logging auth headers
morgan\(["']combined|morgan\(["']dev     # Morgan logging (review log level)
```

### Safe: Structured logging
```
winston\.createLogger\(|const logger.*winston # Winston logger (good)
pino\(\)|const logger.*pino              # Pino logger (good)
morgan\(.*\{.*stream:                    # Morgan with file stream (good)
```

## Database Connection Security

### Dangerous: Insecure DB connections
```
ssl:\s*false|ssl:\s*\{.*rejectUnauthorized:\s*false # SSL disabled
mongodb://.*localhost(?!.*test)           # Local MongoDB in non-test
createPool\(\{(?!.*ssl)                  # MySQL pool without SSL
```

### Safe: Secure DB connections
```
ssl:\s*true|ssl:\s*\{.*rejectUnauthorized:\s*true # SSL enabled (good)
mongodb\+srv://                          # MongoDB SRV (TLS by default, good)
ssl:\s*\{.*ca:                           # Custom CA certificate (good)
```

## File Upload Configuration

### Dangerous: Unrestricted uploads
```
multer\(\{(?!.*limits|.*fileFilter)      # Multer without limits or filter
limits:\s*\{.*fileSize:\s*\d{9,}         # Very large file size limit
```

### Safe: Restricted uploads
```
multer\(\{.*limits:.*fileSize             # Multer with size limit (good)
fileFilter:.*mimetype|fileFilter:.*ext   # File type filtering (good)
multer\.diskStorage\(\{.*filename:       # Custom filename (review for path traversal)
```

## NestJS-Specific Configuration

### Dangerous: NestJS misconfigurations
```
@All\(\)|@Public\(\)                     # Unprotected endpoints (review)
ValidationPipe\(\{.*whitelist:\s*false   # Whitelist disabled
enableCors\(\)(?!\()                     # CORS without config
```

### Safe: NestJS security
```
@UseGuards\(AuthGuard\)                  # Auth guard applied (good)
ValidationPipe\(\{.*whitelist:\s*true    # Whitelist enabled (good)
ValidationPipe\(\{.*forbidNonWhitelisted # Non-whitelisted forbidden (good)
ThrottlerGuard|@Throttle\(              # Rate limiting guard (good)
```

## Event Loop Blocking (Nodejs_Security_Cheat_Sheet)

### Dangerous: Synchronous operations in request handlers
```
readFileSync\(.*req\.|readFileSync\(.*request  # Sync file read in request handler
writeFileSync\(.*req\.|writeFileSync\(.*request # Sync file write in request handler
readdirSync\(.*req\.|mkdirSync\(.*req\.  # Sync directory ops in request handler
appendFileSync\(|unlinkSync\(            # Sync filesystem ops (review if in handler)
execSync\(|spawnSync\(                   # Sync child process in handler
```

### Event loop monitoring
```
# Absence of event loop monitoring is a finding in production Node.js apps
toobusy-js|toobusy\(\)                  # Event loop overload detection (good)
overload-protection                      # Overload protection middleware (good)
res\.status\(503\).*toobusy|503.*overload # 503 on overload (good)
```

## Node.js Permission Model (Nodejs_Security_Cheat_Sheet)

### Safe: Runtime permission restrictions (Node.js v20+)
```
--permission                             # Permission model flag (good)
--allow-fs-read=                         # Restricted filesystem read (good)
--allow-fs-write=                        # Restricted filesystem write (good)
--allow-child-process                    # Explicit child process permission (good)
--allow-worker                           # Explicit worker thread permission (good)
```
