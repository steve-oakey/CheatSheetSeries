# API Security Patterns: Node.js / Express

## Express Route Authorization

### Dangerous: Unprotected endpoints
```
app\.(post|put|delete|patch)\(["']/api(?!.*auth|.*guard|.*middleware) # Write endpoint without auth
router\.(post|put|delete)\(["']/(?!.*authenticate|.*authorize)       # Router write without auth
app\.get\(["']/api/users(?!.*auth|.*isAdmin)                         # User listing without auth
```

### Safe: Protected endpoints
```
app\.use\(["']/api.*authenticate\)       # Auth middleware on API routes (good)
router\.use\(.*passport\.authenticate    # Passport on router (good)
app\.all\(["']/api.*verifyToken\)        # Token verification (good)
```

## Input Validation

### Dangerous: Unvalidated input
```
req\.body\.\w+(?!.*validate|.*sanitize|.*joi|.*yup|.*zod) # Unvalidated body field
req\.params\.\w+(?!.*parseInt|.*Number|.*validate)        # Unvalidated URL param
req\.query\.\w+(?!.*validate|.*sanitize)                   # Unvalidated query param
```

### Safe: Input validation
```
joi\.object\(\{|Joi\.validate\(          # Joi validation (good)
yup\.object\(\{|\.validate\(             # Yup validation (good)
z\.object\(\{|zod\.object\(              # Zod validation (good)
express-validator|body\(["']\w+["']\)\.is # express-validator (good)
celebrate\(|Segments\.                   # Celebrate validation (good)
```

### NestJS Validation
```
ValidationPipe\(                         # NestJS validation pipe (good)
@IsString\(\)|@IsEmail\(\)|@IsInt\(\)    # class-validator decorators (good)
class-validator|class-transformer        # Validation libraries (good)
@Body\(\).*@UsePipes\(                   # Body with validation pipe (good)
```

## Mass Assignment / Over-posting

### Dangerous: Direct object spread from request
```
Object\.assign\(.*req\.body              # Object.assign with request body
\{.*\.\.\.req\.body\}                    # Spread operator with request body
Model\.create\(req\.body\)               # Direct model create from body
\.update\(req\.body\)|\.updateOne\(req\.body # Direct update from body
new \w+\(req\.body\)                     # Constructor with full request body
```

### Safe: Controlled assignment
```
\{.*\}.*=.*req\.body                     # Destructuring specific fields (good)
pick\(req\.body|_.pick\(req\.body        # Lodash pick (good)
allowedFields|whitelist.*req\.body       # Field allowlist (good)
```

## IDOR / Broken Object-Level Authorization

### Dangerous: Direct ID usage without ownership check
```
findById\(req\.params\.id\)(?!.*\.then.*user|.*user\.id) # findById without user check
\.findOne\(\{.*_id:\s*req\.params        # findOne by URL param (review ownership)
\.findByPk\(req\.params\.id\)            # Sequelize findByPk (review)
\.deleteOne\(\{.*_id:\s*req\.params      # Delete by URL param (review ownership)
```

### Safe: User-scoped queries
```
\.find\(\{.*user:\s*req\.user\._id       # User-scoped MongoDB query (good)
\.find\(\{.*userId:\s*req\.user\.id      # User-scoped query (good)
\.where\(\{.*userId:\s*req\.user\.id     # Sequelize user-scoped (good)
req\.user\.id\s*===|req\.user\._id.*equals # Ownership verification (good)
```

## Response Data Filtering

### Dangerous: Over-exposure of data
```
res\.json\(.*user\)(?!.*toJSON|.*select|.*project) # Full user object in response
\.find\(\)\.then\(.*res\.json\)          # All documents returned
toObject\(\)(?!.*transform)              # Mongoose toObject without transform
\.select\(["']-?__v["']\)               # Only excluding version field
```

### Safe: Filtered responses
```
\.select\(["']\w+\s+\w+["']\)           # Mongoose field selection (good)
\.project\(\{|attributes:\s*\[           # Field projection (good)
toJSON\(\{.*transform:                   # Transform on serialization (good)
\.map\(.*\{.*return.*\{                  # Manual field mapping (good)
```

## File Upload Security

### Dangerous: Unrestricted uploads
```
multer\(\)(?!\.)                          # Multer with no config
\.single\(["']\w+["']\)(?!.*fileFilter)   # Single file without filter
originalname.*path\.join\(               # Original filename in path (traversal risk)
```

### Safe: Secure uploads
```
multer\(\{.*fileFilter:                  # Multer with file filter (good)
multer\(\{.*limits:\s*\{.*fileSize       # Multer with size limit (good)
secure_filename\(|uuidv4\(\).*ext        # Safe filename generation (good)
```

## GraphQL Security (Express)

### Dangerous: GraphQL misconfigurations
```
graphiql:\s*true|playground:\s*true      # GraphiQL/Playground in production
depthLimit.*(?=.*\d{2,})                 # Depth limit too high
introspection:\s*true                    # Introspection enabled in production
```

### Safe: Secure GraphQL
```
graphql-depth-limit|depthLimit\(\d\)     # Query depth limit (good)
graphql-rate-limit|rateLimitDirective     # Rate limiting (good)
graphql-shield|shield\(                  # Authorization layer (good)
introspection:\s*false                   # Introspection disabled (good)
```

## Error Handling in APIs

### Dangerous: Verbose error responses
```
res\.status\(500\)\.json\(\{.*error:\s*err\.message # Error message exposed
res\.status\(\d+\)\.send\(.*err\.stack    # Stack trace in response
next\(err\)(?!.*errorHandler)             # Error forwarding without handler
```

### Safe: Sanitized error responses
```
res\.status\(\d+\)\.json\(\{.*error:\s*["'] # Generic error message (good)
app\.use\(.*err.*req.*res.*next.*\{       # Error handler middleware (good)
http-errors|createError\(\d+             # http-errors library (good)
```

## SSRF Prevention

### Dangerous: User-controlled HTTP requests
```
axios\.\w+\(.*req\.(body|query|params)   # Axios with user URL
fetch\(.*req\.|node-fetch\(.*req\.       # Fetch with user URL
http\.get\(.*req\.|https\.get\(.*req\.   # HTTP get with user URL
got\(.*req\.|request\(.*req\.            # Got/request with user URL
```

### Safe: SSRF prevention
```
new URL\(.*\.hostname.*allowedHosts      # URL hostname validation (good)
ssrf-req-filter|ssrf-agent               # SSRF protection library (good)
url\.parse\(.*\.protocol.*===.*https     # Protocol validation (good)
```

## API Rate Limiting

### Dangerous: No rate limiting
```
app\.use\(["']/api(?!.*rateLimit|.*limiter|.*throttle) # API without rate limiting
router\.use\((?!.*rateLimit|.*limiter)   # Router without rate limiting
```

### Safe: Rate-limited APIs
```
express-rate-limit                       # Rate limiting middleware (good)
rate-limiter-flexible                    # Flexible rate limiter (good)
app\.use\(.*limiter\)                    # Limiter applied globally (good)
windowMs:\s*\d+.*max:\s*\d+             # Rate limit config (good)
```

## WebSocket Security

### Dangerous: Unprotected WebSockets
```
wss\.on\(["']connection["'],\s*function  # WebSocket without auth
io\.on\(["']connection["'](?!.*auth|.*middleware) # Socket.io without auth
```

### Safe: Protected WebSockets
```
io\.use\(.*authenticate|io\.use\(.*jwt   # Socket.io auth middleware (good)
ws\.on\(["']message.*verify              # Message verification (good)
socket\.handshake\.auth                  # Socket.io handshake auth (good)
```
