---
applyTo: "**/*controller*,**/*route*,**/*handler*,**/*endpoint*,**/*api*,**/*resolver*,**/*graphql*,**/*websocket*,**/*upload*,**/*Controller*.java,**/*Router*.ts,**/*views*.py"
---

# OWASP API Security Checks

When reviewing or generating API endpoint code, watch for these vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Server-Side Request Forgery (RULE-API-001, CWE-918)
- `RestTemplate.getForObject(userUrl, ...)` (Spring)
- `WebClient.create(userUrl)` (Spring WebFlux)
- `fetch(userUrl)` or `axios.get(userUrl)` on server (Node.js)
- `requests.get(userUrl)` (Python)
- URL parameter used to construct HTTP request without allowlist
- **Fix**: Validate URLs against allowlist of permitted domains. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254). Disable redirects.

### Mass Assignment (RULE-API-002, CWE-915)
- `@RequestBody User user` binding directly to entity (Spring)
- `Object.assign(entity, req.body)` (Node.js)
- `Model.create(req.body)` without field filtering (Mongoose)
- Missing `$fillable` or `$guarded` on Eloquent models (Laravel)
- **Fix**: Use DTOs with only the fields clients should set. Never bind directly to entities.

### Insecure File Upload (RULE-API-003, CWE-434)
- No file extension validation (allowlist of permitted extensions)
- Trusting client-supplied `Content-Type` header
- Using original user-supplied filename for storage
- Storing uploads inside web-accessible directory
- No file size limit configured
- **Fix**: Validate extension (allowlist), validate magic bytes, generate random filename, store outside webroot, enforce size limit

### Unvalidated Redirects (RULE-API-004, CWE-601)
- `response.sendRedirect(request.getParameter("url"))` (Java)
- `res.redirect(req.query.url)` (Express)
- `return redirect(request.args.get('next'))` (Flask)
- **Fix**: Validate redirect URL against allowlist. Use relative paths only.

### GraphQL Introspection in Production (RULE-API-005, CWE-200)
- `introspection: true` in GraphQL config (or not explicitly set to false)
- `graphiql: true` in production config
- **Fix**: Disable introspection and GraphiQL/playground in production builds.

### GraphQL Unbounded Queries (RULE-API-006, CWE-400)
- Missing query depth limiting
- Missing query complexity analysis
- No pagination limits on list resolvers
- **Fix**: Add depth limiting (max 10-15), complexity analysis, pagination with max page size

### WebSocket Missing Origin Validation (RULE-API-007, CWE-346)
- `setAllowedOrigins("*")` in Spring WebSocket config
- No Origin header validation in WS handshake
- **Fix**: Validate Origin header against allowlist. Require authentication on connection.

### Missing Request Body Validation (RULE-API-008, CWE-20)
- `@RequestBody` without `@Valid` or `@Validated` (Spring)
- No schema validation on JSON request bodies
- **Fix**: Add `@Valid` to all `@RequestBody` parameters. Validate Content-Type. Set request size limits.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/api/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/api/patterns/`.
