# API Security Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting REST, GraphQL, WebSocket, and general API vulnerabilities.

## RULE-API-001: Server-Side Request Forgery (SSRF)
- **Severity**: HIGH
- **CWE**: CWE-918 (Server-Side Request Forgery)
- **What to find**: User-controlled URLs passed to server-side HTTP clients
- **Patterns**:
  - `RestTemplate.getForObject(userUrl, ...)` (Spring)
  - `WebClient.create(userUrl)` (Spring WebFlux)
  - `HttpClient.send(HttpRequest.newBuilder(URI.create(userUrl)))` (Java 11+)
  - `fetch(userUrl)` or `axios.get(userUrl)` on server (Node.js)
  - `requests.get(userUrl)` (Python)
  - URL parameter used to construct HTTP request without allowlist validation
- **Fix**: Validate URLs against an allowlist of permitted domains. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.169.254). Disable redirects.
- **PoC**: `curl -X POST "https://<target>/api/fetch" -H "Content-Type: application/json" -d '{"url":"http://169.254.169.254/latest/meta-data/"}'` — if the response contains cloud instance metadata (AMI ID, instance type, IAM role), the server makes requests to user-controlled URLs without validation.
- **Reference**: Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md

## RULE-API-002: Mass Assignment
- **Severity**: MEDIUM
- **CWE**: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
- **What to find**: Request data bound directly to domain entities without field filtering
- **Patterns**:
  - `@RequestBody User user` binding directly to entity (Spring)
  - `@ModelAttribute` on entity class without `setAllowedFields()`
  - `Object.assign(entity, req.body)` (Node.js)
  - Missing DTO pattern: controller uses entity class as parameter type
  - MongoDB/Mongoose: `Model.create(req.body)` without field filtering
  - Laravel: Missing `$fillable` or `$guarded` on Eloquent models
- **Fix**: Use DTOs (Data Transfer Objects) with only the fields clients should set. Never bind directly to entities.
- **Reference**: Mass_Assignment_Cheat_Sheet.md

## RULE-API-003: Insecure File Upload
- **Severity**: HIGH
- **CWE**: CWE-434 (Unrestricted Upload of File with Dangerous Type)
- **What to find**: File upload endpoints without proper validation
- **Patterns**:
  - No file extension validation (allowlist of permitted extensions)
  - Trusting client-supplied `Content-Type` header
  - Using original user-supplied filename for storage
  - Storing uploads inside web-accessible directory (webroot)
  - No file size limit configured
  - No magic byte / file signature validation
  - Accepting archive files (ZIP, RAR) without extraction safeguards
- **Fix**: Validate extension (allowlist), validate magic bytes, generate random filename, store outside webroot, enforce size limit
- **PoC**: `curl -X POST "https://<target>/api/upload" -F "file=@test.html;type=image/png"` — if the server accepts the `.html` file (checking only Content-Type, not extension or magic bytes), then access `https://<target>/uploads/test.html` — if it renders as HTML, uploaded files can serve malicious content.
- **Reference**: File_Upload_Cheat_Sheet.md

## RULE-API-004: Unvalidated Redirects
- **Severity**: MEDIUM
- **CWE**: CWE-601 (URL Redirection to Untrusted Site)
- **What to find**: Redirect targets controlled by user input without validation
- **Patterns**:
  - `response.sendRedirect(request.getParameter("url"))` (Java)
  - `redirect:` + user input in Spring MVC return value
  - `res.redirect(req.query.url)` (Express)
  - `return redirect(request.args.get('next'))` (Flask)
  - `HttpResponseRedirect(request.GET['next'])` (Django)
  - `window.location = userInput` (client-side)
- **Fix**: Validate redirect URL against allowlist. Use relative paths only. Never redirect to user-supplied external URLs.
- **Reference**: Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md

## RULE-API-005: GraphQL Introspection Enabled in Production
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Information Exposure)
- **What to find**: GraphQL introspection and GraphiQL IDE enabled in production
- **Patterns**:
  - `introspection: true` in GraphQL config (or not explicitly set to false)
  - `graphiql: true` in production config
  - No `NoIntrospection` validation rule applied
  - `__schema` queries not blocked
- **Fix**: Disable introspection in production. Remove GraphiQL/playground in production builds.
- **Reference**: GraphQL_Cheat_Sheet.md

## RULE-API-006: GraphQL Query Depth/Complexity Not Limited
- **Severity**: MEDIUM
- **CWE**: CWE-400 (Uncontrolled Resource Consumption)
- **What to find**: No limits on GraphQL query depth or complexity (DoS vector)
- **Patterns**:
  - Missing query depth limiting (no `MaxQueryDepthInstrumentation` or `graphql-depth-limit`)
  - Missing query complexity analysis
  - No pagination limits on list resolvers
  - No timeout on resolver execution
- **Fix**: Add depth limiting (max 10-15), complexity analysis, pagination with max page size, and resolver timeouts
- **Reference**: GraphQL_Cheat_Sheet.md

## RULE-API-007: WebSocket Missing Origin Validation
- **Severity**: HIGH
- **CWE**: CWE-346 (Origin Validation Error)
- **What to find**: WebSocket connections accepted without validating the Origin header
- **Patterns**:
  - `setAllowedOrigins("*")` in Spring WebSocket config
  - No `checkOrigin()` override in `WebSocketHandler`
  - Missing Origin header validation in WS handshake handler
  - No authentication on WebSocket connect
- **Fix**: Validate Origin header against allowlist. Require authentication on connection.
- **PoC**: Create a test HTML page on a different origin: `<script>const ws=new WebSocket('wss://<target>/ws');ws.onopen=()=>ws.send('test');ws.onmessage=e=>document.title=e.data;</script>` — open it in a browser and check if the WebSocket connection succeeds. If it does, the server accepts connections from any origin.
- **Reference**: WebSocket_Security_Cheat_Sheet.md

## RULE-API-008: Missing Request Body Validation
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **What to find**: API endpoints accepting request bodies without validation
- **Patterns**:
  - `@RequestBody` without `@Valid` or `@Validated` (Spring)
  - No schema validation on JSON request bodies
  - Missing `Content-Type` validation (accepting any content type)
  - No request size limits configured
- **Fix**: Add `@Valid` to all `@RequestBody` parameters. Validate Content-Type. Set request size limits.
- **Reference**: REST_Security_Cheat_Sheet.md, Bean_Validation_Cheat_Sheet.md

## RULE-API-009: Verbose API Error Responses
- **Severity**: MEDIUM
- **CWE**: CWE-209 (Information Exposure Through Error Message)
- **What to find**: API error responses containing internal details
- **Patterns**:
  - Stack traces returned in error JSON
  - Database error messages in API responses
  - Internal paths or class names in error responses
  - `e.getMessage()` returned directly in ResponseEntity
  - `server.error.include-stacktrace=always` (Spring Boot)
- **Fix**: Return generic error messages with error codes. Log details server-side only.
- **Reference**: Error_Handling_Cheat_Sheet.md

## RULE-API-010: Missing Rate Limiting
- **Severity**: MEDIUM
- **CWE**: CWE-770 (Allocation of Resources Without Limits)
- **What to find**: API endpoints without rate limiting or throttling
- **Patterns**:
  - No rate limiting middleware/filter configured
  - No `@RateLimiter` or equivalent annotation
  - No API gateway throttling configuration
  - GraphQL without per-query rate limits
- **Fix**: Implement rate limiting per IP/user. Use API gateway throttling. Add circuit breakers.
- **Reference**: Denial_of_Service_Cheat_Sheet.md

## RULE-API-011: REST API Key in URL
- **Severity**: MEDIUM
- **CWE**: CWE-598 (Information Exposure Through Query Strings)
- **What to find**: API keys or tokens passed in URL query parameters
- **Patterns**:
  - `?apiKey=...` or `?api_key=...` in URL patterns
  - `?token=...` in URL patterns
  - `?access_token=...` in URL patterns
  - API key in URL logged in access logs
- **Fix**: Send API keys in `Authorization` header or request body. Never in URLs.
- **Reference**: REST_Security_Cheat_Sheet.md

## RULE-API-012: Missing Content-Type Validation
- **Severity**: LOW
- **CWE**: CWE-20
- **What to find**: API endpoints not validating request Content-Type
- **Patterns**:
  - No `consumes` attribute on endpoint mapping
  - Missing Content-Type check in middleware
  - `@RequestMapping` without `consumes = MediaType.APPLICATION_JSON_VALUE`
- **Fix**: Explicitly set `consumes` on endpoints. Reject requests with unexpected Content-Type.
- **Reference**: REST_Security_Cheat_Sheet.md

## RULE-API-013: Microservice Inter-Service Communication Insecure
- **Severity**: HIGH
- **CWE**: CWE-295 (Improper Certificate Validation)
- **What to find**: Microservices communicating over unencrypted channels or without mutual TLS
- **Patterns**:
  - `http://` URLs for inter-service calls
  - Missing mTLS configuration between services
  - Shared secrets for service-to-service auth (instead of short-lived tokens)
  - No service mesh or network policies
- **Fix**: Use mTLS for service-to-service communication. Use short-lived JWT tokens. Implement network policies.
- **PoC**: `grep -rnE 'http://' --include="*.java" --include="*.py" --include="*.yaml" . | grep -vE '(localhost|127\.0\.0\.1|example\.com|test)'` — matches with internal service hostnames confirm plaintext HTTP for inter-service calls. Also: `curl -v http://<internal-service>:8080/actuator/health` from within the cluster to verify no TLS is required.
- **Reference**: Microservices_Security_Cheat_Sheet.md
