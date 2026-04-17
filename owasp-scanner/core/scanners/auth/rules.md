# Authentication & Authorization Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting authentication, authorization, and session management vulnerabilities.

## RULE-AUTH-001: Weak Password Hashing
- **Severity**: CRITICAL
- **CWE**: CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- **What to find**: Passwords hashed with weak or fast algorithms
- **Patterns**:
  - `MD5` used for passwords: `MessageDigest.getInstance("MD5")`, `md5(password)`, `hashlib.md5`
  - `SHA-1` used for passwords: `MessageDigest.getInstance("SHA-1")`, `sha1(password)`
  - `SHA-256` without salt/iteration: `MessageDigest.getInstance("SHA-256")` for passwords
  - bcrypt with work factor < 10
  - PBKDF2 with < 600,000 iterations (HMAC-SHA256) or < 1,400,000 (HMAC-SHA1)
- **Fix**: Use Argon2id (m=19456, t=2, p=1), scrypt (N=2^17, r=8, p=1), or bcrypt (work factor >= 10)
- **PoC**: `grep -rn 'MD5\|SHA-1\|MessageDigest.getInstance' --include="*.java" . | grep -i password` — any match near password handling confirms weak hashing. Alternatively: `python3 -c "import hashlib,time;s=time.time();hashlib.md5(b'test').hexdigest();print(f'MD5: {time.time()-s:.6f}s')"` shows MD5 completes in microseconds, making brute force feasible.
- **Reference**: Password_Storage_Cheat_Sheet.md

## RULE-AUTH-002: Hardcoded Credentials
- **Severity**: CRITICAL
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **What to find**: Passwords, API keys, or tokens embedded directly in source code
- **Patterns**:
  - `password = "..."` or `password = '...'` (string literal assignment)
  - `apiKey = "..."`, `api_key = "..."`, `API_KEY = "..."`
  - `secret = "..."`, `SECRET_KEY = "..."`
  - `token = "..."` with literal value
  - `Authorization: Bearer <literal_token>`
  - `jdbc:.*password=<literal>` in connection strings
- **Fix**: Use environment variables, vault services, or externalized configuration
- **PoC**: `grep -rnE '(password|apiKey|secret|token)\s*=\s*"[^"]+"' --include="*.java" --include="*.py" --include="*.js" .` — any match with a literal string value (not a variable reference) confirms hardcoded credentials. Redact the actual values when reporting.
- **Reference**: Secrets_Management_Cheat_Sheet.md

## RULE-AUTH-003: JWT Algorithm None
- **Severity**: CRITICAL
- **CWE**: CWE-347 (Improper Verification of Cryptographic Signature)
- **What to find**: JWT configured to accept the `none` algorithm
- **Patterns**:
  - `Algorithm.none()`
  - `"alg": "none"` in token handling
  - JWT verification without explicit algorithm specification
  - `setAllowedClockSkew` with large values
- **Fix**: Always specify algorithm explicitly: `Algorithm.HMAC256(secret)`. Never accept `none`.
- **PoC**: `python3 -c "import base64,json;h=base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=');p=base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=');print(f'{h.decode()}.{p.decode()}.')"` — send the resulting token as `Authorization: Bearer <token>`. If the server accepts it, the JWT `none` algorithm is permitted.
- **Reference**: JSON_Web_Token_for_Java_Cheat_Sheet.md

## RULE-AUTH-004: JWT Missing Validation Claims
- **Severity**: HIGH
- **CWE**: CWE-347
- **What to find**: JWT verification that doesn't validate essential claims
- **Patterns**:
  - `JWT.decode()` without `.verify()` (decoding without verification)
  - Missing `withIssuer()` validation
  - Missing `withAudience()` or `withClaim("aud", ...)` validation
  - Missing `withExpiresAt()` or no expiration check
  - Weak HMAC secret (< 64 characters)
- **Fix**: Validate issuer, audience, expiration, and not-before claims. Use 64+ char secrets for HMAC.
- **PoC**: Decode an existing token at `jwt.io` and check for missing `iss`, `aud`, or `exp` claims. Create a token with an expired `exp` value and send it: `curl -H "Authorization: Bearer <expired-token>" https://<target>/api/protected` — if the request succeeds, expiration is not validated.
- **Reference**: JSON_Web_Token_for_Java_Cheat_Sheet.md

## RULE-AUTH-005: Session Token in localStorage
- **Severity**: HIGH
- **CWE**: CWE-922 (Insecure Storage of Sensitive Information)
- **What to find**: Authentication tokens stored in Web Storage (accessible via XSS)
- **Patterns**:
  - `localStorage.setItem("token", ...)` or `localStorage.setItem("jwt", ...)`
  - `localStorage.setItem("auth", ...)` or `localStorage.setItem("session", ...)`
  - `sessionStorage.setItem("token", ...)`
  - Token retrieval: `localStorage.getItem("token")`
- **Fix**: Store tokens in httpOnly cookies (not accessible via JavaScript). Use `HttpInterceptor` for token attachment.
- **PoC**: Open the browser console on the application page and run: `console.log(localStorage.getItem('token') || sessionStorage.getItem('token'))` — if a JWT or session token is printed, it is accessible to any XSS payload.
- **Reference**: JSON_Web_Token_for_Java_Cheat_Sheet.md, Session_Management_Cheat_Sheet.md

## RULE-AUTH-006: Session Fixation
- **Severity**: HIGH
- **CWE**: CWE-384 (Session Fixation)
- **What to find**: Missing session regeneration after authentication
- **Patterns**:
  - Login handler without `session.invalidate()` + new session creation (Java)
  - Login without `request.getSession(true)` after invalidating old session
  - Missing `session_regenerate_id(true)` after login (PHP)
  - Missing `request.session.cycle_id` after login (Rails)
  - `SessionCreationPolicy.ALWAYS` without regeneration logic
- **Fix**: Invalidate old session and create new one immediately after successful login
- **PoC**: Record the session cookie before login: `curl -v https://<target>/login 2>&1 | grep Set-Cookie`. Then login and compare: `curl -v -X POST -d 'user=test&pass=test' https://<target>/login 2>&1 | grep Set-Cookie` — if the session ID remains the same after successful authentication, the session is not regenerated.
- **Reference**: Session_Management_Cheat_Sheet.md

## RULE-AUTH-007: Missing Authorization Checks
- **Severity**: HIGH
- **CWE**: CWE-862 (Missing Authorization)
- **What to find**: Controller/endpoint methods without authorization annotations
- **Patterns**:
  - `@RequestMapping` or `@GetMapping`/`@PostMapping` without `@PreAuthorize`, `@Secured`, or `@RolesAllowed`
  - `@RestController` with `permitAll()` on sensitive endpoints
  - Missing authorization middleware in Express/Node.js routes
  - Django views without `@login_required` or `@permission_required`
- **Fix**: Add authorization checks on every endpoint. Use deny-by-default access control.
- **PoC**: `curl -s -o /dev/null -w "%{http_code}" https://<target>/api/admin/users` without any authentication header — if the response is `200` instead of `401` or `403`, the endpoint lacks authorization checks.
- **Reference**: Authorization_Cheat_Sheet.md

## RULE-AUTH-008: IDOR - Insecure Direct Object Reference
- **Severity**: HIGH
- **CWE**: CWE-639 (Authorization Bypass through User-Controlled Key)
- **What to find**: Direct use of user-supplied IDs to access resources without ownership verification
- **Patterns**:
  - `findById(request.getParameter("id"))` without ownership check
  - `/api/users/{id}` without verifying requesting user owns the resource
  - `@PathVariable Long id` used directly in database query without ACL check
  - Sequential/predictable resource IDs in URLs
- **Fix**: Verify resource ownership against authenticated user. Use indirect references or UUIDs.
- **PoC**: Authenticate as User A, note a resource ID (e.g., order `123`). Then: `curl -H "Authorization: Bearer <userA-token>" https://<target>/api/orders/124` — if the response returns another user's order data, the endpoint does not verify resource ownership.
- **Reference**: Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.md

## RULE-AUTH-009: User Enumeration via Error Messages
- **Severity**: MEDIUM
- **CWE**: CWE-204 (Observable Response Discrepancy)
- **What to find**: Different error messages for valid vs invalid usernames during authentication
- **Patterns**:
  - `"Invalid username"` (different from password error)
  - `"User not found"` in login response
  - `"Account does not exist"` in login or forgot-password
  - Different HTTP status codes for user-exists vs user-not-found
  - Different response times for valid vs invalid usernames
- **Fix**: Use identical generic messages: `"Invalid username or password"`. Ensure constant-time comparison.
- **Reference**: Authentication_Cheat_Sheet.md

## RULE-AUTH-010: Weak Session Configuration
- **Severity**: MEDIUM
- **CWE**: CWE-613 (Insufficient Session Expiration)
- **What to find**: Session timeout too long or not enforced
- **Patterns**:
  - Session idle timeout > 30 minutes for standard apps
  - Session idle timeout > 5 minutes for high-value apps (financial, healthcare)
  - Absolute session timeout > 8 hours
  - No server-side session invalidation on logout
  - Session ID in URL parameters
  - Identifiable session cookie names: `JSESSIONID`, `PHPSESSID`, `ASP.NET_SessionId`
- **Fix**: Set idle timeout (2-30 min based on risk). Set absolute timeout (4-8 hours). Invalidate server-side on logout.
- **Reference**: Session_Management_Cheat_Sheet.md

## RULE-AUTH-011: Password Stored as String (Java/.NET)
- **Severity**: MEDIUM
- **CWE**: CWE-316 (Cleartext Storage in Memory)
- **What to find**: Passwords stored in immutable String objects that can't be zeroed from memory
- **Patterns**:
  - `String password = ...` (Java -- String is immutable, stays in memory until GC)
  - `string password = ...` (C# -- same issue)
  - `new String(passwordChars)` (converting char[] to String defeats the purpose)
- **Fix**: Use `char[]` or `byte[]` for passwords. Zero the array after use: `Arrays.fill(password, '\0')`
- **Reference**: Password_Storage_Cheat_Sheet.md

## RULE-AUTH-012: OAuth/SAML Misconfiguration
- **Severity**: HIGH
- **CWE**: CWE-287 (Improper Authentication)
- **What to find**: OAuth2 or SAML implementations with security gaps
- **Patterns**:
  - OAuth2: `state` parameter not validated (CSRF in OAuth flow)
  - OAuth2: `redirect_uri` not validated against whitelist
  - OAuth2: Implicit grant flow used (tokens in URL fragment)
  - SAML: Signature not validated on assertions
  - SAML: Audience restriction not enforced
- **Fix**: Validate state parameter, whitelist redirect URIs, use authorization code flow, validate SAML signatures
- **PoC**: Start an OAuth flow and intercept the redirect: `curl -v "https://<target>/oauth/authorize?client_id=app&redirect_uri=https://evil.example.com/callback&response_type=code"` — if the server redirects to the attacker-controlled URI instead of returning an error, the redirect URI is not validated.
- **Reference**: OAuth2_Cheat_Sheet.md, SAML_Security_Cheat_Sheet.md

## RULE-AUTH-013: Missing Rate Limiting on Auth Endpoints
- **Severity**: MEDIUM
- **CWE**: CWE-307 (Improper Restriction of Excessive Authentication Attempts)
- **What to find**: Authentication endpoints without brute-force protection
- **Patterns**:
  - Login endpoint without rate limiting middleware
  - No account lockout after failed attempts
  - No CAPTCHA or progressive delay on repeated failures
  - Password reset endpoint without rate limiting
- **Fix**: Implement progressive delays or account lockout. Add CAPTCHA after N failures.
- **Reference**: Credential_Stuffing_Prevention_Cheat_Sheet.md

## RULE-AUTH-014: Insecure Password Reset Token
- **Severity**: HIGH
- **CWE**: CWE-640 (Weak Password Recovery Mechanism for Forgotten Password)
- **What to find**: Password reset tokens that are predictable, stored in plaintext, or lack expiry
- **Patterns**:
  - Reset token generated with weak RNG (`Math.random()`, `java.util.Random`, `UUID.randomUUID()` without hashing)
  - Reset token stored in database without hashing
  - Reset token compared via plaintext equality instead of constant-time comparison
  - Missing token expiry: no `expiresAt`/`expiry`/`TTL` field on reset tokens
  - Reset token longer than needed in URL (information leakage via Referer header)
  - Password reset does not invalidate existing sessions
- **Fix**: Generate tokens with CSPRNG. Hash before storage (SHA-256). Set short TTL (15-30 min). Invalidate all sessions on reset. Use constant-time comparison.
- **PoC**: Request a password reset and inspect the token in the email link. Check if: (1) the token is short or sequential (predictable), (2) `curl "https://<target>/api/reset?token=<token>"` works after 60+ minutes (no expiry), or (3) the same token works after a second reset request (not invalidated).
- **Reference**: Forgot_Password_Cheat_Sheet.md

## RULE-AUTH-015: Missing MFA on Sensitive Operations
- **Severity**: MEDIUM
- **CWE**: CWE-308 (Use of Single-factor Authentication)
- **What to find**: Administrative, financial, or privilege-changing operations without MFA verification
- **Patterns**:
  - Admin endpoints (`/admin/*`, `@PreAuthorize("hasRole('ADMIN')")`) without MFA step
  - Password change endpoint without reauthentication/MFA
  - Email/phone change endpoint without MFA verification
  - Financial transaction endpoints without step-up authentication
  - Role/permission change endpoints without MFA
  - API key generation/rotation without MFA
- **Fix**: Require MFA or reauthentication for sensitive operations. Implement step-up authentication for elevated actions.
- **Reference**: Multifactor_Authentication_Cheat_Sheet.md

## RULE-AUTH-016: Sensitive Data in Log Output
- **Severity**: HIGH
- **CWE**: CWE-532 (Insertion of Sensitive Information into Log File)
- **What to find**: Passwords, tokens, OTP codes, or API keys written to application logs
- **Patterns**:
  - `logger.*password`, `log.*password` (password in log call)
  - `logger.*token`, `log.*token` (token in log call)
  - `logger.*otp`, `log.*otp`, `logger.*one.time` (OTP in log)
  - `logger.*secret`, `log.*apiKey`, `log.*api_key`
  - `logger.*creditCard`, `log.*ssn`, `log.*socialSecurity`
  - `toString()` on user/auth objects that include sensitive fields
  - Catch blocks logging entire request objects containing credentials
- **Fix**: Never log credentials, tokens, or PII. Use structured logging with redaction. Override `toString()` to exclude sensitive fields.
- **PoC**: `grep -rnE 'log(ger)?\.(info|debug|warn|error).*\b(password|token|secret|otp|apiKey)\b' --include="*.java" --include="*.py" --include="*.js" .` — any match where a sensitive variable is interpolated into a log statement confirms credentials may appear in log files.
- **Reference**: Logging_Cheat_Sheet.md, Logging_Vocabulary_Cheat_Sheet.md
