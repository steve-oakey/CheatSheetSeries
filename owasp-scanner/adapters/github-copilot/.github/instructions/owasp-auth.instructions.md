---
applyTo: "**/*auth*,**/*login*,**/*session*,**/*token*,**/*password*,**/*credential*,**/*jwt*,**/*oauth*,**/*Security*.java,**/*security*.py,**/*security*.ts"
---

# OWASP Authentication & Authorization Security Checks

When reviewing or generating authentication-related code, watch for these vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Weak Password Hashing (RULE-AUTH-001, CWE-916)
- `MD5` for passwords: `MessageDigest.getInstance("MD5")`, `hashlib.md5`
- `SHA-1` for passwords: `MessageDigest.getInstance("SHA-1")`, `sha1(password)`
- `SHA-256` without salt/iteration for passwords
- bcrypt with work factor < 10
- PBKDF2 with < 600,000 iterations (HMAC-SHA256)
- **Fix**: Use Argon2id (m=19456, t=2, p=1), scrypt (N=2^17, r=8, p=1), or bcrypt (work factor >= 10)

### Hardcoded Credentials (RULE-AUTH-002, CWE-798)
- `password = "..."` (string literal assignment)
- `apiKey = "..."`, `api_key = "..."`, `API_KEY = "..."`
- `secret = "..."`, `SECRET_KEY = "..."`
- `Authorization: Bearer <literal_token>`
- **Fix**: Use environment variables, vault services, or externalized configuration

### JWT Algorithm None (RULE-AUTH-003, CWE-347)
- `Algorithm.none()`
- `"alg": "none"` in token handling
- JWT verification without explicit algorithm specification
- **Fix**: Always specify algorithm explicitly. Never accept `none`.

### JWT Missing Validation Claims (RULE-AUTH-004, CWE-347)
- `JWT.decode()` without `.verify()` (decoding without verification)
- Missing issuer, audience, or expiration validation
- Weak HMAC secret (< 64 characters)
- **Fix**: Validate issuer, audience, expiration, and not-before claims. Use 64+ char secrets.

### Session Token in localStorage (RULE-AUTH-005, CWE-922)
- `localStorage.setItem("token", ...)` or `localStorage.setItem("jwt", ...)`
- `sessionStorage.setItem("token", ...)`
- **Fix**: Store tokens in httpOnly cookies (not accessible via JavaScript)

### Missing Authorization Checks (RULE-AUTH-007, CWE-862)
- `@RequestMapping` without `@PreAuthorize`, `@Secured`, or `@RolesAllowed`
- Missing authorization middleware in Express/Node.js routes
- Django views without `@login_required` or `@permission_required`
- **Fix**: Add authorization checks on every endpoint. Use deny-by-default.

### IDOR - Insecure Direct Object Reference (RULE-AUTH-008, CWE-639)
- `findById(request.getParameter("id"))` without ownership check
- `/api/users/{id}` without verifying resource ownership
- Sequential/predictable resource IDs in URLs
- **Fix**: Verify resource ownership against authenticated user. Use UUIDs.

### User Enumeration (RULE-AUTH-009, CWE-204)
- `"Invalid username"` (different from password error)
- `"User not found"` in login response
- Different HTTP status codes for user-exists vs user-not-found
- **Fix**: Use identical generic messages: `"Invalid username or password"`

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/auth/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/auth/patterns/`.
