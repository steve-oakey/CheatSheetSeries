---
name: detect-auth-weaknesses
description: "Detects authentication and authorization weaknesses when auth-related code is being written. Triggers on password hashing, JWT configuration, session management, @PreAuthorize, localStorage token storage."
version: "1.0.0"
---

When you detect code being written that involves authentication, authorization, sessions, or password handling, check for security weaknesses.

Read the auth rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/rules.md` and warn about violations.

Key patterns to watch for:
- MD5/SHA1/SHA256 for password hashing (use Argon2id or bcrypt >= 10) (RULE-AUTH-001)
- Hardcoded passwords/API keys (RULE-AUTH-002)
- JWT without algorithm validation (RULE-AUTH-003)
- Tokens stored in localStorage (use httpOnly cookies) (RULE-AUTH-005)
- Missing `@PreAuthorize` or `@Secured` on endpoints (RULE-AUTH-007)
- Different error messages for valid/invalid usernames (RULE-AUTH-009)
