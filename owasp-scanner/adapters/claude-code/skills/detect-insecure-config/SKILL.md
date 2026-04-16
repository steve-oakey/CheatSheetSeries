---
name: detect-insecure-config
description: "Detects insecure security configurations when CORS, CSRF, headers, TLS, Docker, or Kubernetes config files are being modified. Triggers on SecurityConfig, csrf().disable(), Access-Control-Allow-Origin, Dockerfile, securityContext."
version: "1.0.0"
---

When you detect configuration files being modified that relate to security (CORS, CSRF, HTTP headers, TLS, Docker, Kubernetes), check for misconfigurations.

Read the config rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/rules.md` and warn about violations.

Key patterns to watch for:
- `csrf().disable()` without justification (RULE-CFG-004)
- `Access-Control-Allow-Origin: *` (RULE-CFG-003)
- Missing security headers (CSP, HSTS, X-Frame-Options) (RULE-CFG-001)
- Dockerfile without `USER` directive (RULE-CFG-009)
- Kubernetes `privileged: true` (RULE-CFG-011)
- Stack traces in error responses (RULE-CFG-013)
