---
name: detect-secrets-in-code
description: "Detects hardcoded secrets, API keys, passwords, private keys, and cryptographic keys in source code. Triggers on password assignments, API key patterns, BEGIN PRIVATE KEY, SecretKeySpec, connection strings."
version: "1.0.0"
---

When you detect code being written that contains credential-like strings, API keys, or cryptographic material, warn about hardcoded secrets.

Read the supply-chain rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/rules.md` and warn about violations.

Key patterns to watch for:
- `password = "literal"` or `apiKey = "literal"` (RULE-SC-001)
- Private keys (BEGIN RSA PRIVATE KEY, etc.) (RULE-SC-001)
- AWS/GCP/Azure credentials in source (RULE-SC-001)
- GitHub/Slack/OpenAI tokens (RULE-SC-001)
- Secrets in application.properties/yml (RULE-SC-002)
- Hardcoded encryption keys (`SecretKeySpec("...".getBytes())`) (RULE-SC-009)
- Weak crypto (DES, 3DES, RC4, ECB mode) (RULE-SC-003, RULE-SC-004)
- `Math.random()` or `java.util.Random` for security (RULE-SC-005)

For secrets, ALWAYS warn. False positives are acceptable.
