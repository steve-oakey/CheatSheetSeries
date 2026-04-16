---
name: detect-api-vulnerabilities
description: "Detects API security issues when REST endpoints, GraphQL resolvers, WebSocket handlers, or file upload code is being written. Triggers on @RequestBody, RestTemplate, WebClient, GraphQL config, MultipartFile."
version: "1.0.0"
---

When you detect API endpoint code being written or modified, check for security vulnerabilities.

Read the API rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/rules.md` and warn about violations.

Key patterns to watch for:
- User URLs passed to HTTP clients (SSRF) (RULE-API-001)
- `@RequestBody Entity` without DTO pattern (mass assignment) (RULE-API-002)
- File uploads without extension/size validation (RULE-API-003)
- Redirect with user-controlled URL (RULE-API-004)
- `@RequestBody` without `@Valid` (RULE-API-008)
- GraphQL introspection enabled (RULE-API-005)
