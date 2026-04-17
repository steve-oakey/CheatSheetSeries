---
description: "Scan for API security issues: SSRF, mass assignment, file upload, GraphQL, WebSocket"
---

# OWASP API Security Scan

Scan the current project for REST, GraphQL, WebSocket, and general API vulnerabilities.

## Instructions

1. **Detect stack**: Identify the API framework (Spring MVC, Express, FastAPI, GraphQL libraries, etc.)
2. **Load rules**: Read `owasp-scanner/core/scanners/api/rules.md` for the full 13-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/api/patterns/`:
   - `java-spring.md` for Spring MVC/WebFlux
   - `nodejs-express.md` for Express/Fastify/NestJS
   - `python.md` for Django REST/Flask/FastAPI
   - `generic.md` for other frameworks
4. **Scan**: Check all API endpoint, controller, route, and resolver code
5. **Report**: Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-API-001: Server-Side Request Forgery (SSRF)
- RULE-API-002: Mass assignment
- RULE-API-003: Insecure file upload
- RULE-API-004: Unvalidated redirects
- RULE-API-005/006: GraphQL introspection, unbounded queries
- RULE-API-007: WebSocket missing origin validation
- RULE-API-008: Missing request body validation
- RULE-API-009: Verbose API error responses
- RULE-API-010 through API-013: Rate limiting, API versioning, HATEOAS abuse, batch endpoint issues

Present findings sorted by severity. Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
