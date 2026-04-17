---
description: "Scan for security misconfigurations: headers, CORS, CSRF, cookies, TLS, Docker, Kubernetes"
---

# OWASP Configuration Scan

Scan the current project for security misconfigurations.

## Instructions

1. **Detect stack**: Identify web server, framework, Docker, Kubernetes, and CI/CD configuration
2. **Load rules**: Read `owasp-scanner/core/scanners/config/rules.md` for the full 18-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/config/patterns/`:
   - `java-spring.md` for Spring Boot configuration
   - `nodejs-express.md` for Express/Node.js
   - `python.md` for Django/Flask
   - `generic.md` for Nginx, Apache, Docker, Kubernetes
4. **Scan**: Check all configuration files, security classes, and infrastructure definitions
5. **Report**: Use the format in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-CFG-001/002: Missing security headers, information disclosure headers
- RULE-CFG-003: Overly permissive CORS
- RULE-CFG-004: CSRF protection disabled
- RULE-CFG-005/006: Insecure cookies, missing HSTS
- RULE-CFG-007: Weak TLS configuration
- RULE-CFG-008: Clickjacking vulnerability
- RULE-CFG-009/010: Docker root, Kubernetes misconfigurations
- RULE-CFG-011: Exposed management endpoints (Actuator, etc.)
- RULE-CFG-012/013: Debug mode in production, verbose error messages
- RULE-CFG-014 through CFG-018: Directory listing, logging config, session config

Present findings sorted by severity with code snippets and fixes.
For HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules.
