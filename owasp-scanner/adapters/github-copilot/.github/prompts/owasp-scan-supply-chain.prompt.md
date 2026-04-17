---
description: "Scan for supply chain issues: hardcoded secrets, weak crypto, vulnerable dependencies, CI/CD"
---

# OWASP Supply Chain Scan

Scan the current project for secrets in code, vulnerable dependencies, CI/CD misconfigurations, and cryptographic weaknesses.

## Instructions

1. **Detect stack**: Identify package managers, CI/CD platform, and infrastructure tooling
2. **Load rules**: Read `owasp-scanner/core/scanners/supply-chain/rules.md` for the full 12-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/supply-chain/patterns/`:
   - `java-spring.md` for Maven/Gradle, Spring Boot config
   - `nodejs-express.md` for NPM/Yarn, Node.js config
   - `python.md` for pip, Python config
   - `generic.md` for CI/CD, Docker, infrastructure
4. **Scan**: Check all source files, config files, dependency manifests, and CI/CD pipelines
5. **Report**: Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-SC-001/002: Hardcoded secrets in source code and configuration files
- RULE-SC-003/004: Weak cryptographic algorithms, insecure block cipher modes
- RULE-SC-005: Weak random number generation
- RULE-SC-006/007: Missing dependency scanning, NPM security issues
- RULE-SC-008: CI/CD pipeline secrets exposure
- RULE-SC-009: Hardcoded encryption keys
- RULE-SC-010: Insecure certificate validation
- RULE-SC-011/012: Container image security, SBOM/provenance

Present findings sorted by severity. Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
