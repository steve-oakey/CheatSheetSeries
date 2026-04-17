# Supply Chain Scanner: Cheatsheet Map

| Rule ID | Source Cheatsheet | Section |
|---------|-------------------|---------|
| RULE-SC-001 | Secrets_Management_Cheat_Sheet.md | Hardcoded Secrets Detection |
| RULE-SC-002 | Secrets_Management_Cheat_Sheet.md | Configuration Files |
| RULE-SC-003 | Cryptographic_Storage_Cheat_Sheet.md | Algorithm Selection |
| RULE-SC-004 | Cryptographic_Storage_Cheat_Sheet.md | Cipher Modes |
| RULE-SC-005 | Cryptographic_Storage_Cheat_Sheet.md | Random Number Generation |
| RULE-SC-006 | Vulnerable_Dependency_Management_Cheat_Sheet.md, Dependency_Graph_SBOM_Cheat_Sheet.md | Scanning |
| RULE-SC-007 | NPM_Security_Cheat_Sheet.md | Supply Chain |
| RULE-SC-008 | CI_CD_Security_Cheat_Sheet.md | Pipeline Security |
| RULE-SC-009 | Key_Management_Cheat_Sheet.md | Key Storage |
| RULE-SC-010 | Secrets_Management_Cheat_Sheet.md | Version Control |
| RULE-SC-011 | Software_Supply_Chain_Security_Cheat_Sheet.md, Dependency_Graph_SBOM_Cheat_Sheet.md | SBOM and Provenance |
| RULE-SC-012 | Docker_Security_Cheat_Sheet.md, NodeJS_Docker_Cheat_Sheet.md | Container Hardening |

## Supplementary Cheatsheets

These cheatsheets provide additional context but are not primary rule sources:
- **Java_Security_Cheat_Sheet.md** -- Java cryptography best practices: Google Tink, JCA/JCE AES-GCM, ECDH key agreement, nonce management (referenced by RULE-SC-003, RULE-SC-004)
- **Nodejs_Security_Cheat_Sheet.md** -- Deprecated package detection: csurf (known bypass vulnerabilities), safe alternatives: csrf-csrf, csrf-sync, lusca
