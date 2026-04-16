# Supply Chain Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting secrets in code, vulnerable dependencies, CI/CD misconfigurations, and cryptographic weaknesses.

## RULE-SC-001: Hardcoded Secrets in Source Code
- **Severity**: CRITICAL
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **What to find**: API keys, passwords, tokens, or private keys embedded in source files
- **Patterns**:
  - `password\s*=\s*"[^"]+"`
  - `api[_-]?key\s*=\s*"[^"]+"`
  - `secret\s*=\s*"[^"]+"`
  - `token\s*=\s*"[^"]+"`
  - `AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID` with literal values
  - `PRIVATE_KEY\s*=`
  - `-----BEGIN RSA PRIVATE KEY-----`
  - `-----BEGIN OPENSSH PRIVATE KEY-----`
  - `-----BEGIN EC PRIVATE KEY-----`
  - `-----BEGIN PGP PRIVATE KEY-----`
  - `ghp_[A-Za-z0-9_]{36}` (GitHub personal access token)
  - `sk-[A-Za-z0-9]{48}` (OpenAI/Stripe secret key pattern)
  - `xoxb-` or `xoxp-` (Slack tokens)
  - Database connection strings with embedded credentials
- **Fix**: Use environment variables, vault services (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), or externalized config
- **Reference**: Secrets_Management_Cheat_Sheet.md

## RULE-SC-002: Secrets in Configuration Files
- **Severity**: HIGH
- **CWE**: CWE-798
- **What to find**: Credentials in tracked configuration files
- **Patterns**:
  - `.env` files committed to version control
  - `application.properties`/`application.yml` with plaintext passwords: `spring.datasource.password=<literal>`
  - `docker-compose.yml` with plaintext environment secrets
  - `terraform.tfvars` with sensitive values
  - `config.json`/`settings.json` with API keys or passwords
- **Fix**: Use `.gitignore` for `.env` files. Use Spring Boot config server or environment variables for secrets. Use terraform vault provider.
- **Reference**: Secrets_Management_Cheat_Sheet.md

## RULE-SC-003: Weak Cryptographic Algorithms
- **Severity**: HIGH
- **CWE**: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
- **What to find**: Usage of deprecated or weak cryptographic algorithms
- **Patterns**:
  - `DES`, `3DES`, `DESede` (weak symmetric ciphers)
  - `RC4`, `RC2` (broken stream/block ciphers)
  - `Cipher.getInstance("DES")` or `Cipher.getInstance("DESede")`
  - `Blowfish` with short keys
  - RSA with key size < 2048 bits
  - `MD5` for integrity/signatures (not password hashing -- see RULE-AUTH-001)
  - `SHA-1` for signatures or integrity
- **Fix**: Use AES-256 with GCM mode for symmetric encryption. Use RSA-2048+ or Curve25519 for asymmetric.
- **Reference**: Cryptographic_Storage_Cheat_Sheet.md

## RULE-SC-004: Insecure Block Cipher Mode
- **Severity**: HIGH
- **CWE**: CWE-327
- **What to find**: Block cipher used with ECB mode (reveals patterns in encrypted data)
- **Patterns**:
  - `Cipher.getInstance("AES/ECB/...")`
  - `Cipher.getInstance("DES/ECB/...")`
  - Any `*/ECB/*` cipher mode
  - CBC without HMAC (no authenticated encryption)
- **Fix**: Use authenticated encryption: `AES/GCM/NoPadding`. If CBC required, use Encrypt-then-MAC.
- **Reference**: Cryptographic_Storage_Cheat_Sheet.md

## RULE-SC-005: Weak Random Number Generation
- **Severity**: HIGH
- **CWE**: CWE-338 (Use of Cryptographically Weak PRNG)
- **What to find**: Non-cryptographic random number generators used for security purposes
- **Patterns**:
  - `java.util.Random` (not `SecureRandom`) for tokens, keys, or IDs
  - `Math.random()` for security-sensitive values
  - `rand()` in C/C++ for cryptographic use
  - `random.random()` in Python (not `secrets` module)
  - `mt_rand()` in PHP
  - `crypto.pseudoRandomBytes()` (Node.js deprecated)
- **Fix**: Use CSPRNGs: `java.security.SecureRandom` (Java), `secrets` module (Python), `crypto.randomBytes()` (Node.js)
- **Reference**: Cryptographic_Storage_Cheat_Sheet.md

## RULE-SC-006: Missing Dependency Scanning
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third Party Components)
- **What to find**: No automated dependency vulnerability scanning configured
- **Patterns**:
  - No `dependencyCheck` plugin in `pom.xml` or `build.gradle`
  - No `.snyk` configuration
  - No `npm audit` in CI pipeline
  - No Dependabot/Renovate configuration in `.github/`
  - No SBOM generation configured
  - `package-lock.json` or `yarn.lock` absent (inconsistent builds)
- **Fix**: Add OWASP Dependency-Check to build. Enable Dependabot. Run `npm audit` in CI. Generate SBOM.
- **Reference**: Vulnerable_Dependency_Management_Cheat_Sheet.md, Dependency_Graph_SBOM_Cheat_Sheet.md

## RULE-SC-007: NPM Security Issues
- **Severity**: MEDIUM
- **CWE**: CWE-1104
- **What to find**: NPM configuration that weakens supply chain security
- **Patterns**:
  - `--ignore-scripts` in install commands (disables security scripts too)
  - Missing `package-lock.json` (non-deterministic installs)
  - `npm install` without `--ignore-scripts` review for untrusted packages
  - `postinstall` scripts in dependencies that download/execute code
  - Scoped packages from untrusted registries
- **Fix**: Use lockfiles. Review `postinstall` scripts. Use `npm audit`. Consider `npm ci` for CI builds.
- **Reference**: NPM_Security_Cheat_Sheet.md

## RULE-SC-008: CI/CD Pipeline Secrets Exposure
- **Severity**: HIGH
- **CWE**: CWE-798
- **What to find**: Secrets embedded in CI/CD pipeline configuration files
- **Patterns**:
  - Plaintext secrets in `.github/workflows/*.yml`
  - Plaintext secrets in `Jenkinsfile`, `.gitlab-ci.yml`, `azure-pipelines.yml`
  - `env:` blocks with hardcoded credentials
  - Missing secret masking in pipeline output
  - Overly permissive `permissions:` in GitHub Actions
  - `pull_request_target` with `actions/checkout` (PR code execution with secrets)
- **Fix**: Use CI/CD platform secret management. Use OIDC for cloud authentication. Restrict permissions to minimum.
- **Reference**: CI_CD_Security_Cheat_Sheet.md

## RULE-SC-009: Hardcoded Encryption Keys
- **Severity**: CRITICAL
- **CWE**: CWE-321 (Use of Hard-coded Cryptographic Key)
- **What to find**: Cryptographic keys embedded in source code
- **Patterns**:
  - `SecretKeySpec("hardcoded".getBytes(), "AES")`
  - `private static final String KEY = "..."`
  - `const encryptionKey = "..."`
  - Key material in properties/config files
  - IV (initialization vector) hardcoded or reused
- **Fix**: Store keys in KMS (AWS KMS, Azure Key Vault). Generate with CSPRNG. Never commit keys to source control.
- **Reference**: Key_Management_Cheat_Sheet.md

## RULE-SC-010: Missing .gitignore for Sensitive Files
- **Severity**: MEDIUM
- **CWE**: CWE-538 (File and Directory Information Exposure)
- **What to find**: Sensitive files not excluded from version control
- **Patterns**:
  - `.env` not in `.gitignore`
  - `*.pem`, `*.key`, `*.p12`, `*.jks` not in `.gitignore`
  - `application-local.properties` not in `.gitignore`
  - `credentials.json`, `service-account.json` not in `.gitignore`
  - `terraform.tfstate` not in `.gitignore`
- **Fix**: Add sensitive file patterns to `.gitignore`. Audit git history for accidentally committed secrets.
- **Reference**: Secrets_Management_Cheat_Sheet.md
