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
- **PoC**: `grep -rnE '(password|api[_-]?key|secret|token)\s*=\s*"[^"]{8,}"' --include="*.java" --include="*.py" --include="*.js" --include="*.properties" .` — any match with a literal string value of 8+ characters confirms hardcoded credentials. Also check: `git log --all -p -S 'password' --include="*.java" | head -50` to find secrets in git history.
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
- **PoC**: `git ls-files | grep -iE '(\.env|credentials|service-account|tfvars)$'` — any match confirms sensitive files are tracked in version control. Then: `grep -l 'password\|secret\|api_key' $(git ls-files '*.properties' '*.yml')` to find credentials in committed config files.
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
- **PoC**: `grep -rnE '(DES|DESede|RC4|RC2|Blowfish|MD5|SHA-1)' --include="*.java" --include="*.py" --include="*.js" . | grep -i 'cipher\|encrypt\|MessageDigest\|hashlib'` — any match confirms usage of deprecated cryptographic algorithms.
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
- **PoC**: `grep -rnE 'ECB' --include="*.java" --include="*.py" .` — any match in a `Cipher.getInstance()` call confirms ECB mode usage. To demonstrate the weakness: `python3 -c "from Crypto.Cipher import AES;c=AES.new(b'0123456789abcdef',AES.MODE_ECB);print(c.encrypt(b'AAAAAAAAAAAAAAAA')==c.encrypt(b'AAAAAAAAAAAAAAAA'))"` outputs `True`, showing identical plaintext blocks produce identical ciphertext (pattern leakage).
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
- **PoC**: `grep -rnE '(java\.util\.Random|Math\.random|random\.random|mt_rand)' --include="*.java" --include="*.js" --include="*.py" --include="*.php" .` — any match in security-sensitive context (token generation, key derivation, session IDs) confirms weak RNG. Demonstrate: `python3 -c "import random;random.seed(42);print([random.randint(0,999999) for _ in range(5)])"` — the output is deterministic and reproducible given the seed.
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
- **PoC**: `grep -rnE '(password|secret|token|key)\s*[:=]\s*["'\'][^${}]' --include="*.yml" --include="*.yaml" .github/workflows/ Jenkinsfile .gitlab-ci.yml` — any match with a literal value (not a `${{ secrets.* }}` reference) confirms plaintext credentials in pipeline config. Also check: `grep -rn 'permissions:' .github/workflows/ | grep -v 'contents: read'` for overly permissive GitHub Actions permissions.
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
- **PoC**: `grep -rnE '(SecretKeySpec|encryption[_]?key|ENCRYPTION_KEY|private.static.final.String.*(KEY|key|Secret))' --include="*.java" --include="*.js" --include="*.py" .` — any match where the key value is a string literal confirms hardcoded cryptographic keys. If the key is in source, anyone with repo access can decrypt all data encrypted with it.
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

## RULE-SC-011: Missing Build Provenance and SBOM
- **Severity**: MEDIUM
- **CWE**: CWE-1104 (Use of Unmaintained Third Party Components)
- **What to find**: No software bill of materials (SBOM) generation or build provenance verification
- **Patterns**:
  - No SBOM plugin in build config: `cyclonedx-maven-plugin`, `spdx-maven-plugin`, `@cyclonedx/bom`
  - No SLSA provenance generation in CI/CD pipeline
  - No artifact signing: `jarsigner`, `cosign`, `sigstore` absent from build/release
  - No dependency lock file verification in CI
  - `npm install` instead of `npm ci` in CI (ignores lockfile)
- **Fix**: Generate SBOM with CycloneDX or SPDX. Sign artifacts. Use lockfile verification in CI. Adopt SLSA framework.
- **Reference**: Software_Supply_Chain_Security_Cheat_Sheet.md, Dependency_Graph_SBOM_Cheat_Sheet.md

## RULE-SC-012: Container Security Gaps
- **Severity**: MEDIUM
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **What to find**: Container images with security misconfigurations beyond basic root/privilege checks
- **Patterns**:
  - Secrets passed via `ARG` or `ENV` in Dockerfile (visible in image history)
  - No `HEALTHCHECK` directive (container can run in degraded state undetected)
  - Multi-stage build not used (build tools and source in production image)
  - `.dockerignore` missing or not excluding `.git`, `.env`, `node_modules`
  - Base image not from trusted registry or not scanned
  - `EXPOSE` on unnecessary ports
  - Writable `/tmp` without `noexec` mount option
- **Fix**: Use multi-stage builds. Pass secrets via runtime mount or orchestrator. Add HEALTHCHECK. Use `.dockerignore`. Scan base images.
- **Reference**: Docker_Security_Cheat_Sheet.md, NodeJS_Docker_Cheat_Sheet.md
