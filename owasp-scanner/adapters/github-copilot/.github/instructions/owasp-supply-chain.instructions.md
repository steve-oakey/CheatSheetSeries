---
applyTo: "**/package.json,**/pom.xml,**/build.gradle,**/requirements.txt,**/Pipfile,**/Gemfile,**/go.mod,**/.env,**/.env.*,**/*.lock,**/yarn.lock,**/package-lock.json,**/.github/workflows/*.yml,**/Jenkinsfile,**/.gitlab-ci.yml,**/azure-pipelines.yml"
---

# OWASP Supply Chain Security Checks

When reviewing or generating dependency, CI/CD, or configuration files, watch for supply chain vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Hardcoded Secrets in Source Code (RULE-SC-001, CWE-798)
- `password\s*=\s*"[^"]+"`
- `api[_-]?key\s*=\s*"[^"]+"`
- `-----BEGIN RSA PRIVATE KEY-----`
- `-----BEGIN OPENSSH PRIVATE KEY-----`
- `ghp_[A-Za-z0-9_]{36}` (GitHub personal access token)
- `sk-[A-Za-z0-9]{48}` (OpenAI/Stripe secret key pattern)
- `xoxb-` or `xoxp-` (Slack tokens)
- AWS keys: `AKIA[A-Z0-9]{16}`
- **Fix**: Use environment variables, vault services (AWS Secrets Manager, HashiCorp Vault), or externalized config

### Secrets in Configuration Files (RULE-SC-002, CWE-798)
- `.env` files committed to version control
- `application.properties`/`application.yml` with plaintext passwords
- `docker-compose.yml` with plaintext environment secrets
- **Fix**: Use `.gitignore` for `.env` files. Use environment variables for secrets.

### Weak Cryptographic Algorithms (RULE-SC-003, CWE-327)
- `DES`, `3DES`, `DESede` (weak symmetric ciphers)
- `RC4`, `RC2` (broken ciphers)
- RSA with key size < 2048 bits
- `MD5` or `SHA-1` for integrity/signatures
- **Fix**: Use AES-256-GCM for symmetric. RSA-2048+ or Curve25519 for asymmetric.

### Insecure Block Cipher Mode (RULE-SC-004, CWE-327)
- `AES/ECB/...` (ECB reveals patterns in encrypted data)
- CBC without HMAC (no authenticated encryption)
- **Fix**: Use `AES/GCM/NoPadding` (authenticated encryption)

### Weak Random Number Generation (RULE-SC-005, CWE-338)
- `java.util.Random` (not `SecureRandom`) for tokens/keys
- `Math.random()` for security-sensitive values
- `random.random()` in Python (not `secrets` module)
- **Fix**: Use `SecureRandom` (Java), `secrets` (Python), `crypto.randomBytes()` (Node.js)

### CI/CD Pipeline Secrets Exposure (RULE-SC-008, CWE-798)
- Plaintext secrets in `.github/workflows/*.yml`
- `env:` blocks with hardcoded credentials
- Overly permissive `permissions:` in GitHub Actions
- `pull_request_target` with `actions/checkout` (PR code execution with secrets)
- **Fix**: Use CI/CD platform secret management. Use OIDC for cloud auth. Restrict permissions to minimum.

### Missing Dependency Scanning (RULE-SC-006, CWE-1104)
- No OWASP Dependency-Check plugin configured
- No Dependabot/Renovate configuration
- Missing lockfiles (`package-lock.json`, `yarn.lock`)
- **Fix**: Add OWASP Dependency-Check. Enable Dependabot. Run `npm audit` in CI.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/supply-chain/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/supply-chain/patterns/`.
