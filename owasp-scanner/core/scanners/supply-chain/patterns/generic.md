# Supply Chain Patterns: Language-Agnostic

## Hardcoded Secrets
```
password\s*[:=]\s*["'][^"']{4,}["']
passwd\s*[:=]\s*["'][^"']{4,}["']
api[_-]?key\s*[:=]\s*["'][^"']{8,}["']
secret\s*[:=]\s*["'][^"']{8,}["']
token\s*[:=]\s*["'][^"']{8,}["']
credentials\s*[:=]\s*["']
connection[_-]?string\s*[:=]\s*["']
```

## Private Keys
```
BEGIN RSA PRIVATE KEY
BEGIN OPENSSH PRIVATE KEY
BEGIN EC PRIVATE KEY
BEGIN PGP PRIVATE KEY
BEGIN DSA PRIVATE KEY
BEGIN PRIVATE KEY
```

## Cloud Provider Credentials
```
AWS_SECRET_ACCESS_KEY\s*=
AWS_ACCESS_KEY_ID\s*=
AZURE_CLIENT_SECRET\s*=
GOOGLE_APPLICATION_CREDENTIALS\s*=
```

## Platform Tokens
```
ghp_[A-Za-z0-9_]{36}                   # GitHub PAT
gho_[A-Za-z0-9_]{36}                   # GitHub OAuth
github_pat_[A-Za-z0-9_]{82}            # GitHub fine-grained PAT
glpat-[A-Za-z0-9_-]{20}                # GitLab PAT
sk-[A-Za-z0-9]{48}                     # OpenAI/Stripe secret key
xoxb-[0-9-]+                           # Slack bot token
xoxp-[0-9-]+                           # Slack user token
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}  # SendGrid
```

## Weak Cryptography
```
DES\b|DESede|3DES
RC4|RC2|Blowfish
ECB
MD5(?!.*password)                       # MD5 for non-password use
SHA-?1\b(?!.*password)                  # SHA1 for non-password use
```

## Weak RNG
```
Math\.random\(\)
java\.util\.Random[^S]                  # Not SecureRandom
random\.random\(\)                      # Python non-crypto
mt_rand\(                               # PHP Mersenne Twister
rand\(\)                                # C/C++ weak
```

## CI/CD Secrets in Config
```
env:.*password\s*[:=]\s*[^$]            # Not a variable reference
env:.*secret\s*[:=]\s*[^$]
env:.*token\s*[:=]\s*[^$]
permissions:.*write-all
pull_request_target.*checkout
```

## CI/CD Pipeline Secrets Exposure — Expanded (RULE-SC-008)

### GitHub Actions: Hardcoded secrets in workflows
Search `.github/workflows/*.yml` files:
```
env:\s*\n\s+\w+:\s*["'][^$].*["']       # Env var with hardcoded value (not ${{ secrets }})
run:.*password\s*=\s*["'][^$]           # Password in run command
run:.*token\s*=\s*["'][^$]             # Token in run command
run:.*--access-key\s*=\s*[A-Z0-9]      # AWS key in run command
echo\s+\$\w*(secret|password|token|key) # Echoing secrets to log output
```

### GitHub Actions: Dangerous workflow patterns
```
pull_request_target:.*\n.*actions/checkout  # Checkout PR code with repo secrets (critical)
permissions:\s*write-all                # Overly permissive workflow permissions
permissions:\s*\n\s+contents:\s*write   # Write access without scoping
GITHUB_TOKEN.*write                     # Token with excessive permissions
```

### GitLab CI: Secrets in `.gitlab-ci.yml`
```
variables:\s*\n\s+\w*PASSWORD\w*:\s*["'][^$]   # Hardcoded password variable
variables:\s*\n\s+\w*SECRET\w*:\s*["'][^$]     # Hardcoded secret variable
variables:\s*\n\s+\w*TOKEN\w*:\s*["'][^$]      # Hardcoded token variable
before_script:.*password\s*=\s*["']     # Password in before_script
before_script:.*export\s+\w*SECRET      # Exporting secrets in scripts
```

### Jenkins: Secrets in `Jenkinsfile`
```
withEnv\(\[.*SECRET.*=.*["'][^$]        # Hardcoded secret in withEnv
environment\s*\{.*password\s*=\s*["']   # Hardcoded password in environment block
sh\s+["'].*password\s*=\s*[^$]         # Password in shell command
httpGet.*password=                       # Credentials in URL
credentials\(["'][^"']+["']\)           # Verify credential ID, not plaintext
```

### Azure Pipelines: Secrets in `azure-pipelines.yml`
```
variables:\s*\n\s+-\s*name:.*secret.*\n\s+value:\s*["'][^$]  # Hardcoded secret
variables:\s*\n\s+-\s*name:.*password.*\n\s+value:\s*["'][^$]  # Hardcoded password
variables:\s*\n\s+-\s*name:.*token.*\n\s+value:\s*["'][^$]    # Hardcoded token
```

### Safe: Platform secret management (should be present)
```
\$\{\{\s*secrets\.                       # GitHub Actions secrets reference
\$\[variables\..*\]                     # Azure Pipelines variable groups
credentials\(\s*["']\w+["']\s*\)        # Jenkins credential binding
protected:\s*true                        # GitLab protected variables
masked:\s*true                           # GitLab masked variables
```

### Safe: OIDC / keyless authentication (preferred over static secrets)
```
aws-actions/configure-aws-credentials.*role-to-assume  # AWS OIDC (GitHub)
google-github-actions/auth.*workload_identity_provider  # GCP OIDC (GitHub)
azure/login.*OIDC|federated.*credential                # Azure OIDC (GitHub)
id-token:\s*write                       # OIDC token permission (good)
```

### Safe: Minimal permissions
```
permissions:\s*\n\s+contents:\s*read    # Read-only (good)
permissions:\s*\{\s*\}                  # No permissions (good)
permissions:\s*read-all                 # Read-only global (good)
```

## Missing Security Files
```
\.gitignore                             # Should contain: .env, *.pem, *.key
package-lock\.json|yarn\.lock           # Should exist for npm projects
\.snyk|dependabot\.yml|renovate\.json   # Should exist for dependency scanning
```

## Missing Build Provenance and SBOM (RULE-SC-011)

### Check for SBOM generation (at least ONE should be present)
```
cyclonedx|CycloneDX|CYCLONEDX           # CycloneDX SBOM format
spdx|SPDX                               # SPDX SBOM format
sbom|SBOM                               # Generic SBOM reference
slsa|SLSA                               # SLSA provenance framework
```

### Check for artifact signing (at least ONE should be present in release/CI)
```
jarsigner|Jarsigner                     # Java JAR signing
cosign|Cosign                           # Sigstore cosign
sigstore|Sigstore                       # Sigstore signing
gpg.*--sign|gpg.*--verify               # GPG signing
```

### Dangerous: Lockfile not enforced in CI
```
npm install(?!.*--ci|.*ci\b)            # npm install without ci in CI pipeline
yarn install(?!.*--frozen-lockfile)      # yarn without lockfile enforcement
```

### Safe: Proper dependency verification
```
npm ci                                  # Lockfile-enforced install (good)
yarn install --frozen-lockfile           # Frozen lockfile (good)
--verify-signatures                     # Signature verification
```

## Container Security Gaps (RULE-SC-012)

### Dangerous: Secrets in Dockerfile build
```
ARG.*PASSWORD|ARG.*SECRET|ARG.*TOKEN    # Secrets as build args (visible in history)
ARG.*KEY|ARG.*CREDENTIAL                # Credentials as build args
ENV.*PASSWORD=|ENV.*SECRET=             # Secrets as env vars in image
ENV.*API_KEY=|ENV.*TOKEN=               # Tokens as env vars
```

### Dangerous: Missing container hardening
Check Dockerfile for absence of these:
```
HEALTHCHECK                             # Should be present
\.dockerignore                          # Should exist
```

### Dangerous: Build artifacts in production image
```
^FROM.*AS\s+build(?!.*\n.*FROM)         # Single FROM (no multi-stage build)
RUN.*npm install.*--production=false    # Dev dependencies in production
COPY.*node_modules                      # Copying local node_modules
```

### Safe: Container hardening
```
FROM.*AS\s+build.*\nFROM               # Multi-stage build (good)
RUN.*--mount=type=secret                # BuildKit secret mount (good)
HEALTHCHECK.*CMD                       # Health check present (good)
```
