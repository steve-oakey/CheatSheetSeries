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

## Missing Security Files
```
\.gitignore                             # Should contain: .env, *.pem, *.key
package-lock\.json|yarn\.lock           # Should exist for npm projects
\.snyk|dependabot\.yml|renovate\.json   # Should exist for dependency scanning
```
