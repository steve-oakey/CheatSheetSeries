# Auth Patterns: Language-Agnostic

## Weak Password Hashing
```
md5\(.*password
sha1\(.*password
sha256\(.*password
MessageDigest\.getInstance\("MD5"\)
MessageDigest\.getInstance\("SHA-1"\)
hashlib\.md5\(
hashlib\.sha1\(
hash\(.*'md5'
hash\(.*'sha1'
```

## Hardcoded Credentials
```
password\s*[:=]\s*["'][^"']+["']
api[_-]?key\s*[:=]\s*["'][^"']+["']
secret\s*[:=]\s*["'][^"']+["']
token\s*[:=]\s*["'][^"']+["']
BEGIN RSA PRIVATE KEY
BEGIN OPENSSH PRIVATE KEY
BEGIN EC PRIVATE KEY
BEGIN PGP PRIVATE KEY
AWS_SECRET_ACCESS_KEY\s*=
PRIVATE_KEY\s*=
```

## JWT Issues
```
alg.*none
Algorithm\.none\(\)
decode\(.*verify.*false
decode\((?!.*verify)
jwt\.decode\((?!.*algorithms)
```

## Token Storage
```
localStorage\.setItem\(["']token
localStorage\.setItem\(["']jwt
localStorage\.setItem\(["']auth
localStorage\.setItem\(["']session
localStorage\.setItem\(["']access
sessionStorage\.setItem\(["']token
```

## User Enumeration
```
"Invalid username"
"User not found"
"Account does not exist"
"No account with that email"
"Unknown user"
```

## Session Issues
```
JSESSIONID|PHPSESSID|ASP\.NET_SessionId   # Identifiable session names
session.*URL|url.*session                  # Session in URL
```
