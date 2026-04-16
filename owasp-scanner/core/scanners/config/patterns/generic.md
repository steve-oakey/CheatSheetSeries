# Configuration Patterns: Language-Agnostic

## Security Headers (check response configuration)
```
X-Content-Type-Options.*nosniff         # Should be present
X-Frame-Options.*(DENY|SAMEORIGIN)      # Should be present
Strict-Transport-Security.*max-age      # Should be present
Content-Security-Policy                 # Should be present
Referrer-Policy                         # Should be present
Permissions-Policy                      # Should be present
```

## Information Disclosure (should NOT be present)
```
X-Powered-By
X-AspNet-Version
X-AspNetMvc-Version
Server:.*Apache/\d
Server:.*nginx/\d
Server:.*Microsoft-IIS/\d
```

## CORS Issues
```
Access-Control-Allow-Origin:\s*\*
Access-Control-Allow-Credentials.*true.*Allow-Origin.*\*
origin:\s*['"]?\*['"]?
allowedOrigins\(\s*["']\*["']\s*\)
```

## Cookie Issues
```
Set-Cookie:.*(?!.*Secure)
Set-Cookie:.*(?!.*HttpOnly)
Set-Cookie:.*(?!.*SameSite)
SameSite=None(?!.*Secure)
```

## TLS Issues
```
SSLv3
TLSv1\.0
TLSv1\.1
ssl_protocols.*TLSv1[^.]
DES|3DES|RC4|MD5|NULL|EXPORT
```

## Docker Issues
```
^FROM.*:latest
^FROM\s+\w+\s*$                        # No tag at all
^USER\s+root
--privileged
docker\.sock
^ADD\s+                                 # Should use COPY
curl.*\|\s*bash
curl.*\|\s*sh
```

## Kubernetes Issues
```
privileged:\s*true
runAsUser:\s*0
allowPrivilegeEscalation:\s*true
readOnlyRootFilesystem:\s*false
hostNetwork:\s*true
hostPID:\s*true
hostIPC:\s*true
```

## Error Handling
```
printStackTrace\(\)
\.stackTrace
\.stack\b.*response
DEBUG\s*=\s*True
include-stacktrace.*always
dumpExceptions.*true
```

## Cache Control
```
Cache-Control:.*public                  # Dangerous on sensitive endpoints
```
