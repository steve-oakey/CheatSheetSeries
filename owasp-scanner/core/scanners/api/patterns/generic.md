# API Patterns: Language-Agnostic

## SSRF Indicators
```
(fetch|axios|request|http\.get|urllib)\(.*req\.(query|params|body)
(fetch|axios|request|http\.get|urllib)\(.*\+
url\s*=\s*req\.(query|params|body)
```

## Mass Assignment
```
Object\.assign\(.*req\.body
\.create\(req\.body\)
\.update\(req\.body\)
\{\.\.\.req\.body\}
```

## File Upload Issues
```
\.originalname                          # Using user-supplied filename
\.filename.*req\.(file|body)            # User-controlled filename
multer\(\)                             # Check for file filter config
upload\.single\(                       # Check for validation
\.mimetype                             # Check if validated
```

## Unvalidated Redirects
```
redirect\(.*req\.(query|params|body)
sendRedirect\(.*getParameter
location\s*=\s*req\.(query|params)
301|302.*Location.*req\.
```

## GraphQL Issues
```
introspection.*true
graphiql.*true
playground.*true
__schema
maxDepth|depthLimit|depth-limit         # Should be present
queryComplexity|complexity              # Should be present
```

## WebSocket Issues
```
allowedOrigins.*\*
origin.*\*
ws://                                   # Should use wss://
```

## Rate Limiting (check for absence)
```
rateLimit|rate-limit|throttle
rateLimiter|RateLimiter
express-rate-limit
@RateLimit
```

## API Key in URL
```
[?&]api[_-]?key=
[?&]token=
[?&]access_token=
[?&]secret=
```

## Error Exposure
```
stack.*trace.*response
\.stack\b.*res\.(json|send)
stackTrace.*true
error\.message.*res\.(json|send)
```

## Microservice Inter-Service Communication Insecure (RULE-API-013)

### Dangerous: Unencrypted inter-service calls
```
http://localhost:\d+                    # Plaintext local service calls
http://127\.0\.0\.1:\d+                # Plaintext loopback calls
http://10\.\d+\.\d+\.\d+             # Plaintext internal network calls
http://172\.(1[6-9]|2\d|3[01])         # Plaintext private range calls
http://192\.168\.                       # Plaintext private network calls
http://[a-z]+-service                   # Plaintext service discovery URLs
http://[a-z]+-api                       # Plaintext internal API calls
```

### Dangerous: Shared static secrets for service-to-service auth
```
service[_-]?secret\s*[:=]\s*["'][^"']+  # Static shared secret between services
inter[_-]?service[_-]?key\s*[:=]         # Hardcoded inter-service key
service[_-]?api[_-]?key\s*[:=]\s*["']   # Static API key for service auth
shared[_-]?secret\s*[:=]\s*["']         # Shared secret (should use short-lived tokens)
```

### Dangerous: Missing certificate validation
```
verify\s*[:=]\s*false                   # Disabled TLS verification (Python)
rejectUnauthorized\s*[:=]\s*false       # Disabled cert validation (Node.js)
insecure[_-]?skip[_-]?tls[_-]?verify    # Disabled TLS verification (Go/K8s)
NODE_TLS_REJECT_UNAUTHORIZED.*0          # Global TLS disable (Node.js)
```

### Safe: Encrypted service-to-service communication
```
https://[a-z]+-service                  # TLS service-to-service calls
mtls|mTLS|mutual.*tls|MTLS              # Mutual TLS configured
service[_-]?mesh|serviceMesh            # Service mesh present (Istio/Linkerd)
client[_-]?cert|clientCertificate       # Client certificate auth
PeerAuthentication.*STRICT              # Istio strict mTLS
oidc|OIDC|workload.*identity            # Workload identity/OIDC for services
```
