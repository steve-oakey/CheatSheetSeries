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
