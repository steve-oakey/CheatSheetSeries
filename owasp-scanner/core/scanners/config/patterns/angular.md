# Configuration Patterns: Angular

## XSRF/CSRF Configuration
```
HttpClientXsrfModule                    # Should be configured
withXsrfConfiguration\(                 # Angular 17+ standalone
xsrfCookieName                          # Should be set
xsrfHeaderName                          # Should be set
```
Absence of XSRF module configuration is a finding (RULE-CFG-004).

## Environment Configuration
```
production:\s*false                     # Development mode in production build
enableProdMode\(\)                      # Should be called in main.ts
```

## CSP Meta Tag (Weak)
```
<meta.*Content-Security-Policy          # CSP in meta tag is limited
```
CSP should be configured as HTTP header, not meta tag.

## Error Handling
```
ErrorHandler                            # Check if custom error handler exists
handleError.*console\.log\(.*error      # Logging full errors to console in prod
```
