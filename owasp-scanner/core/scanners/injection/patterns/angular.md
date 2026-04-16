# Injection Patterns: Angular / TypeScript

Angular's built-in sanitization prevents most injection vectors. These patterns detect cases where Angular protections are bypassed or backend injection occurs through Angular services.

## Dangerous Patterns

### Template Injection
```
\[innerHTML\]=".*"                      # If bound to unsanitized user input
bypassSecurityTrustHtml\(               # Bypasses Angular sanitization
bypassSecurityTrustScript\(
bypassSecurityTrustUrl\(
bypassSecurityTrustResourceUrl\(
bypassSecurityTrustStyle\(
```

### Dynamic Code Execution
```
eval\(
new Function\(
setTimeout\(.*,.*string               # setTimeout with string arg (not function)
setInterval\(.*,.*string
```

### HTTP Client Injection (SSRF via Angular)
```
this\.http\.(get|post|put|delete)\(.*\+   # URL concatenation
this\.http\.(get|post|put|delete)\(`.*\$\{  # Template literal URL
HttpClient.*\(.*userInput
```

### SQL/NoSQL via API Calls
Angular doesn't directly query databases, but watch for:
```
\.query\(.*\+                           # Query string building
\.filter\(.*\$where                     # NoSQL operators in frontend query params
encodeURIComponent.*SELECT              # SQL in URL parameters
```

## Safe Alternatives

### Sanitized Content
```
DomSanitizer\.sanitize\(               # Explicit sanitization
DomSanitizer\.bypassSecurityTrust      # Only safe if input is trusted/validated
textContent                             # Safe text insertion
\[textContent\]="                       # Angular safe binding
```

### Safe HTTP Usage
```
HttpParams                              # Parameterized query strings
new HttpParams\(\)\.set\(              # Safe parameter building
environment\.\w+Url                     # Config-based URLs (not user input)
```

## Key Principle

Angular's template compiler auto-escapes interpolated values (`{{ }}`), so `{{ userInput }}` is safe by default. The risk is in explicit bypass functions and `[innerHTML]` bindings. Focus scanning on:
1. Any usage of `bypassSecurityTrust*` functions
2. `[innerHTML]` bindings with dynamic data
3. URL construction for HttpClient calls
