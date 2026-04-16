# XSS Patterns: Angular

## Dangerous Patterns

### Sanitization Bypass
```
bypassSecurityTrustHtml\(
bypassSecurityTrustScript\(
bypassSecurityTrustUrl\(
bypassSecurityTrustResourceUrl\(
bypassSecurityTrustStyle\(
```

### Unsafe DOM Access
```
ElementRef\.nativeElement
this\.el\.nativeElement\.innerHTML
Renderer2.*setProperty\(.*innerHTML
\[innerHTML\]=                          # Template binding (check if sanitized)
```

### Dynamic Code
```
eval\(
new Function\(
document\.write\(
document\.writeln\(
```

### Token Storage
```
localStorage\.setItem\(.*token
localStorage\.setItem\(.*jwt
localStorage\.setItem\(.*auth
localStorage\.getItem\(.*token
```

## Safe Angular Patterns
```
\{\{.*\}\}                              # Interpolation (auto-escaped by Angular)
\[textContent\]=                        # Safe text binding
DomSanitizer\.sanitize\(               # Explicit sanitization
HttpInterceptor                         # Auth token via interceptor
withXsrfConfiguration\(                 # XSRF module config
HttpClientXsrfModule                    # XSRF protection
```

## Angular-Specific Checks
- Verify `HttpClientXsrfModule` or `withXsrfConfiguration()` is configured
- Check that `[innerHTML]` bindings use sanitized data
- Confirm tokens use `HttpInterceptor`, not localStorage
- Look for disabled Angular sanitization in module config
