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

#### bypassSecurityTrust* analysis guidance
Each bypass method has different risk and legitimate use cases:

**bypassSecurityTrustHtml** — HIGH RISK
- Legitimate: Rendering trusted CMS/admin content with known-safe HTML
- Dangerous when input comes from: user input, URL params, API responses without server-side sanitization
- Verify: Input is server-side sanitized OR comes from a trusted admin-only source
```
bypassSecurityTrustHtml\(.*this\.      # Check: is the value from user-controlled property?
bypassSecurityTrustHtml\(.*@Input      # HIGH RISK: component input (parent may pass unsafe data)
bypassSecurityTrustHtml\(.*subscribe   # HIGH RISK: from HTTP response
bypassSecurityTrustHtml\(.*route       # HIGH RISK: from route params
```

**bypassSecurityTrustScript** — CRITICAL RISK
- Almost never legitimate. Flag all occurrences.
```
bypassSecurityTrustScript\(            # ALWAYS FLAG — rarely justified
```

**bypassSecurityTrustUrl** — HIGH RISK
- Legitimate: Dynamic URLs from trusted config (e.g., CDN base URL)
- Dangerous when: user-controlled href/src values (javascript: protocol risk)
```
bypassSecurityTrustUrl\(.*@Input       # HIGH RISK: component input
bypassSecurityTrustUrl\(.*route        # HIGH RISK: from route
bypassSecurityTrustUrl\(.*http         # MEDIUM RISK: check if origin is validated
```

**bypassSecurityTrustResourceUrl** — HIGH RISK
- Legitimate: iframe src for known trusted domains
- Verify: URL is validated against an allowlist of trusted domains
```
bypassSecurityTrustResourceUrl\(.*@Input  # HIGH RISK
bypassSecurityTrustResourceUrl\(.*\+      # HIGH RISK: concatenation
```

**bypassSecurityTrustStyle** — MEDIUM RISK
- Legitimate: Dynamic CSS values (background images, dimensions)
- Dangerous when: url() values from user input (data exfiltration via CSS)
```
bypassSecurityTrustStyle\(.*url\(      # Check: is the URL user-controlled?
bypassSecurityTrustStyle\(.*@Input     # MEDIUM RISK: component input
```

### Unsafe DOM Access
```
ElementRef\.nativeElement
this\.el\.nativeElement\.innerHTML
Renderer2.*setProperty\(.*innerHTML
\[innerHTML\]=                          # Template binding (check if sanitized)
```

#### [innerHTML] binding analysis
```
\[innerHTML\]=.*\|.*sanitize            # Pipe with sanitization (check pipe impl)
\[innerHTML\]=.*\|.*safe                # Custom "safe" pipe (verify it uses DomSanitizer)
\[innerHTML\]=".*Component\."          # Component property — trace data source
```
Verify the data bound to `[innerHTML]` either:
1. Comes from a trusted static source, OR
2. Is explicitly sanitized via `DomSanitizer.sanitize(SecurityContext.HTML, value)`

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
