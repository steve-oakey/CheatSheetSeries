---
name: angular-security
description: "Angular-specific security scanning. Triggers when writing Angular components with DomSanitizer bypass, innerHTML bindings, ElementRef DOM access, token storage, or HttpClient configuration."
version: "1.0.0"
---

When you detect Angular/TypeScript code being written or modified, apply Angular-specific security checks from the OWASP Cheat Sheet Series.

Load the Angular pattern files from each scanner domain:
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/patterns/angular.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/patterns/angular.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/patterns/angular.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/patterns/angular.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/patterns/angular.md`

Angular-specific checks:
- `bypassSecurityTrustHtml/Script/Url/ResourceUrl/Style` -- Sanitization bypass
- `[innerHTML]` bindings with unsanitized dynamic data -- XSS
- `ElementRef.nativeElement` direct DOM access -- Bypasses Angular sanitization
- `localStorage.setItem("token", ...)` -- Tokens accessible via XSS
- Missing `HttpClientXsrfModule` or `withXsrfConfiguration()` -- No CSRF protection
- `eval()` or `new Function()` in component code -- Code injection
- Secrets in `environment.ts` or `environment.prod.ts` -- Client-side exposure
- External scripts without `integrity` attribute -- Missing SRI
- Client-side role checks without server-side backing -- Authorization bypass
