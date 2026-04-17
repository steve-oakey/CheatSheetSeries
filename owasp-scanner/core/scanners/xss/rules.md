# XSS Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting cross-site scripting vulnerabilities.

## RULE-XSS-001: Direct innerHTML Assignment
- **Severity**: HIGH
- **CWE**: CWE-79 (Cross-site Scripting)
- **What to find**: Assignment of untrusted data to `innerHTML` or `outerHTML` properties
- **Patterns**:
  - `element.innerHTML = userInput`
  - `element.outerHTML = userInput`
  - `.innerHTML = response.data`
  - `$(...).html(userInput)` (jQuery)
  - `$(...).append(unsanitizedHTML)` (jQuery)
- **Fix**: Use `element.textContent` for text display, or `DOMPurify.sanitize(input)` before innerHTML assignment
- **PoC**: In the browser console on the affected page: `document.querySelector('[user-input-field]').value = '<img src=x onerror=alert(document.domain)>'; document.querySelector('form').submit();` — if an alert box shows the domain name, the innerHTML sink renders unsanitized input.
- **Reference**: Cross_Site_Scripting_Prevention_Cheat_Sheet.md#safe-sinks

## RULE-XSS-002: document.write / document.writeln
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: Use of `document.write()` or `document.writeln()` with any dynamic data
- **Patterns**:
  - `document.write(` with variable input
  - `document.writeln(` with variable input
- **Fix**: Use DOM manipulation methods (`createElement`, `appendChild`, `textContent`)
- **PoC**: `curl -s "https://<target>/page?q=<img+src%3Dx+onerror%3Dalert(1)>" | grep -i 'onerror'` — if the response body contains the unescaped `onerror` attribute, the input reaches a `document.write()` sink.
- **Reference**: DOM_based_XSS_Prevention_Cheat_Sheet.md

## RULE-XSS-003: Dangerous JavaScript Evaluation
- **Severity**: CRITICAL
- **CWE**: CWE-95 (Eval Injection)
- **What to find**: Dynamic code execution via eval-like functions
- **Patterns**:
  - `eval(userInput)`
  - `new Function(userInput)`
  - `setTimeout(stringArgument, delay)` (string, not function reference)
  - `setInterval(stringArgument, delay)` (string, not function reference)
  - `window.execScript(`
- **Fix**: Use `JSON.parse()` for JSON data. Replace string arguments in setTimeout/setInterval with function references
- **PoC**: `curl "https://<target>/api/callback?fn=alert(document.domain)"` — if the server embeds the parameter into a `setTimeout()` or `eval()` call in the response, the payload will execute in the browser.
- **Reference**: DOM_based_XSS_Prevention_Cheat_Sheet.md

## RULE-XSS-004: Framework Escape Hatch - React
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: React's `dangerouslySetInnerHTML` used without sanitization
- **Patterns**:
  - `dangerouslySetInnerHTML` without `DOMPurify.sanitize()`
  - `dangerouslySetInnerHTML={{__html: userInput}}`
- **Fix**: Sanitize with DOMPurify before passing: `dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(input)}}`
- **PoC**: In React DevTools or via API: submit `<svg onload=alert(document.domain)>` as the field rendered by `dangerouslySetInnerHTML`. If an alert fires when the component renders, the input is not sanitized.
- **Reference**: Cross_Site_Scripting_Prevention_Cheat_Sheet.md#framework-security

## RULE-XSS-005: Framework Escape Hatch - Angular
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: Angular's `bypassSecurityTrust*` functions that disable built-in sanitization
- **Patterns**:
  - `bypassSecurityTrustHtml(`
  - `bypassSecurityTrustScript(`
  - `bypassSecurityTrustUrl(`
  - `bypassSecurityTrustResourceUrl(`
  - `bypassSecurityTrustStyle(`
  - `[innerHTML]` binding with unsanitized dynamic data
  - `ElementRef.nativeElement` direct DOM manipulation
- **Fix**: Avoid bypass functions. If necessary, validate/sanitize input before bypassing. Use Angular's built-in template binding.
- **PoC**: `grep -rn "bypassSecurityTrust" --include="*.ts" .` — any match confirms Angular's sanitizer is bypassed. Submit `<img src=x onerror=alert(document.domain)>` to the bound input field and check if the alert fires in the browser.
- **Reference**: Cross_Site_Scripting_Prevention_Cheat_Sheet.md#framework-security

## RULE-XSS-006: Framework Escape Hatch - Other
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: Other framework functions that bypass auto-escaping
- **Patterns**:
  - Lit: `unsafeHTML(` function
  - Polymer: `inner-h-t-m-l` attribute, `htmlLiteral(` function
  - Vue: `v-html` directive with dynamic data
  - Svelte: `{@html userInput}`
  - EJS/Pug/Handlebars: `<%- unescaped %>`, `!{unescaped}`, `{{{unescaped}}}`
- **Fix**: Use the framework's default escaped output. Sanitize with DOMPurify if raw HTML is required.
- **PoC**: Submit `<img src=x onerror=alert(document.domain)>` into a field rendered by the escape-hatch directive (`v-html`, `{@html}`, `{{{}}}`). If the alert fires in the browser, the framework's auto-escaping is bypassed.
- **Reference**: Cross_Site_Scripting_Prevention_Cheat_Sheet.md#framework-security

## RULE-XSS-007: Unsafe Event Handler Assignment
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: Dynamic data used in JavaScript event handler attributes or assignments
- **Patterns**:
  - `element.onclick = untrustedCode`
  - `element.onerror = untrustedCode`
  - `element.setAttribute("onclick", userInput)`
  - `element.setAttribute("onerror", userInput)`
  - Any `on*` attribute with dynamic content in HTML templates
- **Fix**: Use `addEventListener()` with function references, not string code
- **PoC**: `curl -s "https://<target>/page?callback=alert(document.domain)" | grep -iE 'on(click|error|load)\s*='` — if the response contains user input embedded inside an event handler attribute, the payload will execute on user interaction.
- **Reference**: DOM_based_XSS_Prevention_Cheat_Sheet.md

## RULE-XSS-008: JavaScript URL Protocol
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: User-controlled URLs that could contain `javascript:` or `data:` protocols
- **Patterns**:
  - `href` attribute set to user input without protocol validation
  - `src` attribute set to user input without protocol validation
  - `window.location = userInput`
  - `window.location.href = userInput`
  - `<a href="{{userInput}}">`
  - `<iframe src="{{userInput}}">`
- **Fix**: Validate URL starts with `https://` or `http://` only. Reject `javascript:`, `data:`, `vbscript:` protocols
- **PoC**: `curl -s "https://<target>/redirect?url=javascript:alert(document.domain)" -o /dev/null -D -` — if the server redirects or renders the `javascript:` URL into an `href` attribute, clicking the link executes JavaScript.
- **Reference**: Cross_Site_Scripting_Prevention_Cheat_Sheet.md#url-contexts

## RULE-XSS-009: Unsafe CSP Configuration
- **Severity**: MEDIUM
- **CWE**: CWE-693 (Protection Mechanism Failure)
- **What to find**: Content Security Policy that permits unsafe execution
- **Patterns**:
  - `'unsafe-inline'` in `script-src`
  - `'unsafe-eval'` in `script-src`
  - `script-src *` (wildcard)
  - `default-src *` (wildcard)
  - Missing `script-src` directive entirely
  - Missing `object-src` directive (allows plugin-based XSS)
  - Missing `base-uri` directive (allows base tag injection)
- **Fix**: Use nonce-based CSP: `script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'`
- **Reference**: Content_Security_Policy_Cheat_Sheet.md

## RULE-XSS-010: Missing CSP Header
- **Severity**: MEDIUM
- **CWE**: CWE-693
- **What to find**: No Content-Security-Policy header configured
- **Patterns**:
  - No `Content-Security-Policy` in response headers config
  - CSP only in `meta` tag (limited, no `frame-ancestors` support)
  - `Content-Security-Policy-Report-Only` without enforcement policy
- **Fix**: Add CSP header in server config. Use `Content-Security-Policy` (not Report-Only) for enforcement.
- **Reference**: Content_Security_Policy_Cheat_Sheet.md

## RULE-XSS-011: DOM Clobbering Vulnerability
- **Severity**: MEDIUM
- **CWE**: CWE-79
- **What to find**: Code that accesses named DOM properties without validation, vulnerable to clobbering via injected HTML
- **Patterns**:
  - `window.config` or `window.settings` accessed without explicit declaration
  - `document.getElementById` result used without type checking
  - Global variables set with `var` (hoisted to window) used for security decisions
  - HTML with user-controlled `id` or `name` attributes
- **Fix**: Use `const`/`let` declarations, type-check DOM values, use `Object.freeze()` on sensitive objects
- **Reference**: DOM_Clobbering_Prevention_Cheat_Sheet.md

## RULE-XSS-012: Prototype Pollution
- **Severity**: HIGH
- **CWE**: CWE-1321 (Prototype Pollution)
- **What to find**: Code that allows modification of object prototypes via user input
- **Patterns**:
  - `obj[untrustedKey] = untrustedValue` (bracket notation with user-controlled key)
  - `__proto__` in user-controllable paths
  - `constructor.prototype` in user-controllable paths
  - Deep merge/extend functions without prototype checks
  - `Object.assign()` with user-controlled source objects
  - `lodash.merge()` / `lodash.defaultsDeep()` (older versions)
- **Fix**: Use `Object.create(null)` for dictionaries, `Map`/`Set` for key-value stores, validate keys against `__proto__` and `constructor`
- **PoC**: `curl -X POST "https://<target>/api/settings" -H "Content-Type: application/json" -d '{"__proto__":{"polluted":true}}'` then `curl "https://<target>/api/debug"` — if any object in the response contains `"polluted":true`, the prototype chain was modified by user input.
- **Reference**: Prototype_Pollution_Prevention_Cheat_Sheet.md

## RULE-XSS-013: Unsafe postMessage Handling
- **Severity**: HIGH
- **CWE**: CWE-942 (Permissive Cross-domain Policy)
- **What to find**: postMessage usage without origin validation or with unsafe data handling
- **Patterns**:
  - `window.postMessage(data, '*')` (wildcard target origin)
  - `addEventListener("message", handler)` without `event.origin` check
  - `event.data` used in `innerHTML`, `eval()`, or `document.write()`
- **Fix**: Always specify exact target origin. Always validate `event.origin` in handlers. Use `textContent` for display.
- **PoC**: Create a test HTML page: `<script>window.open('https://<target>'); setTimeout(()=>window.opener.postMessage('test','*'),2000);</script>` — if the target page processes the message without checking `event.origin`, the handler accepts cross-origin messages.
- **Reference**: HTML5_Security_Cheat_Sheet.md

## RULE-XSS-014: localStorage/sessionStorage for Sensitive Data
- **Severity**: MEDIUM
- **CWE**: CWE-922 (Insecure Storage of Sensitive Information)
- **What to find**: Authentication tokens or sensitive data stored in Web Storage (accessible via XSS)
- **Patterns**:
  - `localStorage.setItem("token", ...)`
  - `localStorage.setItem("auth", ...)`
  - `localStorage.setItem("session", ...)`
  - `sessionStorage.setItem("token", ...)`
- **Fix**: Store authentication tokens in httpOnly cookies. Use Web Storage only for non-sensitive UI preferences.
- **Reference**: HTML5_Security_Cheat_Sheet.md

## RULE-XSS-015: Missing Subresource Integrity
- **Severity**: LOW
- **CWE**: CWE-353 (Missing Support for Integrity Check)
- **What to find**: External JavaScript loaded without SRI hash
- **Patterns**:
  - `<script src="https://...">` without `integrity` attribute
  - `<link rel="stylesheet" href="https://...">` without `integrity` attribute
  - CDN-loaded resources without `crossorigin="anonymous"` and `integrity`
- **Fix**: Add SRI: `<script src="..." integrity="sha384-..." crossorigin="anonymous">`
- **Reference**: Third_Party_Javascript_Management_Cheat_Sheet.md

## RULE-XSS-016: insertAdjacentHTML with Untrusted Data
- **Severity**: HIGH
- **CWE**: CWE-79
- **What to find**: `insertAdjacentHTML` used with unsanitized data
- **Patterns**:
  - `element.insertAdjacentHTML("beforeend", userInput)`
  - `element.insertAdjacentHTML("afterbegin", apiResponse)`
- **Fix**: Use `insertAdjacentText()` for text content, or sanitize with DOMPurify before using `insertAdjacentHTML`
- **PoC**: Submit `<img src=x onerror=alert(document.domain)>` as data that reaches an `insertAdjacentHTML` call. If the alert fires when the page renders, the input is inserted as unsanitized HTML.
- **Reference**: DOM_based_XSS_Prevention_Cheat_Sheet.md
