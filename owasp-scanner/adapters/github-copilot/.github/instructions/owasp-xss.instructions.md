---
applyTo: "**/*.jsx,**/*.tsx,**/*.html,**/*.vue,**/*.svelte,**/*.ejs,**/*.hbs,**/*.pug,**/*.js,**/*.ts"
---

# OWASP XSS Security Checks

When reviewing or generating code in these files, watch for cross-site scripting vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Direct innerHTML Assignment (RULE-XSS-001, CWE-79)
- `element.innerHTML = userInput`
- `element.outerHTML = userInput`
- `$(...).html(userInput)` (jQuery)
- `$(...).append(unsanitizedHTML)` (jQuery)
- **Fix**: Use `element.textContent` for text, or `DOMPurify.sanitize(input)` before innerHTML

### Dangerous JavaScript Evaluation (RULE-XSS-003, CWE-95)
- `eval(userInput)`
- `new Function(userInput)`
- `setTimeout(stringArgument, delay)` (string, not function reference)
- `setInterval(stringArgument, delay)` (string, not function reference)
- **Fix**: Use `JSON.parse()` for JSON data. Use function references for timers.

### React dangerouslySetInnerHTML (RULE-XSS-004, CWE-79)
- `dangerouslySetInnerHTML` without `DOMPurify.sanitize()`
- `dangerouslySetInnerHTML={{__html: userInput}}`
- **Fix**: `dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(input)}}`

### Angular Security Bypass (RULE-XSS-005, CWE-79)
- `bypassSecurityTrustHtml()`
- `bypassSecurityTrustScript()`
- `bypassSecurityTrustUrl()`
- `ElementRef.nativeElement` direct DOM manipulation
- **Fix**: Avoid bypass functions. Use Angular's built-in template binding.

### Vue/Svelte/Template Engine Escape Hatches (RULE-XSS-006, CWE-79)
- Vue: `v-html` directive with dynamic data
- Svelte: `{@html userInput}`
- EJS: `<%- unescaped %>`
- Handlebars: `{{{unescaped}}}`
- Pug: `!{unescaped}`
- **Fix**: Use framework default escaped output. Sanitize with DOMPurify if raw HTML required.

### JavaScript URL Protocol (RULE-XSS-008, CWE-79)
- `href` attribute set to user input without protocol validation
- `window.location = userInput`
- **Fix**: Validate URL starts with `https://` or `http://` only. Reject `javascript:`, `data:` protocols.

### Unsafe CSP Configuration (RULE-XSS-009, CWE-693)
- `'unsafe-inline'` in `script-src`
- `'unsafe-eval'` in `script-src`
- `script-src *` (wildcard)
- **Fix**: Use nonce-based CSP: `script-src 'nonce-{RANDOM}' 'strict-dynamic'`

### Prototype Pollution (RULE-XSS-013, CWE-1321)
- `Object.assign(target, untrustedSource)` without filtering
- `_.merge(target, untrustedSource)` (lodash deep merge)
- `JSON.parse(untrusted)` spread into objects without `__proto__` filtering
- **Fix**: Freeze prototypes, validate keys, filter `__proto__` / `constructor` / `prototype`

## Proof of Concept

For CRITICAL and HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rule definitions. Use benign payloads that prove the vulnerability exists without causing damage.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/xss/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/xss/patterns/`.
