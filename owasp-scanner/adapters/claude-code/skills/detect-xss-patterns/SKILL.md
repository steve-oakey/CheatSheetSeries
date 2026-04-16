---
name: detect-xss-patterns
description: "Detects potential XSS vulnerabilities when code involving DOM manipulation, innerHTML, template output, or security bypass functions is being written. Triggers on innerHTML, document.write, eval, dangerouslySetInnerHTML, bypassSecurityTrust."
version: "1.0.0"
---

When you detect code being written that involves DOM manipulation, raw HTML insertion, or security bypass functions, check for XSS vulnerabilities.

Read the XSS rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/rules.md` and warn about violations.

Key patterns to watch for:
- `innerHTML` assignment with user data (use `textContent` or `DOMPurify.sanitize()`)
- `document.write()` (use DOM manipulation methods)
- `eval()`, `new Function()`, `setTimeout(string)` (never evaluate user-controlled strings)
- `dangerouslySetInnerHTML` without DOMPurify (React)
- `bypassSecurityTrust*` functions (Angular -- verify input is truly trusted)
- `[innerHTML]` bindings with unsanitized data (Angular)
- Prototype pollution via `__proto__` or `constructor.prototype`

Provide inline warnings with the specific RULE-XSS-* ID.
