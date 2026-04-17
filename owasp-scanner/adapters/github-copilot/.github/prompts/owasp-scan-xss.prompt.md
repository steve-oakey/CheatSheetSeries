---
description: "Scan for XSS vulnerabilities: DOM XSS, framework escape hatches, CSP, prototype pollution"
---

# OWASP XSS Scan

Scan the current project for cross-site scripting vulnerabilities.

## Instructions

1. **Detect stack**: Identify the frontend framework (React, Angular, Vue, Svelte, etc.)
2. **Load rules**: Read `owasp-scanner/core/scanners/xss/rules.md` for the full 16-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/xss/patterns/`:
   - `angular.md` for Angular
   - `nodejs-express.md` for Express templates (EJS, Pug, Handlebars)
   - `generic.md` for React, Vue, Svelte, and others
4. **Scan**: Search all frontend source, template, and JavaScript files for dangerous patterns
5. **Report**: Use the format in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-XSS-001/002: innerHTML assignment, document.write
- RULE-XSS-003: eval(), new Function(), setTimeout/setInterval with strings
- RULE-XSS-004/005/006: Framework escape hatches (React dangerouslySetInnerHTML, Angular bypassSecurityTrust*, Vue v-html, Svelte {@html})
- RULE-XSS-007/008: Unsafe event handlers, javascript: URL protocol
- RULE-XSS-009: Unsafe CSP configuration
- RULE-XSS-010: Server-side template injection leading to XSS
- RULE-XSS-011/012: Unescaped output in templates, JSON injection into HTML
- RULE-XSS-013: Prototype pollution
- RULE-XSS-014/015/016: postMessage, Web Workers, DOMParser issues

Present findings sorted by severity with code snippets and fixes.
For CRITICAL and HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules.
