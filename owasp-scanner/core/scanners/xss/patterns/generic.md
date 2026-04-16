# XSS Patterns: Language-Agnostic

## Dangerous DOM Sinks
```
\.innerHTML\s*=
\.outerHTML\s*=
document\.write\(
document\.writeln\(
\.insertAdjacentHTML\(
```

### innerHTML analysis guidance
When `innerHTML` is found, check the assignment source:
```
# HIGH RISK: Dynamic user-controlled input
\.innerHTML\s*=\s*.*\+                 # String concatenation
\.innerHTML\s*=\s*.*\$\{              # Template literal with variable
\.innerHTML\s*=\s*.*request            # Server request data
\.innerHTML\s*=\s*.*params             # URL parameters
\.innerHTML\s*=\s*.*query              # Query string
\.innerHTML\s*=\s*.*\bdata\b          # Generic data variable
\.innerHTML\s*=\s*.*\.value            # Form input value
\.innerHTML\s*=\s*.*location\.         # URL components
\.innerHTML\s*=\s*.*document\.cookie   # Cookie data
\.innerHTML\s*=\s*.*event\.data        # postMessage data

# MEDIUM RISK: Indirect sources (trace data flow)
\.innerHTML\s*=\s*[a-zA-Z_]\w*$       # Variable assignment — trace origin
\.innerHTML\s*=\s*.*\(\)              # Function return — check function

# LOW RISK: Static content
\.innerHTML\s*=\s*["'`]<              # Hardcoded HTML string (usually safe)
\.innerHTML\s*=\s*["'`]["'`]         # Empty string (safe)
\.innerHTML\s*=\s*''|""              # Clearing content (safe)
```

For any non-static innerHTML, verify DOMPurify.sanitize() wraps the value:
```
DOMPurify\.sanitize\(                  # Must wrap innerHTML input
createPurify|purify\.sanitize           # DOMPurify instance
sanitizeHtml\(                          # sanitize-html library
xss\(                                   # xss library filter
```

## Dangerous Evaluation
```
eval\(
new Function\(
setTimeout\(\s*["'`]
setInterval\(\s*["'`]
execScript\(
```

## Framework Escape Hatches
```
dangerouslySetInnerHTML
bypassSecurityTrustHtml
bypassSecurityTrustScript
bypassSecurityTrustUrl
bypassSecurityTrustResourceUrl
bypassSecurityTrustStyle
unsafeHTML\(
htmlLiteral\(
v-html=
\{@html\s
<%- .*%>                    # EJS unescaped
!\{.*\}                     # Pug unescaped
\{\{\{.*\}\}\}              # Handlebars unescaped
```

## Event Handler Injection

### Dangerous: Dynamic event handler assignment
```
\.onclick\s*=
\.onerror\s*=
\.onload\s*=
\.onmouseover\s*=
setAttribute\(["']on\w+
```

### Extended event handler surface (commonly exploited)
```
\.onfocus\s*=
\.onblur\s*=
\.onchange\s*=
\.oninput\s*=
\.onkeydown\s*=
\.onkeyup\s*=
\.onsubmit\s*=
\.ondrag\s*=
\.ondrop\s*=
\.onanimationend\s*=
\.ontransitionend\s*=
\.onpointerdown\s*=
```

### Dangerous: HTML string with event handlers (server-rendered or template)
```
on\w+\s*=\s*["'].*\$\{               # Event handler in template literal
on\w+\s*=\s*["'].*\+                  # Event handler with concatenation
on\w+\s*=\s*["'].*request              # Event handler from request data
on\w+\s*=\s*["'].*<%=                  # Event handler from server template
```

### Safe: Event listener API (preferred over inline handlers)
```
\.addEventListener\(["']\w+["']       # addEventListener (safe when handler is defined)
removeEventListener\(                   # Cleanup (good practice)
```

## URL Protocol Risks
```
href\s*=\s*.*userInput
src\s*=\s*.*userInput
window\.location\s*=
window\.location\.href\s*=
location\.assign\(
location\.replace\(
```

## CSP Issues
```
unsafe-inline
unsafe-eval
script-src\s+\*
default-src\s+\*
```

## Prototype Pollution
```
__proto__
constructor\.prototype
Object\.assign\(.*req\.body
\.merge\(.*req\.body
\.extend\(.*req\.body
\.defaultsDeep\(
```

## postMessage Issues
```
postMessage\(.*,\s*["']\*["']\)
addEventListener\(["']message
event\.data.*innerHTML
event\.data.*eval
```

## Web Storage Sensitive Data
```
localStorage\.setItem\(["']token
localStorage\.setItem\(["']auth
localStorage\.setItem\(["']session
localStorage\.setItem\(["']password
localStorage\.setItem\(["']jwt
sessionStorage\.setItem\(["']token
```

## Safe Alternatives (positive indicators)
```
\.textContent\s*=
\.insertAdjacentText\(
createElement\(
createTextNode\(
DOMPurify\.sanitize\(
encodeURIComponent\(
JSON\.parse\(
addEventListener\(
```
