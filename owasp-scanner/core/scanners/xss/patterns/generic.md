# XSS Patterns: Language-Agnostic

## Dangerous DOM Sinks
```
\.innerHTML\s*=
\.outerHTML\s*=
document\.write\(
document\.writeln\(
\.insertAdjacentHTML\(
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
```
\.onclick\s*=
\.onerror\s*=
\.onload\s*=
\.onmouseover\s*=
setAttribute\(["']on\w+
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
