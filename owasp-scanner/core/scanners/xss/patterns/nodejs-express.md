# XSS Patterns: Node.js / Express

## EJS Template XSS

### Dangerous: Unescaped output
```
<%- .*%>                                 # EJS unescaped output tag
<%- .*req\.|<%- .*user                   # Unescaped request/user data
```

### Safe: Escaped output
```
<%= .*%>                                 # EJS escaped output tag (good)
```

## Pug/Jade Template XSS

### Dangerous: Unescaped output
```
!=\s*\w+                                 # Pug unescaped interpolation
!{.*}                                    # Pug unescaped buffered code
- var.*innerHTML|!= .*innerHTML          # innerHTML in Pug template
```

### Safe: Escaped output
```
=\s*\w+(?!=)                             # Pug escaped interpolation (good)
\#\{.*\}                                 # Pug escaped interpolation (good)
```

## Nunjucks Template XSS

### Dangerous: Unescaped output
```
\|safe\b                                 # Nunjucks |safe filter
autoescape\s*=\s*false|autoescape:\s*false # Auto-escaping disabled
```

### Safe: Escaped output
```
\{\{.*\}\}                               # Nunjucks auto-escaped output (good)
\|escape\b                               # Explicit escape filter (good)
autoescape\s*=\s*true|autoescape:\s*true # Auto-escaping enabled (good)
```

## Handlebars Template XSS

### Dangerous: Unescaped output
```
\{\{\{.*\}\}\}                           # Handlebars triple-stash (unescaped)
new Handlebars\.SafeString\(.*req\.      # SafeString with user input
Handlebars\.Utils\.escapeExpression.*(?!.*return) # Review custom helper escaping
```

### Safe: Escaped output
```
\{\{[^{].*[^}]\}\}                       # Handlebars double-stash (escaped, good)
Handlebars\.Utils\.escapeExpression\(    # Explicit escaping (good)
```

## Direct DOM/Response XSS

### Dangerous: Unsanitized content in response
```
res\.send\(.*req\.|res\.write\(.*req\.   # Response with raw request data
res\.send\(.*\$\{.*req\.|res\.send\(.*\+.*req\. # Response with interpolated request
innerHTML\s*=.*req\.|\.html\(.*req\.     # innerHTML with request data
document\.write\(.*req\.                 # document.write with request data
```

### Safe: Sanitized response
```
res\.json\(|res\.jsonp\(                 # JSON response (auto-escaped, good)
res\.render\(["']                        # Template rendering (good, uses escaping)
```

## HTML Sanitization

### Dangerous: No sanitization
```
req\.(body|query|params)\.\w+(?=.*res\.(send|write)) # Request data directly in response
```

### Safe: Sanitization libraries
```
DOMPurify\.sanitize\(                    # DOMPurify (good)
sanitize-html|sanitizeHtml\(            # sanitize-html library (good)
xss\(|require\(["']xss["']\)            # xss library (good)
isomorphic-dompurify                     # Isomorphic DOMPurify (good)
```

## CSP Configuration

### Dangerous: Weak CSP
```
helmet\.contentSecurityPolicy\(.*unsafe-inline # Helmet CSP with unsafe-inline
Content-Security-Policy.*unsafe-eval     # CSP with unsafe-eval
contentSecurityPolicy:\s*false           # CSP disabled in Helmet
```

### Safe: Strong CSP
```
helmet\(\)|helmet\.contentSecurityPolicy\( # Helmet with defaults (good)
nonce.*cspNonce|res\.locals\.nonce        # CSP nonce implementation (good)
```

### Missing Helmet check
Absence of `helmet` middleware in Express apps is a finding.
```
app\.use\(helmet\(\)\)                    # Helmet enabled (good)
const helmet = require\(["']helmet["']\) # Helmet imported (good)
import helmet from ["']helmet["']        # Helmet imported ESM (good)
```

## Cookie Security

### Dangerous: Insecure cookies
```
res\.cookie\(.*httpOnly:\s*false         # Cookie accessible to JS
res\.cookie\(.*secure:\s*false           # Cookie sent over HTTP
res\.cookie\(.*sameSite:\s*["']none      # SameSite=None (review)
session\(\{.*cookie:\s*\{.*secure:\s*false # Session cookie not secure
```

### Safe: Secure cookies
```
res\.cookie\(.*httpOnly:\s*true          # HttpOnly cookie (good)
res\.cookie\(.*secure:\s*true            # Secure cookie (good)
res\.cookie\(.*sameSite:\s*["'](strict|lax) # SameSite set (good)
```

## CSRF Protection

### Dangerous: Missing CSRF
Absence of CSRF middleware (`csurf`, `csrf-csrf`, `lusca`) on state-changing endpoints is a finding.

### Safe: CSRF protection
```
csurf\(\)|csrf\(\)                       # CSRF middleware (good)
lusca\.csrf\(\)                          # Lusca CSRF (good)
csrfToken|_csrf                          # CSRF token usage (good)
```
