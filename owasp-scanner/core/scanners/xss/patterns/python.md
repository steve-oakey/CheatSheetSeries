# XSS Patterns: Python (Django / Flask / FastAPI)

## Django Template XSS

### Dangerous: Escaping disabled
```
\|safe\b                                # |safe filter bypasses auto-escaping
mark_safe\(                             # Marks string as safe HTML
\{% autoescape off %\}                  # Disables auto-escaping for block
format_html\(.*\+                       # format_html with concatenation (defeats purpose)
```

### |safe filter analysis guidance
```
# CRITICAL: User-controlled data passed through |safe
\|safe.*\{\{.*request                   # Request data marked safe
mark_safe\(.*request\.|mark_safe\(.*form # User input marked safe
mark_safe\(.*f"|mark_safe\(.*\.format   # Dynamic content marked safe

# ACCEPTABLE: Static or admin-controlled content
mark_safe\(.*"<                         # Hardcoded HTML string (usually safe)
format_html\(".*\{\}".*,               # format_html with placeholders (good — escapes args)
```

### Safe: Django auto-escaping
```
\{\{.*\}\}                              # Template interpolation (auto-escaped)
\|escape\b                              # Explicit escape filter
\|escapejs\b                            # JavaScript string escaping
format_html\(                           # format_html (escapes arguments, good)
conditional_escape\(                    # Escapes if not already safe (good)
```

## Jinja2 Template XSS

### Dangerous: Markup bypass
```
Markup\(.*request\.|Markup\(.*f"        # Markup with user input
Markup\(.*\.format\(                    # Markup with .format()
autoescape=False                        # Jinja2 env with escaping disabled
\|safe\b                                # Jinja2 |safe filter (same as Django)
```

### Safe: Jinja2 auto-escaping
```
autoescape=True                         # Auto-escaping enabled (good)
autoescape=select_autoescape            # Smart auto-escaping (good)
Environment\(.*autoescape=True          # Environment with escaping (good)
\|e\b                                   # Explicit escape filter (good)
```

## Flask SSTI → XSS

### Dangerous: Template string rendering with user input
```
render_template_string\(.*request\.     # CRITICAL: request data in template source
render_template_string\(.*form\[        # CRITICAL: form data in template
render_template_string\(.*args          # HIGH: args in template source
Markup\(.*request\.                     # Marking request data as safe
```

### Safe: File-based template rendering
```
render_template\("                      # File-based rendering (good)
render_template\('                      # File-based rendering (good)
```

## CSP Configuration

### Django CSP (django-csp middleware)
```
CSP_DEFAULT_SRC.*'unsafe-inline'        # Unsafe inline in CSP
CSP_SCRIPT_SRC.*'unsafe-inline'         # Unsafe inline scripts
CSP_SCRIPT_SRC.*'unsafe-eval'           # Unsafe eval in scripts
CSP_DEFAULT_SRC.*\*                     # Wildcard CSP source
```

### Missing CSP check
Verify `django-csp` or `CSP_*` settings exist. Absence of CSP configuration is a finding.
```
MIDDLEWARE.*csp\.middleware              # django-csp middleware present (good)
CSP_DEFAULT_SRC                         # CSP configured (good)
```

### Flask CSP (Flask-Talisman)
```
Talisman\(.*content_security_policy=None  # CSP disabled in Talisman
Talisman\(.*force_https=False             # HTTPS not enforced
```
Absence of `Talisman` or `flask-talisman` in Flask apps is a finding.

## Response Writing

### Dangerous: Unsanitized content in responses
```
make_response\(.*request\.              # Flask response with request data
Response\(.*request\.|HttpResponse\(.*request\. # Response with request data
JsonResponse\(.*request\.GET            # JSON with unvalidated params
```

### Safe: Sanitized response
```
bleach\.clean\(                         # bleach HTML sanitizer (good)
bleach\.sanitize\(                      # bleach sanitizer (good)
nh3\.clean\(                            # nh3 HTML sanitizer (good, Rust-based)
```
