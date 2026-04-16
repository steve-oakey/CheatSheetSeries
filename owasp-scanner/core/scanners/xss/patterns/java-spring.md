# XSS Patterns: Java / Spring Boot

## Server-Side XSS Sinks

### Template Engine Unescaped Output
```
th:utext=                               # Thymeleaf unescaped
\$\{.*\}.*unescaped                     # JSP/JSTL unescaped
<%= .*%>                                # JSP expression (not auto-escaped)
c:out.*escapeXml="false"               # JSTL with escaping disabled
```

### Response Writing
```
response\.getWriter\(\)\.write\(.*request   # Direct request to response
response\.getWriter\(\)\.print\(.*getParameter
PrintWriter.*write\(.*getParameter
HttpServletResponse.*getOutputStream.*write
```

### Spring MVC
```
@ResponseBody.*return.*request\.getParameter    # Reflecting input
ModelAndView.*addObject\(.*request\.getParameter # Unsanitized model attribute
```

## CSP Configuration (Spring Security)

### Dangerous
```
\.headers\(\)\.contentSecurityPolicy\(.*unsafe-inline
\.headers\(\)\.contentSecurityPolicy\(.*unsafe-eval
\.headers\(\)\.disable\(\)              # Disabling all headers
contentSecurityPolicy\(\)\.disable\(\)  # Disabling CSP
```

### Safe
```
\.headers\(\)\.contentSecurityPolicy\(".*nonce-
\.headers\(\)\.contentSecurityPolicy\(".*strict-dynamic
```

## Safe Patterns
```
HtmlUtils\.htmlEscape\(                 # Spring HTML escaping
StringEscapeUtils\.escapeHtml4\(        # Commons Text
ESAPI\.encoder\(\)\.encodeForHTML\(     # OWASP ESAPI
@XssProtection                          # Spring Security header
th:text=                                # Thymeleaf auto-escaped
c:out.*escapeXml="true"                 # JSTL with escaping
```
