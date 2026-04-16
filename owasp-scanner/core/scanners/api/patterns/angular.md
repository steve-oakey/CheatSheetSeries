# API Patterns: Angular

## SSRF via Angular (Client-Side)
Angular runs client-side, so direct SSRF is not possible. However, watch for:
```
this\.http\.\w+\(.*\+.*userInput       # URL construction with user input
this\.http\.\w+\(`.*\$\{.*input        # Template literal URL with user input
window\.location\.href\s*=             # Open redirect
```

## Unvalidated Redirects
```
window\.location\s*=\s*.*route\.snapshot  # Redirect from route params
window\.location\.href\s*=.*queryParam
this\.router\.navigate\(.*param         # Check if param is validated
```

## File Upload
```
FormData\(\)                            # Check for file validation
\.append\(.*'file'                     # Check if size/type validated
accept=                                # Check file type restrictions
```

## Error Handling
```
catchError\(.*console\.(log|error)     # Logging full errors
\.subscribe\(.*error.*alert\(          # Showing errors to user
HttpErrorResponse.*message.*component  # Displaying raw error messages
```

## API Communication
```
http://                                 # Should use https://
environment\.\w+Url.*http://           # HTTP in environment config
```

## Safe Patterns
```
HttpInterceptor.*catchError             # Centralized error handling
environment\.\w+Url.*https://          # HTTPS URLs
withCredentials.*true                   # Cookie-based auth
```
