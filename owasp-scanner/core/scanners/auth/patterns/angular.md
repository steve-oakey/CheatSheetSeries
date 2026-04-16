# Auth Patterns: Angular

## Token Storage (Dangerous)
```
localStorage\.setItem\(.*token
localStorage\.setItem\(.*jwt
localStorage\.setItem\(.*auth
localStorage\.getItem\(.*token
```

## Token Handling (Check for Issues)
```
HttpInterceptor                         # Should be used for auth headers
Authorization.*Bearer                  # Check token source
```

## Auth Guard Patterns
```
canActivate                            # Route guard (should exist)
canLoad                                # Lazy-load guard
AuthGuard                              # Named guard
isAuthenticated\(\)                    # Auth check method
```

Absence of route guards on protected routes is a finding.

## Client-Side Authorization (Dangerous)
```
\*ngIf=".*role.*admin                  # Client-side role check (need server too)
\*ngIf=".*isAdmin                      # Client-only admin check
localStorage\.getItem\(.*role           # Role from localStorage (spoofable)
```

These client-side checks should always be backed by server-side authorization.

## Safe Patterns
```
HttpInterceptor.*addToken               # Token via interceptor (good)
httpOnly.*cookie                        # Token in httpOnly cookie (good)
withCredentials.*true                   # Cookie-based auth (good if CSRF protected)
```
