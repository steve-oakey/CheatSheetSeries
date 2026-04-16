# Supply Chain Patterns: Angular / TypeScript

## Secrets in Client Code
```
apiKey\s*[:=]\s*["'][^"']{8,}["']       # API key in TypeScript
api_key\s*[:=]\s*["'][^"']{8,}["']
secret\s*[:=]\s*["'][^"']{8,}["']
token\s*[:=]\s*["'][^"']{8,}["']
```

Note: Client-side code is publicly accessible. ANY secret in Angular source is exposed.
Check `environment.ts` and `environment.prod.ts` for embedded secrets.

## Environment Files
```
environment\.prod\.ts.*apiKey           # API key in production config
environment\.prod\.ts.*secret           # Secret in production config
environment\.ts.*password               # Password in environment file
```

## Package Security
```
package-lock\.json                      # Should exist
npm audit                               # Should be in CI
postinstall.*curl|wget                  # Suspicious postinstall scripts
```

## SRI for CDN Resources
Check `angular.json` or `index.html` for external scripts without integrity:
```
<script src="https://.*"(?!.*integrity)
<link.*href="https://.*"(?!.*integrity)
```

## Safe Patterns
```
environment\.\w+\s*[:=]\s*["']/api     # Relative API URLs (good)
HttpInterceptor.*apiKey                 # Key added at runtime (check source)
```
