# AI Security Patterns: Angular

## LLM Output Rendered in Templates (RULE-AIS-009)

### Dangerous: LLM response rendered without sanitization
```
\[innerHTML\]=.*message                  # LLM message in innerHTML binding
\[innerHTML\]=.*response                 # LLM response in innerHTML binding
\[innerHTML\]=.*chat                     # Chat output in innerHTML binding
bypassSecurityTrustHtml\(.*response      # Bypassing sanitizer for LLM output
bypassSecurityTrustHtml\(.*message       # Bypassing sanitizer for chat message
```

### Dangerous: Markdown rendering of LLM output
```
marked\(.*response\)|marked\(.*message\) # Markdown rendering without sanitize
ngx-markdown.*message|ngx-markdown.*chat # ngx-markdown with LLM output
\[data\]=.*response.*markdown            # Markdown component with LLM data
```

### Safe: Sanitized rendering
```
DomSanitizer\.sanitize\(.*response       # Angular DomSanitizer (good)
DOMPurify\.sanitize\(.*marked            # DOMPurify + marked (good)
\{\{.*message.*\}\}                      # Interpolation (auto-escaped by Angular)
\[textContent\]=.*message                # textContent binding (safe)
```

## System Prompt Exposure in Frontend (RULE-AIS-002)

### Dangerous: System prompts in Angular code
```
systemPrompt\s*[:=]\s*['"`]             # System prompt in component/service
SYSTEM_PROMPT\s*=\s*['"`]              # System prompt constant
environment\..*systemPrompt             # System prompt in environment config
```

### Safe: Prompts on server only
```
this\.http\.(post|get)\(.*chat          # API call to backend (good — prompt is server-side)
ChatService.*sendMessage                 # Service that calls backend (good)
```

## Insecure LLM API Key in Frontend (RULE-AIS-006)

### Dangerous: Direct LLM API calls from Angular
```
environment\..*openai.*key              # OpenAI key in environment
environment\..*anthropic.*key           # Anthropic key in environment
HttpClient.*api\.openai\.com            # Direct OpenAI API call from frontend
HttpClient.*api\.anthropic\.com         # Direct Anthropic API call from frontend
fetch\(.*openai|fetch\(.*anthropic      # Fetch to LLM API from frontend
Authorization.*Bearer.*sk-             # Bearer token with OpenAI key
x-api-key.*sk-ant-                     # Anthropic API key header
```

### Safe: Backend proxy
```
HttpClient.*\/api\/chat                 # Proxied through backend (good)
HttpClient.*\/api\/completion           # Proxied through backend (good)
environment\.apiUrl.*chat               # Using backend URL (good)
```

## Missing Rate Limiting on Frontend (RULE-AIS-007)

### Check for client-side rate limiting
```
sendMessage|submitChat|askQuestion      # Chat submission function
```
Verify debouncing or throttling:
```
debounce|debounceTime|throttle          # Debounce/throttle (good)
Subject.*pipe.*debounce                 # RxJS debounce (good)
disabled.*loading|isLoading             # UI blocking during request (good)
```

## Content Display Safety (RULE-AIS-009)

### Check for image/link filtering in chat display
```
\[src\]=.*message|img.*message          # Images from LLM output — check filtering
\[href\]=.*message|a.*message           # Links from LLM output — check filtering
```
Verify link/image sanitization:
```
DOMPurify.*FORBID_TAGS.*img             # Image tag forbidden (good)
DOMPurify.*FORBID_ATTR.*src             # src attribute forbidden (good)
sanitize.*allowedTags(?!.*img)          # Images not in allowlist (good)
target="_blank".*rel="noopener"         # Safe external links (good)
```
