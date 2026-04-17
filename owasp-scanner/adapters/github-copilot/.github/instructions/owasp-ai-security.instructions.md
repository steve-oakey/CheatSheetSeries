---
applyTo: "**/*agent*,**/*llm*,**/*openai*,**/*anthropic*,**/*langchain*,**/*chat*,**/*prompt*,**/*completion*,**/*embedding*,**/*ai*,**/*gemini*,**/*spring-ai*"
---

# OWASP AI Security Checks

When reviewing or generating AI/LLM-related code, watch for these vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### Prompt Injection via String Concatenation (RULE-AIS-001, CWE-77)
- String concatenation or template literals building prompts with user input
- f-strings or format strings combining system instructions with user data
- Missing message role separation (system vs user)
- **Fix**: Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.

### System Prompt Exposure (RULE-AIS-002, CWE-200)
- System prompts in frontend JavaScript/TypeScript bundles
- System prompts in API responses
- System prompts logged at DEBUG/INFO level
- **Fix**: Store system prompts server-side only. Use environment variables or secrets managers.

### Missing Output Validation (RULE-AIS-003, CWE-20)
- LLM output passed directly to `eval()`, `exec()`, or shell commands
- LLM output rendered as HTML without sanitization
- LLM output used in SQL queries or database operations
- LLM output used to construct URLs or file paths
- **Fix**: Validate and sanitize all LLM outputs before use. Apply output format schemas. Never execute LLM-generated code directly.

### Excessive LLM Permissions (RULE-AIS-004, CWE-250)
- Agent tool definitions without permission boundaries
- Database connections with write access from LLM context
- File system access without path restrictions
- Missing human-in-the-loop for destructive operations
- **Fix**: Apply least privilege to all LLM tool access. Require human approval for destructive actions.

### Sensitive Data in LLM Context (RULE-AIS-005, CWE-359)
- Database records with PII sent as LLM context
- Credentials or API keys in prompt templates
- User personal data in few-shot examples
- **Fix**: Redact PII before sending to LLM. Use data minimization. Implement content filtering.

### Insecure LLM API Key Management (RULE-AIS-006, CWE-798)
- OpenAI/Anthropic/Google API keys in source code
- API keys in frontend JavaScript
- API keys in version-controlled config files
- **Fix**: Use environment variables or secrets managers. Proxy LLM calls through backend.

### Missing Rate Limiting on LLM Endpoints (RULE-AIS-007, CWE-770)
- Chat/completion endpoints without per-user rate limits
- No token/cost budget enforcement
- No request size limits on prompt input
- **Fix**: Implement per-user rate limits. Set token budgets. Limit input size. Add timeouts.

### Indirect Prompt Injection (RULE-AIS-008, CWE-94)
- Web scraping results passed directly to LLM
- Email content processed by LLM agents
- User-uploaded documents analyzed without sanitization
- RAG retrieval results used without content filtering
- **Fix**: Sanitize external content before LLM processing. Implement instruction hierarchy. Mark data boundaries.

### LLM Output Rendered as HTML/Markdown (RULE-AIS-009, CWE-79)
- LLM output in `innerHTML` or `dangerouslySetInnerHTML`
- Markdown rendering of LLM output without link/image filtering
- **Fix**: Sanitize LLM output before rendering. Filter markdown image/link URLs.

## Proof of Concept

For HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rule definitions. Use benign payloads that prove the vulnerability exists without causing damage.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/ai-security/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/ai-security/patterns/`.
