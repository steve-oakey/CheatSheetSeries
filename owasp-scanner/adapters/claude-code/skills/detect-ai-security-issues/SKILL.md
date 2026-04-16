---
name: detect-ai-security-issues
description: "Detects potential AI/LLM security vulnerabilities when code involving LLM API calls, prompt construction, agent tool definitions, or model loading is being written. Triggers on OpenAI, Anthropic, LangChain, Spring AI, prompt template, agent tool patterns."
version: "1.0.0"
---

When you detect code being written that involves LLM API calls, prompt construction, AI agent configuration, or model loading, check for AI security vulnerabilities.

Read the AI security rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/rules.md` and warn about violations.

Key patterns to watch for:
- User input concatenated into LLM prompts (use structured message arrays with role separation)
- System prompts in client-side code or logs (keep server-side only)
- LLM output passed to `eval()`, `exec()`, `innerHTML`, or SQL queries (validate and sanitize all output)
- LLM API keys hardcoded in source or frontend code (use env vars or secrets manager, proxy through backend)
- Agent tools with unrestricted write/delete access (apply least privilege, add human-in-the-loop)
- PII or secrets included in LLM context (redact before sending)
- `pickle.load()` for model files (use safetensors or ONNX)
- Unbounded agent loops without iteration limits (set max_iterations)
- LLM output rendered as HTML/Markdown without sanitization (use DOMPurify)
- Missing rate limiting on chat/completion endpoints (add per-user limits and timeouts)

Provide inline warnings with the specific RULE-AIS-* ID.
