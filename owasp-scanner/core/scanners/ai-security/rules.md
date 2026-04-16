# AI Security Rules

Rules for detecting security vulnerabilities in AI/LLM-powered applications.

## RULE-AIS-001: Prompt Injection via String Concatenation
- **Severity**: HIGH
- **CWE**: CWE-77 (Command Injection)
- **What to find**: User input concatenated directly into LLM prompts without separation
- **Patterns**:
  - String concatenation or template literals building prompts with user input
  - f-strings or format strings combining system instructions with user data
  - Missing message role separation (system vs user)
- **Fix**: Use structured message arrays with separate system/user roles. Never concatenate user input into system prompts.
- **Reference**: LLM_Prompt_Injection_Prevention_Cheat_Sheet.md

## RULE-AIS-002: System Prompt Exposure
- **Severity**: MEDIUM
- **CWE**: CWE-200 (Exposure of Sensitive Information)
- **What to find**: System prompts stored in client-accessible locations or logged
- **Patterns**:
  - System prompts in frontend JavaScript/TypeScript bundles
  - System prompts in API responses
  - System prompts logged at DEBUG/INFO level
  - System prompts in version-controlled config without encryption
- **Fix**: Store system prompts server-side only. Use environment variables or secrets managers. Never expose in client code or API responses.
- **Reference**: LLM_Prompt_Injection_Prevention_Cheat_Sheet.md

## RULE-AIS-003: Missing Output Validation
- **Severity**: HIGH
- **CWE**: CWE-20 (Improper Input Validation)
- **What to find**: LLM responses used directly without validation or sanitization
- **Patterns**:
  - LLM output passed directly to `eval()`, `exec()`, or shell commands
  - LLM output rendered as HTML without sanitization
  - LLM output used in SQL queries or database operations
  - LLM output used to construct URLs or file paths
- **Fix**: Validate and sanitize all LLM outputs before use. Apply output format schemas. Never execute LLM-generated code directly.
- **Reference**: AI_Agent_Security_Cheat_Sheet.md

## RULE-AIS-004: Excessive LLM Permissions / Tool Access
- **Severity**: HIGH
- **CWE**: CWE-250 (Execution with Unnecessary Privileges)
- **What to find**: LLM agents with unrestricted access to tools, databases, or APIs
- **Patterns**:
  - Agent tool definitions without permission boundaries
  - Database connections with write access from LLM context
  - File system access without path restrictions
  - API calls without rate limiting from LLM agents
  - Missing human-in-the-loop for destructive operations
- **Fix**: Apply least privilege to all LLM tool access. Require human approval for destructive actions. Use read-only database connections where possible.
- **Reference**: AI_Agent_Security_Cheat_Sheet.md

## RULE-AIS-005: Sensitive Data in LLM Context
- **Severity**: HIGH
- **CWE**: CWE-359 (Exposure of Private Personal Information)
- **What to find**: PII, secrets, or sensitive data passed to LLM APIs
- **Patterns**:
  - Database records with PII sent as LLM context
  - Credentials or API keys in prompt templates
  - User personal data in few-shot examples
  - Full documents sent without redaction
- **Fix**: Redact PII before sending to LLM. Use data minimization. Avoid sending secrets in prompts. Implement content filtering.
- **Reference**: AI_Agent_Security_Cheat_Sheet.md

## RULE-AIS-006: Insecure LLM API Key Management
- **Severity**: HIGH
- **CWE**: CWE-798 (Use of Hard-coded Credentials)
- **What to find**: LLM API keys hardcoded or exposed in client code
- **Patterns**:
  - OpenAI/Anthropic/Google API keys in source code
  - API keys in frontend JavaScript
  - API keys in version-controlled config files
  - Missing API key rotation
- **Fix**: Use environment variables or secrets managers. Proxy LLM calls through backend. Rotate keys regularly. Use scoped API keys.
- **Reference**: Secrets_Management_Cheat_Sheet.md

## RULE-AIS-007: Missing Rate Limiting on LLM Endpoints
- **Severity**: MEDIUM
- **CWE**: CWE-770 (Allocation of Resources Without Limits)
- **What to find**: LLM-powered endpoints without rate limiting or cost controls
- **Patterns**:
  - Chat/completion endpoints without per-user rate limits
  - No token/cost budget enforcement
  - No request size limits on prompt input
  - Missing timeout on LLM API calls
- **Fix**: Implement per-user rate limits. Set token budgets. Limit input size. Add timeouts to LLM calls.
- **Reference**: AI_Agent_Security_Cheat_Sheet.md

## RULE-AIS-008: Indirect Prompt Injection via External Data
- **Severity**: HIGH
- **CWE**: CWE-94 (Improper Control of Generation of Code)
- **What to find**: LLM processing untrusted external content that could contain injected instructions
- **Patterns**:
  - Web scraping results passed directly to LLM
  - Email content processed by LLM agents
  - User-uploaded documents analyzed by LLM without sanitization
  - RAG retrieval results used without content filtering
- **Fix**: Sanitize external content before LLM processing. Use content filtering. Implement instruction hierarchy. Mark data boundaries.
- **Reference**: LLM_Prompt_Injection_Prevention_Cheat_Sheet.md

## RULE-AIS-009: LLM Output Rendered as Markdown/HTML
- **Severity**: MEDIUM
- **CWE**: CWE-79 (Cross-site Scripting)
- **What to find**: LLM responses rendered as HTML or Markdown without sanitization
- **Patterns**:
  - LLM output in `innerHTML` or `dangerouslySetInnerHTML`
  - Markdown rendering of LLM output without link/image filtering
  - LLM output in `[innerHTML]` Angular binding
  - Image markdown in LLM response (exfiltration risk)
- **Fix**: Sanitize LLM output before rendering. Filter markdown image/link URLs. Use allowlist for rendered HTML elements.
- **Reference**: LLM_Prompt_Injection_Prevention_Cheat_Sheet.md

## RULE-AIS-010: Missing Model Input/Output Logging
- **Severity**: MEDIUM
- **CWE**: CWE-778 (Insufficient Logging)
- **What to find**: LLM interactions not logged for audit, debugging, or abuse detection
- **Patterns**:
  - LLM API calls without request/response logging
  - No audit trail for agent actions
  - Missing abuse detection on LLM outputs
  - No content policy violation tracking
- **Fix**: Log all LLM interactions (with PII redaction). Track agent actions. Monitor for policy violations. Implement anomaly detection.
- **Reference**: Secure_AI_Model_Ops_Cheat_Sheet.md

## RULE-AIS-011: Insecure Model Loading
- **Severity**: HIGH
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **What to find**: ML models loaded from untrusted sources or via insecure deserialization
- **Patterns**:
  - `pickle.load()` for model files (arbitrary code execution)
  - Models downloaded over HTTP (not HTTPS)
  - No hash/signature verification on model files
  - Models loaded from user-supplied paths
- **Fix**: Use safe serialization (safetensors, ONNX). Verify model hashes. Download over HTTPS. Never load models from user-supplied paths.
- **Reference**: Secure_AI_Model_Ops_Cheat_Sheet.md

## RULE-AIS-012: Missing Content Filtering
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **What to find**: No content safety filtering on LLM inputs or outputs
- **Patterns**:
  - No content moderation API calls before/after LLM
  - No toxicity/harm classification on outputs
  - No PII detection on inputs sent to LLM
  - No output format validation (expecting JSON but not parsing)
- **Fix**: Implement content moderation on inputs and outputs. Use structured output validation. Add PII detection before LLM calls.
- **Reference**: Secure_AI_Model_Ops_Cheat_Sheet.md

## RULE-AIS-013: Unrestricted Agent Action Chains
- **Severity**: HIGH
- **CWE**: CWE-269 (Improper Privilege Management)
- **What to find**: AI agents that can chain actions without limits or approval gates
- **Patterns**:
  - Agent loops without iteration limits
  - Multi-tool chains without human approval checkpoints
  - Recursive agent calls without depth limits
  - Agents that can invoke other agents without restrictions
- **Fix**: Set iteration limits on agent loops. Add human-in-the-loop for multi-step chains. Limit recursion depth. Restrict cross-agent invocation.
- **Reference**: AI_Agent_Security_Cheat_Sheet.md
