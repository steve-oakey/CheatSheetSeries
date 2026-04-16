# AI Security Patterns: Language-Agnostic

Search patterns that apply regardless of programming language.

## Prompt Injection via String Concatenation (RULE-AIS-001)

### Dangerous: User input concatenated into prompts
```
prompt\s*=.*\+.*user_input              # String concat with user input
prompt\s*=.*\+.*request                 # Concat with request data
prompt\s*=.*\+.*query                   # Concat with query
f".*\{user_input\}.*"                  # f-string with user input
f".*\{request\..*\}.*"                 # f-string with request data
`.*\$\{userInput\}.*`                  # Template literal with user input
String\.format\(.*prompt.*userInput     # Format string with user input
prompt\.replace\(.*user                 # String replacement with user data
system_prompt\s*\+\s*user              # System prompt + user input concatenation
"You are.*"\s*\+                       # System instruction concatenated
```

### Dangerous: Single-string prompt (no role separation)
```
client\.(generate|complete|chat)\(.*\+  # LLM call with string concat
openai\..*completions\.create\(.*prompt\s*= # Legacy single-prompt API
llm\.(call|invoke|predict)\(.*\+        # LLM call with concatenation
```

### Safe: Structured message arrays with role separation
```
\{"role":\s*"system"                    # System role message (good)
\{"role":\s*"user"                      # User role message (good)
messages\s*=\s*\[                       # Message array (good)
ChatMessage|SystemMessage|UserMessage   # Typed message objects (good)
HumanMessage|AIMessage                  # LangChain message types (good)
ChatPromptTemplate                      # LangChain template (good)
PromptTemplate.*input_variables         # Parameterized template (good)
```

## System Prompt Exposure (RULE-AIS-002)

### Dangerous: System prompts in client-accessible code
```
const.*system.*prompt\s*=\s*["'`]       # System prompt in JS constant
export.*system.*prompt                  # Exported prompt
window\..*prompt                        # Prompt in window object
SYSTEM_PROMPT\s*=.*["'`]               # System prompt constant
```

### Dangerous: System prompts logged
```
log.*(system.*prompt|SYSTEM_PROMPT)     # System prompt in logs
console\.log\(.*prompt                  # Console logging prompts
print\(.*system.*prompt                 # Printing system prompt
logger.*(prompt|instruction)            # Logging prompts
```

### Safe: Server-side prompt storage
```
process\.env\.SYSTEM_PROMPT             # Environment variable (good)
os\.environ.*SYSTEM_PROMPT              # Python env var (good)
@Value.*system\.prompt                  # Spring property injection (good)
secrets.*system.*prompt                 # Secrets manager (good)
```

## Missing Output Validation (RULE-AIS-003)

### Dangerous: LLM output used in dangerous sinks
```
eval\(.*response|eval\(.*completion     # LLM output executed
exec\(.*response|exec\(.*completion     # LLM output executed
system\(.*response|system\(.*output     # LLM output in shell command
innerHTML.*response|innerHTML.*output   # LLM output as HTML
dangerouslySetInnerHTML.*response       # React: LLM output as HTML
cursor\.execute\(.*response             # LLM output in SQL
open\(.*response|open\(.*output         # LLM output as file path
subprocess.*response|subprocess.*output # LLM output in subprocess
```

### Safe: Validated LLM output
```
json\.loads\(.*response                 # JSON parsing (validates structure)
schema\.validate\(.*response            # Schema validation
DOMPurify\.sanitize\(.*response         # HTML sanitization
sanitize.*response|sanitize.*output     # Generic sanitization
parse.*response.*schema                 # Structured parsing
```

## Excessive LLM Permissions / Tool Access (RULE-AIS-004)

### Dangerous: Unrestricted tool/action access
```
tools\s*=\s*\[.*\].*#.*all             # All tools enabled
allow.*all.*tools|all.*actions          # All actions permitted
"write"|"delete"|"update".*tool         # Destructive tool access
database.*connection(?!.*read.only)     # Non-read-only DB from agent
```

### Safe: Restricted tool access
```
read.only|readOnly|READ_ONLY            # Read-only access (good)
allow.*list|permitted.*tools            # Tool allowlist (good)
human.*approval|human.*in.*loop         # HITL requirement (good)
confirm.*before.*execut                 # Confirmation gate (good)
max.*iterations|MAX.*STEPS              # Iteration limit (good)
```

## Sensitive Data in LLM Context (RULE-AIS-005)

### Dangerous: PII/secrets sent to LLM
```
prompt.*password|prompt.*secret         # Secrets in prompt
context.*ssn|context.*social_security   # SSN in context
context.*credit_card|context.*ccNumber  # Credit card in context
messages.*email.*@.*password            # PII in messages
api_key.*prompt|token.*prompt           # API keys in prompt
```

### Safe: Redacted data
```
redact|mask|anonymize                   # Data redaction (good)
\[REDACTED\]|\*\*\*\*                  # Masked values (good)
pii.*filter|pii.*detect                 # PII detection (good)
```

## Insecure LLM API Key Management (RULE-AIS-006)

### Dangerous: Hardcoded API keys
```
OPENAI_API_KEY\s*=\s*["']sk-           # OpenAI key hardcoded
ANTHROPIC_API_KEY\s*=\s*["']sk-ant-    # Anthropic key hardcoded
GOOGLE_API_KEY\s*=\s*["']AIza          # Google AI key hardcoded
api[_-]?key\s*[:=]\s*["'][A-Za-z0-9]{20,}  # Generic API key hardcoded
HUGGING_FACE.*TOKEN\s*=\s*["']hf_     # HuggingFace token hardcoded
COHERE_API_KEY\s*=\s*["']              # Cohere key hardcoded
```

### Dangerous: API keys in frontend
```
fetch\(.*api\.openai\.com.*Authorization  # Direct OpenAI call from frontend
fetch\(.*api\.anthropic\.com.*x-api-key   # Direct Anthropic call from frontend
XMLHttpRequest.*openai|XMLHttpRequest.*anthropic  # XHR to LLM API
```

### Safe: Proper key management
```
process\.env\.OPENAI_API_KEY            # Environment variable (good)
os\.environ.*API_KEY                    # Python env var (good)
secrets.*manager|vault.*api_key         # Secrets manager (good)
/api/chat|/api/completion              # Backend proxy endpoint (good)
```

## Missing Rate Limiting on LLM Endpoints (RULE-AIS-007)

### Check for rate limiting on AI endpoints
```
/chat|/completion|/generate|/ask        # AI endpoints — verify rate limiting
/agent|/assistant|/copilot              # Agent endpoints — verify rate limiting
```
Verify at least ONE protection:
```
rateLimit|rate.limit|throttle           # Rate limiting present
max.*tokens|maxTokens|token.*limit      # Token budget
timeout|TIMEOUT.*llm|llm.*timeout       # Timeout configured
max.*request.*size|maxRequestSize       # Input size limit
```

## Indirect Prompt Injection via External Data (RULE-AIS-008)

### Dangerous: Untrusted content sent to LLM
```
scrape|crawl|fetch.*url.*prompt         # Web content → LLM
email.*content.*prompt                  # Email → LLM
upload.*document.*prompt|pdf.*prompt    # Document → LLM
retriev.*context.*prompt                # RAG retrieval → LLM (check filtering)
```

### Safe: Content filtering
```
sanitize.*content.*before.*llm          # Sanitization before LLM
content.*filter|filter.*content         # Content filtering
strip.*html|remove.*script              # HTML stripping
instruction.*boundary|data.*boundary    # Boundary markers
```

## LLM Output Rendered as Markdown/HTML (RULE-AIS-009)

### Dangerous: Rendering LLM output without sanitization
```
innerHTML.*llm|innerHTML.*ai            # LLM output in innerHTML
dangerouslySetInnerHTML.*chat           # Chat output in React innerHTML
\[innerHTML\].*message                  # Angular binding with LLM message
v-html.*response|v-html.*message        # Vue v-html with LLM output
marked\(.*response\)|marked\(.*output\) # Markdown rendering without sanitize
```

### Dangerous: Image/link exfiltration in markdown
```
!\[.*\]\(https?://                      # LLM markdown image (may exfiltrate data in URL)
\[.*\]\(javascript:                     # JavaScript link in LLM output
```

### Safe: Sanitized rendering
```
DOMPurify\.sanitize.*marked             # Sanitized markdown (good)
sanitize.*markdown|markdown.*sanitize   # Sanitized markdown (good)
allowedTags|allowedAttributes           # HTML allowlist (good)
disableImageRendering|filterImages      # Image filtering (good)
```

## Missing Model Input/Output Logging (RULE-AIS-010)

### Check for LLM interaction logging
```
openai|anthropic|cohere|google.*ai      # LLM API usage — verify logging
langchain|llamaindex|semantic.kernel    # Framework usage — verify logging
```
Verify at least ONE:
```
log.*prompt|log.*completion             # Prompt/completion logging
audit.*llm|audit.*ai                    # AI audit trail
trace|tracing|span                      # Distributed tracing
monitor.*llm|observe.*llm              # LLM monitoring
langfuse|langsmith|phoenix              # LLM observability tool
```

## Insecure Model Loading (RULE-AIS-011)

### Dangerous: Unsafe model deserialization
```
pickle\.load\(|pickle\.loads\(          # Pickle deserialization (RCE risk)
torch\.load\((?!.*weights_only)         # PyTorch load without weights_only
joblib\.load\(                          # Joblib (uses pickle)
cloudpickle\.load\(                     # CloudPickle (uses pickle)
dill\.load\(                            # Dill (uses pickle)
```

### Dangerous: Model from untrusted source
```
http://.*model|http://.*\.pkl           # Model over HTTP
http://.*\.pt|http://.*\.bin            # Model over HTTP
from_pretrained\(.*http://              # HuggingFace over HTTP
```

### Safe: Secure model loading
```
safetensors|\.safetensors               # Safe serialization format (good)
torch\.load\(.*weights_only=True        # PyTorch safe mode (good)
onnxruntime|\.onnx                      # ONNX format (good)
verify.*hash|verify.*checksum           # Hash verification (good)
from_pretrained\(.*trust_remote_code=False  # Untrusted code disabled (good)
```

## Missing Content Filtering (RULE-AIS-012)

### Check for content moderation
Look for LLM API calls without moderation checks:
```
openai\..*create\(                      # OpenAI call — check for moderation
anthropic\..*create\(                   # Anthropic call — check for moderation
generate|complete|chat                  # Generic LLM call — check for moderation
```
Verify at least ONE content safety measure:
```
moderation|moderate|content.*filter     # Content moderation
toxicity|harmful|unsafe                 # Safety classification
guardrails|NeMo.*Guardrails             # Guardrails framework
content.*policy|safety.*check           # Policy enforcement
```

## Unrestricted Agent Action Chains (RULE-AIS-013)

### Dangerous: Unbounded agent loops
```
while\s+True.*agent|while\s+True.*tool  # Infinite agent loop
for.*range\(.*999|for.*range\(.*10000   # Excessive iteration count
recursive.*agent.*call(?!.*depth)       # Recursive agent without depth limit
agent.*invoke.*agent(?!.*limit)         # Agent-to-agent without limits
```

### Safe: Bounded agent execution
```
max_iterations|MAX_ITERATIONS           # Iteration limit (good)
max_steps|MAX_STEPS                     # Step limit (good)
recursion_limit|max_depth               # Depth limit (good)
human.*approve|require.*confirmation    # Human approval gate (good)
timeout.*agent|agent.*timeout           # Agent timeout (good)
```
