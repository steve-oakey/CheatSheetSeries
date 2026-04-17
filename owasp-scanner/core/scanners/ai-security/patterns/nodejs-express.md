# AI Security Patterns: Node.js / Express

## LLM Prompt Injection

### Dangerous: Unvalidated user input in prompts
```
`.*\$\{req\.body\.\w+\}.*`.*createChatCompletion # Template literal with request data
prompt.*\+.*req\.body|prompt.*\+.*req\.query     # Prompt concatenation with request
messages\.push\(\{.*content:.*req\.body           # Raw request data in chat message
content:.*`.*\$\{req\.(body|query|params)         # Template literal with request data
new HumanMessage\(.*req\.|HumanMessage\(.*req\.body # LangChain with raw request
```

### Safe: Sanitized prompt construction
```
\{role:\s*["']system["'].*\},\s*\{role:\s*["']user # Separated system/user roles (good)
ChatPromptTemplate\.fromMessages\(       # LangChain template (good)
PromptTemplate\.fromTemplate\(           # LangChain parameterized template (good)
sanitizeInput\(|cleanPrompt\(            # Input sanitization function (good)
```

## Sensitive Data in LLM Context

### Dangerous: PII/secrets in prompts
```
openai\..*create\(.*password|\.chat\.completions.*secret # Secrets in API calls
prompt.*process\.env\.|messages.*process\.env\.          # Environment secrets in prompt
content.*creditCard|content.*ssn|content.*socialSecurity # PII in messages
```

### Safe: Data sanitization before LLM
```
redact\(|mask\(|anonymize\(              # Data redaction (good)
stripPii\(|removePii\(                   # PII removal (good)
\.replace\(/.*password.*/gi              # Pattern-based masking (good)
```

## Insecure Output Handling

### Dangerous: Unvalidated LLM output execution
```
eval\(.*response\.|eval\(.*completion    # Evaluating LLM output
new Function\(.*response\.               # Function from LLM output
child_process\.\w+\(.*response\.         # LLM output as command
vm\.runInContext\(.*response\.            # VM execution of LLM output
cursor\.execute\(.*response\.|\.query\(.*completion # LLM output as SQL
res\.send\(.*completion|innerHTML.*response # LLM output in HTML (XSS)
```

### Safe: Validated LLM output
```
JSON\.parse\(.*response\.                # JSON parsing only (good)
schema\.validate\(.*response|zod.*parse\(.*response # Schema validation (good)
DOMPurify\.sanitize\(.*completion        # HTML sanitization of output (good)
```

## Agent Tool Abuse

### Dangerous: Unrestricted agent tools
```
tools:\s*\[.*\](?!.*allowedTools)        # Tools without restrictions
AgentExecutor.*tools=(?!.*maxIterations) # Agent without iteration limit
\.run\(.*\)(?!.*callbacks|.*timeout)     # Agent run without monitoring
createAgent\(.*tools=(?!.*allowed)       # Agent creation without tool restrictions
```

### Safe: Restricted agent tools
```
maxIterations:\s*\d+                     # Iteration limit (good)
allowedTools:\s*\[                       # Tool allowlist (good)
returnIntermediateSteps:\s*true          # Steps logged (good)
callbacks:\s*\[.*\]                      # Monitoring callbacks (good)
timeout:\s*\d+                           # Execution timeout (good)
```

## RAG Pipeline Security

### Dangerous: Unvalidated retrieval
```
\.similaritySearch\(.*req\.body          # Raw user input in vector search
retriever\.getRelevantDocuments\(.*req\. # Raw request in retriever
asRetriever\(\)(?!.*k:\s*\d)             # Retriever without result limit
```

### Safe: Validated RAG
```
asRetriever\(\{.*k:\s*\d+               # Result count limited (good)
similaritySearch\(.*\d+\)                # Limited similarity search (good)
scoreThreshold:|minScore:                # Score filtering (good)
filter:\s*\{|where:\s*\{                 # Metadata filtering (good)
```

## Model/API Key Management

### Dangerous: Hardcoded API keys
```
OPENAI_API_KEY\s*=\s*["']sk-            # Hardcoded OpenAI key
openai\.apiKey\s*=\s*["']sk-            # Hardcoded OpenAI key
ANTHROPIC_API_KEY\s*=\s*["']            # Hardcoded Anthropic key
apiKey:\s*["']sk-|apiKey:\s*["']xai-    # Hardcoded API key in config
HF_TOKEN\s*=\s*["']hf_                  # Hardcoded HuggingFace token
```

### Safe: Environment-based keys
```
process\.env\.OPENAI_API_KEY             # Key from environment (good)
process\.env\.ANTHROPIC_API_KEY          # Key from environment (good)
Configuration\(\{.*apiKey:\s*process\.env # Config with env key (good)
```

## Model Loading Security

### Dangerous: Unsafe model loading
```
loadModel\(.*req\.|from_pretrained\(.*req\. # User-controlled model loading
pickle\.loads|joblib\.load               # Python-style unsafe deserialization (in Node)
tf\.loadLayersModel\(.*req\.             # TensorFlow model from user input
onnx.*load\(.*req\.                      # ONNX model from user input
```

### Safe: Secure model loading
```
loadModel\(["']|from_pretrained\(["']    # Hardcoded model path (good)
ALLOWED_MODELS|MODEL_ALLOWLIST           # Model allowlist (good)
```

## Rate Limiting for AI Endpoints

### Dangerous: No rate limiting on AI endpoints
```
router\.(post|get)\(["'].*/(ai|llm|chat|generate|complete) # AI endpoint (review rate limiting)
app\.post\(["'].*/prompt|app\.post\(["'].*/ask             # AI endpoint
```

### Safe: Rate-limited AI endpoints
```
rateLimit\(.*router\.post\(["'].*/ai     # Rate-limited AI endpoint (good)
app\.use\(["']/api/ai.*limiter\)         # Limiter on AI routes (good)
windowMs.*max:\s*\d{1,2}\b.*ai          # Strict AI rate limit (good)
```

## Logging & Monitoring

### Dangerous: Missing AI monitoring
```
# Check for absence of:
# - Token usage tracking
# - Prompt/response logging
# - Cost monitoring
# - Anomaly detection
```

### Safe: AI monitoring
```
usage\.total_tokens|totalTokens          # Token tracking (good)
logger\.\w+\(.*prompt|logger\.\w+\(.*completion # Prompt logging (good)
langsmith|langfuse                       # LLM observability tools (good)
opentelemetry.*ai|traceloop              # OpenTelemetry AI tracing (good)
```

## Embedding Security

### Dangerous: Unbounded embedding input
```
embed\(.*req\.body|embedQuery\(.*req\.   # Raw request in embedding
createEmbedding\(.*req\.body             # OpenAI embedding with raw input
maxTokens.*undefined|maxLength.*null     # No input length limit
```

### Safe: Bounded embedding input
```
\.slice\(0,.*embed\(|truncate\(.*embed   # Truncated input (good)
maxTokens:\s*\d+                         # Token limit (good)
encoding\.encode\(.*\.slice\(0           # Token-based truncation (good)
```

## Streaming Response Security

### Dangerous: Unvalidated streaming
```
createChatCompletion\(.*stream:\s*true(?!.*filter|.*sanitize) # Streaming without filtering
for await.*chunk.*res\.write\(           # Raw chunk forwarding (review)
```

### Safe: Validated streaming
```
stream.*filter\(|stream.*sanitize\(      # Filtered stream (good)
transformStream|TransformStream          # Transform stream for validation (good)
SSE.*event:.*data:                       # Server-Sent Events format (good, review content)
```
