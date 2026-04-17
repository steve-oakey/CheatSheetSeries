# AI Security Patterns: Python (Django / Flask / FastAPI)

## LLM Prompt Injection

### Dangerous: Unvalidated user input in prompts
```
f".*\{.*request\.(data|json|form|args).*\}".*\.completions # User input in prompt
prompt\s*=.*f".*\{user_input\}|prompt\s*=.*f".*\{request\. # f-string prompt with user input
prompt\s*=.*\.format\(.*request\.|prompt\s*=.*%s.*%.*request # .format() or % with user data
messages\.append\(\{"role":.*"user".*content.*request\. # Raw request in chat message
langchain.*HumanMessage\(.*content=.*request\. # LangChain with raw user input
```

### Safe: Sanitized prompt construction
```
# System prompt separated from user input
\{"role":\s*"system".*\},\s*\{"role":\s*"user" # Separated system/user roles (good)
ChatPromptTemplate\.from_messages\(     # LangChain template (good, review vars)
PromptTemplate\(.*input_variables=      # LangChain parameterized template (good)
sanitize_input\(|clean_prompt\(|escape_prompt\( # Input sanitization function (good)
```

## Sensitive Data in LLM Context

### Dangerous: PII/secrets in prompts
```
\.completions\.create\(.*password|\.chat\.create\(.*secret # Secrets in API calls
prompt.*=.*os\.environ|prompt.*=.*SECRET_KEY # Environment secrets in prompt
messages.*content.*credit_card|messages.*content.*ssn # PII in messages
embed\(.*password|embed\(.*token         # Secrets in embeddings
```

### Safe: Data sanitization before LLM
```
redact\(|mask\(|anonymize\(             # Data redaction/masking (good)
strip_pii\(|remove_pii\(               # PII removal (good)
\.replace\(.*\*\*\*|re\.sub\(.*\*       # Pattern masking (good)
```

## Insecure Output Handling

### Dangerous: Unvalidated LLM output execution
```
exec\(.*response\.|exec\(.*completion   # Executing LLM output as code
eval\(.*response\.|eval\(.*completion   # Evaluating LLM output
subprocess\.\w+\(.*response\.           # LLM output as system command
os\.system\(.*completion|os\.popen\(.*response # LLM output in shell
cursor\.execute\(.*response\.           # LLM output as SQL query
render_template_string\(.*completion    # LLM output as template
```

### Safe: Validated LLM output
```
json\.loads\(.*response\.               # Parsing as JSON only (good)
schema\.validate\(.*response            # Schema validation of output (good)
pydantic\.BaseModel.*parse_raw\(        # Pydantic output parsing (good)
```

## Agent Tool Abuse

### Dangerous: Unrestricted agent tools
```
tools\s*=\s*\[.*\](?!.*allowed_tools)   # Tools without restrictions
AgentExecutor\(.*tools=.*(?!.*max_iterations) # Agent without iteration limit
\.run\(.*\)(?!.*callbacks|.*timeout)     # Agent run without monitoring
create_\w+_agent\(.*tools=(?!.*allowed) # Agent creation without tool restrictions
```

### Safe: Restricted agent tools
```
max_iterations=\d+                       # Iteration limit set (good)
allowed_tools=\[                         # Tool allowlist (good)
return_intermediate_steps=True           # Steps logged (good)
callbacks=\[.*\]                         # Monitoring callbacks (good)
handle_parsing_errors=True               # Error handling enabled (good)
```

## RAG Pipeline Security

### Dangerous: Unvalidated retrieval
```
\.similarity_search\(.*request\.        # Raw user input in vector search
retriever\.get_relevant_documents\(.*request\. # Raw request in retriever
as_retriever\(\)(?!.*search_kwargs.*k=\d) # Retriever without result limit
```

### Safe: Validated RAG
```
search_kwargs=\{"k":\s*\d+\}            # Result count limited (good)
\.similarity_search\(.*k=\d+            # Limited similarity search (good)
score_threshold=                         # Score threshold filtering (good)
metadata_filter=|where=                  # Metadata filtering (good)
```

## Model/API Key Management

### Dangerous: Hardcoded API keys
```
openai\.api_key\s*=\s*["']sk-           # Hardcoded OpenAI key
OPENAI_API_KEY\s*=\s*["']sk-            # Hardcoded OpenAI key
anthropic\.api_key\s*=\s*["']           # Hardcoded Anthropic key
HUGGING_FACE_HUB_TOKEN\s*=\s*["']hf_   # Hardcoded HuggingFace token
COHERE_API_KEY\s*=\s*["']               # Hardcoded Cohere key
```

### Safe: Environment-based keys
```
openai\.api_key\s*=\s*os\.environ       # Key from environment (good)
os\.getenv\(["']OPENAI_API_KEY          # Key from environment (good)
from dotenv import load_dotenv           # dotenv for key management (good)
AzureKeyCredential\(.*os\.environ       # Azure key from env (good)
```

## Model Loading Security

### Dangerous: Unsafe model loading
```
torch\.load\(.*request\.|torch\.load\(.*user # Loading user-supplied model
pickle\.load\(.*model|joblib\.load\(.*request # Pickle/joblib with user path
transformers\.from_pretrained\(.*request\.  # User-controlled model name
from_pretrained\(.*input\(              # Model name from user input
```

### Safe: Secure model loading
```
torch\.load\(.*weights_only=True        # Weights-only loading (good, PyTorch 2.6+)
safetensors\.torch\.load_file\(         # Safetensors loading (good)
from_pretrained\(["']                   # Hardcoded model name (good)
ALLOWED_MODELS|MODEL_ALLOWLIST          # Model allowlist (good)
```

## Rate Limiting for AI Endpoints

### Dangerous: No rate limiting on AI endpoints
```
@app\.route\(.*/ai/|@app\.route\(.*/llm/|@app\.route\(.*/chat/ # AI endpoint (review rate limiting)
@app\.(post|get)\(.*/generate|@app\.(post|get)\(.*/complete    # Generation endpoint
```

### Safe: Rate-limited AI endpoints
```
@limiter\.limit\(.*@app\.route\(.*/ai   # Rate-limited AI endpoint (good)
@ratelimit\(.*def.*chat|@ratelimit\(.*def.*generate # Rate-limited handler (good)
DEFAULT_THROTTLE_RATES.*ai              # DRF AI throttle rate (good)
```

## Logging & Monitoring

### Dangerous: Missing AI monitoring
```
# Check for absence of:
# - Token usage tracking
# - Prompt/response logging
# - Cost monitoring
# - Anomaly detection on AI endpoints
```

### Safe: AI monitoring
```
usage\[.total_tokens.\]|usage\.total_tokens # Token tracking (good)
logger\.\w+\(.*prompt|logger\.\w+\(.*completion # Prompt logging (good)
langsmith|wandb\.log|mlflow\.log         # ML observability tools (good)
LangSmithCallbackHandler\(              # LangSmith tracing (good)
```

## Embedding Security

### Dangerous: Unbounded embedding input
```
embed\(.*request\.(data|json|form)       # Raw request data embedded
\.encode\(.*request\.                    # Raw request in encoder
max_tokens=None|max_length=None          # No input length limit
```

### Safe: Bounded embedding input
```
text\[:.*\].*embed\(|truncate\(.*embed  # Truncated input (good)
max_tokens=\d+|max_length=\d+           # Token/length limit (good)
tiktoken\.encoding.*encode\(.*\)\[:     # Token-based truncation (good)
```
