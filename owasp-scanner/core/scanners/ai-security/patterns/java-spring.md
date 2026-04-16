# AI Security Patterns: Java / Spring Boot

## Prompt Injection via String Concatenation (RULE-AIS-001)

### Dangerous: Spring AI / LangChain4j prompt construction with user input
```
# Spring AI
Prompt\(.*\+.*request\.getParameter     # Prompt with request param concat
Prompt\(.*\+.*@RequestParam             # Prompt with Spring param concat
PromptTemplate.*\+.*userInput           # Template with concatenation
new Prompt\(.*String\.format\(.*request # Format string with request data
chatClient\.prompt\(\)\.user\(.*\+      # Spring AI ChatClient with concat
chatClient\.call\(.*\+                  # ChatClient call with concat

# LangChain4j
AiServices.*UserMessage.*\+             # LangChain4j with concat
model\.generate\(.*\+.*request          # Model generate with concat
model\.chat\(.*\+.*request              # Model chat with concat

# Direct OpenAI Java client
ChatCompletionRequest.*content.*\+      # OpenAI request with concat
messages\.add\(.*content.*\+            # Message content with concat
```

### Safe: Structured prompt construction
```
# Spring AI
ChatClient.*system\(.*\)\.user\(       # Separate system/user roles (good)
PromptTemplate.*Map\.of\(              # Parameterized template (good)
@SystemMessage                          # LangChain4j annotation (good)
@UserMessage.*\{\{                      # LangChain4j parameterized (good)

# LangChain4j
AiServices\.builder\(                   # Service builder (good)
@V\(".*"\)                              # Named parameter (good)
```

## System Prompt Exposure (RULE-AIS-002)

### Dangerous: System prompts in Spring configuration
```
@Value\(".*system.*prompt"\).*String    # System prompt as config value (check source)
application\.(yml|properties).*system.*prompt  # Prompt in app config
@RestController.*systemPrompt           # Prompt accessible in controller
ResponseEntity.*systemPrompt            # Prompt in API response
```

### Safe: Prompt stored securely
```
@Value\("\$\{.*vault.*prompt\}"\)       # From secrets vault (good)
SecretClient.*getSecret.*prompt         # Azure KeyVault (good)
SecretsManagerClient.*prompt            # AWS Secrets Manager (good)
```

## Missing Output Validation (RULE-AIS-003)

### Dangerous: LLM output in dangerous Spring sinks
```
Runtime\.getRuntime\(\)\.exec\(.*response  # LLM output executed as command
ProcessBuilder.*response\.getContent       # LLM output in process
ScriptEngine.*eval\(.*response             # LLM output evaluated
entityManager\.createNativeQuery\(.*response # LLM output in SQL
JdbcTemplate.*response\.getContent         # LLM output in JDBC
response\.getWriter\(\)\.write\(.*aiResponse # LLM output in HTTP response
th:utext.*aiResponse                       # LLM output unescaped in Thymeleaf
```

### Safe: Validated output
```
ObjectMapper.*readValue\(.*response.*\.class  # JSON deserialization to typed class (good)
JsonSchema.*validate\(.*response              # JSON schema validation (good)
HtmlUtils\.htmlEscape\(.*response             # HTML escaping (good)
BeanOutputParser|MapOutputParser              # Spring AI output parser (good)
```

## Excessive LLM Permissions / Tool Access (RULE-AIS-004)

### Dangerous: Spring AI tool registration without restrictions
```
@Tool(?!.*readOnly|.*readonly)              # Tool without read-only marker
FunctionCallback.*\(.*"delete|"update|"write  # Destructive tool functions
chatClient.*tools\(.*                       # Check what tools are registered
@Description.*delete|@Description.*modify   # Tool that modifies data
```

### Safe: Restricted tool access
```
@Tool.*readOnly\s*=\s*true                  # Read-only tool (good)
@PreAuthorize.*@Tool                        # Authorized tool (good)
human.*confirm|approval.*required           # HITL gate (good)
```

## Insecure LLM API Key Management (RULE-AIS-006)

### Dangerous: API keys in Spring config
```
spring\.ai\.openai\.api-key=sk-            # OpenAI key in properties
spring\.ai\.anthropic\.api-key=sk-ant-     # Anthropic key in properties
spring\.ai\..*api-key=[A-Za-z0-9]{20,}     # Any AI API key hardcoded
```

### Safe: Externalized API keys
```
spring\.ai\.openai\.api-key=\$\{           # Environment variable reference (good)
spring\.ai\..*api-key=\$\{VAULT           # Vault reference (good)
spring\.cloud\.vault.*ai                    # Spring Cloud Vault (good)
```

## Missing Rate Limiting on LLM Endpoints (RULE-AIS-007)

### Dangerous: Spring AI endpoints without rate limiting
```
@PostMapping.*"/chat"|@PostMapping.*"/ask"   # Chat endpoint
@PostMapping.*"/generate"|@PostMapping.*"/complete"  # Generation endpoint
@PostMapping.*"/agent"|@PostMapping.*"/assistant"    # Agent endpoint
```
Verify presence of:
```
@RateLimiter\(.*chat|@RateLimiter\(.*ai     # Resilience4j rate limiter
Bucket4j.*ai|bucket4j.*chat                  # Bucket4j rate limiting
spring\.ai\..*timeout                        # AI client timeout
spring\.ai\.openai\.chat\.options\.max-tokens # Token limit
```

## LLM Output Rendered in Thymeleaf/Spring MVC (RULE-AIS-009)

### Dangerous: Unescaped LLM output in templates
```
th:utext=.*aiResponse|th:utext=.*chatResponse  # Thymeleaf unescaped
th:utext=.*model\..*response                    # Unescaped model attribute
<%= .*aiResponse.*%>                            # JSP unescaped
```

### Safe: Escaped output
```
th:text=.*aiResponse|th:text=.*chatResponse     # Thymeleaf auto-escaped (good)
HtmlUtils\.htmlEscape\(.*response               # Spring HTML escaping (good)
```

## Missing Model Input/Output Logging (RULE-AIS-010)

### Check for logging in Spring AI applications
```
chatClient\.call\(|chatClient\.prompt\(         # Spring AI call — verify logging
AiServices|model\.generate\(                     # LangChain4j — verify logging
```
Verify at least ONE:
```
logger\.(info|debug).*prompt|logger.*response    # Manual logging
ChatClientObservation|ObservationHandler          # Spring AI observation (good)
micrometer.*ai|spring\.ai\..*observation          # Metrics/tracing (good)
MeterBinder.*ai                                   # Custom AI metrics (good)
```

## Insecure Model Loading (RULE-AIS-011)

### Dangerous: Java model loading
```
ObjectInputStream.*model|readObject.*model       # Java deserialization of model
DJL.*load.*http://                               # Deep Java Library over HTTP
OnnxRuntime.*http://                             # ONNX model over HTTP
```

### Safe: Secure model loading in Java
```
DJL.*load.*https://                              # HTTPS model loading (good)
ModelZoo.*artifact                                # DJL ModelZoo (managed) (good)
OrtEnvironment.*createSession.*local              # Local ONNX model (good)
```

## Unrestricted Agent Action Chains (RULE-AIS-013)

### Dangerous: Spring AI agent without limits
```
while.*true.*chatClient                          # Infinite agent loop
for.*i.*<.*999.*chatClient                       # Excessive iterations
@Scheduled.*agent(?!.*limit)                     # Scheduled agent without limit
```

### Safe: Bounded agent execution
```
maxIterations|MAX_ITERATIONS|max\.iterations      # Iteration limit (good)
ChatClientRequestSpec.*advisors                   # Advisors (can add limits)
MessageWindowChatMemory.*maxMessages              # Memory limit (good)
```
