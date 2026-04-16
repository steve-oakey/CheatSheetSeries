# API Patterns: Java / Spring Boot

## SSRF (Server-Side Request Forgery)
```
RestTemplate.*getForObject\(.*request\.getParameter
RestTemplate.*exchange\(.*request\.getParameter
WebClient\.create\(.*request\.getParameter
HttpClient.*URI\.create\(.*request\.getParameter
new URL\(.*request\.getParameter
```

### RestTemplate SSRF analysis guidance
RestTemplate can be exploited for SSRF when URL components come from user input:
```
# CRITICAL: Full URL from user input
RestTemplate.*getForObject\(.*@RequestParam   # URL from query param
RestTemplate.*getForObject\(.*@PathVariable   # URL from path var
RestTemplate.*exchange\(.*@RequestParam        # URL from query param
RestTemplate.*exchange\(.*@RequestBody         # URL from request body
WebClient\.create\(.*@RequestParam             # WebClient from user input
new URI\(.*@RequestParam                       # URI from user input

# HIGH: URL parts from user input (host, port, path)
RestTemplate.*\+.*request\.getParameter        # URL concatenation with input
RestTemplate.*String\.format\(.*request        # Format string URL with input
UriComponentsBuilder.*host\(.*@RequestParam    # Host from user input
UriComponentsBuilder.*port\(.*@RequestParam    # Port from user input
UriComponentsBuilder.*path\(.*@RequestParam    # Path from user input

# MEDIUM: Indirect user input (check data flow)
RestTemplate.*getForObject\(.*url              # Variable named url — trace source
RestTemplate.*exchange\(.*endpoint             # Variable named endpoint — trace
WebClient\.create\(.*serviceUrl                # Variable serviceUrl — trace
```

### Safe: SSRF protection patterns
```
URL.*getHost\(\).*allowlist|whitelist          # Host allowlist check
InetAddress\.getByName.*isLoopbackAddress      # Loopback address check
InetAddress\.getByName.*isSiteLocalAddress     # Private IP check
URI.*getHost\(\).*matches.*\^https?://         # Protocol restriction
URLValidator|UrlValidator                       # URL validation utility
@Pattern.*https?://.*@RequestParam              # Regex URL validation
```

## Mass Assignment

### Dangerous: JPA Entity directly as request body
```
@RequestBody\s+\w+Entity               # Entity class as request body
@ModelAttribute\s+\w+Entity            # Entity as model attribute
@RequestBody.*(?!.*Dto|.*DTO|.*Request|.*Cmd|.*Command)  # Not using DTO pattern
setAllowedFields\(                     # Good - field filtering
setDisallowedFields\(                  # Good - field blocking
@JsonIgnore                            # Good - field exclusion
```

### @RequestBody Entity analysis guidance
Using JPA entities directly as `@RequestBody` allows attackers to set any field:
```
# CRITICAL: Entity with sensitive fields exposed
@RequestBody\s+User\b                  # User entity — may have role, isAdmin, password fields
@RequestBody\s+Account\b               # Account entity — may have balance, status fields
@RequestBody\s+Order\b                 # Order entity — may have price, discount fields
@RequestBody\s+\w+(Entity|Model)\b     # Any entity/model class
```

### Fields attackers target via mass assignment
Check if the entity has these fields (which should NOT be settable via API):
```
# In entity class, look for:
private.*role|private.*isAdmin          # Role escalation
private.*status|private.*verified       # Status manipulation
private.*balance|private.*credit        # Financial manipulation
private.*price|private.*discount        # Price manipulation
private.*createdBy|private.*ownerId     # Ownership manipulation
private.*password|private.*passwordHash # Password setting
private.*id\b                          # ID manipulation (change target record)
```

### Safe: DTO pattern (recommended)
```
@RequestBody.*Dto\b                    # DTO class (good)
@RequestBody.*DTO\b                    # DTO class (good)
@RequestBody.*Request\b                # Request class (good)
@RequestBody.*Command\b                # Command class (good)
@RequestBody.*Cmd\b                    # Command shorthand (good)
ModelMapper|mapstruct|MapStruct         # DTO mapping library (good)
BeanUtils\.copyProperties.*allowList   # Selective copy (good)
@JsonIgnoreProperties                   # Ignoring fields (partial protection)
```

## File Upload
```
MultipartFile.*getOriginalFilename\(\) # Using original filename
transferTo\(.*getOriginalFilename      # Storing with original name
spring\.servlet\.multipart\.max-file-size  # Check size limit
spring\.servlet\.multipart\.max-request-size
```

## Request Validation
```
@RequestBody.*(?!.*@Valid|@Validated)   # Missing validation
@PathVariable.*(?!.*@Pattern|@Min|@Max) # Unvalidated path var
consumes\s*=.*APPLICATION_JSON          # Good - content type restriction
produces\s*=.*APPLICATION_JSON          # Good - response type
```

## WebSocket Configuration
```
setAllowedOrigins\("?\*"?\)            # Wildcard origins
registerStompEndpoints\(               # Check origin config
addEndpoint\(                          # Check origin config
setAllowedOriginPatterns\(             # Check patterns
```

## GraphQL (Spring GraphQL)
```
graphql\.graphiql\.enabled=true        # GraphiQL in production
MaxQueryDepthInstrumentation            # Should be present
MaxQueryComplexityInstrumentation       # Should be present
```

## Error Handling
```
@ExceptionHandler.*ResponseEntity.*e\.getMessage  # Leaking error details
server\.error\.include-stacktrace=always
server\.error\.include-message=always
e\.printStackTrace\(\).*response
```

## Rate Limiting
```
@RateLimiter\(                         # Resilience4j
RateLimiterConfig                      # Should be configured
bucket4j                               # Should be present for API rate limiting
```

## Actuator Exposure
```
management\.endpoints\.web\.exposure\.include=\*  # All endpoints exposed
management\.endpoint\.\w+\.enabled=true
management\.endpoints\.enabled-by-default=true
```

## Microservice Inter-Service Communication Insecure (RULE-API-013)

### Dangerous: Spring clients with plaintext HTTP for internal services
```
RestTemplate.*"http://                  # RestTemplate calling over HTTP
new RestTemplate\(\).*http://           # Unencrypted RestTemplate
WebClient\.create\("http://             # WebClient with plaintext HTTP
@FeignClient\(.*url\s*=\s*"http://     # Feign client over HTTP
@FeignClient\(.*value.*http://          # Feign service URL over HTTP
Retrofit\.Builder\(\).*baseUrl\("http:  # Retrofit over HTTP
HttpComponentsClientHttpRequestFactory  # Check SSL context configuration
SimpleClientHttpRequestFactory          # No built-in SSL support
```

### Dangerous: Disabled certificate validation in Spring
```
NoopHostnameVerifier                    # Disabling hostname checks
TrustAllStrategy                        # Trust all certs (Apache HttpClient)
setHostnameVerifier.*ALLOW_ALL          # Accept any hostname
X509TrustManager.*return\s*(null|new)   # Empty trust manager
SSLContext.*TrustAll                    # Trust-all SSL context
InsecureTrustManagerFactory             # Netty trust-all (WebClient)
\.setSslContext.*trustAll               # WebClient trust-all
```

### Dangerous: Static shared secrets for service auth
```
@Value.*service\.secret                 # Static service secret from config
@Value.*inter\.service\.key             # Static inter-service key
private.*static.*SERVICE_SECRET         # Hardcoded service secret constant
Authorization.*Bearer.*"[A-Za-z0-9._-]{20,}"  # Hardcoded bearer token
```

### Safe: Encrypted and authenticated service-to-service communication
```
SSLContext\.getInstance\("TLS"          # TLS context configured
SSLContext.*KeyManager                  # Client key manager (mTLS)
KeyStore\.getInstance\(                 # Certificate keystore loaded
HttpsURLConnection                      # HTTPS enforced
spring\.ssl\.bundle                     # Spring Boot SSL bundles
server\.ssl\.client-auth=need           # Mutual TLS required
spring\.cloud\.discovery.*https         # Service discovery over HTTPS
@FeignClient\(.*url\s*=\s*"https://    # Feign client over HTTPS
WebClient\.create\("https://            # WebClient with TLS
OAuth2AuthorizedClientManager           # OAuth2 for service-to-service
ClientCredentialsOAuth2AuthorizedClient # Client credentials flow (good)
spring\.security\.oauth2\.resourceserver # Resource server validation
```

A finding is reported when internal service calls use `http://` without mTLS, or when certificate validation is disabled.

## Safe Patterns
```
@Valid\s+@RequestBody                   # Validated request body
@Validated\s+@RequestBody              # Spring validated
@PreAuthorize.*@RequestMapping         # Authorized endpoint
\.setAllowedOrigins\(.*specific\.domain  # Specific CORS origin
antMatchers.*authenticated\(\)          # Authenticated endpoint
```
