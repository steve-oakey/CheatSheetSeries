# API Patterns: Java / Spring Boot

## SSRF (Server-Side Request Forgery)
```
RestTemplate.*getForObject\(.*request\.getParameter
RestTemplate.*exchange\(.*request\.getParameter
WebClient\.create\(.*request\.getParameter
HttpClient.*URI\.create\(.*request\.getParameter
new URL\(.*request\.getParameter
```

## Mass Assignment
```
@RequestBody\s+\w+Entity               # Entity class as request body
@ModelAttribute\s+\w+Entity            # Entity as model attribute
@RequestBody.*(?!.*Dto|.*DTO|.*Request|.*Cmd|.*Command)  # Not using DTO pattern
setAllowedFields\(                     # Good - field filtering
setDisallowedFields\(                  # Good - field blocking
@JsonIgnore                            # Good - field exclusion
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

## Safe Patterns
```
@Valid\s+@RequestBody                   # Validated request body
@Validated\s+@RequestBody              # Spring validated
@PreAuthorize.*@RequestMapping         # Authorized endpoint
\.setAllowedOrigins\(.*specific\.domain  # Specific CORS origin
antMatchers.*authenticated\(\)          # Authenticated endpoint
```
