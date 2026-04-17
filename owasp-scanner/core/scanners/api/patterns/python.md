# API Security Patterns: Python (Django / Flask / FastAPI)

## Django REST Framework (DRF)

### Dangerous: Overly permissive DRF settings
```
DEFAULT_PERMISSION_CLASSES.*AllowAny    # AllowAny as default permission
DEFAULT_AUTHENTICATION_CLASSES\s*=\s*\[\] # No authentication required
DEFAULT_THROTTLE_CLASSES\s*=\s*\[\]     # No rate limiting
DEFAULT_PAGINATION_CLASS.*None           # No pagination (data exposure)
PAGE_SIZE.*\d{4,}                        # Very large page size
```

### Safe: Restrictive DRF settings
```
DEFAULT_PERMISSION_CLASSES.*IsAuthenticated # Authenticated default (good)
DEFAULT_AUTHENTICATION_CLASSES.*JWT|Token  # Token auth configured (good)
DEFAULT_THROTTLE_RATES                    # Throttle rates defined (good)
DEFAULT_PAGINATION_CLASS.*PageNumber      # Pagination enabled (good)
```

### DRF Serializer Security
```
class Meta:.*fields\s*=\s*["']__all__   # Exposing all fields (dangerous)
class Meta:.*exclude\s*=\s*\[\]         # Excluding nothing (dangerous)
depth\s*=\s*[3-9]|\d{2,}               # Deep serialization (data leakage)
```

### Safe: Explicit serializer fields
```
fields\s*=\s*\[|fields\s*=\s*\(        # Explicit field list (good)
read_only_fields\s*=                     # Read-only fields defined (good)
extra_kwargs.*write_only.*True           # Write-only for sensitive fields (good)
```

## Django API Authorization

### Dangerous: Missing object-level permissions
```
def get_queryset.*return.*\.objects\.all\(\) # Returning all objects (review IDOR)
\.objects\.get\(pk=.*request\.(GET|POST|data) # Direct PK from user input
\.objects\.get\(id=.*kwargs\[            # Direct ID from URL kwargs (review)
```

### Safe: Filtered querysets
```
\.objects\.filter\(user=request\.user    # User-scoped queryset (good)
\.objects\.filter\(owner=|\.objects\.filter\(created_by= # Owner filter (good)
get_object_or_404\(.*user=request\.user  # Scoped lookup (good)
self\.check_object_permissions\(         # DRF object permission check (good)
```

## Flask API Security

### Dangerous: Missing auth on Flask endpoints
```
@app\.route\(.*methods=\[.*POST.*\)(?!.*@login_required) # POST without auth
@app\.route\(.*methods=\[.*DELETE.*\)(?!.*@login_required) # DELETE without auth
```

### Safe: Protected Flask endpoints
```
@login_required.*@app\.route             # Login required before route (good)
@jwt_required\(\)                        # JWT required (good)
@auth\.login_required                    # HTTPAuth required (good)
```

### Flask Response Headers
```
@app\.after_request.*response\.headers   # Setting response headers (review)
response\.headers\[.X-Content-Type      # Content-Type-Options header (good)
response\.headers\[.X-Frame-Options     # Frame options header (good)
```

## FastAPI API Security

### Dangerous: Unprotected FastAPI endpoints
```
@app\.(post|put|delete|patch)\((?!.*dependencies.*Depends) # Write endpoint without auth
async def \w+\((?!.*current_user|.*Depends\(get_current) # Handler without auth
```

### Safe: Protected FastAPI endpoints
```
dependencies=\[Depends\(               # Dependency injection (good)
current_user:\s*User\s*=\s*Depends\(   # User dependency (good)
Security\(.*scopes=                     # Scoped security (good)
```

### FastAPI Input Validation (Pydantic)
```
# Pydantic model validation patterns
class \w+\(BaseModel\):                 # Pydantic model definition (good)
Field\(.*max_length=|Field\(.*ge=       # Field constraints (good)
@validator\(|@field_validator\(         # Custom validators (good)
constr\(|conint\(|confloat\(            # Constrained types (good)
```

## Mass Assignment

### Dangerous: Django mass assignment
```
\.objects\.create\(\*\*request\.data     # Direct mass assignment from request
\.objects\.create\(\*\*request\.POST\.dict # Mass assignment from POST
\w+\.save\(\).*for.*in.*request\.data   # Iterating request data into model
form_class\s*=\s*\w+Form.*fields.*__all__ # ModelForm with all fields
```

### Safe: Controlled assignment
```
serializer\.save\(                       # DRF serializer save (good)
form\.save\(                             # Django form save (good)
\.objects\.create\(\w+=.*\w+=            # Explicit field assignment (good)
```

## GraphQL (if applicable)

### Dangerous: GraphQL misconfigurations
```
graphiql=True.*(?=.*production)          # GraphiQL in production
GRAPHENE.*MIDDLEWARE.*(?!.*auth)          # No auth middleware
introspection.*True.*(?=.*production)    # Introspection in production
depth_limit.*None|max_depth.*None        # No query depth limit
```

### Safe: Secure GraphQL
```
introspection.*False                     # Introspection disabled (good)
depth_limit\(\d+\)                       # Query depth limited (good)
DepthAnalysisBackend\(                   # Depth analysis (good)
DisableIntrospection\(                   # Introspection disabled (good)
```

## File Upload API Security

### Dangerous: Unrestricted file upload
```
request\.files\[|request\.FILES\[       # File upload (review validation)
\.save\(.*request\.(form|data)\[.*\+    # Save with user-controlled path
send_file\(.*request\.|FileResponse\(.*request\. # Serving user-controlled path
os\.path\.join\(.*request\.             # Path from user input (path traversal)
```

### Safe: Secure file upload
```
secure_filename\(                        # Werkzeug secure filename (good)
FileExtensionValidator\(                 # Django extension validator (good)
ALLOWED_EXTENSIONS|UPLOAD_EXTENSIONS     # Allowed extensions defined (good)
uuid4\(\).*filename|filename.*uuid4\(\) # UUID-based filename (good)
```

## Error Handling in APIs

### Dangerous: Verbose error responses
```
traceback\.format_exc\(\).*return        # Traceback in response
str\(e\).*return.*json|str\(e\).*jsonify # Exception message in JSON response
exc_info=True.*return                    # Exception info in response
PROPAGATE_EXCEPTIONS.*True               # Exceptions propagated to client
```

### Safe: Sanitized error responses
```
@app\.errorhandler\(                     # Flask error handler (good)
exception_handler.*APIException          # DRF exception handler (good)
@app\.exception_handler\(               # FastAPI exception handler (good)
return.*\{"error":.*"message"            # Structured error response (good)
```

## SSRF Prevention

### Dangerous: User-controlled requests
```
requests\.get\(.*request\.(GET|POST|data|json) # requests with user URL
urllib\.request\.urlopen\(.*request\.    # urllib with user URL
httpx\.\w+\(.*request\.                 # httpx with user URL
aiohttp\.ClientSession\(.*request\.     # aiohttp with user URL
```

### Safe: SSRF prevention
```
# URL validation before fetching
urlparse\(.*\.scheme.*in.*\["https"     # Scheme validation (good)
ipaddress\.ip_address\(.*is_private     # Private IP check (good)
ALLOWED_HOSTS|ALLOWED_URLS              # URL allowlist (good)
```
