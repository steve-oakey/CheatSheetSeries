# Injection Patterns: Python (Django / Flask / FastAPI)

## Dangerous SQL Sinks

### Django ORM Unsafe Methods
```
\.raw\(.*%s|\.raw\(.*\{|\.raw\(.*f"    # Raw SQL with formatting
\.extra\(.*where=.*%|\.extra\(.*select= # extra() with string interpolation
RawSQL\(.*%s|RawSQL\(.*f"              # RawSQL expression with formatting
cursor\.execute\(.*%|cursor\.execute\(.*f" # Direct cursor with formatting
cursor\.execute\(.*\.format\(           # cursor with .format()
cursor\.execute\(.*\+                   # cursor with concatenation
```

### SQLAlchemy Unsafe Methods
```
text\(.*f"|text\(.*\.format\(           # text() with f-string or format
text\(.*%s|text\(.*\+                   # text() with interpolation or concat
db\.engine\.execute\(.*f"               # Raw engine execute with f-string
db\.session\.execute\(.*f"              # Session execute with f-string
from_statement\(.*f"                    # from_statement with f-string
filter\(.*text\(.*\+                    # filter with raw text + concat
```

### SQLAlchemy analysis guidance
```
# CRITICAL: User input in text()
text\(.*request\.|text\(.*args\[        # text() with request/args data
text\(.*form\[|text\(.*json\[           # text() with form/json data

# SAFE: Parameterized text()
text\(.*\)\.bindparams\(                # Bound parameters (good)
text\(".*:param"                        # Named parameters (good)
```

## Dangerous OS Command Execution

### Dangerous: Shell execution with user input
```
os\.system\(.*\+|os\.system\(.*f"       # os.system with dynamic input
os\.popen\(.*\+|os\.popen\(.*f"         # os.popen with dynamic input
subprocess\.call\(.*shell=True          # subprocess with shell=True
subprocess\.run\(.*shell=True           # subprocess.run with shell=True
subprocess\.Popen\(.*shell=True         # Popen with shell=True
commands\.getoutput\(                   # Deprecated, always uses shell
os\.exec[lv]p?\(.*\+                    # os.exec family with concat
```

### Safe: Array-based command execution
```
subprocess\.run\(\[                     # List-based args (good)
subprocess\.call\(\[                    # List-based args (good)
subprocess\.Popen\(\[                   # List-based args (good)
shlex\.split\(                          # Shell-safe argument splitting (good)
shlex\.quote\(                          # Shell-safe quoting (good)
```

## Dangerous Deserialization

### Beyond generic patterns (pickle/yaml already in generic.md)
```
shelve\.open\(                          # Uses pickle internally
marshal\.loads\(                        # Unsafe deserialization
dill\.load\(|dill\.loads\(              # Extended pickle (unsafe)
cloudpickle\.load\(                     # Cloud pickle (unsafe)
yaml\.unsafe_load\(                     # Explicit unsafe YAML
yaml\.full_load\(                       # Full YAML (unsafe before 5.1)
yaml\.load\(.*Loader=yaml\.Loader       # Full loader (unsafe)
```

### Safe: Secure deserialization
```
yaml\.safe_load\(                       # SafeLoader (good)
yaml\.load\(.*Loader=yaml\.SafeLoader   # Explicit SafeLoader (good)
json\.loads?\(                          # JSON parsing (safe)
```

## Server-Side Template Injection (SSTI)

### Dangerous: Dynamic template construction
```
Template\(.*request\.|Template\(.*f"    # Jinja2 Template with user input
from_string\(.*request\.               # Jinja2 from_string with request data
render_template_string\(.*request\.     # Flask render with user input
render_template_string\(.*args          # Flask render with args
Environment\(.*autoescape=False         # Jinja2 autoescape disabled
```

### SSTI analysis guidance
```
# CRITICAL: User input flows into template source
render_template_string\(.*form\[        # Form data in template string
render_template_string\(.*json\[        # JSON data in template string
Template\(.*\.get\(                     # Request data in template

# SAFE: Template file rendering (variables are escaped)
render_template\("                      # File-based template (good)
render_template\('                      # File-based template (good)
```

## LDAP Injection

### Dangerous: Python-ldap with string formatting
```
search_s\(.*f"|search_s\(.*%s           # ldap search with formatting
search_s\(.*\.format\(                  # ldap search with .format()
search_s\(.*\+                          # ldap search with concatenation
ldap\.filter\.filter_format             # Check if actually used
```

### Safe: Parameterized LDAP
```
ldap\.filter\.escape_filter_chars\(     # LDAP escaping (good)
```

## XML/XXE

### Dangerous: Unsafe XML parsers
```
xml\.etree\.ElementTree\.parse\(        # No external entity protection
xml\.sax\.parse\(                       # SAX without secure features
lxml\.etree\.parse\(                    # lxml (check for resolve_entities)
xml\.dom\.minidom\.parse\(              # minidom (no XXE protection)
XMLParser\(.*resolve_entities=True      # lxml explicit entity resolution
```

### Safe: Secure XML parsing
```
defusedxml\.\w+\.parse\(               # defusedxml library (good)
defusedxml\.ElementTree               # defusedxml (good)
XMLParser\(.*resolve_entities=False     # lxml with entities disabled (good)
```

## Stored Procedure SQL Injection (RULE-INJ-014)

### Dangerous: Stored procedure calls with string formatting
```
cursor\.callproc\(.*f"|cursor\.callproc\(.*%  # callproc with formatting
cursor\.execute\("CALL.*f"|cursor\.execute\("CALL.*\+ # CALL with concat
cursor\.execute\("EXEC.*f"|cursor\.execute\("EXEC.*\+ # EXEC with concat
```

### Safe: Parameterized stored procedure calls
```
cursor\.callproc\(.*,\s*\[              # callproc with parameter list (good)
cursor\.callproc\(.*,\s*\(              # callproc with parameter tuple (good)
```

## XPath/XQuery Injection (RULE-INJ-015)

### Dangerous: lxml XPath with string formatting
```
\.xpath\(.*f"|\.xpath\(.*\.format\(     # XPath with f-string or .format()
\.xpath\(.*%s|\.xpath\(.*\+             # XPath with % formatting or concat
etree\.XPath\(.*f"|etree\.XPath\(.*\+   # Compiled XPath with dynamic input
```

### Safe: Parameterized XPath
```
\.xpath\(.*,\s*namespaces=              # XPath with namespaces only (good)
\.xpath\(.*,\s*\w+=                     # XPath with variable binding (good)
etree\.XPath\(.*\)\(                    # Precompiled XPath expression (good)
```

## Django-Specific Input Validation

### Dangerous: Missing validation
```
request\.GET\[|request\.POST\[          # Direct dict access (may raise KeyError)
request\.GET\.get\(.*\)(?!.*clean|.*valid|.*sanitiz) # Unvalidated GET param
request\.data(?!.*serializer|.*validated) # DRF: raw request data usage
```

### Safe: Validated input
```
form\.is_valid\(\)                      # Django form validation (good)
serializer\.is_valid\(                  # DRF serializer validation (good)
serializer\.validated_data              # Validated data access (good)
clean_\w+\(self\)                       # Django form clean methods (good)
```

## Flask/FastAPI Input Validation

### Dangerous: Unvalidated request data
```
request\.args\.get\(.*\)(?!.*valid|.*int\(|.*float\() # Unvalidated query param
request\.form\[|request\.form\.get\(    # Unvalidated form data
request\.json\[|request\.get_json\(     # Unvalidated JSON body
```

### Safe: Validated input
```
@app\.route.*methods=\[.*POST           # Check for validation in handler body
wtforms\.validators\.\w+               # WTForms validation (good)
Schema\(\)\.load\(                      # Marshmallow validation (good)
BaseModel                               # Pydantic model validation (good)
Query\(.*ge=|Query\(.*le=               # FastAPI query validation (good)
```

## Log Injection (RULE-INJ-016)

### Dangerous: String formatting in log statements
```
logging\.\w+\(f".*\{.*request           # logging with f-string + request data
logging\.\w+\(f".*\{.*user              # logging with f-string + user input
logger\.\w+\(f".*\{.*request            # logger with f-string + request data
logger\.\w+\(".*%s".*%.*request         # logger with %-format + request data
logger\.\w+\(".*"\.format\(.*request    # logger with .format() + request data
logger\.\w+\(".*"\s*\+\s*              # logger with string concatenation
logging\.\w+\(".*"\s*\+\s*             # logging with string concatenation
print\(.*request\.                      # print with request data (review)
```

### Safe: Parameterized/structured Python logging
```
logger\.\w+\(".*%s",\s*                # Lazy %-style logging (safe, deferred formatting)
logger\.\w+\(".*%d",\s*                # Lazy %-style int logging (safe)
structlog\.\w+\.\w+\(                  # structlog structured logging (safe)
python-json-logger|pythonjsonlogger    # JSON structured logging (safe)
extra=\{                                # Logging with extra dict (safe)
```

## Regular Expression Denial of Service (RULE-INJ-017)

### Dangerous: Vulnerable regex patterns in Python
```
re\.compile\(.*request\.|re\.compile\(.*user_input  # User-controlled regex
re\.compile\(.*\+|re\.compile\(.*f"     # Dynamic regex construction
re\.\w+\(.*request\.\w+                 # re functions with request data as pattern
re\.compile\(.*\(\w\+\)\+              # Nested quantifier: (a+)+
re\.compile\(.*\(\.\*\)\*              # Nested quantifier: (.*)*
re\.compile\(.*\(\[.*\]\+\)\+          # Nested quantifier on char class
```

### Safe: ReDoS prevention in Python
```
re2                                      # Google RE2 binding (safe, no backtracking)
regex.*timeout=                          # regex module with timeout (partial)
re\.compile\(.*,\s*re\..*TIMEOUT        # re with timeout flag (Python 3.x+)
```
