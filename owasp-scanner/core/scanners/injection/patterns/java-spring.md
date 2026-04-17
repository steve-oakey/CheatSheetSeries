# Injection Patterns: Java / Spring Boot

## Dangerous Sinks (search for these)

### SQL Injection
```
Statement\.executeQuery\(
Statement\.execute\(
Statement\.executeUpdate\(
connection\.createStatement\(
JdbcTemplate\.query\(.*\+
JdbcTemplate\.update\(.*\+
entityManager\.createNativeQuery\(.*\+
entityManager\.createQuery\(.*\+
session\.createQuery\(.*\+
session\.createSQLQuery\(.*\+
@Query\(.*\+
@Query\(.*\?\#\{           # SpEL injection in Spring Data
```

### OS Command Injection
```
Runtime\.getRuntime\(\)\.exec\(
new ProcessBuilder\(.*".*\s.*"   # single string with spaces = concatenated cmd+args
ProcessBuilder.*\.command\(.*\+
```

### LDAP Injection
```
ctx\.search\(.*\+.*\)
"cn=" \+ 
"uid=" \+
"ou=" \+
DirContext.*search.*\+
```

### XML/XXE
```
DocumentBuilderFactory\.newInstance\(\)
SAXParserFactory\.newInstance\(\)
XMLInputFactory\.(newFactory|newInstance)\(\)
TransformerFactory\.newInstance\(\)
SchemaFactory\.newInstance\(\)
SAXBuilder\(\)
SAXReader\(\)
XMLDecoder                              # ALWAYS UNSAFE
javax\.xml\.bind\.Unmarshaller          # Check XMLInputFactory config
```

### Deserialization
```
ObjectInputStream\.readObject\(\)
ObjectInputStream\.readUnshared\(\)
ObjectMapper\.enableDefaultTyping\(\)
ObjectMapper\.activateDefaultTyping\(\)
@JsonTypeInfo\(use\s*=\s*JsonTypeInfo\.Id\.CLASS
@JsonTypeInfo\(use\s*=\s*JsonTypeInfo\.Id\.MINIMAL_CLASS
XStream\.fromXML\(
new Yaml\(\)                            # Without SafeConstructor
Kryo.*readClassAndObject\(
```

### NoSQL Injection (Java MongoDB Driver)
```
BasicDBObject\(.*\+                     # BasicDBObject with string concat
Document\.parse\(.*\+                   # Document.parse with string concat
Document\.parse\(.*request\.getParameter # Document.parse with request data
"\\$where".*\+|"\\$where".*request\.    # $where operator with user input
"\\$regex".*\+|"\\$regex".*request\.    # $regex operator with user input
Filters\.where\(.*\+                    # Filters.where with string concat
BasicDBObject.*"\$\w+".*request\.       # MongoDB operator from user input
MongoCollection.*find\(.*\+             # find with string concat
```

### Safe: MongoDB Java Driver (RULE-INJ-012)
```
Filters\.eq\(                           # Driver query builder (safe)
Filters\.and\(|Filters\.or\(            # Logical filter builders (safe)
Filters\.regex\(.*Pattern\.compile      # Programmatic regex (safe)
new Document\("field",\s*value\)        # Document with literal field (safe)
Bson.*filter                            # Bson filter type (safe)
```

## Safe Alternatives (confirm these are used)

### Parameterized SQL
```
connection\.prepareStatement\(.*\?\s
pstmt\.setString\(
pstmt\.setInt\(
pstmt\.setLong\(
session\.createQuery\(.*:param
\.setParameter\("
@Query\(.*:\w+                          # Named parameters
@Param\("
Restrictions\.eq\(
Restrictions\.like\(
CriteriaBuilder\.\w+\(
```

### Safe Command Execution
```
new ProcessBuilder\("cmd", "arg1"       # Separate array elements
ProcessBuilder.*\.command\(List\.of\(
```

### Safe XML Configuration
```
setFeature\(".*disallow-doctype-decl", true\)
setFeature\(XMLConstants\.FEATURE_SECURE_PROCESSING, true\)
setProperty\(XMLInputFactory\.SUPPORT_DTD, false\)
setProperty\("javax\.xml\.stream\.isSupportingExternalEntities", false\)
setAttribute\(XMLConstants\.ACCESS_EXTERNAL_DTD, ""\)
setAttribute\(XMLConstants\.ACCESS_EXTERNAL_STYLESHEET, ""\)
setExpandEntityReferences\(false\)
setXIncludeAware\(false\)
```

### Safe Deserialization
```
resolveClass.*whitelist                 # Custom ObjectInputStream with whitelist
new SafeConstructor\(\)                 # SnakeYAML
Kryo.*setRegistrationRequired\(true\)
@JsonTypeInfo\(use\s*=\s*JsonTypeInfo\.Id\.NAME  # Name-based (with @JsonSubTypes)
```

## Spring-Specific Checks

### Input Validation
```
@Valid                                  # Bean validation on request body
@Validated                              # Spring validation
@NotNull|@NotBlank|@NotEmpty            # Field-level constraints
@Size\(|@Min\(|@Max\(|@Pattern\(       # Value constraints
BindingResult                           # Validation error handling
```

Absence of `@Valid`/`@Validated` on `@RequestBody` parameters is a finding (RULE-INJ-013).

## Stored Procedure SQL Injection (RULE-INJ-014)

### Dangerous: Java stored procedure calls without parameterization
```
connection\.createStatement\(\).*"EXEC   # Statement with EXEC (no binding)
connection\.createStatement\(\).*"CALL   # Statement with CALL (no binding)
"\{call\s+\w+\(" \+ .*\+.*"\)\}"       # JDBC call syntax with string concat
JdbcTemplate\.update\("EXEC.*\+         # JdbcTemplate with EXEC + concat
JdbcTemplate\.query\("EXEC.*\+          # JdbcTemplate query with EXEC + concat
entityManager\.createNativeQuery\("EXEC.*\+  # Native query with EXEC + concat
entityManager\.createNativeQuery\("CALL.*\+  # Native query with CALL + concat
@Query\(.*nativeQuery.*EXEC.*\#\{       # SpEL injection in native stored proc call
```

### Dangerous: Dynamic SQL in stored procedure definitions (SQL files)
```
DECLARE\s+@sql.*NVARCHAR               # T-SQL dynamic SQL variable
SET\s+@sql\s*=.*\+\s*@                  # Building SQL via concatenation with params
EXEC\s*\(\s*@sql\s*\)                   # Executing concatenated SQL variable
EXECUTE\s+IMMEDIATE\s+.*\|\|           # Oracle concat in EXECUTE IMMEDIATE
```

### Safe: Parameterized stored procedure calls in Java
```
connection\.prepareCall\("\{call.*\?    # CallableStatement with ? placeholders
CallableStatement.*\.setString\(        # Bound parameter (String)
CallableStatement.*\.setInt\(           # Bound parameter (int)
CallableStatement.*\.setLong\(          # Bound parameter (long)
CallableStatement.*\.registerOutParameter # Output parameter registration
SimpleJdbcCall\(                        # Spring SimpleJdbcCall (auto-parameterized)
new SimpleJdbcCall.*withProcedureName   # Named procedure call
SimpleJdbcCall.*addDeclaredParameter    # Declared parameter binding
SimpleJdbcCall.*execute\(.*MapSqlParameterSource  # Parameterized execution
StoredProcedure.*declareParameter       # Spring StoredProcedure with declared params
@Procedure\(                            # Spring Data JPA @Procedure (auto-parameterized)
```

## XPath/XQuery Injection (RULE-INJ-015)

### Dangerous: Java XPath with string concatenation
```
XPathFactory\.newInstance\(\)\.newXPath\(\)\.evaluate\(.*\+   # XPath evaluate + concat
XPathFactory\.newInstance\(\)\.newXPath\(\)\.compile\(.*\+    # XPath compile + concat
xpath\.evaluate\(.*\+.*request\.getParameter   # XPath + request parameter
xpath\.compile\(.*\+.*request\.getParameter     # XPath compile + request param
"//\w+\[@\w+=.*'"\s*\+                  # XPath attribute query with concat
"//\w+\[\w+=.*'"\s*\+                   # XPath predicate query with concat
XPathExpression.*=.*xpath\.compile\(.*\+ # XPath expression with dynamic compilation
```

### Dangerous: XQuery in Java
```
XQDataSource.*createExpression\(.*\+    # XQuery expression with concat
XQExpression.*executeQuery\(.*\+        # XQuery exec with concat
Saxon.*XQueryCompiler.*compile\(.*\+    # Saxon XQuery with concat
BaseXClient.*execute\(.*\+.*userInput   # BaseX XQuery with user input
```

### Safe: Parameterized XPath in Java
```
XPathVariableResolver                   # Custom variable resolver (safe)
xpath\.setXPathVariableResolver\(       # Bound variables (safe)
XPathConstants\.                        # Using typed return constants
xpath\.evaluate\(.*XPathConstants       # Typed XPath evaluation
StringEscapeUtils\.escapeXml            # XML escaping before XPath (partial)
@XmlElement.*@Pattern                   # Schema + regex validation before XPath
new QName\(.*\).*XPathVariableResolver  # QName-based variable binding (safe)
```

## Log Injection (RULE-INJ-016)

### Dangerous: String concatenation in log statements
```
logger\.\w+\(".*"\s*\+\s*              # Logger call with string concatenation
log\.\w+\(".*"\s*\+\s*                 # Log call with string concatenation
LOG\.\w+\(".*"\s*\+\s*                 # LOG constant with string concatenation
logger\.\w+\(.*\+.*request\.getParameter  # Logger with request parameter concat
logger\.\w+\(.*\+.*req\.getParameter    # Logger with req parameter concat
System\.out\.print.*\+.*request\.       # System.out with request data
```

### Log injection analysis guidance
```
# CRITICAL: User input directly concatenated into log message
logger\.\w+\(".*"\s*\+\s*\w*(user|name|input|param|request|email|host|ip|path|url)
# Review: Any non-parameterized log call in controller/filter
logger\.\w+\(".*"\s*\+\s*              # in files matching *Controller*, *Filter*, *Interceptor*
```

### Safe: Parameterized logging
```
logger\.\w+\(".*\{\}",\s*              # SLF4J/Logback parameterized logging (safe)
log\.\w+\(".*\{\}",\s*                 # Parameterized log call (safe)
LOG\.\w+\(".*\{\}",\s*                 # Parameterized LOG call (safe)
JsonTemplateLayout                      # Log4j2 JSON structured layout (safe)
JsonEncoder                             # Logback JSON encoder (safe)
StructuredArgument|StructuredArguments  # Logstash Logback structured args (safe)
maxStringLength="\d+"                   # Log4j2 string length limit (safe)
KeyValuePair                            # Log4j2 key-value logging (safe)
```

## Regular Expression Denial of Service (RULE-INJ-017)

### Dangerous: Vulnerable regex patterns in Java
```
Pattern\.compile\(.*\(\w\+\)\+          # Nested quantifier: (a+)+
Pattern\.compile\(.*\(\.\*\)\*          # Nested quantifier: (.*)*
Pattern\.compile\(.*\(\w\|\w\)\*        # Overlapping alternation: (a|a)*
Pattern\.compile\(.*\(\[.*\]\+\)\+     # Nested quantifier on char class
Pattern\.compile\(.*request\.getParameter # User-controlled regex
Pattern\.compile\(.*req\.getParameter   # User-controlled regex
```

### ReDoS analysis guidance
```
# Review any Pattern.compile with user input or complex nested quantifiers
Pattern\.compile\(.*\+                  # Dynamic regex with string concat
new Regex\(.*\+                         # Dynamic regex construction
\.matches\(.*\+.*,                      # String.matches with dynamic pattern
\.split\(.*request\.|\.split\(.*req\.   # Split with user-controlled pattern
\.replaceAll\(.*request\.               # replaceAll with user-controlled regex
```

### Safe: ReDoS prevention in Java
```
Pattern\.compile\(.*,\s*Pattern\..*TIMEOUT  # Pattern with timeout (partial)
com\.google\.re2j\.Pattern              # RE2 library (safe, no backtracking)
```
