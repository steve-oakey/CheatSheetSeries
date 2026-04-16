# Injection Patterns: Language-Agnostic

Search patterns that apply regardless of programming language.

## Dangerous SQL Patterns

Search for string concatenation near SQL keywords:
```
"SELECT .* \+ .*"
"INSERT .* \+ .*"
"UPDATE .* \+ .*"
"DELETE .* \+ .*"
"WHERE .* \+ .*"
```

Search for format strings with SQL:
```
String\.format\(.*SELECT
String\.format\(.*INSERT
String\.format\(.*UPDATE
String\.format\(.*DELETE
sprintf\(.*SELECT
f".*SELECT.*\{
`.*SELECT.*\$\{
```

## Dangerous Command Execution Patterns

Search for command execution with dynamic input:
```
exec\(.*\+
system\(.*\+
popen\(.*\+
shell_exec\(
passthru\(
```

## Dangerous Deserialization Patterns

Search for deserialization of untrusted data:
```
\.readObject\(
pickle\.load
pickle\.loads
yaml\.load\((?!.*SafeLoader)
yaml\.load\((?!.*safe_load)
jsonpickle\.decode
Marshal\.load
unserialize\(
```

## Dangerous XML Patterns

Search for XML parsers without secure configuration:
```
XMLDecoder
DocumentBuilderFactory\.newInstance
SAXParserFactory\.newInstance
XMLInputFactory\.newFactory
XMLReader
```

Then verify these are followed by security features:
```
disallow-doctype-decl
SUPPORT_DTD.*false
external-general-entities.*false
external-parameter-entities.*false
ACCESS_EXTERNAL_DTD
FEATURE_SECURE_PROCESSING
```

## Dangerous NoSQL Patterns

Search for NoSQL operator injection:
```
\$where
\$regex
\$expr
\$gt.*request
\$ne.*request
\$or.*request
db\.eval\(
```

## Input Validation Red Flags

Search for missing anchors in regex:
```
Pattern\.compile\("[^\\^]
new RegExp\("[^\\^]
/[^\\^].*[^\\$]/
```

Search for denylist patterns (weaker than allowlist):
```
\.contains\("'"\)
\.contains\("<"\)
\.replace\("'", ""\)
\.replace\("<", ""\)
blacklist|blocklist.*=.*\[
```

## Stored Procedure SQL Injection (RULE-INJ-014)

### Dangerous: Dynamic SQL inside stored procedure calls
```
EXEC\s+sp_.*\+                          # EXEC with string concatenation
EXECUTE\s+sp_.*\+                       # EXECUTE with concatenation
EXECUTE\s+IMMEDIATE.*\+                 # Oracle EXECUTE IMMEDIATE + concat
EXEC\s*\(.*\+                           # EXEC with dynamic SQL
sp_executesql.*\+                       # sp_executesql with concat (defeats purpose)
DECLARE.*@sql.*\+.*EXEC\s*\(@sql        # T-SQL dynamic SQL via variable
PREPARE.*FROM.*\+                       # PREPARE statement with concatenation
```

### Dangerous: Calling stored procedures without parameterization
```
createStatement\(\)\.execute.*EXEC      # Statement (not PreparedStatement) with EXEC
createStatement\(\)\.execute.*CALL      # Statement with CALL
"CALL\s+\w+\(" \+                      # String concat in CALL statement
"\{call\s+\w+\(" \+                    # JDBC call syntax with concat
```

### Safe: Parameterized stored procedure calls
```
prepareCall\("\{call.*\?                # JDBC CallableStatement with placeholders
CallableStatement.*set(String|Int|Long) # Bound parameters on callable
sp_executesql.*@param                   # Parameterized sp_executesql (good)
USING\s+\w+                             # Oracle EXECUTE IMMEDIATE ... USING (good)
```

## XPath/XQuery Injection (RULE-INJ-015)

### Dangerous: String concatenation in XPath expressions
```
"//.*\[@.*=.*'" \+                      # XPath attribute selector with concat
xpath\.evaluate\(.*\+                   # XPath evaluate with concatenation
xpath\.compile\(.*\+                    # XPath compile with concatenation
XPathExpression.*\+.*evaluate           # XPath expression built via concat
"//*\[.*" \+                            # XPath predicate with concat
"contains\(.*" \+                       # XPath contains() with concat
SelectSingleNode\(.*\+                  # .NET XPath with concat
SelectNodes\(.*\+                       # .NET XPath with concat
document\.evaluate\(.*\+                # JavaScript XPath with concat
```

### Dangerous: XQuery with dynamic input
```
xquery.*\+.*userInput                   # XQuery with user input concat
XQExpression.*\+                        # XQuery expression with concat
declare.*variable.*\+                   # XQuery variable with concat
```

### Safe: Parameterized or validated XPath
```
XPath.*setVariable                      # XPath variable binding (safe)
XPathVariableResolver                   # Custom variable resolver (safe)
xpath.*precompil|XPathExpression.*cache # Precompiled XPath (good)
allowlist|whitelist.*xpath              # XPath input allowlisting
Pattern\.matches.*xpath                 # Regex validation before XPath
```
