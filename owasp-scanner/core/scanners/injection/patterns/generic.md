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
