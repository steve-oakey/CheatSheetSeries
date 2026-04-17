---
applyTo: "**/*.java,**/*.py,**/*.js,**/*.ts,**/*.go,**/*.rb,**/*.php,**/*.cs,**/*.kt"
---

# OWASP Injection Security Checks

When reviewing or generating code in these files, watch for injection vulnerabilities. Flag any matches and suggest secure alternatives.

## Critical Patterns to Detect

### SQL Injection (RULE-INJ-001, CWE-89)
- `"SELECT ... " + variable` or `"INSERT ... " + variable`
- `String.format("SELECT ... %s", userInput)`
- Template literals with SQL: `` `SELECT ... ${userInput}` ``
- f-strings with SQL: `f"SELECT ... {user_input}"`
- MyBatis `${}` interpolation (unsafe) vs `#{}` (safe)
- **Fix**: Use parameterized queries with bind variables (`?` placeholders)

### Non-Parameterized Statements (RULE-INJ-002, CWE-89)
- `Statement.executeQuery(query)` where query contains concatenation
- `connection.createStatement()` followed by dynamic query execution
- **Fix**: Replace with `PreparedStatement` using `?` placeholders

### ORM Query Injection (RULE-INJ-003, CWE-89)
- `session.createQuery("... " + userInput)` (Hibernate HQL)
- `entityManager.createQuery("... " + param)` (JPA JPQL)
- `entityManager.createNativeQuery("... " + param)`
- **Fix**: Use named parameters: `.setParameter("name", input)`

### OS Command Injection (RULE-INJ-004, CWE-78)
- `Runtime.getRuntime().exec(userControlledString)`
- `child_process.exec(userInput)` (Node.js)
- `os.system(userInput)` or `subprocess.call(userInput, shell=True)` (Python)
- **Fix**: Use array-based command execution with arguments as separate elements

### XXE - Unsafe XML Parsing (RULE-INJ-006, CWE-611)
- `DocumentBuilderFactory.newInstance()` without disabling DTD
- `SAXParserFactory.newInstance()` without disabling external entities
- `XMLInputFactory.newFactory()` without `SUPPORT_DTD = false`
- **Fix**: Set `disallow-doctype-decl` feature to true on all XML parsers

### Unsafe Deserialization (RULE-INJ-008/009, CWE-502)
- `ObjectInputStream.readObject()` on untrusted input (Java)
- `XMLDecoder` usage (Java — fundamentally unsafe)
- `pickle.load()` / `pickle.loads()` on untrusted data (Python)
- `yaml.load()` without `Loader=yaml.SafeLoader` (Python)
- **Fix**: Use class whitelists for Java deserialization; use `json.loads()` or `yaml.safe_load()` for Python

### NoSQL Injection (RULE-INJ-012, CWE-943)
- `db.collection.find({field: req.body.value})` where value could be `{"$gt": ""}`
- `Model.find({email: req.query.email})` without type checking
- **Fix**: Validate input types. Use `mongo-sanitize` or explicit type casting.

## For Comprehensive Scanning

Read the full rule set at `owasp-scanner/core/scanners/injection/rules.md` and language-specific patterns in `owasp-scanner/core/scanners/injection/patterns/`.
