# Injection Scanner Rules

Rules distilled from OWASP Cheat Sheet Series for detecting injection vulnerabilities in source code.

## RULE-INJ-001: SQL Injection via String Concatenation
- **Severity**: CRITICAL
- **CWE**: CWE-89 (SQL Injection)
- **What to find**: Dynamic SQL queries built by concatenating user-controlled input
- **Patterns**:
  - `"SELECT ... " + variable` or `"INSERT ... " + variable`
  - `String.format("SELECT ... %s", userInput)`
  - Template literals with SQL: `` `SELECT ... ${userInput}` ``
  - f-strings with SQL: `f"SELECT ... {user_input}"`
  - MyBatis `${}` interpolation (unsafe) vs `#{}` (safe)
- **Fix**: Use parameterized queries with bind variables (`?` placeholders)
- **PoC**: `curl "https://<target>/api/users?name=test' OR '1'='1' --"` — if the response returns all users instead of one (or returns data without proper authorization), the endpoint is vulnerable to SQL injection.
- **Reference**: SQL_Injection_Prevention_Cheat_Sheet.md#defense-option-1

## RULE-INJ-002: Use of Non-Parameterized Statement
- **Severity**: CRITICAL
- **CWE**: CWE-89
- **What to find**: Use of `Statement` instead of `PreparedStatement` for queries with external input
- **Patterns**:
  - `Statement.executeQuery(query)` where query contains concatenation
  - `Statement.execute(query)` with dynamic SQL
  - `connection.createStatement()` followed by dynamic query execution
- **Fix**: Replace with `connection.prepareStatement(query)` using `?` placeholders and `setString()`/`setInt()` etc.
- **PoC**: `curl "https://<target>/api/items?id=1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables--"` — if the response includes database table names, the endpoint accepts unparameterized SQL.
- **Reference**: SQL_Injection_Prevention_Cheat_Sheet.md#safe-java-prepared-statement-example

## RULE-INJ-003: ORM Query Injection
- **Severity**: HIGH
- **CWE**: CWE-89
- **What to find**: String concatenation in ORM query builders (HQL, JPQL, Criteria)
- **Patterns**:
  - `session.createQuery("... " + userInput)` (Hibernate HQL injection)
  - `entityManager.createQuery("... " + param)` (JPA JPQL injection)
  - `entityManager.createNativeQuery("... " + param)` (native SQL injection)
  - `@Query("... " + ...)` in Spring Data (SpEL injection via `?#{...}`)
- **Fix**: Use named parameters: `session.createQuery("FROM User WHERE name = :name").setParameter("name", input)`
- **PoC**: `curl "https://<target>/api/search?q=test' OR '1'='1"` — if the response returns all records regardless of the search term, the ORM query is injectable.
- **Reference**: Query_Parameterization_Cheat_Sheet.md#hibernate-hql

## RULE-INJ-004: OS Command Injection
- **Severity**: CRITICAL
- **CWE**: CWE-78 (OS Command Injection)
- **What to find**: User input passed to operating system command execution functions
- **Patterns**:
  - `Runtime.getRuntime().exec(userControlledString)`
  - `ProcessBuilder` with a single string containing spaces (command + args concatenated)
  - `child_process.exec(userInput)` (Node.js)
  - `child_process.spawn(cmd, {shell: true})` (Node.js with shell)
  - `os.system(userInput)` (Python)
  - `subprocess.call(userInput, shell=True)` (Python)
  - `system(userInput)` (C/PHP)
- **Fix**: Use array-based command execution with arguments as separate elements. `new ProcessBuilder("cmd", "arg1", "arg2")`
- **PoC**: `curl -X POST "https://<target>/api/convert" -d "filename=test.pdf;id"` — if the response includes OS user information (e.g., `uid=1000`), the input is passed to a shell command unsanitized.
- **Reference**: OS_Command_Injection_Defense_Cheat_Sheet.md

## RULE-INJ-005: LDAP Injection
- **Severity**: HIGH
- **CWE**: CWE-90 (LDAP Injection)
- **What to find**: String concatenation in LDAP search filters or DN construction
- **Patterns**:
  - `"(&(uid=" + userInput + ")(objectClass=person))"`
  - `ctx.search(baseDN, filterWithConcat, controls)`
  - `"cn=" + userInput` (DN construction without escaping)
- **Fix**: Use parameterized LDAP filters: `ctx.search(baseDN, "(&(uid={0})(objectClass=person))", new Object[]{userInput}, controls)`
- **PoC**: `curl "https://<target>/api/users?username=*)(objectClass=*"` — if the response returns multiple user entries instead of an error, the LDAP filter is injectable.
- **Reference**: LDAP_Injection_Prevention_Cheat_Sheet.md

## RULE-INJ-006: XML External Entity (XXE) - Unsafe Parser Configuration
- **Severity**: CRITICAL
- **CWE**: CWE-611 (XXE)
- **What to find**: XML parsers instantiated without disabling external entity processing
- **Patterns**:
  - `DocumentBuilderFactory.newInstance()` without `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
  - `SAXParserFactory.newInstance()` without disallow-doctype-decl feature
  - `XMLInputFactory.newFactory()` without `setProperty(XMLInputFactory.SUPPORT_DTD, false)`
  - `SAXBuilder()` or `SAXReader()` without disallow-doctype-decl
  - `XMLReader` without external entity features disabled
  - `TransformerFactory` without `ACCESS_EXTERNAL_DTD` set to empty string
  - `SchemaFactory` without `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_SCHEMA` restrictions
- **Fix**: Disable DTD processing and external entities. See cheatsheet for parser-specific configuration.
- **PoC**: `curl -X POST "https://<target>/api/xml" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>'` — if the response contains the server's hostname, the XML parser processes external entities.
- **Reference**: XML_External_Entity_Prevention_Cheat_Sheet.md

## RULE-INJ-007: XMLDecoder Usage
- **Severity**: CRITICAL
- **CWE**: CWE-611, CWE-502
- **What to find**: Any use of `java.beans.XMLDecoder` -- it is fundamentally unsafe and cannot be secured
- **Patterns**:
  - `XMLDecoder` (any usage)
  - `new XMLDecoder(`
  - `xmlDecoder.readObject()`
- **Fix**: Replace XMLDecoder with a safe XML parsing library (JAXB, Jackson XML, etc.)
- **PoC**: `grep -rn "XMLDecoder" --include="*.java" .` — any match confirms usage of a fundamentally unsafe API. Verify the decoded input source is external/untrusted by tracing the InputStream origin.
- **Reference**: XML_External_Entity_Prevention_Cheat_Sheet.md#xmldecoder

## RULE-INJ-008: Unsafe Java Deserialization
- **Severity**: CRITICAL
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **What to find**: Native Java deserialization of untrusted data without type filtering
- **Patterns**:
  - `ObjectInputStream.readObject()` on untrusted input
  - `ObjectInputStream.readUnshared()` on untrusted input
  - `XStream.fromXML()` (versions < 1.4.17 or without allowlist)
  - Content-Type `application/x-java-serialized-object` accepted
  - Byte sequences starting with `AC ED 00 05` (hex) or `rO0` (base64)
- **Fix**: Override `resolveClass()` with a class whitelist, use SerialKiller library, or switch to JSON serialization
- **PoC**: `curl -X POST "https://<target>/api/import" -H "Content-Type: application/x-java-serialized-object" -d @payload.bin` where `payload.bin` contains a benign `java.util.HashMap` serialized object (hex: `ACED0005...`). If the server deserializes it without rejection, any class on the classpath can be instantiated.
- **Reference**: Deserialization_Cheat_Sheet.md#java

## RULE-INJ-009: Unsafe Deserialization (Python)
- **Severity**: CRITICAL
- **CWE**: CWE-502
- **What to find**: Python deserialization of untrusted data
- **Patterns**:
  - `pickle.load()` or `pickle.loads()` on untrusted data
  - `yaml.load()` without `Loader=yaml.SafeLoader`
  - `jsonpickle.decode()` on untrusted data
  - `shelve.open()` on untrusted data
- **Fix**: Use `json.loads()` for data interchange. If YAML needed, use `yaml.safe_load()`
- **PoC**: `python3 -c "import pickle,base64; print(base64.b64encode(pickle.dumps({'test':'safe'})).decode())"` — submit the resulting base64 to the endpoint. If the server accepts and processes it, the deserialization path is confirmed. A malicious pickle could execute arbitrary code.
- **Reference**: Deserialization_Cheat_Sheet.md#python

## RULE-INJ-010: Unsafe Deserialization (Jackson Polymorphism)
- **Severity**: HIGH
- **CWE**: CWE-502
- **What to find**: Jackson ObjectMapper with default typing enabled (allows arbitrary class instantiation)
- **Patterns**:
  - `ObjectMapper.enableDefaultTyping()` or `activateDefaultTyping()`
  - `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` (class-based polymorphism)
  - `@JsonTypeInfo(use = JsonTypeInfo.Id.MINIMAL_CLASS)`
- **Fix**: Disable default typing. Use `@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)` with explicit `@JsonSubTypes` whitelist
- **PoC**: `curl -X POST "https://<target>/api/data" -H "Content-Type: application/json" -d '{"@class":"java.util.HashMap","key":"value"}'` — if the server instantiates `HashMap` from the `@class` hint instead of rejecting it, polymorphic deserialization is enabled and arbitrary classes can be targeted.
- **Reference**: Deserialization_Cheat_Sheet.md#java

## RULE-INJ-011: Unsafe Deserialization Libraries
- **Severity**: HIGH
- **CWE**: CWE-502
- **What to find**: Usage of libraries with known deserialization vulnerabilities
- **Patterns**:
  - `fastjson` < v1.2.68 with auto-type
  - `SnakeYAML` without `SafeConstructor`: `new Yaml()` instead of `new Yaml(new SafeConstructor())`
  - `Kryo` < v5.0.0 without class registration
  - `json-io` with `@type` property support
  - `YamlBeans` < v1.16 with UnsafeYamlConfig
- **Fix**: Update to safe versions and enable security features (SafeConstructor, class registration, etc.)
- **PoC**: `grep -rn "new Yaml()\|new Kryo()\|fastjson" --include="*.java" .` — matches without corresponding `SafeConstructor`, `setRegistrationRequired(true)`, or auto-type disabled confirm unsafe library usage. Check the library version in `pom.xml`/`build.gradle` for known CVEs.
- **Reference**: Deserialization_Cheat_Sheet.md

## RULE-INJ-012: NoSQL Injection
- **Severity**: HIGH
- **CWE**: CWE-943 (Improper Neutralization in Data Query Logic)
- **What to find**: User input used to construct NoSQL queries without sanitization
- **Patterns**:
  - MongoDB: `db.eval()` with user input
  - String-built query objects: `eval("(" + queryString + ")")`
  - User-controlled operators: `$where`, `$regex`, `$expr`, `$gt`, `$ne` from request body
  - Raw JSON from client used directly as query filter
- **Fix**: Use driver query objects, whitelist-validate operators, reject input containing `$` prefixed keys
- **PoC**: `curl -X POST "https://<target>/api/login" -H "Content-Type: application/json" -d '{"username":{"$gt":""},"password":{"$gt":""}}'` — if the server returns a successful authentication response, the NoSQL query accepts operator injection.
- **Reference**: NoSQL_Security_Cheat_Sheet.md

## RULE-INJ-013: Missing Input Validation
- **Severity**: MEDIUM
- **CWE**: CWE-20 (Improper Input Validation)
- **What to find**: User input reaching sensitive operations without validation
- **Patterns**:
  - Regex patterns without anchors: `Pattern.compile("\\d+")` instead of `Pattern.compile("^\\d+$")`
  - Denylist-only validation: checking for specific bad chars rather than allowlisting good chars
  - No type conversion/validation before use: `request.getParameter()` used directly
  - No length limits on input fields
- **Fix**: Use allowlist validation with anchored regex (`^...$`), type conversion with error handling, and length limits
- **Reference**: Input_Validation_Cheat_Sheet.md

## RULE-INJ-014: Stored Procedure SQL Injection
- **Severity**: HIGH
- **CWE**: CWE-89
- **What to find**: Stored procedures that build dynamic SQL internally
- **Patterns**:
  - `sp_execute`, `EXECUTE`, `EXEC` with concatenated strings inside stored procedures
  - Dynamic SQL via `EXECUTE IMMEDIATE` with user parameters
  - `PREPARE` statement with concatenated SQL
- **Fix**: Use parameterized stored procedures: `connection.prepareCall("{call sp_name(?)}")` with bind parameters
- **PoC**: `curl "https://<target>/api/report?param=test'; WAITFOR DELAY '0:0:5'--"` — if the response is delayed by ~5 seconds, the stored procedure concatenates input into dynamic SQL (time-based blind injection).
- **Reference**: SQL_Injection_Prevention_Cheat_Sheet.md#defense-option-2

## RULE-INJ-015: XPath/XQuery Injection
- **Severity**: HIGH
- **CWE**: CWE-643 (XPath Injection)
- **What to find**: String concatenation in XPath or XQuery expressions
- **Patterns**:
  - `"//user[@name='" + userInput + "']"`
  - `xpath.evaluate("... " + param, ...)`
  - `XPathFactory` with unsanitized expressions
- **Fix**: Use parameterized XPath queries or precompiled XPath expressions with variable binding
- **PoC**: `curl "https://<target>/api/search?name=test' or '1'='1"` — if the response returns all XML nodes instead of a filtered subset, the XPath expression is injectable.
- **Reference**: Injection_Prevention_Cheat_Sheet.md

## RULE-INJ-016: Log Injection (CRLF)
- **Severity**: MEDIUM
- **CWE**: CWE-117 (Improper Output Neutralization for Logs)
- **What to find**: Untrusted data concatenated into log statements, allowing attackers to inject newlines (CR/LF) to forge log entries or corrupt log integrity
- **Patterns**:
  - `logger.info("... " + userInput)` — string concatenation in log calls
  - `logger.warn("... " + request.getParameter(...))` — request data concatenated into logs
  - `logging.info(f"... {user_input}")` — Python f-string in log call
  - `logger.info(`... ${req.body.name}`)` — Node.js template literal in log call
  - Log message containing unvalidated CR (`\r`) or LF (`\n`) characters from user input
- **Fix**: Use parameterized logging: `logger.warn("Failed login for user {}", username)`. Use structured logging (JSON format) with field-level encoding. Apply `maxStringLength` limits in log configuration.
- **PoC**: `curl -X POST "https://<target>/api/login" -d 'username=admin%0d%0a[INFO] Login succeeded for admin'` — if the injected newline and fake log entry appear as a separate line in the application log file, the endpoint is vulnerable to log injection.
- **Reference**: Java_Security_Cheat_Sheet.md#log-injection

## RULE-INJ-017: Regular Expression Denial of Service (ReDoS)
- **Severity**: MEDIUM
- **CWE**: CWE-1333 (Inefficient Regular Expression Complexity)
- **What to find**: Regex patterns with nested quantifiers that cause catastrophic backtracking when matched against crafted input
- **Patterns**:
  - Nested quantifiers: `(a+)+`, `(a|a)*`, `(.*)*`, `([a-zA-Z]+)*`
  - Overlapping alternation with quantifiers: `(a|aa)+`, `(\d+|\d+\.)+`
  - Complex backtracking: `^(([a-z])+.)+[A-Z]([a-z])+$`
  - User-controlled regex: `new RegExp(req.body.pattern)`, `Pattern.compile(userInput)`, `re.compile(user_input)`
- **Fix**: Use atomic groups or possessive quantifiers where available. Limit regex complexity. Use RE2 or safe-regex libraries. Never compile user input as regex without validation.
- **PoC**: `curl "https://<target>/api/search?q=aaaaaaaaaaaaaaaaaaaaaaaaaaa!"` — if the response takes exponentially longer as the input length grows (e.g., 1s for 20 chars, 30s for 30 chars), the regex is vulnerable to catastrophic backtracking.
- **Reference**: Nodejs_Security_Cheat_Sheet.md#stay-away-from-evil-regexes
