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
- **Reference**: Injection_Prevention_Cheat_Sheet.md
