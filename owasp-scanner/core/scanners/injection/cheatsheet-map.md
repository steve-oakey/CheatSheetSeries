# Injection Scanner: Cheatsheet Map

Maps each rule to the specific section of the OWASP cheatsheet it was derived from.
For deeper analysis, load the full cheatsheet from `core/reference/cheatsheets/`.

| Rule ID | Source Cheatsheet | Section |
|---------|-------------------|---------|
| RULE-INJ-001 | SQL_Injection_Prevention_Cheat_Sheet.md | Anatomy of a Typical SQL Injection Vulnerability |
| RULE-INJ-002 | SQL_Injection_Prevention_Cheat_Sheet.md | Defense Option 1: Prepared Statements |
| RULE-INJ-003 | Query_Parameterization_Cheat_Sheet.md | Hibernate HQL / JPA |
| RULE-INJ-004 | OS_Command_Injection_Defense_Cheat_Sheet.md | Primary Defenses |
| RULE-INJ-005 | LDAP_Injection_Prevention_Cheat_Sheet.md | Primary Defenses |
| RULE-INJ-006 | XML_External_Entity_Prevention_Cheat_Sheet.md | Java (all parser sections) |
| RULE-INJ-007 | XML_External_Entity_Prevention_Cheat_Sheet.md | XMLDecoder |
| RULE-INJ-008 | Deserialization_Cheat_Sheet.md | Java |
| RULE-INJ-009 | Deserialization_Cheat_Sheet.md | Python |
| RULE-INJ-010 | Deserialization_Cheat_Sheet.md | Java (Jackson section) |
| RULE-INJ-011 | Deserialization_Cheat_Sheet.md | Known Affected Libraries |
| RULE-INJ-012 | NoSQL_Security_Cheat_Sheet.md | Injection Prevention |
| RULE-INJ-013 | Input_Validation_Cheat_Sheet.md | Implementing Input Validation |
| RULE-INJ-014 | SQL_Injection_Prevention_Cheat_Sheet.md | Defense Option 2: Stored Procedures |
| RULE-INJ-015 | Injection_Prevention_Cheat_Sheet.md | XPath/XQuery |
| RULE-INJ-016 | Java_Security_Cheat_Sheet.md | Log Injection |
| RULE-INJ-017 | Nodejs_Security_Cheat_Sheet.md | Stay away from evil regexes |

## Supplementary Cheatsheets

These cheatsheets provide additional context but are not primary rule sources:
- **Database_Security_Cheat_Sheet.md** -- Database hardening, least privilege (referenced by RULE-INJ-001, RULE-INJ-002)
- **XML_Security_Cheat_Sheet.md** -- Broader XML attack surface (referenced by RULE-INJ-006, RULE-INJ-007)
- **Java_Security_Cheat_Sheet.md** -- Java-specific injection patterns: NoSQL (Java MongoDB driver), XPath (XPathVariableResolver), HTML/JS encoding (referenced by RULE-INJ-012, RULE-INJ-015, RULE-INJ-016)
- **Nodejs_Security_Cheat_Sheet.md** -- Node.js dangerous functions (eval, child_process.exec), ReDoS patterns (referenced by RULE-INJ-004, RULE-INJ-017)
- **Injection_Prevention_in_Java_Cheat_Sheet.md** -- Redirects to Java_Security_Cheat_Sheet.md
