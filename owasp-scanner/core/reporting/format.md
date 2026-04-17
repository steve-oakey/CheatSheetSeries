# Standard Finding Format

Every security finding produced by the OWASP Scanner **MUST** follow the exact template below. This ensures consistent, machine-diffable reporting across all scanner domains, all AI agent platforms, and all models.

> **CRITICAL INSTRUCTION**: Copy the template structure below **exactly as written**. Replace **only** the `{{...}}` placeholders with actual values. Do not add, remove, reorder, or rename any sections, headings, fields, or table columns. Do not paraphrase or restructure the template. The heading levels, section order, table layout, and code fence format must be reproduced verbatim.

## Finding Template

<!-- TEMPLATE:START — Copy everything between START and END markers exactly. Only replace {{...}} placeholders. -->

```
## Finding: {{RULE_ID}}

| Field | Value |
|-------|-------|
| **Rule** | {{RULE_ID}}: {{RULE_TITLE}} |
| **Severity** | {{SEVERITY}} |
| **CWE** | CWE-{{CWE_NUMBER}} ({{CWE_NAME}}) |
| **File** | {{FILE_PATH}}:{{LINE_NUMBER}} |
| **OWASP Reference** | {{CHEATSHEET_FILENAME}} |

### Vulnerable Code

\`\`\`{{LANGUAGE}}
{{VULNERABLE_CODE_SNIPPET}}
\`\`\`

### Recommended Fix

\`\`\`{{LANGUAGE}}
{{FIXED_CODE_SNIPPET}}
\`\`\`

### Proof of Concept (CRITICAL and HIGH only)

> **Environment**: Non-production only — never execute against production systems.
> **Intent**: Confirms the vulnerability exists. Does not exploit or cause damage.

\`\`\`{{POC_LANGUAGE}}
{{POC_COMMAND_OR_SCRIPT}}
\`\`\`

**Expected result**: {{EXPECTED_RESULT_DESCRIPTION}}

### Explanation

{{EXPLANATION_1_TO_3_SENTENCES}}
```

<!-- TEMPLATE:END -->

## Placeholder Reference

| Placeholder | Value | Example |
|-------------|-------|---------|
| `{{RULE_ID}}` | Stable rule identifier (`RULE-<DOMAIN>-<NNN>`) | `RULE-INJ-001` |
| `{{RULE_TITLE}}` | Short rule name from the rules file | `SQL Injection via String Concatenation` |
| `{{SEVERITY}}` | Exactly one of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` | `CRITICAL` |
| `{{CWE_NUMBER}}` | CWE numeric identifier | `89` |
| `{{CWE_NAME}}` | CWE short name | `SQL Injection` |
| `{{FILE_PATH}}` | Relative path from project root | `src/main/java/com/app/UserDao.java` |
| `{{LINE_NUMBER}}` | 1-based line number | `42` |
| `{{CHEATSHEET_FILENAME}}` | OWASP cheatsheet filename | `SQL_Injection_Prevention_Cheat_Sheet.md` |
| `{{LANGUAGE}}` | Code fence language identifier | `java`, `python`, `javascript`, `typescript` |
| `{{VULNERABLE_CODE_SNIPPET}}` | The vulnerable code with surrounding context | *(see example below)* |
| `{{FIXED_CODE_SNIPPET}}` | The corrected code showing remediation | *(see example below)* |
| `{{POC_LANGUAGE}}` | PoC code fence language: `bash`, `python`, `javascript`, or `browser-console` | `bash` |
| `{{POC_COMMAND_OR_SCRIPT}}` | Minimal non-destructive proof command | *(see example below)* |
| `{{EXPECTED_RESULT_DESCRIPTION}}` | One sentence describing what a successful proof looks like | `Returns all users instead of just the queried one.` |
| `{{EXPLANATION_1_TO_3_SENTENCES}}` | Why dangerous + what attacker could do (sourced from OWASP cheatsheet) | *(see example below)* |

## Format Rules

### DO

- **DO** reproduce the template heading levels exactly: `##` for the finding title, `###` for subsections
- **DO** include the metadata table for every finding, even if there is only one finding
- **DO** include a language identifier on every code fence (e.g., `` ```java ``, never bare `` ``` ``)
- **DO** use exactly one blank line between sections
- **DO** keep the five sections in this exact order: metadata table → Vulnerable Code → Recommended Fix → Proof of Concept → Explanation
- **DO** omit the entire "Proof of Concept" section (heading and all content) for MEDIUM, LOW, and INFO findings

### DO NOT

- **DO NOT** use bullet lists, numbered lists, or prose instead of the metadata table
- **DO NOT** change the table column headers (`Field` and `Value`)
- **DO NOT** add extra fields, columns, or rows to the metadata table
- **DO NOT** add extra subsections beyond the five defined above (no "Impact", "Details", "Notes", "References", etc.)
- **DO NOT** reorder the sections (e.g., putting Explanation before Recommended Fix)
- **DO NOT** leave the PoC section as an empty placeholder for MEDIUM/LOW/INFO — omit it entirely
- **DO NOT** combine multiple findings into a single finding block — one `## Finding:` block per finding
- **DO NOT** use heading level `#` (reserved for the report title) or `####` (not used in findings)
- **DO NOT** wrap the finding in an outer code fence — output it as live Markdown

## Complete Example

Below is a fully filled-in finding. Use this as your reference for exact structure and tone.

---

## Finding: RULE-INJ-001

| Field | Value |
|-------|-------|
| **Rule** | RULE-INJ-001: SQL Injection via String Concatenation |
| **Severity** | CRITICAL |
| **CWE** | CWE-89 (SQL Injection) |
| **File** | src/main/java/com/example/dao/UserDao.java:42 |
| **OWASP Reference** | SQL_Injection_Prevention_Cheat_Sheet.md |

### Vulnerable Code

```java
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = '" + username + "'";
    return jdbcTemplate.queryForObject(sql, new UserRowMapper());
}
```

### Recommended Fix

```java
public User findByUsername(String username) {
    String sql = "SELECT * FROM users WHERE username = ?";
    return jdbcTemplate.queryForObject(sql, new UserRowMapper(), username);
}
```

### Proof of Concept (CRITICAL and HIGH only)

> **Environment**: Non-production only — never execute against production systems.
> **Intent**: Confirms the vulnerability exists. Does not exploit or cause damage.

```bash
curl "https://localhost:8080/api/users?username=test'%20OR%20'1'%3D'1'%20--"
```

**Expected result**: Returns all users instead of just the queried one, confirming the query is injectable.

### Explanation

User-supplied input is concatenated directly into a SQL query string, allowing an attacker to inject arbitrary SQL. This can lead to unauthorized data access, data modification, or full database compromise. Use parameterized queries with bind variables to prevent injection.

---

## Proof of Concept Guidelines

The Proof of Concept (PoC) section is included **only for CRITICAL and HIGH severity findings**. It provides development teams with a reproducible way to verify the vulnerability exists in non-production environments.

### Safety Rules

1. **Non-destructive only** — PoCs must be read-only proofs of existence. Never use DELETE, DROP, UPDATE, TRUNCATE, or any data-modifying operation.
2. **Benign payloads** — Use harmless values that demonstrate the flaw without causing impact:
   - SQL Injection: `' OR '1'='1' --` (read-only proof), never `DROP TABLE`
   - XSS: `<img src=x onerror=alert(document.domain)>` (visual confirmation), never credential-stealing scripts
   - Command Injection: `; id` or `; hostname` (identity commands), never `rm` or `wget` for payloads
   - SSRF: `http://169.254.169.254/latest/meta-data/` (metadata read), never internal service mutation
3. **Non-production environments only** — PoCs are designed for dev/staging/QA environments. Mark this clearly in the output.
4. **Include expected output** — Always state what a successful proof looks like so teams can verify without guesswork.
5. **Minimal access** — PoCs should assume only the access level an attacker would realistically have (e.g., unauthenticated for public endpoints, authenticated as a regular user for IDOR).

### Format Guidelines

- **Web endpoints**: Use `curl` commands with crafted payloads
- **Client-side issues**: Use browser developer console scripts
- **Library/code-level issues**: Use short Python or JavaScript snippets
- **Configuration issues**: Use CLI tools (e.g., `openssl`, `nmap`, `curl -v`) to demonstrate the misconfiguration
- **Secrets/keys**: Use `grep` commands to show the match (redact actual values in output)

### When to Omit

Omit the PoC section when:
- Severity is MEDIUM, LOW, or INFO
- The vulnerability is a configuration absence (e.g., missing SBOM) with no demonstrable exploit
- A safe PoC would require tooling not commonly available to development teams

## Field Descriptions

### Rule ID
Stable identifier in the format `RULE-<DOMAIN>-<NNN>`:
- `RULE-INJ-001` through `RULE-INJ-NNN` -- Injection scanner
- `RULE-XSS-001` through `RULE-XSS-NNN` -- XSS scanner
- `RULE-CFG-001` through `RULE-CFG-NNN` -- Configuration scanner
- `RULE-AUTH-001` through `RULE-AUTH-NNN` -- Auth scanner
- `RULE-API-001` through `RULE-API-NNN` -- API scanner
- `RULE-SC-001` through `RULE-SC-NNN` -- Supply chain scanner

### Severity
See `severity-guide.md` for classification criteria. Use the highest applicable severity.

### CWE
The Common Weakness Enumeration identifier. Use the most specific CWE that applies.

### File
Path relative to the project root, with line number separated by colon.

### OWASP Reference
The filename of the OWASP Cheat Sheet that this rule is derived from.

## Report Aggregation

When multiple findings are produced, the report generator **MUST**:

1. **Sort by severity** (CRITICAL first, INFO last)
2. **Group by domain** within each severity level
3. **Deduplicate** findings that point to the same root cause
4. **Count** total findings per severity level in the executive summary table
5. **Prioritize remediation** by suggesting which findings to fix first (CRITICAL with easy fixes first)
6. **Use the report template** in `core/reporting/report-template.md` exactly as specified — copy its structure verbatim and only replace `{{...}}` placeholders
