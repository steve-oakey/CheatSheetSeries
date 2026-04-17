# Standard Finding Format

Every security finding produced by the OWASP Scanner must follow this format. This ensures consistent reporting across all scanner domains and all AI agent platforms.

## Finding Template

```
## Finding: [RULE-ID]

| Field | Value |
|-------|-------|
| **Rule** | [Rule ID]: [Rule Title] |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **CWE** | CWE-[number] ([name]) |
| **File** | [relative/path/to/file]:[line number] |
| **OWASP Reference** | [Cheatsheet_Name_Cheat_Sheet.md] |

### Vulnerable Code

\`\`\`[language]
[The vulnerable code snippet, with the problematic line highlighted]
\`\`\`

### Recommended Fix

\`\`\`[language]
[The corrected code, showing how to remediate the vulnerability]
\`\`\`

### Proof of Concept (CRITICAL and HIGH only)

> **Environment**: Non-production only — never execute against production systems.
> **Intent**: Confirms the vulnerability exists. Does not exploit or cause damage.

\`\`\`[bash|python|javascript|browser-console]
[A minimal, non-destructive command or script that demonstrates the vulnerability.
 Use benign payloads that prove the issue without modifying data or causing harm.
 Include the expected output that confirms the vulnerability.]
\`\`\`

**Expected result**: [1 sentence describing what a successful proof looks like,
e.g., "Returns data for a user other than the authenticated one."]

### Explanation

[1-3 sentences explaining WHY this is dangerous and WHAT an attacker could do.
 Sourced from the OWASP cheatsheet referenced above.]
```

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

When multiple findings are produced, the report generator should:

1. **Sort by severity** (CRITICAL first, INFO last)
2. **Group by domain** within each severity level
3. **Deduplicate** findings that point to the same root cause
4. **Count** total findings per severity level in an executive summary
5. **Prioritize remediation** by suggesting which findings to fix first (CRITICAL with easy fixes first)
