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

### Explanation

[1-3 sentences explaining WHY this is dangerous and WHAT an attacker could do.
 Sourced from the OWASP cheatsheet referenced above.]
```

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
