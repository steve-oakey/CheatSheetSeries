---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for injection vulnerabilities (SQL, NoSQL, OS command, LDAP, XXE, deserialization)."
---

## Your Task

Perform an injection vulnerability scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/prompt.md`
3. Detect the project's language and load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/patterns/`
4. Search the project source code for each rule's dangerous patterns using Grep and Glob
5. Read suspect files to verify findings in context
6. Report findings using the format in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md`
7. Sort findings by severity (CRITICAL first)

For deeper remediation guidance, read the relevant cheatsheet from `${CLAUDE_PLUGIN_ROOT}/../../core/reference/cheatsheets/`
