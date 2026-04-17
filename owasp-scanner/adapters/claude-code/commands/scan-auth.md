---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for authentication, authorization, and session management vulnerabilities."
---

## Your Task

Perform an authentication and authorization security scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/prompt.md`
3. Load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/patterns/`
4. Search for weak password hashing, hardcoded credentials, JWT issues, session problems, missing authorization
5. Report findings using the format in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md`
6. For CRITICAL and HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules
