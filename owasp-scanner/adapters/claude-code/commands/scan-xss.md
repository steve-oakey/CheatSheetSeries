---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for Cross-Site Scripting vulnerabilities (reflected, stored, DOM-based XSS, CSP, prototype pollution)."
---

## Your Task

Perform an XSS vulnerability scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/prompt.md`
3. Detect the frontend framework and load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/patterns/`
4. Search for dangerous DOM sinks, framework escape hatches, CSP issues, and prototype pollution
5. Report findings using the format in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md`
