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
5. Format every finding **exactly** as specified in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
6. Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
