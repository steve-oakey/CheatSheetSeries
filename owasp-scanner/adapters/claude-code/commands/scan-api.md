---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for API security issues (SSRF, mass assignment, file upload, GraphQL, WebSocket, rate limiting)."
---

## Your Task

Perform an API security scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/prompt.md`
3. Load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/patterns/`
4. Search for SSRF, mass assignment, file upload issues, unvalidated redirects, GraphQL/WebSocket misconfigurations
5. Format every finding **exactly** as specified in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
6. Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
