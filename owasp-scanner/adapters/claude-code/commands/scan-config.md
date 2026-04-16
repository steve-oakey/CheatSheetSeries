---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for security misconfigurations (HTTP headers, CORS, CSRF, cookies, TLS, Docker, Kubernetes)."
---

## Your Task

Perform a configuration security scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/prompt.md`
3. Load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/patterns/`
4. Search configuration files for security misconfigurations
5. Report findings using the format in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md`
