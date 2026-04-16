---
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
  - Agent
description: "Run a comprehensive OWASP security scan against the current project using all 6 scanner domains in parallel."
---

## Your Task

Perform a full OWASP security scan of the current project.

1. Read the orchestrator instructions from `${CLAUDE_PLUGIN_ROOT}/../../core/orchestrator/full-scan.md`
2. Follow the workflow: detect stack, dispatch scanners, generate report
3. Dispatch up to 6 scanner sub-agents in parallel (injection, xss, config, auth, api, supply-chain)
4. Each sub-agent should read its `rules.md` and appropriate `patterns/*.md` from the core scanners directory
5. Compile all findings into a unified report using `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/report-template.md`

The user may provide optional arguments:
- `--focus <domain>` to run only one scanner
- `--path <dir>` to scan a specific subdirectory
- `--severity <level>` to filter output

Core scanner files are at: `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/`
Reference cheatsheets are at: `${CLAUDE_PLUGIN_ROOT}/../../core/reference/cheatsheets/`
