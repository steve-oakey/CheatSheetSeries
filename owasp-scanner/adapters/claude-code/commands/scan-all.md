---
allowed-tools:
  - Bash
  - Read
  - Glob
  - Grep
  - Agent
description: "Run a comprehensive OWASP security scan against the current project using all 7 scanner domains in parallel."
---

## Your Task

Perform a full OWASP security scan of the current project.

1. Read the orchestrator instructions from `${CLAUDE_PLUGIN_ROOT}/../../core/orchestrator/full-scan.md`
2. Follow the workflow: detect stack, dispatch scanners, generate report
3. Dispatch up to 7 scanner sub-agents in parallel (injection, xss, config, auth, api, supply-chain, ai-security)
4. Each sub-agent should read its `rules.md` and appropriate `patterns/*.md` from the core scanners directory
5. Compile all findings into a unified report using `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/report-template.md` — copy the template structure **exactly** and only replace `{{...}}` placeholders
6. Format every individual finding **exactly** as specified in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md` — copy the finding template verbatim, follow the DO/DO NOT format rules, and only replace `{{...}}` placeholders
7. Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in each scanner's rules

The user may provide optional arguments:
- `--focus <domain>` to run only one scanner
- `--path <dir>` to scan a specific subdirectory
- `--severity <level>` to filter output

Core scanner files are at: `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/`
Reference cheatsheets are at: `${CLAUDE_PLUGIN_ROOT}/../../core/reference/cheatsheets/`
