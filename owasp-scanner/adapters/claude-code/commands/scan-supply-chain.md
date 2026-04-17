---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for supply chain risks (hardcoded secrets, vulnerable dependencies, weak crypto, CI/CD issues)."
---

## Your Task

Perform a supply chain security scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/prompt.md`
3. Load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/patterns/`
4. Search ALL source files for hardcoded secrets, weak crypto, missing dependency scanning, CI/CD issues
5. Format every finding **exactly** as specified in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
6. Err on the side of reporting for secrets -- false positives are preferable to misses
7. Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
