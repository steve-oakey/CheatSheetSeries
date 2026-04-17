---
allowed-tools:
  - Read
  - Glob
  - Grep
description: "Scan for AI/LLM security vulnerabilities (prompt injection, output validation, agent security, model ops, API key exposure)."
---

## Your Task

Perform an AI security vulnerability scan of the current project.

1. Read the scanner rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/rules.md`
2. Read the scanner prompt from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/prompt.md`
3. Detect the AI framework and load the appropriate patterns file from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/patterns/`
4. Search for prompt injection vectors, missing output validation, excessive agent permissions, insecure API key handling, and missing content filtering
5. Report findings using the format in `${CLAUDE_PLUGIN_ROOT}/../../core/reporting/format.md`
6. For HIGH findings, include a non-destructive proof of concept adapted from the PoC templates in the rules
