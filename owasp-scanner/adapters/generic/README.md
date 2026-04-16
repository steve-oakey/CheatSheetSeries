# Generic Adapter

Use `system-prompt.md` with any AI coding agent that accepts custom instructions or system prompts.

## How to Use

1. Copy the contents of `system-prompt.md`
2. Paste into your AI agent's system prompt or custom instructions
3. Ask the agent to "scan this code for security vulnerabilities" or "review this file for OWASP issues"

## Supported Agents

- ChatGPT (custom instructions or system prompt)
- Google Gemini
- Any LLM-based coding assistant

## For Deeper Scanning

The generic prompt provides a summary of the top patterns. For comprehensive scanning with all 82 rules:
1. Copy the relevant `rules.md` from `core/scanners/` into the conversation
2. Or point the agent to the full `core/` directory if it has file access
