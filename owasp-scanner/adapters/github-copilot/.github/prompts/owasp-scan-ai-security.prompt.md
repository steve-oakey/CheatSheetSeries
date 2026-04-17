---
description: "Scan for AI/LLM security issues: prompt injection, output validation, agent permissions"
---

# OWASP AI Security Scan

Scan the current project for security vulnerabilities in AI/LLM-powered applications.

## Instructions

1. **Detect stack**: Identify AI/LLM libraries (OpenAI, Anthropic, LangChain, Spring AI, LlamaIndex, etc.)
2. **Load rules**: Read `owasp-scanner/core/scanners/ai-security/rules.md` for the full 13-rule set
3. **Load patterns**: Read the matching pattern file from `owasp-scanner/core/scanners/ai-security/patterns/`:
   - `java-spring.md` for Spring AI
   - `nodejs-express.md` for OpenAI Node SDK, LangChain JS
   - `python.md` for OpenAI Python, LangChain, LlamaIndex
   - `generic.md` for other frameworks
4. **Scan**: Check all AI integration code, prompt templates, agent definitions, and LLM endpoint handlers
5. **Report**: Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md`

## Key Vulnerabilities Covered

- RULE-AIS-001: Prompt injection via string concatenation
- RULE-AIS-002: System prompt exposure
- RULE-AIS-003: Missing LLM output validation
- RULE-AIS-004: Excessive LLM permissions / tool access
- RULE-AIS-005: Sensitive data in LLM context
- RULE-AIS-006: Insecure LLM API key management
- RULE-AIS-007: Missing rate limiting on LLM endpoints
- RULE-AIS-008: Indirect prompt injection via external data
- RULE-AIS-009: LLM output rendered as HTML/Markdown without sanitization
- RULE-AIS-010 through AIS-013: Missing logging, model poisoning, function calling abuse

Present findings sorted by severity. Format every finding **exactly** as specified in `owasp-scanner/core/reporting/format.md` — copy the finding template verbatim and only replace `{{...}}` placeholders. Follow the DO/DO NOT format rules in that file.
Include the Proof of Concept section only for CRITICAL and HIGH findings; omit it entirely for MEDIUM, LOW, and INFO. Adapt PoCs from the templates in the rules.
