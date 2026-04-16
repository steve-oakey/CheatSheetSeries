# AI Security Scanner: Cheatsheet Map

Maps each rule to the specific section of the OWASP cheatsheet it was derived from.
For deeper analysis, load the full cheatsheet from `core/reference/cheatsheets/`.

| Rule ID | Source Cheatsheet | Section |
|---------|-------------------|---------|
| RULE-AIS-001 | LLM_Prompt_Injection_Prevention_Cheat_Sheet.md | Direct Prompt Injection |
| RULE-AIS-002 | LLM_Prompt_Injection_Prevention_Cheat_Sheet.md | System Prompt Protection |
| RULE-AIS-003 | AI_Agent_Security_Cheat_Sheet.md | Output Validation |
| RULE-AIS-004 | AI_Agent_Security_Cheat_Sheet.md | Least Privilege / Tool Access |
| RULE-AIS-005 | AI_Agent_Security_Cheat_Sheet.md | Data Privacy |
| RULE-AIS-006 | Secrets_Management_Cheat_Sheet.md | API Key Management |
| RULE-AIS-007 | AI_Agent_Security_Cheat_Sheet.md | Rate Limiting / Cost Control |
| RULE-AIS-008 | LLM_Prompt_Injection_Prevention_Cheat_Sheet.md | Indirect Prompt Injection |
| RULE-AIS-009 | LLM_Prompt_Injection_Prevention_Cheat_Sheet.md | Markdown/HTML Rendering Injection |
| RULE-AIS-010 | Secure_AI_Model_Ops_Cheat_Sheet.md | Logging and Monitoring |
| RULE-AIS-011 | Secure_AI_Model_Ops_Cheat_Sheet.md | Model Security |
| RULE-AIS-012 | Secure_AI_Model_Ops_Cheat_Sheet.md | Content Safety |
| RULE-AIS-013 | AI_Agent_Security_Cheat_Sheet.md | Agent Action Limits |

## Supplementary Cheatsheets

These cheatsheets provide additional context but are not primary rule sources:
- **Input_Validation_Cheat_Sheet.md** — Input validation principles (referenced by RULE-AIS-003, RULE-AIS-012)
- **Logging_Cheat_Sheet.md** — Logging best practices (referenced by RULE-AIS-010)
- **Cross_Site_Scripting_Prevention_Cheat_Sheet.md** — XSS prevention for rendered LLM output (referenced by RULE-AIS-009)
