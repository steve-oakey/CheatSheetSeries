# OWASP Security Scanner Toolkit

An agent-agnostic security scanning toolkit powered by the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/). Distills 113 OWASP cheatsheets into 103 structured scanning rules across 7 vulnerability domains.

## Architecture

```
owasp-scanner/
  core/           <- Portable scanning intelligence (works with any AI agent)
  adapters/       <- Thin wrappers for specific platforms
```

**Core** contains all scanning rules, patterns, prompts, and orchestrators in plain markdown -- readable by any AI coding agent.

**Adapters** provide platform-specific integration for Claude Code, GitHub Copilot, Cursor, Windsurf, Cline, and generic LLMs.

## Scanner Domains

| Domain | Rules | Focus | Cheatsheets |
|--------|-------|-------|-------------|
| **injection** | 15 | SQL, OS command, LDAP, XXE, deserialization, NoSQL | 11 |
| **xss** | 16 | Reflected/stored/DOM XSS, CSP, prototype pollution | 10 |
| **config** | 18 | HTTP headers, CORS, CSRF, cookies, TLS, Docker, K8s, IaC | 15 |
| **auth** | 16 | Password hashing, JWT, sessions, authorization, IDOR, MFA | 14 |
| **api** | 13 | SSRF, mass assignment, file upload, GraphQL, WebSocket | 17 |
| **supply-chain** | 12 | Secrets, weak crypto, dependencies, CI/CD, containers, SBOM | 8 |
| **ai-security** | 13 | Prompt injection, LLM output validation, agent security, model ops | 3 |
| **Total** | **103** | | **78 primary + 38 supplementary** |

## How to Use

### With Claude Code

```bash
cd owasp-scanner/adapters/claude-code
./install.sh /path/to/your/project
```

Then in Claude Code:
- `/scan-all` -- Full security scan (all 7 domains)
- `/scan-injection` -- Injection vulnerabilities only
- `/scan-xss` -- XSS vulnerabilities only
- `/scan-config` -- Configuration security
- `/scan-auth` -- Authentication & authorization
- `/scan-api` -- API security
- `/scan-supply-chain` -- Supply chain & secrets
- `/scan-ai` -- AI/LLM security

Skills auto-trigger during normal development for real-time security feedback.

### With GitHub Copilot

```bash
cd owasp-scanner/adapters/github-copilot
./install.sh /path/to/your/project
```

Then ask Copilot: "Scan this code for security vulnerabilities using OWASP rules."

### With Cursor

```bash
cd owasp-scanner/adapters/cursor
./install.sh /path/to/your/project
```

### With Windsurf / Cline

```bash
cd owasp-scanner/adapters/windsurf  # or cline
./install.sh /path/to/your/project
```

### With Any Other LLM

Copy the contents of `adapters/generic/system-prompt.md` into your agent's system prompt or custom instructions.

For comprehensive scanning, paste the relevant `core/scanners/*/rules.md` into the conversation.

## Core File Structure

Each scanner domain contains:

```
scanners/<domain>/
  rules.md            # Structured rules (RULE-XXX-NNN format)
  prompt.md            # Scanning instructions for AI agents
  cheatsheet-map.md    # Maps rules to source OWASP cheatsheet sections
  patterns/
    generic.md         # Language-agnostic grep patterns
    java-spring.md     # Java/Spring Boot specific patterns
    angular.md         # Angular specific patterns
```

## Rule Format

Every rule follows this structure:

```markdown
## RULE-INJ-001: SQL Injection via String Concatenation
- **Severity**: CRITICAL
- **CWE**: CWE-89 (SQL Injection)
- **What to find**: [description of the vulnerability pattern]
- **Patterns**: [specific code patterns to search for]
- **Fix**: [remediation with code example]
- **Reference**: [source OWASP cheatsheet]
```

## Finding Format

All findings use the standardized format in `core/reporting/format.md`:
- Rule ID (stable, trackable across scans)
- Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
- CWE identifier
- File path and line number
- Vulnerable code snippet
- Recommended fix with code example
- OWASP cheatsheet reference

## Orchestrators

- `core/orchestrator/full-scan.md` -- Comprehensive scan (all 6 domains)
- `core/orchestrator/quick-scan.md` -- Fast triage (top 20 critical patterns)
- `core/orchestrator/pr-review.md` -- Scan only changed files in a PR

## Language Support

**Language-agnostic** (6 generic pattern files): Works with any language.

**Framework-specific patterns** for:
- Java / Spring Boot (primary backend target)
- Angular (primary frontend target)

Additional language patterns can be added by creating new files in `patterns/` directories.

## Extending

### Adding a new language

Create `patterns/<language>.md` in each scanner domain following the existing format:
- Dangerous sinks (patterns to search for)
- Safe alternatives (patterns that indicate secure code)
- Framework-specific checks

### Adding new rules

1. Add the rule to the appropriate `rules.md` with the next available ID
2. Update `cheatsheet-map.md` to link the rule to its source
3. Add detection patterns to `patterns/*.md` files
4. Update `core/manifest.json` rule count

## Source

Rules are distilled from the [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries), a collection of high-quality security guidance for developers. The full cheatsheets are available in `core/reference/cheatsheets/` for deeper remediation guidance.
