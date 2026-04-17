# OWASP Security Scanner Toolkit

An agent-agnostic security scanning toolkit powered by the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/). Distills 113 OWASP cheatsheets into 103 structured scanning rules across 7 vulnerability domains, delivered as plain markdown readable by any AI coding agent.

## Installation

```bash
cd owasp-scanner
./install.sh --<adapter> /path/to/your/project
```

### Supported Adapters

| Adapter | Command | Notes |
|---------|---------|-------|
| **GitHub Copilot** | `./install.sh --github-copilot /path/to/repo` | Instructions, prompts, agent, and copilot-instructions.md |
| **Claude Code** | `./install.sh --claude-code /path/to/repo` | Plugin with slash commands and auto-trigger skills |
| **Cursor** | `./install.sh --cursor /path/to/repo` | Cursor rules file |
| **Windsurf** | `./install.sh --windsurf /path/to/repo` | Windsurf rules file |
| **Cline** | `./install.sh --cline /path/to/repo` | Cline rules file |

Run `./install.sh --help` to see all available options.

Some adapters support extra flags — these are passed through to the adapter's installer. For example, GitHub Copilot supports `--link` (symlink mode) and `--uninstall`:

```bash
./install.sh --github-copilot --link /path/to/repo    # Symlinks, auto-updates on git pull
./install.sh --github-copilot --uninstall /path/to/repo
```

### Generic / Other LLMs

For agents not listed above, copy the contents of `adapters/generic/system-prompt.md` into your agent's system prompt or custom instructions. For deeper scanning, paste the relevant `core/scanners/*/rules.md` into the conversation.

## Architecture

```
owasp-scanner/
  core/           ← Portable scanning intelligence (works with any AI agent)
  adapters/       ← Thin integration wrappers for specific platforms
  install.sh      ← Unified installer (delegates to adapter installers)
```

**Core** contains all scanning rules, patterns, prompts, and orchestrators in plain markdown.

**Adapters** provide platform-specific configuration for Claude Code, GitHub Copilot, Cursor, Windsurf, Cline, and generic LLMs.

## Scanner Domains

| Domain | Rules | Focus |
|--------|-------|-------|
| **injection** | 15 | SQL, OS command, LDAP, XXE, deserialization, NoSQL |
| **xss** | 16 | Reflected/stored/DOM XSS, CSP, prototype pollution |
| **config** | 18 | HTTP headers, CORS, CSRF, cookies, TLS, Docker, K8s, IaC |
| **auth** | 16 | Password hashing, JWT, sessions, authorization, IDOR, MFA |
| **api** | 13 | SSRF, mass assignment, file upload, GraphQL, WebSocket |
| **supply-chain** | 12 | Secrets, weak crypto, dependencies, CI/CD, containers, SBOM |
| **ai-security** | 13 | Prompt injection, LLM output validation, agent security |
| **Total** | **103** | |

## Core Structure

Each scanner domain under `core/scanners/<domain>/` contains:

| File | Purpose |
|------|---------|
| `rules.md` | Structured rules in `RULE-XXX-NNN` format with severity, CWE, patterns, and fixes |
| `prompt.md` | Scanning instructions for AI agents |
| `cheatsheet-map.md` | Maps each rule to its source OWASP cheatsheet section |
| `patterns/*.md` | Language/framework-specific detection patterns |

Orchestrators in `core/orchestrator/` provide full-scan, quick-scan, and PR-review workflows.

## Language Support

**Language-agnostic** patterns work with any language. Framework-specific patterns are included for:

- Java / Spring Boot
- Python / Django / Flask / FastAPI
- Node.js / Express
- Angular

Add support for additional languages by creating new `patterns/<language>.md` files in each scanner domain.

## Source

Rules are distilled from the [OWASP Cheat Sheet Series](https://github.com/OWASP/CheatSheetSeries). The full cheatsheets are available in `core/reference/cheatsheets/` for deeper remediation guidance.
