# OWASP Security Scanner — GitHub Copilot Adapter

Install the OWASP Security Scanner as a native GitHub Copilot integration using VS Code's instruction files, reusable prompt files, and a custom agent.

## What Gets Installed

| Component | Files | Purpose |
|-----------|-------|---------|
| **Instructions** | 7 files in `.github/instructions/` | Auto-activate security checks when editing relevant files |
| **Prompts** | 10 files in `.github/prompts/` | Reusable scan commands (equivalent to Claude Code's `/scan-*`) |
| **Agent** | 1 file in `.github/agents/` | Dedicated `@owasp-security-scanner` persona |
| **Base instructions** | `.github/copilot-instructions.md` | Always-on scanner awareness |
| **Core rules** | `owasp-scanner` symlink | Full 103-rule set with language-specific patterns |

## Installation

### Quick Start (Copy Mode)

```bash
# From the owasp-scanner directory
./adapters/github-copilot/install.sh /path/to/your-project

# Or from your project directory
/path/to/owasp-scanner/adapters/github-copilot/install.sh .
```

Files are **copied** into your project. To update after pulling new scanner rules, re-run the same command — it overwrites all scanner files cleanly.

### Link Mode (Recommended for Development)

```bash
./adapters/github-copilot/install.sh --link /path/to/your-project
```

Files are **symlinked** individually. Changes to the scanner repo automatically propagate to your project — no re-run needed. Just `git pull` in the scanner repo.

### Uninstall

```bash
./adapters/github-copilot/install.sh --uninstall /path/to/your-project
```

Removes all scanner files, the `owasp-scanner` symlink, and strips the scanner section from `copilot-instructions.md` while preserving any user content.

## Keeping Up to Date

| Mode | How to Update |
|------|---------------|
| **Copy mode** | `cd owasp-scanner && git pull && ./adapters/github-copilot/install.sh /path/to/project` |
| **Link mode** | `cd owasp-scanner && git pull` — done, symlinks auto-propagate |
| **Submodule** | `git submodule update --remote && ./owasp-scanner/adapters/github-copilot/install.sh .` |

Re-running `install.sh` in copy mode is **idempotent**: it overwrites all `owasp-*` files and replaces the scanner section in `copilot-instructions.md` (identified by `<!-- OWASP-SCANNER-START/END -->` markers), preserving any surrounding user content.

## Git Submodule Alternative

For distributed environments (CI/CD, GitHub Codespaces) where symlinks to external paths don't work:

```bash
# Add the scanner as a submodule (one time)
cd your-project
git submodule add https://github.com/OWASP/CheatSheetSeries.git owasp-scanner-upstream

# Create a symlink to the core directory
ln -s owasp-scanner-upstream/owasp-scanner/core owasp-scanner/core

# Install the Copilot adapter
./owasp-scanner-upstream/owasp-scanner/adapters/github-copilot/install.sh .

# Update later
git submodule update --remote
./owasp-scanner-upstream/owasp-scanner/adapters/github-copilot/install.sh .
```

Alternatively, if the OWASP scanner is published as a standalone repo:

```bash
git submodule add https://github.com/OWASP/owasp-security-scanner.git owasp-scanner
./owasp-scanner/adapters/github-copilot/install.sh .
```

## Usage

### Reusable Prompts

After installation, use these prompts from Copilot Chat (accessible via the prompt picker or by referencing the file):

| Prompt | Description |
|--------|-------------|
| `owasp-scan-all` | Full security scan across all 7 domains |
| `owasp-scan-injection` | SQL, OS command, LDAP, XXE, deserialization |
| `owasp-scan-xss` | DOM XSS, framework escapes, CSP, prototype pollution |
| `owasp-scan-config` | Headers, CORS, CSRF, cookies, TLS, Docker, K8s |
| `owasp-scan-auth` | Password hashing, JWT, sessions, authorization, IDOR |
| `owasp-scan-api` | SSRF, mass assignment, file upload, GraphQL, WebSocket |
| `owasp-scan-supply-chain` | Secrets, weak crypto, dependencies, CI/CD |
| `owasp-scan-ai-security` | Prompt injection, LLM output, agent permissions |
| `owasp-quick-scan` | Fast triage: top 23 critical patterns |
| `owasp-pr-review` | Security review of changed files only |

### Custom Agent

Use `@owasp-security-scanner` in Copilot Chat to invoke the dedicated security scanner agent.

### Auto-Active Instructions

Path-specific instructions activate automatically when you edit matching files:
- Editing `*.java` → injection + auth + API checks
- Editing `*.tsx` → XSS checks
- Editing `Dockerfile` → configuration checks
- Editing `package.json` → supply chain checks
- Editing `*agent*.py` → AI security checks

## How It Works

The scanner is organized in two layers:

1. **Core rules** (`owasp-scanner/core/`) — 103 portable rules across 7 domains with language-specific detection patterns, derived from the OWASP Cheat Sheet Series
2. **Copilot adapter** (`.github/`) — instruction files, prompt files, and the agent definition that teach Copilot how to apply those rules

The instruction files embed the top 5-10 most critical patterns per domain inline (for immediate passive scanning), and reference the full rule set in `owasp-scanner/core/` for comprehensive scanning via prompts or the agent.

## Requirements

- VS Code with GitHub Copilot Chat extension
- Custom instructions enabled in Copilot settings (enabled by default)
- The `owasp-scanner/core/` directory must be accessible from your project root (handled automatically by the installer via symlink)
