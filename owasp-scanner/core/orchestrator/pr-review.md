# PR Security Review

Scan only the files changed in the current pull request or branch for security vulnerabilities.

## Workflow

### Step 1: Identify Changed Files

Determine which files have changed:
- Use `git diff --name-only main...HEAD` (or the appropriate base branch)
- Filter to source code, config, and infrastructure files
- Exclude test files, documentation, and non-security-relevant changes

### Step 2: Classify Changes

For each changed file, determine which scanner domains are relevant:
- `*.java` controllers/services: injection, auth, api
- `*.ts`/`*.html` Angular components: xss
- `*Security*.java`/`*Config*.java`: config, auth
- `*.properties`/`*.yml`: config, supply-chain
- `Dockerfile`/`docker-compose.yml`: config
- `*.yaml` (K8s): config
- `pom.xml`/`package.json`: supply-chain
- CI/CD pipeline files: supply-chain
- AI/LLM integration code (`*AI*.java`, `*Chat*.java`, `*Agent*.java`): ai-security
- Prompt template files (`*.prompt`, `*.md` prompts): ai-security

### Step 3: Targeted Scan

For each changed file:
1. Read the file
2. Apply only the relevant scanner rules (based on classification above)
3. Focus on NEW or MODIFIED lines (not pre-existing issues unless they interact with the change)
4. Check if the change introduces new attack surface

### Step 4: Report

Output a PR-focused security report:

```
## PR Security Review

**Branch**: [branch name]
**Files changed**: N
**Security-relevant files**: N

### New Findings in This PR

[List findings introduced by this PR's changes]

### Pre-existing Issues Affected by Changes

[List pre-existing security issues that interact with modified code]

### Recommendations

[Specific suggestions for the PR author]
```

## Key Principle

This is a targeted review, not a full scan. Only report issues related to the changed code. Recommend a full scan for comprehensive coverage.
