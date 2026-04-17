# Supply Chain Patterns: Node.js / Express

## Dependency Management

### Dangerous: Loose version pinning in package.json
```
"\^"|"~"|"\*"|"latest"|">="|">"|"x"     # Non-exact version ranges
"\w+": "\^0\.\d+\.\d+"                  # Caret range on 0.x (breaking changes)
"\w+": "\*"                              # Wildcard version
"\w+": "latest"                          # Latest tag
```

### Safe: Strict version pinning
```
"\w+": "\d+\.\d+\.\d+"                  # Exact version pin (good)
```

### Review: Lock file integrity
```
# Files that MUST exist:
package-lock\.json                       # npm lock file
yarn\.lock                               # Yarn lock file
pnpm-lock\.yaml                          # pnpm lock file
```

Absence of a lock file is a critical finding.

## npm Audit

### CI/CD npm audit integration
```
npm audit(?!.*--audit-level)             # npm audit without severity filter (review)
npm audit.*--audit-level=moderate        # Moderate+ audit (good)
npm audit.*--audit-level=high            # High+ audit (good)
npm audit fix.*--force                   # Force fix (may break, review)
```

### Safe: Automated auditing
```
npm audit|yarn audit|pnpm audit          # Dependency audit (good)
snyk test|snyk monitor                   # Snyk scanning (good)
npm audit --production                   # Production-only audit (good)
```

## Dangerous Packages / Known Vulnerable

### Dangerous: Known vulnerable or deprecated packages
```
require\(["']event-stream["']\)          # Supply chain attack target
require\(["']flatmap-stream["']\)        # Malicious package
require\(["']ua-parser-js["']\).*0\.7    # CVE-2021-27292 (review version)
require\(["']node-serialize["']\)        # Unsafe deserialization (RCE)
require\(["']serialize-javascript["']\)  # Review usage with eval
require\(["']merge["']\)                 # Prototype pollution vulnerable
require\(["']lodash["']\).*(?=.*4\.[0-9]\.|4\.1[0-6]) # Old lodash (CVEs)
```

### Deprecated packages (use alternatives)
```
require\(["']request["']\)               # Deprecated — use axios, got, node-fetch
require\(["']csurf["']\)                 # Deprecated — use csrf-csrf
require\(["']uuid["']\).*v[123]\(        # Old UUID versions
require\(["']mkdirp["']\)               # Use fs.mkdirSync({recursive:true})
require\(["']rimraf["']\)               # Use fs.rmSync({recursive:true}) in Node 14+
```

## Dependency Confusion

### Dangerous: Private registry misconfigurations
```
registry=https://registry\.npmjs\.org    # Public registry as only source
--registry=http://                       # Non-HTTPS registry
```

### Safe: Private registry
```
registry=https://.*\.internal            # Private registry (good)
\.npmrc.*@scope:registry=                # Scoped registry (good)
publishConfig.*registry.*internal        # Publish to private registry (good)
```

## Script Security in package.json

### Dangerous: Insecure scripts
```
"preinstall":\s*".*curl|"preinstall":\s*".*wget # Network call in preinstall
"postinstall":\s*".*\$\(|"postinstall":\s*".*eval # Command substitution in postinstall
"scripts":\s*\{.*".*rm\s+-rf\s+/"       # Dangerous rm in scripts
ignore-scripts.*false                    # Scripts not ignored
```

### Safe: Script security
```
--ignore-scripts                         # Ignore install scripts (good)
npm_config_ignore_scripts=true           # Ignore scripts config (good)
```

## Lock File Manipulation

### Dangerous: Lock file tampering indicators
```
integrity.*sha1:                         # SHA-1 integrity (weak, should be SHA-512)
resolved.*http://                        # Non-HTTPS resolved URL
resolved.*github\.com.*\.tar\.gz         # GitHub tarball (no integrity guarantee)
```

### Safe: Lock file integrity
```
integrity.*sha512:                       # SHA-512 integrity hash (good)
resolved.*https://registry\.npmjs\.org   # Official registry (good)
```

## Vendored / Bundled Dependencies

### Dangerous: Vendored code
```
vendor/|vendored/|third_party/           # Vendored directory (review updates)
bundledDependencies|bundleDependencies   # Bundled deps (review freshness)
```

## Docker/Container Security for Node.js

### Dangerous: Insecure Dockerfile patterns
```
FROM node:\d+$|FROM node:latest          # Untagged or latest base image
USER root                                # Running as root
RUN npm install(?!.*--production|.*--omit=dev) # Dev deps in production image
COPY.*\.env|ADD.*\.env                   # Copying env file into image
npm install.*-g(?!.*npm)                 # Global install in container
```

### Safe: Secure Dockerfile patterns
```
FROM node:\d+\.\d+-slim|FROM node:\d+\.\d+-alpine # Slim/alpine base (good)
USER node                                # Non-root user (good)
RUN npm ci --production|RUN npm ci --omit=dev # Production-only install (good)
COPY.*package\*\.json.*\.               # Copy manifests first (layer caching, good)
\.dockerignore.*node_modules             # Ignore node_modules (good)
```

## Build Pipeline Security

### Dangerous: Insecure CI/CD practices
```
npm install\b(?!.*ci\b)                  # npm install instead of npm ci in CI
\$\{\{.*secrets\..*\}\}.*echo            # Echoing secrets in CI
continue-on-error:\s*true.*audit         # Ignoring audit failures
--no-verify|--no-audit                   # Skipping verification
```

### Safe: Secure CI/CD
```
npm ci\b                                 # Deterministic install (good)
npm audit.*--audit-level                 # Audit with severity level (good)
npx lockfile-lint                        # Lock file linting (good)
socket\.dev|socket security              # Socket.dev scanning (good)
```

## Dynamic require / import

### Dangerous: Dynamic imports with user input
```
require\(.*req\.|require\(.*user_input   # Dynamic require with user input
import\(.*req\.|import\(.*user_input     # Dynamic import with user input
require\(.*\$\{|require\(.*\+            # Dynamic require with interpolation
```

### Safe: Static imports
```
require\(["']\w+                         # Static require (good)
import \w+ from ["']                     # Static import (good)
```

## .npmrc Security

### Dangerous: Insecure .npmrc
```
//registry.*:_authToken=\w+              # Auth token in .npmrc (should be env var)
strict-ssl=false                         # SSL verification disabled
```

### Safe: Secure .npmrc
```
//registry.*:_authToken=\$\{             # Token from environment variable (good)
strict-ssl=true                          # SSL verification enabled (good)
audit=true                               # Audit enabled (good)
```
