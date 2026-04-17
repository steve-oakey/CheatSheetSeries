# Supply Chain Patterns: Python (Django / Flask / FastAPI)

## Dependency Management

### Dangerous: Unpinned or loosely pinned dependencies
```
install_requires=\[.*>=                  # setup.py with minimum version only
install_requires=\[.*[^=]==[^=]         # Review pinning
\w+>=\d+\.\d+(?!,)                      # Lower bound only (no upper bound)
```

### requirements.txt analysis
```
# DANGEROUS: Unpinned
^[a-zA-Z][\w-]+$                        # Package with no version pin
\w+>=\d+                                # Minimum version only
\w+~=                                   # Compatible release (may drift)

# SAFE: Pinned
\w+==\d+\.\d+\.\d+                      # Exact version pin (good)
--hash=sha256:                           # Hash verification (good)
```

### Pipfile analysis
```
# DANGEROUS:
"\*"                                     # Wildcard version in Pipfile
">=.*"(?!.*<)                            # Lower bound without upper

# SAFE:
"==\d+\.\d+\.\d+"                       # Exact version (good)
```

### pyproject.toml analysis
```
# DANGEROUS:
dependencies\s*=\s*\[.*"[a-z][\w-]+"    # Unversioned dependency
dependencies.*>=.*(?!.*<)                # Lower bound without upper

# SAFE:
dependencies.*==\d+\.\d+\.\d+           # Exact pin (good)
```

## Lock File Integrity

### Verify lock file presence
```
# Files that should exist:
Pipfile\.lock                            # Pipenv lock file (good)
poetry\.lock                             # Poetry lock file (good)
requirements\.txt.*--hash=               # Hashed requirements (good)
```

Absence of a lock file (`Pipfile.lock`, `poetry.lock`, or `pip-compile` output) is a finding.

## Dependency Confusion / Typosquatting

### Dangerous: Private index configuration
```
--index-url\s+https://pypi\.org          # Public index as primary
--extra-index-url                        # Extra index (confusion risk)
pip install.*-i\s+http://                # Non-HTTPS package index
```

### Safe: Private index configuration
```
--index-url\s+https://.*\.internal       # Private index as primary (good)
--extra-index-url.*--index-url.*internal # Private primary + extra (review order)
keyring.*artifacts-keyring               # Azure Artifacts auth (good)
```

## Dangerous Packages

### Known dangerous or deprecated packages
```
import pycrypto\b|from pycrypto         # PyCrypto — abandoned, use pycryptodome
import crypto\b(?!.*graphy)             # May be pycrypto
import telnetlib|from telnetlib         # Telnet (insecure protocol)
import ftplib|from ftplib               # FTP (insecure protocol)
import cgi\b|from cgi                   # Deprecated in Python 3.11+
import imp\b|from imp                   # Deprecated, use importlib
import formatter\b                       # Deprecated in Python 3.4+
```

### Safe: Modern replacements
```
from cryptography|import cryptography    # Modern crypto library (good)
import pycryptodome|from Crypto          # PyCryptodome replacement (good)
import paramiko|from paramiko            # SSH instead of telnet (good)
```

## Build Pipeline Security

### Dangerous: Insecure install practices
```
pip install(?!.*--require-hashes)        # Install without hash verification
pip install.*--trusted-host              # Trusting non-HTTPS host
pip install.*--no-verify                 # Skipping verification
setup\.py.*download_url                  # Download URL in setup.py (review)
curl.*\|\s*pip install|wget.*\|\s*pip    # Piping download to pip
```

### Safe: Secure install practices
```
pip install.*--require-hashes            # Hash verification required (good)
pip-audit|safety check|pip install safety # Vulnerability scanning (good)
pip install.*-c\s+constraints\.txt       # Constraints file (good)
```

## Vendored / Bundled Dependencies

### Dangerous: Vendored code
```
vendor/|vendored/|third_party/|_vendor/  # Vendored directory (review updates)
# Copied from|# Source:|# Originally from # Copied code attribution
```

Vendored dependencies should be flagged for manual review — they may miss security patches.

## Import Safety

### Dangerous: Dynamic imports with user input
```
__import__\(.*request\.|importlib\.import_module\(.*request\. # Dynamic import with user input
exec\(.*import|eval\(.*import           # Import via exec/eval
```

### Safe: Static imports
```
from \w+ import \w+                     # Static import (good)
import \w+                              # Static import (good)
importlib\.import_module\(["']          # Hardcoded module import (good)
```

## Docker/Container Security for Python

### Dangerous: Insecure Dockerfile patterns
```
FROM python:\d+$|FROM python:latest     # Untagged or latest base image
USER root|RUN.*pip install.*--user=root  # Running as root
COPY.*requirements.*&&.*pip install(?!.*--no-cache-dir) # No cache cleanup
RUN pip install(?!.*--no-cache-dir)      # pip cache left in image
```

### Safe: Secure Dockerfile patterns
```
FROM python:\d+\.\d+-slim|FROM python:\d+\.\d+-alpine # Slim/alpine base (good)
USER \w+(?!root)                         # Non-root user (good)
--no-cache-dir                           # No pip cache (good)
COPY.*requirements.*\.txt.*\.            # Copy requirements first (layer caching, good)
```

## CI/CD Integration

### Dangerous: CI/CD misconfigurations
```
pip install\b(?!.*-r\s+requirements)     # Ad-hoc pip install in CI
\$\{\{.*secrets\..*\}\}.*echo            # Echoing secrets in CI
continue-on-error:\s*true.*safety        # Ignoring security check failures
```

### Safe: CI/CD security
```
pip-audit|safety check                   # Dependency audit in CI (good)
bandit\s+-r|bandit.*\.py                 # Bandit static analysis (good)
semgrep.*--config=p/python               # Semgrep scanning (good)
```
