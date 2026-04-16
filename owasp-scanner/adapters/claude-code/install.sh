#!/bin/bash
# Install the OWASP Security Scanner as a Claude Code plugin
# Usage: ./install.sh [target-project-dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TARGET_DIR="${1:-.}"

echo "OWASP Security Scanner - Claude Code Plugin Installer"
echo "======================================================"
echo "Scanner root: $SCANNER_ROOT"
echo "Target project: $(cd "$TARGET_DIR" && pwd)"
echo ""

# Create .claude directory in target project if needed
mkdir -p "$TARGET_DIR/.claude"

# Symlink the plugin into the project's .claude directory
PLUGIN_LINK="$TARGET_DIR/.claude/owasp-security-scanner"
if [ -L "$PLUGIN_LINK" ] || [ -d "$PLUGIN_LINK" ]; then
    echo "Plugin already installed at $PLUGIN_LINK"
    echo "Removing old installation..."
    rm -rf "$PLUGIN_LINK"
fi

ln -s "$SCRIPT_DIR" "$PLUGIN_LINK"
echo "Installed plugin via symlink: $PLUGIN_LINK -> $SCRIPT_DIR"

# Verify core files are accessible
if [ -f "$SCANNER_ROOT/core/manifest.json" ]; then
    echo "Core scanner files verified."
else
    echo "WARNING: Core scanner files not found at $SCANNER_ROOT/core/"
    echo "Make sure the owasp-scanner directory is intact."
fi

echo ""
echo "Installation complete! Available commands:"
echo "  /scan-all           - Full security scan (all 7 domains)"
echo "  /scan-injection     - Injection vulnerabilities"
echo "  /scan-xss           - Cross-site scripting"
echo "  /scan-config        - Security misconfigurations"
echo "  /scan-auth          - Authentication & authorization"
echo "  /scan-api           - API security"
echo "  /scan-supply-chain  - Supply chain & secrets"
echo "  /scan-ai-security   - AI agent & LLM security"
echo ""
echo "Auto-trigger skills are also active for real-time security feedback."
