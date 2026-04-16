#!/bin/bash
# Install OWASP Scanner rules for Cursor
# Usage: ./install.sh [target-project-dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"

echo "OWASP Security Scanner - Cursor Installer"
echo "==========================================="

mkdir -p "$TARGET_DIR/.cursor/rules"
cp "$SCRIPT_DIR/rules/security-scan.mdc" "$TARGET_DIR/.cursor/rules/security-scan.mdc"

echo "Installed to $TARGET_DIR/.cursor/rules/security-scan.mdc"
echo "Make sure owasp-scanner/core/ is accessible from the project."
