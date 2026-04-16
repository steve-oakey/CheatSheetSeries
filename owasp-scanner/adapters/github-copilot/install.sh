#!/bin/bash
# Install OWASP Scanner Copilot instructions into a target project
# Usage: ./install.sh [target-project-dir]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"

echo "OWASP Security Scanner - GitHub Copilot Installer"
echo "=================================================="

mkdir -p "$TARGET_DIR/.github"

if [ -f "$TARGET_DIR/.github/copilot-instructions.md" ]; then
    echo "WARNING: .github/copilot-instructions.md already exists."
    echo "Appending OWASP scanner instructions..."
    echo "" >> "$TARGET_DIR/.github/copilot-instructions.md"
    cat "$SCRIPT_DIR/.github/copilot-instructions.md" >> "$TARGET_DIR/.github/copilot-instructions.md"
else
    cp "$SCRIPT_DIR/.github/copilot-instructions.md" "$TARGET_DIR/.github/copilot-instructions.md"
fi

echo "Installed to $TARGET_DIR/.github/copilot-instructions.md"
echo ""
echo "Make sure the owasp-scanner/core/ directory is accessible from the project."
echo "You can symlink it: ln -s /path/to/owasp-scanner target-project/owasp-scanner"
