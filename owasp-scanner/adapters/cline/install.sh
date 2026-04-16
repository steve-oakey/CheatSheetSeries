#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"
cp "$SCRIPT_DIR/.clinerules" "$TARGET_DIR/.clinerules"
echo "Installed to $TARGET_DIR/.clinerules"
