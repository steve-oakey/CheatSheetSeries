#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${1:-.}"
cp "$SCRIPT_DIR/.windsurfrules" "$TARGET_DIR/.windsurfrules"
echo "Installed to $TARGET_DIR/.windsurfrules"
