#!/bin/bash
# Install the OWASP Security Scanner as a GitHub Copilot integration
#
# Usage:
#   ./install.sh [target-project-dir]          Copy mode (re-run to update)
#   ./install.sh --link [target-project-dir]   Symlink mode (auto-updates)
#   ./install.sh --uninstall [target-project-dir]  Remove all scanner files
#
# Re-running in copy mode is idempotent: overwrites owasp-* files and replaces
# the scanner section in copilot-instructions.md between marker comments.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ADAPTER_GITHUB="$SCRIPT_DIR/.github"

# --- Parse arguments ---
MODE="copy"
TARGET_DIR=""

for arg in "$@"; do
    case "$arg" in
        --link)   MODE="link" ;;
        --uninstall) MODE="uninstall" ;;
        *)        TARGET_DIR="$arg" ;;
    esac
done

TARGET_DIR="${TARGET_DIR:-.}"
TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

echo "OWASP Security Scanner — GitHub Copilot Installer"
echo "=================================================="
echo "Mode:       $MODE"
echo "Scanner:    $SCANNER_ROOT"
echo "Target:     $TARGET_DIR"
echo ""

# --- Helper: install a single file (copy or symlink) ---
install_file() {
    local src="$1"
    local dest="$2"

    # Remove existing file or symlink
    if [ -L "$dest" ] || [ -f "$dest" ]; then
        rm -f "$dest"
    fi

    if [ "$MODE" = "link" ]; then
        ln -s "$src" "$dest"
    else
        cp "$src" "$dest"
    fi
}

# --- Helper: inject/replace scanner section in copilot-instructions.md ---
MARKER_START="<!-- OWASP-SCANNER-START -->"
MARKER_END="<!-- OWASP-SCANNER-END -->"

inject_copilot_instructions() {
    local target_file="$TARGET_DIR/.github/copilot-instructions.md"
    local scanner_content
    scanner_content="$(cat "$ADAPTER_GITHUB/copilot-instructions.md")"

    if [ -f "$target_file" ]; then
        # Check if markers already exist
        if grep -q "$MARKER_START" "$target_file" 2>/dev/null; then
            # Replace existing scanner section between markers
            local tmp_file
            tmp_file="$(mktemp)"
            awk -v start="$MARKER_START" -v end="$MARKER_END" -v content="$scanner_content" '
                $0 ~ start { printing=0; printf "%s\n", content; next }
                $0 ~ end   { printing=1; next }
                printing!=0 { print }
            ' "$target_file" > "$tmp_file"
            mv "$tmp_file" "$target_file"
            echo "  Updated scanner section in copilot-instructions.md"
        else
            # Append scanner section
            printf "\n%s\n" "$scanner_content" >> "$target_file"
            echo "  Appended scanner section to existing copilot-instructions.md"
        fi
    else
        # Create new file
        printf "%s\n" "$scanner_content" > "$target_file"
        echo "  Created copilot-instructions.md"
    fi
}

# --- Helper: strip scanner section from copilot-instructions.md ---
strip_copilot_instructions() {
    local target_file="$TARGET_DIR/.github/copilot-instructions.md"

    if [ -f "$target_file" ] && grep -q "$MARKER_START" "$target_file" 2>/dev/null; then
        local tmp_file
        tmp_file="$(mktemp)"
        awk -v start="$MARKER_START" -v end="$MARKER_END" '
            $0 ~ start { skip=1; next }
            $0 ~ end   { skip=0; next }
            !skip { print }
        ' "$target_file" > "$tmp_file"

        # Check if file is empty (only whitespace) after stripping
        if [ -z "$(tr -d '[:space:]' < "$tmp_file")" ]; then
            rm -f "$target_file" "$tmp_file"
            echo "  Removed copilot-instructions.md (was scanner-only)"
        else
            mv "$tmp_file" "$target_file"
            echo "  Stripped scanner section from copilot-instructions.md"
        fi
    fi
}

# =====================================================================
# UNINSTALL
# =====================================================================
if [ "$MODE" = "uninstall" ]; then
    echo "Uninstalling OWASP Security Scanner..."
    echo ""

    # Remove owasp-* instruction files
    if [ -d "$TARGET_DIR/.github/instructions" ]; then
        find "$TARGET_DIR/.github/instructions" -name "owasp-*" -delete 2>/dev/null || true
        echo "  Removed instruction files"
        rmdir "$TARGET_DIR/.github/instructions" 2>/dev/null || true
    fi

    # Remove owasp-* prompt files
    if [ -d "$TARGET_DIR/.github/prompts" ]; then
        find "$TARGET_DIR/.github/prompts" -name "owasp-*" -delete 2>/dev/null || true
        echo "  Removed prompt files"
        rmdir "$TARGET_DIR/.github/prompts" 2>/dev/null || true
    fi

    # Remove owasp-* agent files
    if [ -d "$TARGET_DIR/.github/agents" ]; then
        find "$TARGET_DIR/.github/agents" -name "owasp-*" -delete 2>/dev/null || true
        echo "  Removed agent files"
        rmdir "$TARGET_DIR/.github/agents" 2>/dev/null || true
    fi

    # Strip scanner section from copilot-instructions.md
    strip_copilot_instructions

    # Remove owasp-scanner symlink
    if [ -L "$TARGET_DIR/owasp-scanner" ]; then
        rm -f "$TARGET_DIR/owasp-scanner"
        echo "  Removed owasp-scanner symlink"
    fi

    echo ""
    echo "Uninstall complete."
    exit 0
fi

# =====================================================================
# INSTALL (copy or link mode)
# =====================================================================
echo "Installing OWASP Security Scanner..."
echo ""

# --- Create directories ---
mkdir -p "$TARGET_DIR/.github/instructions"
mkdir -p "$TARGET_DIR/.github/prompts"
mkdir -p "$TARGET_DIR/.github/agents"

# --- Install instruction files ---
echo "Installing instruction files (.github/instructions/)..."
for src_file in "$ADAPTER_GITHUB"/instructions/owasp-*.instructions.md; do
    [ -f "$src_file" ] || continue
    filename="$(basename "$src_file")"
    install_file "$src_file" "$TARGET_DIR/.github/instructions/$filename"
    echo "  $filename"
done

# --- Install prompt files ---
echo "Installing prompt files (.github/prompts/)..."
for src_file in "$ADAPTER_GITHUB"/prompts/owasp-*.prompt.md; do
    [ -f "$src_file" ] || continue
    filename="$(basename "$src_file")"
    install_file "$src_file" "$TARGET_DIR/.github/prompts/$filename"
    echo "  $filename"
done

# --- Install agent files ---
echo "Installing agent files (.github/agents/)..."
for src_file in "$ADAPTER_GITHUB"/agents/owasp-*.agent.md; do
    [ -f "$src_file" ] || continue
    filename="$(basename "$src_file")"
    install_file "$src_file" "$TARGET_DIR/.github/agents/$filename"
    echo "  $filename"
done

# --- Install/update copilot-instructions.md ---
echo "Configuring copilot-instructions.md..."
inject_copilot_instructions

# --- Create owasp-scanner symlink to core ---
echo "Linking scanner core rules..."
SCANNER_LINK="$TARGET_DIR/owasp-scanner"
if [ -L "$SCANNER_LINK" ] || [ -d "$SCANNER_LINK" ]; then
    rm -rf "$SCANNER_LINK"
fi
ln -s "$SCANNER_ROOT" "$SCANNER_LINK"
echo "  owasp-scanner -> $SCANNER_ROOT"

# --- Verify ---
if [ -f "$SCANNER_ROOT/core/manifest.json" ]; then
    echo ""
    echo "Core scanner files verified."
else
    echo ""
    echo "WARNING: Core scanner files not found at $SCANNER_ROOT/core/"
    echo "Make sure the owasp-scanner directory is intact."
fi

echo ""
echo "======================================================"
echo "Installation complete!"
echo ""
echo "Available prompts (use from Copilot Chat prompt picker):"
echo "  owasp-scan-all           Full 7-domain security scan"
echo "  owasp-scan-injection     SQL, OS cmd, LDAP, XXE, deserialization"
echo "  owasp-scan-xss           XSS, framework escapes, CSP"
echo "  owasp-scan-config        Headers, CORS, CSRF, Docker, K8s"
echo "  owasp-scan-auth          Passwords, JWT, sessions, authorization"
echo "  owasp-scan-api           SSRF, mass assignment, file upload"
echo "  owasp-scan-supply-chain  Secrets, crypto, dependencies, CI/CD"
echo "  owasp-scan-ai-security   Prompt injection, LLM output, agents"
echo "  owasp-quick-scan         Fast triage: top 23 critical patterns"
echo "  owasp-pr-review          Changed files only"
echo ""
echo "Custom agent: @owasp-security-scanner"
echo ""
if [ "$MODE" = "link" ]; then
    echo "Mode: LINKED — changes propagate automatically via symlinks."
    echo "Update: cd $(dirname "$SCANNER_ROOT") && git pull"
else
    echo "Mode: COPIED — re-run this command to update after pulling new rules."
    echo "Update: git pull && $0 $TARGET_DIR"
fi
