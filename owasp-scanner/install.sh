#!/bin/bash
# OWASP Security Scanner — Unified Installer
#
# Usage:
#   ./install.sh --<adapter> [options] /path/to/project
#   ./install.sh --help
#
# Examples:
#   ./install.sh --github-copilot /path/to/repo
#   ./install.sh --github-copilot --link /path/to/repo
#   ./install.sh --claude-code /path/to/repo
#   ./install.sh --cursor .

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADAPTERS_DIR="$SCRIPT_DIR/adapters"

# --- Discover supported adapters (those with install.sh, excluding generic) ---
get_supported_adapters() {
    local adapters=()
    for installer in "$ADAPTERS_DIR"/*/install.sh; do
        [ -f "$installer" ] || continue
        local name
        name="$(basename "$(dirname "$installer")")"
        [ "$name" = "generic" ] && continue
        adapters+=("$name")
    done
    printf '%s\n' "${adapters[@]}" | sort
}

# --- Help ---
print_help() {
    echo "OWASP Security Scanner — Unified Installer"
    echo ""
    echo "Usage:"
    echo "  ./install.sh --<adapter> [options] /path/to/project"
    echo "  ./install.sh --help"
    echo ""
    echo "Supported adapters:"
    while IFS= read -r adapter; do
        echo "  --${adapter}"
    done < <(get_supported_adapters)
    echo ""
    echo "Examples:"
    echo "  ./install.sh --github-copilot /path/to/repo"
    echo "  ./install.sh --github-copilot --link /path/to/repo"
    echo "  ./install.sh --claude-code ."
    echo ""
    echo "All additional arguments are passed through to the adapter's installer."
    echo ""
    echo "For generic LLM usage (no installer needed), see:"
    echo "  adapters/generic/system-prompt.md"
}

# --- Parse first argument as adapter selection ---
if [ $# -eq 0 ]; then
    print_help
    exit 0
fi

ADAPTER=""
PASSTHROUGH_ARGS=()

for arg in "$@"; do
    if [ -z "$ADAPTER" ]; then
        case "$arg" in
            --help|-h)
                print_help
                exit 0
                ;;
            --*)
                ADAPTER="${arg#--}"
                ;;
            *)
                echo "Error: First argument must be --<adapter> or --help." >&2
                echo "Run './install.sh --help' to see supported adapters." >&2
                exit 1
                ;;
        esac
    else
        PASSTHROUGH_ARGS+=("$arg")
    fi
done

if [ -z "$ADAPTER" ]; then
    print_help
    exit 0
fi

# --- Validate adapter ---
ADAPTER_INSTALL="$ADAPTERS_DIR/$ADAPTER/install.sh"

if [ "$ADAPTER" = "generic" ]; then
    echo "Error: The generic adapter does not have an installer." >&2
    echo "Copy adapters/generic/system-prompt.md into your agent's custom instructions." >&2
    exit 1
fi

if [ ! -f "$ADAPTER_INSTALL" ]; then
    echo "Error: Unknown adapter '$ADAPTER'." >&2
    echo ""
    echo "Supported adapters:"
    while IFS= read -r a; do
        echo "  --${a}"
    done < <(get_supported_adapters)
    exit 1
fi

# --- Delegate to adapter installer ---
exec bash "$ADAPTER_INSTALL" "${PASSTHROUGH_ARGS[@]}"
