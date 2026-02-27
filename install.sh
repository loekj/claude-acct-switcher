#!/usr/bin/env bash
# Claude Account Switcher  - Installer
# Installs vdm to ~/.claude/account-switcher/ and configures your shell.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")" && pwd)"

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Installer${NC}"
echo -e "  ────────────────────────────────────────"
echo ""

# ── Check prerequisites ──

if ! command -v node &>/dev/null; then
  echo -e "${RED}Node.js is required but not installed.${NC}"
  echo "  Install it from https://nodejs.org/ or via: brew install node"
  exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [[ "$NODE_VERSION" -lt 18 ]]; then
  echo -e "${YELLOW}Warning: Node.js v18+ recommended (found v$(node -v))${NC}"
fi

if [[ "$(uname)" != "Darwin" ]]; then
  echo -e "${RED}This tool requires macOS (uses Keychain for credential storage).${NC}"
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo -e "${RED}python3 is required but not installed.${NC}"
  exit 1
fi

echo -e "  ${GREEN}✓${NC} Prerequisites OK (Node $(node -v), macOS, python3)"
echo ""

# ── Install files ──

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/accounts"

cp "$SCRIPT_DIR/dashboard.mjs" "$INSTALL_DIR/dashboard.mjs"
cp "$SCRIPT_DIR/lib.mjs" "$INSTALL_DIR/lib.mjs"
cp "$SCRIPT_DIR/vdm" "$INSTALL_DIR/vdm"
chmod +x "$INSTALL_DIR/vdm"

# Create default config if it doesn't exist
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  cp "$SCRIPT_DIR/config.example.json" "$INSTALL_DIR/config.json"
fi

# Write version marker from git if available
if command -v git &>/dev/null && git -C "$SCRIPT_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
  git -C "$SCRIPT_DIR" rev-parse --short HEAD > "$INSTALL_DIR/.version" 2>/dev/null || true
fi

echo -e "  ${GREEN}✓${NC} Installed to ${CYAN}$INSTALL_DIR${NC}"

# ── Symlink vdm to PATH ──

LINK_DIR=""
if [[ -d "$HOME/.local/bin" ]]; then
  LINK_DIR="$HOME/.local/bin"
elif [[ -d "/usr/local/bin" ]]; then
  LINK_DIR="/usr/local/bin"
else
  mkdir -p "$HOME/.local/bin"
  LINK_DIR="$HOME/.local/bin"
  echo -e "  ${YELLOW}Note:${NC} Add ${DIM}$HOME/.local/bin${NC} to your PATH if not already."
fi

ln -sf "$INSTALL_DIR/vdm" "$LINK_DIR/vdm"
# Clean up legacy csw symlink if present
rm -f "$LINK_DIR/csw"
echo -e "  ${GREEN}✓${NC} Linked ${CYAN}vdm${NC} to ${DIM}$LINK_DIR${NC}"

# ── Configure shell ──

SHELL_RC=""
if [[ -f "$HOME/.zshrc" ]]; then
  SHELL_RC="$HOME/.zshrc"
elif [[ -f "$HOME/.bashrc" ]]; then
  SHELL_RC="$HOME/.bashrc"
elif [[ -f "$HOME/.bash_profile" ]]; then
  SHELL_RC="$HOME/.bash_profile"
fi

SNIPPET_MARKER="# BEGIN claude-account-switcher"

if [[ -n "$SHELL_RC" ]]; then
  if grep -q "$SNIPPET_MARKER" "$SHELL_RC" 2>/dev/null; then
    echo -e "  ${DIM}Shell config already present in $SHELL_RC${NC}"
  else
    echo "" >> "$SHELL_RC"
    cat >> "$SHELL_RC" << 'SHELL_EOF'
# BEGIN claude-account-switcher
if ! lsof -iTCP:3333 -sTCP:LISTEN -t >/dev/null 2>&1; then
  nohup node ~/.claude/account-switcher/dashboard.mjs >/dev/null 2>&1 &
  disown
fi
export ANTHROPIC_BASE_URL=http://localhost:3334
# END claude-account-switcher
SHELL_EOF
    echo -e "  ${GREEN}✓${NC} Added auto-start to ${CYAN}$SHELL_RC${NC}"
  fi
else
  echo -e "  ${YELLOW}Could not detect shell config file.${NC}"
  echo "  Add this to your shell profile manually:"
  echo ""
  echo '    # BEGIN claude-account-switcher'
  echo '    if ! lsof -iTCP:3333 -sTCP:LISTEN -t >/dev/null 2>&1; then'
  echo '      nohup node ~/.claude/account-switcher/dashboard.mjs >/dev/null 2>&1 &'
  echo '      disown'
  echo '    fi'
  echo '    export ANTHROPIC_BASE_URL=http://localhost:3334'
  echo '    # END claude-account-switcher'
fi

echo ""
echo -e "  ${BOLD}${GREEN}Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source $SHELL_RC${NC})"
echo -e "    2. Log in to your first account:  ${DIM}claude login${NC}"
echo -e "    3. Save it:                       ${DIM}vdm add account-1${NC}"
echo -e "    4. Switch accounts or open the dashboard: ${DIM}vdm dashboard${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:3333${NC}"
echo -e "  API Proxy:  ${CYAN}http://localhost:3334${NC}"
echo ""
