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
if xcode-select -p &>/dev/null && xcrun --find swiftc &>/dev/null; then
  HAS_CLT=true
  echo -e "  ${GREEN}✓${NC} Command Line Tools found (for the menu bar icon)"
else
  HAS_CLT=false
  echo -e "  ${YELLOW}!${NC} Command Line Tools not found: no menu bar icon. vdm works without it."
  echo -e "    ${DIM}Add it later: xcode-select --install, then vdm menubar on${NC}"
fi
echo ""

# ── Install files ──

mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/accounts"

for f in "$SCRIPT_DIR"/*.mjs; do
  cp "$f" "$INSTALL_DIR/$(basename "$f")"
done
cp "$SCRIPT_DIR/vdm" "$INSTALL_DIR/vdm"
cp "$SCRIPT_DIR/install-hooks.sh" "$INSTALL_DIR/install-hooks.sh"
mkdir -p "$INSTALL_DIR/menubar"
cp "$SCRIPT_DIR"/menubar/*.swift "$INSTALL_DIR/menubar/"
chmod +x "$INSTALL_DIR/vdm"

# Create default config if it doesn't exist
if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
  cp "$SCRIPT_DIR/config.example.json" "$INSTALL_DIR/config.json"
fi

# Write version marker from git if available (prefer semver tag, fall back to hash)
if command -v git &>/dev/null && git -C "$SCRIPT_DIR" rev-parse --git-dir &>/dev/null 2>&1; then
  git -C "$SCRIPT_DIR" fetch --tags --quiet 2>/dev/null || true
  ( git -C "$SCRIPT_DIR" describe --tags --abbrev=0 2>/dev/null \
    || git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null ) > "$INSTALL_DIR/.version" || true
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
# Sets ANTHROPIC_BASE_URL; starts vdm in new terminals only while the daemon is off

SHELL_RC="$("$INSTALL_DIR/vdm" _setup-shell || true)"
if [[ -n "$SHELL_RC" ]]; then
  echo -e "  ${GREEN}✓${NC} Shell set up in ${CYAN}$SHELL_RC${NC}"
else
  echo -e "  ${YELLOW}Could not find a shell config file (.zshrc, .bashrc).${NC} Add this to yours:"
  echo ""
  echo '    export ANTHROPIC_BASE_URL=http://localhost:3334'
  echo ""
fi

# ── Daemon: vdm starts at login and again after a crash (VDM_NO_DAEMON=1 skips it) ──

if [[ "${VDM_NO_DAEMON:-}" != "1" ]]; then
  if "$INSTALL_DIR/vdm" daemon on >/dev/null; then
    echo -e "  ${GREEN}✓${NC} Daemon on: vdm runs in the background ${DIM}(no admin password; macOS may say \"Background item added\")${NC}"
  else
    echo -e "  ${YELLOW}!${NC} The daemon did not start. New terminals start vdm instead. Try: ${DIM}vdm daemon on${NC}"
  fi
fi

# ── Menu bar icon (VDM_NO_MENUBAR=1 skips it) ──

if [[ "$HAS_CLT" == "true" && "${VDM_NO_MENUBAR:-}" != "1" ]]; then
  if "$INSTALL_DIR/vdm" menubar on >/dev/null; then
    echo -e "  ${GREEN}✓${NC} Menu bar icon on"
  else
    echo -e "  ${YELLOW}!${NC} Menu bar icon not built. See ${DIM}$INSTALL_DIR/menubar-build.log${NC}"
  fi
fi

# ── Remove hooks older versions installed (no longer needed) ──

if [[ -f "$INSTALL_DIR/install-hooks.sh" ]]; then
  source "$INSTALL_DIR/install-hooks.sh"
  if has_legacy_hooks; then
    remove_legacy_hooks && echo -e "  ${GREEN}✓${NC} Removed old token-tracking hooks" || true
  else
    remove_legacy_hooks 2>/dev/null || true
  fi
fi

echo ""
echo -e "  ${BOLD}${GREEN}Installation complete!${NC}"
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source ${SHELL_RC:-~/.zshrc}${NC})"
echo -e "    2. Log in to each account:  ${DIM}claude login${NC}  (vdm finds them by itself)"
echo -e "    3. Open the dashboard:      ${DIM}vdm dashboard${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://localhost:3333${NC}"
echo -e "  API Proxy:  ${CYAN}http://localhost:3334${NC}"
echo ""
