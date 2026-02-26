#!/usr/bin/env bash
# Claude Account Switcher  - Uninstaller
# Safely removes csw, the dashboard, shell config, and optionally saved accounts.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

INSTALL_DIR="$HOME/.claude/account-switcher"
SNIPPET_MARKER="# claude-account-switcher"

echo ""
echo -e "${BOLD}  Claude Account Switcher  - Uninstaller${NC}"
echo -e "  ──────────────────────────────────────────"
echo ""

# ── Show what will be removed ──

echo -e "  ${BOLD}This will:${NC}"
echo -e "    1. Stop the running dashboard/proxy"
echo -e "    2. Remove the auto-start block from your shell config"
echo -e "    3. Remove the ${CYAN}ANTHROPIC_BASE_URL${NC} export"
echo -e "    4. Remove the ${CYAN}csw${NC} symlink from PATH"
echo -e "    5. Remove ${CYAN}$INSTALL_DIR${NC}"
echo ""

if [[ -d "$INSTALL_DIR/accounts" ]]; then
  ACCT_COUNT=$(find "$INSTALL_DIR/accounts" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  if [[ "$ACCT_COUNT" -gt 0 ]]; then
    echo -e "  ${YELLOW}Note:${NC} You have ${BOLD}$ACCT_COUNT saved account profile(s)${NC} in $INSTALL_DIR/accounts/"
    echo -e "  ${DIM}(These are cached credentials  - your Keychain entries are not affected.)${NC}"
    echo ""
  fi
fi

read -rp "  Continue? [y/N] " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo -e "  ${DIM}Cancelled.${NC}"
  echo ""
  exit 0
fi

echo ""

# ── 1. Stop running processes ──

stopped=false

# Try csw dashboard stop
if [[ -x "$INSTALL_DIR/csw" ]]; then
  "$INSTALL_DIR/csw" dashboard stop 2>/dev/null && stopped=true || true
fi

# Fallback: kill by port
if [[ "$stopped" != "true" ]]; then
  for port in 3333 3334; do
    pid=$(lsof -iTCP:"$port" -sTCP:LISTEN -t 2>/dev/null | head -1) || true
    if [[ -n "$pid" ]]; then
      kill "$pid" 2>/dev/null && stopped=true || true
    fi
  done
fi

# Fallback: kill by process name
if [[ "$stopped" != "true" ]]; then
  pkill -f "node.*account-switcher.*dashboard" 2>/dev/null || true
fi

echo -e "  ${GREEN}✓${NC} Stopped dashboard/proxy"

# ── 2 & 3. Remove shell config block ──

SHELL_RC=""
for rc in "$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.bash_profile"; do
  if [[ -f "$rc" ]] && grep -q "$SNIPPET_MARKER" "$rc" 2>/dev/null; then
    SHELL_RC="$rc"
    break
  fi
done

if [[ -n "$SHELL_RC" ]]; then
  # Remove the auto-start block (from marker line through the export line)
  # Creates a backup first
  cp "$SHELL_RC" "${SHELL_RC}.csw-backup"

  # Use sed to remove the block:
  #   # claude-account-switcher  - auto-start proxy + set base URL
  #   if ! lsof -iTCP:3333 ...
  #     nohup node ...
  #     disown
  #   fi
  #   export ANTHROPIC_BASE_URL=http://localhost:3334
  sed -i '' '/^# claude-account-switcher/,/^export ANTHROPIC_BASE_URL.*localhost:3334/d' "$SHELL_RC"

  # Clean up any leftover blank lines at the end of the file
  # (only strip trailing blank lines, nothing else)
  while [[ -s "$SHELL_RC" ]] && [[ "$(tail -c 1 "$SHELL_RC" | xxd -p)" == "0a" ]] && [[ -z "$(tail -1 "$SHELL_RC")" ]]; do
    # Check the last two lines  - only strip if the last TWO lines are blank (double newline from our insertion)
    if [[ -z "$(tail -2 "$SHELL_RC" | head -1)" ]]; then
      sed -i '' '$ d' "$SHELL_RC"
    else
      break
    fi
  done

  echo -e "  ${GREEN}✓${NC} Removed auto-start block from ${CYAN}$SHELL_RC${NC}"
  echo -e "    ${DIM}Backup: ${SHELL_RC}.csw-backup${NC}"
else
  echo -e "  ${DIM}No shell config block found (already clean)${NC}"
fi

# ── 4. Remove csw symlink ──

removed_link=false
for link in "$HOME/.local/bin/csw" "/usr/local/bin/csw"; do
  if [[ -L "$link" ]]; then
    target=$(readlink "$link" 2>/dev/null || true)
    if [[ "$target" == *"account-switcher"* ]]; then
      rm -f "$link"
      echo -e "  ${GREEN}✓${NC} Removed symlink ${DIM}$link${NC}"
      removed_link=true
    fi
  fi
done
if [[ "$removed_link" != "true" ]]; then
  echo -e "  ${DIM}No csw symlink found${NC}"
fi

# ── 5. Remove install directory ──

if [[ -d "$INSTALL_DIR" ]]; then
  rm -rf "$INSTALL_DIR"
  echo -e "  ${GREEN}✓${NC} Removed ${CYAN}$INSTALL_DIR${NC}"
else
  echo -e "  ${DIM}$INSTALL_DIR does not exist (already clean)${NC}"
fi

echo ""
echo -e "  ${BOLD}${GREEN}Uninstall complete.${NC}"
echo ""
echo -e "  ${BOLD}To finish:${NC}"
echo -e "    1. Restart your terminal (or run: ${DIM}source ${SHELL_RC:-~/.zshrc}${NC})"
echo -e "    2. Your Keychain credentials are untouched  - Claude Code will"
echo -e "       continue to work normally with whichever account was last active."
echo ""
