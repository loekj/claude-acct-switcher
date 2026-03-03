#!/usr/bin/env bash
# install-hooks.sh — [BETA] Shared hook installer for token usage tracking
# Sourced by install.sh, uninstall.sh, and vdm upgrade.
# Provides: install_beta_hooks(), uninstall_beta_hooks()
#
# Two hooks are installed:
# 1. Claude Code hooks in ~/.claude/settings.json (UserPromptSubmit + Stop)
# 2. Global git prepare-commit-msg hook for token usage trailers

# Detect dashboard port (respect CSW_PORT env var)
_VDM_PORT="${CSW_PORT:-3333}"
_VDM_HOOKS_MARKER="# vdm-token-usage"
_VDM_HOOKS_PATH_MARKER=".vdm-set-hooks-path"

install_beta_hooks() {
  _install_claude_code_hooks
  _install_git_hook
}

uninstall_beta_hooks() {
  _uninstall_claude_code_hooks
  _uninstall_git_hook
}

# ─────────────────────────────────────────────────
# Claude Code hooks (~/.claude/settings.json)
# ─────────────────────────────────────────────────

_install_claude_code_hooks() {
  local settings_dir="$HOME/.claude"
  local settings_file="$settings_dir/settings.json"

  mkdir -p "$settings_dir" 2>/dev/null || true

  if ! python3 -c "
import json, os, sys

settings_file = '$settings_file'
port = '$_VDM_PORT'
start_url = f'http://localhost:{port}/api/session-start'
stop_url = f'http://localhost:{port}/api/session-stop'

# Load existing settings
settings = {}
if os.path.exists(settings_file):
    try:
        with open(settings_file) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        # Corrupt file — backup and start fresh
        backup = settings_file + '.vdm-backup'
        try:
            import shutil
            shutil.copy2(settings_file, backup)
        except:
            pass
        settings = {}

if not isinstance(settings, dict):
    settings = {}

# Ensure hooks structure
if 'hooks' not in settings:
    settings['hooks'] = {}
hooks = settings['hooks']

def ensure_hook(event_name, url):
    if event_name not in hooks:
        hooks[event_name] = []
    event_hooks = hooks[event_name]
    if not isinstance(event_hooks, list):
        event_hooks = []
        hooks[event_name] = event_hooks
    # Check if our hook is already present (by URL marker)
    for entry in event_hooks:
        inner = entry.get('hooks', []) if isinstance(entry, dict) else []
        for h in inner:
            if isinstance(h, dict) and h.get('url', '') == url:
                return  # already installed
    # Add our hook
    event_hooks.append({
        'hooks': [{'type': 'http', 'url': url, 'timeout': 5}]
    })

ensure_hook('UserPromptSubmit', start_url)
ensure_hook('Stop', stop_url)

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
" 2>&1; then
    echo -e "  ${YELLOW:-}Warning: Failed to install Claude Code hooks${NC:-}" >&2
  fi
}

_uninstall_claude_code_hooks() {
  local settings_file="$HOME/.claude/settings.json"
  [[ -f "$settings_file" ]] || return 0

  if ! python3 -c "
import json, os, sys

settings_file = '$settings_file'
port = '$_VDM_PORT'
start_url = f'http://localhost:{port}/api/session-start'
stop_url = f'http://localhost:{port}/api/session-stop'

try:
    with open(settings_file) as f:
        settings = json.load(f)
except:
    sys.exit(0)

if not isinstance(settings, dict) or 'hooks' not in settings:
    sys.exit(0)

hooks = settings['hooks']

def remove_hook(event_name, url):
    if event_name not in hooks:
        return
    event_hooks = hooks[event_name]
    if not isinstance(event_hooks, list):
        return
    filtered = []
    for entry in event_hooks:
        inner = entry.get('hooks', []) if isinstance(entry, dict) else []
        has_ours = any(isinstance(h, dict) and h.get('url', '') == url for h in inner)
        if not has_ours:
            filtered.append(entry)
    hooks[event_name] = filtered
    # Clean up empty arrays
    if not hooks[event_name]:
        del hooks[event_name]

remove_hook('UserPromptSubmit', start_url)
remove_hook('Stop', stop_url)

# Clean up empty hooks dict
if not hooks:
    del settings['hooks']

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)
" 2>&1; then
    echo -e "  ${YELLOW:-}Warning: Failed to uninstall Claude Code hooks${NC:-}" >&2
  fi
}

# ─────────────────────────────────────────────────
# Global git prepare-commit-msg hook
# ─────────────────────────────────────────────────

_install_git_hook() {
  local hooks_dir=""
  local we_set_hooks_path=false

  # Determine hooks directory
  hooks_dir=$(git config --global core.hooksPath 2>/dev/null) || true

  if [[ -z "$hooks_dir" ]]; then
    hooks_dir="$HOME/.config/git/hooks"
    mkdir -p "$hooks_dir" 2>/dev/null || true
    git config --global core.hooksPath "$hooks_dir" 2>/dev/null || true
    # Write marker so uninstall knows we set it
    touch "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" 2>/dev/null || true
    we_set_hooks_path=true
  else
    # Expand ~ in path
    hooks_dir="${hooks_dir/#\~/$HOME}"
    mkdir -p "$hooks_dir" 2>/dev/null || true
  fi

  local hook_file="$hooks_dir/prepare-commit-msg"

  # Check if our hook is already installed
  if [[ -f "$hook_file" ]] && grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    # Already installed — update in place
    return 0
  fi

  # If existing hook without our marker, move aside
  if [[ -f "$hook_file" ]] && ! grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    mv "$hook_file" "${hook_file}.vdm-original" 2>/dev/null || true
  fi

  # Write our hook
  cat > "$hook_file" << 'HOOKEOF'
#!/bin/bash
# vdm-token-usage
# [BETA] Appends token usage trailer to commit messages.
# Part of claude-acct-switcher (https://github.com/loekj/claude-acct-switcher)

# Chain to repo-local hook (core.hooksPath disables .git/hooks/)
LOCAL_HOOK="$(git rev-parse --git-dir 2>/dev/null)/hooks/prepare-commit-msg"
[[ -x "$LOCAL_HOOK" ]] && [[ "$LOCAL_HOOK" != "$0" ]] && { "$LOCAL_HOOK" "$@" || exit $?; }

# Chain to pre-existing global hook we moved aside
[[ -x "${0}.vdm-original" ]] && { "${0}.vdm-original" "$@" || exit $?; }

# Skip merge/squash/amend
[[ "$2" == "merge" || "$2" == "squash" || "$2" == "commit" ]] && exit 0

# Check if commitTokenUsage is enabled (disabled by default; silent fail = skip)
VDM_PORT="${CSW_PORT:-3333}"
SETTINGS=$(curl -s --max-time 2 "http://localhost:${VDM_PORT}/api/settings" 2>/dev/null) || true
if echo "$SETTINGS" | python3 -c "import json,sys; s=json.load(sys.stdin); sys.exit(0 if s.get('commitTokenUsage',False) else 1)" 2>/dev/null; then
  : # enabled, continue
else
  exit 0
fi

# Query proxy for token usage since last commit (2s timeout, silent fail)
REPO=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
LAST_TS=$(( $(git log -1 --format=%ct 2>/dev/null || echo 0) * 1000 ))
USAGE=$(curl -s --max-time 2 "http://localhost:${VDM_PORT}/api/token-usage?repo=${REPO}&since=${LAST_TS}" 2>/dev/null) || exit 0

# Parse JSON and append trailer if tokens > 0
python3 -c "
import json, sys

commit_msg_file = sys.argv[1]
try:
    usage = json.loads(sys.argv[2])
except:
    sys.exit(0)

if not usage:
    sys.exit(0)

# Group by model
models = {}
for e in usage:
    m = e.get('model', 'unknown')
    if m not in models:
        models[m] = {'in': 0, 'out': 0}
    models[m]['in'] += e.get('inputTokens', 0)
    models[m]['out'] += e.get('outputTokens', 0)

total = sum(v['in'] + v['out'] for v in models.values())
if total <= 0:
    sys.exit(0)

def fmt(n):
    return f'{n:,}'

# Shorten model names: claude-sonnet-4-6-20250514 -> sonnet 4.6
def short_model(m):
    import re
    s = re.sub(r'^claude-', '', m)
    s = re.sub(r'-\d{8}$', '', s)
    # Match name-major-minor pattern
    match = re.match(r'^([a-z]+(?:-[a-z]+)*)-(\d+(?:-\d+)*)$', s)
    if match:
        name = match.group(1)
        ver = match.group(2).replace('-', '.')
        return f'{name} {ver}'
    return s

lines = []
for model in sorted(models.keys()):
    v = models[model]
    lines.append(f'{short_model(model)}: {fmt(v[\"in\"])} / {fmt(v[\"out\"])}')
trailer = 'Token-Usage: ' + ', '.join(lines)

with open(commit_msg_file, 'r') as f:
    content = f.read()

# Don't duplicate
if 'Token-Usage:' in content:
    sys.exit(0)

with open(commit_msg_file, 'w') as f:
    f.write(content.rstrip() + '\n\n' + trailer + '\n')
" "$1" "$USAGE" 2>/dev/null || true
HOOKEOF

  chmod +x "$hook_file" 2>/dev/null || true
}

_uninstall_git_hook() {
  local hooks_dir=""
  hooks_dir=$(git config --global core.hooksPath 2>/dev/null) || true

  if [[ -z "$hooks_dir" ]]; then
    hooks_dir="$HOME/.config/git/hooks"
  else
    hooks_dir="${hooks_dir/#\~/$HOME}"
  fi

  local hook_file="$hooks_dir/prepare-commit-msg"

  if [[ -f "$hook_file" ]] && grep -q "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    # Restore original if we moved one aside
    if [[ -f "${hook_file}.vdm-original" ]]; then
      mv "${hook_file}.vdm-original" "$hook_file" 2>/dev/null || true
    else
      rm -f "$hook_file" 2>/dev/null || true
    fi
  fi

  # If we set core.hooksPath and no other hooks remain, unset it
  if [[ -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" ]]; then
    local remaining
    remaining=$(find "$hooks_dir" -maxdepth 1 -type f ! -name "$_VDM_HOOKS_PATH_MARKER" 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$remaining" -eq 0 ]]; then
      git config --global --unset core.hooksPath 2>/dev/null || true
      rm -rf "$hooks_dir" 2>/dev/null || true
    else
      rm -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" 2>/dev/null || true
    fi
  fi
}
