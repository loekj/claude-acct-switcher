#!/usr/bin/env bash
# install-hooks.sh — removes the hooks older versions installed (v4 dropped them).
# Sourced by install.sh, uninstall.sh and vdm. Older `vdm upgrade` scripts also source
# this file and call install_beta_hooks, so both entry points only clean up.
#
# Older versions installed exactly two things:
# 1. Claude Code HTTP hooks in ~/.claude/settings.json: UserPromptSubmit → /api/session-start
#    and Stop → /api/session-stop on localhost
# 2. A global git prepare-commit-msg hook (marked "# vdm-token-usage") for commit trailers
#
# Cleanup only ever removes those exact entries. Everything else is left byte-for-byte.

_VDM_HOOKS_MARKER="# vdm-token-usage"
_VDM_HOOKS_PATH_MARKER=".vdm-set-hooks-path"

remove_legacy_hooks() {
  _uninstall_claude_code_hooks
  _uninstall_git_hook
}

# Entry points kept for older scripts
install_beta_hooks() { remove_legacy_hooks; }
uninstall_beta_hooks() { remove_legacy_hooks; }

# True when ~/.claude/settings.json still has our old hooks
has_legacy_hooks() {
  [[ -f "$HOME/.claude/settings.json" ]] && grep -q "/api/session-start\|/api/session-stop" "$HOME/.claude/settings.json" 2>/dev/null
}

# ─────────────────────────────────────────────────
# Claude Code hooks (~/.claude/settings.json)
# ─────────────────────────────────────────────────

_uninstall_claude_code_hooks() {
  local settings_file="$HOME/.claude/settings.json"
  [[ -f "$settings_file" ]] || return 0
  # Cheap pre-check: never parse or rewrite a file that doesn't mention our endpoints
  grep -q "/api/session-start\|/api/session-stop" "$settings_file" 2>/dev/null || return 0

  if ! python3 - "$settings_file" <<'PY'
import copy, json, os, re, shutil, sys, tempfile, time

path = os.path.realpath(sys.argv[1])  # write through a symlink, never replace it

# Exactly what older versions installed: an http hook to localhost /api/session-start|stop
OURS = re.compile(r'^http://(localhost|127\.0\.0\.1):\d+/api/session-(start|stop)$')
EVENTS = ('UserPromptSubmit', 'Stop')

def is_ours(h):
    return isinstance(h, dict) and h.get('type') == 'http' and isinstance(h.get('url'), str) and bool(OURS.match(h['url']))

def without_ours(settings):
    """Copy of settings with only our hook entries removed (and containers we emptied)."""
    out = copy.deepcopy(settings)
    hooks = out.get('hooks')
    if not isinstance(hooks, dict):
        return out, False
    changed = False
    for ev in EVENTS:
        groups = hooks.get(ev)
        if not isinstance(groups, list):
            continue
        kept_groups = []
        ev_changed = False
        for g in groups:
            inner = g.get('hooks') if isinstance(g, dict) else None
            if isinstance(inner, list) and any(is_ours(h) for h in inner):
                changed = ev_changed = True
                kept = [h for h in inner if not is_ours(h)]
                if kept:                      # a group shared with other hooks keeps them
                    g = dict(g)
                    g['hooks'] = kept
                    kept_groups.append(g)
                continue                      # a group that held only our hook goes
            kept_groups.append(g)
        if not ev_changed:
            continue                          # untouched event: leave as is
        if kept_groups:
            hooks[ev] = kept_groups
        else:
            del hooks[ev]                     # we emptied this event list
    if changed and not hooks:
        del out['hooks']                      # we emptied the hooks object
    return out, changed

def indent_of(raw):
    for line in raw.split('\n')[1:]:
        stripped = line.lstrip(' \t')
        if stripped and len(stripped) < len(line):
            ws = line[:len(line) - len(stripped)]
            return '\t' if ws.startswith('\t') else len(ws)
    return 2

for attempt in range(3):
    try:
        with open(path, encoding='utf-8') as f:
            raw = f.read()
        settings = json.loads(raw)
    except Exception:
        sys.exit(0)                           # unreadable / not JSON: leave it alone
    if not isinstance(settings, dict):
        sys.exit(0)
    cleaned, changed = without_ours(settings)
    if not changed:
        sys.exit(0)

    text = json.dumps(cleaned, indent=indent_of(raw), ensure_ascii=False)
    if raw.endswith('\n'):
        text += '\n'

    # Backup of the exact original bytes, next to the file
    backup = f"{path}.vdm-backup-{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(path, backup)

    # Claude Code may have rewritten the file meanwhile: start over if so
    with open(path, encoding='utf-8') as f:
        if f.read() != raw:
            os.remove(backup)
            continue

    mode = os.stat(path).st_mode & 0o7777
    fd, tmp = tempfile.mkstemp(prefix='.settings.', dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try: os.remove(tmp)
        except Exception: pass
        raise

    # Verify: the file now equals the original minus our entries, nothing else
    try:
        with open(path, encoding='utf-8') as f:
            ok = json.load(f) == cleaned
    except Exception:
        ok = False
    if not ok:
        shutil.copy2(backup, path)
        print(f"  Restored {sys.argv[1]} from backup: cleanup could not be verified", file=sys.stderr)
        sys.exit(1)
    print(f"  Removed old vdm hooks from {sys.argv[1]} (backup: {os.path.basename(backup)})")
    sys.exit(0)

print(f"  Skipped {sys.argv[1]}: it kept changing while vdm tried to clean it", file=sys.stderr)
sys.exit(1)
PY
  then
    echo -e "  ${YELLOW:-}Warning: could not remove old vdm hooks from $settings_file (file left as it was)${NC:-}" >&2
  fi
}

# ─────────────────────────────────────────────────
# Global git prepare-commit-msg hook
# ─────────────────────────────────────────────────

_uninstall_git_hook() {
  local hooks_dir=""
  hooks_dir=$(git config --global core.hooksPath 2>/dev/null) || true

  if [[ -z "$hooks_dir" ]]; then
    hooks_dir="$HOME/.config/git/hooks"
  else
    hooks_dir="${hooks_dir/#\~/$HOME}"
  fi

  local hook_file="$hooks_dir/prepare-commit-msg"

  # Only a hook that carries our marker is ours
  if [[ -f "$hook_file" ]] && grep -qF "$_VDM_HOOKS_MARKER" "$hook_file" 2>/dev/null; then
    if [[ -f "${hook_file}.vdm-original" ]]; then
      mv "${hook_file}.vdm-original" "$hook_file" 2>/dev/null || true   # put the user's hook back
    else
      rm -f "$hook_file" 2>/dev/null || true
    fi
  fi

  # We created this hooks folder (and set core.hooksPath to it) only if our marker is there.
  # Undo that only when nothing else lives in it; never delete anything that isn't ours.
  if [[ -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" ]]; then
    local others
    others=$(find "$hooks_dir" -mindepth 1 -maxdepth 1 ! -name "$_VDM_HOOKS_PATH_MARKER" 2>/dev/null | head -1)
    rm -f "$hooks_dir/$_VDM_HOOKS_PATH_MARKER" 2>/dev/null || true
    if [[ -z "$others" ]]; then
      local current
      current=$(git config --global core.hooksPath 2>/dev/null) || true
      if [[ "${current/#\~/$HOME}" == "$hooks_dir" ]]; then
        git config --global --unset core.hooksPath 2>/dev/null || true
      fi
      rmdir "$hooks_dir" 2>/dev/null || true
    fi
  fi
}
