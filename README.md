# Van Damme-o-Matic

![Van Damme Splits](https://64.media.tumblr.com/tumblr_m3o0n4yKbu1qi66kho2_400.gifv)

---

## Why This Exists / Who Is This For

You don't sleep. Your Claude Code sessions run 24/7 via `--remote-control`. You're on the move, your machine is doing roundhouse kicks through code while you're grabbing coffee, and then — **BAM** — rate limited. Session dead. Work stopped.

What does Anthropic want you to do? Log in again. Through their slow, annoying UI. Click click click wait click. Meanwhile your autonomous agent is sitting there like a chump, doing nothing.

**No. Absolutely not.**

Jean-Claude's on automatic mode from now on.

Van Damme-o-Matic does the splits across multiple accounts so you never have to. It auto-switches on rate limits, auto-refreshes expiring tokens, and keeps your sessions alive while you're nowhere near a keyboard. NEVER EVER get bogged down because you need to log in to a new account through Anthropic's slow annoying UI again.

- **`--remote-control` power users** — your machine works while you don't
- **People running multiple Claude Code sessions** — spread the load, never hit a wall
- **Anyone who refuses to babysit token expiry** — tokens refresh themselves, accounts rotate automatically
- **Night owls, insomniacs, and the simply relentless** — your AI doesn't sleep and neither should your account management

---

## What It Does

- **Transparent API proxy** — sits between Claude Code and Anthropic's API, swapping auth tokens invisibly
- **Auto-switch on 429** — when one account hits its rate limit, the proxy retries with the next available account
- **Auto-switch on 401** — attempts token refresh first, falls back to switching accounts
- **OAuth token auto-refresh** — background timer refreshes tokens before they expire, no manual re-login ever
- **Proactive switching** — before each request, picks the least-utilized account
- **5 rotation strategies** — sticky, conserve, round-robin, spread, drain-first
- **Web dashboard** — see all accounts, rate limits, usage stats, and activity log at `http://localhost:3333`
- **CLI tool (`vdm`)** — add, list, switch, and remove accounts from the terminal
- **Auto-discover** — log in with `claude login` and accounts are detected automatically
- **macOS Keychain** — credentials are stored securely in the system keychain, never in plaintext
- **Zero dependencies** — pure Node.js + bash. No npm install needed.

## Requirements

- **macOS** (uses Keychain for credential storage)
- **Node.js 18+**
- **python3** (for JSON parsing in the CLI)
- **Claude Code** installed (`claude` CLI)

## Quick Install

```bash
git clone https://github.com/loekj/claude-acct-switcher.git
cd claude-acct-switcher
./install.sh
```

The installer:
1. Copies files to `~/.claude/account-switcher/`
2. Symlinks `vdm` to your PATH
3. Adds auto-start + `ANTHROPIC_BASE_URL` to your shell config
4. Creates default `config.json`

Then restart your terminal.

## Manual Install

If you prefer to set things up yourself:

```bash
# 1. Copy files
mkdir -p ~/.claude/account-switcher
cp dashboard.mjs lib.mjs vdm ~/.claude/account-switcher/
cp config.example.json ~/.claude/account-switcher/config.json
chmod +x ~/.claude/account-switcher/vdm

# 2. Add to your shell profile (~/.zshrc, ~/.bashrc, etc.)
cat >> ~/.zshrc << 'EOF'

# van-damme-o-matic — auto-start proxy + set base URL
if ! lsof -iTCP:3333 -sTCP:LISTEN -t >/dev/null 2>&1; then
  nohup node ~/.claude/account-switcher/dashboard.mjs >/dev/null 2>&1 &
  disown
fi
export ANTHROPIC_BASE_URL=http://localhost:3334
EOF

# 3. Optional: symlink vdm to PATH
ln -sf ~/.claude/account-switcher/vdm ~/.local/bin/vdm

# 4. Restart your terminal
```

## Usage

### Adding Accounts

```bash
# Log in to account A
claude login
vdm add work

# Log in to account B
claude login
vdm add personal

# Label them (optional — auto-detected from Anthropic API)
vdm label work alice@company.com
vdm label personal bob@gmail.com
```

### CLI Commands

```
vdm add <name>              Save current login as a named profile
vdm label <name> <label>    Add a label (email/description) to a profile
vdm list                    List all saved profiles
vdm switch [name]           Switch to a profile (interactive if no name)
vdm remove <name>           Delete a saved profile
vdm status                  Show current account details + settings
vdm config [key] [on|off]   View or toggle settings (proxy, autoswitch)
vdm dashboard [start|stop]  Launch/stop the web dashboard
vdm help                    Show help
```

### Dashboard

Open `http://localhost:3333` in your browser, or:

```bash
vdm dashboard
```

The dashboard shows:
- All accounts with plan type, token health, and rate limit utilization
- Live rate limit bars (5-hour and weekly windows)
- Activity log (auto-switches, rate limits, discoveries)
- Aggregate usage stats (sessions, messages, tokens)

### Settings

Toggle from the CLI, dashboard header, or edit `~/.claude/account-switcher/config.json`:

```bash
vdm config                    # Show current settings
vdm config proxy off          # Disable token-swapping proxy (passthrough)
vdm config proxy on           # Re-enable proxy
vdm config autoswitch off     # Stop auto-switching on 429/401
vdm config autoswitch on      # Re-enable auto-switch
vdm config rotation sticky    # Stay on current account (default)
vdm config rotation conserve  # Max out active accounts first
vdm config rotation round-robin  # Rotate on a timer
vdm config rotation spread    # Always pick lowest utilization
vdm config rotation drain-first  # Use highest 5hr account first
vdm config interval 60        # Set rotation timer to 60 minutes
```

| Setting | Default | Description |
|---------|---------|-------------|
| `proxyEnabled` | `true` | When OFF, proxy passes requests through without swapping tokens |
| `autoSwitch` | `true` | When OFF, 429/401 responses are returned as-is (no auto-retry) |
| `rotationStrategy` | `sticky` | How the proxy picks accounts proactively (see below) |
| `rotationIntervalMin` | `60` | Timer interval in minutes (only used by `round-robin`) |

### Rotation Strategies

All strategies still auto-switch on 429/401 when `autoSwitch` is enabled. The rotation strategy controls **proactive** account selection before each request.

| Strategy | Behavior |
|----------|----------|
| **Sticky** (default) | Stay on current account. Only switches when rate-limited. Safest option. |
| **Conserve** | Drain active accounts first (weekly limit is primary, 5hr is tiebreaker). Untouched accounts stay dormant — their windows never start. Maximizes total runway. |
| **Round-robin** | Rotate to the least-utilized account every N minutes (configurable). |
| **Spread** | Always pick the least-utilized account on every request. Switches often. |
| **Drain first** | Use the account with the highest 5hr utilization. Good for short sessions. |

You can change the strategy from the dashboard header or the CLI.

## How It Works

```
Claude Code  ──ANTHROPIC_BASE_URL──>  Local Proxy (:3334)  ──>  api.anthropic.com
                                          |
                                          |-- Picks account per rotation strategy
                                          |-- Swaps Authorization header
                                          |-- Adds oauth-2025-04-20 beta header
                                          |-- On 429 --> retries with next account
                                          |-- On 401 --> refreshes token, then retries/switches
                                          |-- Background token refresh (every 5 min)
                                          '-- Tracks rate limits from response headers
```

The proxy runs alongside a dashboard server on port 3333. Both start automatically when you open a new terminal.

Credentials live in the macOS Keychain under the service `Claude Code-credentials`. The proxy reads the active token, replaces the auth header, and forwards to Anthropic. When it gets a 429, it writes the next account's credentials to the Keychain and retries — Claude Code picks up the change seamlessly.

### Token Refresh

Refresh tokens are single-use. After a refresh, the old token is dead. Van Damme-o-Matic handles this with:

- **Atomic file writes** — tmp file, chmod 600, rename over original
- **Per-account locks** — no two refreshes for the same account run concurrently
- **Fingerprint migration** — all state (utilization, history, caches) transfers to the new token
- **Retry with backoff** — 3 attempts at 1s, 2s, 4s for transient failures
- **Reactive + proactive** — background timer catches tokens before expiry, 401 handler catches the rest

## Ports

| Port | Service | Env Override |
|------|---------|-------------|
| 3333 | Web Dashboard | `CSW_PORT` |
| 3334 | API Proxy | `CSW_PROXY_PORT` |

## File Structure

```
~/.claude/account-switcher/
  dashboard.mjs         # Dashboard + API proxy server
  lib.mjs               # Pure/testable functions
  vdm                   # CLI tool
  config.json           # Settings (auto-switch, proxy on/off)
  activity-log.json     # Persistent activity log
  accounts/
    account-1.json      # Saved credential profiles
    account-1.label     # Human-readable label (email)
    account-2.json
    account-2.label
```

## Testing

Zero-dependency tests using Node.js built-in `node:test` (Node 18+):

```bash
# Run all tests
node --test 'test/*.test.mjs'

# Unit tests only (pure logic — fast, no servers)
node --test test/lib.test.mjs

# Integration tests only (starts real server, tests HTTP API)
node --test test/api.test.mjs
```

## Uninstall

Run the uninstaller — it confirms before deleting anything:

```bash
# From the repo directory:
./uninstall.sh
```

The uninstaller will:
1. Stop the running dashboard/proxy
2. Remove the auto-start block from your shell config (creates a backup first)
3. Remove the `ANTHROPIC_BASE_URL` export
4. Remove the `vdm` symlink from PATH
5. Remove `~/.claude/account-switcher/` (including saved account profiles)

Your **Keychain credentials are not touched** — Claude Code will continue to work normally with whichever account was last active.

<details>
<summary>Manual uninstall (if you prefer)</summary>

```bash
# Stop the proxy
vdm dashboard stop

# Remove install directory
rm -rf ~/.claude/account-switcher
rm -f ~/.local/bin/vdm

# Edit your shell config (~/.zshrc, ~/.bashrc, etc.) and delete this block:
#   # van-damme-o-matic — auto-start proxy + set base URL
#   if ! lsof -iTCP:3333 -sTCP:LISTEN -t >/dev/null 2>&1; then
#     nohup node ~/.claude/account-switcher/dashboard.mjs >/dev/null 2>&1 &
#     disown
#   fi
#   export ANTHROPIC_BASE_URL=http://localhost:3334

# Restart your terminal
```
</details>

## Troubleshooting

**"No accounts configured"**
Run `claude login` then `vdm add my-account`.

**Dashboard not loading**
Check if the server is running: `lsof -iTCP:3333`. If not, start it: `node ~/.claude/account-switcher/dashboard.mjs`

**Claude Code not using the proxy**
Verify the env var: `echo $ANTHROPIC_BASE_URL` — should be `http://localhost:3334`. Restart your terminal if it's missing.

**"Rate limits unavailable" on a card**
The account is already rate-limited and can't be probed. Rate limit data will appear once traffic flows through the proxy or the limit resets.

**Token expired**
Tokens auto-refresh now. If it still fails, re-login: `claude login`, then `vdm add <name>` (overwrites the old profile).

## License

[The Unlicense](LICENSE) — public domain. Do whatever you want with it.

---

![Van Damme Kick](https://preview.redd.it/jean-claude-van-damme-and-his-iconic-kick-1980s-v0-2c0w3vmx370e1.jpeg?auto=webp&s=1b457b9e34e736221ae116384b7797c9e29ef868)
