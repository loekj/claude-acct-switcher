#!/usr/bin/env node
// Van Damme-o-Matic  - Dashboard
// Zero dependencies, uses Node.js built-in modules only.

import { createServer } from 'node:http';
import { readdir, readFile, writeFile, mkdir, unlink, chmod, rename } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { existsSync, writeFileSync, mkdirSync, readdirSync, readFileSync, unlinkSync, renameSync } from 'node:fs';
import { Transform } from 'node:stream';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Prevent EIO/EPIPE on stdout/stderr from crashing the process when
// running as a background daemon (terminal closed, pipe broken).
process.stdout?.on?.('error', () => {});
process.stderr?.on?.('error', () => {});

const PORT = parseInt(process.env.CSW_PORT || '3333', 10);
const ACCOUNTS_DIR = join(__dirname, 'accounts');
const STATS_CACHE = join(process.env.HOME, '.claude', 'stats-cache.json');
const CONFIG_FILE = join(__dirname, 'config.json');
const STATE_FILE = join(__dirname, 'account-state.json');
const TOKEN_USAGE_FILE = join(__dirname, 'token-usage.json');
const SESSION_HISTORY_FILE = join(__dirname, 'session-history.json');
const KEYCHAIN_ACCOUNT = process.env.USER || execSync('whoami').toString().trim();

// Detect installed Claude Code version for User-Agent mimicry
function detectClaudeCodeVersion() {
  try {
    const out = execSync('claude --version 2>/dev/null', { encoding: 'utf8', timeout: 3000 }).trim();
    const match = out.match(/^([\d.]+)/);
    if (match) return match[1];
  } catch {}
  // Fallback: read symlink target which contains the version
  try {
    const target = execSync('readlink ~/.local/bin/claude 2>/dev/null || readlink /usr/local/bin/claude 2>/dev/null', { encoding: 'utf8', timeout: 2000 }).trim();
    const match = target.match(/versions\/([\d.]+)/);
    if (match) return match[1];
  } catch {}
  return '2.1.0'; // safe default
}
const CLAUDE_CODE_VERSION = detectClaudeCodeVersion();

// Project version — read from .version file (written by vdm upgrade), fall back to git tag
function detectProjectVersion() {
  const versionFile = join(__dirname, '.version');
  try {
    const v = readFileSync(versionFile, 'utf8').trim();
    if (v) return v;
  } catch {}
  try {
    return execSync('git describe --tags --abbrev=0 2>/dev/null', { encoding: 'utf8', cwd: __dirname, timeout: 3000 }).trim();
  } catch {}
  return 'dev';
}
const PROJECT_VERSION = detectProjectVersion();

// Auto-detect keychain service name for robustness against Claude Code updates.
// Falls back to the known default if detection fails.
function detectKeychainService() {
  try {
    // Search for any keychain entry matching the Claude Code pattern
    const out = execSync(
      `security find-generic-password -a "${KEYCHAIN_ACCOUNT}" -s "Claude Code-credentials" -w 2>/dev/null && echo "Claude Code-credentials"`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    const lines = out.split('\n');
    return lines[lines.length - 1]; // last line is the service name
  } catch {
    // Try a broader search for any "Claude" credential
    try {
      const dump = execSync(
        `security dump-keychain 2>/dev/null | grep -A4 '"svce"' | grep -i claude | head -1`,
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
      ).trim();
      const match = dump.match(/"svce"<blob>="([^"]+)"/);
      if (match) return match[1];
    } catch {}
  }
  return 'Claude Code-credentials'; // fallback
}

const KEYCHAIN_SERVICE = detectKeychainService();

// ─────────────────────────────────────────────────
// Settings (persisted to config.json)
// ─────────────────────────────────────────────────

const DEFAULT_SETTINGS = {
  autoSwitch: true,
  proxyEnabled: true,
  rotationStrategy: 'conserve',
  rotationIntervalMin: 60,
  notifications: true,
  serializeRequests: false,
  serializeDelayMs: 200,
  commitTokenUsage: false,
  sessionMonitor: false,
};

function loadSettings() {
  try {
    if (existsSync(CONFIG_FILE)) {
      return { ...DEFAULT_SETTINGS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch { /* corrupt file  - use defaults */ }
  return { ...DEFAULT_SETTINGS };
}

function saveSettings(settings) {
  writeFileSync(CONFIG_FILE, JSON.stringify(settings, null, 2));
}

let settings = loadSettings();
let lastRotationTime = 0; // tracks when proactive rotation last happened
let _consecutive400s = 0;  // global: consecutive 400 errors across requests (reset on success)
let _consecutive400sAt = 0;  // timestamp of last 400 (for time-based decay)
const _lastWarnPct = new Map(); // acctName → last logged percentage (dedup 90%+ warnings)

// ── Circuit breaker ──
// When the proxy fails repeatedly (all recovery strategies exhausted), it
// auto-disables into passthrough mode so Claude Code can still reach the API
// with its own token / trigger re-auth.  Resets after a cooldown.
let _circuitOpen = false;
let _circuitOpenAt = 0;
let _consecutiveExhausted = 0; // count of requests where ALL recovery strategies failed
const CIRCUIT_COOLDOWN_MS = 2 * 60 * 1000; // 2 minutes
const CIRCUIT_OPEN_THRESHOLD = 3;           // open after N consecutive exhausted requests
const CIRCUIT_400_THRESHOLD = 10;           // open circuit after N consecutive 400s across requests

function _isCircuitOpen() {
  if (!_circuitOpen) return false;
  if (Date.now() - _circuitOpenAt > CIRCUIT_COOLDOWN_MS) {
    _circuitOpen = false;
    _consecutiveExhausted = 0;
    _consecutive400s = 0;
    log('circuit', 'Circuit breaker closed — retrying proxy mode');
    return false;
  }
  return true;
}

function _openCircuit(reason) {
  if (_circuitOpen) return;
  _circuitOpen = true;
  _circuitOpenAt = Date.now();
  log('circuit', `Circuit breaker OPEN (${reason}) — passthrough for ${CIRCUIT_COOLDOWN_MS / 1000}s`);
  notify('Proxy Bypassed', `${reason} — passthrough mode for ${CIRCUIT_COOLDOWN_MS / 60000}min`);
}

// ─────────────────────────────────────────────────
// Keychain helpers
// ─────────────────────────────────────────────────

function readKeychain() {
  try {
    const raw = execSync(
      `security find-generic-password -s "${KEYCHAIN_SERVICE}" -w`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }
    ).trim();
    return JSON.parse(raw);
  } catch (e) {
    log('error', `Keychain read failed: ${e.message}`);
    return null;
  }
}

function writeKeychain(creds) {
  const json = JSON.stringify(creds);
  try {
    execSync(
      `security delete-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}"`,
      { stdio: 'pipe', timeout: 5000 }
    );
  } catch { /* might not exist */ }
  execSync(
    `security add-generic-password -s "${KEYCHAIN_SERVICE}" -a "${KEYCHAIN_ACCOUNT}" -w "${json.replace(/"/g, '\\"')}"`,
    { stdio: 'pipe', timeout: 5000 }
  );
}

import https from 'node:https';
import { execFile } from 'node:child_process';
import http from 'node:http';
import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders as _buildForwardHeaders,
  stripHopByHopHeaders,
  createAccountStateManager,
  isAccountAvailable as _isAccountAvailable,
  scoreAccount as _scoreAccount,
  pickBestAccount as _pickBestAccount,
  pickDrainFirst as _pickDrainFirst,
  pickConserve as _pickConserve,
  pickAnyUntried as _pickAnyUntried,
  getEarliestReset as _getEarliestReset,
  pickByStrategy as _pickByStrategy,
  createProbeTracker,
  createUtilizationHistory,
  buildRefreshRequestBody,
  parseRefreshResponse,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  createPerAccountLock,
  ROTATION_STRATEGIES,
  ROTATION_INTERVALS,
} from './lib.mjs';

// Fetch email from Anthropic roles API using OAuth token
function fetchAccountEmail(token) {
  return new Promise((resolve) => {
    const req = https.get('https://api.anthropic.com/api/oauth/claude_cli/roles', {
      headers: { 'Authorization': `Bearer ${token}` },
      timeout: 3000,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const d = JSON.parse(data);
          const name = d.organization_name || '';
          const match = name.match(/^(.+?)(?:'s Organization| Organization)$/);
          resolve(match ? match[1] : name || '');
        } catch { resolve(''); }
      });
    });
    req.on('error', () => resolve(''));
    req.on('timeout', () => { req.destroy(); resolve(''); });
  });
}

// Cache emails so we don't hit the API on every 5s refresh
const emailCache = new Map(); // fingerprint -> { email, fetchedAt }
const EMAIL_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function getEmailForToken(token, fp) {
  const cached = emailCache.get(fp);
  if (cached && Date.now() - cached.fetchedAt < EMAIL_CACHE_TTL) {
    return cached.email;
  }
  const email = await fetchAccountEmail(token);
  if (email) emailCache.set(fp, { email, fetchedAt: Date.now() });
  return email;
}

// ─────────────────────────────────────────────────
// Auto-discover: detect unknown keychain tokens and
// auto-save them as new accounts.
// ─────────────────────────────────────────────────

const ACTIVITY_LOG_FILE = join(__dirname, 'activity-log.json');
const ACTIVITY_MAX_ENTRIES = 500;
const ACTIVITY_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

// Load persisted activity log on startup (prune stale entries)
let activityLog = [];
try {
  if (existsSync(ACTIVITY_LOG_FILE)) {
    const raw = JSON.parse(readFileSync(ACTIVITY_LOG_FILE, 'utf8'));
    const cutoff = Date.now() - ACTIVITY_MAX_AGE;
    activityLog = raw.filter(e => e.ts >= cutoff).slice(0, ACTIVITY_MAX_ENTRIES);
  }
} catch { activityLog = []; }

function logActivity(type, detail = {}) {
  const entry = { ts: Date.now(), type, ...detail };
  activityLog.unshift(entry);
  // Prune by age + cap
  const cutoff = Date.now() - ACTIVITY_MAX_AGE;
  while (activityLog.length > 0 && activityLog[activityLog.length - 1].ts < cutoff) activityLog.pop();
  if (activityLog.length > ACTIVITY_MAX_ENTRIES) activityLog.length = ACTIVITY_MAX_ENTRIES;
  // Persist async  - fire and forget
  writeFile(ACTIVITY_LOG_FILE, JSON.stringify(activityLog)).catch(() => {});
}

// ─────────────────────────────────────────────────
// [BETA] Session Monitor — constants & data
// ─────────────────────────────────────────────────

const SESSION_INACTIVITY_MS = 10 * 60 * 1000; // 10 min → session considered completed
const SESSION_HISTORY_MAX = 200;               // max entries on disk
const SESSION_MAX_ACTIVE = 30;                 // max concurrent tracked sessions
const SESSION_TIMELINE_MAX = 50;               // max timeline entries per session
const SESSION_FILES_MAX = 100;                 // max filesModified per session
const SESSION_BODY_MAX = 2 * 1024 * 1024;      // 2 MB — skip parsing larger bodies
const HAIKU_TIMEOUT = 5000;                    // 5s timeout on Haiku calls
const HAIKU_BACKOFF_MS = 2 * 60 * 1000;        // 2 min backoff after 3 consecutive failures
const SESSION_AWAITING_THRESHOLD = 120000;     // 2 min idle → "awaiting input"

const monitoredSessions = new Map();           // sessionId → session object
let _summarizerOverhead = { inputTokens: 0, outputTokens: 0 };
let _haikuFailCount = 0;
let _haikuBackoffUntil = 0;

// Load persisted session history on startup
let sessionHistory = [];
try {
  if (existsSync(SESSION_HISTORY_FILE)) {
    sessionHistory = JSON.parse(readFileSync(SESSION_HISTORY_FILE, 'utf8'));
    if (!Array.isArray(sessionHistory)) sessionHistory = [];
    sessionHistory = sessionHistory.slice(0, SESSION_HISTORY_MAX);
  }
} catch { sessionHistory = []; }

// Check if the current keychain creds match a saved profile.
// If not, auto-save them as a new account.
async function autoDiscoverAccount() {
  const creds = readKeychain();
  if (!creds?.claudeAiOauth?.accessToken) return;
  const fp = getFingerprint(creds);

  // Check all saved profiles for a fingerprint match
  let files;
  try {
    files = (await readdir(ACCOUNTS_DIR)).filter(f => f.endsWith('.json'));
  } catch {
    // accounts dir might not exist yet
    try { mkdirSync(ACCOUNTS_DIR, { recursive: true }); } catch {}
    files = [];
  }

  // Resolve email for the new token so we can deduplicate by identity
  const token = creds.claudeAiOauth.accessToken;
  const email = await fetchAccountEmail(token);

  for (const file of files) {
    const savedName = basename(file, '.json');
    try {
      const raw = await readFile(join(ACCOUNTS_DIR, file), 'utf8');
      const saved = JSON.parse(raw);
      if (getFingerprint(saved) === fp) return; // exact same token already saved

      // Same refresh token = same underlying account, even when email fetch failed
      const savedRefresh = saved.claudeAiOauth?.refreshToken;
      const currentRefresh = creds.claudeAiOauth.refreshToken;
      if (savedRefresh && currentRefresh && savedRefresh === currentRefresh) {
        writeFileSync(join(ACCOUNTS_DIR, file), JSON.stringify(creds, null, 2));
        const oldFp = getFingerprint(saved);
        migrateAccountState(saved.claudeAiOauth?.accessToken, token, oldFp, fp, savedName);
        console.log(`[auto-discover] Updated "${savedName}" with refreshed token (same refreshToken)`);
        if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
        invalidateTokenCache();
        return;
      }

      // Same email = same account with a refreshed token  - update in place
      if (email) {
        let savedEmail = '';
        try { savedEmail = (await readFile(join(ACCOUNTS_DIR, `${savedName}.label`), 'utf8')).trim(); } catch {}
        if (savedEmail === email) {
          writeFileSync(join(ACCOUNTS_DIR, file), JSON.stringify(creds, null, 2));
          // Migrate persisted state / history from old fingerprint to new
          const oldFp = getFingerprint(saved);
          migrateAccountState(saved.claudeAiOauth?.accessToken, token, oldFp, fp, savedName);
          console.log(`[auto-discover] Updated "${savedName}" with refreshed token (${email})`);
          if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
          invalidateTokenCache(); // ensure getActiveToken() sees the updated token
          return;
        }
      }
    } catch { /* skip */ }
  }

  // Truly new account  - save it
  let idx = 1;
  while (existsSync(join(ACCOUNTS_DIR, `auto-${idx}.json`))) idx++;

  // Cap auto-discovered accounts to prevent runaway creation during error spirals
  const MAX_AUTO_ACCOUNTS = 5;
  if (idx > MAX_AUTO_ACCOUNTS) {
    console.log(`[auto-discover] Skipping — already ${idx - 1} auto accounts (max ${MAX_AUTO_ACCOUNTS})`);
    return;
  }

  const name = `auto-${idx}`;

  try { mkdirSync(ACCOUNTS_DIR, { recursive: true }); } catch {}
  writeFileSync(join(ACCOUNTS_DIR, `${name}.json`), JSON.stringify(creds, null, 2));

  if (email) {
    writeFileSync(join(ACCOUNTS_DIR, `${name}.label`), email);
  }

  const displayName = email || name;
  logActivity('account-discovered', { name, label: displayName });
  console.log(`[auto-discover] New account saved as "${name}" (${displayName})`);

  // Invalidate caches so the proxy picks it up
  if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
}

// Auto-discover runs on proxy requests (see handleProxyRequest),
// not on a timer  - no wasted work when idle.

// ─────────────────────────────────────────────────
// Rate limit fetcher  - uses a minimal haiku call
// to read back the rate-limit response headers.
// ─────────────────────────────────────────────────
const rateLimitCache = new Map(); // fingerprint -> { data, fetchedAt }
const RATE_LIMIT_CACHE_TTL = 5 * 60 * 1000; // 5 min  - proxy state fills the gap between probes

// ── Probe cost tracking (uses lib.mjs) ──
const probeTracker = createProbeTracker();
const PROBE_LOG_FILE = join(__dirname, 'probe-log.json');

// Load persisted probe log on startup
try {
  if (existsSync(PROBE_LOG_FILE)) {
    const raw = readFileSync(PROBE_LOG_FILE, 'utf8');
    probeTracker.load(JSON.parse(raw));
  }
} catch { /* corrupt file - start fresh */ }

function saveProbeLogToDisk() {
  try { writeFileSync(PROBE_LOG_FILE, JSON.stringify(probeTracker.toJSON())); } catch {}
}

function recordProbe() { probeTracker.record(); saveProbeLogToDisk(); }
function getProbeStats() { return probeTracker.getStats(); }

const utilizationHistory = createUtilizationHistory(); // 24h window, ~2 min intervals
const weeklyHistory = createUtilizationHistory(7 * 24 * 60 * 60 * 1000, 15 * 60 * 1000); // 7d window, ~15 min intervals

const HISTORY_FILE = join(__dirname, 'utilization-history.json');

function loadHistoryFromDisk() {
  try {
    const raw = readFileSync(HISTORY_FILE, 'utf8');
    const data = JSON.parse(raw);
    if (data.fiveH) {
      for (const [fp, entries] of Object.entries(data.fiveH)) {
        utilizationHistory.load(fp, entries);
      }
    }
    if (data.weekly) {
      for (const [fp, entries] of Object.entries(data.weekly)) {
        weeklyHistory.load(fp, entries);
      }
    }
  } catch {}
}

function saveHistoryToDisk() {
  try {
    writeFileSync(HISTORY_FILE, JSON.stringify({ fiveH: utilizationHistory.toJSON(), weekly: weeklyHistory.toJSON() }));
  } catch {}
}

loadHistoryFromDisk();

// ── macOS desktop notifications ──

let _lastNotifyAt = 0;
const NOTIFY_THROTTLE_MS = 10_000; // max 1 notification per 10 seconds

function notify(title, message) {
  if (!settings.notifications) return;
  const now = Date.now();
  if (now - _lastNotifyAt < NOTIFY_THROTTLE_MS) return; // throttle notification spam
  _lastNotifyAt = now;
  try {
    const escaped = (s) => s.replace(/"/g, '\\"');
    execFile('osascript', ['-e',
      `display notification "${escaped(message)}" with title "${escaped(title)}" sound name "Blow"`
    ], { timeout: 3000 }, () => {});
  } catch { /* non-critical */ }
}

function fetchRateLimits(token) {
  return new Promise((resolve) => {
    // Mimic the Anthropic TypeScript SDK request shape to look identical
    // to a real Claude Code session. Uses haiku (cheapest) with max_tokens:1.
    const body = JSON.stringify({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 1,
      messages: [{ role: 'user', content: '.' }],
    });

    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Authorization': `Bearer ${token}`,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'oauth-2025-04-20',
        'User-Agent': `claude-code/${CLAUDE_CODE_VERSION}`,
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        // Read rate limit headers from both 200 and 429 responses
        if (res.statusCode !== 200 && res.statusCode !== 429) {
          resolve(null);
          return;
        }
        const h = res.headers;
        resolve({
          status: h['anthropic-ratelimit-unified-status'] || (res.statusCode === 429 ? 'limited' : 'unknown'),
          fiveH: {
            status: h['anthropic-ratelimit-unified-5h-status'] || 'unknown',
            reset: Number(h['anthropic-ratelimit-unified-5h-reset'] || 0),
            utilization: parseFloat(h['anthropic-ratelimit-unified-5h-utilization'] || '0'),
          },
          sevenD: {
            status: h['anthropic-ratelimit-unified-7d-status'] || 'unknown',
            reset: Number(h['anthropic-ratelimit-unified-7d-reset'] || 0),
            utilization: parseFloat(h['anthropic-ratelimit-unified-7d-utilization'] || '0'),
          },
          fallbackPct: parseFloat(h['anthropic-ratelimit-unified-fallback-percentage'] || '0'),
          overageStatus: h['anthropic-ratelimit-unified-overage-status'] || 'unknown',
          overageDisabledReason: h['anthropic-ratelimit-unified-overage-disabled-reason'] || '',
          fetchedAt: Date.now(),
        });
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

async function getRateLimitsForToken(token, fp, { allowProbe = true } = {}) {
  // 1. Check probe cache
  const cached = rateLimitCache.get(fp);
  if (cached && Date.now() - cached.fetchedAt < RATE_LIMIT_CACHE_TTL) {
    return cached.data;
  }

  // 2. Check proxy-tracked state (populated from real traffic  - no extra API calls)
  if (typeof accountState !== 'undefined') {
    const proxyState = accountState.get(token);
    if (proxyState && proxyState.updatedAt && Date.now() - proxyState.updatedAt < RATE_LIMIT_CACHE_TTL) {
      return {
        status: proxyState.limited ? 'limited' : 'ok',
        fiveH: {
          status: proxyState.limited ? 'limited' : 'ok',
          reset: proxyState.resetAt || 0,
          utilization: proxyState.utilization5h || 0,
        },
        sevenD: {
          status: 'ok',
          reset: proxyState.resetAt7d || 0,
          utilization: proxyState.utilization7d || 0,
        },
        fetchedAt: proxyState.updatedAt,
      };
    }
  }

  // 3. Check persisted state (survives restarts)
  const persisted = persistedState[fp];
  let fromPersisted = null;
  if (persisted && persisted.updatedAt) {
    // Pass through last-known values as-is. Don't zero out when the window
    // epoch has passed — that causes the UI to flash "0% / rolling window"
    // between data sources. The staleness indicator communicates the age.
    fromPersisted = {
      status: 'ok',
      fiveH: { status: 'ok', reset: persisted.resetAt || 0, utilization: persisted.utilization5h || 0 },
      sevenD: { status: 'ok', reset: persisted.resetAt7d || 0, utilization: persisted.utilization7d || 0 },
      fetchedAt: persisted.updatedAt,
    };
    // If probe suppressed, return persisted state (with reset-aware values)
    if (!allowProbe) return fromPersisted;
    // If persisted state is recent enough, use it
    if (Date.now() - persisted.updatedAt < RATE_LIMIT_CACHE_TTL) return fromPersisted;
  }

  // 4. Fall back to API probe  - but NOT if probing is suppressed
  //    (conserve strategy: probing a dormant account activates its rate limit window)
  if (!allowProbe) return null;

  recordProbe();
  const data = await fetchRateLimits(token);
  if (data) {
    rateLimitCache.set(fp, { data, fetchedAt: Date.now() });
    // Persist probe results
    updatePersistedState(fp, {
      utilization5h: data.fiveH.utilization,
      utilization7d: data.sevenD.utilization,
      resetAt: data.fiveH.reset,
      resetAt7d: data.sevenD.reset,
    });
    return data;
  }

  // 5. Probe failed  - fall back to stale persisted data instead of null
  if (fromPersisted) {
    fromPersisted.staleAt = fromPersisted.fetchedAt;
    return fromPersisted;
  }
  return null;
}

// ─────────────────────────────────────────────────
// Data loaders
// ─────────────────────────────────────────────────

async function loadProfiles() {
  const activeCreds = readKeychain();
  const activeFp = activeCreds ? getFingerprint(activeCreds) : '';

  let files;
  try {
    files = (await readdir(ACCOUNTS_DIR)).filter(f => f.endsWith('.json'));
  } catch {
    files = [];
  }

  const profiles = [];
  for (const file of files) {
    const name = basename(file, '.json');
    try {
      const raw = await readFile(join(ACCOUNTS_DIR, file), 'utf8');
      const creds = JSON.parse(raw);
      const oauth = creds.claudeAiOauth || {};
      const fp = getFingerprint(creds);

      // Resolve display name: try live API, then persisted .label file, then account name
      let email = '';
      if (oauth.accessToken) {
        email = await getEmailForToken(oauth.accessToken, fp);
      }
      if (!email) {
        try { email = (await readFile(join(ACCOUNTS_DIR, `${name}.label`), 'utf8')).trim(); } catch {}
      }

      // Rate limit fetching strategy:
      // - Active account: always get fresh data (from probe cache or proxy state)
      // - Has persisted state with usage: use proxy state (updated from traffic), no probe needed
      // - Has persisted state at 0%: truly dormant in conserve mode, skip probe
      // - No state at all: probe ONCE to discover actual state, then persist
      let rateLimits = null;
      let dormant = false;
      if (oauth.accessToken) {
        const isActive = fp === activeFp;
        const persisted = persistedState[fp];
        const hasProxyState = !!(accountState.get(oauth.accessToken)?.updatedAt);
        const conserveMode = settings.rotationStrategy === 'conserve';

        let allowProbe = true;
        if (conserveMode && !isActive) {
          if (hasProxyState) {
            // Proxy traffic is keeping it updated  - no probe needed
            allowProbe = false;
          } else if (persisted) {
            // Check reset-aware utilization (if window reset since we saved, it's now 0)
            const nowSec = Math.floor(Date.now() / 1000);
            const eff5h = (persisted.resetAt && persisted.resetAt < nowSec) ? 0 : (persisted.utilization5h || 0);
            const eff7d = (persisted.resetAt7d && persisted.resetAt7d < nowSec) ? 0 : (persisted.utilization7d || 0);
            if (eff5h === 0 && eff7d === 0) {
              allowProbe = false;
              dormant = true;
            }
            // else: has usage  - probe to refresh
          }
          // else: no state at all  - probe once to discover
        }

        rateLimits = await getRateLimitsForToken(oauth.accessToken, fp, { allowProbe });
      }

      // Clear stale refresh failures only if the token fingerprint has actually
      // changed since the failure was recorded (meaning a real refresh happened,
      // e.g. user ran `claude login`). Previously this cleared on expiresAt > now,
      // which hid failures when tokens had future expiry but were already rejected.
      const expiresAt = oauth.expiresAt || 0;
      const failureEntry = refreshFailures.get(name);
      if (failureEntry && failureEntry.fp && failureEntry.fp !== fp) {
        refreshFailures.delete(name);
      }

      // Check if the proxy has marked this account as expired (e.g. via 401)
      const proxyExpired = !!(accountState.get(oauth.accessToken)?.expired);

      profiles.push({
        name,
        label: email || name,
        subscriptionType: oauth.subscriptionType || 'unknown',
        rateLimitTier: oauth.rateLimitTier || 'unknown',
        expiresAt,
        isActive: fp === activeFp,
        fingerprint: fp,
        rateLimits,
        dormant,
        expired: proxyExpired,
        refreshFailed: refreshFailures.get(name) || null,
      });
    } catch {
      // skip corrupt files
    }
  }

  // Dedup pass: if two profiles resolved to the same email, keep the one with
  // the newest expiresAt and remove the other from disk. This handles duplicates
  // created when autoDiscover ran while email fetch was failing.
  const seen = new Map(); // email → profile index
  const toRemove = [];
  for (let i = 0; i < profiles.length; i++) {
    const p = profiles[i];
    // Only dedup by real email labels (skip bare account names like "auto-1")
    if (!p.label || p.label === p.name) continue;
    const prev = seen.get(p.label);
    if (prev !== undefined) {
      const prevP = profiles[prev];
      // Keep the one with the newer expiresAt; on tie, keep the active one
      const keepNew = (p.expiresAt > prevP.expiresAt) || (p.expiresAt === prevP.expiresAt && p.isActive);
      const loserIdx = keepNew ? prev : i;
      const loser = profiles[loserIdx];
      toRemove.push(loserIdx);
      try {
        unlinkSync(join(ACCOUNTS_DIR, `${loser.name}.json`));
        try { unlinkSync(join(ACCOUNTS_DIR, `${loser.name}.label`)); } catch {}
        log('dedup', `Removed duplicate account "${loser.name}" (same email as "${keepNew ? p.name : prevP.name}")`);
      } catch (e) {
        log('warn', `Failed to remove duplicate account file "${loser.name}": ${e.message}`);
      }
      if (keepNew) seen.set(p.label, i);
    } else {
      seen.set(p.label, i);
    }
  }
  if (toRemove.length > 0) {
    invalidateAccountsCache();
    // Return profiles with duplicates removed
    const removeSet = new Set(toRemove);
    return profiles.filter((_, i) => !removeSet.has(i));
  }

  return profiles;
}

async function loadStats() {
  try {
    const raw = await readFile(STATS_CACHE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────
// API handlers
// ─────────────────────────────────────────────────

async function handleAPI(req, res) {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/api/profiles' && req.method === 'GET') {
    const profiles = await loadProfiles();
    // Attach utilization history + velocity to each profile
    for (const p of profiles) {
      p.utilizationHistory = utilizationHistory.getHistory(p.fingerprint);
      p.weeklyHistory = weeklyHistory.getHistory(p.fingerprint);
      p.velocity5h = utilizationHistory.getVelocity(p.fingerprint);
      p.minutesToLimit = utilizationHistory.predictMinutesToLimit(p.fingerprint);
    }
    const stats = await loadStats();
    const probeStats = getProbeStats();
    // Check if all accounts are exhausted
    const allAccounts = loadAllAccountTokens();
    const allExhausted = allAccounts.length > 0 &&
      allAccounts.every(a => !isAccountAvailable(a.token, a.expiresAt));
    const earliestReset = allExhausted ? getEarliestReset() : null;
    json(res, { profiles, stats, probeStats, allExhausted, earliestReset, rotationStrategy: settings.rotationStrategy, queueStats: getQueueStats() });
    return true;
  }

  if (url.pathname === '/api/proxy-status' && req.method === 'GET') {
    json(res, typeof getProxyStatus === 'function' ? getProxyStatus() : {});
    return true;
  }

  if (url.pathname === '/api/switch' && req.method === 'POST') {
    const body = await readBody(req);
    const { name } = JSON.parse(body);
    const file = join(ACCOUNTS_DIR, `${name}.json`);
    try {
      const raw = await readFile(file, 'utf8');
      const creds = JSON.parse(raw);
      writeKeychain(creds);
      invalidateTokenCache();
      // Log the manual switch
      let label = '';
      try { label = (await readFile(join(ACCOUNTS_DIR, `${name}.label`), 'utf8')).trim(); } catch {}
      // Auto-set strategy to sticky so the manual switch isn't overridden
      let strategyChanged = false;
      const prevStrategy = settings.rotationStrategy;
      if (prevStrategy !== 'sticky' && prevStrategy !== 'round-robin') {
        settings.rotationStrategy = 'sticky';
        saveSettings(settings);
        strategyChanged = true;
        logActivity('settings-changed', {
          autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
          rotationStrategy: 'sticky', rotationIntervalMin: settings.rotationIntervalMin,
          reason: 'manual-switch',
        });
      }
      lastRotationTime = Date.now();
      logActivity('manual-switch', { to: label || name });
      json(res, { ok: true, switched: name, label: label || name, strategyChanged, strategy: settings.rotationStrategy });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 400);
    }
    return true;
  }

  if (url.pathname === '/api/remove' && req.method === 'POST') {
    const body = await readBody(req);
    const { name } = JSON.parse(body);
    if (!name) {
      json(res, { ok: false, error: 'name required' }, 400);
      return true;
    }
    const file = join(ACCOUNTS_DIR, `${name}.json`);
    try {
      // Verify the account exists
      const raw = await readFile(file, 'utf8');
      const creds = JSON.parse(raw);
      // Prevent removing the active account
      const activeCreds = readKeychain();
      if (activeCreds && getFingerprint(creds) === getFingerprint(activeCreds)) {
        json(res, { ok: false, error: 'Cannot remove the active account. Switch to another account first.' }, 400);
        return true;
      }
      // Delete account files
      await unlink(file);
      try { await unlink(join(ACCOUNTS_DIR, `${name}.label`)); } catch {}
      logActivity('account-removed', { name });
      if (typeof invalidateAccountsCache === 'function') invalidateAccountsCache();
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 400);
    }
    return true;
  }

  if (url.pathname === '/api/refresh' && req.method === 'POST') {
    const body = await readBody(req);
    const { name } = JSON.parse(body);
    if (!name) {
      json(res, { ok: false, error: 'name required' }, 400);
      return true;
    }
    try {
      refreshFailures.delete(name);
      const result = await refreshAccountToken(name, { force: true });
      json(res, result, result.ok ? 200 : 500);
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/activity' && req.method === 'GET') {
    json(res, { log: activityLog.slice(0, 100) });
    return true;
  }

  // SSE endpoint: stream proxy logs in real-time (used by `vdm logs`)
  if (url.pathname === '/api/logs/stream' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    res.write(`data: ${JSON.stringify({ tag: 'system', msg: 'Connected to log stream', line: '--- Connected to Van Damme-o-Matic log stream ---' })}\n\n`);
    // Replay buffered history so new clients see recent logs immediately
    for (const entry of _logBuffer) {
      res.write(`data: ${JSON.stringify(entry)}\n\n`);
    }
    _logSubscribers.add(res);
    req.on('close', () => _logSubscribers.delete(res));
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'GET') {
    json(res, settings);
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'POST') {
    const body = await readBody(req);
    const patch = JSON.parse(body);
    if (typeof patch.autoSwitch === 'boolean') settings.autoSwitch = patch.autoSwitch;
    if (typeof patch.proxyEnabled === 'boolean') {
      const wasEnabled = settings.proxyEnabled;
      settings.proxyEnabled = patch.proxyEnabled;
      if (wasEnabled !== patch.proxyEnabled) {
        // Reset error state on proxy toggle for a clean slate
        _consecutive400s = 0;
        _consecutive400sAt = 0;
        _circuitOpen = false;
        _consecutiveExhausted = 0;
        if (patch.proxyEnabled) {
          log('info', 'Proxy re-enabled — clean state');
        } else {
          log('info', 'Proxy disabled — error state reset');
        }
      }
    }
    if (typeof patch.notifications === 'boolean') settings.notifications = patch.notifications;
    if (typeof patch.rotationStrategy === 'string' && ROTATION_STRATEGIES[patch.rotationStrategy]) {
      settings.rotationStrategy = patch.rotationStrategy;
      lastRotationTime = Date.now(); // reset timer on strategy change
    }
    if (typeof patch.rotationIntervalMin === 'number' && ROTATION_INTERVALS.includes(patch.rotationIntervalMin)) {
      settings.rotationIntervalMin = patch.rotationIntervalMin;
      lastRotationTime = Date.now(); // reset timer on interval change
    }
    if (typeof patch.serializeRequests === 'boolean') {
      settings.serializeRequests = patch.serializeRequests;
      // If turning off, drain queued requests immediately
      if (!patch.serializeRequests) drainSerializationQueue();
    }
    if (typeof patch.serializeDelayMs === 'number' && patch.serializeDelayMs >= 0 && patch.serializeDelayMs <= 2000) {
      settings.serializeDelayMs = patch.serializeDelayMs;
    }
    if (typeof patch.commitTokenUsage === 'boolean') settings.commitTokenUsage = patch.commitTokenUsage;
    if (typeof patch.sessionMonitor === 'boolean') settings.sessionMonitor = patch.sessionMonitor;
    saveSettings(settings);
    logActivity('settings-changed', {
      autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
      rotationStrategy: settings.rotationStrategy, rotationIntervalMin: settings.rotationIntervalMin,
    });
    json(res, settings);
    return true;
  }

  // ── [BETA] Session tracking for token usage ──

  if (url.pathname === '/api/session-start' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const data = JSON.parse(body);
      const sessionId = data.session_id;
      const cwd = data.cwd;
      if (!sessionId || !cwd) {
        json(res, { ok: false, error: 'session_id and cwd required' }, 400);
        return true;
      }
      // Only register new sessions — don't overwrite startedAt on subsequent
      // UserPromptSubmit hooks (otherwise we'd lose usage from earlier prompts)
      if (!pendingSessions.has(sessionId)) {
        let repo = cwd, branch = '(no git)', commitHash = '';
        try {
          // Use --git-common-dir to resolve to main repo root (not worktree directory)
          // so worktree sessions group with the parent repo in the dashboard.
          try {
            repo = execSync(`git -C "${cwd}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim().replace(/\/\.git\/?$/, '');
          } catch {
            repo = execSync(`git -C "${cwd}" rev-parse --show-toplevel 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
          }
          branch = _resolveWorktreeBranch(cwd, execSync(`git -C "${cwd}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim());
          commitHash = execSync(`git -C "${cwd}" rev-parse --short HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
        } catch { /* not a git repo */ }
        pendingSessions.set(sessionId, { repo, branch, commitHash, cwd, startedAt: Date.now() });
        ensureLocalCommitHook(cwd);
        log('tokens', `Session started: ${sessionId.slice(0, 8)}… (${basename(repo)}/${branch})`);
      } else {
        // Re-read branch on subsequent prompts (handles worktree branch switches)
        const session = pendingSessions.get(sessionId);
        // Keep cwd up to date so periodic persist and auto-claim use the latest directory
        if (cwd && cwd !== session.cwd) session.cwd = cwd;
        try {
          const newBranch = _resolveWorktreeBranch(cwd, execSync(`git -C "${cwd}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim());
          if (newBranch && newBranch !== session.branch) {
            log('tokens', `Session ${sessionId.slice(0, 8)}… branch updated: ${session.branch} → ${newBranch}`);
            session.branch = newBranch;
            session.commitHash = execSync(`git -C "${cwd}" rev-parse --short HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
          }
        } catch { /* ignore */ }
      }
      // Prune stale sessions (>24h — sessions can be long-lived)
      const staleThreshold = Date.now() - 24 * 60 * 60 * 1000;
      for (const [id, s] of pendingSessions) {
        if (s.startedAt < staleThreshold) {
          // Auto-persist before pruning so data isn't lost
          _autoClaimSession(id, s);
          pendingSessions.delete(id);
        }
      }
      json(res, { ok: true });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/session-stop' && req.method === 'POST') {
    try {
      const body = await readBody(req);
      const data = JSON.parse(body);
      const sessionId = data.session_id;
      if (!sessionId) {
        json(res, { ok: false, error: 'session_id required' }, 400);
        return true;
      }
      const session = pendingSessions.get(sessionId);
      if (!session) {
        log('tokens', `Session stop: ${sessionId.slice(0, 8)}… (not found — may have been auto-claimed)`);
        json(res, { ok: true, claimed: 0 });
        return true;
      }
      const stopAt = Date.now();
      const claimed = claimUsageInRange(session.startedAt, stopAt);
      for (const entry of claimed) {
        appendTokenUsage({
          ts: entry.ts,
          repo: session.repo,
          branch: session.branch,
          commitHash: session.commitHash,
          model: entry.model,
          inputTokens: entry.inputTokens,
          outputTokens: entry.outputTokens,
          account: entry.account,
        });
      }
      pendingSessions.delete(sessionId);
      log('tokens', `Session stopped: ${sessionId.slice(0, 8)}… (claimed ${claimed.length} entries)`);
      json(res, { ok: true, claimed: claimed.length });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/token-usage/flush' && req.method === 'POST') {
    // Force all active sessions to claim and persist unclaimed usage now.
    // Same logic as the periodic timer, but triggered on demand (used by commit hooks).
    try {
      let flushed = 0;
      for (const [id, session] of pendingSessions) {
        const now = Date.now();
        if (session.cwd) {
          try {
            const cur = _resolveWorktreeBranch(session.cwd, execSync(`git -C "${session.cwd}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim());
            if (cur && cur !== session.branch) {
              session.branch = cur;
              session.commitHash = execSync(`git -C "${session.cwd}" rev-parse --short HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
            }
          } catch { /* ignore */ }
        }
        const claimed = claimUsageInRange(session.startedAt, now);
        for (const entry of claimed) {
          appendTokenUsage({
            ts: entry.ts, repo: session.repo, branch: session.branch,
            commitHash: session.commitHash, model: entry.model,
            inputTokens: entry.inputTokens, outputTokens: entry.outputTokens,
            account: entry.account,
          });
        }
        if (claimed.length > 0) {
          session.startedAt = now;
          flushed += claimed.length;
        }
      }
      if (flushed > 0) log('tokens', `Flush: persisted ${flushed} entries on demand`);
      json(res, { ok: true, flushed });
    } catch (e) {
      json(res, { ok: false, error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/token-usage' && req.method === 'GET') {
    try {
      const usage = loadTokenUsage();
      let filtered = usage;
      const repo = url.searchParams.get('repo');
      const branch = url.searchParams.get('branch');
      const since = url.searchParams.get('since');
      const limit = parseInt(url.searchParams.get('limit') || '0', 10);
      if (repo) filtered = filtered.filter(e => e.repo === repo);
      if (branch) filtered = filtered.filter(e => e.branch === branch);
      if (since) filtered = filtered.filter(e => e.ts >= Number(since));
      if (limit > 0) filtered = filtered.slice(-limit);
      json(res, filtered);
    } catch (e) {
      json(res, [], 500);
    }
    return true;
  }

  // ── [BETA] Session Monitor API ──

  if (url.pathname === '/api/sessions' && req.method === 'GET') {
    const now = Date.now();
    const active = [];
    for (const [, s] of monitoredSessions) {
      active.push({
        id: s.id,
        account: s.account,
        model: s.model,
        cwd: s.cwd,
        repo: s.repo,
        branch: s.branch,
        timeline: s.timeline,
        currentActivity: s.currentActivity,
        requestCount: s.requestCount,
        totalInputTokens: s.totalInputTokens,
        totalOutputTokens: s.totalOutputTokens,
        startedAt: s.startedAt,
        lastActiveAt: s.lastActiveAt,
      });
    }
    // Sort: processing first, then by lastActiveAt desc
    active.sort((a, b) => {
      const aProc = (now - a.lastActiveAt) < SESSION_AWAITING_THRESHOLD;
      const bProc = (now - b.lastActiveAt) < SESSION_AWAITING_THRESHOLD;
      if (aProc !== bProc) return aProc ? -1 : 1;
      return b.lastActiveAt - a.lastActiveAt;
    });
    const recent = sessionHistory.slice(0, 20);
    json(res, {
      enabled: !!settings.sessionMonitor,
      active,
      recent,
      overhead: _summarizerOverhead,
      conflicts: getFileConflicts(),
    });
    return true;
  }

  return false;
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    req.on('error', reject);
  });
}

// ─────────────────────────────────────────────────
// HTML Dashboard
// ─────────────────────────────────────────────────

function renderHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Van Damme-o-Matic</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: hsl(220 14% 96%);
    --card: #fff;
    --foreground: hsl(224 71% 4%);
    --muted: hsl(220 9% 46%);
    --border: hsl(220 13% 91%);
    --primary: hsl(217 91% 60%);
    --primary-soft: hsl(217 91% 97%);
    --green: hsl(142 71% 45%);
    --green-soft: hsl(142 76% 94%);
    --green-border: hsl(142 60% 80%);
    --yellow: hsl(38 92% 50%);
    --yellow-soft: hsl(48 100% 95%);
    --yellow-border: hsl(48 80% 75%);
    --red: hsl(0 84% 60%);
    --red-soft: hsl(0 86% 97%);
    --red-border: hsl(0 70% 85%);
    --blue-soft: hsl(217 91% 97%);
    --blue-border: hsl(217 60% 85%);
    --purple: hsl(271 81% 56%);
    --purple-soft: hsl(271 81% 97%);
    --purple-border: hsl(271 50% 85%);
    --cyan: hsl(187 85% 43%);
    --cyan-soft: hsl(187 70% 95%);
    --cyan-border: hsl(187 50% 80%);
    --shadow: 0 1px 3px rgba(0,0,0,0.04), 0 1px 2px rgba(0,0,0,0.06);
    --shadow-lg: 0 4px 12px -2px rgba(0,0,0,0.06), 0 2px 6px -1px rgba(0,0,0,0.04);
    --radius: 14px;
    --radius-sm: 10px;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--foreground);
    min-height: 100vh;
    padding: 2.5rem 1.5rem;
    -webkit-font-smoothing: antialiased;
  }
  .container { max-width: 720px; margin: 0 auto; }

  /* ── Header ── */
  .header {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    margin-bottom: 1.5rem;
  }
  .header-left h1 {
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.02em;
    margin-bottom: 0.25rem;
  }
  .header-sub {
    font-size: 0.9375rem;
    color: var(--muted);
  }
  .ctrl {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    user-select: none;
  }
  .sw {
    position: relative;
    width: 32px;
    height: 18px;
    -webkit-appearance: none;
    appearance: none;
    background: var(--border);
    border-radius: 9px;
    cursor: pointer;
    transition: background 0.2s;
    outline: none;
    border: none;
  }
  .sw::before {
    content: '';
    position: absolute;
    top: 2px; left: 2px;
    width: 14px; height: 14px;
    border-radius: 50%;
    background: #fff;
    box-shadow: 0 1px 2px rgba(0,0,0,0.15);
    transition: transform 0.2s;
  }
  .sw:checked { background: var(--green); }
  .sw:checked::before { transform: translateX(14px); }
  /* ── Config tab ── */
  .config-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    overflow: hidden;
  }
  .config-section {
    padding: 1.25rem 1.5rem;
  }
  .config-section + .config-section {
    border-top: 1px solid var(--border);
  }
  .config-section-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 0.875rem;
  }
  .config-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 1.5rem;
    padding: 0.5rem 0;
  }
  .config-row + .config-row {
    border-top: 1px solid color-mix(in srgb, var(--border) 50%, transparent);
    padding-top: 0.75rem;
    margin-top: 0.25rem;
  }
  .config-info { flex: 1; min-width: 0; }
  .config-label {
    font-size: 0.9375rem;
    font-weight: 500;
    color: var(--foreground);
  }
  .config-desc {
    font-size: 0.8125rem;
    color: var(--muted);
    margin-top: 0.125rem;
    line-height: 1.4;
  }
  .config-select {
    background: var(--card);
    color: var(--foreground);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.375rem 0.625rem;
    font-size: 0.875rem;
    font-weight: 500;
    font-family: inherit;
    cursor: pointer;
    outline: none;
    min-width: 120px;
  }
  .config-select:hover { border-color: var(--primary); }
  .strategy-list {
    margin-top: 0.75rem;
    display: flex;
    flex-direction: column;
    gap: 0.375rem;
  }
  .strategy-item {
    display: flex;
    align-items: baseline;
    gap: 0.5rem;
    padding: 0.5rem 0.625rem;
    border-radius: 8px;
    border: 1px solid transparent;
    transition: background 0.15s, border-color 0.15s;
  }
  .strategy-item.active {
    background: color-mix(in srgb, var(--primary) 8%, transparent);
    border-color: color-mix(in srgb, var(--primary) 25%, transparent);
  }
  .strategy-item-name {
    font-size: 0.8125rem;
    font-weight: 600;
    color: var(--foreground);
    white-space: nowrap;
    min-width: 5.5rem;
  }
  .strategy-item.active .strategy-item-name { color: var(--primary); }
  .strategy-item-desc {
    font-size: 0.8125rem;
    color: var(--muted);
    line-height: 1.4;
  }
  .config-select:focus { border-color: var(--primary); box-shadow: 0 0 0 2px var(--blue-soft); }

  /* ── Tabs ── */
  .tabs {
    display: flex;
    gap: 0.25rem;
    margin-bottom: 1.25rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.25rem;
    box-shadow: var(--shadow);
  }
  .tab {
    flex: 1;
    padding: 0.5rem 0;
    font-size: 0.9375rem;
    font-weight: 500;
    color: var(--muted);
    cursor: pointer;
    border: none;
    border-radius: 8px;
    background: none;
    transition: all 0.15s;
    font-family: inherit;
  }
  .tab:hover { color: var(--foreground); }
  .tab.active {
    background: var(--primary);
    color: #fff;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
  }
  .tab-content { display: none; }
  .tab-content.active { display: block; }

  /* ── Account cards ── */
  .accounts { display: flex; flex-direction: column; gap: 0.625rem; }

  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.25rem 1.5rem;
    transition: box-shadow 0.2s, border-color 0.2s;
  }
  .card:hover { box-shadow: var(--shadow-lg); }
  .card.active { border-color: var(--green); border-width: 2px; }
  .card.stale { opacity: 0.5; }
  .card.stale:hover { opacity: 0.7; }
  .stale-msg {
    margin-top: 0.5rem;
    font-size: 0.8rem;
    color: var(--red);
    line-height: 1.4;
  }
  .stale-msg code {
    background: var(--bg);
    padding: 0.1em 0.4em;
    border-radius: 3px;
    font-size: 0.85em;
  }

  .card-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }
  .card-identity {
    display: flex;
    align-items: center;
    gap: 0.625rem;
  }
  .status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .status-dot.active { background: var(--green); box-shadow: 0 0 0 3px hsl(142 71% 45% / 0.15); }
  .status-dot.inactive { background: var(--border); }
  .card-name {
    font-size: 1.0625rem;
    font-weight: 600;
  }
  .card-token-sep {
    color: var(--border);
    font-size: 0.875rem;
  }
  .card-token {
    font-size: 0.8125rem;
    color: var(--foreground);
    font-weight: 400;
  }

  .card-badges { display: flex; gap: 0.375rem; align-items: center; }
  .badge {
    display: inline-flex;
    align-items: center;
    font-size: 0.75rem;
    font-weight: 500;
    padding: 0.125rem 0.5rem;
    border-radius: 4px;
    border: 1px solid;
  }
  .badge-max { color: var(--cyan); background: var(--cyan-soft); border-color: var(--cyan-border); }
  .badge-pro { color: var(--primary); background: var(--blue-soft); border-color: var(--blue-border); }
  .badge-free { color: var(--muted); background: var(--bg); border-color: var(--border); }
  .badge-active { color: var(--green); background: var(--green-soft); border-color: var(--green-border); }

  .card-token.tok-bad { color: var(--red); }

  /* Rate limit bars */
  .rate-bars {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 3rem;
  }
  .rate-group {}
  .rate-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    margin-bottom: 0.3125rem;
  }
  .rate-label {
    font-size: 0.75rem;
    color: var(--muted);
    font-weight: 500;
  }
  .rate-pct {
    font-size: 0.75rem;
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .pct-ok { color: var(--green); }
  .pct-mid { color: var(--yellow); }
  .pct-high { color: var(--red); }
  .rate-track {
    height: 4px;
    background: var(--bg);
    border-radius: 2px;
    overflow: hidden;
  }
  .rate-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 0.4s ease;
  }
  .fill-ok { background: var(--green); }
  .fill-mid { background: var(--yellow); }
  .fill-high { background: var(--red); }
  .fill-full { background: var(--red); animation: pulse-fill 1.5s infinite; }
  @keyframes pulse-fill { 0%,100%{opacity:1} 50%{opacity:0.5} }
  .rate-reset {
    font-size: 0.6875rem;
    color: var(--muted);
    margin-top: 0.1875rem;
    font-variant-numeric: tabular-nums;
  }

  .switch-btn {
    padding: 0.5rem 1.125rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--foreground);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
    box-shadow: 0 1px 2px rgba(0,0,0,0.05);
  }
  .switch-btn:hover {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
  }
  .switch-btn:active { transform: scale(0.98); }

  .remove-btn {
    padding: 0.375rem 0.75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted-foreground);
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
  }
  .remove-btn:hover {
    background: #dc2626;
    color: #fff;
    border-color: #dc2626;
  }

  .refresh-btn {
    padding: 0.375rem 0.75rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border);
    background: transparent;
    color: var(--primary);
    font-size: 0.75rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    font-family: inherit;
  }
  .refresh-btn:hover {
    background: var(--primary);
    color: #fff;
    border-color: var(--primary);
  }

  .card.switching { opacity: 0.5; pointer-events: none; }

  /* ── Session Monitor ── */
  .session-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 0.875rem 1rem;
    margin-bottom: 0.75rem;
    border-left: 3px solid var(--muted);
    position: relative;
  }
  .session-card.processing { border-left-color: #3fb950; }
  .session-card.awaiting { border-left-color: var(--yellow); }
  .session-card.completed { border-left-color: var(--muted); opacity: 0.85; }
  .session-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    color: var(--muted);
    margin-bottom: 0.5rem;
    cursor: pointer;
    user-select: none;
  }
  .session-card.collapsed .session-header { margin-bottom: 0; }
  .session-header b { color: var(--foreground); font-weight: 600; }
  .session-header-left { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .session-header-right { flex-shrink: 0; white-space: nowrap; display: flex; align-items: center; gap: 0.5rem; margin-left: 0.5rem; }
  .session-collapse-indicator { font-size: 0.625rem; color: var(--muted); transition: transform 0.15s; }
  .session-card.collapsed .session-collapse-indicator { transform: rotate(-90deg); }
  .session-card.collapsed .session-timeline,
  .session-card.collapsed .session-meta,
  .session-card.collapsed .session-copy-btn { display: none; }
  .session-collapsed-activity {
    display: none;
    font-size: 0.75rem;
    color: var(--muted);
    font-style: italic;
    margin-top: 0.375rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .session-card.collapsed .session-collapsed-activity { display: block; }
  .session-awaiting {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    background: var(--yellow-soft);
    color: var(--yellow);
    border: 1px solid var(--yellow-border);
    border-radius: 4px;
    padding: 0.0625rem 0.375rem;
    font-size: 0.6875rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .session-timeline {
    font-size: 0.8125rem;
    line-height: 1.6;
    margin: 0.375rem 0;
    max-height: 500px;
    overflow-y: auto;
  }
  .tl-input {
    color: var(--foreground);
    font-weight: 600;
  }
  .tl-input::before { content: '\\2192 '; color: var(--primary); }
  .tl-action {
    color: var(--muted);
    padding-left: 1.25rem;
  }
  .tl-action::before { content: '\\21B3 '; }
  .tl-current {
    color: var(--muted);
    padding-left: 1.25rem;
    font-style: italic;
    font-size: 0.75rem;
  }
  .session-meta {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.375rem;
    display: flex;
    gap: 0.75rem;
  }
  .session-conflicts {
    background: rgba(248,81,73,0.08);
    border: 1px solid rgba(248,81,73,0.3);
    border-radius: var(--radius);
    padding: 0.5rem 0.75rem;
    margin-bottom: 0.75rem;
    font-size: 0.8125rem;
    color: #f85149;
  }
  .session-copy-btn {
    position: absolute;
    bottom: 0.5rem;
    right: 0.5rem;
    background: none;
    border: 1px solid var(--border);
    border-radius: 4px;
    cursor: pointer;
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    color: var(--muted);
    opacity: 0;
    transition: opacity 0.15s;
  }
  .session-card:hover .session-copy-btn { opacity: 1; }
  .session-copy-btn:hover { background: var(--surface); }
  .tab-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--yellow);
    color: #000;
    font-size: 0.625rem;
    font-weight: 700;
    min-width: 1rem;
    height: 1rem;
    border-radius: 0.5rem;
    padding: 0 0.25rem;
    margin-left: 0.375rem;
    vertical-align: middle;
  }
  .session-section-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 0.75rem 0 0.375rem;
  }
  .session-overhead {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.75rem;
    padding-top: 0.5rem;
    border-top: 1px solid var(--border);
  }
  @keyframes braille-spin {
    0%   { content: '\\280B'; }
    10%  { content: '\\2819'; }
    20%  { content: '\\2839'; }
    30%  { content: '\\2838'; }
    40%  { content: '\\283C'; }
    50%  { content: '\\2834'; }
    60%  { content: '\\2826'; }
    70%  { content: '\\2827'; }
    80%  { content: '\\2807'; }
    90%  { content: '\\280F'; }
  }
  .braille-spin::before {
    content: '\\280B';
    animation: braille-spin 1.2s steps(1) infinite;
    margin-right: 0.25rem;
  }
  .braille-static::before {
    content: '\\28FF';
    margin-right: 0.25rem;
    opacity: 0.6;
  }

  /* ── Activity log ── */
  .activity-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1rem 1.25rem;
    max-height: 500px;
    overflow-y: auto;
  }
  .evt {
    display: flex;
    align-items: baseline;
    gap: 0.75rem;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--bg);
    font-size: 0.875rem;
  }
  .evt:last-child { border-bottom: none; }
  .evt-time {
    color: var(--muted);
    font-size: 0.8125rem;
    white-space: nowrap;
    min-width: 100px;
    font-variant-numeric: tabular-nums;
  }
  .evt-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .evt-msg { flex: 1; color: var(--muted); line-height: 1.4; }
  .evt-msg b { color: var(--foreground); font-weight: 600; }

  /* ── Usage ── */
  .usage-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1.5rem;
  }
  .usage-title {
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 1.25rem;
  }
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0.75rem;
    margin-bottom: 1.5rem;
  }
  .stat-item {
    background: var(--bg);
    border-radius: var(--radius-sm);
    padding: 1rem 0.75rem;
    text-align: center;
  }
  .stat-val {
    font-size: 1.375rem;
    font-weight: 700;
    color: var(--foreground);
    font-variant-numeric: tabular-nums;
  }
  .stat-label {
    font-size: 0.6875rem;
    color: var(--muted);
    font-weight: 500;
    margin-top: 0.25rem;
  }
  .chart-legend {
    display: flex;
    gap: 1rem;
    justify-content: flex-end;
    margin-bottom: 0.5rem;
    font-size: 0.6875rem;
    color: var(--muted);
  }
  .chart-legend-item { display: flex; align-items: center; gap: 0.3rem; }
  .chart-legend-dot { width: 8px; height: 8px; border-radius: 2px; }
  .chart-container {
    height: 160px;
    display: flex;
    align-items: flex-end;
    gap: 3px;
  }
  .chart-day {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 0;
  }
  .chart-bars {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    width: 100%;
    justify-content: center;
    height: 125px;
  }
  .chart-bar {
    flex: 1;
    min-width: 4px;
    max-width: 16px;
    border-radius: 3px 3px 0 0;
    transition: height 0.3s;
    position: relative;
    cursor: default;
  }
  .chart-bar:hover { opacity: 0.75; z-index: 20; }
  .chart-bar:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--foreground);
    color: #fff;
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.6875rem;
    white-space: nowrap;
    z-index: 10;
    pointer-events: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .chart-bar.msg-bar { background: var(--primary); }
  .chart-bar.tok-bar { background: var(--purple); opacity: 0.6; }
  .chart-label {
    font-size: 0.625rem;
    color: var(--muted);
    margin-top: 0.375rem;
  }

  /* ── Toast ── */
  .toast {
    position: fixed;
    bottom: 1.5rem;
    left: 50%;
    transform: translateX(-50%) translateY(80px);
    background: var(--foreground);
    color: #fff;
    padding: 0.625rem 1.25rem;
    border-radius: var(--radius-sm);
    font-size: 0.8125rem;
    font-weight: 500;
    opacity: 0;
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 100;
    box-shadow: 0 8px 20px rgba(0,0,0,0.15);
  }
  .toast.show { transform: translateX(-50%) translateY(0); opacity: 1; }

  .empty-state {
    text-align: center;
    padding: 3rem 1.5rem;
    color: var(--muted);
    font-size: 0.875rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .empty-state code {
    background: var(--bg);
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    font-size: 0.8125rem;
  }

  /* ── Scrollbar ── */
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: hsl(220 9% 46% / 0.25); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: hsl(220 9% 46% / 0.4); }

  /* ── Exhausted banner ── */
  .exhausted-banner {
    background: hsl(0 60% 15%);
    border: 1px solid hsl(0 50% 30%);
    border-radius: var(--radius-sm);
    padding: 0.625rem 1rem;
    margin-bottom: 0.75rem;
    display: flex;
    align-items: center;
    gap: 0.625rem;
    font-size: 0.875rem;
    color: hsl(0 80% 80%);
    animation: pulse-border 2s ease-in-out infinite;
  }
  @keyframes pulse-border {
    0%, 100% { border-color: hsl(0 50% 30%); }
    50% { border-color: hsl(0 70% 50%); }
  }
  .exhausted-icon {
    width: 22px; height: 22px;
    border-radius: 50%;
    background: hsl(0 60% 40%);
    color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-weight: 700; font-size: 0.8125rem;
    flex-shrink: 0;
  }

  /* ── Sparklines ── */
  .sparkline-wrap {
    margin-top: 0.375rem;
    width: 100%;
  }
  .sparkline-svg { display: block; width: 100%; height: auto; }
  .velocity-badge {
    font-size: 0.6875rem;
    font-weight: 500;
    color: var(--muted);
    white-space: nowrap;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.125rem 0.5rem;
    font-variant-numeric: tabular-nums;
  }
  .velocity-badge.velocity-ok { color: var(--green); border-color: var(--green-border); background: var(--green-soft); }
  .velocity-badge.velocity-warn { color: var(--yellow); border-color: var(--yellow-border); background: var(--yellow-soft); }
  .velocity-badge.velocity-crit { color: var(--red); border-color: var(--red-border); background: var(--red-soft); }

  /* ── Animations ── */
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .card { animation: fadeInUp 0.3s ease-out; }

  /* ── Tokens tab ── */
  .tok-filters {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }
  .tok-filters .config-select {
    flex: 1;
    min-width: 100px;
  }
  .tok-proportion {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 1rem;
  }
  .tok-proportion-seg {
    height: 100%;
    transition: width 0.3s;
  }
  .tok-model-row {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 0;
    font-size: 0.875rem;
    flex-wrap: wrap;
  }
  .tok-model-row + .tok-model-row {
    border-top: 1px solid var(--bg);
  }
  .tok-model-dot {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex-shrink: 0;
  }
  .tok-model-name {
    font-weight: 500;
    min-width: 120px;
  }
  .tok-model-detail {
    color: var(--muted);
    font-size: 0.8125rem;
    flex: 1;
  }
  .tok-model-total {
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .tok-model-pct {
    color: var(--muted);
    font-size: 0.8125rem;
    font-variant-numeric: tabular-nums;
    min-width: 3rem;
    text-align: right;
  }
  .tok-branch-row {
    padding: 0.75rem 0;
    font-size: 0.875rem;
  }
  .tok-branch-row + .tok-branch-row {
    border-top: 1px solid var(--bg);
  }
  .tok-branch-name {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 500;
  }
  .tok-branch-badge {
    font-size: 0.6875rem;
    font-weight: 500;
    color: var(--cyan);
    background: var(--cyan-soft);
    border: 1px solid var(--cyan-border);
    border-radius: 4px;
    padding: 0.0625rem 0.375rem;
  }
  .tok-branch-stats {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-top: 0.25rem;
  }
  .tok-branch-total {
    font-weight: 600;
    font-variant-numeric: tabular-nums;
  }
  .tok-branch-pct {
    color: var(--muted);
    font-size: 0.8125rem;
    font-variant-numeric: tabular-nums;
  }
  .tok-branch-detail {
    font-size: 0.75rem;
    color: var(--muted);
    margin-top: 0.25rem;
    line-height: 1.6;
  }
  #tok-stats.stat-grid { grid-template-columns: repeat(5, 1fr); }
  .tok-stat-sub { font-size: 0.5625rem; color: var(--muted); margin-top: 0.0625rem; }
  .tok-savings-banner {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.8125rem;
    color: var(--muted);
    margin-bottom: 1.25rem;
    flex-wrap: wrap;
  }
  .tok-savings-banner select {
    font-size: 0.75rem;
    padding: 0.125rem 0.375rem;
    border-radius: 4px;
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--foreground);
  }
  .tok-savings-val { color: var(--green); font-weight: 600; }
  .tok-trend { font-size: 0.6875rem; font-weight: 500; margin-top: 0.125rem; }
  .tok-trend.up { color: var(--red); }
  .tok-trend.down { color: var(--green); }
  .tok-repo-group { margin-bottom: 0.25rem; }
  .tok-repo-header {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.625rem 0;
    cursor: pointer;
    user-select: none;
  }
  .tok-repo-header:hover { opacity: 0.8; }
  .tok-repo-group + .tok-repo-group .tok-repo-header {
    border-top: 1px solid var(--bg);
  }
  .tok-repo-chevron {
    font-size: 0.625rem;
    color: var(--muted);
    transition: transform 0.15s;
    flex-shrink: 0;
    width: 1rem;
    text-align: center;
  }
  .tok-repo-chevron.collapsed { transform: rotate(-90deg); }
  .tok-repo-name { font-weight: 600; }
  .tok-repo-inactive { opacity: 0.5; }
  .tok-branch-inactive { opacity: 0.6; }
  .tok-inactive-sep {
    font-size: 0.6875rem;
    color: var(--muted);
    padding: 0.75rem 0 0.25rem;
    border-top: 1px dashed var(--border);
    margin-top: 0.5rem;
  }
  .tok-model-cost {
    font-size: 0.8125rem;
    color: var(--muted);
    font-variant-numeric: tabular-nums;
    min-width: 4rem;
    text-align: right;
  }
  .tok-export-btn {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--foreground);
    font-size: 0.75rem;
    padding: 0.375rem 0.75rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .tok-export-btn:hover { background: var(--bg); }
  .tok-chart-wrap {
    display: flex;
    align-items: flex-end;
    gap: 2px;
  }
  .tok-chart-bar-area {
    height: 120px;
    display: flex;
    align-items: flex-end;
    justify-content: center;
    width: 100%;
  }
  .tok-chart-bar-group {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    min-width: 4px;
  }
  .tok-chart-stack {
    width: 100%;
    max-width: 28px;
    display: flex;
    flex-direction: column-reverse;
  }
  .tok-chart-seg {
    width: 100%;
    min-height: 0;
    transition: height 0.3s;
    position: relative;
    cursor: default;
  }
  .tok-chart-seg:first-child { border-radius: 0 0 2px 2px; }
  .tok-chart-seg:last-child { border-radius: 2px 2px 0 0; }
  .tok-chart-seg:hover { opacity: 0.75; z-index: 20; }
  .tok-chart-seg:hover::after {
    content: attr(data-tooltip);
    position: absolute;
    bottom: calc(100% + 6px);
    left: 50%;
    transform: translateX(-50%);
    background: var(--foreground);
    color: #fff;
    padding: 0.25rem 0.5rem;
    border-radius: 6px;
    font-size: 0.6875rem;
    white-space: nowrap;
    z-index: 10;
    pointer-events: none;
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .tok-chart-label {
    font-size: 0.5625rem;
    color: var(--muted);
    margin-top: 0.25rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 100%;
    text-align: center;
  }

  /* ── Chart carousel ── */
  .chart-carousel {
    position: relative;
  }
  .chart-carousel-inner {
    overflow: hidden;
  }
  .chart-carousel-slides {
    display: flex;
    transition: transform 0.3s ease;
  }
  .chart-carousel-slide {
    min-width: 100%;
    flex-shrink: 0;
  }
  .chart-carousel-dots {
    display: flex;
    justify-content: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  .chart-carousel-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--border);
    border: none;
    cursor: pointer;
    padding: 0;
    transition: background 0.2s;
  }
  .chart-carousel-dot.active { background: var(--primary); }
  .chart-carousel-dot:hover { background: var(--muted); }

  /* ── Cost savings chart ── */
  .savings-chart-container {
    position: relative;
    height: 160px;
    margin-top: 0.5rem;
  }
  .savings-chart-svg {
    width: 100%;
    height: 100%;
  }
  .savings-chart-svg .grid-line {
    stroke: var(--border);
    stroke-width: 0.5;
  }
  .savings-chart-svg .axis-label {
    fill: var(--muted);
    font-size: 9px;
    font-family: inherit;
  }
  .savings-chart-svg .line-plan {
    stroke: var(--muted);
    stroke-width: 1.5;
    stroke-dasharray: 6 3;
    fill: none;
  }
  .savings-chart-svg .line-api {
    stroke: var(--primary);
    stroke-width: 2;
    fill: none;
  }
  .savings-chart-svg .area-savings {
    opacity: 0.10;
  }
  .savings-chart-legend {
    display: flex;
    gap: 1rem;
    margin-bottom: 0.5rem;
  }
  .savings-chart-legend-item {
    display: flex;
    align-items: center;
    gap: 0.375rem;
    font-size: 0.6875rem;
    color: var(--muted);
  }
  .savings-chart-legend-line {
    width: 16px;
    height: 2px;
    border-radius: 1px;
  }
  .savings-chart-legend-line.dashed {
    background: repeating-linear-gradient(90deg, var(--muted) 0 6px, transparent 6px 9px);
    height: 2px;
  }
  .savings-chart-legend-line.solid {
    background: var(--primary);
  }
  .savings-chart-total {
    font-size: 0.8125rem;
    color: var(--foreground);
    margin-top: 0.5rem;
    text-align: center;
  }
  .savings-chart-total .saved { color: var(--green); font-weight: 600; }
  .savings-chart-total .over { color: var(--red); font-weight: 600; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-left">
      <h1>Van Damme-o-Matic</h1>
      <div class="header-sub"><span id="account-count">0</span> accounts connected<span id="current-strategy"></span><span id="probe-stats"></span></div>
    </div>
  </div>

  <div id="exhausted-banner" class="exhausted-banner" style="display:none">
    <span class="exhausted-icon">!</span>
    <span>All accounts rate-limited. Next available: <strong id="exhausted-reset"> -</strong></span>
  </div>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('accounts')">Accounts</button>
    <button class="tab" onclick="switchTab('activity')">Activity</button>
    <button class="tab" onclick="switchTab('usage')">Usage</button>
    <button class="tab" onclick="switchTab('sessions')">Sessions<span id="sessions-badge" class="tab-badge" style="display:none"></span></button>
    <button class="tab" onclick="switchTab('config')">Config</button>
    <button class="tab" onclick="switchTab('logs')">Logs</button>
  </div>

  <div id="tab-accounts" class="tab-content active">
    <div id="accounts" class="accounts">
      <div class="empty-state">Loading...</div>
    </div>
  </div>

  <div id="tab-activity" class="tab-content">
    <div id="activity-wrap" class="activity-card">
      <div id="activity-log" style="color:var(--muted);padding:2rem 0">No activity yet</div>
    </div>
  </div>

  <div id="tab-usage" class="tab-content">
    <div id="stats-section" class="usage-card" style="display:none">
      <div class="usage-title">Usage  - All Accounts</div>
      <div id="stats-grid" class="stat-grid"></div>
      <div>
        <div class="chart-legend">
          <div class="chart-legend-item"><span class="chart-legend-dot" style="background:var(--primary)"></span> Messages</div>
          <div class="chart-legend-item"><span class="chart-legend-dot" style="background:var(--purple)"></span> Tokens</div>
        </div>
        <div id="chart" class="chart-container"></div>
      </div>
    </div>
    <div class="tok-filters">
      <select class="config-select" id="tok-repo" onchange="tokFilterChange('repo')"><option value="">All repos</option></select>
      <select class="config-select" id="tok-branch" onchange="tokFilterChange('branch')"><option value="">All branches</option></select>
      <select class="config-select" id="tok-model" onchange="tokFilterChange('model')"><option value="">All models</option></select>
      <select class="config-select" id="tok-account" onchange="tokFilterChange('account')"><option value="">All accounts</option></select>
      <select class="config-select" id="tok-time" onchange="tokFilterChange('time')">
        <option value="1">1 day</option>
        <option value="7" selected>7 days</option>
        <option value="30">30 days</option>
        <option value="90">90 days</option>
      </select>
      <button class="tok-export-btn" onclick="exportUsageCsv()">Export CSV</button>
    </div>
    <div id="tok-empty" class="empty-state" style="display:none">No token usage data yet.</div>
    <div id="tok-content" style="display:none">
      <div class="usage-card chart-carousel" style="margin-bottom:1rem">
        <div class="chart-carousel-inner">
          <div class="chart-carousel-slides" id="chart-carousel-slides">
            <div class="chart-carousel-slide" id="tok-savings-chart"></div>
            <div class="chart-carousel-slide" id="tok-chart"></div>
          </div>
        </div>
        <div class="chart-carousel-dots" id="chart-carousel-dots">
          <button class="chart-carousel-dot active" onclick="chartCarouselGo(0)"></button>
          <button class="chart-carousel-dot" onclick="chartCarouselGo(1)"></button>
        </div>
      </div>
      <div id="tok-stats" class="stat-grid" style="margin-bottom:0.5rem"></div>
      <div id="tok-savings" class="tok-savings-banner"></div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Model Breakdown</div>
        <div id="tok-models"></div>
      </div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Account Breakdown</div>
        <div id="tok-accounts"></div>
      </div>
      <div class="usage-card">
        <div class="usage-title">Repository &amp; Branch</div>
        <div id="tok-repos"></div>
      </div>
    </div>
  </div>

  <div id="tab-sessions" class="tab-content">
    <div id="sessions-content">
      <div class="empty-state" id="sessions-disabled">Session Monitor is OFF. Enable it in Config (BETA).</div>
    </div>
  </div>

  <div id="tab-config" class="tab-content">
    <div class="config-card">
      <div class="config-section">
        <div class="config-section-title">Proxy</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Enable proxy</div>
            <div class="config-desc">Route Claude Code API calls through the local proxy for account switching</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-proxy" checked onchange="toggleSetting('proxyEnabled', this.checked)">
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Auto-switch on rate limit</div>
            <div class="config-desc">Automatically switch to another account when the current one hits a 429 or 401</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-autoswitch" checked onchange="toggleSetting('autoSwitch', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Rotation Strategy</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Strategy</div>
            <div class="config-desc" id="strategy-hint"></div>
          </div>
          <select class="config-select" id="sel-strategy" onchange="changeStrategy(this.value)">
            <option value="sticky">Sticky</option>
            <option value="conserve">Conserve</option>
            <option value="round-robin">Round-robin</option>
            <option value="spread">Spread</option>
            <option value="drain-first">Drain first</option>
          </select>
        </div>
        <div class="config-row" id="interval-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Rotation interval</div>
            <div class="config-desc">How often to rotate to the least-used account</div>
          </div>
          <select class="config-select" id="sel-interval" onchange="changeInterval(Number(this.value))">
            <option value="15">15 min</option>
            <option value="30">30 min</option>
            <option value="60">1 hr</option>
            <option value="120">2 hr</option>
          </select>
        </div>
        <div id="strategy-list" class="strategy-list"></div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Notifications</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Desktop notifications</div>
            <div class="config-desc">Show macOS notifications on account switches, rate limits, and errors</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-notifs" checked onchange="toggleSetting('notifications', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Request Serialization <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Serialize requests</div>
            <div class="config-desc">Queue concurrent API requests to avoid 429 collisions from multiple sessions</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-serialize" onchange="toggleSetting('serializeRequests', this.checked)">
        </div>
        <div class="config-row" id="serialize-delay-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Delay between requests</div>
            <div class="config-desc">Milliseconds to wait between dispatching queued requests</div>
          </div>
          <select class="config-select" id="sel-serialize-delay" onchange="changeSerializeDelay(Number(this.value))">
            <option value="0">0 ms</option>
            <option value="100">100 ms</option>
            <option value="200">200 ms</option>
            <option value="500">500 ms</option>
            <option value="1000">1000 ms</option>
          </select>
        </div>
        <div id="queue-stats" style="font-size:0.8125rem;color:var(--muted);margin-top:0.25rem;display:none"></div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Commit Tokens <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Token-Usage commit trailer</div>
            <div class="config-desc">Append a Token-Usage trailer to commit messages showing tokens consumed since the last commit</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-commit-tokens" onchange="toggleSetting('commitTokenUsage', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Session Monitor <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Enable session monitor</div>
            <div class="config-desc">Track active Claude Code sessions with AI-summarized timelines. Uses Haiku for summaries (separate token overhead).</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-session-monitor" onchange="toggleSetting('sessionMonitor', this.checked)">
        </div>
      </div>
    </div>
  </div>

  <div id="tab-logs" class="tab-content">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.5rem">
      <div style="font-size:0.8125rem;color:var(--muted)" id="log-status">Disconnected</div>
      <button onclick="clearLogs()" style="background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:0.25rem 0.75rem;border-radius:6px;cursor:pointer;font-size:0.75rem">Clear</button>
    </div>
    <div id="log-container" style="background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:0.75rem;font-family:'SF Mono',Monaco,Consolas,monospace;font-size:0.75rem;line-height:1.5;height:calc(100vh - 220px);overflow-y:auto;color:#c9d1d9"></div>
  </div>

</div>

<div id="toast" class="toast"></div>

<script>
function switchTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  document.querySelector('.tab[onclick*="' + id + '"]').classList.add('active');
  if (id === 'usage') refreshTokens();
  if (id === 'sessions') refreshSessions();
  if (id === 'logs') connectLogStream();
  const url = new URL(location);
  url.searchParams.set('tab', id);
  history.replaceState(null, '', url);
}

function formatNum(n) {
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function fillClass(pct) {
  if (pct >= 1) return 'fill-full';
  if (pct >= 0.8) return 'fill-high';
  if (pct >= 0.5) return 'fill-mid';
  return 'fill-ok';
}
function pctClass(pct) {
  if (pct >= 80) return 'pct-high';
  if (pct >= 50) return 'pct-mid';
  return 'pct-ok';
}

function formatTimeLeft(resetUnix) {
  if (!resetUnix) return 'rolling window';
  const diff = resetUnix - Math.floor(Date.now() / 1000);
  if (diff <= 0) return 'resetting...';
  const h = Math.floor(diff / 3600);
  const m = Math.floor((diff % 3600) / 60);
  if (h > 24) return Math.floor(h/24) + 'd ' + (h%24) + 'h left';
  if (h > 0) return h + 'h ' + m + 'm left';
  return m + 'm left';
}

function tokenStatus(expiresAt) {
  if (!expiresAt) return { text: 'Unknown', cls: '' };
  const diff = expiresAt - Date.now();
  if (diff <= 0) return { text: 'Expired', cls: 'tok-bad' };
  const h = Math.floor(diff / 3600000);
  const d = Math.floor(h / 24);
  if (d > 7) return { text: 'Valid', cls: 'tok-ok' };
  if (d >= 1) return { text: 'Expires in ' + d + 'd', cls: 'tok-warn' };
  if (h >= 1) return { text: 'Expires in ' + h + 'h', cls: 'tok-warn' };
  return { text: 'Expires soon', cls: 'tok-bad' };
}

function planBadge(subscriptionType, rateLimitTier) {
  const sub = (subscriptionType || 'free').toLowerCase();
  const tier = (rateLimitTier || '').toLowerCase();
  let label, cls;
  if (sub === 'max' || tier.indexOf('max') !== -1) {
    cls = 'badge-max';
    const m = tier.match(/(\d+)x/);
    label = m ? 'MAX ' + m[1] + 'x' : 'MAX';
  } else if (sub === 'pro' || tier.indexOf('pro') !== -1) {
    cls = 'badge-pro';
    label = 'PRO';
  } else {
    cls = 'badge-free';
    label = 'FREE';
  }
  return '<span class="badge ' + cls + '">' + label + '</span>';
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(t._tid);
  t._tid = setTimeout(() => t.classList.remove('show'), 2200);
}

async function doSwitch(name, displayName, e) {
  if (e) e.stopPropagation();
  document.querySelectorAll('.card').forEach(c => c.classList.add('switching'));
  try {
    const resp = await fetch('/api/switch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) {
      const toastName = data.label || displayName || name;
      let msg = 'Switched to ' + toastName;
      if (data.strategyChanged) msg += ' (strategy set to Sticky)';
      showToast(msg);
      if (data.strategyChanged) {
        document.getElementById('sel-strategy').value = data.strategy;
        updateStrategyUI(data.strategy);
      }
      setTimeout(refresh, 300);
    }
    else showToast('Error: ' + data.error);
  } catch(e) { showToast('Failed to switch'); }
  document.querySelectorAll('.card').forEach(c => c.classList.remove('switching'));
}

async function doRemove(name, e) {
  if (e) e.stopPropagation();
  if (!confirm('Remove account "' + name + '"? This deletes the saved credentials file.')) return;
  try {
    const resp = await fetch('/api/remove', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) { showToast('Removed ' + name); setTimeout(refresh, 300); }
    else showToast('Error: ' + data.error);
  } catch(e) { showToast('Failed to remove'); }
}

async function doRefresh(name, e) {
  if (e) e.stopPropagation();
  try {
    const resp = await fetch('/api/refresh', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) { showToast('Refreshed ' + name); setTimeout(refresh, 300); }
    else showToast('Refresh failed: ' + data.error);
  } catch(e) { showToast('Failed to refresh'); }
}

function renderProbeStats(ps) {
  const el = document.getElementById('probe-stats');
  if (!ps || !ps.probeCount7d) { el.textContent = ''; return; }
  const totalTok = ps.inputTokens + ps.outputTokens;
  el.innerHTML = ' · ' + formatNum(ps.probeCount7d) + ' probes (7d) · ~' + formatNum(totalTok) + ' tokens overhead';
}

/**
 * Render a time-axis sparkline with real clock-time labels.
 * X-axis is a simple sliding window: [now - windowMs, now].
 *
 * @param {Array} hist - history entries with { ts, u5h, u7d }
 * @param {string} key - 'u5h' or 'u7d'
 * @param {number} windowMs - fixed x-axis span in ms (24h or 7d)
 * @param {string} mode - 'hours' or 'days'  - controls label generation
 */
function renderSparkline(hist, key, windowMs, mode) {
  const W = 320, H = 44, padL = 1, padR = 1, padT = 1, padB = 12;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const now = Date.now();

  const windowEnd = now;
  const windowStart = windowEnd - windowMs;

  // Generate real-time labels
  let svg = '';
  if (mode === 'hours') {
    // Hourly grid: show labels every 6 hours, minor gridlines every 3 hours
    const stepMs = 3 * 3600000; // 3-hour gridline step
    const firstHour = new Date(windowStart);
    firstHour.setMinutes(0, 0, 0);
    firstHour.setHours(Math.ceil(firstHour.getHours() / 3) * 3);
    if (firstHour.getTime() < windowStart) firstHour.setTime(firstHour.getTime() + stepMs);
    for (let t = firstHour.getTime(); t <= windowEnd; t += stepMs) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const h = d.getHours();
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      // Only label every 6 hours to prevent overlap
      if (h % 6 === 0) {
        svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + h + ':00</text>';
      }
    }
  } else {
    // Daily grid: find the first midnight >= windowStart, then every day
    const firstDay = new Date(windowStart);
    firstDay.setHours(0, 0, 0, 0);
    if (firstDay.getTime() < windowStart) firstDay.setTime(firstDay.getTime() + 86400000);
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    for (let t = firstDay.getTime(); t <= windowEnd; t += 86400000) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const label = dayNames[d.getDay()];
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + label + '</text>';
    }
  }

  // Binary activity area: ON (utilization > 0) vs OFF, with shaded fill
  if (hist && hist.length >= 1) {
    var pts = hist.filter(function(h) { return h.ts >= windowStart && h.ts <= windowEnd; });
    // Insert synthetic OFF points when gap between consecutive points > 10 min
    // This prevents the step function from holding ON state across long idle periods
    var GAP_THRESHOLD = 10 * 60 * 1000; // 10 minutes
    var filled = [];
    for (var gi = 0; gi < pts.length; gi++) {
      filled.push(pts[gi]);
      if (gi < pts.length - 1 && (pts[gi + 1].ts - pts[gi].ts) > GAP_THRESHOLD) {
        filled.push({ ts: pts[gi].ts + GAP_THRESHOLD, u5h: 0, u7d: 0 });
      }
    }
    pts = filled;
    if (pts.length) {
      var yOn = padT, yOff = padT + chartH;
      var d = 'M' + (padL + ((pts[0].ts - windowStart) / windowMs) * chartW).toFixed(1) + ',' + yOff;
      for (var pi = 0; pi < pts.length; pi++) {
        var x = padL + ((pts[pi].ts - windowStart) / windowMs) * chartW;
        var on = (pts[pi][key] || 0) > 0;
        d += ' L' + x.toFixed(1) + ',' + (on ? yOn : yOff).toFixed(1);
        // Step to next point (hold value until next timestamp)
        if (pi < pts.length - 1) {
          var xNext = padL + ((pts[pi + 1].ts - windowStart) / windowMs) * chartW;
          d += ' L' + xNext.toFixed(1) + ',' + (on ? yOn : yOff).toFixed(1);
        }
      }
      // Close path back to baseline
      var xLast = padL + ((pts[pts.length - 1].ts - windowStart) / windowMs) * chartW;
      d += ' L' + xLast.toFixed(1) + ',' + yOff + ' Z';
      svg += '<path d="' + d + '" fill="var(--primary)" opacity="0.25" />';
      // Top edge line for clarity
      var edge = '';
      for (var ei = 0; ei < pts.length; ei++) {
        var ex = padL + ((pts[ei].ts - windowStart) / windowMs) * chartW;
        var eOn = (pts[ei][key] || 0) > 0;
        edge += (ei === 0 ? 'M' : ' L') + ex.toFixed(1) + ',' + (eOn ? yOn : yOff).toFixed(1);
        if (ei < pts.length - 1) {
          var exNext = padL + ((pts[ei + 1].ts - windowStart) / windowMs) * chartW;
          edge += ' L' + exNext.toFixed(1) + ',' + (eOn ? yOn : yOff).toFixed(1);
        }
      }
      svg += '<path d="' + edge + '" fill="none" stroke="var(--primary)" stroke-width="1" />';
    }
  }

  return '<svg class="sparkline-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '">' + svg + '</svg>';
}

function formatEta(minutes) {
  if (minutes < 5) return '<5m';
  // Round to nearest 10 minutes
  const rounded = Math.round(minutes / 10) * 10;
  if (rounded <= 0) return '<5m';
  const h = Math.floor(rounded / 60);
  const m = rounded % 60;
  return h + ':' + String(m).padStart(2, '0');
}

function renderVelocityInline(p) {
  if (p.minutesToLimit == null) return '';
  const min = p.minutesToLimit;
  let cls = 'velocity-badge';
  let text;
  if (min <= 0) { cls += ' velocity-crit'; text = 'at limit'; }
  else if (min < 300) { cls += ' velocity-crit'; text = 'Est. ' + formatEta(min) + ' to limit'; }
  else { cls += ' velocity-ok'; text = '>5hr to limit'; }
  return '<span class="card-token-sep">&middot;</span>' +
    '<span class="' + cls + '" title="Estimated time until 5h rate limit is reached, based on current usage velocity">' + text + '</span>';
}

let _lastProfilesHash = '';
var _cachedProfiles = [];
let _lastActivityHash = '';
let _lastStatsHash = '';
let _firstRender = true;
const _sparkCache = {};

function quickHash(obj) {
  return JSON.stringify(obj);
}

async function refresh() {
  try {
    const resp = await fetch('/api/profiles');
    const { profiles, stats, probeStats, allExhausted, earliestReset, rotationStrategy, queueStats } = await resp.json();
    _cachedProfiles = profiles;
    const ph = quickHash(profiles);
    if (ph !== _lastProfilesHash) {
      _lastProfilesHash = ph;
      renderAccounts(profiles, _firstRender);
    }
    document.getElementById('account-count').textContent = profiles.length;
    if (rotationStrategy) {
      const strategyNames = { sticky: 'Sticky', conserve: 'Conserve', 'round-robin': 'Round-robin', spread: 'Spread', 'drain-first': 'Drain first' };
      document.getElementById('current-strategy').textContent = ' \\u00b7 ' + (strategyNames[rotationStrategy] || rotationStrategy);
    }
    if (probeStats) renderProbeStats(probeStats);
    // [BETA] Queue stats
    if (queueStats) {
      var qEl = document.getElementById('queue-stats');
      if (queueStats.inflight > 0 || queueStats.queued > 0) {
        qEl.style.display = '';
        qEl.textContent = 'Queue: ' + queueStats.inflight + ' inflight, ' + queueStats.queued + ' queued';
      } else {
        qEl.style.display = 'none';
      }
    }
    // Exhausted banner
    const banner = document.getElementById('exhausted-banner');
    if (allExhausted) {
      banner.style.display = '';
      document.getElementById('exhausted-reset').textContent = earliestReset || 'unknown';
    } else {
      banner.style.display = 'none';
    }
    if (stats) {
      const sh = quickHash(stats);
      if (sh !== _lastStatsHash) {
        _lastStatsHash = sh;
        renderStats(stats);
      }
    }
  } catch(e) { console.error('Refresh:', e); }
  try {
    const resp = await fetch('/api/activity');
    const log = (await resp.json()).log || [];
    const ah = quickHash(log);
    if (ah !== _lastActivityHash) {
      _lastActivityHash = ah;
      renderActivity(log);
    }
  } catch {}
  _firstRender = false;
  refreshTokens();
  // Only fetch sessions when the tab is active or periodically for badge updates
  var sessTab = document.getElementById('tab-sessions');
  if (sessTab && sessTab.classList.contains('active')) {
    refreshSessions();
  } else {
    refreshSessionsBadgeOnly();
  }
}

function renderAccounts(profiles, animate) {
  const el = document.getElementById('accounts');
  if (!profiles.length) {
    el.innerHTML = '<div class="empty-state">No accounts yet. Run <code>/login</code> in Claude Code  - accounts are auto-discovered.</div>';
    return;
  }
  el.innerHTML = profiles.map((p, i) => {
    const active = p.isActive;
    const displayName = p.label || p.name;
    const eName = p.name.replace(/'/g, "\\\\'");
    const tok = tokenStatus(p.expiresAt);

    let barsHtml = '';
    if (p.rateLimits) {
      const rl = p.rateLimits;
      const f = Math.round(rl.fiveH.utilization * 100);
      const s = Math.round(rl.sevenD.utilization * 100);

      // 5hr sparkline  - 24h sliding window
      const hist5h = p.utilizationHistory || [];
      const spark5h = '<div class="sparkline-wrap">' +
        renderSparkline(hist5h, 'u5h', 24*60*60*1000, 'hours') +
        '</div>';

      // Weekly sparkline  - 7d sliding window
      const hist7d = p.weeklyHistory || [];
      const spark7d = '<div class="sparkline-wrap">' +
        renderSparkline(hist7d, 'u7d', 7*24*60*60*1000, 'days') +
        '</div>';

      barsHtml = '<div class="rate-bars">' +
        '<div class="rate-group">' +
          '<div class="rate-head"><span class="rate-label">5h window</span><span class="rate-pct ' + pctClass(f) + '">' + f + '%</span></div>' +
          '<div class="rate-track"><div class="rate-fill ' + fillClass(rl.fiveH.utilization) + '" style="width:' + Math.min(f,100) + '%"></div></div>' +
          '<div class="rate-reset" data-reset="' + rl.fiveH.reset + '">' + formatTimeLeft(rl.fiveH.reset) + '</div>' +
          spark5h +
        '</div>' +
        '<div class="rate-group">' +
          '<div class="rate-head"><span class="rate-label">Weekly</span><span class="rate-pct ' + pctClass(s) + '">' + s + '%</span></div>' +
          '<div class="rate-track"><div class="rate-fill ' + fillClass(rl.sevenD.utilization) + '" style="width:' + Math.min(s,100) + '%"></div></div>' +
          '<div class="rate-reset" data-reset="' + rl.sevenD.reset + '">' + formatTimeLeft(rl.sevenD.reset) + '</div>' +
          spark7d +
        '</div>' +
      '</div>';
    } else if (p.dormant) {
      barsHtml = '<div style="font-size:0.8125rem;color:var(--cyan);margin-top:0.25rem;font-weight:500">Dormant  - window preserved</div>';
    } else {
      barsHtml = '<div style="font-size:0.8125rem;color:var(--muted);margin-top:0.25rem">Rate limits unavailable</div>';
    }

    const animStyle = animate ? ' style="animation-delay:' + (i*0.05) + 's"' : ' style="animation:none"';
    const isStale = !active && (p.expired || p.refreshFailed || (p.expiresAt && p.expiresAt < Date.now()));
    var staleMsg = '';
    if (isStale) {
      if (p.refreshFailed && !p.refreshFailed.retriable) {
        staleMsg = '<div class="stale-msg">Token expired. Click Refresh or run <code>claude login</code> to reactivate.</div>';
      } else {
        staleMsg = '<div class="stale-msg">Token expired. Auto-refresh will retry shortly.</div>';
      }
    }
    var cardClass = 'card' + (active ? ' active' : '') + (isStale ? ' stale' : '');
    var buttonsHtml = '';
    if (!active) {
      buttonsHtml = '<div style="margin-top:0.875rem;display:flex;justify-content:space-between;align-items:center">' +
        '<button class="remove-btn" onclick="doRemove(\\''+eName+'\\',event)">Remove</button>' +
        (isStale ? '<button class="refresh-btn" onclick="doRefresh(\\''+eName+'\\',event)">Refresh</button>' : '<button class="switch-btn" onclick="doSwitch(\\''+eName+'\\',\\''+displayName.replace(/'/g, "\\\\'")+'\\''+',event)">Switch to this account</button>') +
      '</div>';
    }
    return '<div class="' + cardClass + '"' + animStyle + '>' +
      '<div class="card-top">' +
        '<div class="card-identity">' +
          '<div class="status-dot ' + (active ? 'active' : 'inactive') + '"></div>' +
          '<span class="card-name">' + displayName + '</span>' +
          (active ? renderVelocityInline(p) : '') +
        '</div>' +
        '<div class="card-badges">' +
          planBadge(p.subscriptionType, p.rateLimitTier) +
          (active ? '<span class="badge badge-active">Active</span>' : '') +
        '</div>' +
      '</div>' +
      barsHtml +
      staleMsg +
      buttonsHtml +
    '</div>';
  }).join('');
}

const MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];

const evtColors = {
  'auto-switch': 'var(--cyan)', 'proactive-switch': 'var(--purple)',
  'manual-switch': 'var(--primary)', 'rate-limited': 'var(--yellow)',
  'auth-expired': 'var(--red)', 'all-exhausted': 'var(--red)',
  'account-discovered': 'var(--green)', 'account-renamed': 'var(--muted)',
  'settings-changed': 'var(--muted)',
  'upgrade': 'var(--green)',
  'refresh-failed': 'var(--red)', 'token-refreshed': 'var(--green)',
};

function evtMsg(e) {
  switch (e.type) {
    case 'auto-switch': return 'Auto-switched from <b>' + (e.from||'?') + '</b> to <b>' + (e.to||'?') + '</b>';
    case 'proactive-switch': return 'Proactive switch to <b>' + (e.to||'?') + '</b>';
    case 'manual-switch': return 'Switched to <b>' + (e.to||'?') + '</b>';
    case 'rate-limited': return '<b>' + (e.account||'?') + '</b> rate limited' + (e.retryAfter ? ' (' + Math.round(e.retryAfter/60) + ' min)' : '');
    case 'auth-expired': return '<b>' + (e.account||'?') + '</b> token expired';
    case 'all-exhausted': return 'All accounts exhausted';
    case 'account-discovered': return 'Discovered <b>' + (e.label||e.name||'?') + '</b>';
    case 'account-renamed': return 'Renamed <b>' + (e.name||'?') + '</b> to <b>' + (e.label||'?') + '</b>';
    case 'settings-changed': return 'Settings updated';
    case 'upgrade': return 'Upgraded to <b>' + (e.to||'?') + '</b>';
    case 'refresh-failed': return '<b>' + (e.account||'?') + '</b> refresh failed: ' + (e.error||'unknown');
    case 'token-refreshed': return '<b>' + (e.account||'?') + '</b> token refreshed';
    default: return e.type;
  }
}

function evtTime(ts) {
  const d = new Date(ts);
  const now = new Date();
  const time = d.toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
  if (d.toDateString() === now.toDateString()) return time;
  const y = new Date(now); y.setDate(y.getDate()-1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday ' + time;
  return d.getDate() + ' ' + MONTHS[d.getMonth()] + ' ' + time;
}

function renderActivity(log) {
  const el = document.getElementById('activity-log');
  if (!log.length) { el.innerHTML = '<div style="color:var(--muted);padding:2rem 0">No activity yet</div>'; return; }
  el.innerHTML = log.map(e => {
    const c = evtColors[e.type] || 'var(--muted)';
    return '<div class="evt">' +
      '<span class="evt-time">' + evtTime(e.ts) + '</span>' +
      '<span class="evt-dot" style="background:' + c + '"></span>' +
      '<span class="evt-msg">' + evtMsg(e) + '</span>' +
    '</div>';
  }).join('');
}

function formatChartDate(iso) {
  const p = iso.split('-');
  return parseInt(p[2],10) + ' ' + MONTHS[parseInt(p[1],10)-1];
}

function renderStats(stats) {
  document.getElementById('stats-section').style.display = '';
  const grid = document.getElementById('stats-grid');
  const totalTokens = Object.values(stats.modelUsage||{}).reduce((s,m) => s + (m.inputTokens||0) + (m.outputTokens||0), 0);
  const totalCache = Object.values(stats.modelUsage||{}).reduce((s,m) => s + (m.cacheReadInputTokens||0), 0);
  grid.innerHTML = [
    { v: formatNum(stats.totalSessions||0), l: 'Sessions' },
    { v: formatNum(stats.totalMessages||0), l: 'Messages' },
    { v: formatNum(totalTokens), l: 'Tokens' },
    { v: formatNum(totalCache), l: 'Cache Reads' },
  ].map(s => '<div class="stat-item"><div class="stat-val">' + s.v + '</div><div class="stat-label">' + s.l + '</div></div>').join('');

  const tokenMap = {};
  (stats.dailyModelTokens||[]).forEach(d => {
    tokenMap[d.date] = Object.values(d.tokensByModel||{}).reduce((s,v)=>s+v,0);
  });
  const daily = (stats.dailyActivity||[]).slice(-14);
  if (daily.length) {
    const maxMsg = Math.max(...daily.map(d => d.messageCount||0), 1);
    const maxTok = Math.max(...daily.map(d => tokenMap[d.date]||0), 1);
    const H = 115;
    document.getElementById('chart').innerHTML = daily.map(d => {
      const msgs = d.messageCount||0;
      const toks = tokenMap[d.date]||0;
      const hM = Math.max(3, (msgs/maxMsg)*H);
      const hT = Math.max(3, (toks/maxTok)*H);
      const lbl = formatChartDate(d.date);
      return '<div class="chart-day"><div class="chart-bars">' +
        '<div class="chart-bar msg-bar" style="height:'+hM+'px" data-tooltip="'+lbl+': '+formatNum(msgs)+' msgs"></div>' +
        '<div class="chart-bar tok-bar" style="height:'+hT+'px" data-tooltip="'+lbl+': '+formatNum(toks)+' tokens"></div>' +
      '</div><div class="chart-label">'+lbl+'</div></div>';
    }).join('');
  }
}

function tickCountdowns() {
  document.querySelectorAll('[data-reset]').forEach(el => {
    el.textContent = formatTimeLeft(Number(el.dataset.reset));
  });
}

const STRATEGY_HINTS = {
  sticky: 'Stays on current account. Only switches when rate-limited (429/401).',
  conserve: 'Drains active accounts first (weekly limit primary). Untouched accounts stay dormant  - their windows never start.',
  'round-robin': 'Rotates to the least-used account on a timer. Good balance of safety and efficiency.',
  spread: 'Picks the least-used account on every request. Switches often  - may trigger Anthropic notices.',
  'drain-first': 'Uses the account with highest 5hr utilization first. Good for short sessions.',
};

async function loadSettingsUI() {
  try {
    const s = await (await fetch('/api/settings')).json();
    document.getElementById('toggle-proxy').checked = s.proxyEnabled;
    document.getElementById('toggle-autoswitch').checked = s.autoSwitch;
    document.getElementById('toggle-notifs').checked = s.notifications !== false;
    document.getElementById('sel-strategy').value = s.rotationStrategy || 'conserve';
    document.getElementById('sel-interval').value = s.rotationIntervalMin || 60;
    updateStrategyUI(s.rotationStrategy || 'conserve');
    // [BETA] Serialization
    document.getElementById('toggle-serialize').checked = !!s.serializeRequests;
    document.getElementById('sel-serialize-delay').value = s.serializeDelayMs || 200;
    document.getElementById('serialize-delay-ctrl').style.display = s.serializeRequests ? '' : 'none';
    // Commit token usage
    document.getElementById('toggle-commit-tokens').checked = !!s.commitTokenUsage;
    // Session monitor
    document.getElementById('toggle-session-monitor').checked = !!s.sessionMonitor;
  } catch {}
}

const STRATEGY_DETAILS = {
  sticky:        { name: 'Sticky',      desc: 'Stay on the current account until it hits a rate limit (429) or auth error (401). Never switches proactively  - minimal disruption.' },
  conserve:      { name: 'Conserve',    desc: 'Concentrate usage on accounts whose rate-limit windows are already active. Untouched accounts stay dormant so their 5hr and weekly windows never start  - maximizes total available capacity over time.' },
  'round-robin': { name: 'Round-robin', desc: 'Rotate to the least-used account on a fixed timer. Balances load evenly while limiting switch frequency.' },
  spread:        { name: 'Spread',      desc: 'Always pick the account with the lowest 5hr utilization on every request. Switches often  - best for short, bursty sessions.' },
  'drain-first': { name: 'Drain first', desc: 'Use the account with the highest 5hr utilization first, draining it before moving on. Good for finishing off nearly-exhausted windows.' },
};

function updateStrategyUI(strategy) {
  document.getElementById('interval-ctrl').style.display = strategy === 'round-robin' ? '' : 'none';
  document.getElementById('strategy-hint').textContent = STRATEGY_HINTS[strategy] || '';
  const list = document.getElementById('strategy-list');
  list.innerHTML = Object.entries(STRATEGY_DETAILS).map(([key, s]) =>
    '<div class="strategy-item' + (key === strategy ? ' active' : '') + '">' +
      '<span class="strategy-item-name">' + s.name + '</span>' +
      '<span class="strategy-item-desc">' + s.desc + '</span>' +
    '</div>'
  ).join('');
}

async function toggleSetting(key, value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ [key]: value })
    });
    const msgs = {
      proxyEnabled: value ? 'Proxy enabled' : 'Proxy disabled  - passthrough mode',
      autoSwitch: value ? 'Auto-switch enabled' : 'Auto-switch disabled',
      notifications: value ? 'Notifications enabled' : 'Notifications disabled',
      serializeRequests: value ? 'Request serialization enabled' : 'Request serialization disabled',
      commitTokenUsage: value ? 'Commit token trailer enabled' : 'Commit token trailer disabled',
    };
    showToast(msgs[key] || (key + ' = ' + value));
    // Show/hide serialize delay control
    if (key === 'serializeRequests') {
      document.getElementById('serialize-delay-ctrl').style.display = value ? '' : 'none';
    }
  } catch { showToast('Failed to update'); }
}

async function changeSerializeDelay(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ serializeDelayMs: value })
    });
    showToast('Serialize delay: ' + value + ' ms');
  } catch { showToast('Failed to update'); }
}

async function changeStrategy(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rotationStrategy: value })
    });
    updateStrategyUI(value);
    showToast('Rotation: ' + (document.getElementById('sel-strategy').selectedOptions[0]?.text || value));
  } catch { showToast('Failed to update'); }
}

async function changeInterval(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rotationIntervalMin: value })
    });
    showToast('Rotation interval: ' + (value >= 60 ? (value/60) + ' hr' : value + ' min'));
  } catch { showToast('Failed to update'); }
}

// ── Tokens tab ──

var TOK_COLORS = ['var(--primary)', 'var(--purple)', 'var(--cyan)', 'var(--green)', 'var(--yellow)', 'var(--red)'];

var TOK_PRICING = {
  'claude-opus-4-6': { input: 15, output: 75 },
  'claude-sonnet-4-6': { input: 3, output: 15 },
  'claude-haiku-4-5': { input: 0.80, output: 4 },
};
var TOK_PRICING_DEFAULT = { input: 3, output: 15 };
var TOK_PLANS = {
  'pro':    { label: 'Pro ($20/mo)', monthly: 20 },
  'max5x':  { label: 'MAX 5x ($100/mo)', monthly: 100 },
  'max20x': { label: 'MAX 20x ($200/mo)', monthly: 200 },
};
var _tokPrevPeriodData = [];
var _tokRepoCollapsed = {};

function estimateCost(model, inTok, outTok) {
  var key = Object.keys(TOK_PRICING).find(function(k) { return model && model.indexOf(k) === 0; });
  var p = key ? TOK_PRICING[key] : TOK_PRICING_DEFAULT;
  return (inTok / 1e6) * p.input + (outTok / 1e6) * p.output;
}

function formatCost(dollars) {
  if (dollars === 0) return '$0.00';
  if (dollars < 0.01) return '&lt;$0.01';
  if (dollars < 100) return '$' + dollars.toFixed(2);
  return '$' + Math.round(dollars).toLocaleString();
}

function toggleRepoCollapse(repoKey) {
  _tokRepoCollapsed[repoKey] = !_tokRepoCollapsed[repoKey];
  renderRepoBranchBreakdown(_tokFilteredData || []);
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function shortModel(m) {
  if (!m) return 'unknown';
  var s = m.replace(/^claude-/, '').replace(/-\\d{8}$/, '');
  var match = s.match(/^([a-z]+(?:-[a-z]+)*)-(\\d+(?:-\\d+)*)$/);
  if (match) return match[1] + ' ' + match[2].replace(/-/g, '.');
  return s;
}

function getModelColor(model, sortedModels) {
  var idx = sortedModels.indexOf(model);
  if (idx < 0) idx = 0;
  return TOK_COLORS[idx % TOK_COLORS.length];
}

var _lastTokensHash = '';
var _tokensRawData = [];
var _tok30dData = [];
var _tokFilteredData = [];
var _tokFetching = false;
var _tokNeedsRefresh = false;

function tokTimeRange() {
  var sel = document.getElementById('tok-time');
  return sel ? parseInt(sel.value, 10) || 7 : 7;
}

async function refreshTokens() {
  var tab = document.getElementById('tab-usage');
  if (!tab || !tab.classList.contains('active')) return;
  if (_tokFetching) { _tokNeedsRefresh = true; return; }
  _tokFetching = true;
  _tokNeedsRefresh = false;
  try {
    var days = tokTimeRange();
    var now = Date.now();
    var currentCutoff = now - days * 24 * 60 * 60 * 1000;
    var since = now - Math.max(2 * days, 30) * 24 * 60 * 60 * 1000;
    var url = '/api/token-usage?since=' + since;
    var repoSel = document.getElementById('tok-repo');
    var branchSel = document.getElementById('tok-branch');
    if (repoSel && repoSel.value) url += '&repo=' + encodeURIComponent(repoSel.value);
    if (branchSel && branchSel.value) url += '&branch=' + encodeURIComponent(branchSel.value);
    var resp = await fetch(url);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    if (!Array.isArray(data)) data = [];
    var hash = quickHash(data);
    if (hash === _lastTokensHash) return;
    _lastTokensHash = hash;
    var cutoff30d = now - 30 * 24 * 60 * 60 * 1000;
    _tok30dData = data.filter(function(e) { return (e.timestamp || e.ts || 0) >= cutoff30d; });
    _tokensRawData = data.filter(function(e) { return (e.timestamp || e.ts || 0) >= currentCutoff; });
    _tokPrevPeriodData = data.filter(function(e) { var t = e.timestamp || e.ts || 0; return t < currentCutoff; });
    applyTokenModelFilter();
  } catch (e) {
    console.error('Token fetch:', e);
    // Show empty state on error if no cached data
    if (!_tokensRawData.length) {
      var content = document.getElementById('tok-content');
      var empty = document.getElementById('tok-empty');
      if (content) content.style.display = 'none';
      if (empty) empty.style.display = '';
    }
  } finally {
    _tokFetching = false;
    if (_tokNeedsRefresh) refreshTokens();
  }
}

function applyTokenModelFilter() {
  var data = _tokensRawData;
  var prevData = _tokPrevPeriodData;
  var modelSel = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  if (modelSel && modelSel.value) {
    data = data.filter(function(e) { return e.model === modelSel.value; });
    prevData = prevData.filter(function(e) { return e.model === modelSel.value; });
  }
  if (accountSel && accountSel.value) {
    data = data.filter(function(e) { return e.account === accountSel.value; });
    prevData = prevData.filter(function(e) { return e.account === accountSel.value; });
  }
  _tokFilteredData = data;
  populateTokenFilters(_tokensRawData);
  renderTokenStats(data, prevData);
  renderDailyChart(data);
  renderCostSavingsChart();
  renderModelBreakdown(data);
  renderAccountBreakdown(data);
  renderRepoBranchBreakdown(data);
}

function populateTokenFilters(data) {
  var repoSel = document.getElementById('tok-repo');
  var branchSel = document.getElementById('tok-branch');
  var modelSel = document.getElementById('tok-model');
  var accountSel = document.getElementById('tok-account');
  if (!repoSel || !branchSel || !modelSel) return;
  var prevRepo = repoSel.value;
  var prevBranch = branchSel.value;
  var prevModel = modelSel.value;
  var prevAccount = accountSel ? accountSel.value : '';
  var repoSet = {}, modelSet = {}, accountSet = {};
  for (var i = 0; i < data.length; i++) {
    if (data[i].repo) repoSet[data[i].repo] = 1;
    if (data[i].model) modelSet[data[i].model] = 1;
    if (data[i].account) accountSet[data[i].account] = 1;
  }
  var repos = Object.keys(repoSet).sort();
  repoSel.innerHTML = '<option value="">All repos</option>' +
    repos.map(function(r) {
      return '<option value="' + escHtml(r) + '"' + (r === prevRepo ? ' selected' : '') + '>' + escHtml(r.split('/').pop()) + '</option>';
    }).join('');
  var branchData = prevRepo ? data.filter(function(e) { return e.repo === prevRepo; }) : data;
  var filteredBranches = {};
  for (var j = 0; j < branchData.length; j++) {
    if (branchData[j].branch) filteredBranches[branchData[j].branch] = 1;
  }
  var branches = Object.keys(filteredBranches).sort();
  branchSel.innerHTML = '<option value="">All branches</option>' +
    branches.map(function(b) {
      return '<option value="' + escHtml(b) + '"' + (b === prevBranch ? ' selected' : '') + '>' + escHtml(b) + '</option>';
    }).join('');
  var models = Object.keys(modelSet).sort();
  modelSel.innerHTML = '<option value="">All models</option>' +
    models.map(function(m) {
      return '<option value="' + escHtml(m) + '"' + (m === prevModel ? ' selected' : '') + '>' + escHtml(shortModel(m)) + '</option>';
    }).join('');
  if (accountSel) {
    var accounts = Object.keys(accountSet).sort();
    accountSel.innerHTML = '<option value="">All accounts</option>' +
      accounts.map(function(a) {
        return '<option value="' + escHtml(a) + '"' + (a === prevAccount ? ' selected' : '') + '>' + escHtml(a) + '</option>';
      }).join('');
  }
}

function renderTokenStats(data, prevData) {
  var content = document.getElementById('tok-content');
  var empty = document.getElementById('tok-empty');
  if (!content || !empty) return;
  if (!data.length) {
    content.style.display = 'none';
    empty.style.display = '';
    return;
  }
  content.style.display = '';
  empty.style.display = 'none';
  var totalIn = 0, totalOut = 0, requests = 0, totalCost = 0;
  for (var i = 0; i < data.length; i++) {
    var inT = data[i].inputTokens || 0;
    var outT = data[i].outputTokens || 0;
    totalIn += inT;
    totalOut += outT;
    totalCost += estimateCost(data[i].model, inT, outT);
    requests++;
  }
  var trendHtml = '';
  if (prevData && prevData.length) {
    var prevTotal = 0;
    for (var p = 0; p < prevData.length; p++) prevTotal += (prevData[p].inputTokens || 0) + (prevData[p].outputTokens || 0);
    if (prevTotal > 0) {
      var curTotal = totalIn + totalOut;
      var pctChange = Math.round(((curTotal - prevTotal) / prevTotal) * 100);
      if (pctChange !== 0) {
        var arrow = pctChange > 0 ? '\u2191' : '\u2193';
        var cls = pctChange > 0 ? 'up' : 'down';
        trendHtml = '<div class="tok-trend ' + cls + '">' + arrow + ' ' + Math.abs(pctChange) + '% vs prev period</div>';
      }
    }
  }
  var statsEl = document.getElementById('tok-stats');
  if (statsEl) statsEl.innerHTML = [
    { v: formatNum(totalIn + totalOut), l: 'Total Tokens', extra: trendHtml },
    { v: formatNum(totalIn), l: 'Input' },
    { v: formatNum(totalOut), l: 'Output' },
    { v: formatNum(requests), l: 'Requests' },
    { v: formatCost(totalCost), l: 'API Equiv.', sub: 'at API rates' },
  ].map(function(s) {
    var h = '<div class="stat-item"><div class="stat-val">' + s.v + '</div><div class="stat-label">' + s.l + '</div>';
    if (s.sub) h += '<div class="tok-stat-sub">' + s.sub + '</div>';
    if (s.extra) h += s.extra;
    return h + '</div>';
  }).join('');
  // Savings banner — daily rate comparison
  var savingsEl = document.getElementById('tok-savings');
  if (savingsEl) {
    var days = tokTimeRange();
    var planSel = document.getElementById('tok-plan');
    var planKey = planSel ? planSel.value : 'max5x';
    var plan = TOK_PLANS[planKey] || TOK_PLANS['max5x'];
    var planDaily = plan.monthly / 30;
    var apiDaily = days > 0 ? totalCost / days : 0;
    var savedDaily = apiDaily - planDaily;
    var opts = Object.keys(TOK_PLANS).map(function(k) {
      return '<option value="' + k + '"' + (k === planKey ? ' selected' : '') + '>' + TOK_PLANS[k].label + '</option>';
    }).join('');
    var msg;
    if (savedDaily > 0) {
      msg = 'saves you ~<span class="tok-savings-val">' + formatCost(savedDaily) + '/day</span> vs API rates (' + formatCost(planDaily) + '/day plan vs ' + formatCost(apiDaily) + '/day API)';
    } else {
      msg = 'costs ' + formatCost(planDaily) + '/day \u00b7 API equiv ' + formatCost(apiDaily) + '/day';
    }
    savingsEl.innerHTML = 'Your <select id="tok-plan" onchange="applyTokenModelFilter()">' + opts + '</select> ' + msg;
  }
}

function renderModelBreakdown(data) {
  var el = document.getElementById('tok-models');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var modelMap = {};
  for (var i = 0; i < data.length; i++) {
    var m = data[i].model || 'unknown';
    if (!modelMap[m]) modelMap[m] = { input: 0, output: 0, total: 0 };
    modelMap[m].input += data[i].inputTokens || 0;
    modelMap[m].output += data[i].outputTokens || 0;
    modelMap[m].total += (data[i].inputTokens || 0) + (data[i].outputTokens || 0);
  }
  var sortedModels = Object.keys(modelMap).sort().filter(function(k) { return modelMap[k].total > 0; });
  if (!sortedModels.length) { el.innerHTML = ''; return; }
  var grandTotal = 0;
  for (var j = 0; j < sortedModels.length; j++) grandTotal += modelMap[sortedModels[j]].total;
  if (!grandTotal) grandTotal = 1;
  var propBar = '<div class="tok-proportion">';
  for (var k = 0; k < sortedModels.length; k++) {
    var pct = (modelMap[sortedModels[k]].total / grandTotal) * 100;
    propBar += '<div class="tok-proportion-seg" style="width:'+pct+'%;background:'+getModelColor(sortedModels[k], sortedModels)+'"></div>';
  }
  propBar += '</div>';
  var rows = '';
  for (var r = 0; r < sortedModels.length; r++) {
    var md = modelMap[sortedModels[r]];
    var pctR = Math.round((md.total / grandTotal) * 100);
    var mdCost = estimateCost(sortedModels[r], md.input, md.output);
    rows += '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:'+getModelColor(sortedModels[r], sortedModels)+'"></div>' +
      '<div class="tok-model-name">'+escHtml(shortModel(sortedModels[r]))+'</div>' +
      '<div class="tok-model-detail">'+formatNum(md.input)+' in / '+formatNum(md.output)+' out</div>' +
      '<div class="tok-model-total">'+formatNum(md.total)+'</div>' +
      '<div class="tok-model-cost">'+formatCost(mdCost)+'</div>' +
      '<div class="tok-model-pct">'+pctR+'%</div>' +
    '</div>';
  }
  el.innerHTML = propBar + rows;
}

function renderDailyChart(data) {
  var el = document.getElementById('tok-chart');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var days = tokTimeRange();
  var now = Date.now();
  var buckets, labelFn, bucketCount;
  if (days === 1) {
    bucketCount = 24;
    labelFn = function(idx) { return idx + 'h'; };
  } else if (days <= 30) {
    bucketCount = days;
    labelFn = function(idx) {
      var d = new Date(now - (days - 1 - idx) * 86400000);
      return (d.getMonth()+1) + '/' + d.getDate();
    };
  } else {
    bucketCount = 13;
    labelFn = function(idx) {
      var d = new Date(now - (12 - idx) * 7 * 86400000);
      return (d.getMonth()+1) + '/' + d.getDate();
    };
  }
  // Collect all models
  var allModels = {};
  for (var i = 0; i < data.length; i++) allModels[data[i].model || 'unknown'] = 1;
  var sortedModels = Object.keys(allModels).sort();
  // Init buckets
  buckets = [];
  for (var b = 0; b < bucketCount; b++) {
    var obj = { total: 0 };
    for (var mi = 0; mi < sortedModels.length; mi++) obj[sortedModels[mi]] = 0;
    buckets.push(obj);
  }
  // Fill buckets
  var periodStart = days === 1
    ? now - 24 * 3600000
    : days <= 30
      ? now - days * 86400000
      : now - 13 * 7 * 86400000;
  for (var j = 0; j < data.length; j++) {
    var ts = data[j].timestamp || data[j].ts || 0;
    var tok = (data[j].inputTokens || 0) + (data[j].outputTokens || 0);
    var elapsed = ts - periodStart;
    if (elapsed < 0) continue;
    var idx;
    if (days === 1) {
      idx = Math.floor(elapsed / 3600000);
    } else if (days <= 30) {
      idx = Math.floor(elapsed / 86400000);
    } else {
      idx = Math.floor(elapsed / (7 * 86400000));
    }
    if (idx >= bucketCount) idx = bucketCount - 1;
    if (idx < 0) idx = 0;
    var model = data[j].model || 'unknown';
    buckets[idx][model] = (buckets[idx][model] || 0) + tok;
    buckets[idx].total += tok;
  }
  var maxTotal = Math.max.apply(null, buckets.map(function(b) { return b.total; })) || 1;
  // Build legend
  var legend = '<div class="chart-legend">';
  for (var li = 0; li < sortedModels.length; li++) {
    legend += '<div class="chart-legend-item"><span class="chart-legend-dot" style="background:' + getModelColor(sortedModels[li], sortedModels) + '"></span> ' + escHtml(shortModel(sortedModels[li])) + '</div>';
  }
  legend += '</div>';
  // Build bars
  var showLabel = bucketCount <= 31;
  var bars = '<div class="tok-chart-wrap">';
  for (var k = 0; k < bucketCount; k++) {
    var bucket = buckets[k];
    var stackH = Math.round((bucket.total / maxTotal) * 120);
    bars += '<div class="tok-chart-bar-group">';
    bars += '<div class="tok-chart-bar-area"><div class="tok-chart-stack" style="height:' + stackH + 'px">';
    for (var si = 0; si < sortedModels.length; si++) {
      var segVal = bucket[sortedModels[si]] || 0;
      if (segVal <= 0) continue;
      var segH = Math.max(1, Math.round((segVal / bucket.total) * stackH));
      bars += '<div class="tok-chart-seg" style="height:' + segH + 'px;background:' + getModelColor(sortedModels[si], sortedModels) + '" data-tooltip="' + escHtml(shortModel(sortedModels[si])) + ': ' + formatNum(segVal) + '"></div>';
    }
    bars += '</div></div>';
    if (showLabel) {
      bars += '<div class="tok-chart-label">' + labelFn(k) + '</div>';
    }
    bars += '</div>';
  }
  bars += '</div>';
  var chartTitle = days === 1 ? 'Hourly Usage' : days <= 30 ? 'Daily Usage' : 'Weekly Usage';
  el.innerHTML = '<div class="usage-title">' + chartTitle + '</div>' + legend + bars;
}

var _chartCarouselIdx = 0;
var _chartCarouselTimer = null;
function chartCarouselGo(idx) {
  _chartCarouselIdx = idx;
  var slides = document.getElementById('chart-carousel-slides');
  var dots = document.getElementById('chart-carousel-dots');
  if (slides) slides.style.transform = 'translateX(-' + (idx * 100) + '%)';
  if (dots) {
    var btns = dots.querySelectorAll('.chart-carousel-dot');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('active', i === idx);
    }
  }
  clearInterval(_chartCarouselTimer);
  _chartCarouselTimer = setInterval(chartCarouselNext, 10000);
}
function chartCarouselNext() {
  var dots = document.getElementById('chart-carousel-dots');
  var count = dots ? dots.querySelectorAll('.chart-carousel-dot').length : 2;
  chartCarouselGo((_chartCarouselIdx + 1) % count);
}
_chartCarouselTimer = setInterval(chartCarouselNext, 10000);

function getPlanMonthlyCost(subscriptionType, rateLimitTier) {
  var sub = (subscriptionType || '').toLowerCase();
  var tier = (rateLimitTier || '').toLowerCase();
  // Infer subscription type from tier string when subscriptionType is missing/unknown
  var isMax = sub === 'max' || tier.indexOf('max') !== -1;
  var isPro = sub === 'pro' || tier.indexOf('pro') !== -1;
  if (isMax) {
    var m = tier.match(/(\d+)x/);
    if (m) {
      var mult = parseInt(m[1], 10);
      if (mult >= 20) return 200;
      return 100;
    }
    return 100;
  }
  if (isPro) return 20;
  return 0;
}

function renderCostSavingsChart() {
  var el = document.getElementById('tok-savings-chart');
  if (!el) return;
  var data = _tok30dData;
  if (!data.length) { el.innerHTML = '<div class="usage-title">Cost Savings</div><div style="color:var(--muted);font-size:0.8125rem;padding:2rem 0;text-align:center">No usage data for savings chart</div>'; return; }

  // Compute total monthly plan cost from profiles
  var totalMonthlyPlan = 0;
  for (var pi = 0; pi < _cachedProfiles.length; pi++) {
    totalMonthlyPlan += getPlanMonthlyCost(_cachedProfiles[pi].subscriptionType, _cachedProfiles[pi].rateLimitTier);
  }
  if (totalMonthlyPlan === 0) totalMonthlyPlan = 100; // fallback

  var dailyPlanCost = totalMonthlyPlan / 30;

  // Build 30-day buckets of API cost
  var now = Date.now();
  var dayMs = 86400000;
  var bucketCount = 30;
  var periodStart = now - bucketCount * dayMs;
  var dailyCosts = [];
  for (var b = 0; b < bucketCount; b++) dailyCosts.push(0);

  for (var i = 0; i < data.length; i++) {
    var ts = data[i].timestamp || data[i].ts || 0;
    var elapsed = ts - periodStart;
    if (elapsed < 0) continue;
    var idx = Math.floor(elapsed / dayMs);
    if (idx >= bucketCount) idx = bucketCount - 1;
    if (idx < 0) idx = 0;
    dailyCosts[idx] += estimateCost(data[i].model, data[i].inputTokens || 0, data[i].outputTokens || 0);
  }

  // Accumulate
  var cumPlan = [];
  var cumApi = [];
  var runPlan = 0, runApi = 0;
  for (var d = 0; d < bucketCount; d++) {
    runPlan += dailyPlanCost;
    runApi += dailyCosts[d];
    cumPlan.push(runPlan);
    cumApi.push(runApi);
  }

  var maxVal = Math.max(cumPlan[bucketCount - 1], cumApi[bucketCount - 1], 1);
  var totalSaved = cumApi[bucketCount - 1] - cumPlan[bucketCount - 1];

  // SVG dimensions
  var svgW = 500, svgH = 140;
  var padL = 45, padR = 10, padT = 10, padB = 25;
  var chartW = svgW - padL - padR;
  var chartH = svgH - padT - padB;

  function xPos(idx) { return padL + (idx / (bucketCount - 1)) * chartW; }
  function yPos(val) { return padT + chartH - (val / maxVal) * chartH; }

  // Grid lines
  var gridLines = '';
  var gridCount = 4;
  for (var g = 0; g <= gridCount; g++) {
    var gVal = (maxVal / gridCount) * g;
    var gy = yPos(gVal);
    gridLines += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (svgW - padR) + '" y2="' + gy + '" class="grid-line"/>';
    gridLines += '<text x="' + (padL - 4) + '" y="' + (gy + 3) + '" class="axis-label" text-anchor="end">$' + Math.round(gVal) + '</text>';
  }

  // X-axis labels (every 5 days)
  var xLabels = '';
  for (var xl = 0; xl < bucketCount; xl += 5) {
    var labelDate = new Date(periodStart + (xl + 0.5) * dayMs);
    xLabels += '<text x="' + xPos(xl) + '" y="' + (svgH - 2) + '" class="axis-label" text-anchor="middle">' + (labelDate.getMonth() + 1) + '/' + labelDate.getDate() + '</text>';
  }
  // Last day label
  var lastDate = new Date(now - 0.5 * dayMs);
  xLabels += '<text x="' + xPos(bucketCount - 1) + '" y="' + (svgH - 2) + '" class="axis-label" text-anchor="middle">' + (lastDate.getMonth() + 1) + '/' + lastDate.getDate() + '</text>';

  // Build path strings
  var planPath = '', apiPath = '';
  for (var p = 0; p < bucketCount; p++) {
    var cmd = p === 0 ? 'M' : 'L';
    planPath += cmd + xPos(p).toFixed(1) + ',' + yPos(cumPlan[p]).toFixed(1);
    apiPath += cmd + xPos(p).toFixed(1) + ',' + yPos(cumApi[p]).toFixed(1);
  }

  // Area between the two lines (for savings visualization)
  var areaPath = '';
  for (var a = 0; a < bucketCount; a++) {
    areaPath += (a === 0 ? 'M' : 'L') + xPos(a).toFixed(1) + ',' + yPos(cumApi[a]).toFixed(1);
  }
  for (var a2 = bucketCount - 1; a2 >= 0; a2--) {
    areaPath += 'L' + xPos(a2).toFixed(1) + ',' + yPos(cumPlan[a2]).toFixed(1);
  }
  areaPath += 'Z';

  var areaColor = totalSaved > 0 ? 'var(--green)' : 'var(--red)';

  var svg = '<svg class="savings-chart-svg" viewBox="0 0 ' + svgW + ' ' + svgH + '" preserveAspectRatio="none">' +
    gridLines + xLabels +
    '<path d="' + areaPath + '" class="area-savings" fill="' + areaColor + '"/>' +
    '<path d="' + planPath + '" class="line-plan"/>' +
    '<path d="' + apiPath + '" class="line-api"/>' +
    '</svg>';

  var legend = '<div class="savings-chart-legend">' +
    '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line dashed"></span>Plan cost</div>' +
    '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line solid"></span>API equiv.</div>' +
    '</div>';

  var totalLine = '';
  if (totalSaved > 0) {
    totalLine = '<div class="savings-chart-total">30-day savings: <span class="saved">' + formatCost(totalSaved) + '</span> (' + formatCost(totalMonthlyPlan) + '/mo plan vs ' + formatCost(cumApi[bucketCount - 1]) + ' API)</div>';
  } else {
    totalLine = '<div class="savings-chart-total">30-day delta: <span class="over">' + formatCost(Math.abs(totalSaved)) + ' over</span> (' + formatCost(totalMonthlyPlan) + '/mo plan vs ' + formatCost(cumApi[bucketCount - 1]) + ' API)</div>';
  }

  el.innerHTML = '<div class="usage-title">Cost Savings (30 days)</div>' + legend +
    '<div class="savings-chart-container">' + svg + '</div>' + totalLine;
}

function renderAccountBreakdown(data) {
  var el = document.getElementById('tok-accounts');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var accountMap = {};
  for (var i = 0; i < data.length; i++) {
    var acct = data[i].account || 'unknown';
    if (!accountMap[acct]) accountMap[acct] = { input: 0, output: 0, total: 0, cost: 0 };
    var inT = data[i].inputTokens || 0;
    var outT = data[i].outputTokens || 0;
    accountMap[acct].input += inT;
    accountMap[acct].output += outT;
    accountMap[acct].total += inT + outT;
    accountMap[acct].cost += estimateCost(data[i].model, inT, outT);
  }
  var sortedAccounts = Object.keys(accountMap).sort(function(a,b) { return accountMap[b].total - accountMap[a].total; });
  if (!sortedAccounts.length) { el.innerHTML = ''; return; }
  var grandTotal = 0;
  for (var j = 0; j < sortedAccounts.length; j++) grandTotal += accountMap[sortedAccounts[j]].total;
  if (!grandTotal) grandTotal = 1;
  var propBar = '<div class="tok-proportion">';
  for (var k = 0; k < sortedAccounts.length; k++) {
    var pct = (accountMap[sortedAccounts[k]].total / grandTotal) * 100;
    propBar += '<div class="tok-proportion-seg" style="width:' + pct + '%;background:' + TOK_COLORS[k % TOK_COLORS.length] + '"></div>';
  }
  propBar += '</div>';
  var rows = '';
  for (var r = 0; r < sortedAccounts.length; r++) {
    var ad = accountMap[sortedAccounts[r]];
    var pctR = Math.round((ad.total / grandTotal) * 100);
    var cost = ad.cost;
    rows += '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:' + TOK_COLORS[r % TOK_COLORS.length] + '"></div>' +
      '<div class="tok-model-name">' + escHtml(sortedAccounts[r]) + '</div>' +
      '<div class="tok-model-detail">' + formatNum(ad.input) + ' in / ' + formatNum(ad.output) + ' out</div>' +
      '<div class="tok-model-total">' + formatNum(ad.total) + '</div>' +
      '<div class="tok-model-cost">' + formatCost(cost) + '</div>' +
      '<div class="tok-model-pct">' + pctR + '%</div>' +
    '</div>';
  }
  el.innerHTML = propBar + rows;
}

function renderRepoBranchBreakdown(data) {
  var el = document.getElementById('tok-repos');
  if (!el) return;
  if (!data.length) { el.innerHTML = ''; return; }
  var now = Date.now();
  var inactiveThreshold = now - 3 * 86400000;
  var allModels = {};
  // Group by repo, then by branch
  var repoMap = {};
  for (var i = 0; i < data.length; i++) {
    var repo = data[i].repo || 'unknown';
    var branch = data[i].branch || 'unknown';
    var inTok = data[i].inputTokens || 0;
    var outTok = data[i].outputTokens || 0;
    var m = data[i].model || 'unknown';
    var ts = data[i].timestamp || data[i].ts || 0;
    allModels[m] = 1;
    if (!repoMap[repo]) repoMap[repo] = { totalIn: 0, totalOut: 0, lastTs: 0, cost: 0, branches: {} };
    repoMap[repo].totalIn += inTok;
    repoMap[repo].totalOut += outTok;
    repoMap[repo].cost += estimateCost(m, inTok, outTok);
    if (ts > repoMap[repo].lastTs) repoMap[repo].lastTs = ts;
    if (!repoMap[repo].branches[branch]) repoMap[repo].branches[branch] = { totalIn: 0, totalOut: 0, lastTs: 0, models: {} };
    var br = repoMap[repo].branches[branch];
    br.totalIn += inTok;
    br.totalOut += outTok;
    if (ts > br.lastTs) br.lastTs = ts;
    if (!br.models[m]) br.models[m] = { input: 0, output: 0 };
    br.models[m].input += inTok;
    br.models[m].output += outTok;
  }
  var sortedAllModels = Object.keys(allModels).sort();
  var grandTotal = 0;
  var repoList = Object.keys(repoMap).map(function(r) {
    var rd = repoMap[r];
    var total = rd.totalIn + rd.totalOut;
    grandTotal += total;
    return { key: r, name: r.split('/').pop(), totalIn: rd.totalIn, totalOut: rd.totalOut, total: total, lastTs: rd.lastTs, cost: rd.cost, branches: rd.branches };
  });
  if (!grandTotal) grandTotal = 1;
  // Split active/inactive
  var active = repoList.filter(function(r) { return r.lastTs >= inactiveThreshold; });
  var inactive = repoList.filter(function(r) { return r.lastTs < inactiveThreshold; });
  active.sort(function(a,b) { return b.total - a.total; });
  inactive.sort(function(a,b) { return b.total - a.total; });
  // Default collapse: collapsed if more than 3 active repos
  var defaultCollapsed = active.length > 3;
  function renderRepoGroup(repo, isInactive) {
    if (_tokRepoCollapsed[repo.key] === undefined) {
      _tokRepoCollapsed[repo.key] = isInactive ? true : defaultCollapsed;
    }
    var collapsed = _tokRepoCollapsed[repo.key];
    var pct = Math.round((repo.total / grandTotal) * 100);
    var cost = repo.cost;
    var cls = 'tok-repo-group' + (isInactive ? ' tok-repo-inactive' : '');
    var chevCls = 'tok-repo-chevron' + (collapsed ? ' collapsed' : '');
    var h = '<div class="' + cls + '">';
    h += '<div class="tok-repo-header" onclick="toggleRepoCollapse(this.dataset.key)" data-key="' + escHtml(repo.key) + '">';
    h += '<span class="' + chevCls + '">\u25BC</span>';
    h += '<span class="tok-repo-name">' + escHtml(repo.name) + '</span>';
    h += '<span class="tok-model-detail" style="flex:1">' + formatNum(repo.totalIn) + ' in / ' + formatNum(repo.totalOut) + ' out</span>';
    h += '<span class="tok-model-cost">' + formatCost(cost) + '</span>';
    h += '<span class="tok-model-pct">' + pct + '%</span>';
    h += '</div>';
    if (!collapsed) {
      var branchKeys = Object.keys(repo.branches).sort(function(a,b) {
        var ta = repo.branches[a].totalIn + repo.branches[a].totalOut;
        var tb = repo.branches[b].totalIn + repo.branches[b].totalOut;
        return tb - ta;
      });
      for (var bi = 0; bi < branchKeys.length; bi++) {
        var br = repo.branches[branchKeys[bi]];
        var brTotal = br.totalIn + br.totalOut;
        var brPct = Math.round((brTotal / grandTotal) * 100);
        var brInactive = br.lastTs < inactiveThreshold;
        var brCls = 'tok-branch-row' + (brInactive ? ' tok-branch-inactive' : '');
        var modelEntries = Object.entries(br.models).sort(function(a,b) { return (b[1].input + b[1].output) - (a[1].input + a[1].output); });
        var modelDetail = modelEntries.map(function(e) {
          return '<span style="color:'+getModelColor(e[0], sortedAllModels)+'">'+escHtml(shortModel(e[0]))+'</span> '+formatNum(e[1].input)+' / '+formatNum(e[1].output);
        }).join(' \u00b7 ');
        h += '<div class="' + brCls + '" style="padding-left:1.5rem">';
        h += '<div class="tok-branch-name"><span class="tok-branch-badge">' + escHtml(branchKeys[bi]) + '</span></div>';
        h += '<div class="tok-branch-stats">';
        h += '<span class="tok-branch-total">' + formatNum(br.totalIn) + ' / ' + formatNum(br.totalOut) + '</span>';
        h += '<span class="tok-branch-pct">' + brPct + '%</span>';
        h += '</div>';
        h += '<div class="tok-branch-detail">' + modelDetail + '</div>';
        h += '</div>';
      }
    }
    h += '</div>';
    return h;
  }
  var html = '';
  for (var a = 0; a < active.length; a++) html += renderRepoGroup(active[a], false);
  if (inactive.length) {
    html += '<div class="tok-inactive-sep">Inactive (no usage in last 3 days)</div>';
    for (var n = 0; n < inactive.length; n++) html += renderRepoGroup(inactive[n], true);
  }
  el.innerHTML = html;
}

function tokFilterChange(which) {
  if (which === 'repo') {
    var branchEl = document.getElementById('tok-branch');
    if (branchEl) branchEl.value = '';
    _lastTokensHash = '';
    refreshTokens();
  } else if (which === 'model' || which === 'account') {
    applyTokenModelFilter();
  } else {
    _lastTokensHash = '';
    refreshTokens();
  }
}

function exportUsageCsv() {
  var data = _tokFilteredData || _tokensRawData;
  if (!data.length) { showToast('No data to export'); return; }
  var lines = ['timestamp,repo,branch,model,account,input_tokens,output_tokens'];
  for (var i = 0; i < data.length; i++) {
    var e = data[i];
    var ts = e.timestamp || e.ts || '';
    if (ts) ts = new Date(ts).toISOString();
    lines.push([
      ts,
      '"' + (e.repo || '').replace(/"/g, '""') + '"',
      '"' + (e.branch || '').replace(/"/g, '""') + '"',
      '"' + (e.model || '').replace(/"/g, '""') + '"',
      '"' + (e.account || '').replace(/"/g, '""') + '"',
      e.inputTokens || 0,
      e.outputTokens || 0
    ].join(','));
  }
  var blob = new Blob([lines.join('\\n')], { type: 'text/csv' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = 'usage-export-' + new Date().toISOString().slice(0,10) + '.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

refresh();
loadSettingsUI();
setInterval(refresh, 5000);
setInterval(tickCountdowns, 1000);
// Restore tab from URL query param
const _initTab = new URLSearchParams(location.search).get('tab');
if (_initTab && document.getElementById('tab-' + _initTab)) switchTab(_initTab);

// ── Log stream ──
let _logES = null;
const LOG_MAX_LINES = 5000;
const LOG_TAG_COLORS = {
  error: '#f85149', warn: '#f85149',
  switch: '#d29922', proactive: '#d29922',
  refresh: '#58a6ff', circuit: '#58a6ff', fallback: '#58a6ff',
  info: '#8b949e', system: '#8b949e',
};

function connectLogStream() {
  if (_logES) return; // already connected
  const container = document.getElementById('log-container');
  const status = document.getElementById('log-status');
  status.textContent = 'Connecting...';
  _logES = new EventSource('/api/logs/stream');
  _logES.onopen = () => { status.textContent = 'Connected'; status.style.color = '#3fb950'; };
  _logES.onerror = () => { status.textContent = 'Reconnecting...'; status.style.color = '#f85149'; };
  _logES.onmessage = (ev) => {
    try {
      const data = JSON.parse(ev.data);
      const line = document.createElement('div');
      const tag = (data.tag || 'info').toLowerCase();
      const color = LOG_TAG_COLORS[tag] || '#8b949e';
      line.innerHTML = '<span style="color:' + color + ';font-weight:600">[' + tag.toUpperCase() + ']</span> ' + escapeHtml(data.msg || data.line || '');
      // Check scroll position before DOM changes
      const atBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 60;
      container.appendChild(line);
      // Prune oldest lines, preserving scroll position if user scrolled up
      var pruneCount = container.childElementCount - LOG_MAX_LINES;
      if (pruneCount > 0 && !atBottom) {
        var removedHeight = 0;
        while (pruneCount-- > 0) {
          removedHeight += container.firstChild.offsetHeight;
          container.removeChild(container.firstChild);
        }
        container.scrollTop -= removedHeight;
      } else {
        while (container.childElementCount > LOG_MAX_LINES) container.removeChild(container.firstChild);
      }
      if (atBottom) container.scrollTop = container.scrollHeight;
    } catch {}
  };
}

function clearLogs() {
  const container = document.getElementById('log-container');
  container.innerHTML = '';
}

function escapeHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Session Monitor ──

function sessionDuration(ms) {
  if (ms < 60000) return Math.floor(ms / 1000) + 's';
  if (ms < 3600000) return Math.floor(ms / 60000) + 'm ' + Math.floor((ms % 60000) / 1000) + 's';
  return Math.floor(ms / 3600000) + 'h ' + Math.floor((ms % 3600000) / 60000) + 'm';
}

function sessionTimeAgo(ts) {
  var d = Date.now() - ts;
  if (d < 60000) return Math.floor(d / 1000) + 's ago';
  if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
  return Math.floor(d / 3600000) + 'h ago';
}

function sessionEstCost(inTok, outTok, model) {
  // Rough estimates per 1M tokens
  var inCost = 15, outCost = 75; // opus defaults
  if (model && model.includes('sonnet')) { inCost = 3; outCost = 15; }
  if (model && model.includes('haiku')) { inCost = 0.25; outCost = 1.25; }
  return ((inTok * inCost + outTok * outCost) / 1e6).toFixed(2);
}

var _lastBadgeRefresh = 0;
var _collapsedSessions = new Set();
function toggleSessionCollapse(id) {
  if (_collapsedSessions.has(id)) _collapsedSessions.delete(id);
  else _collapsedSessions.add(id);
  var card = document.querySelector('.session-card[data-sid="' + id + '"]');
  if (card) card.classList.toggle('collapsed');
}
function refreshSessionsBadgeOnly() {
  // Throttle badge-only fetches to once per 10s
  var now = Date.now();
  if (now - _lastBadgeRefresh < 10000) return;
  _lastBadgeRefresh = now;
  fetch('/api/sessions').then(function(r) { return r.json(); }).then(function(data) {
    var threshold = ${SESSION_AWAITING_THRESHOLD};
    updateSessionsBadge((data.active || []).filter(function(s) { return (Date.now() - s.lastActiveAt) >= threshold; }).length);
  }).catch(function() {});
}

async function refreshSessions() {
  try {
    var resp = await fetch('/api/sessions');
    var data = await resp.json();
    // No quickHash guard — time-derived displays (duration, idle, state) must
    // update even when API data is unchanged (wall-clock drives state transitions)
    renderSessions(data);
    var threshold = ${SESSION_AWAITING_THRESHOLD};
    updateSessionsBadge((data.active || []).filter(function(s) { return (Date.now() - s.lastActiveAt) >= threshold; }).length);
  } catch {}
}

function renderSessions(data) {
  var el = document.getElementById('sessions-content');
  if (!el) return;
  var active = data.active || [];
  var recent = data.recent || [];
  if (!active.length && !recent.length) {
    if (!data.enabled) {
      el.innerHTML = '<div class="empty-state">Session Monitor is OFF. Enable it in Config (BETA).</div>';
    } else {
      el.innerHTML = '<div class="empty-state">No sessions yet. Start a Claude Code session with the proxy running.</div>';
    }
    return;
  }
  var html = '';

  // Conflicts banner
  if (data.conflicts && data.conflicts.length) {
    html += '<div class="session-conflicts">';
    data.conflicts.forEach(function(c) {
      html += '<div>\\u26A0 ' + c.count + ' sessions editing ' + escapeHtml(c.file) + '</div>';
    });
    html += '</div>';
  }

  // Active sessions
  if (active.length) {
    html += '<div class="session-section-title">ACTIVE</div>';
    active.forEach(function(s) {
      var idleMs = Date.now() - s.lastActiveAt;
      var state = idleMs < ${SESSION_AWAITING_THRESHOLD} ? 'processing' : 'awaiting';
      var dur = sessionDuration(Date.now() - s.startedAt);
      var idle = state === 'awaiting' ? sessionDuration(idleMs) : '';
      var proj = sessionProj(s);
      var collapsed = _collapsedSessions.has(s.id) ? ' collapsed' : '';
      html += '<div class="session-card ' + state + collapsed + '" data-sid="' + s.id + '">';
      html += '<button class="session-copy-btn" onclick="copyTimeline(\\'' + s.id + '\\')">\\uD83D\\uDCCB</button>';
      html += '<div class="session-header" onclick="toggleSessionCollapse(\\'' + s.id + '\\')">';
      html += '<span class="session-collapse-indicator">\\u25BC</span>';
      html += '<span class="session-header-left"><b>' + escapeHtml(s.account) + '</b> \\u00b7 ' + escapeHtml(proj) + '</span>';
      html += '<span class="session-header-right"><span>' + dur + '</span>';
      if (state === 'awaiting') {
        html += '<span class="session-awaiting">\\u23F8 input ' + idle + '</span>';
      }
      html += '</span>';
      html += '</div>';
      // Collapsed activity summary (visible only when collapsed)
      if (s.currentActivity) {
        var brailleC = state === 'processing' ? 'braille-spin' : 'braille-static';
        html += '<div class="session-collapsed-activity"><span class="' + brailleC + '"></span>' + escapeHtml(s.currentActivity) + '</div>';
      }
      // Timeline
      html += '<div class="session-timeline">';
      s.timeline.forEach(function(e) {
        if (e.type === 'input') html += '<div class="tl-input">' + escapeHtml(e.text) + '</div>';
        else html += '<div class="tl-action">' + escapeHtml(e.text) + '</div>';
      });
      // Current activity
      if (s.currentActivity) {
        var brailleClass = state === 'processing' ? 'braille-spin' : 'braille-static';
        html += '<div class="tl-current"><span class="' + brailleClass + '"></span>' + escapeHtml(s.currentActivity) + '</div>';
      }
      html += '</div>';
      // Meta
      html += '<div class="session-meta">';
      html += '<span>' + s.requestCount + ' req</span>';
      html += '<span>' + formatNum(s.totalInputTokens + s.totalOutputTokens) + ' tok</span>';
      html += '</div>';
      html += '</div>';
    });
  }

  // Recent sessions
  if (recent.length) {
    html += '<div class="session-section-title">RECENT</div>';
    recent.forEach(function(s) {
      var ago = sessionTimeAgo(s.completedAt || s.startedAt);
      var dur = sessionDuration(s.duration || 0);
      var cost = sessionEstCost(s.totalInputTokens || 0, s.totalOutputTokens || 0, s.model);
      var proj = sessionProj(s);
      var collapsed = _collapsedSessions.has(s.id) ? ' collapsed' : '';
      html += '<div class="session-card completed' + collapsed + '" data-sid="' + s.id + '">';
      html += '<button class="session-copy-btn" onclick="copyTimeline(\\'' + s.id + '\\')">\\uD83D\\uDCCB</button>';
      html += '<div class="session-header" onclick="toggleSessionCollapse(\\'' + s.id + '\\')">';
      html += '<span class="session-collapse-indicator">\\u25BC</span>';
      html += '<span class="session-header-left"><span>' + ago + '</span> \\u00b7 <b>' + escapeHtml(s.account) + '</b> \\u00b7 ' + escapeHtml(proj) + '</span>';
      html += '<span class="session-header-right"><span>' + dur + ' \\u00b7 ~$' + cost + '</span></span>';
      html += '</div>';
      html += '<div class="session-timeline">';
      (s.timeline || []).forEach(function(e) {
        if (e.type === 'input') html += '<div class="tl-input">' + escapeHtml(e.text) + '</div>';
        else html += '<div class="tl-action">' + escapeHtml(e.text) + '</div>';
      });
      html += '</div>';
      html += '<div class="session-meta">';
      html += '<span>' + (s.requestCount || 0) + ' req</span>';
      html += '<span>' + formatNum((s.totalInputTokens || 0) + (s.totalOutputTokens || 0)) + ' tok</span>';
      html += '</div>';
      html += '</div>';
    });
  }

  // Overhead footer
  if (data.overhead) {
    var oh = data.overhead.inputTokens + data.overhead.outputTokens;
    if (oh > 0) {
      html += '<div class="session-overhead">Summarizer overhead: ' + formatNum(oh) + ' tokens (Haiku)</div>';
    }
  }

  el.innerHTML = html;
}

function updateSessionsBadge(count) {
  var badge = document.getElementById('sessions-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = '';
  } else {
    badge.style.display = 'none';
  }
}

function sessionProj(s) {
  if (s.branch) {
    if (s.branch === 'main' || s.branch === 'master') return (s.repo || '') + '/' + s.branch;
    var parts = s.branch.split('/');
    return parts[parts.length - 1];
  }
  return s.repo || s.cwd || 'unknown';
}
function copyTimeline(sessionId) {
  // Find session data from last render
  fetch('/api/sessions').then(function(r) { return r.json(); }).then(function(data) {
    var s = (data.active || []).find(function(a) { return a.id === sessionId; })
         || (data.recent || []).find(function(a) { return a.id === sessionId; });
    if (!s) { showToast('Session not found'); return; }
    var proj = sessionProj(s);
    var dur = sessionDuration(s.duration || (Date.now() - s.startedAt));
    var tok = formatNum((s.totalInputTokens || 0) + (s.totalOutputTokens || 0));
    var md = '## Session: ' + proj + ' (' + dur + ', ' + tok + ' tokens)\\n';
    (s.timeline || []).forEach(function(e) {
      if (e.type === 'input') md += '- \\u2192 ' + e.text + '\\n';
      else md += '  - ' + e.text + '\\n';
    });
    navigator.clipboard.writeText(md).then(function() {
      showToast('Timeline copied');
    }).catch(function() {
      showToast('Copy failed');
    });
  }).catch(function() { showToast('Failed to fetch session'); });
}
</script>
<footer style="text-align:center;padding:2rem 0 1rem;font-size:0.75rem;color:#9ca3af;line-height:1.8">
  <div>🤙 Vibe coded with love by LJ &middot; ${PROJECT_VERSION}</div>
  <a href="https://github.com/loekj/claude-acct-switcher" target="_blank" rel="noopener" style="color:#9ca3af;text-decoration:none">github.com/loekj/claude-acct-switcher</a>
</footer>
</body>
</html>`;
}

// ─────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  try {
    // CORS for local dev
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // API routes
    if (req.url.startsWith('/api/')) {
      const handled = await handleAPI(req, res);
      if (handled) return;
    }

    // Dashboard HTML
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(renderHTML());
  } catch (e) {
    console.error('Server error:', e);
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => {
  console.log(`Dashboard running at http://localhost:${PORT}`);
  // Discover any existing keychain token on startup so the dashboard
  // shows accounts immediately (don't wait for the first proxy request)
  autoDiscoverAccount().catch(() => {});
});

// ─────────────────────────────────────────────────
// Transparent API Proxy (port 3334) with AUTO-SWITCH
//
// All Claude Code sessions should set:
//   ANTHROPIC_BASE_URL=http://localhost:3334
//
// On each request the proxy:
//  1. Picks the best available account (proactive)
//  2. Forwards to api.anthropic.com
//  3. On 429 → auto-retries with next account
//  4. On 401 → marks token expired, tries next
//  5. On 529 → returns as-is (server overload)
//  6. Tracks per-account rate-limit state from
//     every response's headers
// ─────────────────────────────────────────────────

const PROXY_PORT = parseInt(process.env.CSW_PROXY_PORT || '3334', 10);
const PROXY_TIMEOUT = 5 * 60 * 1000; // 5 min per upstream request
const REQUEST_DEADLINE_MS = 45_000;   // hard cap on total handleProxyRequest time
const MAX_EVENT_LOG = 50;

// ── Structured logger ──

// ── Live log streaming (SSE subscribers for `vdm logs`) ──
const _logSubscribers = new Set();
const _logBuffer = [];
const LOG_BUFFER_MAX = 2000;

function log(tag, msg, extra = '') {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  const line = `[${ts}] [${tag}] ${msg}${extra ? ' ' + extra : ''}`;
  try { console.log(line); } catch { /* stdout broken (EIO/EPIPE) — ignore */ }
  const entry = { ts, tag, msg: msg + (extra ? ' ' + extra : ''), line };
  // Buffer for replay to new SSE clients
  _logBuffer.push(entry);
  if (_logBuffer.length > LOG_BUFFER_MAX) _logBuffer.shift();
  // Push to all SSE subscribers (these still work even when stdout is dead)
  for (const res of [..._logSubscribers]) {
    try { res.write(`data: ${JSON.stringify(entry)}\n\n`); }
    catch { _logSubscribers.delete(res); }
  }
}

// ── Event log (exposed to dashboard via /api/proxy-log) ──

const proxyEventLog = []; // { ts, type, from, to, reason }

// Dedup noisy events (rate-limited / all-exhausted) so the activity log
// doesn't fill up when Claude Code retries against an already-limited account.
const _eventDedupMap = new Map(); // "type:key" → timestamp
const EVENT_DEDUP_WINDOW = 5 * 60 * 1000; // 5 min

function logEvent(type, detail = {}) {
  if (type === 'rate-limited' || type === 'all-exhausted') {
    const dedupKey = type === 'rate-limited' ? `rate-limited:${detail.account || ''}` : 'all-exhausted';
    const lastTs = _eventDedupMap.get(dedupKey);
    if (lastTs && Date.now() - lastTs < EVENT_DEDUP_WINDOW) return;
    _eventDedupMap.set(dedupKey, Date.now());
  }

  const entry = { ts: Date.now(), type, ...detail };
  proxyEventLog.unshift(entry);
  if (proxyEventLog.length > MAX_EVENT_LOG) proxyEventLog.length = MAX_EVENT_LOG;
  // Also persist to the activity log
  logActivity(type, detail);
}

// ── Keychain token cache ──

let _kcCache = null;
let _kcCacheAt = 0;
const KC_CACHE_TTL = 2000;

function getActiveToken() {
  const now = Date.now();
  if (_kcCache && now - _kcCacheAt < KC_CACHE_TTL) return _kcCache;
  const creds = readKeychain();
  _kcCache = creds?.claudeAiOauth?.accessToken || null;
  _kcCacheAt = now;
  return _kcCache;
}

function invalidateTokenCache() {
  _kcCache = null;
  _kcCacheAt = 0;
}

// ── Per-account state ──
// Map<token, { name, limited, expired, resetAt, retryAfter,
//              utilization5h, utilization7d, updatedAt }>

const accountState = createAccountStateManager();

// ── Persisted state (keyed by fingerprint, survives restarts) ──
// Saved: { [fingerprint]: { utilization5h, utilization7d, resetAt, resetAt7d, updatedAt } }

let persistedState = {};

function loadPersistedState() {
  try {
    const raw = readFileSync(STATE_FILE, 'utf8');
    persistedState = JSON.parse(raw);
  } catch {
    persistedState = {};
  }
}

function savePersistedState() {
  try {
    writeFileSync(STATE_FILE, JSON.stringify(persistedState));
  } catch {}
}

function updatePersistedState(fingerprint, data) {
  persistedState[fingerprint] = {
    utilization5h: data.utilization5h || 0,
    utilization7d: data.utilization7d || 0,
    resetAt: data.resetAt || 0,
    resetAt7d: data.resetAt7d || 0,
    updatedAt: Date.now(),
  };
  savePersistedState();
}

// Load on startup
loadPersistedState();

// Prune history entries that predate a known window reset
(function pruneStaleHistory() {
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [fp, ps] of Object.entries(persistedState)) {
    if (ps.resetAt && ps.resetAt < nowSec) {
      const resetMs = ps.resetAt * 1000;
      const hist = utilizationHistory.getHistory(fp);
      const fresh = hist.filter(e => e.ts > resetMs);
      utilizationHistory.load(fp, fresh);
    }
    if (ps.resetAt7d && ps.resetAt7d < nowSec) {
      const resetMs = ps.resetAt7d * 1000;
      const hist = weeklyHistory.getHistory(fp);
      const fresh = hist.filter(e => e.ts > resetMs);
      weeklyHistory.load(fp, fresh);
    }
  }
  saveHistoryToDisk();
})();

// Server-side sparkline cache (cleared on window resets to force re-render)
const _sparkCache = {};

function updateAccountState(token, name, headers, fingerprint) {
  accountState.update(token, name, headers);
  if (fingerprint) {
    const u5h = parseFloat(headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    const u7d = parseFloat(headers['anthropic-ratelimit-unified-7d-utilization'] || '0');
    const reset7d = Number(headers['anthropic-ratelimit-unified-7d-reset'] || 0);
    const reset5h = Number(headers['anthropic-ratelimit-unified-5h-reset'] || 0);

    // Detect window resets using actual reset timestamps from API headers.
    // Rolling windows advance the reset epoch by seconds on each request,
    // so require a large jump (>1h) to distinguish a true window reset from
    // normal rolling advancement.  Also require utilization to have dropped.
    const RESET_JUMP = 3600; // 1 hour in seconds
    const prevReset5h = persistedState[fingerprint]?.resetAt || 0;
    if (reset5h > prevReset5h + RESET_JUMP && prevReset5h > 0 && u5h < (utilizationHistory.getHistory(fingerprint).slice(-1)[0]?.u5h ?? u5h)) {
      utilizationHistory.load(fingerprint, []);
      delete _sparkCache[fingerprint + '_5h'];
    }
    const prevReset7d = persistedState[fingerprint]?.resetAt7d || 0;
    if (reset7d > prevReset7d + RESET_JUMP && prevReset7d > 0 && u7d < (weeklyHistory.getHistory(fingerprint).slice(-1)[0]?.u7d ?? u7d)) {
      weeklyHistory.load(fingerprint, []);
      delete _sparkCache[fingerprint + '_7d'];
    }

    utilizationHistory.record(fingerprint, u5h, u7d);
    weeklyHistory.record(fingerprint, u5h, u7d);
    updatePersistedState(fingerprint, { utilization5h: u5h, utilization7d: u7d, resetAt: reset5h, resetAt7d: reset7d });
    saveHistoryToDisk();
  }
}

function markAccountLimited(token, name, retryAfterSec = 0) {
  accountState.markLimited(token, name, retryAfterSec);
}

function markAccountExpired(token, name) {
  accountState.markExpired(token, name);
}

// ── Load saved accounts from disk ──

let _accountsCache = null;
let _accountsCacheAt = 0;
const ACCOUNTS_CACHE_TTL = 5000; // 5s  - covers hot path without stale data

function loadAllAccountTokens() {
  const now = Date.now();
  if (_accountsCache && now - _accountsCacheAt < ACCOUNTS_CACHE_TTL) return _accountsCache;
  try {
    const files = readdirSync(ACCOUNTS_DIR).filter(f => f.endsWith('.json'));
    const accounts = [];
    for (const file of files) {
      try {
        const raw = readFileSync(join(ACCOUNTS_DIR, file), 'utf8');
        const creds = JSON.parse(raw);
        const token = creds?.claudeAiOauth?.accessToken;
        if (!token) continue;
        const name = basename(file, '.json');
        let label = '';
        try { label = readFileSync(join(ACCOUNTS_DIR, `${name}.label`), 'utf8').trim(); } catch {}
        const expiresAt = creds.claudeAiOauth?.expiresAt || 0;
        accounts.push({ name, label, token, creds, expiresAt });
      } catch { /* skip corrupt */ }
    }
    _accountsCache = accounts;
    _accountsCacheAt = now;
    return accounts;
  } catch {
    return _accountsCache || [];
  }
}

function invalidateAccountsCache() {
  _accountsCache = null;
  _accountsCacheAt = 0;
}

// ── Account picker ──

function isAccountAvailable(token, expiresAt) {
  return _isAccountAvailable(token, expiresAt, accountState);
}

function scoreAccount(token) {
  return _scoreAccount(token, accountState);
}

function pickBestAccount(excludeTokens = new Set()) {
  return _pickBestAccount(loadAllAccountTokens(), accountState, excludeTokens);
}

// Fallback: pick any untried account even if marked limited (in case state is stale)
function pickAnyUntried(excludeTokens) {
  return _pickAnyUntried(loadAllAccountTokens(), excludeTokens);
}

// ── Build forwarding headers ──

function buildForwardHeaders(originalHeaders, token) {
  return _buildForwardHeaders(originalHeaders, token);
}

// ── Forward request with timeout ──

function forwardToAnthropic(method, path, headers, body, timeout = PROXY_TIMEOUT) {
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com',
      port: 443,
      path, method, headers,
      timeout,
    }, resolve);
    req.on('timeout', () => { req.destroy(new Error('upstream timeout')); });
    req.on('error', reject);
    if (body.length) req.write(body);
    req.end();
  });
}

// Drain a response and return the body (for error responses).
// Destroys the stream on timeout to prevent partial-data races.
function drainResponse(res) {
  return new Promise(r => {
    let done = false;
    const chunks = [];
    const finish = () => { if (!done) { done = true; r(Buffer.concat(chunks)); } };
    res.on('data', c => chunks.push(c));
    res.on('end', finish);
    res.on('error', finish);
    // Safety: if stream stalls, destroy it and resolve with whatever we have
    setTimeout(() => { res.destroy(); finish(); }, 5000);
  });
}

// ── Empty-body 400 detection ──
// The Anthropic API returns "400 with no body" when OAuth tokens are
// null/expired.  Legitimate 400s always include a JSON error body.
function isEmptyBody400(statusCode, bodyBuffer) {
  return statusCode === 400 && (!bodyBuffer || bodyBuffer.length === 0);
}

// ── Smart passthrough ──
// Shared logic for proxy-disabled and circuit-breaker passthrough modes.
// 1. Forward to Anthropic with provided auth
// 2. If 400-empty-body → read fresh token from keychain (bypass cache), retry
// 3. If still 400-empty-body → return 401 to trigger Claude Code re-auth
// 4. Otherwise → forward response as-is
async function _smartPassthrough(clientReq, clientRes, body, fwd, label) {
  const res = await forwardToAnthropic(clientReq.method, clientReq.url, fwd, body, PROXY_TIMEOUT);
  // Drain body to inspect for empty-body 400
  const resBuf = await drainResponse(res);
  if (isEmptyBody400(res.statusCode, resBuf)) {
    log('fallback', `${label}: 400-empty-body detected — trying fresh keychain token`);
    // Bypass cache: read directly from keychain
    invalidateTokenCache();
    const freshCreds = readKeychain();
    const freshToken = freshCreds?.claudeAiOauth?.accessToken;
    if (freshToken && freshToken !== fwd['authorization']?.replace(/^Bearer\s+/i, '')) {
      const retryFwd = { ...fwd, authorization: `Bearer ${freshToken}` };
      retryFwd['content-length'] = String(body.length);
      try {
        const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, retryFwd, body, 15_000);
        const retryBuf = await drainResponse(retryRes);
        if (!isEmptyBody400(retryRes.statusCode, retryBuf)) {
          // Fresh token worked — forward the response
          if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
          const hdrs = { ...retryRes.headers };
          if (retryBuf.length) hdrs['content-length'] = String(retryBuf.length);
          clientRes.writeHead(retryRes.statusCode, hdrs);
          clientRes.end(retryBuf);
          return;
        }
        log('fallback', `${label}: fresh token also got 400-empty-body`);
      } catch (e) {
        log('error', `${label}: fresh-token retry failed: ${e.message}`);
      }
    }
    // All tokens stale → convert to 401 so Claude Code re-authenticates
    log('fallback', `${label}: converting 400-empty-body → 401 to trigger re-auth`);
    if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
    clientRes.writeHead(401, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({
      type: 'error',
      error: { type: 'authentication_error', message: 'Token expired (proxy: empty-body 400 converted to 401)' },
    }));
    return;
  }
  // Normal response (non-empty or non-400) — forward as-is
  if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return;
  const hdrs = { ...res.headers };
  if (resBuf.length) hdrs['content-length'] = String(resBuf.length);
  clientRes.writeHead(res.statusCode, hdrs);
  clientRes.end(resBuf);
}

// ── Passthrough fallback ──
// When all proxy recovery strategies fail, forward the request with the
// ORIGINAL client authorization header.  This lets Claude Code reach the
// real API and trigger its own re-auth flow instead of the proxy returning
// an opaque error that makes sessions permanently stale.

async function _passthroughFallback(clientReq, clientRes, body, reason) {
  // Guard: client already disconnected — nothing to deliver
  if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) {
    log('fallback', `Passthrough skipped (${reason}) — client already disconnected or headers sent`);
    return false;
  }
  try {
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    log('fallback', `Proxy recovery exhausted (${reason}) — passthrough with original auth`);
    // Short timeout: we've already spent time on recovery, don't stall further
    const res = await forwardToAnthropic(clientReq.method, clientReq.url, fwd, body, 15_000);
    // Drain body to check for empty-body 400
    const resBuf = await drainResponse(res);
    if (isEmptyBody400(res.statusCode, resBuf)) {
      log('fallback', `Passthrough (${reason}): 400-empty-body — trying fresh keychain token`);
      invalidateTokenCache();
      const freshCreds = readKeychain();
      const freshToken = freshCreds?.claudeAiOauth?.accessToken;
      if (freshToken && freshToken !== fwd['authorization']?.replace(/^Bearer\s+/i, '')) {
        const retryFwd = { ...fwd, authorization: `Bearer ${freshToken}` };
        retryFwd['content-length'] = String(body.length);
        try {
          const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, retryFwd, body, 15_000);
          const retryBuf = await drainResponse(retryRes);
          if (!isEmptyBody400(retryRes.statusCode, retryBuf)) {
            if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return false;
            const hdrs = { ...retryRes.headers };
            if (retryBuf.length) hdrs['content-length'] = String(retryBuf.length);
            clientRes.writeHead(retryRes.statusCode, hdrs);
            clientRes.end(retryBuf);
            _consecutiveExhausted = 0;
            if (retryRes.statusCode < 400) _consecutive400s = 0;
            return true;
          }
        } catch (e) {
          log('error', `Passthrough fresh-token retry failed (${reason}): ${e.message}`);
        }
      }
      // Convert to 401 so Claude Code re-authenticates
      log('fallback', `Passthrough (${reason}): converting 400-empty-body → 401 to trigger re-auth`);
      if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) return false;
      clientRes.writeHead(401, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: { type: 'authentication_error', message: 'Token expired (proxy: empty-body 400 converted to 401)' },
      }));
      _consecutiveExhausted = 0;
      return true; // we delivered a response (401)
    }
    // Forward whatever the upstream returns — even errors.
    // A standard 401 from the real API lets Claude Code re-authenticate,
    // which is far better than a proxy 502 that kills the session.
    if (clientRes.destroyed || clientRes.writableEnded || clientRes.headersSent) {
      return false;
    }
    const hdrs = { ...res.headers };
    if (resBuf.length) hdrs['content-length'] = String(resBuf.length);
    clientRes.writeHead(res.statusCode, hdrs);
    clientRes.end(resBuf);
    // Passthrough delivered a response — reset failure counters
    _consecutiveExhausted = 0;
    if (res.statusCode < 400) _consecutive400s = 0;
    return true;
  } catch (e) {
    log('error', `Passthrough fallback failed (${reason}): ${e.message}`);
    _consecutiveExhausted++;
    if (_consecutiveExhausted >= CIRCUIT_OPEN_THRESHOLD) {
      _openCircuit(`${_consecutiveExhausted} consecutive failures`);
    }
    return false;
  }
}

// ── Mutex for auto-switch (prevents interleaved keychain writes) ──

let _switchLock = Promise.resolve();

function withSwitchLock(fn) {
  const prev = _switchLock;
  let release;
  _switchLock = new Promise(r => { release = r; });
  return prev.then(fn).finally(release);
}

// ─────────────────────────────────────────────────
// OAuth Token Refresh
// ─────────────────────────────────────────────────

const OAUTH_TOKEN_URL = process.env.OAUTH_TOKEN_URL || 'https://platform.claude.com/v1/oauth/token';
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const OAUTH_DEFAULT_SCOPES = 'user:profile user:inference user:sessions:claude_code user:mcp_servers';
const REFRESH_BUFFER_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
const REFRESH_MAX_RETRIES = 3;
const REFRESH_BACKOFF_BASE = 1000; // 1s, 2s, 4s

const refreshLock = createPerAccountLock();
// Track refresh failures per account: name → { error, retriable, ts }
const refreshFailures = new Map();

/**
 * Atomic file write: write to .tmp, chmod 600, rename over original.
 */
async function atomicWriteAccountFile(name, creds) {
  const filePath = join(ACCOUNTS_DIR, `${name}.json`);
  const tmpPath = filePath + '.tmp';
  const data = JSON.stringify(creds, null, 2);
  await writeFile(tmpPath, data, 'utf8');
  await chmod(tmpPath, 0o600);
  await rename(tmpPath, filePath);
}

/**
 * Call the OAuth refresh endpoint. Returns parsed result via parseRefreshResponse.
 */
function callRefreshEndpoint(refreshToken, scopes) {
  return new Promise((resolve) => {
    const scope = Array.isArray(scopes)
      ? scopes.join(' ')
      : (typeof scopes === 'string' ? scopes.replace(/,/g, ' ') : OAUTH_DEFAULT_SCOPES);
    const body = buildRefreshRequestBody(refreshToken, OAUTH_CLIENT_ID, scope);
    const parsed = new URL(OAUTH_TOKEN_URL);
    const isHttp = parsed.protocol === 'http:';
    const mod = isHttp ? http : https;
    const port = parsed.port || (isHttp ? 80 : 443);

    const req = mod.request({
      hostname: parsed.hostname,
      port,
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
      timeout: 10000,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        resolve(parseRefreshResponse(res.statusCode, data));
      });
      res.on('error', (err) => resolve({ ok: false, error: `response stream: ${err.message}`, retriable: true }));
    });
    req.on('error', (err) => resolve({ ok: false, error: err.message, retriable: true }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout', retriable: true }); });
    req.write(body);
    req.end();
  });
}

/**
 * Migrate all state from old fingerprint to new fingerprint after token refresh.
 */
function migrateAccountState(oldToken, newToken, oldFp, newFp, name) {
  // Migrate in-memory account state
  const oldState = accountState.get(oldToken);
  if (oldState) {
    accountState.update(newToken, name, {
      'anthropic-ratelimit-unified-status': oldState.limited ? 'limited' : 'ok',
      'anthropic-ratelimit-unified-5h-utilization': String(oldState.utilization5h || 0),
      'anthropic-ratelimit-unified-7d-utilization': String(oldState.utilization7d || 0),
      'anthropic-ratelimit-unified-5h-reset': String(oldState.resetAt || 0),
      'anthropic-ratelimit-unified-7d-reset': String(oldState.resetAt7d || 0),
    });
    accountState.remove(oldToken);
  }

  // Migrate utilization history (5h + weekly)
  const hist5h = utilizationHistory.getHistory(oldFp);
  if (hist5h.length) {
    utilizationHistory.load(newFp, hist5h);
    utilizationHistory.load(oldFp, []); // clear old
  }
  const histWeekly = weeklyHistory.getHistory(oldFp);
  if (histWeekly.length) {
    weeklyHistory.load(newFp, histWeekly);
    weeklyHistory.load(oldFp, []); // clear old
  }

  // Migrate persisted state
  if (persistedState[oldFp]) {
    persistedState[newFp] = { ...persistedState[oldFp], updatedAt: Date.now() };
    delete persistedState[oldFp];
    savePersistedState();
  }

  // Migrate email cache
  const cachedEmail = emailCache.get(oldFp);
  if (cachedEmail) {
    emailCache.set(newFp, cachedEmail);
    emailCache.delete(oldFp);
  }

  // Migrate rate limit cache
  const cachedRate = rateLimitCache.get(oldFp);
  if (cachedRate) {
    rateLimitCache.set(newFp, cachedRate);
    rateLimitCache.delete(oldFp);
  }
}

/**
 * Main refresh orchestrator for a single account.
 * Wrapped in per-account lock to prevent concurrent refreshes.
 */
async function refreshAccountToken(accountName, { force = false } = {}) {
  return refreshLock.withLock(accountName, async () => {
    // 1. Re-read credentials from disk (may have been refreshed by concurrent request)
    let rawCreds;
    try {
      const raw = readFileSync(join(ACCOUNTS_DIR, `${accountName}.json`), 'utf8');
      rawCreds = JSON.parse(raw);
    } catch (e) {
      log('refresh', `Failed to read account file for ${accountName}: ${e.message}`);
      return { ok: false, error: `Cannot read account file: ${e.message}` };
    }

    const oauth = rawCreds.claudeAiOauth;
    if (!oauth) {
      return { ok: false, error: 'No claudeAiOauth in credentials' };
    }

    let accountLabel = accountName;
    try { accountLabel = readFileSync(join(ACCOUNTS_DIR, `${accountName}.label`), 'utf8').trim() || accountName; } catch {}

    // 2. Check if still needs refresh (double-check after lock)
    //    Skip this check when force=true (e.g. 401/400 from API means token is invalid
    //    regardless of what the stored expiresAt says)
    if (!force && !shouldRefreshToken(oauth.expiresAt, REFRESH_BUFFER_MS)) {
      log('refresh', `${accountName}: token still valid, skipping refresh`);
      return { ok: true, skipped: true };
    }

    // 3. Verify refresh token exists
    if (!oauth.refreshToken) {
      log('refresh', `${accountName}: no refresh token available`);
      return { ok: false, error: 'No refresh token' };
    }

    const oldToken = oauth.accessToken;
    const oldFp = getFingerprintFromToken(oldToken);

    // 4. Call OAuth endpoint with retry + exponential backoff
    let result;
    for (let attempt = 0; attempt < REFRESH_MAX_RETRIES; attempt++) {
      result = await callRefreshEndpoint(oauth.refreshToken, oauth.scopes);
      if (result.ok) break;
      if (!result.retriable) break;
      // Exponential backoff: 1s, 2s, 4s
      const delay = REFRESH_BACKOFF_BASE * Math.pow(2, attempt);
      log('refresh', `${accountName}: attempt ${attempt + 1} failed (${result.error}), retrying in ${delay}ms...`);
      await new Promise(r => setTimeout(r, delay));
    }

    if (!result.ok) {
      log('refresh', `${accountName}: refresh failed after retries: ${result.error}`);
      refreshFailures.set(accountName, { error: result.error, retriable: !!result.retriable, ts: Date.now(), fp: oldFp });
      logActivity('refresh-failed', { account: accountLabel, error: result.error, retriable: !!result.retriable });
      return { ok: false, error: result.error };
    }

    // 5. Build new credentials and atomic-write to disk
    const newExpiresAt = result.expiresIn
      ? computeExpiresAt(result.expiresIn)
      : Date.now() + 8 * 60 * 60 * 1000; // fallback: 8 hours
    const newCreds = buildUpdatedCreds(rawCreds, result.accessToken, result.refreshToken, newExpiresAt);

    try {
      await atomicWriteAccountFile(accountName, newCreds);
    } catch (e) {
      log('refresh', `CRITICAL: ${accountName}: refresh succeeded but file write failed: ${e.message}`);
      return { ok: false, error: `File write failed: ${e.message}` };
    }

    const newFp = getFingerprintFromToken(result.accessToken);
    log('refresh', `${accountName}: token refreshed successfully (fp ${oldFp} → ${newFp}, expires ${new Date(newExpiresAt).toISOString()})`);

    // 6. Migrate state from old fingerprint to new fingerprint
    migrateAccountState(oldToken, result.accessToken, oldFp, newFp, accountName);

    // 7. Update keychain if this is the active account
    const activeToken = getActiveToken();
    if (activeToken === oldToken) {
      try {
        await withSwitchLock(() => {
          writeKeychain(newCreds);
          invalidateTokenCache();
        });
        log('refresh', `${accountName}: updated keychain (was active account)`);
      } catch (e) {
        log('warn', `${accountName}: keychain update failed after refresh: ${e.message}`);
      }
    }

    // 8. Invalidate caches
    invalidateAccountsCache();
    refreshFailures.delete(accountName);
    logActivity('token-refreshed', { account: accountLabel });

    return { ok: true, accessToken: result.accessToken, expiresAt: newExpiresAt };
  });
}

// ── Background refresh timer ──

const REFRESH_FAILURE_TTL = 2 * 60 * 60 * 1000; // 2 hours

async function refreshSweep(label = 'refresh-bg') {
  const accounts = loadAllAccountTokens();
  for (const acct of accounts) {
    if (shouldRefreshToken(acct.expiresAt, REFRESH_BUFFER_MS)) {
      const prior = refreshFailures.get(acct.name);
      if (prior && !prior.retriable) {
        if (Date.now() - prior.ts < REFRESH_FAILURE_TTL) continue;
        // TTL expired — retry
        log(label, `${acct.label || acct.name}: retrying after non-retriable failure (${Math.round((Date.now() - prior.ts) / 60000)}m ago)`);
      }
      log(label, `${acct.label || acct.name}: token near expiry, refreshing...`);
      try {
        await refreshAccountToken(acct.name);
      } catch (e) {
        log(label, `${acct.label || acct.name}: background refresh error: ${e.message}`);
        const failFp = getFingerprintFromToken(acct.token);
        refreshFailures.set(acct.name, { error: e.message, retriable: true, ts: Date.now(), fp: failFp });
        logActivity('refresh-failed', { account: acct.label || acct.name, error: e.message, retriable: true });
      }
    }
  }
}

// Run immediately on startup (handles expired tokens after sleep/restart)
refreshSweep('refresh-startup').catch(() => {});

// Detect system wake: if the timer fires much later than expected, the system slept
let lastRefreshTick = Date.now();
setInterval(async () => {
  const now = Date.now();
  const drift = now - lastRefreshTick - REFRESH_CHECK_INTERVAL;
  lastRefreshTick = now;
  if (drift > 30_000) {
    log('refresh-wake', `System wake detected (drift ${Math.round(drift / 1000)}s), refreshing all tokens...`);
    // Clear non-retriable failures so all accounts get a fresh chance after sleep
    for (const [name, entry] of refreshFailures) {
      if (!entry.retriable) refreshFailures.delete(name);
    }
  }
  await refreshSweep();
}, REFRESH_CHECK_INTERVAL);

// ── Startup: clean orphaned .tmp files ──

(function cleanupTmpFiles() {
  try {
    const files = readdirSync(ACCOUNTS_DIR);
    for (const file of files) {
      if (!file.endsWith('.json.tmp')) continue;
      const original = file.replace(/\.tmp$/, '');
      const tmpPath = join(ACCOUNTS_DIR, file);
      const origPath = join(ACCOUNTS_DIR, original);
      if (existsSync(origPath)) {
        // Original exists  - tmp is leftover from interrupted write
        try { unlinkSync(tmpPath); } catch {}
        log('startup', `Cleaned orphaned tmp file: ${file}`);
      } else {
        // Original missing  - recover from crash after write, before rename
        try {
          renameSync(tmpPath, origPath);
          log('startup', `Recovered account from tmp file: ${file} → ${original}`);
        } catch {}
      }
    }
  } catch {}
})();

// ─────────────────────────────────────────────────
// [BETA] Request Serialization Queue
// ─────────────────────────────────────────────────

let _inflightCount = 0;
const _requestQueue = [];

function getQueueStats() {
  return { inflight: _inflightCount, queued: _requestQueue.length };
}

function drainSerializationQueue() {
  while (_requestQueue.length > 0) {
    const next = _requestQueue.shift();
    next.resolve();
  }
}

function withSerializationQueue(fn, isRetry = false) {
  // If serialization disabled, retries, or nothing inflight → run immediately
  if (!settings.serializeRequests || isRetry || _inflightCount === 0) {
    _inflightCount++;
    return fn().finally(() => {
      _inflightCount--;
      _dispatchNext();
    });
  }

  // Queue the request
  return new Promise((resolve, reject) => {
    const entry = { fn, resolve: null, reject: null };
    const timeout = setTimeout(() => {
      const idx = _requestQueue.indexOf(entry);
      if (idx !== -1) _requestQueue.splice(idx, 1);
      reject(new Error('queue_timeout'));
    }, 120_000);

    entry.resolve = () => {
      clearTimeout(timeout);
      _inflightCount++;
      fn().then(resolve, reject).finally(() => {
        _inflightCount--;
        _dispatchNext();
      });
    };
    entry.reject = (err) => {
      clearTimeout(timeout);
      reject(err);
    };
    _requestQueue.push(entry);
  });
}

function _dispatchNext() {
  if (_requestQueue.length === 0) return;
  const delay = settings.serializeDelayMs || 0;
  if (delay > 0) {
    setTimeout(() => {
      if (_requestQueue.length > 0) {
        const next = _requestQueue.shift();
        next.resolve();
      }
    }, delay);
  } else {
    const next = _requestQueue.shift();
    next.resolve();
  }
}

// ─────────────────────────────────────────────────
// [BETA] Token Usage Extractor (SSE Transform Stream)
// ─────────────────────────────────────────────────

function createUsageExtractor() {
  let inputTokens = 0;
  let outputTokens = 0;
  let model = '';
  let lineBuffer = '';
  let nextEventType = '';

  const extractor = new Transform({
    transform(chunk, encoding, callback) {
      // Pass through bytes unchanged
      this.push(chunk);

      // Scan for usage data in SSE events
      const text = chunk.toString('utf8');
      lineBuffer += text;

      const lines = lineBuffer.split('\n');
      // Keep the last (potentially incomplete) line in the buffer
      lineBuffer = lines.pop() || '';

      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('event:')) {
          nextEventType = trimmed.slice(6).trim();
        } else if (trimmed.startsWith('data:') && nextEventType) {
          try {
            const data = JSON.parse(trimmed.slice(5).trim());
            if (nextEventType === 'message_start' && data.message) {
              if (data.message.usage) {
                inputTokens = data.message.usage.input_tokens || 0;
              }
              if (data.message.model) {
                model = data.message.model;
              }
            } else if (nextEventType === 'message_delta' && data.usage) {
              outputTokens = data.usage.output_tokens || 0;
            }
          } catch { /* not JSON or malformed — skip */ }
          nextEventType = '';
        }
      }

      callback();
    },
    flush(callback) {
      callback();
    },
  });

  extractor.getUsage = () => ({
    inputTokens,
    outputTokens,
    model,
    ts: Date.now(),
  });

  return extractor;
}

// ─────────────────────────────────────────────────
// [BETA] Session Monitor — server-side functions
// ─────────────────────────────────────────────────

// FNV-1a hash (32-bit) — fast, deterministic, good distribution
function _fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h * 0x01000193) >>> 0;
  }
  return h.toString(16);
}

// Simple string hash for turn detection
function _simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return h.toString(36);
}

function extractCwd(bodyObj) {
  // Search system prompt for working directory
  const sysContent = bodyObj.system;
  let searchText = '';
  if (typeof sysContent === 'string') {
    searchText = sysContent;
  } else if (Array.isArray(sysContent)) {
    searchText = sysContent.map(b => typeof b === 'string' ? b : b.text || '').join(' ');
  }
  const match = searchText.match(/working directory:\s*(.+)/i);
  if (match) return match[1].trim().split('\n')[0].trim();
  // Fallback: hash first 200 chars of system prompt
  return '_sys_' + _fnv1a(searchText.slice(0, 200));
}

function deriveSessionId(cwd, account) {
  return _fnv1a(cwd + '::' + account);
}

function detectNewTurn(bodyObj, session) {
  const msgs = bodyObj.messages || [];
  // Find last user message
  let lastUserText = '';
  let assistantContext = '';
  const toolUses = [];
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role === 'user' && !lastUserText) {
      if (typeof m.content === 'string') lastUserText = m.content;
      else if (Array.isArray(m.content)) {
        lastUserText = m.content.filter(b => b.type === 'text').map(b => b.text).join(' ');
      }
    }
    if (m.role === 'assistant' && !assistantContext) {
      if (typeof m.content === 'string') assistantContext = m.content;
      else if (Array.isArray(m.content)) {
        for (const b of m.content) {
          if (b.type === 'text') assistantContext = (assistantContext || '') + b.text;
          if (b.type === 'tool_use') toolUses.push(b);
        }
      }
    }
    if (lastUserText && assistantContext) break;
  }
  if (!lastUserText) return null;
  // Clean inputs before summarisation
  lastUserText = lastUserText.replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '').trim();
  assistantContext = assistantContext
    .replace(/<system-reminder>[\s\S]*?<\/system-reminder>/g, '')
    .replace(/```[\s\S]*?```/g, '')           // strip code blocks
    .replace(/`[^`]+`/g, '')                  // strip inline code
    .replace(/^I'll [^\n]*/gm, '')            // strip "I'll do X" preambles
    .replace(/^Let me [^\n]*/gm, '')          // strip "Let me..." preambles
    .replace(/\n{2,}/g, '\n').trim();
  const hash = _simpleHash(lastUserText);
  if (hash === session.lastUserHash) return null;
  session.lastUserHash = hash;
  return { userText: lastUserText, assistantContext, toolUses };
}

function formatCurrentActivity(bodyObj) {
  const msgs = bodyObj.messages || [];
  // Scan from end for last assistant tool_use (skip user messages — tool_result
  // content is raw tool output and not useful as an activity label)
  for (let i = msgs.length - 1; i >= 0; i--) {
    const m = msgs[i];
    if (m.role === 'assistant' && Array.isArray(m.content)) {
      for (let j = m.content.length - 1; j >= 0; j--) {
        const b = m.content[j];
        if (b.type === 'tool_use') {
          const name = b.name || 'unknown';
          let arg = '';
          if (b.input) {
            if (b.input.command) arg = b.input.command.replace(/\n/g, ' ');
            else if (b.input.file_path) arg = b.input.file_path;
            else if (b.input.pattern) arg = b.input.pattern;
            else if (b.input.query) arg = b.input.query.replace(/\n/g, ' ');
          }
          const text = arg ? `${name} ${arg}` : name;
          return text.length > 60 ? text.slice(0, 57) + '...' : text;
        }
      }
    }
  }
  return null;
}

function extractFilesModified(toolUses) {
  const files = new Set();
  for (const tu of toolUses) {
    if (!tu.input) continue;
    if (tu.name === 'Edit' || tu.name === 'Write') {
      const fp = tu.input.file_path;
      if (fp) files.add(basename(fp));
    }
    if (tu.name === 'Bash' && typeof tu.input.command === 'string') {
      // Heuristic: detect common file-modifying patterns
      const cmd = tu.input.command;
      const editMatch = cmd.match(/(?:sed|awk|tee|>)\s+["']?([^\s"'|;]+)/);
      if (editMatch) files.add(basename(editMatch[1]));
    }
  }
  return [...files];
}

async function callHaikuSummary(userText, assistantContext, toolUses) {
  // Check backoff
  if (_haikuBackoffUntil > Date.now()) return null;

  // Skip if no meaningful content to summarize
  const trimmedUser = userText.trim();
  const trimmedCtx = (assistantContext || '').trim();
  if (!trimmedUser && !trimmedCtx && !toolUses.length) return null;

  const toolList = toolUses.map(t => {
    const name = t.name || 'unknown';
    let arg = '';
    if (t.input) {
      if (t.input.command) arg = t.input.command.replace(/\n/g, ' ').slice(0, 60);
      else if (t.input.file_path) arg = `${basename(t.input.file_path)}`;
      else if (t.input.pattern) arg = t.input.pattern.slice(0, 40);
    }
    return arg ? `${name} ${arg}` : name;
  }).slice(0, 10).join(', ');

  const sysMsg = 'You summarize coding activity for a monitoring dashboard. Output ONLY 2-3 plain-text sentences. Past tense. No code, no markdown, no bullets, no preamble. Never quote code snippets or commands. Never start with "The user" or "I\'ll". Focus on what was decided, found, or changed. Skip verification steps, test runs, and routine checks.';
  const userMsg = `${trimmedUser.slice(0, 500)}${trimmedCtx ? '\n' + trimmedCtx.slice(0, 300) : ''}${toolList ? '\nTools: ' + toolList : ''}`;

  let token;
  try { token = getActiveToken(); } catch { return null; }
  if (!token) return null;

  const reqBody = JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 300,
    system: sysMsg,
    messages: [{ role: 'user', content: userMsg }],
  });

  try {
    const res = await forwardToAnthropic('POST', '/v1/messages', {
      'host': 'api.anthropic.com',
      'authorization': `Bearer ${token}`,
      'content-type': 'application/json',
      'content-length': String(Buffer.byteLength(reqBody)),
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'oauth-2025-04-20',
    }, Buffer.from(reqBody), HAIKU_TIMEOUT);

    const buf = await drainResponse(res);
    if (res.statusCode !== 200) {
      _haikuFailCount++;
      if (_haikuFailCount >= 3) _haikuBackoffUntil = Date.now() + HAIKU_BACKOFF_MS;
      return null;
    }

    _haikuFailCount = 0;
    const data = JSON.parse(buf.toString('utf8'));

    // Track overhead tokens
    if (data.usage) {
      _summarizerOverhead.inputTokens += data.usage.input_tokens || 0;
      _summarizerOverhead.outputTokens += data.usage.output_tokens || 0;
    }

    // Parse response — split into sentences, first = input, rest = actions
    const raw = (data.content?.[0]?.text || '').replace(/<[^>]+>/g, '').trim();
    if (!raw) return null;
    // Split on sentence boundaries (period/exclamation/question followed by space or end)
    const isMeta = s => /^(The user |I'll |I don't |I can't |However|Please share|Since there|This appears|You've provided|Let me )/i.test(s);
    const sentences = raw.split(/(?<=[.!?])\s+/)
      .map(s => s.replace(/^[\s*\-•>]+/, '').trim())
      .filter(s => s && !isMeta(s));
    if (!sentences.length) return null;
    const input = sentences[0].slice(0, 200);
    const actions = sentences.slice(1, 4).map(s => s.slice(0, 200));

    if (input || actions.length) {
      return { input, actions };
    }
    return null;
  } catch {
    _haikuFailCount++;
    if (_haikuFailCount >= 3) _haikuBackoffUntil = Date.now() + HAIKU_BACKOFF_MS;
    return null;
  }
}

function formatTurnFallback(userText, toolUses) {
  // Rule-based: truncate user text as input, format tool names as actions
  const input = userText.slice(0, 60).replace(/\n/g, ' ').trim();
  const actions = toolUses.slice(0, 3).map(t => {
    const name = t.name || 'unknown';
    let arg = '';
    if (t.input) {
      if (t.input.file_path) arg = basename(t.input.file_path);
      else if (t.input.command) arg = t.input.command.replace(/\n/g, ' ').slice(0, 40);
    }
    return arg ? `${name}: ${arg}` : name;
  });
  return { input: input || 'working...', actions };
}

function updateSessionTimeline(bodyObj, acctName, usage, token) {
  const cwd = extractCwd(bodyObj);
  const sessionId = deriveSessionId(cwd, acctName);
  const model = bodyObj.model || '';

  // Detect repo/branch from cwd
  let repo = '', branch = '';
  const cwdStr = typeof cwd === 'string' && !cwd.startsWith('_sys_') ? cwd : '';
  if (cwdStr) {
    repo = basename(cwdStr);
    // Sanitize for shell: reject paths with characters that could escape double quotes
    if (!/["$`\\]/.test(cwdStr)) {
      try {
        branch = execSync(`git -C "${cwdStr}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 2000 }).trim();
      } catch {}
    }
  }

  // Create or retrieve session
  let session = monitoredSessions.get(sessionId);
  if (!session) {
    // Enforce max active sessions
    if (monitoredSessions.size >= SESSION_MAX_ACTIVE) {
      // Expire oldest
      let oldestId = null, oldestTs = Infinity;
      for (const [id, s] of monitoredSessions) {
        if (s.lastActiveAt < oldestTs) { oldestTs = s.lastActiveAt; oldestId = id; }
      }
      if (oldestId) {
        persistCompletedSession(monitoredSessions.get(oldestId));
        monitoredSessions.delete(oldestId);
      }
    }
    session = {
      id: sessionId,
      account: acctName,
      model,
      cwd: cwdStr || cwd,
      repo,
      branch,
      timeline: [],
      currentActivity: null,
      filesModified: [],
      requestCount: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUserHash: null,
      pendingHaiku: false,
      queuedTurns: [],
      startedAt: Date.now(),
      lastActiveAt: Date.now(),
      status: 'active',
      completedAt: null,
    };
    monitoredSessions.set(sessionId, session);
  }

  // Update session metadata
  session.lastActiveAt = Date.now();
  session.requestCount++;
  if (model) session.model = model;
  if (usage) {
    session.totalInputTokens += usage.inputTokens || 0;
    session.totalOutputTokens += usage.outputTokens || 0;
  }

  // Update current activity (no AI)
  const activity = formatCurrentActivity(bodyObj);
  if (activity) session.currentActivity = activity;

  // Detect new turn
  const turn = detectNewTurn(bodyObj, session);
  if (!turn) return;

  // Extract files modified from tool uses
  const newFiles = extractFilesModified(turn.toolUses);
  for (const f of newFiles) {
    if (!session.filesModified.includes(f)) {
      session.filesModified.push(f);
      if (session.filesModified.length > SESSION_FILES_MAX) session.filesModified.shift();
    }
  }

  // Batch turns: accumulate for 10s, then summarise together
  session.queuedTurns.push(turn);
  if (session.queuedTurns.length > 10) session.queuedTurns.splice(0, session.queuedTurns.length - 5);
  if (session._batchTimer || session.pendingHaiku) return;
  session._batchTimer = setTimeout(() => {
    session._batchTimer = null;
    const batch = session.queuedTurns.splice(0);
    if (!batch.length) return;
    // Merge batch: combine user texts and tool uses, use latest assistant context
    const mergedUser = batch.map(t => t.userText).join(' | ');
    const mergedContext = batch[batch.length - 1].assistantContext;
    const mergedTools = batch.flatMap(t => t.toolUses);
    session.pendingHaiku = true;
    callHaikuSummary(mergedUser, mergedContext, mergedTools).then(result => {
      const summary = result || formatTurnFallback(mergedUser, mergedTools);
      if (summary.input) {
        session.timeline.push({ type: 'input', text: summary.input });
      }
      for (const action of (summary.actions || [])) {
        session.timeline.push({ type: 'action', text: action });
      }
      while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
      session.pendingHaiku = false;
      // If more turns arrived while we were waiting, kick off another batch
      if (session.queuedTurns.length > 0) {
        session._batchTimer = setTimeout(() => {
          session._batchTimer = null;
          // Re-trigger by pushing a synthetic empty turn check
          const next = session.queuedTurns.splice(0);
          if (!next.length) return;
          const mu = next.map(t => t.userText).join(' | ');
          const mc = next[next.length - 1].assistantContext;
          const mt = next.flatMap(t => t.toolUses);
          const fb = formatTurnFallback(mu, mt);
          if (fb.input) session.timeline.push({ type: 'input', text: fb.input });
          for (const a of fb.actions) session.timeline.push({ type: 'action', text: a });
          while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
        }, 10000);
      }
    }).catch(() => {
      const fb = formatTurnFallback(mergedUser, mergedTools);
      if (fb.input) session.timeline.push({ type: 'input', text: fb.input });
      for (const a of fb.actions) session.timeline.push({ type: 'action', text: a });
      while (session.timeline.length > SESSION_TIMELINE_MAX) session.timeline.shift();
      session.pendingHaiku = false;
      session.queuedTurns.splice(0);
    });
  }, 10000);
}

function persistCompletedSession(session) {
  if (!session) return;
  session.status = 'completed';
  session.completedAt = session.completedAt || Date.now();
  sessionHistory.unshift({
    id: session.id,
    account: session.account,
    model: session.model,
    cwd: session.cwd,
    repo: session.repo,
    branch: session.branch,
    timeline: session.timeline.slice(0, SESSION_TIMELINE_MAX),
    requestCount: session.requestCount,
    totalInputTokens: session.totalInputTokens,
    totalOutputTokens: session.totalOutputTokens,
    startedAt: session.startedAt,
    completedAt: session.completedAt,
    duration: session.completedAt - session.startedAt,
  });
  if (sessionHistory.length > SESSION_HISTORY_MAX) sessionHistory.length = SESSION_HISTORY_MAX;
  try { writeFileSync(SESSION_HISTORY_FILE, JSON.stringify(sessionHistory, null, 2)); } catch {}
}

function getFileConflicts() {
  const fileToSessions = new Map(); // file → [{ id, account }]
  for (const [, session] of monitoredSessions) {
    if (session.status !== 'active') continue;
    for (const f of session.filesModified) {
      if (!fileToSessions.has(f)) fileToSessions.set(f, []);
      fileToSessions.get(f).push({ id: session.id, account: session.account });
    }
  }
  const conflicts = [];
  for (const [file, sessions] of fileToSessions) {
    // Deduplicate by session ID (same session can only count once)
    const uniqueById = new Map();
    for (const s of sessions) uniqueById.set(s.id, s.account);
    if (uniqueById.size >= 2) {
      const accounts = [...new Set(uniqueById.values())];
      conflicts.push({ file, accounts, count: uniqueById.size });
    }
  }
  return conflicts;
}

// Session expiry timer — check every 30s
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of monitoredSessions) {
    if (session.status === 'active' && now - session.lastActiveAt > SESSION_INACTIVITY_MS) {
      persistCompletedSession(session);
      monitoredSessions.delete(id);
    }
  }
}, 30000);

// ─────────────────────────────────────────────────
// [BETA] Ensure prepare-commit-msg hook in repos with local core.hooksPath
// ─────────────────────────────────────────────────

const _hookedRepoPaths = new Set(); // avoid re-checking the same repo

function ensureLocalCommitHook(cwd) {
  try {
    if (!settings.commitTokenUsage) return;
    // Check for local core.hooksPath override
    let localHooksPath;
    try {
      localHooksPath = execSync(`git -C "${cwd}" config --local core.hooksPath 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
    } catch { return; } // no local override
    if (!localHooksPath) return;

    // Resolve relative paths
    let repoRoot;
    try {
      repoRoot = execSync(`git -C "${cwd}" rev-parse --show-toplevel 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
    } catch { return; }

    const resolvedLocal = localHooksPath.startsWith('/') ? localHooksPath : join(repoRoot, localHooksPath);

    // Skip if already checked this repo
    if (_hookedRepoPaths.has(resolvedLocal)) return;
    _hookedRepoPaths.add(resolvedLocal);

    // Check for global hooks path
    let globalHooksPath;
    try {
      globalHooksPath = execSync('git config --global core.hooksPath 2>/dev/null', { encoding: 'utf8', timeout: 3000 }).trim();
    } catch { return; }
    if (!globalHooksPath) return;
    globalHooksPath = globalHooksPath.replace(/^~/, process.env.HOME || '');

    // If local == global, no problem
    if (resolvedLocal === globalHooksPath) return;

    // Read the global hook content
    const globalHookFile = join(globalHooksPath, 'prepare-commit-msg');
    if (!existsSync(globalHookFile)) return;
    const globalHookContent = readFileSync(globalHookFile, 'utf8');
    if (!globalHookContent.includes('vdm-token-usage')) return;

    // Check if local hook already has our marker
    const localHookFile = join(resolvedLocal, 'prepare-commit-msg');
    if (existsSync(localHookFile)) {
      const existing = readFileSync(localHookFile, 'utf8');
      if (existing.includes('vdm-token-usage')) return; // already installed
      // Back up existing hook
      try { renameSync(localHookFile, localHookFile + '.vdm-original'); } catch {}
    }

    // Copy global hook to local hooks dir
    mkdirSync(resolvedLocal, { recursive: true });
    writeFileSync(localHookFile, globalHookContent);
    try { execSync(`chmod +x "${localHookFile}"`, { timeout: 2000 }); } catch {}
    log('tokens', `Installed commit hook in ${resolvedLocal} (local hooksPath override detected)`);
  } catch { /* silent — best effort */ }
}

// ─────────────────────────────────────────────────
// [BETA] Token Usage Ring Buffer
// ─────────────────────────────────────────────────

const recentUsage = []; // { ts, inputTokens, outputTokens, model, account, claimed }
const RECENT_USAGE_MAX = 2000;

function recordUsage(usage, account) {
  if (!usage || (!usage.inputTokens && !usage.outputTokens)) return;
  recentUsage.push({
    ts: usage.ts || Date.now(),
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
    model: usage.model,
    account,
    claimed: false,
  });
  while (recentUsage.length > RECENT_USAGE_MAX) recentUsage.shift();
}

function claimUsageInRange(startTs, endTs) {
  const claimed = [];
  for (const entry of recentUsage) {
    if (!entry.claimed && entry.ts >= startTs && entry.ts <= endTs) {
      entry.claimed = true;
      claimed.push(entry);
    }
  }
  return claimed;
}

/**
 * When inside a Claude Code git worktree, the checked-out branch is an
 * auto-generated name like `worktree-jolly-dazzling-dolphin`.  Resolve it
 * back to the real feature branch so token usage is attributed correctly.
 */
function _resolveWorktreeBranch(cwd, detectedBranch) {
  if (!detectedBranch.startsWith('worktree-')) return detectedBranch;
  try {
    // Confirm we're actually in a worktree (git-dir != git-common-dir)
    const gitDir = execSync(`git -C "${cwd}" rev-parse --path-format=absolute --git-dir 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
    const commonDir = execSync(`git -C "${cwd}" rev-parse --path-format=absolute --git-common-dir 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
    if (gitDir === commonDir) return detectedBranch;
  } catch { return detectedBranch; }

  // Strategy 1: find a non-worktree branch at the exact same commit
  try {
    const candidates = execSync(`git -C "${cwd}" branch --points-at HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 })
      .trim().split('\n')
      .map(b => b.replace(/^[*+]?\s+/, '').trim())
      .filter(b => b && !b.startsWith('worktree-'));
    if (candidates.length === 1) return candidates[0];
    if (candidates.length > 1) return candidates.find(b => b.includes('/')) || candidates[0];
  } catch { /* ignore */ }

  // Strategy 2: walk recent commits for the closest decorated non-worktree branch
  try {
    const lines = execSync(`git -C "${cwd}" log --format=%D --max-count=30 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim().split('\n');
    for (const line of lines) {
      if (!line.trim()) continue;
      const refs = line.split(',').map(r => r.trim())
        .filter(r => r && !r.startsWith('HEAD') && !r.startsWith('worktree-') && !r.startsWith('origin/') && !r.startsWith('tag:'));
      if (refs.length > 0) return refs.find(r => r.includes('/')) || refs[0];
    }
  } catch { /* ignore */ }

  return detectedBranch;
}

// ─────────────────────────────────────────────────
// [BETA] Session Tracking
// ─────────────────────────────────────────────────

const pendingSessions = new Map(); // session_id → { repo, branch, commitHash, cwd, startedAt }

// Claim and persist usage for a session (used by auto-claim and stale pruning)
function _autoClaimSession(sessionId, session) {
  // Re-read branch before persisting (handles worktree branch switches)
  if (session.cwd) {
    try {
      const cur = _resolveWorktreeBranch(session.cwd, execSync(`git -C "${session.cwd}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim());
      if (cur && cur !== session.branch) {
        session.branch = cur;
        session.commitHash = execSync(`git -C "${session.cwd}" rev-parse --short HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
      }
    } catch { /* ignore */ }
  }
  const claimed = claimUsageInRange(session.startedAt, Date.now());
  for (const entry of claimed) {
    appendTokenUsage({
      ts: entry.ts,
      repo: session.repo,
      branch: session.branch,
      commitHash: session.commitHash,
      model: entry.model,
      inputTokens: entry.inputTokens,
      outputTokens: entry.outputTokens,
      account: entry.account,
    });
  }
  if (claimed.length > 0) {
    log('tokens', `Auto-claimed ${claimed.length} entries for session ${sessionId.slice(0, 8)}…`);
  }
}

// Periodically auto-persist unclaimed usage so the Tokens tab shows data
// even for long-running sessions that haven't called session-stop yet.
const TOKEN_AUTO_PERSIST_INTERVAL = 2 * 60 * 1000; // every 2 minutes
setInterval(() => {
  // For each active session, claim any unclaimed entries and persist them.
  // Update startedAt so we don't double-count on next interval.
  for (const [id, session] of pendingSessions) {
    const now = Date.now();
    // Re-read branch before persisting (handles worktree branch switches)
    if (session.cwd) {
      try {
        const cur = _resolveWorktreeBranch(session.cwd, execSync(`git -C "${session.cwd}" rev-parse --abbrev-ref HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim());
        if (cur && cur !== session.branch) {
          log('tokens', `Periodic: session ${id.slice(0, 8)}… branch updated: ${session.branch} → ${cur}`);
          session.branch = cur;
          session.commitHash = execSync(`git -C "${session.cwd}" rev-parse --short HEAD 2>/dev/null`, { encoding: 'utf8', timeout: 3000 }).trim();
        }
      } catch { /* ignore */ }
    }
    const claimed = claimUsageInRange(session.startedAt, now);
    for (const entry of claimed) {
      appendTokenUsage({
        ts: entry.ts,
        repo: session.repo,
        branch: session.branch,
        commitHash: session.commitHash,
        model: entry.model,
        inputTokens: entry.inputTokens,
        outputTokens: entry.outputTokens,
        account: entry.account,
      });
    }
    if (claimed.length > 0) {
      session.startedAt = now; // advance so we don't re-claim
      log('tokens', `Periodic persist: ${claimed.length} entries for session ${id.slice(0, 8)}…`);
    }
  }
  // Unclaimed entries outside any session's time range are left in the ring
  // buffer — they'll be claimed by session-stop, or age out naturally.
  // No (unknown) attribution: better to lose data than misattribute it.
}, TOKEN_AUTO_PERSIST_INTERVAL);

// ─────────────────────────────────────────────────
// [BETA] Token Usage Storage (token-usage.json)
// ─────────────────────────────────────────────────

const TOKEN_USAGE_MAX_ENTRIES = 50_000;
const TOKEN_USAGE_MAX_AGE = 90 * 24 * 60 * 60 * 1000; // 90 days
let _tokenUsageCache = null;

function loadTokenUsage() {
  if (_tokenUsageCache) return _tokenUsageCache;
  try {
    if (existsSync(TOKEN_USAGE_FILE)) {
      const raw = readFileSync(TOKEN_USAGE_FILE, 'utf8');
      _tokenUsageCache = JSON.parse(raw);
      return _tokenUsageCache;
    }
  } catch { /* corrupt file */ }
  _tokenUsageCache = [];
  return _tokenUsageCache;
}

function appendTokenUsage(entry) {
  const usage = loadTokenUsage();
  usage.push(entry);
  // Prune old entries
  const cutoff = Date.now() - TOKEN_USAGE_MAX_AGE;
  const pruned = usage.filter(e => e.ts >= cutoff);
  const final = pruned.length > TOKEN_USAGE_MAX_ENTRIES
    ? pruned.slice(pruned.length - TOKEN_USAGE_MAX_ENTRIES)
    : pruned;
  _tokenUsageCache = final;
  try {
    writeFileSync(TOKEN_USAGE_FILE, JSON.stringify(final, null, 2));
  } catch (e) {
    log('error', `Failed to write token-usage.json: ${e.message}`);
  }
}

// ─────────────────────────────────────────────────
// [BETA] Pipe helper — waits for stream to complete
// ─────────────────────────────────────────────────

function pipeAndWait(src, dst) {
  return new Promise(resolve => {
    let resolved = false;
    const done = () => { if (!resolved) { resolved = true; resolve(); } };
    src.on('end', done);
    src.on('error', done);
    dst.on('close', done);
    dst.on('error', done);
    src.pipe(dst);
  });
}

// ── Proxy server ──

const proxyServer = createServer((clientReq, clientRes) => {
  // Health checks bypass the serialization queue
  if (clientReq.method === 'GET' && clientReq.url === '/health') {
    handleProxyRequest(clientReq, clientRes).catch(err => {
      log('error', `Unhandled proxy error: ${err.message}\n${err.stack}`);
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Proxy error: ${err.message}` } }));
      }
    });
    return;
  }

  withSerializationQueue(() => handleProxyRequest(clientReq, clientRes)).catch(err => {
    if (err.message === 'queue_timeout') {
      log('warn', 'Request timed out in serialization queue');
      if (!clientRes.headersSent) {
        clientRes.writeHead(504, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'timeout_error', message: 'Request queued too long (serialization timeout)' } }));
      }
      return;
    }
    log('error', `Unhandled proxy error: ${err.message}\n${err.stack}`);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Proxy error: ${err.message}` } }));
    }
  });
});

async function handleProxyRequest(clientReq, clientRes) {
  // Health check
  if (clientReq.method === 'GET' && clientReq.url === '/health') {
    clientRes.writeHead(200, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({
      status: _circuitOpen ? 'passthrough' : 'ok',
      accounts: loadAllAccountTokens().length,
      activeToken: getActiveToken() ? 'present' : 'missing',
      circuitBreaker: _circuitOpen ? 'open' : 'closed',
      consecutiveExhausted: _consecutiveExhausted,
    }));
    return;
  }

  // ── Proxy disabled: smart passthrough ──
  // Buffers the body so we can detect 400-empty-body and retry with a fresh
  // keychain token or convert to 401 for Claude Code re-auth.
  if (!settings.proxyEnabled) {
    const bodyChunks = [];
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => bodyChunks.push(c));
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
    const body = Buffer.concat(bodyChunks);
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    try {
      await _smartPassthrough(clientReq, clientRes, body, fwd, 'proxy-disabled');
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Passthrough error: ${err.message}` } }));
      }
    }
    return;
  }

  // ── Circuit breaker: auto-passthrough after repeated proxy failures ──
  // When open, skip all proxy logic and forward directly to Anthropic.
  // This lets Claude Code's own auth / re-auth work normally.
  if (_isCircuitOpen()) {
    log('circuit', 'Circuit breaker open — smart passthrough');
    const bodyChunks = [];
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => bodyChunks.push(c));
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
    const body = Buffer.concat(bodyChunks);
    const fwd = stripHopByHopHeaders(clientReq.headers);
    fwd['host'] = 'api.anthropic.com';
    fwd['content-length'] = String(body.length);
    // Ensure OAuth beta flag is present (required for OAuth tokens)
    const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
    fwd['anthropic-beta'] = betas.join(',');
    try {
      await _smartPassthrough(clientReq, clientRes, body, fwd, 'circuit-breaker');
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Passthrough error: ${err.message}` } }));
      }
    }
    return;
  }

  // Buffer request body for replay on retry (with size guard to prevent OOM)
  const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50 MB
  const bodyChunks = [];
  let bodySize = 0;
  try {
    await new Promise((resolve, reject) => {
      clientReq.on('data', c => {
        bodySize += c.length;
        if (bodySize > MAX_BODY_SIZE) {
          reject(new Error('body_too_large')); // reject BEFORE destroy to win any sync error-event race
          clientReq.destroy();
          return;
        }
        bodyChunks.push(c);
      });
      clientReq.on('end', resolve);
      clientReq.on('error', reject);
    });
  } catch (e) {
    if (e.message === 'body_too_large') {
      clientRes.writeHead(413, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: `Request body too large (max ${MAX_BODY_SIZE / 1024 / 1024}MB)` }));
      return;
    }
    throw e;
  }
  const body = Buffer.concat(bodyChunks);
  const deadline = Date.now() + REQUEST_DEADLINE_MS;
  const isDeadlineExceeded = () => Date.now() > deadline;

  // Check if keychain has a token we haven't saved yet (e.g. user just did /login)
  // Skip during error spirals to avoid creating bogus auto-accounts from stale keychain tokens
  if (_consecutive400s < 3) {
    await autoDiscoverAccount().catch(() => {});
  }

  let allAccounts = loadAllAccountTokens();
  if (!allAccounts.length) {
    log('error', 'No accounts configured — trying passthrough');
    if (await _passthroughFallback(clientReq, clientRes, body, 'no-accounts')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No accounts configured. Run: vdm add <name>' } }));
    return;
  }

  const maxAttempts = allAccounts.length + 2; // +1 for refresh retry, +1 for minimal-header retry
  const triedTokens = new Set();
  const billingMarkedTokens = new Set(); // tokens marked billing-unavailable this request
  const refreshAttempted = new Set(); // track refresh attempts to prevent infinite loops
  let _bulkRefreshAttempted = false;   // per-request: tried force-refreshing all tokens?
  let _minimalHeaderRetried = false;   // per-request: tried minimal-header last resort?

  // Start with active keychain token, apply rotation strategy
  let token = getActiveToken();
  const activeAcct = allAccounts.find(a => a.token === token);

  if (settings.autoSwitch) {
    const { account: strategyPick, rotated } = _pickByStrategy({
      strategy: settings.rotationStrategy || 'conserve',
      intervalMin: settings.rotationIntervalMin || 60,
      currentToken: token,
      lastRotationTime,
      accounts: allAccounts,
      stateManager: accountState,
      excludeTokens: new Set(),
    });

    if (strategyPick) {
      const oldName = activeAcct?.label || activeAcct?.name || 'none';
      const pickName = strategyPick.label || strategyPick.name;
      const isSameAccount = activeAcct && strategyPick.name === activeAcct.name;
      const reason = rotated ? settings.rotationStrategy : 'unavailable';
      if (!isSameAccount) {
        log('proactive', `${oldName} → switch to ${pickName} (${reason})`);
      }
      try {
        await withSwitchLock(() => {
          writeKeychain(strategyPick.creds);
          invalidateTokenCache();
        });
      } catch (e) {
        log('warn', `Keychain write failed during proactive switch: ${e.message}`);
      }
      token = strategyPick.token;
      lastRotationTime = Date.now();
      if (!isSameAccount) {
        logEvent('proactive-switch', { from: oldName, to: pickName, reason });
        if (reason === 'unavailable') {
          notify('Account Switched', `${oldName} unavailable → ${pickName}`);
        }
      }
    } else if (!token) {
      log('error', 'No active account in keychain — trying passthrough');
      if (await _passthroughFallback(clientReq, clientRes, body, 'no-active-account')) return;
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No active account in keychain' } }));
      return;
    }
  }

  // Guard: never forward a null/empty token (causes 400 with no body)
  if (!token) {
    log('error', 'No active token available — trying passthrough with original auth');
    if (await _passthroughFallback(clientReq, clientRes, body, 'no-active-token')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'No active token available — check keychain access' } }));
    return;
  }

  // Pre-flight refresh: if the selected token is already expired, refresh it
  // before forwarding to avoid a wasted 401 round-trip (e.g. after laptop sleep)
  {
    const preAcct = allAccounts.find(a => a.token === token);
    if (preAcct && preAcct.expiresAt && preAcct.expiresAt < Date.now() && !isDeadlineExceeded()) {
      log('refresh-preflight', `${preAcct.label || preAcct.name}: token expired, refreshing before forwarding...`);
      const preAcctName = preAcct.label || preAcct.name;
      try {
        const result = await refreshAccountToken(preAcct.name);
        if (result.ok && result.skipped) {
          // Another process refreshed the on-disk token but our in-memory copy
          // is stale — do NOT seed refreshAttempted so the 401 handler can retry
          // with force: true to pick up the new token.
          log('refresh-preflight', `${preAcctName}: skipped (another process refreshed), will allow 401 retry`);
        } else if (result.ok) {
          refreshAttempted.add(preAcctName);
          invalidateAccountsCache();
          const refreshed = loadAllAccountTokens().find(a => a.name === preAcct.name);
          if (refreshed) {
            token = refreshed.token;
            try {
              await withSwitchLock(() => {
                writeKeychain(refreshed.creds);
                invalidateTokenCache();
              });
            } catch {}
            log('refresh-preflight', `${preAcctName}: refreshed OK, proceeding with new token`);
          }
        } else {
          // Refresh failed — seed refreshAttempted to avoid retrying the same
          // account in the 401 handler (it would just fail again after ~37s)
          refreshAttempted.add(preAcctName);
        }
      } catch (e) {
        refreshAttempted.add(preAcctName);
        log('refresh-preflight', `${preAcctName}: preflight refresh failed: ${e.message}`);
      }
    }
  }

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    // Deadline guard: on retries, bail early if we've run out of time
    if (attempt > 0 && isDeadlineExceeded()) {
      log('deadline', `Request deadline exceeded after ${attempt} attempts (${REQUEST_DEADLINE_MS}ms) — trying passthrough`);
      if (await _passthroughFallback(clientReq, clientRes, body, 'deadline-exceeded')) return;
      clientRes.writeHead(504, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'timeout_error',
          message: `Proxy request deadline exceeded (${REQUEST_DEADLINE_MS / 1000}s). All token refreshes may have timed out.`,
        },
      }));
      return;
    }

    triedTokens.add(token);
    const acct = allAccounts.find(a => a.token === token);
    const acctName = acct?.label || acct?.name || 'unknown';

    let proxyRes;
    let lastNetworkError;
    try {
      const headers = buildForwardHeaders(clientReq.headers, token);
      headers['content-length'] = String(body.length);
      proxyRes = await forwardToAnthropic(clientReq.method, clientReq.url, headers, body);
    } catch (err) {
      lastNetworkError = err;
      // Network error  - retry once with same token on transient errors
      if (err.code === 'ECONNRESET' || err.code === 'ETIMEDOUT' || err.code === 'ECONNREFUSED') {
        log('retry', `Network error (${err.code}) on ${acctName}, retrying once...`);
        await new Promise(r => setTimeout(r, 500));
        try {
          const headers = buildForwardHeaders(clientReq.headers, token);
          headers['content-length'] = String(body.length);
          proxyRes = await forwardToAnthropic(clientReq.method, clientReq.url, headers, body);
          lastNetworkError = null;
        } catch (err2) {
          lastNetworkError = err2;
          log('error', `Retry also failed on ${acctName}: ${err2.message}`);
        }
      } else {
        log('error', `Forward error on ${acctName}: ${err.message}`);
      }
    }

    // Network failure after retry  - try switching to another account before giving up
    if (lastNetworkError) {
      if (settings.autoSwitch) {
        const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
        if (next) {
          log('switch', `  → network error on ${acctName}, switching to ${next.label || next.name}`);
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during network-error switch: ${e.message}`);
          }
          token = next.token;
          logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: 'network-error' });
          continue;
        }
      }
      // All accounts tried or autoSwitch off — try passthrough fallback
      if (await _passthroughFallback(clientReq, clientRes, body, 'network-error-all-exhausted')) return;
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: `Upstream unreachable: ${lastNetworkError.message}` } }));
      return;
    }

    const status = proxyRes.statusCode;

    // ── 429: Rate limited → auto-switch (if enabled) ──
    if (status === 429) {
      const retryAfter = parseInt(proxyRes.headers['retry-after'] || '0', 10);

      // Transient burst 429s (short retry-after) are normal — Claude Code
      // retries on its own.  Pass through silently without noisy logging,
      // marking the account as limited, or sending notifications.
      const isTransient = retryAfter < 60;

      if (!isTransient) {
        markAccountLimited(token, acctName, retryAfter);
        logEvent('rate-limited', { account: acctName, retryAfter });
      }
      log('switch', `${acctName} → 429 ${isTransient ? 'transient' : 'rate limited'} (retry-after: ${retryAfter}s)`);

      if (!settings.autoSwitch || isTransient) {
        if (!isTransient) log('switch', '  → auto-switch OFF, returning 429 as-is');
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
        clientRes.on('close', () => { proxyRes.destroy(); });
        await pipeAndWait(proxyRes, clientRes);
        return;
      }

      await drainResponse(proxyRes);

      // Try next best account
      const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
      if (next) {
        log('switch', `  → switching to ${next.label || next.name}`);
        try {
          await withSwitchLock(() => {
            writeKeychain(next.creds);
            invalidateTokenCache();
            invalidateAccountsCache();
          });
        } catch (e) {
          log('warn', `Keychain write failed during 429 switch: ${e.message}`);
        }
        token = next.token;
        logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '429' });
        notify('Account Switched', `${acctName} rate-limited → ${next.label || next.name}`);
        continue;
      }

      // All exhausted
      log('switch', '  → all accounts exhausted, returning 429');
      logEvent('all-exhausted', {});
      notify('All Accounts Exhausted', `All ${allAccounts.length} accounts rate-limited. Reset: ${getEarliestReset()}`);
      clientRes.writeHead(429, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'rate_limit_error',
          message: `All ${allAccounts.length} accounts rate limited. Earliest reset: ${getEarliestReset()}`,
        },
      }));
      return;
    }

    // ── 401: Auth error → try refresh first, then fallback to switch ──
    if (status === 401) {
      log('switch', `${acctName} → 401 auth error`);

      await drainResponse(proxyRes);

      // Try to refresh the token (once per account per request)
      if (acct && !refreshAttempted.has(acctName) && !isDeadlineExceeded()) {
        refreshAttempted.add(acctName);
        log('refresh', `${acctName}: attempting token refresh after 401...`);
        try {
          const refreshResult = await refreshAccountToken(acct.name, { force: true });
          if (refreshResult.ok && !refreshResult.skipped) {
            log('refresh', `${acctName}: refresh succeeded, retrying request`);
            // Re-read the account to get new token
            invalidateAccountsCache();
            const refreshedAccounts = loadAllAccountTokens();
            const refreshedAcct = refreshedAccounts.find(a => a.name === acct.name);
            if (refreshedAcct && refreshedAcct.token !== acct.token) {
              token = refreshedAcct.token;
              triedTokens.delete(acct.token); // allow retry with genuinely new token
              continue;
            }
            // Refresh returned same token — treat as failed
            log('refresh', `${acctName}: refresh returned same token, treating as failed`);
          }
        } catch (e) {
          log('refresh', `${acctName}: refresh failed: ${e.message}`);
        }
      }

      // Refresh failed or already attempted  - fall through to existing logic
      markAccountExpired(token, acctName);
      logEvent('auth-expired', { account: acctName });

      if (!settings.autoSwitch) {
        log('switch', '  → auto-switch OFF — trying passthrough');
        if (await _passthroughFallback(clientReq, clientRes, body, '401-autoswitch-off')) return;
        clientRes.writeHead(401, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'Token expired' },
        }));
        return;
      }

      const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
      if (next) {
        log('switch', `  → switching to ${next.label || next.name}`);
        try {
          await withSwitchLock(() => {
            writeKeychain(next.creds);
            invalidateTokenCache();
          });
        } catch (e) {
          log('warn', `Keychain write failed during 401 switch: ${e.message}`);
        }
        token = next.token;
        logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '401' });
        notify('Account Switched', `${acctName} token expired → ${next.label || next.name}`);
        continue;
      }

      // No valid accounts left — try passthrough so Claude Code can re-auth
      log('switch', '  → no valid accounts remain — trying passthrough fallback');
      notify('All Tokens Expired', 'No valid accounts remain — trying passthrough');
      if (await _passthroughFallback(clientReq, clientRes, body, 'all-401-expired')) return;
      clientRes.writeHead(401, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({
        type: 'error',
        error: {
          type: 'authentication_error',
          message: 'All account tokens are expired. Re-add accounts with: vdm add <name>',
        },
      }));
      return;
    }

    // ── 400: Bad request → multi-layer recovery ──
    //
    // The Anthropic API returns 400 for many reasons: bad tokens, expired
    // OAuth, malformed headers, AND legitimate request errors.  We must
    // distinguish between "request is wrong" (switching won't help) and
    // "something about the proxy/token is wrong" (switching/refreshing can
    // help).  Multiple recovery strategies are tried in order.
    if (status === 400) {
      const bodyBuf = await drainResponse(proxyRes);
      const bodyStr = bodyBuf.toString('utf8').trim();

      // Track this 400 for the global consecutive-failure counter.
      // Time-decay: reset if last 400 was >30s ago (prevents stale counter
      // from a past episode affecting unrelated future requests).
      if (_consecutive400s > 0 && Date.now() - _consecutive400sAt > 30_000) {
        _consecutive400s = 0;
      }
      _consecutive400s++;
      _consecutive400sAt = Date.now();

      // ── Circuit breaker: stop the death spiral ──
      // If we've hit too many consecutive 400s across requests, all accounts
      // are likely dead (billing, expired, etc).  Open the circuit breaker
      // and fall through to passthrough mode instead of keep switching.
      if (_consecutive400s >= CIRCUIT_400_THRESHOLD) {
        _openCircuit(`${_consecutive400s} consecutive 400 errors`);
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
        return;
      }

      // Parse error type from response body
      let errorType = null;
      let parsedError = null;
      if (bodyStr) {
        try {
          parsedError = JSON.parse(bodyStr);
          errorType = parsedError?.error?.type || parsedError?.type || null;
        } catch {
          // Not JSON — HTML error page, garbled data, etc.
        }
      }

      // Detect the specific "no body" / empty-body / non-JSON patterns that
      // indicate this is NOT a legitimate request validation error
      const looksLikeAuthIssue =
        !bodyStr ||                                  // truly empty
        !parsedError ||                              // not valid JSON
        errorType === 'authentication_error' ||      // explicit auth error
        errorType === 'permission_error' ||           // permission issue
        /status code|no body|invalid.*token|unauthorized/i.test(bodyStr);  // heuristic

      // Billing errors (credit balance too low) are never fixable by token
      // refresh — skip straight to account switching (Strategy 3).
      const errorMessage = parsedError?.error?.message || '';
      const isBillingError = /credit balance|billing.*issue|payment.*required/i.test(errorMessage);

      // Billing errors: mark this account as temporarily unavailable so
      // pickBestAccount / pickByStrategy won't keep selecting it.
      // This is THE key fix for the death spiral: without this, the account
      // looks "available" (not expired, not rate-limited) and gets re-selected
      // on every subsequent request, causing an infinite cycle.
      if (isBillingError && token) {
        const BILLING_COOLDOWN_SEC = 300; // 5 min cooldown
        accountState.markLimited(token, acctName, BILLING_COOLDOWN_SEC);
        billingMarkedTokens.add(token);
        log('billing', `${acctName}: marked unavailable for ${BILLING_COOLDOWN_SEC}s (billing error)`);
      }

      // Only pass through immediately if it's clearly a request validation
      // error AND we haven't seen a suspicious pattern of repeated 400s
      if (errorType === 'invalid_request_error' && _consecutive400s < 3 && !isBillingError) {
        log('info', `${acctName} → 400 invalid_request_error (passing through): ${bodyStr.slice(0, 200)}`);
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
        return;
      }

      const reason = isBillingError ? `billing error (${errorMessage.slice(0, 80)})` :
        looksLikeAuthIssue ? 'auth/token issue' :
        _consecutive400s >= 3 ? `repeated 400s (${_consecutive400s} consecutive)` :
        `unknown (type: ${errorType || 'none'})`;
      log('error', `${acctName} → 400 (${reason}, body: ${bodyStr.slice(0, 300) || '(empty)'})`);
      logEvent('bad-request-400', { account: acctName, errorType, consecutive: _consecutive400s });

      // ── Strategy 1: Force-refresh ALL tokens if we're in a repeated-failure loop ──
      // (Skip for billing errors — refreshing tokens won't restore credits)
      if (_consecutive400s >= 3 && !_bulkRefreshAttempted && !isDeadlineExceeded() && !isBillingError) {
        _bulkRefreshAttempted = true;
        log('error', `${_consecutive400s} consecutive 400s — force-refreshing ALL account tokens (parallel)`);
        const toRefresh = allAccounts.filter(a => !refreshAttempted.has(a.label || a.name));
        for (const a of toRefresh) refreshAttempted.add(a.label || a.name);
        const results = await Promise.allSettled(
          toRefresh.map(a => refreshAccountToken(a.name, { force: true }))
        );
        for (let i = 0; i < results.length; i++) {
          if (results[i].status === 'rejected') {
            log('refresh', `${toRefresh[i].name}: bulk refresh failed: ${results[i].reason?.message}`);
          }
        }
        invalidateAccountsCache();
        allAccounts = loadAllAccountTokens(); // refresh stale allAccounts so account lookups work
        const refreshedAcct = allAccounts.find(a => a.name === (acct?.name));
        if (refreshedAcct && refreshedAcct.token !== token) {
          token = refreshedAcct.token;
          triedTokens.clear(); // all tokens changed — retry everything
          continue;
        }
      }

      // ── Strategy 2: Refresh this specific account's token ──
      // (Skip for billing errors — refreshing tokens won't restore credits)
      if (acct && !refreshAttempted.has(acctName) && !isDeadlineExceeded() && !isBillingError) {
        refreshAttempted.add(acctName);
        log('refresh', `${acctName}: attempting token refresh after 400...`);
        try {
          const refreshResult = await refreshAccountToken(acct.name, { force: true });
          if (refreshResult.ok && !refreshResult.skipped) {
            log('refresh', `${acctName}: refresh succeeded, retrying request`);
            invalidateAccountsCache();
            const refreshedAccounts = loadAllAccountTokens();
            const refreshedAcct = refreshedAccounts.find(a => a.name === acct.name);
            if (refreshedAcct && refreshedAcct.token !== acct.token) {
              token = refreshedAcct.token;
              triedTokens.delete(acct.token);
              continue;
            }
            log('refresh', `${acctName}: refresh returned same token, treating as failed`);
          }
        } catch (e) {
          log('refresh', `${acctName}: refresh failed: ${e.message}`);
        }
      }

      // ── Strategy 3: Switch to another account ──
      if (settings.autoSwitch) {
        const next = pickBestAccount(triedTokens) || pickAnyUntried(triedTokens);
        if (next) {
          log('switch', `  → 400 on ${acctName}, switching to ${next.label || next.name}`);
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during 400 switch: ${e.message}`);
          }
          token = next.token;
          logEvent('auto-switch', { from: acctName, to: next.label || next.name, reason: '400-error' });
          notify('Account Switched', `${acctName} → 400 error → ${next.label || next.name}`);
          continue;
        }
      }

      // ── Strategy 4 (last resort): Retry with minimal headers ──
      // If ALL accounts failed, the problem might be a forwarded header that
      // the API rejects.  Retry once with only the essential headers.
      if (!_minimalHeaderRetried) {
        _minimalHeaderRetried = true;
        log('error', 'All accounts returned 400 — retrying with minimal headers (last resort)');
        const minimalHeaders = {
          'host': 'api.anthropic.com',
          'authorization': `Bearer ${token}`,
          'content-type': clientReq.headers['content-type'] || 'application/json',
          'content-length': String(body.length),
          'anthropic-version': clientReq.headers['anthropic-version'] || '2023-06-01',
          'anthropic-beta': 'oauth-2025-04-20',
        };
        try {
          const retryRes = await forwardToAnthropic(clientReq.method, clientReq.url, minimalHeaders, body);
          if (retryRes.statusCode < 400 || retryRes.statusCode >= 500) {
            // It worked (or it's a server error, not our fault) — pipe through
            log('info', `Minimal-header retry succeeded (status ${retryRes.statusCode})`);
            _consecutive400s = 0;

            // The minimal-header retry succeeded — billing errors were header-caused,
            // not genuine. Clear the false billing marks from this request.
            if (billingMarkedTokens.size > 0) {
              for (const t of billingMarkedTokens) {
                accountState.clearBillingCooldown(t);
              }
              log('billing', `Cleared ${billingMarkedTokens.size} false-positive billing marks (header-caused)`);
            }

            // Log header diff for debugging: which headers were in the full request
            // but NOT in the minimal retry? One of these caused the 400.
            const fullHeaders = buildForwardHeaders(clientReq.headers, token);
            const strippedKeys = Object.keys(fullHeaders)
              .filter(k => !(k.toLowerCase() in {
                'host': 1, 'authorization': 1, 'content-type': 1,
                'content-length': 1, 'anthropic-version': 1, 'anthropic-beta': 1,
              }));
            if (strippedKeys.length > 0) {
              log('info', `Headers in full request but not minimal retry: ${strippedKeys.join(', ')}`);
            }
            clientRes.writeHead(retryRes.statusCode, retryRes.headers);
            retryRes.on('error', () => { try { clientRes.end(); } catch {} });
            clientRes.on('close', () => { retryRes.destroy(); });
            await pipeAndWait(retryRes, clientRes);
            return;
          }
          // Still 4xx — it's genuinely a bad request or truly dead tokens
          const retryBuf = await drainResponse(retryRes);
          log('error', `Minimal-header retry also returned ${retryRes.statusCode}: ${retryBuf.toString('utf8').slice(0, 200)}`);
        } catch (e) {
          log('error', `Minimal-header retry failed: ${e.message}`);
        }
      }

      // All strategies exhausted — try passthrough with original auth header
      // so Claude Code can reach the real API / trigger its own re-auth flow.
      log('error', `All 400 recovery strategies exhausted — trying passthrough fallback`);
      if (await _passthroughFallback(clientReq, clientRes, body, 'all-400-strategies-exhausted')) return;
      // Passthrough also failed — return the best error we have
      if (bodyStr) {
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
      } else {
        // Empty body = auth failure — return 401 to trigger Claude Code re-auth
        log('fallback', 'Final fallback: converting empty-body 400 → 401 to trigger re-auth');
        clientRes.writeHead(401, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: {
            type: 'authentication_error',
            message: 'Token expired (proxy: empty-body 400 converted to 401 after all recovery strategies)',
          },
        }));
      }
      return;
    }

    // ── 529: Overloaded → pass through, switching won't help ──
    if (status === 529) {
      log('info', `${acctName} → 529 overloaded (not switching  - server-side issue)`);
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
      clientRes.on('close', () => { proxyRes.destroy(); });
      await pipeAndWait(proxyRes, clientRes);
      return;
    }

    // ── Any other response: success or client error → pipe through ──
    _consecutive400s = 0; // reset on any non-400 response
    _consecutiveExhausted = 0;
    updateAccountState(token, acctName, proxyRes.headers, getFingerprintFromToken(token));

    // Check if utilization is critically high and log a warning (only at 90%, 95%, 100%)
    const u5h = parseFloat(proxyRes.headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    if (u5h >= 0.9) {
      const tier = u5h >= 1.0 ? 100 : u5h >= 0.95 ? 95 : 90;
      const lastTier = _lastWarnPct.get(acctName);
      if (lastTier !== tier) {
        _lastWarnPct.set(acctName, tier);
        log('warn', `${acctName} at ${tier}% of 5h limit`);
      }
    }

    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
    clientRes.on('close', () => { proxyRes.destroy(); });

    // [BETA] Extract token usage from SSE streaming responses
    const contentType = proxyRes.headers['content-type'] || '';
    if (contentType.includes('text/event-stream')) {
      const extractor = createUsageExtractor();
      proxyRes.pipe(extractor).pipe(clientRes);
      await new Promise(resolve => {
        let done = false;
        const finish = () => { if (!done) { done = true; resolve(); } };
        extractor.on('end', finish);
        extractor.on('error', finish);
        clientRes.on('close', finish);
      });
      recordUsage(extractor.getUsage(), acctName);
      // [BETA] Session Monitor — extract timeline from completed request
      setImmediate(() => {
        try {
          if (!settings.sessionMonitor) return;
          if (body.length > SESSION_BODY_MAX) {
            // For oversized bodies, extract cwd via regex on raw string to keep session alive
            const rawPrefix = body.toString('utf8', 0, Math.min(body.length, 4096));
            const cwdMatch = rawPrefix.match(/working directory:\s*(.+)/i);
            if (cwdMatch) {
              const cwd = cwdMatch[1].trim().split('\\n')[0].trim();
              const sid = deriveSessionId(cwd, acctName);
              const s = monitoredSessions.get(sid);
              if (s) s.lastActiveAt = Date.now();
            }
            return;
          }
          const bodyObj = JSON.parse(body.toString('utf8'));
          updateSessionTimeline(bodyObj, acctName, extractor.getUsage(), token);
        } catch {}
      });
    } else {
      await pipeAndWait(proxyRes, clientRes);
    }
    return;
  }

  // Should not reach here, but safety net
  log('error', 'Exhausted all retry attempts without resolution — trying passthrough');
  if (!clientRes.headersSent) {
    if (await _passthroughFallback(clientReq, clientRes, body, 'all-retries-exhausted')) return;
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'proxy_error', message: 'All accounts tried, none succeeded' } }));
  }
}

function getEarliestReset() {
  const fromState = _getEarliestReset(accountState);
  if (fromState !== 'unknown') return fromState;
  // Fallback: check persisted state
  let earliest = Infinity;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const ps of Object.values(persistedState)) {
    if (ps.resetAt && ps.resetAt > nowSec && ps.resetAt < earliest) earliest = ps.resetAt;
    if (ps.resetAt7d && ps.resetAt7d > nowSec && ps.resetAt7d < earliest) earliest = ps.resetAt7d;
  }
  if (earliest === Infinity) return 'unknown';
  const d = new Date(earliest * 1000);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ── Expose proxy state to dashboard ──

function getProxyStatus() {
  const accounts = loadAllAccountTokens();
  return {
    accounts: accounts.map(a => {
      const state = accountState.get(a.token);
      return {
        name: a.name,
        label: a.label,
        available: isAccountAvailable(a.token, a.expiresAt),
        ...(state || {}),
      };
    }),
    recentEvents: proxyEventLog.slice(0, 20),
  };
}

// ── Graceful shutdown ──

function shutdown(signal) {
  log('info', `Received ${signal}, shutting down...`);
  // Persist all active monitored sessions before exit
  for (const [id, session] of monitoredSessions) {
    persistCompletedSession(session);
    monitoredSessions.delete(id);
  }
  proxyServer.close();
  server.close();
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
let _inExceptionHandler = false;
process.on('uncaughtException', (err) => {
  if (_inExceptionHandler) return;        // break recursive EIO death spiral
  _inExceptionHandler = true;
  try {
    log('fatal', `Uncaught exception: ${err.message}`);
    log('fatal', err.stack);
  } catch { /* if even log() fails, swallow — keeping process alive is paramount */ }
  _inExceptionHandler = false;
  // Keep running  - the proxy is more useful alive with a logged error
});
process.on('unhandledRejection', (reason) => {
  try { log('fatal', `Unhandled rejection: ${reason}`); } catch { /* swallow */ }
});

proxyServer.listen(PROXY_PORT, () => {
  const s = settings;
  log('info', `API proxy on http://localhost:${PROXY_PORT} (proxy=${s.proxyEnabled ? 'on' : 'off'}, auto-switch=${s.autoSwitch ? 'on' : 'off'}, rotation=${s.rotationStrategy || 'conserve'}, ${loadAllAccountTokens().length} accounts)`);
});
