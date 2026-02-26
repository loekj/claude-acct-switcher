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

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env.CSW_PORT || '3333', 10);
const ACCOUNTS_DIR = join(__dirname, 'accounts');
const STATS_CACHE = join(process.env.HOME, '.claude', 'stats-cache.json');
const CONFIG_FILE = join(__dirname, 'config.json');
const STATE_FILE = join(__dirname, 'account-state.json');
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
  } catch {
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
          return;
        }
      }
    } catch { /* skip */ }
  }

  // Truly new account  - save it
  let idx = 1;
  while (existsSync(join(ACCOUNTS_DIR, `auto-${idx}.json`))) idx++;
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

const utilizationHistory = createUtilizationHistory(); // 5h window, ~2 min intervals
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

function notify(title, message) {
  if (!settings.notifications) return;
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

      profiles.push({
        name,
        label: email || name,
        subscriptionType: oauth.subscriptionType || 'unknown',
        rateLimitTier: oauth.rateLimitTier || 'unknown',
        expiresAt: oauth.expiresAt || 0,
        isActive: fp === activeFp,
        fingerprint: fp,
        rateLimits,
        dormant,
      });
    } catch {
      // skip corrupt files
    }
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
    json(res, { profiles, stats, probeStats, allExhausted, earliestReset });
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
      logActivity('manual-switch', { to: label || name });
      json(res, { ok: true, switched: name });
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
      const result = await refreshAccountToken(name);
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

  if (url.pathname === '/api/settings' && req.method === 'GET') {
    json(res, settings);
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'POST') {
    const body = await readBody(req);
    const patch = JSON.parse(body);
    if (typeof patch.autoSwitch === 'boolean') settings.autoSwitch = patch.autoSwitch;
    if (typeof patch.proxyEnabled === 'boolean') settings.proxyEnabled = patch.proxyEnabled;
    if (typeof patch.notifications === 'boolean') settings.notifications = patch.notifications;
    if (typeof patch.rotationStrategy === 'string' && ROTATION_STRATEGIES[patch.rotationStrategy]) {
      settings.rotationStrategy = patch.rotationStrategy;
      lastRotationTime = Date.now(); // reset timer on strategy change
    }
    if (typeof patch.rotationIntervalMin === 'number' && ROTATION_INTERVALS.includes(patch.rotationIntervalMin)) {
      settings.rotationIntervalMin = patch.rotationIntervalMin;
      lastRotationTime = Date.now(); // reset timer on interval change
    }
    saveSettings(settings);
    logActivity('settings-changed', {
      autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
      rotationStrategy: settings.rotationStrategy, rotationIntervalMin: settings.rotationIntervalMin,
    });
    json(res, settings);
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

  .card.switching { opacity: 0.5; pointer-events: none; }

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
  .chart-bar:hover { opacity: 0.75; }
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
  .velocity-badge.velocity-warn { color: var(--yellow); border-color: var(--yellow-border); background: var(--yellow-soft); }
  .velocity-badge.velocity-crit { color: var(--red); border-color: var(--red-border); background: var(--red-soft); }

  /* ── Animations ── */
  @keyframes fadeInUp {
    from { opacity: 0; transform: translateY(12px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .card { animation: fadeInUp 0.3s ease-out; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-left">
      <h1>Van Damme-o-Matic</h1>
      <div class="header-sub"><span id="account-count">0</span> accounts connected<span id="probe-stats"></span></div>
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
    <button class="tab" onclick="switchTab('config')">Config</button>
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
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
function switchTab(id) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  document.querySelector('.tab[onclick*="' + id + '"]').classList.add('active');
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
  if (sub === 'max') {
    cls = 'badge-max';
    const m = tier.match(/(\\d+)x/);
    label = m ? 'MAX ' + m[1] + 'x' : 'MAX';
  } else if (sub === 'pro') {
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

async function doSwitch(name, e) {
  if (e) e.stopPropagation();
  document.querySelectorAll('.card').forEach(c => c.classList.add('switching'));
  try {
    const resp = await fetch('/api/switch', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ name })
    });
    const data = await resp.json();
    if (data.ok) { showToast('Switched to ' + name); setTimeout(refresh, 300); }
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

function renderProbeStats(ps) {
  const el = document.getElementById('probe-stats');
  if (!ps || !ps.probeCount7d) { el.textContent = ''; return; }
  const totalTok = ps.inputTokens + ps.outputTokens;
  el.innerHTML = ' · ' + formatNum(ps.probeCount7d) + ' probes (7d) · ~' + formatNum(totalTok) + ' tokens overhead';
}

/**
 * Render a time-axis sparkline with real clock-time labels.
 * X-axis: (now - windowMs) on the left → now on the right.
 * Data populates left-to-right as time progresses.
 *
 * @param {Array} hist - history entries with { ts, u5h, u7d }
 * @param {string} key - 'u5h' or 'u7d'
 * @param {number} windowMs - fixed x-axis span in ms (5h or 7d)
 * @param {string} mode - 'hours' or 'days'  - controls label generation
 */
function renderSparkline(hist, key, windowMs, mode) {
  const W = 320, H = 44, padL = 1, padR = 1, padT = 1, padB = 12;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const now = Date.now();
  const windowStart = now - windowMs;

  // Generate real-time labels
  let svg = '';
  if (mode === 'hours') {
    // Hourly grid: find the first whole hour >= windowStart, then every hour
    const firstHour = new Date(windowStart);
    firstHour.setMinutes(0, 0, 0);
    if (firstHour.getTime() < windowStart) firstHour.setTime(firstHour.getTime() + 3600000);
    for (let t = firstHour.getTime(); t <= now; t += 3600000) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const label = d.getHours() + ':00';
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + label + '</text>';
    }
  } else {
    // Daily grid: find the first midnight >= windowStart, then every day
    const firstDay = new Date(windowStart);
    firstDay.setHours(0, 0, 0, 0);
    if (firstDay.getTime() < windowStart) firstDay.setTime(firstDay.getTime() + 86400000);
    const dayNames = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
    for (let t = firstDay.getTime(); t <= now; t += 86400000) {
      const x = padL + ((t - windowStart) / windowMs) * chartW;
      const d = new Date(t);
      const label = dayNames[d.getDay()];
      svg += '<line x1="' + x.toFixed(1) + '" y1="' + padT + '" x2="' + x.toFixed(1) + '" y2="' + (padT + chartH) + '" stroke="var(--border)" stroke-width="0.5" />';
      svg += '<text x="' + x.toFixed(1) + '" y="' + (H - 1) + '" fill="var(--muted)" font-size="6" text-anchor="middle" font-family="inherit">' + label + '</text>';
    }
  }

  // Data polyline  - position by real timestamp on the window axis
  if (hist && hist.length >= 2) {
    const points = hist
      .filter(h => h.ts >= windowStart)
      .map(h => {
        const x = padL + ((h.ts - windowStart) / windowMs) * chartW;
        const y = padT + chartH - (h[key] || 0) * chartH;
        return x.toFixed(1) + ',' + y.toFixed(1);
      }).join(' ');
    if (points) {
      svg += '<polyline points="' + points + '" fill="none" stroke="var(--primary)" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />';
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
  else if (min <= 30) { cls += ' velocity-crit'; text = 'Est. ' + formatEta(min) + ' to limit'; }
  else if (min <= 120) { cls += ' velocity-warn'; text = 'Est. ' + formatEta(min) + ' to limit'; }
  else { text = 'Est. ' + formatEta(min) + ' to limit'; }
  return '<span class="card-token-sep">&middot;</span>' +
    '<span class="' + cls + '" title="Estimated time until 5h rate limit is reached, based on current usage velocity">' + text + '</span>';
}

let _lastProfilesHash = '';
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
    const { profiles, stats, probeStats, allExhausted, earliestReset } = await resp.json();
    const ph = quickHash(profiles);
    // Always re-render when stale data exists so the "Xm ago" label stays current
    const hasStale = profiles.some(p => p.rateLimits && p.rateLimits.fetchedAt && !p.dormant &&
      Date.now() - p.rateLimits.fetchedAt > STALE_THRESHOLD);
    if (ph !== _lastProfilesHash || hasStale) {
      _lastProfilesHash = ph;
      renderAccounts(profiles, _firstRender);
    }
    document.getElementById('account-count').textContent = profiles.length;
    if (probeStats) renderProbeStats(probeStats);
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
}

const STALE_THRESHOLD = 10 * 60 * 1000; // 10 min

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

    // Staleness detection  - purely visual, no persisted state modified
    // Dormant accounts (0% on both windows) are excluded  - 0% doesn't go stale
    const isStale = !p.dormant && p.rateLimits && p.rateLimits.fetchedAt &&
      (Date.now() - p.rateLimits.fetchedAt > STALE_THRESHOLD);
    let staleLabel = '';
    if (isStale) {
      const agoMin = Math.round((Date.now() - p.rateLimits.fetchedAt) / 60000);
      const agoText = agoMin >= 60 ? Math.round(agoMin / 60) + 'h' : agoMin + 'm';
      staleLabel = '<span style="font-size:0.75rem;color:var(--muted);margin-left:0.25rem">(stale \\u00b7 ' + agoText + ' ago)</span>';
    }

    let barsHtml = '';
    if (p.rateLimits) {
      const rl = p.rateLimits;
      const f = Math.round(rl.fiveH.utilization * 100);
      const s = Math.round(rl.sevenD.utilization * 100);

      // 5hr sparkline  - real clock-time labels, left=5h ago, right=now
      const hist5h = p.utilizationHistory || [];
      const spark5h = '<div class="sparkline-wrap">' +
        renderSparkline(hist5h, 'u5h', 5*60*60*1000, 'hours') +
        '</div>';

      // Weekly sparkline  - day-of-week labels, left=7d ago, right=now
      const hist7d = p.weeklyHistory || [];
      const spark7d = '<div class="sparkline-wrap">' +
        renderSparkline(hist7d, 'u7d', 7*24*60*60*1000, 'days') +
        '</div>';

      barsHtml = '<div class="rate-bars">' +
        '<div class="rate-group">' +
          '<div class="rate-head"><span class="rate-label">5h window' + staleLabel + '</span><span class="rate-pct ' + pctClass(f) + '">' + f + '%</span></div>' +
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

    const staleClass = isStale ? ' stale' : '';
    const animStyle = animate ? ' style="animation-delay:' + (i*0.05) + 's"' : ' style="animation:none"';
    return '<div class="card' + (active ? ' active' : '') + staleClass + '"' + animStyle + '>' +
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
      (active ? '' : '<div style="margin-top:0.875rem;display:flex;justify-content:space-between;align-items:center"><button class="remove-btn" onclick="doRemove(\\''+eName+'\\',event)">Remove</button><button class="switch-btn" onclick="doSwitch(\\''+eName+'\\',event)">Switch to this account</button></div>') +
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
    };
    showToast(msgs[key] || (key + ' = ' + value));
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

refresh();
loadSettingsUI();
setInterval(refresh, 5000);
setInterval(tickCountdowns, 1000);
</script>
<footer style="text-align:center;padding:2rem 0 1rem;font-size:0.75rem;color:#9ca3af;line-height:1.8">
  <div>🤙 Vibe coded with love by LJ</div>
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
const MAX_EVENT_LOG = 50;

// ── Structured logger ──

function log(tag, msg, extra = '') {
  const ts = new Date().toLocaleTimeString('en-GB', { hour12: false });
  console.log(`[${ts}] [${tag}] ${msg}${extra ? ' ' + extra : ''}`);
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

// Drain a response and return the body (for error responses)
function drainResponse(res) {
  return new Promise(r => {
    let done = false;
    const chunks = [];
    const finish = () => { if (!done) { done = true; r(Buffer.concat(chunks)); } };
    res.on('data', c => chunks.push(c));
    res.on('end', finish);
    res.on('error', finish);
    // Safety: if stream stalls, resolve after 5s to prevent hanging forever
    setTimeout(finish, 5000);
  });
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

const OAUTH_TOKEN_URL = process.env.OAUTH_TOKEN_URL || 'https://console.anthropic.com/v1/oauth/token';
const REFRESH_BUFFER_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
const REFRESH_MAX_RETRIES = 3;
const REFRESH_BACKOFF_BASE = 1000; // 1s, 2s, 4s

const refreshLock = createPerAccountLock();

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
function callRefreshEndpoint(refreshToken) {
  return new Promise((resolve) => {
    const body = buildRefreshRequestBody(refreshToken);
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
        'Content-Type': 'application/x-www-form-urlencoded',
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
async function refreshAccountToken(accountName) {
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

    // 2. Check if still needs refresh (double-check after lock)
    if (!shouldRefreshToken(oauth.expiresAt, REFRESH_BUFFER_MS)) {
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
      result = await callRefreshEndpoint(oauth.refreshToken);
      if (result.ok) break;
      if (!result.retriable) break;
      // Exponential backoff: 1s, 2s, 4s
      const delay = REFRESH_BACKOFF_BASE * Math.pow(2, attempt);
      log('refresh', `${accountName}: attempt ${attempt + 1} failed (${result.error}), retrying in ${delay}ms...`);
      await new Promise(r => setTimeout(r, delay));
    }

    if (!result.ok) {
      log('refresh', `${accountName}: refresh failed after retries: ${result.error}`);
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
    logActivity('token-refreshed', { account: accountName });

    return { ok: true, accessToken: result.accessToken, expiresAt: newExpiresAt };
  });
}

// ── Background refresh timer ──

setInterval(async () => {
  const accounts = loadAllAccountTokens();
  for (const acct of accounts) {
    if (shouldRefreshToken(acct.expiresAt, REFRESH_BUFFER_MS)) {
      log('refresh-bg', `${acct.label || acct.name}: token near expiry, refreshing...`);
      try {
        await refreshAccountToken(acct.name);
      } catch (e) {
        log('refresh-bg', `${acct.label || acct.name}: background refresh error: ${e.message}`);
      }
    }
  }
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

// ── Proxy server ──

const proxyServer = createServer((clientReq, clientRes) => {
  handleProxyRequest(clientReq, clientRes).catch(err => {
    log('error', `Unhandled proxy error: ${err.message}\n${err.stack}`);
    if (!clientRes.headersSent) {
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: `Proxy error: ${err.message}` }));
    }
  });
});

async function handleProxyRequest(clientReq, clientRes) {
  // Health check
  if (clientReq.method === 'GET' && clientReq.url === '/health') {
    clientRes.writeHead(200, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({
      status: 'ok',
      accounts: loadAllAccountTokens().length,
      activeToken: getActiveToken() ? 'present' : 'missing',
    }));
    return;
  }

  // ── Proxy disabled: pure passthrough ──
  if (!settings.proxyEnabled) {
    const fwd = {};
    for (const [k, v] of Object.entries(clientReq.headers)) {
      const lk = k.toLowerCase();
      if (lk === 'host' || lk === 'connection') continue;
      fwd[k] = v;
    }
    fwd['host'] = 'api.anthropic.com';
    try {
      const proxyRes = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'api.anthropic.com', port: 443,
          path: clientReq.url, method: clientReq.method,
          headers: fwd, timeout: PROXY_TIMEOUT,
        }, resolve);
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('upstream timeout')));
        clientReq.pipe(req);
      });
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
      clientReq.on('close', () => { proxyRes.destroy(); });
      proxyRes.pipe(clientRes);
    } catch (err) {
      if (!clientRes.headersSent) {
        clientRes.writeHead(502, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({ error: `Passthrough error: ${err.message}` }));
      }
    }
    return;
  }

  // Buffer request body for replay on retry
  const bodyChunks = [];
  await new Promise((resolve, reject) => {
    clientReq.on('data', c => bodyChunks.push(c));
    clientReq.on('end', resolve);
    clientReq.on('error', reject);
  });
  const body = Buffer.concat(bodyChunks);

  // Check if keychain has a token we haven't saved yet (e.g. user just did /login)
  await autoDiscoverAccount().catch(() => {});

  const allAccounts = loadAllAccountTokens();
  if (!allAccounts.length) {
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ error: 'No accounts configured. Run: vdm add <name>' }));
    return;
  }

  const maxAttempts = allAccounts.length + 1; // +1 to allow for a refresh retry
  const triedTokens = new Set();
  const refreshAttempted = new Set(); // track refresh attempts to prevent infinite loops

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
      const reason = rotated ? settings.rotationStrategy : 'unavailable';
      log('proactive', `${oldName} → switch to ${strategyPick.label || strategyPick.name} (${reason})`);
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
      logEvent('proactive-switch', { from: oldName, to: strategyPick.label || strategyPick.name, reason });
      if (reason === 'unavailable') {
        notify('Account Switched', `${oldName} unavailable → ${strategyPick.label || strategyPick.name}`);
      }
    } else if (!token) {
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: 'No active account in keychain' }));
      return;
    }
  }

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
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
      // All accounts tried or autoSwitch off  - return the upstream error
      clientRes.writeHead(502, { 'Content-Type': 'application/json' });
      clientRes.end(JSON.stringify({ error: `Upstream unreachable: ${lastNetworkError.message}` }));
      return;
    }

    const status = proxyRes.statusCode;

    // ── 429: Rate limited → auto-switch (if enabled) ──
    if (status === 429) {
      const retryAfter = parseInt(proxyRes.headers['retry-after'] || '0', 10);
      markAccountLimited(token, acctName, retryAfter);
      logEvent('rate-limited', { account: acctName, retryAfter });
      log('switch', `${acctName} → 429 rate limited (retry-after: ${retryAfter}s)`);

      if (!settings.autoSwitch) {
        log('switch', '  → auto-switch OFF, returning 429 as-is');
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
        proxyRes.pipe(clientRes);
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
      if (acct && !refreshAttempted.has(acctName)) {
        refreshAttempted.add(acctName);
        log('refresh', `${acctName}: attempting token refresh after 401...`);
        try {
          const refreshResult = await refreshAccountToken(acct.name);
          if (refreshResult.ok && !refreshResult.skipped) {
            log('refresh', `${acctName}: refresh succeeded, retrying request`);
            // Re-read the account to get new token
            invalidateAccountsCache();
            const refreshedAccounts = loadAllAccountTokens();
            const refreshedAcct = refreshedAccounts.find(a => a.name === acct.name);
            if (refreshedAcct) {
              token = refreshedAcct.token;
              triedTokens.delete(acct.token); // allow retry with new token
              continue;
            }
          }
        } catch (e) {
          log('refresh', `${acctName}: refresh failed: ${e.message}`);
        }
      }

      // Refresh failed or already attempted  - fall through to existing logic
      markAccountExpired(token, acctName);
      logEvent('auth-expired', { account: acctName });

      if (!settings.autoSwitch) {
        log('switch', '  → auto-switch OFF, returning 401 as-is');
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

      // No valid accounts left
      log('switch', '  → no valid accounts remain');
      notify('All Tokens Expired', 'No valid accounts remain. Run: vdm add <name>');
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

    // ── 529: Overloaded → pass through, switching won't help ──
    if (status === 529) {
      log('info', `${acctName} → 529 overloaded (not switching  - server-side issue)`);
      clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
      proxyRes.pipe(clientRes);
      return;
    }

    // ── Any other response: success or client error → pipe through ──
    updateAccountState(token, acctName, proxyRes.headers, getFingerprintFromToken(token));

    // Check if utilization is critically high and log a warning
    const u5h = parseFloat(proxyRes.headers['anthropic-ratelimit-unified-5h-utilization'] || '0');
    if (u5h >= 0.9) {
      log('warn', `${acctName} at ${Math.round(u5h * 100)}% of 5h limit`);
    }

    clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
    proxyRes.pipe(clientRes);
    return;
  }

  // Should not reach here, but safety net
  log('error', 'Exhausted all retry attempts without resolution');
  if (!clientRes.headersSent) {
    clientRes.writeHead(502, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ error: 'All accounts tried, none succeeded' }));
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
  proxyServer.close();
  server.close();
  process.exit(0);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', (err) => {
  log('fatal', `Uncaught exception: ${err.message}`);
  log('fatal', err.stack);
  // Keep running  - the proxy is more useful alive with a logged error
});
process.on('unhandledRejection', (reason) => {
  log('fatal', `Unhandled rejection: ${reason}`);
});

proxyServer.listen(PROXY_PORT, () => {
  const s = settings;
  log('info', `API proxy on http://localhost:${PROXY_PORT} (proxy=${s.proxyEnabled ? 'on' : 'off'}, auto-switch=${s.autoSwitch ? 'on' : 'off'}, rotation=${s.rotationStrategy || 'conserve'}, ${loadAllAccountTokens().length} accounts)`);
});
