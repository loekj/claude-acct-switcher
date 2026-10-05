#!/usr/bin/env node
// Van Damme-o-Matic  - Dashboard
// Zero dependencies, uses Node.js built-in modules only.

import { createServer } from 'node:http';
import { readdir, readFile, writeFile, mkdir, unlink, chmod, rename, access, open } from 'node:fs/promises';
import { join, basename } from 'node:path';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { existsSync, writeFileSync, mkdirSync, readdirSync, readFileSync, unlinkSync, renameSync } from 'node:fs';
import { Transform, pipeline } from 'node:stream';
import { StringDecoder } from 'node:string_decoder';

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
const LEGACY_TOKEN_USAGE_FILE = join(__dirname, 'token-usage.json'); // pre-v4 per-request log, imported once
const USAGE_DIR = join(__dirname, 'usage');                           // hourly rollups, one file per UTC day
const SESSIONS_FILE = join(__dirname, 'sessions.json');               // session affinity pins + per-session stats
const ARTIFACTS_FILE = join(__dirname, 'artifacts.json');             // which account owns which artifact
const CLAUDE_DIR = process.env.CSW_CLAUDE_DIR || join(process.env.HOME, '.claude'); // Claude Code's data (session names); overridable for tests
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

// CSW_KEYCHAIN_SERVICE: use a different keychain item (tests run against a throwaway one).
const KEYCHAIN_SERVICE = process.env.CSW_KEYCHAIN_SERVICE || detectKeychainService();

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
  maxConcurrentPerAccount: 8, // balance mode: max concurrent in-flight requests per account
  balanceWaitMs: 10000,       // balance mode: wait for a freed slot before overflowing
  sessionAffinity: true,      // keep each Claude Code session on one account while its prompt cache is warm
  sessionHistory: false,      // save sessions to history/ (browse, search, continue later); off until turned on
  historyRetentionDays: 0,    // delete saved sessions this old (0 = keep forever)
  historyExclude: [],         // folders whose sessions are never saved
  claudeCommand: 'claude',    // how `vdm history continue|resume` and copied commands start Claude Code
  hotTokensPer5m: 25_000_000, // account charts: above this many tokens per 5 minutes the line turns red
  keepWarm: true,             // ping idle sessions so their prompt cache stays warm (smart, learned); on unless turned off
};

// Settings of features removed in v4 (commit token trailers, AI session monitor).
const REMOVED_SETTINGS = ['commitTokenUsage', 'sessionMonitor'];

function loadSettings() {
  let s = { ...DEFAULT_SETTINGS };
  try {
    if (existsSync(CONFIG_FILE)) {
      s = { ...DEFAULT_SETTINGS, ...JSON.parse(readFileSync(CONFIG_FILE, 'utf8')) };
    }
  } catch { /* corrupt file  - use defaults */ }
  for (const k of REMOVED_SETTINGS) delete s[k];
  return clampSettings(s);
}

// Clamp numeric balance settings even when set via a hand-edited config.json
// (the API validates these, but loadSettings spreads the raw file). Keeps the
// per-request slot wait safely under REQUEST_DEADLINE_MS (45s).
function clampSettings(s) {
  const n = (v, def, lo, hi) => (typeof v === 'number' && isFinite(v) ? Math.min(Math.max(v, lo), hi) : def);
  s.maxConcurrentPerAccount = Math.floor(n(s.maxConcurrentPerAccount, 8, 1, 50));
  s.balanceWaitMs = n(s.balanceWaitMs, 10000, 0, 30000);
  s.hotTokensPer5m = Math.round(n(s.hotTokensPer5m, 25_000_000, 100_000, 10_000_000_000));
  s.sessionHistory = s.sessionHistory === true;
  s.keepWarm = s.keepWarm !== false;
  s.historyRetentionDays = Math.floor(n(s.historyRetentionDays, 0, 0, 3650));
  const excludeAsked = (typeof s.historyExclude === 'string' ? s.historyExclude.split(/\r?\n/) : Array.isArray(s.historyExclude) ? s.historyExclude : [])
    .filter(x => typeof x === 'string' && x.trim());
  s.historyExclude = cleanExcludeList(s.historyExclude);
  if (s.historyExclude.length < excludeAsked.length) {
    console.error(`[config] historyExclude: ignored ${excludeAsked.length - s.historyExclude.length} folder(s) that are not full paths (use / or ~/)`);
  }
  s.claudeCommand = cleanClaudeCommand(s.claudeCommand) || 'claude';
  return s;
}

/** Folders never saved by session history: `~` expanded, only absolute paths. */
function cleanExcludeList(v) {
  if (typeof v === 'string') v = v.split(/\r?\n/);
  if (!Array.isArray(v)) return [];
  return v.filter(x => typeof x === 'string' && x.trim())
    .map(x => x.trim().replace(/^~(?=\/|$)/, process.env.HOME || '~').replace(/\/+$/, ''))
    .filter(x => x.startsWith('/'))
    .slice(0, 50);
}

/** A launch command for Claude Code: one line, not empty, not huge. */
function cleanClaudeCommand(v) {
  const c = typeof v === 'string' ? v.trim() : '';
  return c && c.length <= 300 && !/[\r\n\0]/.test(c) ? c : '';
}

function saveSettings(settings) {
  writeFileSync(CONFIG_FILE, JSON.stringify(settings, null, 2));
}

let settings = loadSettings();
// Drop settings of removed features from config.json
try {
  if (existsSync(CONFIG_FILE) && REMOVED_SETTINGS.some(k => k in JSON.parse(readFileSync(CONFIG_FILE, 'utf8')))) saveSettings(settings);
} catch { /* unreadable config  - leave it */ }
let lastRotationTime = 0; // tracks when proactive rotation last happened
let _consecutive400s = 0;  // global: consecutive 400 errors across requests (reset on success)
let _consecutive400sAt = 0;  // timestamp of last 400 (for time-based decay)
const _lastWarnPct = new Map(); // acctName → last logged percentage (dedup 90%+ warnings)
const _modelRouteLogged = new Map(); // "acct:model" → last log time (dedup per-model reroutes)

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
import { execFile, fork } from 'node:child_process';
import { setPriority } from 'node:os';
import { createReadStream } from 'node:fs';
import zlib from 'node:zlib';
import http from 'node:http';
import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders as _buildForwardHeaders,
  stripHopByHopHeaders,
  createAccountStateManager,
  createBalanceLimiter,
  parseRateLimitHeaders,
  modelFamily,
  createSessionStore,
  sessionAffinity,
  sessionLabel,
  extractSessionId,
  extractModel,
  cacheTtlFromBody,
  createSSEUsageParser,
  parseJsonUsage,
  usageCost,
  planMonthlyUsd,
  createUsageDay,
  summarizeUsage,
  cacheEfficiency,
  utcDay,
  extractArtifactRefs,
  artifactRefMatches,
  isAccountAvailable as _isAccountAvailable,
  scoreAccount as _scoreAccount,
  pickBestAccount as _pickBestAccount,
  pickLeastLoaded as _pickLeastLoaded,
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
  createThroughputStore,
  throughputFromRollups,
  HOUR_MS,
  KEEP_WARM_MIN_TOKENS,
  SIDE_CALL_MAX_TOKENS,
  lostCacheTokens,
  rebuildCost,
  pingCostRatio,
  breakEvenPings,
  isCacheRebuild,
  cacheFingerprint,
  classifyRebuild,
  returnCurve,
  weibullCurve,
  RETURN_PRIOR,
  bestPingCount,
  createKeepWarmPlanner,
  createCacheLedger,
  setTopLevelJsonFields,
  throughputLine,
  totalTokens,
  THROUGHPUT_BUCKET_MS,
  isLoopbackAddr,
  isLocalHost,
  originAllowed,
  isSameOrigin,
} from './lib.mjs';

// Both servers answer only this computer. CSW_ALLOW_REMOTE=1 lets other devices in
// (e.g. a devcontainer using host.docker.internal); web pages are still refused.
const ALLOW_REMOTE = process.env.CSW_ALLOW_REMOTE === '1';

// CSW_UPSTREAM (e.g. http://127.0.0.1:9999): send every API call to a stand-in server
// instead of api.anthropic.com (tests).
const UPSTREAM = process.env.CSW_UPSTREAM ? new URL(process.env.CSW_UPSTREAM) : null;

// http(s).request against the API host (or the CSW_UPSTREAM stand-in).
function apiRequest(options, onResponse) {
  if (!UPSTREAM) return https.request({ hostname: 'api.anthropic.com', port: 443, ...options }, onResponse);
  const mod = UPSTREAM.protocol === 'http:' ? http : https;
  return mod.request({ ...options, hostname: UPSTREAM.hostname, port: UPSTREAM.port || (UPSTREAM.protocol === 'http:' ? 80 : 443) }, onResponse);
}

// Fetch email from Anthropic roles API using OAuth token
function fetchAccountEmail(token) {
  return new Promise((resolve) => {
    const req = apiRequest({
      path: '/api/oauth/claude_cli/roles',
      method: 'GET',
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
    req.end();
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

  // Resolve email for the new token so we can deduplicate by identity.
  // Use the cached resolver (5-min TTL) — autoDiscover runs on every proxy request,
  // and an uncached fetch would hit api.anthropic.com once per request, hammering the
  // active account's token (exactly the per-account load balance mode tries to avoid).
  const token = creds.claudeAiOauth.accessToken;
  const email = await getEmailForToken(token, fp);

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
          rememberAccountEmail(savedName, email);
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

  // Backstop against runaway creation (error spirals are already gated separately
  // by the _consecutive400s check at the autoDiscoverAccount call site). Set high
  // enough not to block legitimate multi-account setups.
  const MAX_AUTO_ACCOUNTS = 25;
  if (idx > MAX_AUTO_ACCOUNTS) {
    console.log(`[auto-discover] Skipping — already ${idx - 1} auto accounts (max ${MAX_AUTO_ACCOUNTS})`);
    return;
  }

  const name = `auto-${idx}`;

  try { mkdirSync(ACCOUNTS_DIR, { recursive: true }); } catch {}
  writeFileSync(join(ACCOUNTS_DIR, `${name}.json`), JSON.stringify(creds, null, 2));

  if (email) {
    writeFileSync(join(ACCOUNTS_DIR, `${name}.label`), email);
    writeFileSync(join(ACCOUNTS_DIR, `${name}.email`), email);
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

  } catch {}
}

function writeHistoryFile() {
  _historyDirty = false;
  try {
    writeFileSync(HISTORY_FILE + '.tmp', JSON.stringify({ v: 2, fiveH: utilizationHistory.toJSON() }));
    renameSync(HISTORY_FILE + '.tmp', HISTORY_FILE);
  } catch {}
}

// Usage history changes on every response: mark it and write at most every 30 s (and on exit).
let _historyDirty = false;
function saveHistoryToDisk() { _historyDirty = true; }
setInterval(() => { if (_historyDirty) writeHistoryFile(); }, 30_000).unref?.();

loadHistoryFromDisk();

// Tokens per account (by email) in 5-minute buckets by model family (account-card charts), kept 26 h.
const THROUGHPUT_FILE = join(__dirname, 'throughput.json');
const throughput = createThroughputStore();
try { throughput.load(JSON.parse(readFileSync(THROUGHPUT_FILE, 'utf8'))); } catch { /* none yet */ }
let _throughputDirty = false;
function writeThroughputFile() {
  _throughputDirty = false;
  try {
    writeFileSync(THROUGHPUT_FILE + '.tmp', JSON.stringify(throughput.toJSON()));
    renameSync(THROUGHPUT_FILE + '.tmp', THROUGHPUT_FILE);
  } catch (e) { log('error', `Failed to save throughput.json: ${e.message}`); }
}
setInterval(() => { if (_throughputDirty) writeThroughputFile(); }, 30_000).unref?.();

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

    const req = apiRequest({
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
        const rl = parseRateLimitHeaders(h);
        resolve({
          status: rl.status || (res.statusCode === 429 ? 'rejected' : 'unknown'),
          fiveH: { reset: rl.fiveH?.reset || 0, utilization: rl.fiveH?.utilization || 0 },
          sevenD: { reset: rl.sevenD?.reset || 0, utilization: rl.sevenD?.utilization || 0 },
          // Per-model weekly bucket (Fable)  - only on accounts that have one
          sevenDOI: rl.sevenDOI ? { reset: rl.sevenDOI.reset, utilization: rl.sevenDOI.utilization } : null,
          overageStatus: rl.overageStatus || 'unknown',
          overageDisabledReason: h['anthropic-ratelimit-unified-overage-disabled-reason'] || '',
          headers: h,
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

// Why an account can't take requests right now (for the card), or null.
// { until (epoch s), what: human-readable limit }
function blockedInfo(name) {
  const a = loadAllAccountTokens().find(x => x.name === name);
  const st = a && accountState.get(a.token);
  if (!st) return null;
  const nowSec = Math.floor(Date.now() / 1000);
  const label = { five_hour: '5-hour limit', seven_day: 'weekly limit', seven_day_opus: 'weekly Opus limit', seven_day_sonnet: 'weekly Sonnet limit' };
  if (st.limited && st.limitedUntil > nowSec) return { until: st.limitedUntil, what: label[st.claim] || 'rate limited' };
  if (st.limited && st.retryAfter > Date.now()) return { until: Math.floor(st.retryAfter / 1000), what: 'cooling down' };
  if ((st.utilization5h || 0) >= 1 && st.resetAt > nowSec) return { until: st.resetAt, what: '5-hour limit' };
  if ((st.utilization7d || 0) >= 1 && st.resetAt7d > nowSec) return { until: st.resetAt7d, what: 'weekly limit' };
  return null;
}

// Per-model weekly limits that are used up (other models still work): [{ family, until }]
function modelBlocks(name) {
  const a = loadAllAccountTokens().find(x => x.name === name);
  const limits = a && accountState.get(a.token)?.modelLimits;
  const nowSec = Math.floor(Date.now() / 1000);
  return Object.entries(limits || {})
    .filter(([family, until]) => family !== 'fable' && until > nowSec)   // Fable has its own row
    .map(([family, until]) => ({ family, until }));
}

// Rate-limit view for the dashboard from tracked state (live or persisted).
function rateLimitsFromState(st, fetchedAt) {
  const limited = !!st.limitedUntil && st.limitedUntil > Math.floor(Date.now() / 1000);
  return {
    status: limited ? 'rejected' : 'ok',
    claim: st.claim || null,
    fiveH: { reset: st.resetAt || 0, utilization: st.utilization5h || 0 },
    sevenD: { reset: st.resetAt7d || 0, utilization: st.utilization7d || 0 },
    sevenDOI: st.utilization7dOI == null ? null : { reset: st.resetAt7dOI || 0, utilization: st.utilization7dOI || 0 },
    fableBlockedUntil: st.modelLimits?.fable || 0,
    fetchedAt,
  };
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
      return rateLimitsFromState(proxyState, proxyState.updatedAt);
    }
  }

  // 3. Check persisted state (survives restarts)
  const persisted = persistedState[fp];
  let fromPersisted = null;
  if (persisted && persisted.updatedAt) {
    // Pass through last-known values as-is. Don't zero out when the window
    // epoch has passed — that causes the UI to flash "0% / rolling window"
    // between data sources. The staleness indicator communicates the age.
    fromPersisted = rateLimitsFromState(persisted, persisted.updatedAt);
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
    const { headers, ...pub } = data;
    rateLimitCache.set(fp, { data: pub, fetchedAt: Date.now() });
    // Feed the probe into live state too, so balance/strategy pickers see used-up windows
    const acct = loadAllAccountTokens().find(a => a.token === token);
    if (acct) updateAccountState(token, acct.label || acct.name, headers, fp);
    else updatePersistedState(fp, {
      utilization5h: pub.fiveH.utilization, utilization7d: pub.sevenD.utilization,
      resetAt: pub.fiveH.reset, resetAt7d: pub.sevenD.reset,
      utilization7dOI: pub.sevenDOI?.utilization ?? null, resetAt7dOI: pub.sevenDOI?.reset || 0,
    });
    return pub;
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
        rememberAccountEmail(name, email);
      }
      if (!email) {
        try { email = (await readFile(join(ACCOUNTS_DIR, `${name}.label`), 'utf8')).trim(); } catch {}
      }

      const isActive = fp === activeFp;

      // Rate limit fetching strategy:
      // - Active account: always get fresh data (from probe cache or proxy state)
      // - Has persisted state with usage: use proxy state (updated from traffic), no probe needed
      // - Has persisted state at 0%: truly dormant in conserve mode, skip probe
      // - No state at all: probe ONCE to discover actual state, then persist
      let rateLimits = null;
      let dormant = false;
      if (oauth.accessToken) {
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

      // For the active account, prefer the live keychain's subscription/tier data
      // over stale stored files (which may predate Claude Code populating these fields).
      const activeOauth = activeCreds?.claudeAiOauth || {};
      const subType = (isActive && activeOauth.subscriptionType) ? activeOauth.subscriptionType
        : (oauth.subscriptionType || 'unknown');
      const rlTier = (isActive && activeOauth.rateLimitTier) ? activeOauth.rateLimitTier
        : (oauth.rateLimitTier || 'unknown');

      // Backfill: if the stored file has stale/missing tier data but keychain has it,
      // update the file so the data persists even when this account is inactive.
      if (isActive && activeOauth.rateLimitTier && activeOauth.rateLimitTier !== oauth.rateLimitTier) {
        try {
          const updatedCreds = { ...creds, claudeAiOauth: { ...oauth, subscriptionType: subType, rateLimitTier: rlTier } };
          writeFileSync(join(ACCOUNTS_DIR, file), JSON.stringify(updatedCreds, null, 2));
        } catch { /* non-critical */ }
      }

      profiles.push({
        name,
        label: email || name,
        id: (loadAllAccountTokens().find(a => a.name === name) || {}).id || email || name,
        subscriptionType: subType,
        rateLimitTier: rlTier,
        expiresAt,
        isActive,
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
        try { unlinkSync(join(ACCOUNTS_DIR, `${loser.name}.email`)); } catch {}
        sessionStore.renameAccount(loser.name, keepNew ? p.name : prevP.name);
        markSessionsDirty();
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

  if (url.pathname === '/api/history' || url.pathname.startsWith('/api/history/')) return handleHistoryAPI(req, res, url);

  if (url.pathname === '/api/cache-care' && req.method === 'GET') { json(res, cacheCareReport()); return true; }
  if (url.pathname === '/api/cache-care/mode' && req.method === 'POST') {
    const { sid, mode } = JSON.parse(await readBody(req) || '{}');
    if (!sid || typeof sid !== 'string' || !['auto', 'pin', 'never'].includes(mode)) { json(res, { error: 'sid and mode (auto|pin|never) required' }, 400); return true; }
    keepWarmPlanner.setMode(sid, mode);
    cacheCare.dirty = true;
    json(res, { ok: true, sid, mode });
    return true;
  }

  if (url.pathname === '/api/profiles' && req.method === 'GET') {
    const profiles = await loadProfiles();
    // Attach utilization history + velocity to each profile
    for (const p of profiles) {
      p.throughput = accountThroughput(p);
      p.velocity5h = utilizationHistory.getVelocity(p.id);
      p.minutesToLimit = utilizationHistory.predictMinutesToLimit(p.id);
      p.inflight = balanceLimiter.get(p.name); // balance-mode concurrent in-flight (0 in other modes)
      p.sessions = accountSessions(p.name);
      p.artifactCount = (artifactIndex.accounts[p.name]?.frames || []).length;
      p.blocked = blockedInfo(p.name);
      p.modelBlocks = modelBlocks(p.name);
      const c30 = cacheReport30d().byAccount[p.id];
      p.cache30d = c30 ? { hit: c30.hit, rebuild: c30.rebuild } : null;
    }
    const stats = await loadStats();
    const probeStats = getProbeStats();
    // Check if all accounts are exhausted
    const allAccounts = loadAllAccountTokens();
    const allExhausted = allAccounts.length > 0 &&
      allAccounts.every(a => !isAccountAvailable(a.token, a.expiresAt));
    const earliestReset = allExhausted ? getEarliestReset() : null;
    json(res, {
      profiles, stats, probeStats, allExhausted, earliestReset,
      rotationStrategy: settings.rotationStrategy, balanceCap: settings.maxConcurrentPerAccount || 8,
      sessionAffinity: settings.sessionAffinity !== false, sessionHistory: settings.sessionHistory === true, hotTokensPer5m: settings.hotTokensPer5m,
      cacheCare: cacheCareHeadline(), queueStats: getQueueStats(),
    });
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
      // A manual switch moves every session: release all affinity pins
      sessionStore.unpinAll('manual-switch');
      markSessionsDirty();
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
      try { await unlink(join(ACCOUNTS_DIR, `${name}.email`)); } catch {}
      sessionStore.unpinAccount(name);
      markSessionsDirty();
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
    json(res, { ...settings, claudeCommandEnv: process.env.VDM_CLAUDE_CMD || null });
    return true;
  }

  if (url.pathname === '/api/settings' && req.method === 'POST') {
    const body = await readBody(req);
    const patch = JSON.parse(body);
    if (typeof patch.historyExclude === 'string') patch.historyExclude = patch.historyExclude.split(/\r?\n/);
    // Refusals first, so a rejected request changes nothing
    if (Array.isArray(patch.historyExclude) &&
        cleanExcludeList(patch.historyExclude).length !== patch.historyExclude.filter(x => typeof x === 'string' && x.trim()).length) {
      json(res, { error: 'Use full folder paths (starting with / or ~/)' }, 400);
      return true;
    }
    if (patch.claudeCommand !== undefined && !isLoopbackAddr(req.socket.remoteAddress)) {
      json(res, { error: 'Only this computer can change the launch command' }, 403);
      return true;
    }
    if (patch.claudeCommand !== undefined && !cleanClaudeCommand(patch.claudeCommand)) {
      json(res, { error: 'Launch command must be one line (max 300 characters)' }, 400);
      return true;
    }
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
      // Balance mode supersedes the global serialize gate — disarm it so the two
      // beta gates never both apply.
      if (patch.rotationStrategy === 'balance' && settings.serializeRequests) {
        settings.serializeRequests = false;
        drainSerializationQueue();
      }
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
    if (typeof patch.maxConcurrentPerAccount === 'number' && patch.maxConcurrentPerAccount >= 1 && patch.maxConcurrentPerAccount <= 50) {
      settings.maxConcurrentPerAccount = Math.floor(patch.maxConcurrentPerAccount);
    }
    if (typeof patch.balanceWaitMs === 'number' && patch.balanceWaitMs >= 0 && patch.balanceWaitMs <= 30000) {
      settings.balanceWaitMs = patch.balanceWaitMs;
    }
    if (typeof patch.sessionAffinity === 'boolean') settings.sessionAffinity = patch.sessionAffinity;
    if (typeof patch.hotTokensPer5m === 'number' && patch.hotTokensPer5m >= 100_000 && patch.hotTokensPer5m <= 10_000_000_000) {
      settings.hotTokensPer5m = Math.round(patch.hotTokensPer5m);
    }
    if (typeof patch.keepWarm === 'boolean' && patch.keepWarm !== settings.keepWarm) {
      settings.keepWarm = patch.keepWarm;
      log('cache', patch.keepWarm ? 'Keep-warm on: idle sessions keep their prompt cache (learned limits)' : 'Keep-warm off');
    }
    const historyBefore = JSON.stringify(historyConfig());
    if (typeof patch.sessionHistory === 'boolean') settings.sessionHistory = patch.sessionHistory;
    if (typeof patch.historyRetentionDays === 'number' && patch.historyRetentionDays >= 0 && patch.historyRetentionDays <= 3650) {
      settings.historyRetentionDays = Math.floor(patch.historyRetentionDays);
    }
    if (Array.isArray(patch.historyExclude)) settings.historyExclude = cleanExcludeList(patch.historyExclude);
    if (patch.claudeCommand !== undefined) settings.claudeCommand = cleanClaudeCommand(patch.claudeCommand);
    saveSettings(settings);
    if (JSON.stringify(historyConfig()) !== historyBefore) applyHistorySettings();
    logActivity('settings-changed', {
      autoSwitch: settings.autoSwitch, proxyEnabled: settings.proxyEnabled,
      rotationStrategy: settings.rotationStrategy, rotationIntervalMin: settings.rotationIntervalMin,
    });
    json(res, settings);
    return true;
  }

  // ── Sessions (affinity) ──

  if (url.pathname === '/api/sessions' && req.method === 'GET') {
    const hours = Math.min(Math.max(parseInt(url.searchParams.get('hours') || '24', 10) || 24, 1), 168);
    json(res, { affinity: settings.sessionAffinity !== false, sessions: listSessions(hours) });
    return true;
  }

  // ── Artifacts (which account owns what) ──

  if (url.pathname === '/api/artifacts' && req.method === 'GET') {
    json(res, artifactsView());
    return true;
  }

  if (url.pathname === '/api/artifacts/refresh' && req.method === 'POST') {
    await refreshArtifacts('manual').catch(() => {});
    json(res, artifactsView());
    return true;
  }

  // ── Usage (hourly rollups) ──

  if (url.pathname === '/api/usage' && req.method === 'GET') {
    try {
      json(res, usageReport(url.searchParams));
    } catch (e) {
      json(res, { error: e.message }, 500);
    }
    return true;
  }

  if (url.pathname === '/api/usage/export' && req.method === 'GET') {
    const days = Math.min(Math.max(parseInt(url.searchParams.get('days') || '30', 10) || 30, 1), 400);
    const since = Date.now() - days * 86400000;
    const f = {};
    for (const k of ['repo', 'branch', 'model', 'account']) if (url.searchParams.get(k)) f[k] = url.searchParams.get(k);
    const rows = loadUsageRows(since, Date.now()).filter(r => r.h >= since
      && (!f.repo || r.repo === f.repo) && (!f.branch || r.branch === f.branch)
      && (!f.model || r.model === f.model) && (!f.account || r.account === f.account));
    const cols = ['hour', 'account', 'model', 'repo', 'branch', 'requests', 'input', 'output', 'cacheRead', 'cacheWrite5m', 'cacheWrite1h', 'webSearches', 'apiCostUsd'];
    const q = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const lines = [cols.join(',')];
    for (const r of rows.sort((a, b) => a.h - b.h)) {
      lines.push([
        new Date(r.h).toISOString(), q(r.account), q(r.model), q(r.repo), q(r.branch),
        r.requests, r.input, r.output, r.cacheRead, r.cacheWrite5m, r.cacheWrite1h, r.webSearches,
        usageCost({ ...r, speed: r.fast ? 'fast' : null }, r.model).toFixed(4),
      ].join(','));
    }
    res.writeHead(200, {
      'Content-Type': 'text/csv',
      'Content-Disposition': `attachment; filename="vdm-usage-${new Date().toISOString().slice(0, 10)}.csv"`,
    });
    res.end(lines.join('\n'));
    return true;
  }

  return false;
}

function json(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

const API_BODY_MAX = 1024 * 1024; // dashboard API bodies are tiny JSON

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', c => {
      size += c.length;
      if (size > API_BODY_MAX) { req.destroy(); reject(new Error('Request body too large')); return; }
      chunks.push(c);
    });
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
    --surface: hsl(220 14% 98%);
    --muted-foreground: var(--muted);
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
  @media (max-width: 720px) {
    .tabs { overflow-x: auto; scrollbar-width: none; }
    .tab { flex: 0 0 auto; padding: 0.5rem 0.75rem; white-space: nowrap; }
  }

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
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  .card-identity {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    min-width: 0;
  }
  .card-identity .card-name { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
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

  .card-badges { display: flex; gap: 0.375rem; align-items: center; flex-wrap: wrap; justify-content: flex-end; flex-shrink: 0; max-width: 60%; }
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

  /* Balance-mode per-account in-flight count */
  .badge-inflight { gap: 0.375rem; font-variant-numeric: tabular-nums; }
  .badge-inflight .inflight-cap { opacity: 0.5; font-weight: 400; }
  .badge-inflight .inflight-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex: none; }
  .inflight-idle { color: var(--muted); background: var(--bg); border-color: var(--border); }
  .inflight-idle .inflight-dot { opacity: 0.35; }
  .inflight-active { color: var(--purple); background: var(--purple-soft); border-color: var(--purple-border); }
  .inflight-active .inflight-dot { animation: inflightPulse 1.4s ease-in-out infinite; }
  .inflight-full { color: var(--yellow); background: var(--yellow-soft); border-color: var(--yellow-border); }
  @keyframes inflightPulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }

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

  /* ── Sessions & affinity ── */
  .tab-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    background: var(--border);
    color: var(--foreground);
    font-size: 0.625rem;
    font-weight: 700;
    min-width: 1rem;
    height: 1rem;
    border-radius: 0.5rem;
    padding: 0 0.25rem;
    margin-left: 0.375rem;
    vertical-align: middle;
  }
  /* Affinity strength: 3 bars = strong, 2 = ok, 1 = weak */
  .aff { display: inline-flex; align-items: flex-end; gap: 2px; height: 11px; flex-shrink: 0; }
  .aff i { display: block; width: 3px; border-radius: 1px; background: var(--border); }
  .aff i:nth-child(1) { height: 5px; }
  .aff i:nth-child(2) { height: 8px; }
  .aff i:nth-child(3) { height: 11px; }
  .aff-strong i { background: var(--green); }
  .aff-ok i:nth-child(-n+2) { background: var(--yellow); }
  .aff-weak i:nth-child(1) { background: var(--red); }
  .acct-sessions {
    margin-top: 0.875rem;
    padding-top: 0.75rem;
    border-top: 1px dashed var(--border);
  }
  .acct-sessions-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 0.375rem;
  }
  .sess-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; padding: 0.1875rem 0; }
  .sess-here { width: 6px; height: 6px; border-radius: 50%; background: var(--green); flex-shrink: 0; }
  .sess-here.away { background: var(--border); }
  .sess-name { flex: 1; min-width: 0; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sess-meta { font-size: 0.75rem; color: var(--muted); white-space: nowrap; font-variant-numeric: tabular-nums; }
  .link-btn {
    background: none;
    border: none;
    padding: 0;
    font-family: inherit;
    font-size: 0.75rem;
    color: var(--primary);
    cursor: pointer;
  }
  .link-btn:hover { text-decoration: underline; }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-family: inherit;
    font-size: 0.6875rem;
    font-weight: 500;
    padding: 0.125rem 0.5rem;
    border-radius: 999px;
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--muted);
    cursor: pointer;
  }
  .chip:hover { border-color: var(--primary); color: var(--primary); }
  .section-note { font-size: 0.8125rem; color: var(--muted); line-height: 1.55; margin-bottom: 0.875rem; }
  .sess-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
  }
  .sess-card-top { display: flex; align-items: center; gap: 0.5rem; }
  .sess-card-title { flex: 1; min-width: 0; font-weight: 600; font-size: 0.9375rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sess-sub { font-size: 0.75rem; color: var(--muted); margin-top: 0.125rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sess-aff-line { display: flex; align-items: center; gap: 0.5rem; font-size: 0.8125rem; margin-top: 0.625rem; }
  .sess-accts { margin-top: 0.5rem; }
  .sess-acct-row { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; padding: 0.125rem 0; font-variant-numeric: tabular-nums; }
  .sess-acct-name { width: 40%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sess-acct-bar { flex: 1; height: 5px; border-radius: 3px; background: var(--border); overflow: hidden; }
  .sess-acct-bar > div { height: 100%; background: var(--primary); }
  .sess-moves { margin-top: 0.5rem; font-size: 0.75rem; color: var(--muted); }
  .sess-move { padding: 0.0625rem 0; }
  .sess-move.warm { color: var(--red); }
  .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); box-shadow: 0 0 0 3px var(--green-soft); flex-shrink: 0; }
  .live-dot.off { background: var(--border); box-shadow: none; }

  /* ── Artifacts ── */
  .art-toolbar { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .art-search { flex: 1; min-width: 200px; cursor: text; }
  .art-group {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    margin-bottom: 0.75rem;
    overflow: hidden;
  }
  .art-group-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 0.5rem;
    padding: 0.625rem 1rem;
    font-size: 0.8125rem;
    font-weight: 600;
    border-bottom: 1px solid var(--border);
  }
  .art-row { display: flex; align-items: baseline; gap: 0.75rem; padding: 0.5rem 1rem; border-top: 1px solid var(--border); font-size: 0.8125rem; }
  .art-group-head + .art-row { border-top: none; }
  .art-title { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--foreground); text-decoration: none; font-weight: 500; }
  .art-title:hover { color: var(--primary); }
  .art-meta { font-size: 0.75rem; color: var(--muted); white-space: nowrap; }
  .art-err { font-size: 0.75rem; font-weight: 500; color: var(--red); }


  /* ── History ── */
  .hist-toolbar { display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.625rem; flex-wrap: wrap; }
  .hist-search { flex: 1 1 100%; min-width: 0; cursor: text; }
  .hist-check { display: inline-flex; align-items: center; gap: 0.375rem; font-size: 0.8125rem; color: var(--muted); cursor: pointer; }
  .hist-status { font-size: 0.8125rem; color: var(--muted); margin-bottom: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; }
  .hist-status b { color: var(--foreground); font-weight: 600; }
  .hist-status .warn { color: hsl(32 80% 38%); }
  .hist-progress { display: inline-block; width: 120px; height: 5px; border-radius: 3px; background: var(--border); overflow: hidden; vertical-align: middle; }
  .hist-progress > div { height: 100%; background: var(--primary); transition: width 0.4s; }
  .hist-day { font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 1rem 0 0.375rem; }
  .hist-day:first-child { margin-top: 0; }
  .hist-row {
    background: var(--card); border: 1px solid var(--border); border-radius: var(--radius-sm);
    padding: 0.625rem 0.875rem; margin-bottom: 0.375rem; cursor: pointer; transition: border-color 0.15s, box-shadow 0.15s;
  }
  .hist-row:hover, .hist-row:focus-visible { border-color: var(--primary); outline: none; }
  .hist-row.sel { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-soft); }
  .hist-top { display: flex; align-items: center; gap: 0.5rem; }
  .hist-title { flex: 1; min-width: 0; font-weight: 600; font-size: 0.875rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hist-cost { font-size: 0.75rem; color: var(--muted); font-variant-numeric: tabular-nums; white-space: nowrap; }
  .hist-sub { font-size: 0.75rem; color: var(--muted); margin-top: 0.125rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hist-text { font-size: 0.8125rem; margin-top: 0.375rem; line-height: 1.45; color: var(--foreground); overflow: hidden; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; word-break: break-word; }
  .hist-last { font-size: 0.75rem; color: var(--muted); margin-top: 0.25rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .hist-text mark, .hm mark { background: var(--yellow-soft); color: inherit; border-radius: 2px; padding: 0 1px; box-shadow: 0 0 0 1px var(--yellow-border); }
  .hist-chips { display: flex; gap: 0.25rem; flex-wrap: wrap; margin-top: 0.375rem; }
  .hist-chip { font-size: 0.6875rem; padding: 0.0625rem 0.4375rem; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); background: var(--bg); white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis; }
  .hist-chip.acct { color: var(--primary); border-color: var(--blue-border); background: var(--blue-soft); }
  .pill-saved { color: hsl(32 80% 38%); background: var(--yellow-soft); border: 1px solid var(--yellow-border); }
  .pill-soft { color: var(--muted); background: var(--bg); border: 1px solid var(--border); }
  .hist-more { display: block; margin: 0.75rem auto 0; }
  .hist-off { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); padding: 1.5rem 1.75rem; max-width: 640px; }
  .hist-off h3 { margin: 0 0 0.5rem; font-size: 1.0625rem; }
  .hist-off ul { margin: 0.5rem 0 1rem 1.125rem; padding: 0; font-size: 0.875rem; line-height: 1.6; color: var(--foreground); }
  .hist-off p { font-size: 0.8125rem; color: var(--muted); line-height: 1.55; margin: 0.5rem 0; }
  .hbtn {
    font-family: inherit; font-size: 0.8125rem; font-weight: 500; padding: 0.4375rem 0.875rem; border-radius: var(--radius-sm);
    border: 1px solid var(--border); background: var(--card); color: var(--foreground); cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 0.375rem;
  }
  .hbtn:hover { border-color: var(--primary); color: var(--primary); }
  .hbtn:disabled { opacity: 0.5; cursor: not-allowed; }
  .hbtn-primary { background: var(--primary); border-color: var(--primary); color: #fff; }
  .hbtn-primary:hover { color: #fff; filter: brightness(1.08); }
  .hbtn-danger { color: var(--red); }
  .hbtn-danger:hover { border-color: var(--red); color: var(--red); background: var(--red-soft); }
  .hist-backdrop { position: fixed; inset: 0; background: rgba(15, 23, 42, 0.28); z-index: 60; display: none; }
  .hist-backdrop.open { display: block; }
  .hist-drawer {
    position: fixed; top: 0; right: 0; bottom: 0; width: min(760px, 100vw); background: var(--bg); z-index: 61;
    box-shadow: var(--shadow-lg); transform: translateX(105%); transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1);
    display: flex; flex-direction: column;
  }
  .hist-drawer:not(.open) { visibility: hidden; transition: transform 0.22s cubic-bezier(0.4, 0, 0.2, 1), visibility 0s linear 0.22s; }
  .hist-drawer.open { transform: none; }
  .hd-scroll { overflow-y: auto; overflow-x: hidden; padding: 1.25rem 1.5rem 2rem; flex: 1; min-width: 0; }
  .hd-scroll > * { min-width: 0; }
  .hd-head { display: flex; align-items: flex-start; gap: 0.75rem; }
  .hd-title { flex: 1; min-width: 0; font-size: 1.125rem; font-weight: 700; line-height: 1.3; word-break: break-word; }
  .hd-close { border: none; background: none; font-size: 1.5rem; line-height: 1; color: var(--muted); cursor: pointer; padding: 0 0.25rem; }
  .hd-close:hover { color: var(--foreground); }
  .hd-sub { font-size: 0.8125rem; color: var(--muted); margin-top: 0.25rem; display: flex; gap: 0.375rem; flex-wrap: wrap; align-items: center; }
  .hd-id { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; }
  .hd-actions { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 0.75rem; margin-top: 1rem; }
  .hd-act { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.875rem 1rem; display: flex; flex-direction: column; gap: 0.5rem; min-width: 0; }
  .hd-act.main { border-color: var(--blue-border); box-shadow: 0 0 0 3px var(--primary-soft); }
  .hd-act-title { font-weight: 600; font-size: 0.875rem; }
  .hd-act-desc { font-size: 0.75rem; color: var(--muted); line-height: 1.5; }
  .hd-btns { display: flex; gap: 0.375rem; flex-wrap: wrap; margin-top: auto; }
  .hd-cmd { display: block; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.6875rem; background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.3125rem 0.5rem; color: var(--muted); overflow-x: auto; white-space: nowrap; }
  .hd-warn { font-size: 0.75rem; color: hsl(32 80% 38%); background: var(--yellow-soft); border: 1px solid var(--yellow-border); border-radius: 6px; padding: 0.375rem 0.5rem; line-height: 1.45; word-break: break-word; }
  .hd-facts { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0.3125rem 1rem; font-size: 0.8125rem; margin-top: 1.125rem; background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); padding: 0.875rem 1rem; }
  .hd-facts dt { color: var(--muted); }
  .hd-facts dd { margin: 0; min-width: 0; word-break: break-word; }
  .hd-files { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; line-height: 1.6; }
  .hd-conv-head { display: flex; align-items: center; gap: 0.5rem; margin: 1.25rem 0 0.5rem; }
  .hd-conv-head b { flex: 1; font-size: 0.875rem; }
  .hd-conv-head select { max-width: 60%; }
  .hm { margin-bottom: 0.5rem; border-radius: var(--radius-sm); padding: 0.5rem 0.75rem; font-size: 0.8125rem; line-height: 1.5; scroll-margin-top: 1rem; }
  .hm-who { font-size: 0.6875rem; font-weight: 600; color: var(--muted); margin-bottom: 0.125rem; text-transform: uppercase; letter-spacing: 0.04em; }
  .hm-user { background: var(--blue-soft); border: 1px solid var(--blue-border); }
  .hm-claude { background: var(--card); border: 1px solid var(--border); }
  .hm-text { white-space: pre-wrap; word-break: break-word; }
  .hm-text.clamp { max-height: 16em; overflow: hidden; -webkit-mask-image: linear-gradient(180deg, #000 70%, transparent); mask-image: linear-gradient(180deg, #000 70%, transparent); }
  .hm-recap { font-style: italic; color: var(--muted); border-left: 3px solid var(--border); border-radius: 0; padding: 0.25rem 0.75rem; }
  .hm-cmd { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; color: var(--muted); padding: 0.125rem 0.75rem; }
  .hm-tools { margin: 0 0 0.5rem; font-size: 0.75rem; color: var(--muted); }
  .hm-tools summary { cursor: pointer; padding: 0.125rem 0.75rem; list-style: none; }
  .hm-tools summary::before { content: '▸ '; }
  .hm-tools[open] summary::before { content: '▾ '; }
  .hm-tool { font-family: 'SF Mono', Monaco, Consolas, monospace; padding: 0.0625rem 0.75rem 0.0625rem 1.75rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .hm-compact { margin: 0.75rem 0; border: 1px dashed var(--purple-border); background: var(--purple-soft); border-radius: var(--radius-sm); font-size: 0.8125rem; }
  .hm-compact summary { cursor: pointer; padding: 0.375rem 0.75rem; color: var(--purple); font-weight: 600; font-size: 0.75rem; }
  .hm-compact .hm-text { padding: 0 0.75rem 0.5rem; }
  .hm.focus { box-shadow: 0 0 0 2px var(--yellow); }
  .hm-pager { display: flex; justify-content: center; margin: 0.5rem 0; }
  .hd-foot { display: flex; gap: 0.5rem; justify-content: space-between; margin-top: 1.25rem; padding-top: 1rem; border-top: 1px solid var(--border); flex-wrap: wrap; }
  .hd-input { width: 100%; font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 0.75rem; }
  @media (max-width: 720px) {
    .hd-actions { grid-template-columns: minmax(0, 1fr); }
    .hd-scroll { padding: 1rem 1rem 2rem; }
    .hd-facts { grid-template-columns: minmax(0, 1fr); }
    .hd-facts dt { margin-top: 0.375rem; }
  }

  /* ── Plan value ── */
  .plan-table { width: 100%; border-collapse: collapse; font-size: 0.8125rem; font-variant-numeric: tabular-nums; }
  .plan-table th {
    text-align: left;
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    padding: 0 0.5rem 0.375rem 0;
  }
  .plan-table td { padding: 0.375rem 0.5rem 0.375rem 0; border-top: 1px solid var(--border); }
  .plan-table .num { text-align: right; }
  .plan-table td.name { max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .val-good { color: var(--green); font-weight: 600; }
  .val-bad { color: var(--red); font-weight: 600; }

  /* ── Account card extras ── */
  .badge-soft { background: var(--card); color: var(--muted); border: 1px solid var(--border); }
  .blocked-banner {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin: -0.25rem 0 0.75rem;
    padding: 0.4375rem 0.75rem;
    border-radius: 8px;
    background: var(--red-soft);
    border: 1px solid var(--red-border);
    color: var(--red);
    font-size: 0.8125rem;
    font-weight: 500;
  }
  .blocked-banner .muted { color: var(--muted); font-weight: 400; }
  .blocked-banner.model { background: var(--yellow-soft); border-color: var(--yellow-border); color: hsl(32 80% 38%); }
  .rate-sub { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.375rem; font-size: 0.75rem; color: var(--muted); }
  .rate-sub .rate-track { flex: 1; height: 4px; }
  .rate-sub .rate-pct { font-size: 0.75rem; min-width: 2.5rem; text-align: right; }

  /* ── Sessions tab ── */
  .sess-toolbar { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .sess-toolbar .sess-meta { flex: 1; }
  .sess-section-title {
    font-size: 0.6875rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin: 1rem 0 0.5rem;
  }
  .sess-line {
    display: flex;
    align-items: center;
    gap: 0.625rem;
    padding: 0.5rem 1rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    margin-bottom: 0.375rem;
    font-size: 0.8125rem;
  }
  .pill {
    font-size: 0.625rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    padding: 0.0625rem 0.375rem;
    border-radius: 4px;
    flex-shrink: 0;
  }
  .pill-running { color: var(--green); background: var(--green-soft); border: 1px solid var(--green-border); }

  /* ── Usage extras ── */
  .eff-row {
    display: grid;
    grid-template-columns: minmax(0, 1.5fr) 96px minmax(0, 1.4fr) 4.5rem;
    align-items: center;
    gap: 0.75rem;
    padding: 0.4375rem 0;
    font-size: 0.875rem;
  }
  .eff-row + .eff-row { border-top: 1px solid var(--border); }
  .eff-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .eff-detail { color: var(--muted); font-size: 0.8125rem; text-align: right; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .eff-hit { text-align: right; font-weight: 600; font-variant-numeric: tabular-nums; }
  .eff-group { font-size: 0.6875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); margin: 0.875rem 0 0.25rem; }
  .notice { font-size: 0.8125rem; color: var(--muted); background: var(--surface); border: 1px dashed var(--border); border-radius: 8px; padding: 0.625rem 0.75rem; }
  .err-state { color: var(--red); }

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
  .spark-legend { display: flex; flex-wrap: wrap; gap: 0.125rem 0.625rem; font-size: 0.625rem; color: var(--muted); margin-top: 0.125rem; font-variant-numeric: tabular-nums; }
  .spark-hot { color: var(--red); font-weight: 600; }

  /* ── Smart cache ── */
  .sc-head { display: flex; align-items: center; gap: 1rem; margin: 0.25rem 0 0.875rem; }
  .sc-big { font-size: 2.25rem; font-weight: 700; line-height: 1; color: var(--green); font-variant-numeric: tabular-nums; }
  .sc-big.none { color: var(--muted); font-size: 1.5rem; }
  .sc-sub { font-size: 0.8125rem; color: var(--muted); line-height: 1.5; }
  .sc-sub b { color: var(--foreground); }
  .sc-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.75rem; }
  .sc-cell { border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 0.625rem 0.75rem; font-size: 0.8125rem; line-height: 1.5; min-width: 0; }
  .sc-cell-title { font-weight: 600; margin-bottom: 0.25rem; }
  .sc-num { font-variant-numeric: tabular-nums; }
  .sc-cause { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 0.5rem; font-size: 0.75rem; padding: 0.125rem 0; }
  .sc-cause-name { color: var(--muted); line-height: 1.35; }
  .sc-learned { font-size: 0.75rem; color: var(--muted); margin-top: 0.75rem; }
  .sc-off { font-size: 0.8125rem; background: var(--yellow-soft); border: 1px solid var(--yellow-border); border-radius: var(--radius-sm); padding: 0.5rem 0.75rem; margin-bottom: 0.75rem; }
  .sess-cache { display: flex; align-items: center; gap: 0.5rem; font-size: 0.75rem; color: var(--muted); margin-top: 0.375rem; flex-wrap: wrap; }
  .sess-cache b { color: var(--foreground); font-weight: 600; }
  .sess-cache .ok { color: var(--green); }
  .sess-cache select { font-size: 0.6875rem; padding: 0.0625rem 0.25rem; margin-left: auto; }
  @media (max-width: 720px) { .sc-grid { grid-template-columns: minmax(0, 1fr); } }
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
    max-width: 240px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
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
  #tok-stats.stat-grid { grid-template-columns: repeat(4, 1fr); }
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
    <button class="tab" onclick="switchTab('sessions')">Sessions<span id="sessions-badge" class="tab-badge" style="display:none"></span></button>
    <button class="tab" onclick="switchTab('history')">History</button>
    <button class="tab" onclick="switchTab('artifacts')">Artifacts</button>
    <button class="tab" onclick="switchTab('usage')">Usage</button>
    <button class="tab" onclick="switchTab('activity')">Activity</button>
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
        <option value="365">1 year</option>
      </select>
      <button class="tok-export-btn" onclick="exportUsageCsv()">Export CSV</button>
    </div>
    <div class="usage-card" style="margin-bottom:1rem" id="tok-smartcache"><div class="usage-title">Smart cache</div><div class="sc-sub">Loading...</div></div>
    <div id="tok-empty" class="empty-state" style="display:none"></div>
    <div id="tok-content" style="display:none">
      <div id="tok-stats" class="stat-grid" style="margin-bottom:1rem"></div>
      <div class="usage-card" style="margin-bottom:1rem" id="tok-savings-chart"></div>
      <div class="usage-card" style="margin-bottom:1rem" id="tok-chart"></div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Plan value</div>
        <div class="section-note">What each account's usage would cost at API prices (cache reads and writes included), against its subscription price for the same period.</div>
        <div id="tok-plans"></div>
      </div>
      <div class="usage-card" style="margin-bottom:1rem">
        <div class="usage-title">Cache efficiency &middot; last 30 days, all traffic</div>
        <div class="section-note">Hit = share of prompt tokens read from cache: higher is cheaper and uses up limits slower. Rebuilt = share written to cache again; it rises when sessions move between accounts. The line is the daily hit rate.</div>
        <div id="tok-cache"></div>
      </div>
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
    <div id="stats-section" class="usage-card" style="display:none;margin-top:1rem">
      <div class="usage-title">Claude Code's own counters (this Mac, all time)</div>
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

  <div id="tab-sessions" class="tab-content">
    <div class="section-note" id="sessions-note"></div>
    <div class="sess-toolbar">
      <select class="config-select" id="sess-account" onchange="renderSessions()" aria-label="Filter sessions by account"><option value="">All accounts</option></select>
      <span class="sess-meta" id="sess-counts"></span>
    </div>
    <div id="sessions-content"><div class="empty-state">Loading...</div></div>
  </div>


  <div id="tab-history" class="tab-content">
    <div id="hist-off" class="hist-off" style="display:none">
      <h3>Session history is off</h3>
      <p>Claude Code deletes old sessions after 30 days. With history on, vdm keeps them, so you can:</p>
      <ul>
        <li>search everything said in any session (your prompts, Claude's replies, files, commands)</li>
        <li>continue an old session in a new one: copy one prompt, paste it in, done</li>
        <li>resume a session exactly, even after Claude Code deleted it</li>
      </ul>
      <p>No AI is used for this, and nothing leaves this computer. While Claude Code still has a session, the saved copy uses no extra disk (it is a hard link). Only text is indexed for search.</p>
      <div style="display:flex;gap:0.5rem;align-items:center;margin-top:1rem">
        <button class="hbtn hbtn-primary" onclick="histTurnOn()">Turn on session history</button>
        <span class="sess-meta" id="hist-off-note"></span>
      </div>
    </div>
    <div id="hist-main">
      <div class="hist-toolbar">
        <input class="config-select hist-search" id="hist-q" placeholder='Search all sessions, e.g. vat portugal file:app.js branch:fix "exact words"' aria-label="Search sessions" oninput="histQueryChanged()" onkeydown="histSearchKey(event)">
        <select class="config-select" id="hist-project" onchange="histFilterChanged()" aria-label="Project"><option value="">All projects</option></select>
        <select class="config-select" id="hist-account" onchange="histFilterChanged()" aria-label="Account"><option value="">All accounts</option></select>
        <select class="config-select" id="hist-days" onchange="histFilterChanged()" aria-label="Period">
          <option value="0">Any time</option><option value="1">Today</option><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option>
        </select>
        <label class="hist-check" title="Sessions started by scripts (claude -p, SDK)"><input type="checkbox" id="hist-auto" onchange="histFilterChanged()"> Automated</label>
      </div>
      <div class="hist-status" id="hist-status"></div>
      <div id="hist-list"><div class="empty-state">Loading...</div></div>
    </div>
    <div class="hist-backdrop" id="hist-backdrop" onclick="histClose()"></div>
    <aside class="hist-drawer" id="hist-drawer" role="dialog" aria-modal="true" aria-label="Session details">
      <div class="hd-scroll" id="hist-detail"></div>
    </aside>
  </div>

  <div id="tab-artifacts" class="tab-content">
    <div class="section-note">Claude Code publishes artifacts with its own login (the active account), not through the proxy. This list asks every account which artifacts it owns. Paste a link or type a title to find the owner.</div>
    <div class="art-toolbar">
      <input class="config-select art-search" id="art-search" placeholder="Search title or paste an artifact link" aria-label="Search artifacts" oninput="renderArtifacts()" onkeydown="if (event.key === 'Escape') { this.value = ''; renderArtifacts(); }">
      <button class="tok-export-btn" id="art-refresh" onclick="refreshArtifactsNow()">Check now</button>
    </div>
    <div class="section-note" id="art-status" style="margin-bottom:0.5rem"></div>
    <div id="artifacts-content"><div class="empty-state">Loading...</div></div>
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
          <input type="checkbox" class="sw" id="toggle-proxy" aria-label="Enable proxy" checked onchange="toggleSetting('proxyEnabled', this.checked)">
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Auto-switch on rate limit</div>
            <div class="config-desc">Automatically switch to another account when the current one hits a 429 or 401</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-autoswitch" aria-label="Auto-switch on rate limit" checked onchange="toggleSetting('autoSwitch', this.checked)">
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
            <option value="balance">Balance</option>
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
        <div class="config-row" id="max-concurrent-ctrl" style="display:none">
          <div class="config-info">
            <div class="config-label">Max concurrent per account</div>
            <div class="config-desc">In-flight requests allowed per account before spilling to the next</div>
          </div>
          <select class="config-select" id="sel-max-concurrent" onchange="changeMaxConcurrent(Number(this.value))">
            <option value="2">2</option>
            <option value="4">4</option>
            <option value="6">6</option>
            <option value="8">8</option>
            <option value="12">12</option>
            <option value="16">16</option>
          </select>
        </div>
        <div id="strategy-list" class="strategy-list"></div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Session Affinity</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Keep each session on one account</div>
            <div class="config-desc" title="Prompt caches live per account. Moving a running session rebuilds its whole cache on the new account, which costs more and uses up limits faster. A session only moves when its account is limited, expired or failing. The rotation strategy decides where new and idle sessions go.">Running sessions stay on their account while their cache is warm (saves cost and limits). New and idle sessions follow the strategy.</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-affinity" aria-label="Session affinity" checked onchange="toggleSetting('sessionAffinity', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Cache Care</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Keep idle sessions' caches warm</div>
            <div class="config-desc">Just before an open session's prompt cache expires, vdm resends its last request with "no answer needed", on the same account. That costs a cache read (a few % of a rebuild) and keeps the cache. How long to keep each session warm is learned from when you come back. On by default. Pings use a little of your plan's usage. Needs session affinity.</div>
            <div class="config-desc" id="keepwarm-learned" style="margin-top:0.375rem"></div>
          </div>
          <input type="checkbox" class="sw" id="toggle-keepwarm" aria-label="Keep caches warm" onchange="toggleSetting('keepWarm', this.checked)">
        </div>
      </div>


      <div class="config-section">
        <div class="config-section-title">Account Charts</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Hot line</div>
            <div class="config-desc">Above this many tokens per 5 minutes (all models, incl. cache reads) an account's chart line turns red.</div>
          </div>
          <select class="config-select" id="sel-hot" onchange="saveHotLine(Number(this.value))">
            <option value="5000000">5M</option><option value="10000000">10M</option><option value="25000000">25M</option><option value="50000000">50M</option><option value="100000000">100M</option>
          </select>
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Session History</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Save sessions</div>
            <div class="config-desc">Keep Claude Code sessions after Claude Code deletes them (30 days), so you can search them and continue them later. See the History tab.</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-history" aria-label="Save sessions" onchange="toggleSetting('sessionHistory', this.checked)">
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Launch command</div>
            <div class="config-desc" id="claude-cmd-desc">How copied commands and <code>vdm history continue</code> start Claude Code. Use the full command, not a shell alias, e.g. <code>claude --dangerously-skip-permissions</code>.</div>
          </div>
          <input class="config-select hd-input" id="inp-claude-cmd" style="max-width:280px" aria-label="Launch command" spellcheck="false" onchange="saveClaudeCommand(this.value)">
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Keep saved sessions</div>
            <div class="config-desc">Older saved sessions are deleted (only ones Claude Code no longer has).</div>
          </div>
          <select class="config-select" id="sel-history-keep" onchange="saveHistoryKeep(Number(this.value))">
            <option value="0">Forever</option><option value="90">90 days</option><option value="180">180 days</option><option value="365">1 year</option><option value="730">2 years</option>
          </select>
        </div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Never save these folders</div>
            <div class="config-desc">One folder per line. Sessions started in these folders (or below) are skipped.</div>
          </div>
          <textarea class="config-select hd-input" id="inp-history-exclude" rows="2" style="max-width:280px;resize:vertical" aria-label="Folders to skip" spellcheck="false" onchange="saveHistoryExclude(this.value)"></textarea>
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Notifications</div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Desktop notifications</div>
            <div class="config-desc">Show macOS notifications on account switches, rate limits, and errors</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-notifs" aria-label="Desktop notifications" checked onchange="toggleSetting('notifications', this.checked)">
        </div>
      </div>

      <div class="config-section">
        <div class="config-section-title">Request Serialization <span style="font-size:0.625rem;font-weight:500;color:var(--yellow);background:var(--yellow-soft);border:1px solid var(--yellow-border);border-radius:4px;padding:0.125rem 0.375rem;margin-left:0.375rem;vertical-align:middle">BETA</span></div>
        <div class="config-row">
          <div class="config-info">
            <div class="config-label">Serialize requests</div>
            <div class="config-desc">Queue concurrent API requests to avoid 429 collisions from multiple sessions</div>
          </div>
          <input type="checkbox" class="sw" id="toggle-serialize" aria-label="Serialize requests" onchange="toggleSetting('serializeRequests', this.checked)">
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
  if (id === 'usage') refreshTokens(true);
  if (id === 'sessions') refreshSessions();
  if (id === 'artifacts') refreshArtifactsTab();
  if (id === 'history') refreshHistory();
  if (id === 'config') loadSettingsUI(); // may have changed via vdm or another tab
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

// Balance mode only: a live count of concurrent in-flight requests routed to this
// account, out of the per-account cap. Purple pulse = actively serving; yellow = at
// cap (further requests wait for a slot, then overflow). Empty string in other modes,
// where the proxy pins a single keychain account and per-account in-flight is always 0.
function inflightBadge(p, balanceMode, cap) {
  if (!balanceMode) return '';
  const n = p.inflight || 0;
  const c = cap || 8;
  let cls = 'inflight-idle';
  if (n >= c) cls = 'inflight-full';
  else if (n > 0) cls = 'inflight-active';
  const title = n + (n === 1 ? ' request' : ' requests') + ' in-flight (cap ' + c + ' per account)';
  return '<span class="badge badge-inflight ' + cls + '" title="' + title + '">' +
    '<span class="inflight-dot"></span>' + n + '<span class="inflight-cap">/' + c + '</span></span>';
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
var HOT_TOKENS = 25000000;            // from settings (hotTokensPer5m)
var CHART_SCALE = { day: 0, week: 0 };  // shared y-scale of all account charts
var _chartSeq = 0;

function fmtTokens(n) {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + 'M';
  if (n >= 1e3) return Math.round(n / 1e3) + 'K';
  return String(Math.round(n));
}

/**
 * Total tokens through one account per 5 minutes: a line through one dot per 5 minutes (24 h)
 * or per hour (7 days, as that hour's 5-minute average). Same scale on every card (yMax).
 * Above the hot line (settings: hotTokensPer5m) the line and its dots turn red.
 */
function renderUsageChart(series, windowMs, mode, yMax, idBase) {
  const W = 320, H = 58, padL = 1, padR = 1, padT = 1, padB = 12;
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

  var values = (series && series.values) || [];
  var span = mode === 'hours' ? 'last 24 hours' : 'last 7 days';
  var total = 0, peakV = 0, peakI = -1, hotSlots = 0;
  values.forEach(function(v, i) {
    if (v > peakV) { peakV = v; peakI = i; }
    if (v > HOT_TOKENS) hotSlots++;
  });
  total = (series && series.total) || 0;
  if (!peakV) {
    svg += '<text x="' + (W / 2) + '" y="' + (padT + chartH / 2 + 2) + '" fill="var(--muted)" font-size="6.5" text-anchor="middle" font-family="inherit">No requests through this account in the ' + span + '</text>';
    return '<div class="sparkline-wrap"><svg class="sparkline-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="No requests in the ' + span + '">' + svg + '</svg></div>';
  }
  var top = Math.max(yMax || 0, peakV, 1);
  var xOf = function(i) { return padL + ((series.start + (i + 0.5) * series.step - windowStart) / windowMs) * chartW; };
  var yOf = function(v) { return padT + chartH * (1 - Math.min(v / top, 1)); };
  var yHot = yOf(HOT_TOKENS);
  var line = '', blueDots = '', redDots = '';
  values.forEach(function(v, i) {
    var x = xOf(i);
    if (x < padL - 0.5) return;
    var y = yOf(v);
    line += (line ? ' L' : 'M') + x.toFixed(2) + ',' + y.toFixed(2);
    if (v > 0) {
      var r = mode === 'hours' ? 0.85 : 1;
      var dot = 'M' + (x - r).toFixed(2) + ',' + y.toFixed(2) + 'a' + r + ',' + r + ' 0 1,0 ' + 2 * r + ',0a' + r + ',' + r + ' 0 1,0 ' + -2 * r + ',0';
      if (v > HOT_TOKENS) redDots += dot; else blueDots += dot;
    }
  });
  var id = idBase || ('hot' + (++_chartSeq));
  svg += '<defs><clipPath id="' + id + '-above"><rect x="0" y="0" width="' + W + '" height="' + yHot.toFixed(2) + '"/></clipPath>' +
    '<clipPath id="' + id + '-below"><rect x="0" y="' + yHot.toFixed(2) + '" width="' + W + '" height="' + (H - yHot).toFixed(2) + '"/></clipPath></defs>';
  svg += '<line x1="' + padL + '" x2="' + (W - padR) + '" y1="' + yHot.toFixed(2) + '" y2="' + yHot.toFixed(2) + '" stroke="var(--red)" stroke-width="0.5" stroke-dasharray="2 2" opacity="0.7" />';
  svg += '<text x="' + (W - padR - 1) + '" y="' + (yHot - 1.5).toFixed(2) + '" fill="var(--red)" font-size="5" text-anchor="end" font-family="inherit" opacity="0.85" stroke="var(--card)" stroke-width="2" paint-order="stroke">hot ' + fmtTokens(HOT_TOKENS) + '</text>';
  svg += '<path d="' + line + '" fill="none" stroke="var(--primary)" stroke-width="1" stroke-linejoin="round" clip-path="url(#' + id + '-below)" />';
  svg += '<path d="' + line + '" fill="none" stroke="var(--red)" stroke-width="1.25" stroke-linejoin="round" clip-path="url(#' + id + '-above)" />';
  if (blueDots) svg += '<path d="' + blueDots + '" fill="var(--primary)" />';
  if (redDots) svg += '<path d="' + redDots + '" fill="var(--red)" />';
  svg += '<text x="' + (padL + 2) + '" y="' + (padT + 6) + '" fill="var(--muted)" font-size="5.5" font-family="inherit" stroke="var(--card)" stroke-width="2" paint-order="stroke">' + fmtTokens(top) + ' / 5 min</text>';
  var pd = new Date(series.start + peakI * series.step);
  var peakWhen = mode === 'hours' ? pd.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : pd.toLocaleDateString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' });
  var hotText = hotSlots ? (mode === 'hours' ? hotSlots * 5 + ' min hot' : hotSlots + ' h hot') : '';
  var tip = 'Total tokens through this account (all models, incl. cache reads), ' + span + ', per 5 minutes' +
    (mode === 'hours' ? '' : ' (hourly averages)') + '. Total ' + fmtTokens(total) + '. Peak ' + fmtTokens(peakV) + ' per 5 min (' + peakWhen + ').' +
    ' Red: above ' + fmtTokens(HOT_TOKENS) + ' per 5 min (Config). Same scale on every account.';
  return '<div class="sparkline-wrap" title="' + escHtml(tip) + '"><svg class="sparkline-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + escHtml(tip) + '">' + svg + '</svg>' +
    '<div class="spark-legend"><span>' + fmtTokens(total) + ' tokens</span><span>peak ' + fmtTokens(peakV) + '/5 min</span>' +
    (hotText ? '<span class="spark-hot">' + hotText + '</span>' : '') + '</div></div>';
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
    const { profiles, stats, probeStats, allExhausted, earliestReset, rotationStrategy, balanceCap, sessionAffinity, sessionHistory, hotTokensPer5m, cacheCare, queueStats } = await resp.json();
    HIST.enabled = !!sessionHistory;
    if (hotTokensPer5m) HOT_TOKENS = hotTokensPer5m;
    _cachedProfiles = profiles;
    updateSessionsBadge(profiles);
    const balanceMode = rotationStrategy === 'balance';
    const cap = balanceCap || 8;
    // Fold balance context into the hash so strategy/cap flips also force a re-render.
    const ph = quickHash({ profiles, balanceMode, cap, hot: HOT_TOKENS, hist: HIST.enabled });
    if (ph !== _lastProfilesHash) {
      _lastProfilesHash = ph;
      renderAccounts(profiles, _firstRender, balanceMode, cap);
    }
    document.getElementById('account-count').textContent = profiles.length;
    if (rotationStrategy) {
      const strategyNames = { sticky: 'Sticky', conserve: 'Conserve', 'round-robin': 'Round-robin', spread: 'Spread', 'drain-first': 'Drain first', balance: 'Balance' };
      document.getElementById('current-strategy').textContent = ' \\u00b7 ' + (strategyNames[rotationStrategy] || rotationStrategy) +
        (sessionAffinity ? ' \\u00b7 session affinity on' : ' \\u00b7 session affinity off') + smartCacheHeadline(cacheCare);
    }
    if (probeStats) renderProbeStats(probeStats);
    // [BETA] Queue stats
    if (queueStats) {
      var qEl = document.getElementById('queue-stats');
      if (queueStats.balanceMode && (queueStats.balanceInflight > 0 || queueStats.balanceWaiting > 0)) {
        qEl.style.display = '';
        qEl.textContent = 'Balance: ' + queueStats.balanceInflight + ' in-flight'
          + (queueStats.balanceWaiting > 0 ? ', ' + queueStats.balanceWaiting + ' waiting for a slot' : '');
      } else if (!queueStats.balanceMode && (queueStats.inflight > 0 || queueStats.queued > 0)) {
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
  // Each of these only fetches while its tab is open
  refreshTokens();
  refreshSessions();
  refreshArtifactsTab();
}

// Per-card HTML from the last render, keyed by account name. Only cards whose HTML
// changed are replaced, so a click on a card isn't lost to the 5s refresh.
var _cardHtml = {};

function renderAccounts(profiles, animate, balanceMode, balanceCap) {
  var el = document.getElementById('accounts');
  // One scale for all account charts, so a busy account stands out next to a quiet one.
  // Never below the hot line, so the hot line always shows.
  var peak = function(k) {
    return profiles.reduce(function(m, p) {
      var v = (p.throughput && p.throughput[k] && p.throughput[k].values) || [];
      return Math.max(m, v.reduce(function(a, b) { return Math.max(a, b); }, 0));
    }, 0);
  };
  CHART_SCALE.day = Math.max(peak('day'), HOT_TOKENS * 1.25);
  CHART_SCALE.week = Math.max(peak('week'), HOT_TOKENS * 1.25);
  if (!profiles.length) {
    el.innerHTML = '<div class="empty-state">No accounts yet. Run <code>/login</code> in Claude Code: accounts are picked up automatically.</div>';
    el.dataset.names = '';
    _cardHtml = {};
    return;
  }
  var cards = profiles.map(function(p, i) { return [p.name, accountCardHtml(p, i, animate, balanceMode, balanceCap)]; });
  var names = cards.map(function(c) { return c[0]; }).join('|');
  if (el.dataset.names !== names) {
    el.innerHTML = cards.map(function(c) { return c[1]; }).join('');
    el.dataset.names = names;
    _cardHtml = {};
    cards.forEach(function(c) { _cardHtml[c[0]] = c[1]; });
  } else {
    var nodes = el.children || [];
    cards.forEach(function(c, i) {
      if (_cardHtml[c[0]] === c[1]) return;
      if (nodes[i]) nodes[i].outerHTML = c[1];
      else el.dataset.names = '';   // DOM out of step: full render next time
      _cardHtml[c[0]] = c[1];
    });
  }
  tickCountdowns();
}

function rateGroup(label, util, reset, extra) {
  var pct = Math.round(util * 100);
  return '<div class="rate-group">' +
    '<div class="rate-head"><span class="rate-label">' + label + '</span><span class="rate-pct ' + pctClass(pct) + '">' + pct + '%</span></div>' +
    '<div class="rate-track"><div class="rate-fill ' + fillClass(util) + '" style="width:' + Math.min(pct, 100) + '%"></div></div>' +
    '<div class="rate-reset" data-reset="' + reset + '"></div>' +
    (extra || '') +
  '</div>';
}

function accountCardHtml(p, i, animate, balanceMode, balanceCap) {
  var active = p.isActive;
  var displayName = p.label || p.name;
  var eName = p.name.replace(/'/g, "\\\\'");

  var barsHtml = '';
  if (p.rateLimits) {
    var rl = p.rateLimits;
    var tp = p.throughput || {};
    var spark5h = renderUsageChart(tp.day, 24*60*60*1000, 'hours', CHART_SCALE.day, 'hot-' + i + '-d');
    var spark7d = renderUsageChart(tp.week, 7*24*60*60*1000, 'days', CHART_SCALE.week, 'hot-' + i + '-w');
    // Fable has its own weekly bucket (only on accounts whose responses carry it)
    var fable = '';
    if (rl.sevenDOI) {
      var blocked = rl.fableBlockedUntil && rl.fableBlockedUntil > Date.now() / 1000;
      var o = blocked ? 100 : Math.round(rl.sevenDOI.utilization * 100);
      fable = '<div class="rate-sub" title="Fable has its own weekly limit on this account. When it is used up, only Fable requests move to another account.">' +
        '<span>Fable</span>' +
        '<div class="rate-track"><div class="rate-fill ' + fillClass(o / 100) + '" style="width:' + Math.min(o, 100) + '%"></div></div>' +
        '<span class="rate-pct ' + pctClass(o) + '">' + (blocked ? 'used up' : o + '%') + '</span></div>';
    }
    barsHtml = '<div class="rate-bars">' +
      rateGroup('5h window', rl.fiveH.utilization, rl.fiveH.reset, spark5h) +
      rateGroup('Weekly', rl.sevenD.utilization, rl.sevenD.reset, fable + spark7d) +
    '</div>';
  } else if (p.dormant) {
    barsHtml = '<div style="font-size:0.8125rem;color:var(--cyan);margin-top:0.25rem;font-weight:500">Dormant: its limit windows have not started</div>';
  } else {
    barsHtml = '<div style="font-size:0.8125rem;color:var(--muted);margin-top:0.25rem">Limits not known yet</div>';
  }

  var blockedHtml = p.blocked
    ? '<div class="blocked-banner">Used up: ' + escHtml(p.blocked.what) + ' <span class="muted">&middot; back in <span data-reset="' + p.blocked.until + '" data-short="1"></span>. New and moved sessions skip it.</span></div>'
    : '';
  // Weekly limit for one model family (Opus or Sonnet): other models keep using the account
  (p.modelBlocks || []).forEach(function(b) {
    var fam = b.family.charAt(0).toUpperCase() + b.family.slice(1);
    blockedHtml += '<div class="blocked-banner model">' + escHtml(fam) + ' weekly limit used up <span class="muted">&middot; back in <span data-reset="' + b.until + '" data-short="1"></span>. Other models still use this account.</span></div>';
  });

  var animStyle = animate ? ' style="animation-delay:' + (i*0.05) + 's"' : ' style="animation:none"';
  var isStale = !active && (p.expired || p.refreshFailed || (p.expiresAt && p.expiresAt < Date.now()));
  var staleMsg = '';
  if (isStale) {
    staleMsg = p.refreshFailed && !p.refreshFailed.retriable
      ? '<div class="stale-msg">Login expired. Click Refresh or run <code>claude login</code> for this account.</div>'
      : '<div class="stale-msg">Login expired. Auto-refresh will retry shortly.</div>';
  }
  var cardClass = 'card' + (active ? ' active' : '') + (isStale ? ' stale' : '');
  var buttonsHtml = '';
  if (!active) {
    buttonsHtml = '<div style="margin-top:0.875rem;display:flex;justify-content:space-between;align-items:center">' +
      '<button class="remove-btn" onclick="doRemove(\\'' + eName + '\\',event)">Remove</button>' +
      (isStale ? '<button class="refresh-btn" onclick="doRefresh(\\'' + eName + '\\',event)">Refresh</button>'
               : '<button class="switch-btn" onclick="doSwitch(\\'' + eName + '\\',\\'' + displayName.replace(/'/g, "\\\\'") + '\\',event)">Switch to this account</button>') +
    '</div>';
  }
  var cache = p.cache30d && p.cache30d.hit != null
    ? '<span class="badge badge-soft" title="Share of prompt tokens read from cache over the last 30 days. Higher is cheaper.">cache ' + Math.round(p.cache30d.hit * 100) + '%</span>' : '';
  var arts = p.artifactCount
    ? '<button class="chip" onclick="openArtifactsFor(\\'' + eName + '\\')" title="Artifacts this account owns on claude.ai">' + p.artifactCount + ' artifact' + (p.artifactCount === 1 ? '' : 's') + '</button>' : '';
  return '<div class="' + cardClass + '"' + animStyle + ' data-name="' + escHtml(p.name) + '">' +
    '<div class="card-top">' +
      '<div class="card-identity">' +
        '<div class="status-dot ' + (active ? 'active' : 'inactive') + '"></div>' +
        '<span class="card-name" title="' + escHtml(displayName) + '">' + escHtml(displayName) + '</span>' +
        (active ? renderVelocityInline(p) : '') +
      '</div>' +
      '<div class="card-badges">' +
        cache + arts +
        inflightBadge(p, balanceMode, balanceCap) +
        planBadge(p.subscriptionType, p.rateLimitTier) +
        (active ? '<span class="badge badge-active" title="Claude Code is logged in with this account; new sessions start here">Active</span>' : '') +
      '</div>' +
    '</div>' +
    blockedHtml +
    barsHtml +
    renderAccountSessions(p) +
    staleMsg +
    buttonsHtml +
  '</div>';
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
  'session-moved': 'var(--yellow)',
};

const LIMIT_TEXT = {
  five_hour: 'used up its 5-hour limit', seven_day: 'used up its weekly limit',
  seven_day_opus: 'used up its weekly Opus limit', seven_day_sonnet: 'used up its weekly Sonnet limit',
  seven_day_overage_included: 'used up its Fable limit', 'retry-after': 'rate limited',
};

function evtMsg(e) {
  switch (e.type) {
    case 'auto-switch': return 'Auto-switched from <b>' + (e.from||'?') + '</b> to <b>' + (e.to||'?') + '</b>';
    case 'proactive-switch': return 'Proactive switch to <b>' + (e.to||'?') + '</b>';
    case 'manual-switch': return 'Switched to <b>' + (e.to||'?') + '</b>';
    case 'rate-limited': return '<b>' + escHtml(e.account||'?') + '</b> ' + (LIMIT_TEXT[e.limit] || (e.limit && / bucket$/.test(e.limit) ? 'used up its Fable limit' : 'rate limited')) + (!e.limit && e.retryAfter ? ' (' + Math.round(e.retryAfter/60) + ' min)' : '');
    case 'session-moved': return 'Session <b>' + escHtml(e.session || '?') + '</b> moved from <b>' + escHtml(e.from || '?') + '</b> to <b>' + escHtml(e.to || '?') + '</b>: ' + escHtml(MOVE_REASON[e.reason] || e.reason || '') + ', cache rebuilt';
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

// Live countdowns ("2h 5m left") and relative times ("3m ago"), so cards don't need
// re-rendering just because time passed.
function tickCountdowns() {
  document.querySelectorAll('[data-reset]').forEach(el => {
    const t = formatTimeLeft(Number(el.dataset.reset));
    el.textContent = el.dataset.short ? t.replace(/ left$/, '') : t;
  });
  document.querySelectorAll('[data-ago]').forEach(el => {
    el.textContent = timeAgo(Number(el.dataset.ago));
  });
}

const STRATEGY_HINTS = {
  sticky: 'Stays on current account. Only switches when rate-limited (429/401).',
  conserve: 'Drains active accounts first (weekly limit primary). Untouched accounts stay dormant  - their windows never start.',
  'round-robin': 'Rotates to the least-used account on a timer. Good balance of safety and efficiency.',
  spread: 'Picks the least-used account on every request. Switches often  - may trigger Anthropic notices.',
  'drain-first': 'Uses the account with highest 5hr utilization first. Good for short sessions.',
  balance: 'Spreads sessions across accounts by load, capped per account. Skips accounts whose 5h, weekly or Fable window is used up. Best for running many sessions at once.',
};

async function loadSettingsUI() {
  try {
    const s = await (await fetch('/api/settings')).json();
    document.getElementById('toggle-proxy').checked = s.proxyEnabled;
    document.getElementById('toggle-autoswitch').checked = s.autoSwitch;
    document.getElementById('toggle-notifs').checked = s.notifications !== false;
    document.getElementById('sel-strategy').value = s.rotationStrategy || 'conserve';
    document.getElementById('sel-interval').value = s.rotationIntervalMin || 60;
    document.getElementById('sel-max-concurrent').value = s.maxConcurrentPerAccount || 8;
    updateStrategyUI(s.rotationStrategy || 'conserve');
    // [BETA] Serialization
    document.getElementById('toggle-serialize').checked = !!s.serializeRequests;
    document.getElementById('sel-serialize-delay').value = s.serializeDelayMs || 200;
    document.getElementById('serialize-delay-ctrl').style.display = s.serializeRequests ? '' : 'none';
    document.getElementById('toggle-affinity').checked = s.sessionAffinity !== false;
    document.getElementById('toggle-history').checked = s.sessionHistory === true;
    document.getElementById('toggle-keepwarm').checked = s.keepWarm !== false;
    loadKeepWarmLearned();
    var hot = document.getElementById('sel-hot');
    var hotVal = String(s.hotTokensPer5m || 25000000);
    if (![].some.call(hot.options, function(o) { return o.value === hotVal; })) {
      var hotOpt = document.createElement('option');
      hotOpt.value = hotVal; hotOpt.textContent = fmtTokens(Number(hotVal));
      hot.appendChild(hotOpt);
    }
    hot.value = hotVal;
    var cmdInput = document.getElementById('inp-claude-cmd');
    if (document.activeElement !== cmdInput) cmdInput.value = s.claudeCommandEnv || s.claudeCommand || 'claude';
    cmdInput.disabled = !!s.claudeCommandEnv;
    cmdInput.title = s.claudeCommandEnv ? 'Set by VDM_CLAUDE_CMD in the environment' : '';
    var keep = document.getElementById('sel-history-keep');
    var days = String(s.historyRetentionDays || 0);
    if (![].some.call(keep.options, function(o) { return o.value === days; })) {
      var opt = document.createElement('option');
      opt.value = days; opt.textContent = days + ' days';
      keep.appendChild(opt);
    }
    keep.value = days;
    var ex = document.getElementById('inp-history-exclude');
    if (document.activeElement !== ex) ex.value = (s.historyExclude || []).join(String.fromCharCode(10));
  } catch {}
}

const STRATEGY_DETAILS = {
  sticky:        { name: 'Sticky',      desc: 'Stay on the current account until it hits a rate limit (429) or auth error (401). Never switches proactively  - minimal disruption.' },
  conserve:      { name: 'Conserve',    desc: 'Concentrate usage on accounts whose rate-limit windows are already active. Untouched accounts stay dormant so their 5hr and weekly windows never start  - maximizes total available capacity over time.' },
  'round-robin': { name: 'Round-robin', desc: 'Rotate to the least-used account on a fixed timer. Balances load evenly while limiting switch frequency.' },
  spread:        { name: 'Spread',      desc: 'Always pick the account with the lowest 5hr utilization on every request. Switches often  - best for short, bursty sessions.' },
  'drain-first': { name: 'Drain first', desc: 'Use the account with the highest 5hr utilization first, draining it before moving on. Good for finishing off nearly-exhausted windows.' },
  balance:       { name: 'Balance',     desc: 'Place new sessions on the least-loaded account (in-flight requests plus warm sessions), capped per account. Accounts whose 5h, weekly or Fable window is used up are skipped, and nearly full ones go last. With session affinity a running session stays on its account (it waits for a slot there instead of moving). Best when running many sessions/subagents at once.' },
};

function updateStrategyUI(strategy) {
  document.getElementById('interval-ctrl').style.display = strategy === 'round-robin' ? '' : 'none';
  document.getElementById('max-concurrent-ctrl').style.display = strategy === 'balance' ? '' : 'none';
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
      sessionAffinity: value ? 'Session affinity on' : 'Session affinity off  - sessions follow the strategy per request',
      sessionHistory: value ? 'Session history on: saving your sessions' : 'Session history off (saved sessions are kept)',
      keepWarm: value ? 'Keep-warm on: idle sessions keep their cache' : 'Keep-warm off',
    };
    if (key === 'sessionHistory') { HIST.enabled = value; setTimeout(function() { refreshHistory(); }, 600); }
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
    // Balance mode supersedes serialize — reflect the server-side auto-disable in the UI.
    if (value === 'balance') {
      document.getElementById('toggle-serialize').checked = false;
      document.getElementById('serialize-delay-ctrl').style.display = 'none';
    }
    showToast('Rotation: ' + (document.getElementById('sel-strategy').selectedOptions[0]?.text || value));
  } catch { showToast('Failed to update'); }
}

async function changeMaxConcurrent(value) {
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ maxConcurrentPerAccount: value })
    });
    showToast('Max concurrent per account: ' + value);
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

// ── Usage tab ──

var TOK_COLORS = ['var(--primary)', 'var(--purple)', 'var(--cyan)', 'var(--green)', 'var(--yellow)', 'var(--red)',
  'hsl(330 75% 58%)', 'hsl(25 90% 55%)', 'hsl(160 60% 38%)', 'hsl(250 55% 62%)', 'hsl(200 15% 50%)', 'hsl(90 55% 40%)'];
var _usage = null;
var _usageHash = '';
var _usageFetchedAt = 0;
var USAGE_REFRESH_MS = 30000;   // the tab is about trends: a slower refresh keeps it calm
var _tokFetching = false;
var _tokNeedsRefresh = false;
var _tokRepoCollapsed = {};

function formatCost(dollars) {
  if (!dollars) return '$0.00';
  if (dollars < 0.01) return '&lt;$0.01';
  if (dollars < 100) return '$' + dollars.toFixed(2);
  return '$' + Math.round(dollars).toLocaleString();
}

function formatPct(x) {
  return x == null ? '&ndash;' : Math.round(x * 100) + '%';
}

function escHtml(s) {
  if (s == null || s === '') return '';
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

function tokTimeRange() {
  var sel = document.getElementById('tok-time');
  return sel ? parseInt(sel.value, 10) || 7 : 7;
}

// Prompt tokens = uncached input + cache reads + cache writes
function tokPrompt(t) {
  return (t.input || 0) + (t.cacheRead || 0) + (t.cacheWrite5m || 0) + (t.cacheWrite1h || 0);
}
function tokTotal(t) { return tokPrompt(t) + (t.output || 0); }

async function refreshTokens(force) {
  var tab = document.getElementById('tab-usage');
  if (!tab || !tab.classList.contains('active')) return;
  refreshSmartCache();
  if (!force && _usage && Date.now() - _usageFetchedAt < USAGE_REFRESH_MS) return;
  if (_tokFetching) { _tokNeedsRefresh = true; return; }
  _tokFetching = true;
  _tokNeedsRefresh = false;
  try {
    var q = 'days=' + tokTimeRange();
    ['repo', 'branch', 'model', 'account'].forEach(function(k) {
      var el = document.getElementById('tok-' + k);
      if (el && el.value) q += '&' + k + '=' + encodeURIComponent(el.value);
    });
    var resp = await fetch('/api/usage?' + q);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    _usageFetchedAt = Date.now();
    var h = quickHash({ t: data.totals, s: data.series, p: data.plans, o: data.options, f: data.filter, c: data.cache30d && data.cache30d.overall });
    if (h === _usageHash) return;
    _usageHash = h;
    _usage = data;
    renderUsage(data);
  } catch (e) {
    if (!_usage) {
      var empty = document.getElementById('tok-empty');
      empty.className = 'empty-state err-state';
      empty.textContent = 'Could not load usage (' + e.message + '). Retrying...';
      empty.style.display = '';
    }
  } finally {
    _tokFetching = false;
    if (_tokNeedsRefresh) refreshTokens(true);
  }
}

function hasUsageFilter() {
  return ['repo', 'branch', 'model', 'account'].some(function(k) { var el = document.getElementById('tok-' + k); return el && el.value; });
}

function clearUsageFilters() {
  ['repo', 'branch', 'model', 'account'].forEach(function(k) { var el = document.getElementById('tok-' + k); if (el) el.value = ''; });
  tokFilterChange('time');
}

function renderUsage(d) {
  populateTokenFilters(d.options);
  var content = document.getElementById('tok-content');
  var empty = document.getElementById('tok-empty');
  if (!d.totals.requests) {
    content.style.display = 'none';
    empty.className = 'empty-state';
    empty.innerHTML = hasUsageFilter()
      ? 'No usage matches these filters. <button class="link-btn" style="font-size:inherit" onclick="clearUsageFilters()">Clear filters</button>'
      : 'No token usage recorded in this period yet.';
    empty.style.display = '';
    return;
  }
  content.style.display = '';
  empty.style.display = 'none';
  renderTokenStats(d);
  renderDailyChart(d);
  renderCostSavingsChart(d);
  renderPlanValue(d);
  renderCacheEfficiency(d.cache30d);
  renderModelBreakdown(d);
  renderAccountBreakdown(d);
  renderRepoBranchBreakdown(d);
}

function populateTokenFilters(opts) {
  function fill(id, values, allLabel, labelFn) {
    var sel = document.getElementById(id);
    if (!sel || document.activeElement === sel) return;   // never rebuild a select the user is using
    var cur = sel.value;
    var list = values.slice();
    if (cur && list.indexOf(cur) === -1) list.push(cur);
    var html = '<option value="">' + allLabel + '</option>' + list.map(function(v) {
      return '<option value="' + escHtml(v) + '"' + (v === cur ? ' selected' : '') + '>' + escHtml(labelFn ? labelFn(v) : v) + '</option>';
    }).join('');
    if (sel.dataset.opts === html) return;
    sel.innerHTML = html;
    sel.dataset.opts = html;
  }
  fill('tok-repo', opts.repos || [], 'All repos', function(r) { return r.split('/').pop(); });
  fill('tok-branch', opts.branches || [], 'All branches');
  fill('tok-model', opts.models || [], 'All models', shortModel);
  fill('tok-account', opts.accounts || [], 'All accounts');
}

function renderTokenStats(d) {
  var t = d.totals, p = d.prevTotals || {};
  var total = tokTotal(t), prevTotal = tokTotal(p);
  var trendHtml = '';
  if (prevTotal > 0) {
    var pctChange = Math.round(((total - prevTotal) / prevTotal) * 100);
    if (pctChange !== 0) {
      trendHtml = '<div class="tok-trend ' + (pctChange > 0 ? 'up' : 'down') + '">' + (pctChange > 0 ? '&uarr;' : '&darr;') + ' ' + Math.abs(pctChange) + '% vs prev period</div>';
    }
  }
  var prompt = tokPrompt(t);
  var writes = (t.cacheWrite5m || 0) + (t.cacheWrite1h || 0);
  var stats = [
    { v: formatNum(total), l: 'Total tokens', sub: 'incl. cache', extra: trendHtml },
    { v: formatNum(t.requests), l: 'Requests' },
    { v: formatPct(prompt ? t.cacheRead / prompt : null), l: 'Cache hit', sub: formatPct(prompt ? writes / prompt : null) + ' rebuilt' },
    { v: formatCost(t.cost), l: 'API price', sub: 'same usage, pay-as-you-go' },
    { v: formatNum(t.cacheRead), l: 'Cache reads' },
    { v: formatNum(writes), l: 'Cache writes' },
    { v: formatNum(t.input), l: 'Uncached input' },
    { v: formatNum(t.output), l: 'Output' },
  ];
  document.getElementById('tok-stats').innerHTML = stats.map(function(s) {
    var h = '<div class="stat-item"><div class="stat-val">' + s.v + '</div><div class="stat-label">' + s.l + '</div>';
    if (s.sub) h += '<div class="tok-stat-sub">' + s.sub + '</div>';
    if (s.extra) h += s.extra;
    return h + '</div>';
  }).join('');
}

// Time buckets for charts: hourly (1-2 days), daily (up to a month), weekly (longer).
function usageBuckets(d) {
  var groupMs = d.days > 31 ? 7 * 86400000 : d.bucketMs;
  var start = Math.floor(d.since / groupMs) * groupMs;
  var count = Math.max(1, Math.ceil((Date.now() - start) / groupMs));
  var buckets = [];
  for (var i = 0; i < count; i++) buckets.push({ t: start + i * groupMs, total: 0, cost: 0, byModel: {} });
  (d.series || []).forEach(function(s) {
    var idx = Math.floor((s.t - start) / groupMs);
    if (idx < 0) return;
    if (idx >= count) idx = count - 1;
    var b = buckets[idx];
    b.cost += s.cost || 0;
    Object.keys(s.byModel).forEach(function(m) {
      b.byModel[m] = (b.byModel[m] || 0) + s.byModel[m];
      b.total += s.byModel[m];
    });
  });
  return { buckets: buckets, groupMs: groupMs };
}

function bucketLabel(t, groupMs) {
  var dt = new Date(t);
  if (groupMs < 86400000) return String(dt.getHours()).padStart(2, '0') + 'h';
  return (dt.getMonth() + 1) + '/' + dt.getDate();
}

function renderDailyChart(d) {
  var el = document.getElementById('tok-chart');
  var bk = usageBuckets(d);
  var buckets = bk.buckets;
  var sortedModels = Object.keys(d.byModel).sort();
  var maxTotal = Math.max.apply(null, buckets.map(function(b) { return b.total; })) || 1;
  var legend = '<div class="chart-legend">' + sortedModels.map(function(m) {
    return '<div class="chart-legend-item"><span class="chart-legend-dot" style="background:' + getModelColor(m, sortedModels) + '"></span> ' + escHtml(shortModel(m)) + '</div>';
  }).join('') + '</div>';
  var labelEvery = Math.ceil(buckets.length / 16);
  var bars = '<div class="tok-chart-wrap">';
  buckets.forEach(function(b, k) {
    var stackH = Math.round((b.total / maxTotal) * 120);
    bars += '<div class="tok-chart-bar-group"><div class="tok-chart-bar-area"><div class="tok-chart-stack" style="height:' + stackH + 'px">';
    sortedModels.forEach(function(m) {
      var v = b.byModel[m] || 0;
      if (v <= 0) return;
      var segH = Math.max(1, Math.round((v / b.total) * stackH));
      bars += '<div class="tok-chart-seg" style="height:' + segH + 'px;background:' + getModelColor(m, sortedModels) + '" data-tooltip="' + escHtml(shortModel(m)) + ': ' + formatNum(v) + ' tokens"></div>';
    });
    bars += '</div></div>';
    bars += '<div class="tok-chart-label">' + (k % labelEvery === 0 ? bucketLabel(b.t, bk.groupMs) : '') + '</div></div>';
  });
  bars += '</div>';
  var title = bk.groupMs < 86400000 ? 'Hourly Usage' : bk.groupMs === 86400000 ? 'Daily Usage' : 'Weekly Usage';
  el.innerHTML = '<div class="usage-title">' + title + ' &middot; tokens by model, incl. cache</div>' + legend + bars;
}

// Cumulative API-price value of the usage vs the cumulative (prorated) plan price.
function renderCostSavingsChart(d) {
  var el = document.getElementById('tok-savings-chart');
  var bk = usageBuckets(d);
  var buckets = bk.buckets;
  var n = buckets.length;
  var showPlan = d.planComparable && d.planDaily > 0;
  var planPerBucket = showPlan ? d.planDaily * bk.groupMs / 86400000 : 0;
  var cumPlan = [], cumApi = [], runPlan = 0, runApi = 0;
  buckets.forEach(function(b) {
    runPlan += planPerBucket;
    runApi += b.cost;
    cumPlan.push(runPlan);
    cumApi.push(runApi);
  });
  var maxVal = Math.max(cumPlan[n - 1], cumApi[n - 1], 1);
  var svgW = 500, svgH = 140, padL = 45, padR = 10, padT = 10, padB = 25;
  var chartW = svgW - padL - padR, chartH = svgH - padT - padB;
  function xPos(i) { return padL + (n > 1 ? i / (n - 1) : 0) * chartW; }
  function yPos(v) { return padT + chartH - (v / maxVal) * chartH; }
  var grid = '';
  for (var g = 0; g <= 4; g++) {
    var gv = (maxVal / 4) * g, gy = yPos(gv);
    grid += '<line x1="' + padL + '" y1="' + gy + '" x2="' + (svgW - padR) + '" y2="' + gy + '" class="grid-line"/>';
    grid += '<text x="' + (padL - 4) + '" y="' + (gy + 3) + '" class="axis-label" text-anchor="end">$' + Math.round(gv).toLocaleString() + '</text>';
  }
  var labelEvery = Math.ceil(n / 6);
  var xl = '';
  for (var i = 0; i < n; i += labelEvery) {
    xl += '<text x="' + xPos(i) + '" y="' + (svgH - 2) + '" class="axis-label" text-anchor="middle">' + bucketLabel(buckets[i].t, bk.groupMs) + '</text>';
  }
  var planPath = '', apiPath = '', area = '';
  for (var p = 0; p < n; p++) {
    var c = p === 0 ? 'M' : 'L';
    planPath += c + xPos(p).toFixed(1) + ',' + yPos(cumPlan[p]).toFixed(1);
    apiPath += c + xPos(p).toFixed(1) + ',' + yPos(cumApi[p]).toFixed(1);
    area += c + xPos(p).toFixed(1) + ',' + yPos(cumApi[p]).toFixed(1);
  }
  for (var a2 = n - 1; a2 >= 0; a2--) area += 'L' + xPos(a2).toFixed(1) + ',' + yPos(cumPlan[a2]).toFixed(1);
  area += 'Z';
  var saved = cumApi[n - 1] - cumPlan[n - 1];
  var svg = '<svg class="savings-chart-svg" viewBox="0 0 ' + svgW + ' ' + svgH + '" preserveAspectRatio="none" role="img" aria-label="Cumulative API price' + (showPlan ? ' versus plan price' : '') + '">' + grid + xl +
    (showPlan ? '<path d="' + area + '" class="area-savings" fill="' + (saved > 0 ? 'var(--green)' : 'var(--red)') + '"/><path d="' + planPath + '" class="line-plan"/>' : '') +
    '<path d="' + apiPath + '" class="line-api"/></svg>';
  var legend = '<div class="savings-chart-legend">' +
    (showPlan ? '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line dashed"></span>Plan price (prorated)</div>' : '') +
    '<div class="savings-chart-legend-item"><span class="savings-chart-legend-line solid"></span>Same usage at API prices</div></div>';
  var multiple = showPlan && cumPlan[n - 1] > 0 ? (cumApi[n - 1] / cumPlan[n - 1]) : null;
  var total = showPlan
    ? '<div class="savings-chart-total">Plans ' + formatCost(cumPlan[n - 1]) + ' vs API price ' + formatCost(cumApi[n - 1]) +
      ' &middot; <span class="' + (multiple >= 1 ? 'saved' : 'over') + '">' + multiple.toFixed(1) + '&times; value</span></div>'
    : '<div class="savings-chart-total">API price ' + formatCost(cumApi[n - 1]) + (d.planComparable ? '' : ' &middot; plan line hidden: a plan covers all of an account\\'s usage, not one repo, branch or model') + '</div>';
  el.innerHTML = '<div class="usage-title">' + (showPlan ? 'Plan vs API price' : 'API price') + ' &middot; last ' + d.days + ' day' + (d.days === 1 ? '' : 's') + '</div>' + legend +
    '<div class="savings-chart-container">' + svg + '</div>' + total;
}

function renderPlanValue(d) {
  var el = document.getElementById('tok-plans');
  if (!d.planComparable) {
    el.innerHTML = '<div class="notice">A plan covers all of an account\\'s usage, so it can\\'t be compared to one repo, branch or model. Clear those filters (an account filter is fine) to see plan value.</div>';
    return;
  }
  var plans = (d.plans || []).slice().sort(function(a, b) { return b.apiCost - a.apiCost; });
  if (!plans.length) { el.innerHTML = '<div class="section-note">No accounts.</div>'; return; }
  var sumPlan = 0, sumApi = 0;
  var rows = plans.map(function(p) {
    var mult = p.planCost ? p.apiCost / p.planCost : null;
    if (p.planCost) { sumPlan += p.planCost; sumApi += p.apiCost; }
    return '<tr><td class="name" title="' + escHtml(p.label) + '">' + escHtml(p.label) + '</td>' +
      '<td>' + escHtml(p.monthly ? p.tier + ' ($' + p.monthly + '/mo)' : p.tier + ' (not supported)') + '</td>' +
      '<td class="num">' + (p.planCost ? formatCost(p.planCost) : '&ndash;') + '</td>' +
      '<td class="num">' + formatCost(p.apiCost) + '</td>' +
      '<td class="num">' + (mult == null ? '&ndash;' : '<span class="' + (mult >= 1 ? 'val-good' : 'val-bad') + '">' + mult.toFixed(1) + '&times;</span>') + '</td></tr>';
  }).join('');
  var totalMult = sumPlan ? sumApi / sumPlan : null;
  rows += '<tr><td class="name"><b>Total (Max plans)</b></td><td></td><td class="num"><b>' + formatCost(sumPlan) + '</b></td><td class="num"><b>' + formatCost(sumApi) + '</b></td>' +
    '<td class="num">' + (totalMult == null ? '&ndash;' : '<span class="' + (totalMult >= 1 ? 'val-good' : 'val-bad') + '">' + totalMult.toFixed(1) + '&times;</span>') + '</td></tr>';
  el.innerHTML = '<table class="plan-table"><thead><tr><th>Account</th><th>Plan</th><th class="num" title="Subscription price prorated to ' + d.days + ' days">Plan, ' + d.days + 'd</th><th class="num" title="The same tokens at pay-as-you-go API prices">API price</th><th class="num" title="API price divided by plan price">Value</th></tr></thead><tbody>' + rows + '</tbody></table>';
}

// Tiny 30-day trend line of cache hit % (gaps on days without traffic).
function cacheSparkline(trend) {
  var W = 90, H = 18, n = trend.length;
  if (!n) return '';
  var segs = [], cur = '';
  trend.forEach(function(v, i) {
    if (v == null) { if (cur) segs.push(cur); cur = ''; return; }
    var x = (n > 1 ? i / (n - 1) : 0.5) * (W - 2) + 1;
    var y = H - 1 - v * (H - 2);
    cur += (cur ? ' L' : 'M') + x.toFixed(1) + ',' + y.toFixed(1);
  });
  if (cur) segs.push(cur);
  var paths = segs.map(function(p) {
    return p.indexOf('L') === -1 ? '<circle cx="' + p.slice(1).split(',')[0] + '" cy="' + p.split(',')[1] + '" r="1.5" fill="var(--primary)"/>'
      : '<path d="' + p + '" fill="none" stroke="var(--primary)" stroke-width="1.25"/>';
  }).join('');
  return '<svg width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H + '" style="flex-shrink:0">' +
    '<line x1="0" y1="1" x2="' + W + '" y2="1" stroke="var(--border)" stroke-width="0.5"/>' + paths + '</svg>';
}

function renderCacheEfficiency(c) {
  var el = document.getElementById('tok-cache');
  if (!c || !c.overall || !c.overall.prompt) { el.innerHTML = '<div class="notice">No traffic in the last 30 days.</div>'; return; }
  function row(name, g, bold) {
    return '<div class="eff-row">' +
      '<div class="eff-name" title="' + escHtml(name) + '">' + (bold ? '<b>' + escHtml(name) + '</b>' : escHtml(name)) + '</div>' +
      cacheSparkline(g.trend) +
      '<div class="eff-detail">' + formatNum(g.prompt) + ' prompt tokens &middot; ' + formatPct(g.rebuild) + ' rebuilt</div>' +
      '<div class="eff-hit" title="Cache hit rate">' + formatPct(g.hit) + ' hit</div>' +
    '</div>';
  }
  function rows(map, labelFn) {
    return Object.keys(map).sort(function(a, b) { return map[b].prompt - map[a].prompt; }).map(function(k) {
      return row(labelFn ? labelFn(k) : k, map[k]);
    }).join('');
  }
  el.innerHTML = row('All traffic', c.overall, true) +
    '<div class="eff-group">Per account</div>' + rows(c.byAccount) +
    '<div class="eff-group">Per model</div>' + rows(c.byModel, shortModel);
}

function breakdownRows(map, colorFn, labelFn) {
  var keys = Object.keys(map).sort(function(a, b) { return map[b].cost - map[a].cost; });
  var grand = keys.reduce(function(s, k) { return s + map[k].cost; }, 0) || 1;
  var bar = '<div class="tok-proportion">' + keys.map(function(k, i) {
    return '<div class="tok-proportion-seg" style="width:' + (map[k].cost / grand * 100) + '%;background:' + colorFn(k, i) + '"></div>';
  }).join('') + '</div>';
  var rows = keys.map(function(k, i) {
    var m = map[k];
    var prompt = tokPrompt(m);
    return '<div class="tok-model-row">' +
      '<div class="tok-model-dot" style="background:' + colorFn(k, i) + '"></div>' +
      '<div class="tok-model-name" title="' + escHtml(k) + '">' + escHtml(labelFn ? labelFn(k) : k) + '</div>' +
      '<div class="tok-model-detail">' + formatNum(m.requests) + ' calls &middot; ' + formatNum(prompt) + ' in (' + formatPct(prompt ? m.cacheRead / prompt : null) + ' cached) / ' + formatNum(m.output) + ' out</div>' +
      '<div class="tok-model-cost">' + formatCost(m.cost) + '</div>' +
      '<div class="tok-model-pct">' + Math.round(m.cost / grand * 100) + '%</div>' +
    '</div>';
  }).join('');
  return bar + rows + '<div class="section-note" style="margin:0.5rem 0 0">% = share of the API price.</div>';
}

function renderModelBreakdown(d) {
  var models = Object.keys(d.byModel).sort();
  document.getElementById('tok-models').innerHTML = breakdownRows(d.byModel, function(k) { return getModelColor(k, models); }, shortModel);
}

function renderAccountBreakdown(d) {
  document.getElementById('tok-accounts').innerHTML = breakdownRows(d.byAccount, function(k, i) { return TOK_COLORS[i % TOK_COLORS.length]; });
}

function toggleRepoCollapse(repoKey) {
  _tokRepoCollapsed[repoKey] = !_tokRepoCollapsed[repoKey];
  if (_usage) renderRepoBranchBreakdown(_usage);
}

function renderRepoBranchBreakdown(d) {
  var el = document.getElementById('tok-repos');
  var models = Object.keys(d.byModel).sort();
  var inactiveThreshold = Date.now() - 3 * 86400000;
  var grandCost = d.totals.cost || 1;
  var repos = Object.keys(d.byRepo).map(function(k) {
    var r = d.byRepo[k];
    return { key: k, name: k.split('/').pop() || k, total: tokTotal(r), cost: r.cost, lastTs: r.lastTs, branches: r.branches };
  });
  var active = repos.filter(function(r) { return r.lastTs >= inactiveThreshold; }).sort(function(a, b) { return b.total - a.total; });
  var inactive = repos.filter(function(r) { return r.lastTs < inactiveThreshold; }).sort(function(a, b) { return b.total - a.total; });
  var defaultCollapsed = active.length > 3;
  function group(repo, isInactive) {
    if (_tokRepoCollapsed[repo.key] === undefined) _tokRepoCollapsed[repo.key] = isInactive ? true : defaultCollapsed;
    var collapsed = _tokRepoCollapsed[repo.key];
    var h = '<div class="tok-repo-group' + (isInactive ? ' tok-repo-inactive' : '') + '">';
    h += '<div class="tok-repo-header" role="button" tabindex="0" aria-expanded="' + !collapsed + '" onclick="toggleRepoCollapse(this.dataset.key)" onkeydown="if (event.key === \\'Enter\\' || event.key === \\' \\') { event.preventDefault(); toggleRepoCollapse(this.dataset.key); }" data-key="' + escHtml(repo.key) + '">';
    h += '<span class="tok-repo-chevron' + (collapsed ? ' collapsed' : '') + '">&#9660;</span>';
    h += '<span class="tok-repo-name">' + escHtml(repo.name) + '</span>';
    h += '<span class="tok-model-detail" style="flex:1">' + formatNum(repo.total) + ' tokens</span>';
    h += '<span class="tok-model-cost">' + formatCost(repo.cost) + '</span>';
    h += '<span class="tok-model-pct" title="Share of the API price">' + Math.round(repo.cost / grandCost * 100) + '%</span></div>';
    if (!collapsed) {
      Object.keys(repo.branches).sort(function(a, b) { return tokTotal(repo.branches[b]) - tokTotal(repo.branches[a]); }).forEach(function(bn) {
        var br = repo.branches[bn];
        var detail = Object.keys(br.byModel).sort(function(a, b) { return br.byModel[b] - br.byModel[a]; }).map(function(m) {
          return '<span style="color:' + getModelColor(m, models) + '">' + escHtml(shortModel(m)) + '</span> ' + formatNum(br.byModel[m]);
        }).join(' &middot; ');
        h += '<div class="tok-branch-row' + (br.lastTs < inactiveThreshold ? ' tok-branch-inactive' : '') + '" style="padding-left:1.5rem">';
        h += '<div class="tok-branch-name"><span class="tok-branch-badge">' + escHtml(bn) + '</span></div>';
        h += '<div class="tok-branch-stats"><span class="tok-branch-total">' + formatCost(br.cost) + '</span><span class="tok-branch-pct">' + Math.round(br.cost / grandCost * 100) + '%</span></div>';
        h += '<div class="tok-branch-detail">' + detail + '</div></div>';
      });
    }
    return h + '</div>';
  }
  var html = active.map(function(r) { return group(r, false); }).join('');
  if (inactive.length) {
    html += '<div class="tok-inactive-sep">Inactive (no usage in last 3 days)</div>';
    html += inactive.map(function(r) { return group(r, true); }).join('');
  }
  el.innerHTML = html;
}

function tokFilterChange(which) {
  if (which === 'repo') {
    var branchEl = document.getElementById('tok-branch');
    if (branchEl) branchEl.value = '';
  }
  _usageHash = '';
  refreshTokens(true);
}

function exportUsageCsv() {
  var q = 'days=' + tokTimeRange();
  ['repo', 'branch', 'model', 'account'].forEach(function(k) {
    var el = document.getElementById('tok-' + k);
    if (el && el.value) q += '&' + k + '=' + encodeURIComponent(el.value);
  });
  window.location = '/api/usage/export?' + q;
}


// ── Smart cache ──
var SC_CAUSE = {
  idle: 'idle past cache lifetime', account: 'moved to another account', model: 'model switched',
  tools: 'tool list changed', system: 'system prompt changed', settings: 'thinking or settings changed',
  beta: 'API beta header changed', history: 'history rewritten (e.g. compaction)', unknown: 'dropped upstream',
};
var SC_STOP = {
  done: 'learned limit reached', cold: 'cache had already expired', missed: 'ping missed the cache', 'near-limit': 'account near its limit',
  'rate-limited': 'rate limited', moved: 'session moved account', unsupported: 'this model cannot be kept warm',
  network: 'network error', 'no-request-kept': 'no request kept yet', 'account-removed': 'account removed',
};
var _scFetchedAt = 0;

function money(n) {
  var a = Math.abs(n || 0);
  return (n < 0 ? '-' : '') + (a >= 100 ? '$' + Math.round(a).toLocaleString() : '$' + a.toFixed(2));
}

function smartCacheHeadline(c) {
  if (!c || c.pct == null || !(c.saved > 0.005)) return '';
  return ' · smart cache saved ' + Math.round(c.pct * 100) + '% (≈ ' + money(c.saved) + ' this week)';
}

async function refreshSmartCache() {
  if (Date.now() - _scFetchedAt < 15000) return;
  _scFetchedAt = Date.now();
  try { renderSmartCache(await (await fetch('/api/cache-care')).json()); } catch (e) { /* next refresh */ }
}

function renderSmartCache(d) {
  var el = document.getElementById('tok-smartcache');
  if (!el || !d || !d.week) return;
  var w = d.week, m = d.month;
  var head = w.pct == null && w.pings > 0
    ? '<div class="sc-big none">0%</div><div class="sc-sub">' + w.pings + ' keep-warm pings so far (' + money(w.pingCost) + '); no session has come back to a kept cache yet.</div>'
    : w.pct == null
    ? '<div class="sc-big none">–</div><div class="sc-sub">No cache savings or rebuilds recorded yet this week.</div>'
    : w.saved < 0
      ? '<div class="sc-big none">0%</div><div class="sc-sub">Keep-warm cost <b>≈ ' + money(-w.saved) + '</b> more than it saved this week (pings for sessions that did not come back in time).</div>'
      : '<div class="sc-big">' + Math.round(w.pct * 100) + '%</div><div class="sc-sub">of prompt-cache rebuild cost avoided this week · <b>≈ ' + money(w.saved) + '</b> saved' +
        (m.pct != null ? '<br>30 days: ' + Math.round(m.pct * 100) + '% · ≈ ' + money(m.saved) : '') + '</div>';
  var causes = Object.keys(w.rebuilds || {}).map(function(k) { return [k, w.rebuilds[k]]; }).sort(function(a, b) { return b[1].cost - a[1].cost; });
  var lost = causes.length ? causes.slice(0, 6).map(function(c) {
    return '<div class="sc-cause"><span class="sc-cause-name">' + escHtml(SC_CAUSE[c[0]] || c[0]) + '</span>' +
      '<span class="sc-num">' + c[1].count + '× · ' + money(c[1].cost) + '</span></div>';
  }).join('') : '<div class="sc-sub">None this week.</div>';
  var L = d.learned || {};
  var learned = 'Keeps idle sessions warm up to ' + (L.hours ? L.hours.opus : '?') + ' h (Opus) · ' + (L.hours ? L.hours.fable : '?') + ' h (Fable) · ' +
    (L.source === 'yours' ? 'learned from your ' + (L.periods || 0).toLocaleString() + ' idle periods' : 'starting estimate until 50 of your idle periods are seen (' + (L.periods || 0) + ' so far)');
  el.innerHTML = '<div class="usage-title">Smart cache</div>' +
    '<div class="section-note">Prompt-cache rebuilds vdm avoided, at API prices. On a subscription the same share of usage limits is saved.</div>' +
    (d.keepWarm ? '' : '<div class="sc-off">Keep-warm is off: idle sessions lose their cache after an hour. <button class="link-btn" onclick="switchTab(&quot;config&quot;)">Turn it on in Config</button></div>') +
    '<div class="sc-head">' + head + '</div>' +
    '<div class="sc-grid">' +
      '<div class="sc-cell"><div class="sc-cell-title">Keep-warm</div>' + w.pings + ' pings · ' + money(w.pingCost) + '<br>' + w.warmResumes + ' returns to a warm cache · <b class="sc-num">' + money(w.keepWarmSaved) + '</b> saved</div>' +
      '<div class="sc-cell"><div class="sc-cell-title">Session affinity</div>' + w.affinityMoves + ' account moves avoided · <b class="sc-num">' + money(w.affinitySaved) + '</b> saved</div>' +
      '<div class="sc-cell"><div class="sc-cell-title">Still rebuilt · ' + money(w.rebuildCost) + '</div>' + lost + '</div>' +
    '</div>' +
    '<div class="sc-learned">' + escHtml(learned) + (d.stats ? ' · ' + d.stats.kept + ' sessions held, ' + d.stats.memoryMB + ' MB · ' + d.stats.pingsLastHour + ' pings in the last hour' : '') + '</div>';
}

async function loadKeepWarmLearned() {
  try {
    var d = await (await fetch('/api/cache-care')).json();
    var L = d.learned || {};
    document.getElementById('keepwarm-learned').textContent = 'Learned: up to ' + (L.hours ? L.hours.opus : '?') + ' h for Opus, ' + (L.hours ? L.hours.fable : '?') + ' h for Fable · ' +
      (L.source === 'yours' ? 'from your ' + (L.periods || 0).toLocaleString() + ' idle periods' : 'starting estimate (' + (L.periods || 0) + ' of 50 idle periods seen)');
  } catch (e) { /* shown next time */ }
}

function minsUntil(t) { var m = Math.max(0, Math.round((t - Date.now()) / 60000)); return m >= 60 ? Math.floor(m / 60) + 'h ' + (m % 60) + 'm' : m + 'm'; }

function sessionCacheLine(s) {
  var c = s.cache;
  if (!c || !c.state) return '';
  var state;
  if (c.state === 'active') state = '<span class="ok">cache warm</span>';
  else if (c.state === 'kept' && c.small) state = 'cache warm for ' + minsUntil(c.expiresAt) + ' · small, not kept warm';
  else if (c.state === 'kept') state = '<span class="ok">kept warm</span> · next ping in ' + minsUntil(c.nextPingAt) + (c.limit ? ' · ' + c.pingsThisIdle + ' of ' + c.limit : '');
  else if (c.state === 'warm') state = 'cache warm for ' + minsUntil(c.expiresAt) + (c.small ? ' · small, not kept warm' : '');
  else if (c.state === 'stopped') state = 'cache warm for ' + minsUntil(c.expiresAt) + ' · keep-warm stopped: ' + escHtml(SC_STOP[c.stopped] || c.stopped || '');
  else state = 'cache cold';
  var extra = [];
  if (c.saved > 0.005) extra.push('saved ≈ ' + money(c.saved));
  var rb = Object.keys(c.rebuilds || {});
  if (rb.length) {
    var n = rb.reduce(function(a, k) { return a + c.rebuilds[k]; }, 0);
    extra.push('rebuilt ' + n + '×' + (c.lastRebuild ? ' (last: ' + escHtml(SC_CAUSE[c.lastRebuild.cause] || c.lastRebuild.cause) + ')' : ''));
  }
  var modeSel = '<select class="config-select" data-id="' + escHtml(s.id) + '" onchange="setCacheMode(this.dataset.id, this.value)" aria-label="Keep this session warm" title="Auto: learned limit. Keep warm: until the break-even. Never: no pings.">' +
    ['auto', 'pin', 'never'].map(function(v) { return '<option value="' + v + '"' + (c.mode === v ? ' selected' : '') + '>' + ({ auto: 'Auto', pin: 'Keep warm', never: 'Never' })[v] + '</option>'; }).join('') + '</select>';
  return '<div class="sess-cache"><span>' + state + (extra.length ? ' · ' + extra.join(' · ') : '') + '</span>' + modeSel + '</div>';
}

async function setCacheMode(sid, mode) {
  try {
    var r = await fetch('/api/cache-care/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ sid: sid, mode: mode }) });
    showToast(r.ok ? ({ auto: 'Cache: automatic', pin: 'Cache: kept warm until the break-even', never: 'Cache: never kept warm' })[mode] : 'Could not change it');
  } catch (e) { showToast('Could not change it'); }
}

// ── History ──
var HIST = { enabled: false, data: null, rows: [], offset: 0, timer: null, poll: null, open: null, detail: null, handoff: null, msgs: null, seq: 0 };
var HM = String.fromCharCode(2), HM_END = String.fromCharCode(3);

function histParams() {
  var p = new URLSearchParams();
  var q = document.getElementById('hist-q').value.trim();
  if (q) p.set('q', q);
  var project = document.getElementById('hist-project').value;
  var account = document.getElementById('hist-account').value;
  var days = document.getElementById('hist-days').value;
  if (project) p.set('project', project);
  if (account) p.set('account', account);
  if (days && days !== '0') p.set('days', days);
  if (document.getElementById('hist-auto').checked) p.set('automated', '1');
  p.set('offset', String(HIST.offset));
  p.set('limit', '50');
  return p.toString();
}

async function refreshHistory(append) {
  var seq = ++HIST.seq;
  if (!append) HIST.offset = 0;
  try {
    var r = await fetch('/api/history?' + histParams());
    var d = await r.json();
    if (seq !== HIST.seq) return; // a newer search is running
    HIST.enabled = !!d.enabled;
    HIST.data = d;
    HIST.rows = append ? HIST.rows.concat(d.sessions || []) : (d.sessions || []);
    renderHistory();
    histPollWhileBusy(d);
  } catch (e) {
    document.getElementById('hist-status').textContent = 'Could not load history: ' + e.message;
  }
}

// While the first pass saves sessions, refresh every few seconds to show progress
function histPollWhileBusy(d) {
  clearTimeout(HIST.poll);
  var busy = d && (d.backfill || d.state === 'starting' || d.state === 'restarting');
  if (busy && document.getElementById('tab-history').classList.contains('active')) {
    HIST.poll = setTimeout(function() { refreshHistory(); }, 3000);
  }
}

function histQueryChanged() {
  clearTimeout(HIST.timer);
  HIST.timer = setTimeout(function() { refreshHistory(); }, 220);
}

function histFilterChanged() { refreshHistory(); }

function histSearchKey(ev) {
  if (ev.key === 'Escape') { ev.target.value = ''; refreshHistory(); }
  if (ev.key === 'Enter') { clearTimeout(HIST.timer); refreshHistory(); }
}

function histFill(id, values, allLabel) {
  var sel = document.getElementById(id);
  var key = JSON.stringify(values);
  if (sel.dataset.key === key || document.activeElement === sel) return;
  var cur = sel.value;
  sel.innerHTML = '<option value="">' + allLabel + '</option>' + values.map(function(v) {
    return '<option value="' + escHtml(v.value) + '">' + escHtml(v.label) + '</option>';
  }).join('');
  sel.value = values.some(function(v) { return v.value === cur; }) ? cur : '';
  sel.dataset.key = key;
}

function fmtBytes(n) {
  if (!n) return '0 MB';
  if (n < 1e9) return Math.max(0.1, n / 1e6).toFixed(n < 1e7 ? 1 : 0) + ' MB';
  return (n / 1e9).toFixed(1) + ' GB';
}

function histSnippet(s) {
  return escHtml(s).split(HM).join('<mark>').split(HM_END).join('</mark>');
}

function histDayLabel(t) {
  if (!t) return 'Unknown date';
  var d = new Date(t), now = new Date();
  var day = function(x) { return new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime(); };
  var diff = Math.round((day(now) - day(d)) / 86400000);
  if (diff === 0) return 'Today';
  if (diff === 1) return 'Yesterday';
  return d.toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short', year: d.getFullYear() === now.getFullYear() ? undefined : 'numeric' });
}

function baseName(p) { var a = String(p || '').split('/'); return a[a.length - 1] || p; }

function histRow(s) {
  var where = [s.project, s.branch].filter(Boolean).join(' · ');
  var badges = (s.live ? '<span class="pill pill-running" title="This Claude Code session is still open">running</span>' : '') +
    (!s.original ? '<span class="pill pill-saved" title="Claude Code deleted its copy. vdm kept this one.">saved copy</span>' : '') +
    (s.compactions ? '<span class="pill pill-soft" title="Compacted ' + s.compactions + ' times">compacted ×' + s.compactions + '</span>' : '');
  var text = s.snippet ? histSnippet(s.snippet) : (s.firstPrompt ? '“' + escHtml(s.firstPrompt) + '”' : '<span style="color:var(--muted)">No messages</span>');
  var last = !s.snippet && s.lastPrompt && s.lastPrompt !== s.firstPrompt ? '<div class="hist-last">Last: “' + escHtml(s.lastPrompt) + '”</div>' : '';
  var chips = s.accounts.slice(0, 3).map(function(a) { return '<span class="hist-chip acct" title="' + a.requests + ' requests via the proxy">' + escHtml(a.label) + '</span>'; }).join('') +
    s.topFiles.map(function(f) { return '<span class="hist-chip" title="' + escHtml(f) + '">' + escHtml(baseName(f)) + '</span>'; }).join('');
  return '<div class="hist-row' + (HIST.open === s.id ? ' sel' : '') + '" tabindex="0" data-id="' + s.id + '" data-seq="' + (s.hitSeq == null ? '' : s.hitSeq) + '" onclick="histOpen(this.dataset.id, this.dataset.seq)" onkeydown="if (event.key === &quot;Enter&quot;) histOpen(this.dataset.id, this.dataset.seq)">' +
    '<div class="hist-top"><span class="hist-title" title="' + escHtml(s.title) + '">' + escHtml(s.title) + '</span>' + badges +
      '<span class="hist-cost" title="What this session would cost at API prices (incl. subagents)">' + formatCost(s.cost) + '</span></div>' +
    '<div class="hist-sub">' + escHtml(where || s.cwd) + (where ? ' · ' : ' · ') + agoSpan(s.lastAt) + ' · ' + s.userTurns + (s.userTurns === 1 ? ' message' : ' messages') + (s.agents ? ' · ' + s.agents + ' subagents' : '') + '</div>' +
    '<div class="hist-text">' + text + '</div>' + last +
    (chips ? '<div class="hist-chips">' + chips + '</div>' : '') +
  '</div>';
}

function renderHistory() {
  var d = HIST.data || {};
  var off = document.getElementById('hist-off');
  var main = document.getElementById('hist-main');
  var showOff = !d.enabled && !(d.count > 0);
  off.style.display = showOff ? '' : 'none';
  main.style.display = showOff ? 'none' : '';
  document.getElementById('hist-off-note').textContent = d.module === false ? 'history.mjs is missing: run vdm upgrade' : '';
  if (showOff) return;

  var f = d.facets || { projects: [], accounts: [] };
  histFill('hist-project', f.projects.map(function(p) { return { value: p, label: p }; }), 'All projects');
  histFill('hist-account', f.accounts.map(function(a) { return { value: a.name, label: a.label }; }), 'All accounts');

  var st = [];
  if (d.module === false) st.push('<span class="warn">history.mjs is missing: run <code>vdm upgrade</code></span>');
  if (!d.enabled) st.push('<span class="warn">History is off: showing sessions saved earlier.</span> <button class="link-btn" onclick="histTurnOn()">Turn on</button>');
  else if (d.writer === false) st.push('<span class="warn">Read-only: another vdm process is saving sessions right now. This one takes over when it stops.</span>');
  if (d.backfill) {
    var pct = d.backfill.total ? Math.round(d.backfill.done / d.backfill.total * 100) : 0;
    st.push('Saving your sessions… <span class="hist-progress"><div style="width:' + pct + '%"></div></span> ' + d.backfill.done + ' / ' + d.backfill.total);
  } else if (d.state === 'starting' || d.state === 'restarting') st.push('Starting…');
  var storage = d.storage || { own: 0, shared: 0 };
  st.push('<b>' + (d.count || 0) + '</b> sessions saved · ' + fmtBytes(storage.own) + ' on disk' +
    (storage.shared ? ' <span title="Hard links to files Claude Code still has: no extra space until Claude Code deletes them">(+' + fmtBytes(storage.shared) + ' shared with Claude Code)</span>' : ''));
  if (d.search) st.push(d.total + ' found' + (d.search.partial ? ' (search stopped early: add words to narrow it)' : ''));
  if (d.automatedHidden) st.push(d.automatedHidden + ' automated hidden');
  if (d.error) st.push('<span class="warn">' + escHtml(d.error) + '</span>');
  document.getElementById('hist-status').innerHTML = st.join(' <span style="opacity:0.4">|</span> ');

  var list = document.getElementById('hist-list');
  if (!HIST.rows.length) {
    var q = document.getElementById('hist-q').value.trim();
    list.innerHTML = '<div class="empty-state">' + (q ? 'No session mentions that. Try fewer words, or <code>file:</code> / <code>branch:</code>.' : (d.backfill ? 'Saving your sessions…' : 'No sessions saved yet.')) + '</div>';
    return;
  }
  var html = '', lastDay = '';
  var searching = !!(d.search);
  HIST.rows.forEach(function(s) {
    if (!searching) {
      var day = histDayLabel(s.lastAt);
      if (day !== lastDay) { html += '<div class="hist-day">' + escHtml(day) + '</div>'; lastDay = day; }
    }
    html += histRow(s);
  });
  if (HIST.rows.length < d.total) html += '<button class="hbtn hist-more" onclick="histMore()">Show more (' + (d.total - HIST.rows.length) + ' left)</button>';
  list.innerHTML = html;
}

function histMore() { HIST.offset = HIST.rows.length; refreshHistory(true); }

async function histTurnOn() {
  await toggleSetting('sessionHistory', true);
  var t = document.getElementById('toggle-history');
  if (t) t.checked = true;
}

// ── History: detail drawer ──

function histFact(label, value) {
  return value ? '<dt>' + label + '</dt><dd>' + value + '</dd>' : '';
}

function fmtWhen(t) { return t ? new Date(t).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '?'; }

function fmtDuration(ms) {
  if (!ms || ms < 60000) return 'under a minute';
  var m = Math.round(ms / 60000);
  if (m < 120) return m + ' min';
  var h = Math.round(m / 60);
  return h < 48 ? h + ' h' : Math.round(h / 24) + ' days';
}

async function histOpen(id, seq) {
  if (!HIST.open) HIST.returnFocus = document.activeElement;
  HIST.open = id;
  HIST.handoff = null;
  document.querySelectorAll('.hist-row').forEach(function(r) { r.classList.toggle('sel', r.dataset.id === id); });
  document.getElementById('hist-drawer').classList.add('open');
  document.getElementById('hist-backdrop').classList.add('open');
  var box = document.getElementById('hist-detail');
  box.innerHTML = '<div class="empty-state">Loading...</div>';
  box.scrollTop = 0;
  var url = new URL(location);
  url.searchParams.set('session', id);
  history.replaceState(null, '', url);
  try {
    var r = await fetch('/api/history/' + encodeURIComponent(id));
    var d = await r.json();
    if (HIST.open !== id) return;
    if (!r.ok) { box.innerHTML = '<div class="empty-state">' + escHtml(d.error || 'Not found') + '</div>'; return; }
    HIST.open = d.id; // the URL may hold a short id
    HIST.detail = d;
    renderHistDetail(d);
    var closeBtn = box.querySelector('.hd-close');
    if (closeBtn) closeBtn.focus({ preventScroll: true });
    histPrepareHandoff(d.id);
    await histLoadMessages(seq !== undefined && seq !== '' && seq !== null ? { around: Number(seq) } : {});
  } catch (e) { box.innerHTML = '<div class="empty-state">Could not load: ' + escHtml(e.message) + '</div>'; }
}

function histClose() {
  var closingId = HIST.open;
  HIST.open = null;
  var back = HIST.returnFocus;
  HIST.returnFocus = null;
  if (!back || !document.contains(back)) back = document.querySelector('.hist-row[data-id="' + closingId + '"]');
  if (back && back.focus) back.focus({ preventScroll: true });
  document.getElementById('hist-drawer').classList.remove('open');
  document.getElementById('hist-backdrop').classList.remove('open');
  document.querySelectorAll('.hist-row.sel').forEach(function(r) { r.classList.remove('sel'); });
  var url = new URL(location);
  url.searchParams.delete('session');
  history.replaceState(null, '', url);
}

document.addEventListener('keydown', function(ev) {
  if (ev.key === 'Escape' && HIST.open) histClose();
});

function openHistoryFor(id) {
  switchTab('history');
  histOpen(id);
}

// Write the handoff as soon as the panel opens, so "Copy prompt" copies right on click
async function histPrepareHandoff(id) {
  try {
    var r = await fetch('/api/history/' + id + '/handoff', { method: 'POST' });
    var h = await r.json();
    if (r.ok && HIST.open === id) HIST.handoff = h;
  } catch (e) { /* tried again on click */ }
}

function renderHistDetail(d) {
  var where = [d.project, d.branch].filter(Boolean).join(' · ');
  var badges = (d.live ? '<span class="pill pill-running">running</span>' : '') +
    (!d.original ? '<span class="pill pill-saved" title="Claude Code deleted its copy. vdm kept this one.">saved copy</span>' : '');
  var resume;
  if (!d.cwdExists) {
    resume = '<div class="hd-warn">The folder of this session is gone: ' + escHtml(d.cwd || '?') + '.' +
      (d.repoRoot && d.branch ? ' Recreate it with <code>git -C ' + escHtml(d.repoRoot) + ' worktree add ' + escHtml(d.cwd) + ' ' + escHtml(d.branch) + '</code>, or continue from the handoff instead.' : ' Continue from the handoff instead.') + '</div>';
  } else if (d.needsRestore && !d.canResume) {
    resume = '<div class="hd-warn">' + escHtml(d.rawNote || 'No full copy of this session was saved, only the text.') + '</div>';
  } else {
    resume = (d.needsRestore ? '<div class="hd-act-desc">Claude Code deleted its copy. This first puts the saved copy back.</div>' : '') +
      '<div class="hd-btns"><button class="hbtn" onclick="histResume()">' + (d.needsRestore ? 'Restore session file' : 'Copy resume command') + '</button></div>' +
      '<code class="hd-cmd" title="' + escHtml(d.commands.resume) + '">' + escHtml(d.commands.resume) + '</code>';
  }
  var accounts = d.accounts.map(function(a) { return escHtml(a.label) + ' <span style="color:var(--muted)">(' + a.requests + ' req)</span>'; }).join(', ');
  var files = d.files.slice(0, 12).map(function(f) { return '<div title="' + escHtml(f[0]) + '">' + escHtml(f[0].replace(d.cwd + '/', '')) + (f[1] > 1 ? ' <span style="color:var(--muted)">×' + f[1] + '</span>' : '') + '</div>'; }).join('') +
    (d.files.length > 12 ? '<div style="color:var(--muted)">+' + (d.files.length - 12) + ' more</div>' : '');
  var links = (d.allLinks || []).map(function(l) { return '<a href="' + escHtml(l) + '" target="_blank" rel="noopener">' + escHtml(l.replace('https://', '')) + '</a>'; }).join('<br>');
  var st = d.stats || {};
  var models = (d.models || []).map(function(m) { return escHtml(shortModel(m)); }).join(', ');
  var html = '<div class="hd-head"><div class="hd-title">' + escHtml(d.title) + '</div><button class="hd-close" onclick="histClose()" aria-label="Close">&times;</button></div>' +
    '<div class="hd-sub">' + badges + (where ? '<span>' + escHtml(where) + '</span><span>·</span>' : '') +
      '<span class="hd-id" title="Session id">' + d.id + '</span><button class="chip" onclick="histCopy(HIST.detail.id, &quot;Session id copied&quot;)">copy id</button></div>' +
    '<div class="hd-actions">' +
      '<div class="hd-act main"><div class="hd-act-title">Continue in a new session</div>' +
        '<div class="hd-act-desc">vdm writes a handoff file from this session (no AI): the latest summary, the last messages and the files that changed. Paste the prompt into any new Claude session.</div>' +
        '<div class="hd-btns"><button class="hbtn hbtn-primary" onclick="histCopyPrompt()">Copy prompt</button>' +
        '<button class="hbtn" onclick="histCopy(HIST.detail.commands.continue, &quot;Command copied: run it in a terminal&quot;)" title="Opens a new Claude session in the right folder with the handoff loaded">Copy terminal command</button></div>' +
        '<code class="hd-cmd">' + escHtml(d.commands.continue) + '</code></div>' +
      '<div class="hd-act"><div class="hd-act-title">Resume exactly</div>' +
        '<div class="hd-act-desc">Opens this same session with its full history (Claude Code --resume). Its prompt cache is gone, so the first message costs more.</div>' + resume + '</div>' +
    '</div>' +
    '<dl class="hd-facts">' +
      histFact('Folder', escHtml(d.cwd || '?') + (d.cwdExists ? '' : ' <span class="pill pill-saved">gone</span>')) +
      histFact('Branch', escHtml((d.branches || []).join(' → ') || d.branch || '')) +
      histFact('When', fmtWhen(d.firstAt) + ' → ' + fmtWhen(d.lastAt) + ' <span style="color:var(--muted)">(' + fmtDuration((d.lastAt || 0) - (d.firstAt || 0)) + ')</span>') +
      histFact('Size', d.userTurns + ' of your messages · ' + (st.claudeMsgs || 0) + ' replies · ' + (st.toolCalls || 0) + ' tool calls' + (d.compactions ? ' · compacted ×' + d.compactions : '')) +
      histFact('Cost', formatCost(d.cost) + ' <span style="color:var(--muted)">at API prices (from the transcript' + (d.agents ? ', incl. ' + d.agents + ' subagents' : '') + ')</span>') +
      histFact('Models', models) +
      histFact('Accounts', accounts) +
      histFact('Files changed', files ? '<div class="hd-files">' + files + '</div>' : '') +
      histFact('Links', links) +
    '</dl>' +
    '<div class="hd-conv-head"><b>Conversation <span style="color:var(--muted);font-weight:400">(' + d.messages + ' entries)</span></b>' +
      (d.prompts.length ? '<select class="config-select" id="hd-jump" onchange="histJump(this.value)" aria-label="Jump to one of your messages"><option value="">Jump to your message…</option>' +
        d.prompts.map(function(p) { return '<option value="' + p.i + '">' + escHtml((p.t ? new Date(p.t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) + ' · ' : '') + p.x) + '</option>'; }).join('') + '</select>' : '') +
    '</div>' +
    '<div id="hd-msgs"><div class="empty-state">Loading...</div></div>' +
    '<div class="hd-foot"><a class="hbtn" href="/api/history/' + d.id + '/download" download>Download transcript (.jsonl)</a>' +
      '<button class="hbtn hbtn-danger" onclick="histDelete()">Delete from archive</button></div>';
  document.getElementById('hist-detail').innerHTML = html;
}

async function histLoadMessages(opts) {
  var id = HIST.open;
  var seq = HIST.msgSeq = (HIST.msgSeq || 0) + 1;
  var p = new URLSearchParams();
  if (opts.around != null && !isNaN(opts.around)) p.set('around', String(opts.around));
  if (opts.from != null) p.set('from', String(opts.from));
  p.set('limit', '200');
  var box = document.getElementById('hd-msgs');
  try {
    var r = await fetch('/api/history/' + id + '/messages?' + p.toString());
    var m = await r.json();
    if (HIST.open !== id || !box || seq !== HIST.msgSeq) return;
    if (!r.ok) { box.innerHTML = '<div class="empty-state">Could not load messages: ' + escHtml(m.error || r.status) + '</div>'; return; }
    HIST.msgs = m;
    box.innerHTML = renderHistMessages(m);
    var focus = opts.around != null ? opts.around : opts.focus;
    if (focus != null && !isNaN(focus)) {
      var el = document.getElementById('hm-' + focus) || box.querySelector('[data-first="' + focus + '"]');
      if (el) {
        var group = el.tagName === 'DETAILS' ? el : (el.closest && el.closest('details'));
        if (group) group.open = true;
        el.classList.add('focus');
        el.scrollIntoView({ block: 'center' });
      }
    }
  } catch (e) { if (box) box.innerHTML = '<div class="empty-state">Could not load messages: ' + escHtml(e.message) + '</div>'; }
}

function histJump(seq) { if (seq !== '') histLoadMessages({ around: Number(seq) }); }

function histText(x) {
  var t = escHtml(x);
  return x.length > 1400 ? '<div class="hm-text clamp">' + t + '</div><button class="link-btn" onclick="this.previousElementSibling.classList.remove(&quot;clamp&quot;); this.remove()">Show all</button>' : '<div class="hm-text">' + t + '</div>';
}

function renderHistMessages(m) {
  var recs = m.records || [];
  if (!recs.length) return '<div class="empty-state">No messages saved.</div>';
  var out = [];
  if (m.start > 0) out.push('<div class="hm-pager"><button class="hbtn" onclick="histLoadMessages({ from: ' + Math.max(0, recs[0].i - 200) + ', focus: ' + recs[0].i + ' })">Show earlier (' + m.start + ' more)</button></div>');
  var tools = [];
  var flush = function() {
    if (!tools.length) return;
    var counts = {};
    tools.forEach(function(t) { counts[t.n || 'tool'] = (counts[t.n || 'tool'] || 0) + 1; });
    var sum = Object.keys(counts).map(function(k) { return k + (counts[k] > 1 ? ' ×' + counts[k] : ''); }).join(', ');
    out.push('<details class="hm-tools" data-first="' + tools[0].i + '"><summary>' + tools.length + (tools.length === 1 ? ' tool call' : ' tool calls') + ' · ' + escHtml(sum) + '</summary>' +
      tools.map(function(t) { return '<div class="hm-tool" id="hm-' + t.i + '" title="' + escHtml(t.x) + '">' + escHtml(t.n || '') + ' · ' + escHtml(t.x) + '</div>'; }).join('') + '</details>');
    tools = [];
  };
  recs.forEach(function(r) {
    if (r.r === 'tool') { tools.push(r); return; }
    flush();
    var time = r.t ? new Date(r.t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : '';
    if (r.r === 'user') out.push('<div class="hm hm-user" id="hm-' + r.i + '"><div class="hm-who">You · ' + time + '</div>' + histText(r.x) + '</div>');
    else if (r.r === 'claude') out.push('<div class="hm hm-claude" id="hm-' + r.i + '"><div class="hm-who">Claude</div>' + histText(r.x) + '</div>');
    else if (r.r === 'compact') out.push('<details class="hm-compact" id="hm-' + r.i + '"><summary>Compacted' + (r.p ? ' at ' + formatNum(r.p) + ' tokens' : '') + ' · ' + time + ' · Claude Code’s summary</summary>' + histText(r.x) + '</details>');
    else if (r.r === 'recap') out.push('<div class="hm hm-recap" id="hm-' + r.i + '">Recap: ' + escHtml(r.x) + '</div>');
    else if (r.r === 'command') out.push('<div class="hm-cmd" id="hm-' + r.i + '">' + escHtml(r.x) + '</div>');
  });
  flush();
  var last = recs[recs.length - 1];
  if (m.start + recs.length < m.total) out.push('<div class="hm-pager"><button class="hbtn" onclick="histLoadMessages({ from: ' + (last.i + 1) + ', focus: ' + (last.i + 1) + ' })">Show later (' + (m.total - m.start - recs.length) + ' more)</button></div>');
  return out.join('');
}

// Copy to the clipboard. Browsers can refuse (e.g. after a slow request): then show the text so
// it can be copied by hand, and never claim it was copied.
async function histCopy(text, msg) {
  var ok = false;
  var had = document.activeElement;
  try { await navigator.clipboard.writeText(text); ok = true; }
  catch (e) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand('copy') === true; } catch (e2) { ok = false; }
    ta.remove();
    if (had && had.focus) had.focus({ preventScroll: true });
  }
  if (ok) showToast(msg || 'Copied');
  else window.prompt('Your browser blocked copying. Copy this by hand (Cmd+C):', text);
  return ok;
}

async function histCopyPrompt() {
  var id = HIST.open;
  if (!HIST.handoff || HIST.handoff.id !== id) {
    try {
      var r = await fetch('/api/history/' + id + '/handoff', { method: 'POST' });
      var h = await r.json();
      if (!r.ok) { showToast(h.error || 'Could not write the handoff'); return; }
      HIST.handoff = h;
    } catch (e) { showToast('Could not write the handoff'); return; }
  }
  histCopy(HIST.handoff.prompt, 'Prompt copied: paste it into a new Claude session');
}

async function histResume() {
  var d = HIST.detail;
  if (!d.needsRestore) { histCopy(d.commands.resume, 'Command copied: run it in a terminal'); return; }
  // Restoring can take a while; the browser may then refuse a copy, so this click only restores
  try {
    var r = await fetch('/api/history/' + d.id + '/restore', { method: 'POST' });
    var x = await r.json();
    if (!r.ok) { showToast(x.error || 'Restore failed'); return; }
  } catch (e) { showToast('Restore failed'); return; }
  showToast('Restored. Now click “Copy resume command”.');
  histOpen(d.id);
}

async function histDelete() {
  var d = HIST.detail;
  if (!confirm('Delete "' + d.title + '" from the vdm archive?' + String.fromCharCode(10, 10) + 'Claude Code’s own copy is not touched. vdm will not save this session again.')) return;
  try {
    var r = await fetch('/api/history/' + d.id + '/delete', { method: 'POST' });
    var x = await r.json();
    if (!r.ok) { showToast(x.error || 'Delete failed'); return; }
    showToast('Deleted from the archive');
    histClose();
    refreshHistory();
  } catch (e) { showToast('Delete failed'); }
}

async function saveHistorySetting(patch, msg) {
  try {
    var r = await fetch('/api/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(patch) });
    var x = await r.json();
    showToast(r.ok ? msg : (x.error || 'Failed to update'));
    if (!r.ok) {
      // Put the saved value back, even in the field that still has focus
      if (document.activeElement && document.activeElement.blur) document.activeElement.blur();
      loadSettingsUI();
    }
  } catch (e) { showToast('Failed to update'); }
}

async function saveHotLine(v) {
  HOT_TOKENS = v;
  await saveHistorySetting({ hotTokensPer5m: v }, 'Hot line: ' + fmtTokens(v) + ' tokens per 5 minutes');
  refresh();
}

function saveClaudeCommand(v) { saveHistorySetting({ claudeCommand: v }, 'Launch command saved'); }
function saveHistoryKeep(days) { saveHistorySetting({ historyRetentionDays: days }, days ? 'Saved sessions kept for ' + days + ' days' : 'Saved sessions kept forever'); }
function saveHistoryExclude(v) {
  var list = v.split(String.fromCharCode(10)).map(function(x) { return x.trim(); }).filter(Boolean);
  saveHistorySetting({ historyExclude: list }, list.length ? list.length + ' folders skipped' : 'No folders skipped');
}

// Open a session from the URL (?tab=history&session=<id>)
(function() {
  var sid = new URLSearchParams(location.search).get('session');
  if (sid && new URLSearchParams(location.search).get('tab') === 'history') setTimeout(function() { histOpen(sid); }, 50);
})();

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

// ── Sessions (affinity) ──

var AFF_TEXT = { strong: 'Locked', ok: 'Holding', weak: 'Drifting' };
var MOVE_REASON = {
  assign: 'placed',
  idle: 'cache had expired, re-placed',
  unavailable: 'account was limited or used up',
  'account-removed': 'account was removed',
  '429-limit': 'account hit its limit',
  '429-burst': 'account was briefly overloaded',
  '401': 'login expired',
  '400': 'account rejected the request',
  'network-error': 'network error',
  'manual-switch': 'you switched accounts',
};

function timeAgo(ts) {
  if (!ts) return '';
  var d = Date.now() - ts;
  if (d < 60000) return 'just now';
  if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
  if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
  return Math.floor(d / 86400000) + 'd ago';
}

function agoSpan(ts) {
  return '<span data-ago="' + (ts || 0) + '">' + timeAgo(ts) + '</span>';
}

function affTitle(level, warmMoves1h, cacheHit, share) {
  var parts = [(AFF_TEXT[level] || level) + ' to its account'];
  parts.push(warmMoves1h ? warmMoves1h + (warmMoves1h === 1 ? ' move' : ' moves') + ' with a warm cache in the last hour' : 'no cache-losing moves in the last hour');
  if (share != null && share < 1) parts.push(Math.round(share * 100) + '% of recent requests on one account');
  if (cacheHit != null) parts.push(Math.round(cacheHit * 100) + '% of recent prompt tokens read from cache');
  return parts.join(' · ');
}

function affBars(level, title) {
  return '<span class="aff aff-' + level + '" title="' + escHtml(title || '') + '" role="img" aria-label="' + escHtml(title || '') + '"><i></i><i></i><i></i></span>';
}

function cachePct(hit) {
  return hit == null ? '&ndash; cache' : Math.round(hit * 100) + '% cache';
}

// Sessions block on an account card: who ran through this account in the last 24h.
function renderAccountSessions(p) {
  var list = p.sessions || [];
  if (!list.length) return '';
  var warm = list.filter(function(s) { return s.pinnedHere; }).length;
  var rows = list.slice(0, 5).map(function(s) {
    var title = affTitle(s.affinity, s.warmMoves1h, s.cacheHit, s.share) + (s.title ? ' · ' + s.title : '');
    return '<div class="sess-row" title="' + escHtml(title) + '">' +
      '<span class="sess-here' + (s.pinnedHere ? '' : ' away') + '" title="' + (s.pinnedHere ? 'Warm here: this session is pinned to this account right now' : 'Not pinned here now') + '"></span>' +
      affBars(s.affinity, title) +
      '<span class="sess-name">' + escHtml(s.label) + '</span>' +
      '<span class="sess-meta">' + s.requests + ' req &middot; ' + cachePct(s.cacheHit) + ' &middot; ' + agoSpan(s.lastAt) + '</span></div>';
  }).join('');
  var eName = p.name.replace(/'/g, "\\\\'");
  var more = list.length > 5 ? '<button class="link-btn" onclick="openSessionsFor(\\'' + eName + '\\')">Show all ' + list.length + '</button>' : '';
  return '<div class="acct-sessions"><div class="acct-sessions-head"><span>Sessions</span>' +
    '<span title="Green dot = pinned here now with a warm cache">' + warm + ' warm here &middot; ' + list.length + ' in 24h</span></div>' + rows + more + '</div>';
}

var _sessions = null;
var _sessionsHash = '';
var _sessionsError = '';

async function refreshSessions() {
  var tab = document.getElementById('tab-sessions');
  if (!tab || !tab.classList.contains('active')) return;
  try {
    var resp = await fetch('/api/sessions?hours=24');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    _sessionsError = '';
    var h = quickHash({ d: data, hist: HIST.enabled });
    if (h === _sessionsHash) return;
    _sessionsHash = h;
    _sessions = data;
  } catch (e) {
    _sessionsError = 'Could not load sessions (' + e.message + '). Retrying...';
  }
  renderSessions();
}

function openSessionsFor(name) {
  switchTab('sessions');
  var sel = document.getElementById('sess-account');
  sel.dataset.want = name;
  sel.value = name;
  renderSessions();
}

function moveLine(m) {
  return '<div class="sess-move' + (m.warm ? ' warm' : '') + '">' + agoSpan(m.ts) + ' &middot; ' + escHtml(m.fromLabel) + ' &rarr; ' + escHtml(m.toLabel) +
    ' &middot; ' + escHtml(MOVE_REASON[m.reason] || m.reason) + (m.agent !== 'main' ? ' (subagent)' : '') +
    (m.warm ? ' &middot; cache rebuilt' : ' &middot; cache was already cold') + '</div>';
}

function sessionCard(s) {
  var a = s.affinity;
  var title = affTitle(a.level, a.warmMoves1h, a.cacheHit, a.share);
  // The label is often "branch:id": don't repeat the branch underneath
  var branch = s.meta.branch && s.label.indexOf(s.meta.branch + ':') !== 0 ? s.meta.branch : '';
  var where = [s.meta.repoName, branch].filter(Boolean).join(' · ');
  var sub = s.meta.autoTitle ? s.meta.autoTitle + (where ? ' · ' + where : '') : where;
  var warmLanes = s.lanes.filter(function(l) { return l.warm; });
  var subagents = warmLanes.filter(function(l) { return l.agent !== 'main'; }).length;
  var on = 'On <b>' + escHtml(s.homeLabel || '?') + '</b>' + (subagents ? ' &middot; ' + subagents + ' subagent' + (subagents === 1 ? '' : 's') + ' warm' : '');
  var total = s.accounts.reduce(function(n, x) { return n + x.requests; }, 0) || 1;
  var accts = s.accounts.map(function(x) {
    var prompt = x.input + x.cacheRead + x.cacheWrite;
    return '<div class="sess-acct-row"><span class="sess-acct-name" title="' + escHtml(x.label) + '">' + escHtml(x.label) + '</span>' +
      '<span class="sess-acct-bar" title="' + Math.round(x.requests / total * 100) + '% of this session\\'s requests"><div style="width:' + (x.requests / total * 100).toFixed(1) + '%"></div></span>' +
      '<span class="sess-meta">' + x.requests + ' req &middot; ' + cachePct(prompt ? x.cacheRead / prompt : null) + ' &middot; ' + formatCost(x.cost) + '</span></div>';
  }).join('');
  var moves = s.moves.length ? '<div class="sess-moves">' + s.moves.slice(0, 3).map(moveLine).join('') +
    (s.moves.length > 3 ? '<div>+' + (s.moves.length - 3) + ' earlier moves</div>' : '') + '</div>' : '';
  var arts = s.artifacts && s.artifacts.length
    ? ' <button class="chip" onclick="openArtifactSearch(\\'claude.ai/artifact/' + escHtml(s.artifacts[s.artifacts.length - 1]) + '\\')" title="Find who owns the latest artifact linked in this session">' + (s.artifacts.length === 1 ? 'artifact' : 'latest of ' + s.artifacts.length + ' artifacts') + '</button>' : '';
  return '<div class="sess-card">' +
    '<div class="sess-card-top">' +
      '<span class="sess-card-title" title="' + escHtml(s.id) + '">' + escHtml(s.label) + '</span>' +
      (s.live ? '<span class="pill pill-running" title="This Claude Code session is still open">running</span>' : '') +
      (HIST.enabled ? '<button class="chip" data-id="' + escHtml(s.id) + '" onclick="openHistoryFor(this.dataset.id)" title="Search, read and continue this session">history</button>' : '') +
      '<span class="sess-meta">' + agoSpan(s.lastAt) + '</span></div>' +
    (sub ? '<div class="sess-sub" title="' + escHtml(sub) + '">' + escHtml(sub) + '</div>' : '') +
    '<div class="sess-aff-line">' + affBars(a.level, title) + '<span><b>' + (AFF_TEXT[a.level] || a.level) + '</b> &middot; ' + on + ' &middot; ' + cachePct(a.cacheHit) +
      ' &middot; ' + s.requests + ' req' + (s.model ? ' &middot; ' + escHtml(shortModel(s.model)) : '') + '</span>' + arts + '</div>' +
    '<div class="sess-accts">' + accts + '</div>' + sessionCacheLine(s) + moves +
  '</div>';
}

function sessionLine(s) {
  var a = s.affinity;
  var title = affTitle(a.level, a.warmMoves1h, a.cacheHit, a.share);
  var where = [s.meta.repoName, s.meta.branch].filter(Boolean).join(' · ');
  return '<div class="sess-line" title="' + escHtml((s.meta.autoTitle ? s.meta.autoTitle + ' · ' : '') + where) + '">' +
    affBars(a.level, title) +
    '<span class="sess-name">' + escHtml(s.label) + '</span>' +
    (s.live ? '<span class="pill pill-running">running</span>' : '') +
    '<span class="sess-meta">last on ' + escHtml(s.homeLabel || '?') + ' &middot; ' + s.requests + ' req' + (s.moves.length ? ' &middot; ' + s.moves.length + ' move' + (s.moves.length === 1 ? '' : 's') : '') + ' &middot; ' + agoSpan(s.lastAt) + '</span></div>';
}

function renderSessions() {
  var note = document.getElementById('sessions-note');
  var el = document.getElementById('sessions-content');
  var data = _sessions;
  if (!data) {
    el.innerHTML = _sessionsError ? '<div class="empty-state err-state">' + escHtml(_sessionsError) + '</div>' : '<div class="empty-state">Loading...</div>';
    return;
  }
  note.innerHTML = data.affinity
    ? 'Each Claude Code session, and each of its subagents, stays on one account while its prompt cache is warm. <span style="color:var(--red)">Red</span> moves rebuilt a warm cache on another account.' +
      (_sessionsError ? ' <span class="err-state">' + escHtml(_sessionsError) + '</span>' : '')
    : 'Session affinity is <b>off</b> (Config): sessions are tracked, but not kept on one account.';
  var sel = document.getElementById('sess-account');
  var names = {};
  data.sessions.forEach(function(s) { s.accounts.forEach(function(x) { names[x.name] = x.label; }); });
  var want = sel.dataset.want || sel.value;
  var opts = '<option value="">All accounts</option>' + Object.keys(names).sort().map(function(n) {
    return '<option value="' + escHtml(n) + '"' + (n === want ? ' selected' : '') + '>' + escHtml(names[n]) + '</option>';
  }).join('');
  if (sel.dataset.opts !== opts && document.activeElement !== sel) { sel.innerHTML = opts; sel.dataset.opts = opts; }
  delete sel.dataset.want;
  var acct = sel.value;
  var list = data.sessions.filter(function(s) { return !acct || s.accounts.some(function(x) { return x.name === acct; }); });
  var activeNow = list.filter(function(s) { return s.lanes.some(function(l) { return l.warm; }); });
  var earlier = list.filter(function(s) { return !s.lanes.some(function(l) { return l.warm; }); });
  document.getElementById('sess-counts').textContent = activeNow.length + ' active now · ' + earlier.length + ' earlier (last 24h)';
  if (!list.length) {
    el.innerHTML = '<div class="empty-state">' + (acct ? 'No sessions used this account in the last 24 hours.' : 'No sessions in the last 24 hours. A session shows up after its first request through the proxy.') + '</div>';
    return;
  }
  var html = '';
  if (activeNow.length) html += '<div class="sess-section-title">Active now (cache warm)</div>' + activeNow.map(sessionCard).join('');
  if (earlier.length) html += '<div class="sess-section-title">Earlier (cache expired)</div>' + earlier.map(sessionLine).join('');
  el.innerHTML = html;
  tickCountdowns();
}

function updateSessionsBadge(profiles) {
  var badge = document.getElementById('sessions-badge');
  if (!badge) return;
  var live = {};
  (profiles || []).forEach(function(p) {
    (p.sessions || []).forEach(function(s) { if (s.pinnedHere) live[s.id] = 1; });
  });
  var n = Object.keys(live).length;
  badge.textContent = n;
  badge.style.display = n ? '' : 'none';
  badge.title = n + ' session' + (n === 1 ? '' : 's') + ' with a warm cache';
}

// ── Artifacts ──

var _artifacts = null;
var _artifactsHash = '';
var _artifactsError = '';
var _artExpanded = {};
var ART_ROWS = 8;

async function refreshArtifactsTab() {
  var tab = document.getElementById('tab-artifacts');
  if (!tab || !tab.classList.contains('active')) return;
  try {
    var resp = await fetch('/api/artifacts');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    _artifactsError = '';
    var h = quickHash(data);
    if (h !== _artifactsHash) { _artifactsHash = h; _artifacts = data; }
  } catch (e) {
    _artifactsError = 'Could not load artifacts (' + e.message + ').';
  }
  renderArtifacts();
}

async function refreshArtifactsNow() {
  var btn = document.getElementById('art-refresh');
  btn.disabled = true;
  btn.textContent = 'Checking...';
  try {
    var resp = await fetch('/api/artifacts/refresh', { method: 'POST' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    _artifacts = await resp.json();
    _artifactsHash = quickHash(_artifacts);
    renderArtifacts();
    var failed = _artifacts.accounts.filter(function(a) { return a.error; }).length;
    showToast(failed ? 'Checked; ' + failed + ' account' + (failed === 1 ? '' : 's') + ' could not be read' : 'Artifact list is up to date');
  } catch (e) { showToast('Check failed: ' + e.message); }
  btn.disabled = false;
  btn.textContent = 'Check now';
}

// A pasted link: the id part after /artifact/
function artifactQueryId(q) {
  var i = q.indexOf('/artifact/');
  if (i === -1) return '';
  return q.slice(i + 10).split(/[?#\\s]/)[0];
}

function artifactMatches(f, q, id) {
  if (!q) return true;
  if (id) return f.slug === id || (f.slug.length >= 8 && id.slice(-f.slug.length) === f.slug) || (id.length >= 8 && f.slug.slice(-id.length) === id);
  return (f.title + ' ' + f.description + ' ' + f.slug).toLowerCase().indexOf(q) !== -1;
}

function toggleArtGroup(name) {
  _artExpanded[name] = !_artExpanded[name];
  renderArtifacts();
}

function renderArtifacts() {
  var el = document.getElementById('artifacts-content');
  var status = document.getElementById('art-status');
  var data = _artifacts;
  if (!data) {
    el.innerHTML = _artifactsError ? '<div class="empty-state err-state">' + escHtml(_artifactsError) + '</div>' : '<div class="empty-state">Loading...</div>';
    return;
  }
  status.innerHTML = (data.updatedAt ? 'Checked ' + agoSpan(data.updatedAt) : 'Not checked yet') + ' &middot; checks every ' + data.pollMinutes + ' min' +
    (data.refreshing ? ' &middot; checking now...' : '') + (_artifactsError ? ' &middot; <span class="err-state">' + escHtml(_artifactsError) + '</span>' : '');
  var raw = (document.getElementById('art-search').value || '').trim();
  var q = raw.toLowerCase();
  var id = artifactQueryId(raw);
  var anyMatch = false;
  var html = data.accounts.map(function(a) {
    var frames = a.frames.filter(function(f) { return artifactMatches(f, q, id); });
    if (q && !frames.length) return '';
    if (frames.length) anyMatch = true;
    var state = !a.fetchedAt
      ? (a.error ? '<span class="art-err">could not check: ' + escHtml(a.error) + '</span>' : 'not checked yet')
      : (a.error ? '<span class="art-err">last check failed (' + escHtml(a.error) + '), showing the list from ' + agoSpan(a.fetchedAt) + '</span> &middot; ' : '') +
        (q ? frames.length + ' of ' : '') + a.frames.length + ' owned' + (a.shared ? ' &middot; ' + a.shared + ' shared' : '');
    var head = '<div class="art-group-head" id="art-g-' + escHtml(a.name) + '"><span>' + escHtml(a.label) + '</span><span class="art-meta">' + state + '</span></div>';
    var shown = (q || _artExpanded[a.name]) ? frames : frames.slice(0, ART_ROWS);
    var rows = shown.map(function(f) {
      var created = f.createdAt ? new Date(f.createdAt).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }) : '';
      var meta = [created, f.audience ? 'visible to ' + f.audience : '', f.session ? 'from session ' + f.session.label : ''].filter(Boolean).join(' · ');
      return '<div class="art-row"><a class="art-title" href="' + escHtml(f.url) + '" target="_blank" rel="noopener" title="' + escHtml(f.description || f.title) + '">' + escHtml(f.title || f.slug) + '</a>' +
        '<span class="art-meta">' + escHtml(meta) + '</span></div>';
    }).join('');
    if (!frames.length) rows = '<div class="art-row"><span class="art-meta">' + (a.fetchedAt ? 'No artifacts' : 'Waiting for the first check') + '</span></div>';
    if (!q && frames.length > ART_ROWS) {
      var eName = a.name.replace(/'/g, "\\\\'");
      rows += '<div class="art-row"><button class="link-btn" onclick="toggleArtGroup(\\'' + eName + '\\')">' + (_artExpanded[a.name] ? 'Show fewer' : 'Show all ' + frames.length) + '</button></div>';
    }
    return '<div class="art-group">' + head + rows + '</div>';
  }).join('');
  if (q && !anyMatch) {
    html = '<div class="empty-state">None of your connected accounts owns an artifact matching "' + escHtml(raw) + '".' +
      (data.updatedAt ? '' : ' The first check has not finished yet.') + '</div>';
  }
  el.innerHTML = html || '<div class="empty-state">No accounts.</div>';
  tickCountdowns();
}

function openArtifactSearch(text) {
  switchTab('artifacts');
  document.getElementById('art-search').value = text || '';
  renderArtifacts();
}

function openArtifactsFor(name) {
  switchTab('artifacts');
  document.getElementById('art-search').value = '';
  setTimeout(function() {
    renderArtifacts();
    var g = document.getElementById('art-g-' + name);
    if (g) g.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 300);
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

/**
 * Why a dashboard request is refused, or null. Only this computer may connect (unless
 * CSW_ALLOW_REMOTE=1), the Host must be ours (DNS rebinding), and other web pages may not
 * call the API (foreign Origin, or a cross-site fetch).
 */
function dashboardRefusal(req) {
  if (!ALLOW_REMOTE) {
    if (!isLoopbackAddr(req.socket.remoteAddress)) return 'remote';
    if (!isLocalHost(req.headers.host, PORT)) return 'host';
  }
  const origin = req.headers.origin;
  if (origin && !isSameOrigin(origin, req.headers.host)) return 'origin';
  if (req.headers['sec-fetch-site'] === 'cross-site' && req.headers['sec-fetch-mode'] !== 'navigate') return 'cross-site';
  return null;
}

const server = createServer(async (req, res) => {
  try {
    const refusal = dashboardRefusal(req);
    if (refusal) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      res.end(refusal === 'remote'
        ? 'vdm dashboard: only this computer may connect (set CSW_ALLOW_REMOTE=1 to allow other devices)\n'
        : 'vdm dashboard: request refused (not from this dashboard)\n');
      return;
    }
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
  onServerListening();
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
    utilization7dOI: data.utilization7dOI ?? null,
    resetAt7dOI: data.resetAt7dOI || 0,
    limitedUntil: data.limitedUntil || 0,
    claim: data.claim || null,
    modelLimits: data.modelLimits || undefined,
    updatedAt: Date.now(),
  };
  savePersistedState();
}

// Snapshot of an account's tracked state for account-state.json.
function persistAccountState(token, fingerprint) {
  const st = accountState.get(token);
  if (st && fingerprint) updatePersistedState(fingerprint, st);
}

// Load on startup
loadPersistedState();



function updateAccountState(token, name, headers, fingerprint) {
  accountState.update(token, name, headers);
  // Responses without unified headers (errors, other endpoints) carry no limit info
  const rl = parseRateLimitHeaders(headers);
  if (!rl.status && !rl.fiveH && !rl.sevenD && !rl.sevenDOI) return;
  if (fingerprint) {
    // A missing header is "unknown" (the chart keeps the last value), never 0
    const util = (h) => {
      const v = parseFloat(headers[h]);
      return Number.isFinite(v) ? v : null;
    };
    const key = historyKey(token, fingerprint);
    utilizationHistory.record(key, util('anthropic-ratelimit-unified-5h-utilization'), util('anthropic-ratelimit-unified-7d-utilization'));
    persistAccountState(token, fingerprint);
    saveHistoryToDisk();
  }
}

/** Usage history is kept per account email (stable across token refreshes and re-logins). */
function historyKey(token, fingerprint) {
  const acct = loadAllAccountTokens().find(a => a.token === token);
  return acct ? acct.id : fingerprint;
}

function markAccountLimited(token, name, retryAfterSec = 0) {
  accountState.markLimited(token, name, retryAfterSec);
}

// A 429 that says the account (or this model's bucket) is used up until a reset.
function markAccountRejected(token, name, headers) {
  const r = accountState.markRejected(token, name, headers);
  persistAccountState(token, getFingerprintFromToken(token));
  return r;
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
        let label = '', email = '';
        try { label = readFileSync(join(ACCOUNTS_DIR, `${name}.label`), 'utf8').trim(); } catch {}
        try { email = readFileSync(join(ACCOUNTS_DIR, `${name}.email`), 'utf8').trim(); } catch {}
        const expiresAt = creds.claudeAiOauth?.expiresAt || 0;
        accounts.push({ name, label, email, id: accountId({ name, label, email }), token, creds, expiresAt });
      } catch { /* skip corrupt */ }
    }
    _accountsCache = accounts;
    _accountsCacheAt = now;
    return accounts;
  } catch {
    return _accountsCache || [];
  }
}

/**
 * The key for data that spans days (usage, charts, saved sessions): the account's email, so
 * a re-login, a re-added account or a new token keeps adding to the same history. Before the
 * email is known: an email-looking label, else the account file name.
 */
function accountId({ name, label, email }) {
  if (email) return email;
  if (label && label.includes('@')) return label;
  return name;
}

/** Remember an account's email in <name>.email (never edited by `vdm label`). */
function rememberAccountEmail(name, email) {
  if (!name || !email || !email.includes('@')) return;
  const file = join(ACCOUNTS_DIR, `${name}.email`);
  try { if (readFileSync(file, 'utf8').trim() === email) return; } catch { /* new */ }
  try {
    writeFileSync(file, email);
    invalidateAccountsCache();
  } catch (e) { log('warn', `Could not save the email of "${name}": ${e.message}`); }
}

/** Old usage rows may carry a label or file name: map them to the account's current id. */
function accountAliases() {
  const m = new Map();
  for (const a of loadAllAccountTokens()) {
    if (a.label) m.set(a.label, a.id);
    m.set(a.name, a.id);
  }
  return m;
}

function invalidateAccountsCache() {
  _accountsCache = null;
  _accountsCacheAt = 0;
}

// Seed live state from disk so used-up / rejected accounts stay skipped across restarts.
(function seedAccountState() {
  for (const a of loadAllAccountTokens()) {
    const ps = persistedState[getFingerprintFromToken(a.token)];
    if (ps) accountState.restore(a.token, a.label || a.name, ps);
  }
})();

// Older versions keyed usage history by token fingerprint (or account file name), so a token
// refresh or re-login started an empty chart. Move them to the account email; the rest age out.
(function migrateHistoryKeys() {
  for (const a of loadAllAccountTokens()) {
    for (const old of [getFingerprintFromToken(a.token), a.name, a.label]) {
      if (old && old !== a.id) {
        utilizationHistory.rename(old, a.id);
        throughput.rename(old, a.id);
      }
    }
  }
  utilizationHistory.prune();
  writeHistoryFile();
  _throughputDirty = true;
})();

// ── Account picker ──

function isAccountAvailable(token, expiresAt, model = null) {
  return _isAccountAvailable(token, expiresAt, accountState, Date.now(), model);
}

function scoreAccount(token) {
  return _scoreAccount(token, accountState);
}

function pickBestAccount(excludeTokens = new Set(), model = null) {
  return _pickBestAccount(loadAllAccountTokens(), accountState, excludeTokens, model);
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
    const req = apiRequest({ path, method, headers, timeout }, resolve);
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
  // Migrate in-memory account state (all of it: limits, per-model blocks, cooldowns)
  accountState.transfer(oldToken, newToken);

  // Usage history is keyed by account name: an entry under the old fingerprint (a token
  // seen before the account was saved) joins the account's history
  const acct = loadAllAccountTokens().find(a => a.name === name);
  if (acct) utilizationHistory.rename(oldFp, acct.id);

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
  return {
    inflight: _inflightCount,
    queued: _requestQueue.length,
    balanceMode: isBalanceMode(),
    balanceInflight: balanceLimiter.total(),
    balanceWaiting: balanceLimiter.waitingCount(),
  };
}

function drainSerializationQueue() {
  while (_requestQueue.length > 0) {
    const next = _requestQueue.shift();
    next.resolve();
  }
}

function withSerializationQueue(fn, isRetry = false) {
  // Balance mode gates per-account (inside handleProxyRequest), never globally → run immediately.
  // If serialization disabled, retries, or nothing inflight → run immediately
  if (isBalanceMode() || !settings.serializeRequests || isRetry || _inflightCount === 0) {
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
// Per-account concurrency load-balancing (`balance` mode)
// ─────────────────────────────────────────────────

const BALANCE_MIN_COOLDOWN_SEC = 3;              // floor for transient-429 cooldown in balance mode
const balanceLimiter = createBalanceLimiter();   // in-flight tracker + wait/overflow queue
const _balanceCooldown = new Map();              // accountName -> cooldownUntil (ms); transient-429 backoff

function isBalanceMode() {
  return settings.rotationStrategy === 'balance';
}

// Briefly sideline an account after a transient 429 WITHOUT polluting the global
// rate-limit (`limited`) state — purely a load-balancing backoff. Keyed by name.
function balanceCoolDown(name, seconds) {
  if (name) _balanceCooldown.set(name, Date.now() + seconds * 1000);
}

// Tokens of accounts currently in balance cooldown (so pickLeastLoaded skips them).
// Prunes ALL expired entries first — including those for accounts that have since
// been removed — so the map can't grow unbounded under account churn.
function _balanceCooledTokens(allAccounts, now = Date.now()) {
  if (_balanceCooldown.size === 0) return null;
  for (const [name, until] of _balanceCooldown) {
    if (until <= now) _balanceCooldown.delete(name);
  }
  if (_balanceCooldown.size === 0) return null;
  const cooled = new Set();
  for (const a of allAccounts) {
    if (_balanceCooldown.has(a.name)) cooled.add(a.token);
  }
  return cooled.size ? cooled : null;
}

/**
 * Acquire a per-account concurrency slot for balance mode.
 *
 * Picks the least-loaded available account (in-flight requests plus warm session lanes
 * pinned there, skipping accounts whose windows for this model are used up); if it's
 * under the cap, acquires and returns immediately. If every available account is at the
 * cap, waits up to `balanceWaitMs` for a freed slot, then OVERFLOWS onto the least-loaded
 * account rather than ever dropping the request. Returns the chosen account with the slot
 * already acquired, or null when no account is available at all (genuine exhaustion).
 *
 * opts.only: a session lane's pinned account  - wait for a slot on that account (then
 *   overflow onto it) instead of moving the lane and losing its prompt cache. Returns
 *   null when that account can't take the request.
 * opts.prefer: the session's home account for a new lane (subagent next to its parent).
 *
 * The wait/overflow/wakeup mechanics live in `balanceLimiter` (createBalanceLimiter,
 * unit-tested in lib.mjs). Here we only supply the live candidate picker.
 */
async function acquireBalanceSlot(allAccounts, excludeTokens = new Set(), { model = null, prefer = null, only = null } = {}) {
  const cap = settings.maxConcurrentPerAccount || 8;
  const waitMs = settings.balanceWaitMs ?? 10_000;
  // Merge in accounts that are in transient-429 cooldown so they're skipped too.
  const withCooldown = () => {
    const cooled = _balanceCooledTokens(allAccounts);
    if (!cooled) return excludeTokens;
    const merged = new Set(excludeTokens);
    for (const t of cooled) merged.add(t);
    return merged;
  };
  const usable = (a) => !withCooldown().has(a.token) && isAccountAvailable(a.token, a.expiresAt, model);
  if (only) {
    // A pinned lane ignores burst cooldowns: moving it would rebuild its cache, and a
    // burst 429 on its own request is waited out on the same account instead.
    const pinnedUsable = () => !excludeTokens.has(only.token) && isAccountAvailable(only.token, only.expiresAt, model);
    if (!pinnedUsable()) return null;
    const result = await balanceLimiter.acquire(
      () => (pinnedUsable() ? { key: only.name, inflight: balanceLimiter.get(only.name), account: only } : null),
      { cap, waitMs },
    );
    if (!result) return null;
    if (result.overflow) log('balance', `${only.label || only.name} over cap (${cap})  - kept for session affinity`);
    return { account: result.account, overflow: result.overflow };
  }
  // Single account: capping/waiting can't spread load anywhere, so never block —
  // acquire immediately (best effort) if it's available, else report exhausted.
  if (allAccounts.length <= 1) {
    const only1 = allAccounts.find(usable);
    if (!only1) return null;
    balanceLimiter.inflight.acquire(only1.name);
    return { account: only1, overflow: false };
  }
  const extraLoad = settings.sessionAffinity !== false ? sessionStore.warmLoad() : null;
  const result = await balanceLimiter.acquire(() => {
    const pick = _pickLeastLoaded(allAccounts, balanceLimiter.inflight, accountState, cap, withCooldown(), Date.now(), { model, extraLoad, prefer });
    return pick ? { key: pick.account.name, inflight: pick.inflight, account: pick.account } : null;
  }, { cap, waitMs });
  if (!result) return null;                        // no available account → caller runs exhausted path
  if (result.overflow) {
    const nm = result.account.label || result.account.name;
    logEvent('balance-overflow', { account: nm, cap });
    log('balance', `all accounts at cap (${cap}) — overflow onto ${nm}`);
  }
  return { account: result.account, overflow: result.overflow };
}

// ─────────────────────────────────────────────────
// Token usage tap (passes bytes through, reads `usage`)
// ─────────────────────────────────────────────────

const USAGE_JSON_MAX = 4 * 1024 * 1024; // don't buffer huge non-streamed bodies

function createUsageTap(kind) {
  const decoder = new StringDecoder('utf8');
  const sse = kind === 'sse' ? createSSEUsageParser() : null;
  let jsonBuf = '';
  let jsonTooBig = false;
  const tap = new Transform({
    transform(chunk, encoding, callback) {
      this.push(chunk);
      try {
        const text = decoder.write(chunk);
        if (sse) sse.feed(text);
        else if (!jsonTooBig) {
          jsonBuf += text;
          if (jsonBuf.length > USAGE_JSON_MAX) { jsonTooBig = true; jsonBuf = ''; }
        }
      } catch { /* never break the stream over accounting */ }
      callback();
    },
  });
  tap.result = () => {
    if (sse) return sse.result();
    if (jsonTooBig) return null;
    return parseJsonUsage(jsonBuf + decoder.end());
  };
  return tap;
}

// ─────────────────────────────────────────────────
// Session affinity runtime
// ─────────────────────────────────────────────────

const sessionStore = createSessionStore();
try {
  if (existsSync(SESSIONS_FILE)) sessionStore.load(JSON.parse(readFileSync(SESSIONS_FILE, 'utf8')));
} catch { /* corrupt file  - start fresh */ }

let _sessionsDirty = false;
function markSessionsDirty() { _sessionsDirty = true; }

function saveSessions(force = false) {
  if (!_sessionsDirty && !force) return;
  _sessionsDirty = false;
  sessionStore.prune();
  try {
    writeFileSync(SESSIONS_FILE + '.tmp', JSON.stringify(sessionStore.toJSON()));
    renameSync(SESSIONS_FILE + '.tmp', SESSIONS_FILE);
  } catch (e) { log('error', `Failed to save sessions.json: ${e.message}`); }
}
setInterval(saveSessions, 30_000);

function accountByName(name) {
  return loadAllAccountTokens().find(a => a.name === name) || null;
}

function accountDisplay(name) {
  const a = accountByName(name);
  return (a && (a.label || a.name)) || name;
}

// Log a lane move. Warm moves rebuild the lane's prompt cache, so they also go
// to the activity log.
function noteMove(sid, move) {
  if (!move) return;
  markSessionsDirty();
  const label = sessionLabel(sessionStore.get(sid)?.meta, sid);
  const lane = move.agent === 'main' ? '' : ` [${String(move.agent).slice(0, 8)}]`;
  log('affinity', `${label}${lane}: ${accountDisplay(move.from)} → ${accountDisplay(move.to)} (${move.reason}${move.warm ? ', cache lost' : ', cache cold'})`);
  if (move.warm) {
    logActivity('session-moved', { session: label, from: accountDisplay(move.from), to: accountDisplay(move.to), reason: move.reason });
  }
}

// ── Session names: Claude Code's live registry + transcript ──

let _registry = new Map();   // sessionId → { name, nameSource, cwd, status }
let _registryOk = false;      // the registry folder could be read (empty then means: nothing running)

function processAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

// ~/.claude/sessions/<pid>.json: Claude Code's list of running sessions (name, cwd, status).
// Refreshed in the background; readers get the last snapshot.
async function refreshSessionRegistry() {
  const map = new Map();
  const dir = join(CLAUDE_DIR, 'sessions');
  let files = [];
  let ok = true;
  try { files = (await readdir(dir)).filter(f => f.endsWith('.json')); } catch { ok = false; }
  for (const f of files) {
    try {
      const j = JSON.parse(await readFile(join(dir, f), 'utf8'));
      const pid = Number(j?.pid) || parseInt(f, 10);
      if (pid > 0 && !processAlive(pid)) continue; // left behind by a session that crashed
      if (j && j.sessionId) map.set(j.sessionId, { name: j.name, nameSource: j.nameSource, cwd: j.cwd, status: j.status });
    } catch { /* being rewritten  - skip */ }
  }
  _registry = map;
  _registryOk = ok;
}
refreshSessionRegistry().catch(() => {});
setInterval(() => refreshSessionRegistry().catch(() => {}), 15_000);

function readSessionRegistry() {
  return _registry;
}

const _transcriptPaths = new Map(); // sessionId → transcript path, or { missAt } when not found
const TRANSCRIPT_TAIL_BYTES = 256 * 1024;
const TRANSCRIPT_MISS_RETRY_MS = 10 * 60 * 1000;

async function findTranscript(sessionId) {
  const hit = _transcriptPaths.get(sessionId);
  if (typeof hit === 'string') return hit;
  if (hit && Date.now() - hit.missAt < TRANSCRIPT_MISS_RETRY_MS) return null; // e.g. claude -p without a transcript
  const root = join(CLAUDE_DIR, 'projects');
  let dirs = [];
  try { dirs = await readdir(root); } catch { /* no projects dir */ }
  for (const d of dirs) {
    const p = join(root, d, `${sessionId}.jsonl`);
    try { await access(p); _transcriptPaths.set(sessionId, p); return p; } catch { /* not here */ }
  }
  _transcriptPaths.set(sessionId, { missAt: Date.now() });
  return null;
}

// ~/.claude/projects/<dir>/<sessionId>.jsonl: read the tail for branch, cwd and titles.
async function readTranscriptMeta(sessionId) {
  const file = await findTranscript(sessionId);
  if (!file) return null;
  let text = '';
  let fh;
  try {
    fh = await open(file, 'r');
    const { size } = await fh.stat();
    const start = Math.max(0, size - TRANSCRIPT_TAIL_BYTES);
    const buf = Buffer.alloc(size - start);
    await fh.read(buf, 0, buf.length, start);
    text = buf.toString('utf8');
    if (start > 0) text = text.slice(text.indexOf('\n') + 1); // drop the partial first line
  } catch { return null; } finally { if (fh) await fh.close().catch(() => {}); }
  const meta = {};
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line) continue;
    if (!meta.customTitle && line.includes('"custom-title"')) {
      try { meta.customTitle = JSON.parse(line).customTitle; } catch {}
    } else if (!meta.autoTitle && line.includes('"ai-title"')) {
      try { meta.autoTitle = JSON.parse(line).aiTitle; } catch {}
    } else if ((!meta.branch || !meta.cwd) && line.includes('"gitBranch"')) {
      try {
        const j = JSON.parse(line);
        if (!meta.branch && j.gitBranch) meta.branch = j.gitBranch;
        if (!meta.cwd && j.cwd) meta.cwd = j.cwd;
      } catch {}
    }
    if (meta.customTitle && meta.autoTitle && meta.branch && meta.cwd) break;
  }
  return meta;
}

function gitAsync(cwd, args) {
  return new Promise((resolve) => {
    execFile('git', ['-C', cwd, ...args], { timeout: 3000, encoding: 'utf8' }, (err, out) => resolve(err ? null : String(out).trim()));
  });
}

const _repoRootCache = new Map(); // cwd → main repo root (worktrees resolve to their parent repo)

async function resolveRepoRoot(cwd) {
  if (_repoRootCache.has(cwd)) return _repoRootCache.get(cwd);
  let root = await gitAsync(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']);
  root = root ? root.replace(/\/\.git\/?$/, '') : (await gitAsync(cwd, ['rev-parse', '--show-toplevel'])) || '';
  _repoRootCache.set(cwd, root);
  return root;
}

/**
 * In a Claude Code worktree the checked-out branch is an auto-generated name like
 * `worktree-jolly-dazzling-dolphin`. Resolve it back to the real feature branch.
 */
async function resolveWorktreeBranch(cwd, branch) {
  if (!branch || !branch.startsWith('worktree-')) return branch;
  const pointsAt = await gitAsync(cwd, ['branch', '--points-at', 'HEAD']);
  const candidates = (pointsAt || '').split('\n').map(b => b.replace(/^[*+]?\s+/, '').trim()).filter(b => b && !b.startsWith('worktree-'));
  if (candidates.length) return candidates.find(b => b.includes('/')) || candidates[0];
  const decorated = await gitAsync(cwd, ['log', '--format=%D', '--max-count=30']);
  for (const line of (decorated || '').split('\n')) {
    const refs = line.split(',').map(r => r.trim())
      .filter(r => r && !r.startsWith('HEAD') && !r.startsWith('worktree-') && !r.startsWith('origin/') && !r.startsWith('tag:'));
    if (refs.length) return refs.find(r => r.includes('/')) || refs[0];
  }
  return branch;
}

const _metaRefreshedAt = new Map(); // sessionId → last refresh (ms)
const SESSION_META_REFRESH_MS = 60_000;

// Refresh a session's display info (name, cwd, repo, branch). Off the hot path and
// throttled to once a minute per session.
async function refreshSessionMeta(sid, body) {
  const now = Date.now();
  if (now - (_metaRefreshedAt.get(sid) || 0) < SESSION_META_REFRESH_MS) return;
  _metaRefreshedAt.set(sid, now);
  if (_metaRefreshedAt.size > 2000) {
    for (const [k, t] of _metaRefreshedAt) if (now - t > SESSION_META_REFRESH_MS) _metaRefreshedAt.delete(k);
  }
  const reg = readSessionRegistry().get(sid);
  const tr = (await readTranscriptMeta(sid)) || {};
  let cwd = reg?.cwd || tr.cwd || '';
  let branch = tr.branch || '';
  if ((!cwd || !branch) && body) {
    // Claude Code puts the working directory and git branch in the system prompt
    const head = body.subarray(0, Math.min(body.length, 256 * 1024)).toString('utf8');
    if (!cwd) cwd = (head.match(/working directory:\s*([^\n\\"]+)/i) || [])[1]?.trim() || '';
    if (!branch) branch = (head.match(/Current branch:\s*([^\n\\"]+)/) || [])[1]?.trim() || '';
  }
  let repo = '';
  if (cwd && await access(cwd).then(() => true, () => false)) {
    repo = await resolveRepoRoot(cwd);
    if (branch.startsWith('worktree-')) branch = await resolveWorktreeBranch(cwd, branch);
  }
  const meta = { cwd, branch, repo, live: !!reg, status: reg?.status || null };
  if (reg) { meta.name = reg.name || null; meta.nameSource = reg.nameSource || null; }
  if (tr.customTitle) meta.customTitle = tr.customTitle;
  if (tr.autoTitle) meta.autoTitle = tr.autoTitle;
  sessionStore.setMeta(sid, meta);
  markSessionsDirty();
}

// Live flag drifts once a session ends: re-check against the registry when listing.
function isSessionLive(sid) {
  return readSessionRegistry().has(sid);
}

// Compact per-session view for one account's card.
function accountSessions(name, now = Date.now()) {
  const dayAgo = now - 24 * 60 * 60 * 1000;
  const out = [];
  for (const s of sessionStore.all()) {
    const here = s.accounts[name];
    const lanesHere = Object.values(s.lanes).filter(l => l.account === name);
    const warmHere = lanesHere.some(l => now - l.lastAt < l.ttlMs);
    if (!warmHere && (!here || here.lastAt < dayAgo)) continue;
    const aff = sessionAffinity(s, now);
    out.push({
      id: s.id,
      label: sessionLabel(s.meta, s.id),
      title: s.meta.autoTitle || s.meta.name || '',
      repo: s.meta.repo ? basename(s.meta.repo) : '',
      branch: s.meta.branch || '',
      live: isSessionLive(s.id),
      pinnedHere: warmHere,
      requests: here?.requests || 0,
      lastAt: here?.lastAt || s.lastAt,
      affinity: aff.level,
      cacheHit: aff.cacheHit,
      warmMoves1h: aff.warmMoves1h,
      share: aff.share,
    });
  }
  out.sort((a, b) => (b.pinnedHere - a.pinnedHere) || (b.lastAt - a.lastAt));
  return out;
}

// Full session list for the Sessions tab.
function listSessions(hours = 24, now = Date.now()) {
  const since = now - hours * 60 * 60 * 1000;
  return sessionStore.all()
    .filter(s => s.lastAt >= since)
    .sort((a, b) => b.lastAt - a.lastAt)
    .map(s => {
      const aff = sessionAffinity(s, now);
      const accounts = Object.entries(s.accounts)
        .map(([name, a]) => ({ name, label: accountDisplay(name), ...a }))
        .sort((x, y) => y.requests - x.requests);
      // warm = used within its cache TTL (also right after a manual switch released the pin)
      const lanes = Object.entries(s.lanes)
        .filter(([, l]) => l.account || l.prevAccount)
        .map(([agent, l]) => {
          const account = l.account || l.prevAccount;
          return { agent, account, pinned: !!l.account, label: accountDisplay(account), warm: now - l.lastAt < l.ttlMs, lastAt: l.lastAt, ttlMs: l.ttlMs };
        });
      return {
        id: s.id,
        label: sessionLabel(s.meta, s.id),
        meta: { ...s.meta, repoName: s.meta.repo ? basename(s.meta.repo) : '' },
        live: isSessionLive(s.id),
        model: s.model,
        firstAt: s.firstAt,
        lastAt: s.lastAt,
        requests: s.requests,
        home: sessionStore.home(s.id),
        homeLabel: accountDisplay(sessionStore.home(s.id) || ''),
        affinity: aff,
        accounts,
        lanes,
        moves: s.moves.slice(-10).reverse().map(m => ({ ...m, fromLabel: accountDisplay(m.from), toLabel: accountDisplay(m.to) })),
        artifacts: s.artifacts,
        cache: sessionCacheView(s.id, now),
      };
    });
}

// ─────────────────────────────────────────────────
// Usage store: hourly rollups, one JSON file per UTC day in usage/
// ─────────────────────────────────────────────────

const _usageDays = new Map(); // 'YYYY-MM-DD' → { data, dirty, touchedAt }

function usageDayFile(day) { return join(USAGE_DIR, `${day}.json`); }

function usageDay(day) {
  let d = _usageDays.get(day);
  if (!d) {
    let file = {};
    try { file = JSON.parse(readFileSync(usageDayFile(day), 'utf8')) || {}; } catch { /* new day */ }
    d = { data: createUsageDay(file.rows || []), dirty: false, touchedAt: Date.now(), legacyImported: !!file.legacyImported };
    _usageDays.set(day, d);
  }
  d.touchedAt = Date.now();
  return d;
}

function recordUsage(rec) {
  const d = usageDay(utcDay(rec.ts));
  d.data.add(rec);
  d.dirty = true;
}

function flushUsage() {
  const today = utcDay(Date.now());
  for (const [day, d] of _usageDays) {
    if (d.dirty) {
      try {
        mkdirSync(USAGE_DIR, { recursive: true });
        const out = { v: 1, day, rows: d.data.rows() };
        if (d.legacyImported) out.legacyImported = true;
        writeFileSync(usageDayFile(day) + '.tmp', JSON.stringify(out));
        renameSync(usageDayFile(day) + '.tmp', usageDayFile(day));
        d.dirty = false;
      } catch (e) { log('error', `Failed to write usage/${day}.json: ${e.message}`); }
    }
    // Keep today hot; drop other days from memory once idle
    if (!d.dirty && day !== today && Date.now() - d.touchedAt > 10 * 60 * 1000) _usageDays.delete(day);
  }
}
setInterval(flushUsage, 30_000);

function loadUsageRows(since, until = Date.now()) {
  const alias = accountAliases();
  const rows = [];
  const first = utcDay(since), last = utcDay(until);
  const days = new Set(_usageDays.keys());
  try { for (const f of readdirSync(USAGE_DIR)) if (/^\d{4}-\d{2}-\d{2}\.json$/.test(f)) days.add(f.slice(0, 10)); } catch {}
  for (const day of [...days].sort()) {
    if (day < first || day > last) continue;
    for (const r of usageDay(day).data.rows()) rows.push(r);
  }
  // Rows saved under a label or file name count for the account email
  return rows.map(r => (alias.has(r.account) && alias.get(r.account) !== r.account ? { ...r, account: alias.get(r.account) } : r));
}

// One-time import of the pre-v4 per-request log (token-usage.json) into rollups.
// Repeat-safe: each day file is marked as holding the imported rows in the same atomic
// write, so a crash before the final rename never imports a day twice.
(function importLegacyTokenUsage() {
  if (!existsSync(LEGACY_TOKEN_USAGE_FILE)) return;
  try {
    const entries = JSON.parse(readFileSync(LEGACY_TOKEN_USAGE_FILE, 'utf8'));
    let n = 0;
    const skip = new Set();
    for (const e of Array.isArray(entries) ? entries : []) {
      if (!e || !e.ts) continue;
      const day = utcDay(e.ts);
      if (skip.has(day)) continue;
      const d = usageDay(day);
      if (d.legacyImported && !d.importing) { skip.add(day); continue; }
      d.legacyImported = true;
      d.importing = true;
      d.data.add({
        ts: e.ts, account: e.account, model: e.model, repo: e.repo || '', branch: e.branch || '',
        usage: { input: e.inputTokens || 0, output: e.outputTokens || 0 },
      });
      d.dirty = true;
      n++;
    }
    for (const d of _usageDays.values()) delete d.importing;
    flushUsage();
    renameSync(LEGACY_TOKEN_USAGE_FILE, LEGACY_TOKEN_USAGE_FILE.replace(/\.json$/, '.imported.json'));
    console.log(`[usage] Imported ${n} legacy token-usage entries into usage/`);
  } catch (e) {
    console.log(`[usage] Legacy token-usage import failed: ${e.message}`);
  }
})();

// Book one proxied request: per-session stats and the usage rollup.

// Hourly token totals per account from the usage rollups: the 7-day chart, and the part of the
// 24-hour chart from before the 5-minute store existed. Memoized: /api/profiles asks every 5 s.
let _rollupThroughput = { at: 0, data: null };
function rollupThroughput() {
  const now = Date.now();
  if (_rollupThroughput.data && now - _rollupThroughput.at < 60_000) return _rollupThroughput.data;
  const rows = loadUsageRows(now - 7 * 86400000 - 3600000, now);
  _rollupThroughput = { at: now, data: throughputFromRollups(rows, { since: now - 7 * 86400000 - 3600000 }) };
  return _rollupThroughput.data;
}

/** Line-chart data for one account card: total tokens per 5 minutes over 24 h and 7 days. */
function accountThroughput(p, now = Date.now()) {
  const tp = rollupThroughput();
  const hourly = tp[p.id] || [];
  return {
    day: throughputLine({ fine: throughput.series(p.id, now - 86400000, now), hourly, startedAt: throughput.startedAt, now, windowMs: 86400000, step: THROUGHPUT_BUCKET_MS }),
    week: throughputLine({ hourly, now, windowMs: 7 * 86400000, step: 3600000 }),
  };
}

function recordProxyUsage({ sid, agent, acct, model, usage, ttlMs }) {
  if (!usage) return;
  throughput.add(acct?.id || acct?.name || 'unknown', model, totalTokens(usage));
  _throughputDirty = true;
  const cost = usageCost(usage, model);
  let repo = '', branch = '';
  if (sid) {
    sessionStore.recordRequest(sid, agent, acct?.name || 'unknown', { ...usage, cost }, { model, ttlMs });
    const meta = sessionStore.get(sid)?.meta || {};
    repo = meta.repo || '';
    branch = meta.branch || '';
    markSessionsDirty();
  }
  recordUsage({ ts: Date.now(), account: acct?.id || acct?.label || acct?.name || 'unknown', model, repo, branch, usage });
}

// Rolling 30-day prompt-cache efficiency (per account / per model, daily trend).
// Memoized for a minute: /api/profiles asks for it every 5 seconds.
let _cache30d = { at: 0, data: null };
function cacheReport30d() {
  const now = Date.now();
  if (_cache30d.data && now - _cache30d.at < 60_000) return _cache30d.data;
  const since = Math.floor((now - 29 * 86400000) / 86400000) * 86400000; // 30 UTC days incl. today
  _cache30d = { at: now, data: cacheEfficiency(loadUsageRows(since, now), { since, until: now }) };
  return _cache30d.data;
}

// Usage tab report: current period vs previous period, plus plan value per account.
function usageReport(params) {
  const days = Math.min(Math.max(parseInt(params.get('days') || '7', 10) || 7, 1), 400);
  const filter = {};
  for (const k of ['repo', 'branch', 'model', 'account']) if (params.get(k)) filter[k] = params.get(k);
  const now = Date.now();
  const since = now - days * 86400000;
  const rows = loadUsageRows(since - days * 86400000, now);
  const bucketMs = days <= 2 ? 3600000 : 86400000;
  const cur = summarizeUsage(rows, { since, filter, bucketMs });
  const prev = summarizeUsage(rows, { since: since - days * 86400000, until: since, filter }).totals;

  // Plan value: each Max account's prorated subscription vs the API price of what it used.
  const MONTH_DAYS = 30.4375;
  const plans = loadAllAccountTokens().map(a => {
    const o = a.creds?.claudeAiOauth || {};
    const monthly = planMonthlyUsd(o.subscriptionType, o.rateLimitTier);
    const used = cur.byAccount[a.id];
    return {
      name: a.name, key: a.id, label: a.label || a.id, monthly,
      tier: (String(o.rateLimitTier || '').match(/(\d+)x/) || [])[1] ? `Max ${String(o.rateLimitTier).match(/(\d+)x/)[1]}x` : (o.subscriptionType || 'unknown'),
      planCost: monthly ? monthly * days / MONTH_DAYS : null,
      apiCost: used?.cost || 0,
      requests: used?.requests || 0,
    };
  }).filter(p => !filter.account || p.key === filter.account);
  const planDaily = plans.reduce((sum, p) => sum + (p.monthly ? p.monthly / MONTH_DAYS : 0), 0);
  // A plan covers all of an account's usage: comparing it to one repo/branch/model is meaningless
  const planComparable = !filter.repo && !filter.branch && !filter.model;

  return { days, since, bucketMs, filter, ...cur, prevTotals: prev, plans, planDaily, planComparable, cache30d: cacheReport30d() };
}

// ─────────────────────────────────────────────────
// Artifact tracker: which account owns which claude.ai artifact
// ─────────────────────────────────────────────────
//
// Claude Code publishes artifacts straight to the API with its own login (the
// account in the keychain), not through this proxy  - so the owner can differ from
// the account a session's messages were routed to. The tracker asks each account
// for the artifacts it owns (the same listing `/artifacts` in Claude Code uses).

const ARTIFACT_POLL_MS = 15 * 60 * 1000;
let artifactIndex = { updatedAt: 0, accounts: {}, links: {} };
try {
  if (existsSync(ARTIFACTS_FILE)) {
    const raw = JSON.parse(readFileSync(ARTIFACTS_FILE, 'utf8'));
    artifactIndex = { updatedAt: raw.updatedAt || 0, accounts: raw.accounts || {}, links: raw.links || {} };
  }
} catch { /* corrupt file  - start fresh */ }
let _artifactsRefreshing = null;
let _artifactLinksDirty = false;

function saveArtifacts() {
  try {
    writeFileSync(ARTIFACTS_FILE + '.tmp', JSON.stringify(artifactIndex));
    renameSync(ARTIFACTS_FILE + '.tmp', ARTIFACTS_FILE);
  } catch (e) { log('error', `Failed to save artifacts.json: ${e.message}`); }
}

function fetchArtifactFrames(token) {
  return new Promise((resolve) => {
    const req = apiRequest({
      path: '/api/frame/frames?limit=200',
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'anthropic-beta': 'oauth-2025-04-20',
        'User-Agent': `claude-code/${CLAUDE_CODE_VERSION} (external, cli)`,
        'Accept': 'application/json',
        'X-Frame-CP': 'go',
        'X-Frame-Surface': 'code',
        'X-Frame-Platform': 'cli',
        'X-Frame-Client-Version': CLAUDE_CODE_VERSION,
      },
      timeout: 15000,
    }, (res) => {
      let data = '';
      res.on('data', c => { if (data.length < 8 * 1024 * 1024) data += c; });
      res.on('end', () => {
        if (res.statusCode !== 200) return resolve({ ok: false, error: `HTTP ${res.statusCode}` });
        try {
          const j = JSON.parse(data);
          resolve({ ok: true, frames: Array.isArray(j.frames) ? j.frames : [] });
        } catch { resolve({ ok: false, error: 'unexpected response' }); }
      });
    });
    req.on('error', (e) => resolve({ ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false, error: 'timeout' }); });
    req.end();
  });
}

async function refreshArtifacts(reason = 'poll') {
  if (_artifactsRefreshing) return _artifactsRefreshing;
  _artifactsRefreshing = (async () => {
    const accounts = loadAllAccountTokens();
    const names = new Set(accounts.map(a => a.name));
    for (const name of Object.keys(artifactIndex.accounts)) if (!names.has(name)) delete artifactIndex.accounts[name];
    for (const a of accounts) {
      const prev = artifactIndex.accounts[a.name];
      if (a.expiresAt && a.expiresAt < Date.now()) {
        artifactIndex.accounts[a.name] = { ...(prev || { frames: [] }), label: a.label || a.name, error: 'token expired' };
        continue;
      }
      const r = await fetchArtifactFrames(a.token);
      if (!r.ok) {
        artifactIndex.accounts[a.name] = { ...(prev || { frames: [] }), label: a.label || a.name, error: r.error };
        continue;
      }
      const frames = r.frames
        .filter(f => f && f.slug && f.rel !== 'shared' && !f.softDeleted)
        .map(f => ({
          slug: f.slug, title: f.title || '', description: f.description || '',
          createdAt: f.created_at || null, updatedAt: f.updatedAt || null,
          audience: f.audience || null, ownerEmail: f.owner_email || null,
        }));
      artifactIndex.accounts[a.name] = { label: a.label || a.name, fetchedAt: Date.now(), error: null, frames, shared: r.frames.filter(f => f?.rel === 'shared').length };
    }
    artifactIndex.updatedAt = Date.now();
    saveArtifacts();
    log('artifacts', `Artifact index refreshed (${reason}): ${Object.values(artifactIndex.accounts).reduce((n, a) => n + (a.frames || []).length, 0)} artifacts across ${accounts.length} accounts`);
  })().finally(() => { _artifactsRefreshing = null; });
  return _artifactsRefreshing;
}

setTimeout(() => refreshArtifacts('startup').catch(() => {}), 20_000);
setInterval(() => refreshArtifacts('poll').catch(() => {}), ARTIFACT_POLL_MS);

// A session's messages mention an artifact link (e.g. the Artifact tool's result):
// remember which session it came from.
function noteArtifactRefs(sid, refs, routedAccount) {
  for (const ref of refs) {
    if (!sessionStore.addArtifact(sid, ref)) continue;
    if (!artifactIndex.links[ref]) {
      artifactIndex.links[ref] = { sessionId: sid, seenAt: Date.now(), routedAccount: routedAccount || null };
      _artifactLinksDirty = true;
    }
    markSessionsDirty();
  }
}
setInterval(() => { if (_artifactLinksDirty) { _artifactLinksDirty = false; saveArtifacts(); } }, 30_000);

function artifactsView() {
  const linkFor = (slug) => {
    for (const [ref, link] of Object.entries(artifactIndex.links)) {
      if (artifactRefMatches(ref, slug)) return link;
    }
    return null;
  };
  const accounts = loadAllAccountTokens().map(a => {
    const entry = artifactIndex.accounts[a.name] || {};
    const frames = (entry.frames || []).map(f => {
      const link = linkFor(f.slug);
      const s = link ? sessionStore.get(link.sessionId) : null;
      return {
        ...f,
        url: `https://claude.ai/code/artifact/${f.slug}`,
        session: link ? { id: link.sessionId, label: s ? sessionLabel(s.meta, s.id) : String(link.sessionId).slice(0, 8) } : null,
      };
    }).sort((x, y) => String(y.createdAt || '').localeCompare(String(x.createdAt || '')));
    return { name: a.name, label: a.label || a.name, fetchedAt: entry.fetchedAt || 0, error: entry.error || null, shared: entry.shared || 0, frames };
  });
  return { updatedAt: artifactIndex.updatedAt, refreshing: !!_artifactsRefreshing, pollMinutes: ARTIFACT_POLL_MS / 60000, accounts };
}

// ─────────────────────────────────────────────────
// Pipe helper — waits for stream to complete
// ─────────────────────────────────────────────────

// stream.pipeline settles on completion and on an error anywhere. A client that is
// already gone makes pipeline throw synchronously: drop the upstream response instead.
function pipeAndWait(...streams) {
  return new Promise(resolve => {
    const dst = streams[streams.length - 1];
    const abandon = () => { for (const st of streams) st.destroy(); resolve(); };
    if (dst.destroyed || dst.writableEnded) return abandon();
    try { pipeline(...streams, () => resolve()); } catch { abandon(); }
  });
}


// ── Session history (child process: history.mjs) ──
// All archive work (links, digests, compression, search) runs in a separate low-priority
// process, so the proxy never waits on it and a crash there never takes the proxy down.
// It starts when history is on (or on demand to browse saved sessions) and restarts with
// backoff when it dies.

const HISTORY_MODULE = join(__dirname, 'history.mjs');
const ARCHIVE_DIR = process.env.CSW_HISTORY_DIR || join(__dirname, 'history');
const HISTORY_BROWSE_IDLE_MS = 10 * 60 * 1000; // history off: stop a child started only to browse
const HISTORY_ID_RE = /^[0-9a-f-]{4,36}$/;

const _hist = {
  child: null, ready: null, state: 'off', pending: new Map(), nextId: 1,
  restarts: 0, startedAt: 0, lastError: '', stopping: false, restartTimer: null, idleTimer: null,
};

function claudeCommand() {
  return cleanClaudeCommand(process.env.VDM_CLAUDE_CMD) || settings.claudeCommand || 'claude';
}

function historyConfig() {
  return {
    enabled: settings.sessionHistory === true,
    retentionDays: settings.historyRetentionDays || 0,
    exclude: settings.historyExclude || [],
    claudeCommand: claudeCommand(),
  };
}

function hasSavedHistory() {
  try { return readdirSync(join(ARCHIVE_DIR, 'sessions')).length > 0; } catch { return false; }
}

function pipeChildLines(stream, tag) {
  let buf = '';
  stream.setEncoding('utf8');
  stream.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) log(tag, line);
    }
    if (buf.length > 64 * 1024) buf = '';
  });
}

function startHistory() {
  if (_hist.child) return _hist.ready;
  if (!existsSync(HISTORY_MODULE)) {
    _hist.state = 'missing';
    return Promise.reject(new Error('history.mjs is missing: run `vdm upgrade`'));
  }
  clearTimeout(_hist.restartTimer);
  _hist.state = 'starting';
  _hist.startedAt = Date.now();
  let child;
  try {
    child = fork(HISTORY_MODULE, ['serve'], {
      execArgv: ['--max-old-space-size=512'],
      env: { ...process.env, NODE_NO_WARNINGS: '1', CSW_HISTORY_DIR: ARCHIVE_DIR },
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
  } catch (err) {
    _hist.state = 'error';
    _hist.lastError = err.message;
    return Promise.reject(err);
  }
  _hist.child = child;
  try { setPriority(child.pid, 10); } catch { /* not allowed */ }
  pipeChildLines(child.stdout, 'history');
  pipeChildLines(child.stderr, 'history');
  _hist.ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error('history process did not start'));
      try { child.kill('SIGKILL'); } catch { /* gone */ }
    }, 20000);
    child.on('message', (m) => {
      if (m && m.ready) { clearTimeout(timer); _hist.state = 'ready'; resolve(); return; }
      const p = m && _hist.pending.get(m.id);
      if (!p) return;
      _hist.pending.delete(m.id);
      clearTimeout(p.timer);
      if (m.ok) p.resolve(m.result);
      else p.reject(Object.assign(new Error(m.error || 'history error'), { code: m.code || null }));
    });
    child.once('exit', () => { clearTimeout(timer); reject(new Error('history process stopped')); });
  });
  _hist.ready.catch(() => {});
  child.on('error', (err) => log('error', `History process: ${err.message}`));
  child.on('exit', (code, signal) => {
    if (_hist.child === child) _hist.child = null;
    for (const p of _hist.pending.values()) { clearTimeout(p.timer); p.reject(new Error('history process stopped')); }
    _hist.pending.clear();
    if (_hist.stopping) {
      _hist.stopping = false;
      _hist.state = 'off';
      // History was turned on while this child was stopping: start a fresh one
      if (historyConfig().enabled) startHistory().catch(err => log('error', `History: ${err.message}`));
      return;
    }
    _hist.lastError = `stopped unexpectedly (${signal || `exit ${code}`})`;
    log('error', `History process ${_hist.lastError}`);
    if (!historyConfig().enabled) { _hist.state = 'off'; return; }
    if (Date.now() - _hist.startedAt > 10 * 60 * 1000) _hist.restarts = 0;
    const delay = Math.min(5 * 60 * 1000, 5000 * 2 ** _hist.restarts++);
    _hist.state = 'restarting';
    _hist.restartTimer = setTimeout(() => { startHistory().catch(() => {}); }, delay);
    _hist.restartTimer.unref?.();
  });
  return _hist.ready.then(() => historySend('config', historyConfig()));
}

function stopHistory() {
  clearTimeout(_hist.restartTimer);
  clearTimeout(_hist.idleTimer);
  const child = _hist.child;
  if (!child) { _hist.state = 'off'; return; }
  _hist.stopping = true;
  try { child.disconnect(); } catch { /* gone */ }
  setTimeout(() => { try { child.kill('SIGTERM'); } catch { /* gone */ } }, 3000).unref?.();
}

function historySend(op, args = {}, timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    const child = _hist.child;
    if (!child || !child.connected) { reject(new Error('history process is not running')); return; }
    const id = _hist.nextId++;
    const timer = setTimeout(() => { _hist.pending.delete(id); reject(new Error('history process did not answer in time')); }, timeoutMs);
    _hist.pending.set(id, { resolve, reject, timer });
    try { child.send({ id, op, args }); } catch (err) { clearTimeout(timer); _hist.pending.delete(id); reject(err); }
  });
}

/** Ask the history process (starting it if needed: with history off it stops again when idle). */
async function historyCall(op, args = {}, timeoutMs) {
  if (!_hist.child) await startHistory();
  else await _hist.ready;
  if (!historyConfig().enabled) {
    clearTimeout(_hist.idleTimer);
    _hist.idleTimer = setTimeout(stopHistory, HISTORY_BROWSE_IDLE_MS);
    _hist.idleTimer.unref?.();
  }
  return historySend(op, args, timeoutMs);
}

function applyHistorySettings() {
  const cfg = historyConfig();
  if (cfg.enabled) {
    clearTimeout(_hist.idleTimer);
    saveSessions(true); // the first scan reads which accounts each session used
    if (_hist.child) historySend('config', cfg).catch(() => {});
    else startHistory().catch(err => log('error', `History: ${err.message}`));
    log('history', 'Session history on');
  } else if (_hist.child) {
    historySend('config', cfg).catch(() => {});
    clearTimeout(_hist.idleTimer);
    _hist.idleTimer = setTimeout(stopHistory, HISTORY_BROWSE_IDLE_MS);
    _hist.idleTimer.unref?.();
    log('history', 'Session history off (saved sessions are kept)');
  }
}

let _serversListening = 0;
function onServerListening() {
  if (++_serversListening === 2 && historyConfig().enabled) {
    startHistory().catch(err => log('error', `History: ${err.message}`));
  }
}

function historyStatusCode(err) {
  if (err.code === 'NOT_FOUND') return 404;
  if (err.code === 'AMBIGUOUS') return 400;
  return 503;
}

async function handleHistoryAPI(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api', 'history', id?, action?]
  const q = url.searchParams;
  const base = () => ({
    enabled: historyConfig().enabled, state: _hist.state, error: _hist.lastError || null,
    module: existsSync(HISTORY_MODULE), claudeCommand: claudeCommand(),
  });
  try {
    if (parts.length === 3 && parts[2] === 'status' && req.method === 'GET') {
      if (!_hist.child && !historyConfig().enabled && !hasSavedHistory()) { json(res, { ...base(), sessions: 0 }); return true; }
      json(res, { ...base(), ...(await historyCall('status')) });
      return true;
    }
    if (parts.length === 3 && parts[2] === 'scan' && req.method === 'POST') {
      if (!historyConfig().enabled) { json(res, { ...base(), error: 'Session history is off' }, 409); return true; }
      saveSessions(true);
      json(res, { ...base(), ...(await historyCall('scan')) });
      return true;
    }
    if (parts.length === 2 && req.method === 'GET') {
      if (!_hist.child && !historyConfig().enabled && !hasSavedHistory()) {
        json(res, { ...base(), total: 0, count: 0, sessions: [], facets: { projects: [], branches: [], accounts: [] }, storage: { shared: 0, own: 0 } });
        return true;
      }
      const args = {
        q: (q.get('q') || '').slice(0, 500), project: q.get('project') || '', branch: q.get('branch') || '', account: q.get('account') || '',
        days: Number(q.get('days')) || 0, automated: q.get('automated') === '1',
        offset: Number(q.get('offset')) || 0, limit: Number(q.get('limit')) || 50,
      };
      json(res, { ...base(), ...(await historyCall('list', args)) });
      return true;
    }
    const id = parts[2];
    if (!id || !HISTORY_ID_RE.test(id)) { json(res, { error: 'Bad session id' }, 400); return true; }
    const action = parts[3] || '';
    if (parts.length > 4) return false;
    if (!action && req.method === 'GET') { json(res, await historyCall('get', { id })); return true; }
    if (action === 'messages' && req.method === 'GET') {
      const num = (k) => (q.has(k) && q.get(k) !== '' ? Number(q.get(k)) : null);
      json(res, await historyCall('messages', { id, from: num('from'), around: num('around'), limit: Number(q.get('limit')) || 200 }));
      return true;
    }
    if (action === 'handoff' && req.method === 'POST') { json(res, await historyCall('handoff', { id })); return true; }
    if (action === 'restore' && req.method === 'POST') {
      const r = await historyCall('restore', { id }, 120000);
      logActivity('history-restored', { session: id.slice(0, 8), restored: r.restored });
      json(res, r);
      return true;
    }
    if (action === 'delete' && req.method === 'POST') { json(res, await historyCall('remove', { id })); return true; }
    if (action === 'download' && req.method === 'GET') {
      const t = await historyCall('transcript', { id });
      const okPath = [ARCHIVE_DIR, join(CLAUDE_DIR, 'projects')].some(root => t.file.startsWith(root + '/'));
      if (!okPath) { json(res, { error: 'Refused' }, 403); return true; }
      res.writeHead(200, {
        'Content-Type': 'application/x-ndjson',
        'Content-Disposition': `attachment; filename="${t.id}.jsonl"`,
        'Cache-Control': 'no-store',
      });
      const streams = [createReadStream(t.file)];
      if (t.compressed) streams.push(zlib.createBrotliDecompress());
      await pipeAndWait(...streams, res);
      return true;
    }
    return false;
  } catch (err) {
    if (!res.headersSent) json(res, { ...base(), error: err.message }, historyStatusCode(err));
    else res.destroy();
    return true;
  }
}


// ─────────────────────────────────────────────────
// Cache care: explain every cache rebuild, keep idle caches warm
// ─────────────────────────────────────────────────
// Doctor: each rebuild of a big prompt gets a cause (idle, account move, tools changed, ...).
// Keep-warm (settings.keepWarm): an idle session's last request is replayed with max_tokens 0
// just before its cache expires, on the same account, for as long as the learned return curve
// says it pays (look-ahead optimal stopping, capped at the break-even). Request bodies are kept
// in memory only.

const CACHE_CARE_FILE = join(__dirname, 'cache-care.json');
const IDLE_LOG_MAX = 5000;
const KEEP_WARM_PINGS_PER_HOUR = 60;
const KEEP_WARM_NEAR_LIMIT = { fiveH: 0.85, sevenD: 0.95 };
// Tests only: a short cache lifetime and a fast tick, so keep-warm can be checked in seconds
const CACHE_TTL_OVERRIDE = Number(process.env.CSW_CACHE_TTL_MS) || 0;
const KEEP_WARM_TICK_MS = Number(process.env.CSW_KEEP_WARM_TICK_MS) || 20_000;

const cacheCare = { idle: [], probe: {}, sessions: {}, recentPings: [], dirty: false };
let cacheLedger = createCacheLedger();
const keepWarmPlanner = createKeepWarmPlanner({ pingLimit: (l) => keepWarmLimit(l) });
// Each lane's last conversation request (memory only): the cache doctor compares the next one
// with it when a cache was lost, and keep-warm replays a main lane's one. lane = sid|agent
const _lastBodies = new Map();
let _bodyBytes = 0;
const BODIES_MEMORY_MAX = 300 * 1024 * 1024;
const _affinityHeld = new Map();       // sid|agent → { account, at, credited }: one credit per warm stretch
const _pingInFlight = new Set();       // account names with a keep-warm ping running

try {
  const j = JSON.parse(readFileSync(CACHE_CARE_FILE, 'utf8'));
  cacheCare.idle = Array.isArray(j.idle) ? j.idle.slice(-IDLE_LOG_MAX) : [];
  cacheCare.probe = j.probe || {};
  cacheCare.sessions = j.sessions || {};
  cacheLedger = createCacheLedger(j.ledger);
  keepWarmPlanner.loadModes(j.modes);
} catch { /* first run */ }

function saveCacheCare(force = false) {
  if (!cacheCare.dirty && !force) return;
  cacheCare.dirty = false;
  cacheLedger.prune();
  // Per-session counters of sessions not seen for 30 days go
  const cut = Date.now() - 30 * 86400000;
  for (const [sid, c] of Object.entries(cacheCare.sessions)) if ((c.lastAt || 0) < cut) delete cacheCare.sessions[sid];
  try {
    writeFileSync(CACHE_CARE_FILE + '.tmp', JSON.stringify({
      v: 1, idle: cacheCare.idle, probe: cacheCare.probe, sessions: cacheCare.sessions,
      ledger: cacheLedger.toJSON(), modes: keepWarmPlanner.modes(),
    }));
    renameSync(CACHE_CARE_FILE + '.tmp', CACHE_CARE_FILE);
  } catch (e) { log('error', `Failed to save cache-care.json: ${e.message}`); }
}

function sessionCache(sid) {
  const c = cacheCare.sessions[sid] || (cacheCare.sessions[sid] = { pings: 0, pingCost: 0, warmResumes: 0, saved: 0, affinitySaved: 0, rebuilds: {}, lastRebuild: null, lastAt: 0 });
  c.lastAt = Date.now();
  cacheCare.dirty = true;
  return c;
}

// Learned return curve (refit at most every 10 minutes): this user's own idle periods once
// there are enough of them, else the prior measured on real Claude Code use.
let _curve = { at: 0, surv: null, periods: 0, source: 'prior' };
function returnCurveNow() {
  const now = Date.now();
  if (_curve.surv && now - _curve.at < 10 * 60 * 1000) return _curve;
  const periods = cacheCare.idle.map(p => ({ waitMs: p.waitMs, returned: p.returned }));
  // Sessions idle right now count as "not back yet" (censored)
  for (const l of keepWarmPlanner.all()) {
    if (l.realAt && l.inflight === 0 && now - l.realAt >= l.ttlMs - Math.min(60000, l.ttlMs / 4)) periods.push({ waitMs: now - l.realAt, returned: false });
  }
  const yours = periods.length >= 50;
  _curve = {
    at: now, periods: periods.length, source: yours ? 'yours' : 'prior',
    surv: yours ? returnCurve(periods) : weibullCurve(RETURN_PRIOR.shape, RETURN_PRIOR.scaleMs),
  };
  return _curve;
}

/** Pings for one idle period of this lane: learned look-ahead, capped at the break-even. */
function keepWarmLimit(l) {
  const model = l.model || 'claude-opus-5-5', ttl = l.ttlMs || HOUR_MS;
  const cap = breakEvenPings(model, ttl);
  if (l.mode === 'pin') return cap;
  const h = bestPingCount(returnCurveNow().surv, pingCostRatio(model, ttl), cap);
  return h === 0 ? 0 : Math.min(cap, Math.max(2, h));
}

function learnedKeepWarm() {
  const c = returnCurveNow();
  const hours = (model) => {
    const n = keepWarmLimit({ model, ttlMs: HOUR_MS, mode: 'auto' });
    return Math.round(n * (HOUR_MS - 60000) / HOUR_MS);
  };
  return { periods: c.periods, source: c.source, hours: { opus: hours('claude-opus-5-5'), fable: hours('claude-fable-5-1') } };
}

function laneLabel(sid) {
  return sessionLabel(sessionStore.get(sid)?.meta, sid);
}

/** Session affinity (and so keep-warm) only works while the proxy chooses accounts. */
function affinityActive() {
  return settings.sessionAffinity !== false && (isBalanceMode() || settings.autoSwitch);
}

/** Where balance mode would send this request if the lane were not kept on `pinned`. */
function balanceAlternative(allAccounts, pinned, model) {
  const load = { ...sessionStore.warmLoad() };
  load[pinned.name] = Math.max(0, (load[pinned.name] || 0) - 1); // not counting this lane itself
  const pick = _pickLeastLoaded(allAccounts, balanceLimiter.inflight, accountState, settings.maxConcurrentPerAccount || 8,
    _balanceCooledTokens(allAccounts) || new Set(), Date.now(), { model, extraLoad: load });
  return pick && pick.account.name !== pinned.name ? pick.account.name : null;
}

function cacheCareBegin(sid, agent) {
  if (sid && agent === 'main') keepWarmPlanner.start(sid);
}

function cacheCareEnd(sid, agent) {
  if (sid && agent === 'main') keepWarmPlanner.end(sid);
}

function setLru(map, key, value, max) {
  map.delete(key);
  map.set(key, value);
  if (map.size > max) map.delete(map.keys().next().value);
}

const BODY_SKIP_HEADERS = new Set(['authorization', 'x-api-key', 'cookie', 'host', 'content-length', 'connection', 'accept-encoding']);

function rememberBody(laneKey, entry) {
  const old = _lastBodies.get(laneKey);
  if (old) _bodyBytes -= old.bytes;
  _lastBodies.delete(laneKey); // insertion order = recency
  _lastBodies.set(laneKey, entry);
  _bodyBytes += entry.bytes;
  if (_bodyBytes <= BODIES_MEMORY_MAX) return;
  // Over the cap: drop subagent lanes first, then the oldest
  const order = [..._lastBodies.keys()].sort((x, y) => (x.endsWith('|main') ? 1 : 0) - (y.endsWith('|main') ? 1 : 0));
  for (const k of order) {
    if (_bodyBytes <= BODIES_MEMORY_MAX * 0.9) break;
    _bodyBytes -= _lastBodies.get(k).bytes;
    _lastBodies.delete(k);
  }
}

function forgetBodies(sid) {
  for (const [k, v] of _lastBodies) {
    if (k.startsWith(sid + '|')) { _bodyBytes -= v.bytes; _lastBodies.delete(k); }
  }
}

/**
 * A successful request's usage arrived. Side calls (titles, quick checks) are skipped: they
 * share the session id but not its conversation. Then: learning (idle periods end here),
 * keep-warm and affinity savings, the cache doctor (only when the previous prompt's cache was
 * lost: bodies are parsed then, not on every request), and this body is kept for the next time.
 */
function cacheCareResponse({ sid, agent, acct, model, usage, ttlMs, startedAt, body, headers, path, affinityAlt, pinnedName }) {
  if (!sid || !usage || !acct || !Buffer.isBuffer(body)) return;
  if (CACHE_TTL_OVERRIDE) ttlMs = CACHE_TTL_OVERRIDE;
  const write = (usage.cacheWrite5m || 0) + (usage.cacheWrite1h || 0);
  const tokens = (usage.input || 0) + (usage.cacheRead || 0) + write;
  const cacheRead = usage.cacheRead || 0;
  const account = acct.id || acct.name;
  const laneKey = `${sid}|${agent}`;
  const prev = _lastBodies.get(laneKey);
  if (tokens < SIDE_CALL_MAX_TOKENS && prev && prev.tokens >= KEEP_WARM_MIN_TOKENS) return; // a side call

  let warmResume = false;
  if (agent === 'main') {
    const r = keepWarmPlanner.finish(sid, { startedAt, account, model, ttlMs, tokens, cacheRead });
    warmResume = r.warmResume;
    if (r.idle) {
      cacheCare.idle.push({ waitMs: r.idle.waitMs, returned: true, tokens: r.idle.tokens, model: r.idle.model, at: startedAt });
      if (cacheCare.idle.length > IDLE_LOG_MAX) cacheCare.idle.splice(0, cacheCare.idle.length - IDLE_LOG_MAX);
      cacheCare.dirty = true;
    }
    if (warmResume) {
      const saved = rebuildCost(cacheRead, model, ttlMs);
      cacheLedger.warmResume(saved);
      const c = sessionCache(sid);
      c.warmResumes++;
      c.saved += saved;
      log('cache', `${laneLabel(sid)}: back to a warm cache (kept warm, saved ≈ $${saved.toFixed(2)})`);
    }
  }

  // Session affinity kept this warm lane on its account where the strategy would have moved
  // it: without affinity it would have moved (and rebuilt) once, then stayed. So: one credit
  // per warm stretch on an account, only when the request really ran there.
  const held = _affinityHeld.get(laneKey);
  const sameStretch = held && held.account === account && startedAt - held.at < ttlMs;
  const canCredit = !!affinityAlt && pinnedName === acct.name && !warmResume && cacheRead > 0;
  const credit = () => {
    const saved = rebuildCost(cacheRead, model, ttlMs);
    cacheLedger.affinity(saved);
    sessionCache(sid).affinitySaved += saved;
    return true;
  };
  if (sameStretch) {
    held.at = startedAt;
    if (canCredit && !held.credited) held.credited = credit();
  } else {
    setLru(_affinityHeld, laneKey, { account, at: startedAt, credited: canCredit ? credit() : false }, 2000);
  }

  // Cache doctor: the previous prompt's cache was (mostly) not read back
  const lost = prev ? lostCacheTokens(cacheRead, prev.tokens) : 0;
  if (lost > 0) {
    setImmediate(() => {
      let a = null, b = null;
      try { a = cacheFingerprint(prev.body, prev.headers); b = cacheFingerprint(body, headers); } catch { /* compare what we can */ }
      const c = a && b
        ? classifyRebuild(a, b, { gapMs: startedAt - prev.at, ttlMs: prev.ttlMs, prevAccount: prev.account, account })
        : { cause: 'unknown', detail: 'could not compare the requests' };
      const cost = rebuildCost(lost, model, ttlMs);
      cacheLedger.rebuild(c.cause, cost);
      const sc = sessionCache(sid);
      sc.rebuilds[c.cause] = (sc.rebuilds[c.cause] || 0) + 1;
      sc.lastRebuild = { cause: c.cause, detail: c.detail, at: startedAt, cost };
      const lane = agent === 'main' ? '' : ` [${agent.slice(0, 8)}]`;
      log('cache', `${laneLabel(sid)}${lane}: cache rebuilt (${c.detail}), ≈ $${cost.toFixed(2)} extra`);
    });
  }

  const h = {};
  for (const [k, v] of Object.entries(headers || {})) if (!BODY_SKIP_HEADERS.has(k)) h[k] = v;
  rememberBody(laneKey, { body, headers: h, path: path || '/v1/messages', account, accountName: acct.name, at: startedAt, ttlMs, tokens, model, bytes: body.length });
}

function readResponse(res, timeoutMs) {
  return new Promise((resolve) => {
    const chunks = [];
    let done = false;
    const finish = () => { if (!done) { done = true; resolve(Buffer.concat(chunks)); } };
    res.on('data', c => chunks.push(c));
    res.on('end', finish);
    res.on('error', finish);
    setTimeout(() => { res.destroy(); finish(); }, timeoutMs).unref?.();
  });
}

/** Replay a lane's last request with max_tokens 0 (or 1), check that it read the cache. */
async function sendKeepWarmPing(l, snap, acct) {
  const startedAt = Date.now();
  let req;
  try { req = JSON.parse(snap.body.toString('utf8')); } catch { keepWarmPlanner.stop(l.sid, 'unreadable'); return; }
  const key = `${req.model}|${req.thinking?.type || 'none'}`;
  if (cacheCare.probe[key] === 'no') { keepWarmPlanner.stop(l.sid, 'unsupported'); return; }
  const original = snap.body.toString('utf8');
  const attempt = async (maxTokens) => {
    // Only max_tokens and stream change; every other byte is the session's own request
    const pingBody = setTopLevelJsonFields(original, { max_tokens: maxTokens, stream: false });
    if (pingBody == null) throw new Error('request body is not a JSON object');
    const buf = Buffer.from(pingBody);
    const headers = buildForwardHeaders(snap.headers, acct.token);
    headers['content-length'] = String(buf.length);
    headers['accept'] = 'application/json';
    const res = await forwardToAnthropic('POST', snap.path, headers, buf, 60_000);
    const text = (await readResponse(res, 60_000)).toString('utf8');
    return { status: res.statusCode, headers: res.headers, text };
  };
  const maxTokensRejected = (r) => r.status === 400 && /max_tokens/i.test(r.text);
  try {
    let r = await attempt(cacheCare.probe[key] === 'one' ? 1 : 0);
    if (maxTokensRejected(r) && cacheCare.probe[key] !== 'one') {
      cacheCare.probe[key] = 'one';
      r = await attempt(1);
    }
    if (maxTokensRejected(r)) {
      cacheCare.probe[key] = 'no';
      cacheCare.dirty = true;
      log('cache', `Keep-warm is not possible for ${req.model} with ${req.thinking?.type || 'no'} thinking (the API refuses the ping)`);
      keepWarmPlanner.stop(l.sid, 'unsupported');
      return;
    }
    updateAccountState(acct.token, acct.label || acct.name, r.headers, getFingerprintFromToken(acct.token));
    if (r.status !== 200) {
      keepWarmPlanner.stop(l.sid, r.status === 429 ? 'rate-limited' : `error ${r.status}`);
      log('cache', `Keep-warm ping for ${laneLabel(l.sid)} got ${r.status}: stopped for this idle period`);
      return;
    }
    if (!cacheCare.probe[key]) cacheCare.probe[key] = 'zero';
    const parsed = parseJsonUsage(r.text);
    const usage = parsed?.usage;
    if (!usage) { keepWarmPlanner.stop(l.sid, 'no-usage'); return; }
    const model = parsed.model || req.model;
    const cost = usageCost(usage, model);
    cacheLedger.ping(cost);
    const sc = sessionCache(l.sid);
    sc.pings++;
    sc.pingCost += cost;
    cacheCare.recentPings.push(startedAt);
    recordUsage({ ts: startedAt, account: acct.id || acct.name, model, repo: '(keep-warm)', branch: '', usage });
    throughput.add(acct.id || acct.name, model, totalTokens(usage));
    _throughputDirty = true;
    sessionStore.touch(l.sid, 'main', { ttlMs: l.ttlMs }); // the affinity pin stays warm too
    const write = (usage.cacheWrite5m || 0) + (usage.cacheWrite1h || 0);
    const ok = (usage.cacheRead || 0) >= l.tokens * 0.9 && write <= l.tokens * 0.1;
    keepWarmPlanner.pinged(l.sid, ok ? { ok: true, startedAt } : { ok: false, reason: 'missed' });
    const kept = _lastBodies.get(`${l.sid}|main`);
    if (ok && kept === snap) kept.at = startedAt; // the doctor measures idle time from the last touch
    if (!ok) log('cache', `Keep-warm ping for ${laneLabel(l.sid)} missed the cache (read ${usage.cacheRead || 0} of ${l.tokens} tokens): stopped for this idle period`);
  } catch (e) {
    keepWarmPlanner.stop(l.sid, 'network');
    log('cache', `Keep-warm ping for ${laneLabel(l.sid)} failed: ${e.message}`);
  }
}

function nearLimit(acct) {
  const st = accountState.get(acct.token);
  if (!st) return false;
  return (st.utilization5h || 0) >= KEEP_WARM_NEAR_LIMIT.fiveH || (st.utilization7d || 0) >= KEEP_WARM_NEAR_LIMIT.sevenD;
}

/** Every 20 s: notice closed sessions (learning), then send the pings that are due. */
async function keepWarmTick() {
  const now = Date.now();
  const registry = readSessionRegistry();
  // A session missing from Claude Code's registry is closed: its idle period ends without a
  // return. Only when the registry could be read (else nothing is known).
  if (_registryOk) {
    for (const l of keepWarmPlanner.all()) {
      if (registry.has(l.sid) || l.inflight > 0) continue;
      if (l.realAt && now - l.realAt >= l.ttlMs - Math.min(60000, l.ttlMs / 4)) {
        cacheCare.idle.push({ waitMs: now - l.realAt, returned: false, tokens: l.tokens, model: l.model, at: now });
        cacheCare.dirty = true;
      }
      keepWarmPlanner.drop(l.sid);
      forgetBodies(l.sid);
    }
  }
  // Subagent lanes are short-lived: forget their bodies after 2 hours
  for (const [k, v] of _lastBodies) {
    if (!k.endsWith('|main') && now - v.at > 2 * HOUR_MS) { _bodyBytes -= v.bytes; _lastBodies.delete(k); }
  }
  // Pings: only while the next request will land on the same account, and only for sessions
  // known to be open
  if (!settings.keepWarm || !settings.proxyEnabled || !affinityActive() || !_registryOk) return;
  cacheCare.recentPings = cacheCare.recentPings.filter(t => now - t < HOUR_MS);
  const accounts = loadAllAccountTokens();
  for (const l of keepWarmPlanner.due(now)) {
    if (cacheCare.recentPings.length >= KEEP_WARM_PINGS_PER_HOUR) break;
    if (!registry.has(l.sid)) continue;
    const snap = _lastBodies.get(`${l.sid}|main`);
    if (!snap || snap.tokens < KEEP_WARM_MIN_TOKENS) { keepWarmPlanner.stop(l.sid, 'no-request-kept'); continue; }
    const acct = accounts.find(a => a.name === snap.accountName);
    if (!acct) { keepWarmPlanner.stop(l.sid, 'account-removed'); continue; }
    if (_pingInFlight.has(acct.name)) continue;
    const route = sessionStore.route(l.sid, 'main');
    if (!route || route.account !== acct.name) { keepWarmPlanner.stop(l.sid, 'moved'); continue; }
    if (!isAccountAvailable(acct.token, acct.expiresAt, l.model) || nearLimit(acct)) { keepWarmPlanner.stop(l.sid, 'near-limit'); continue; }
    _pingInFlight.add(acct.name);
    sendKeepWarmPing(l, snap, acct).finally(() => _pingInFlight.delete(acct.name));
  }
}
setInterval(() => { keepWarmTick().catch(e => log('error', `Keep-warm: ${e.message}`)); }, KEEP_WARM_TICK_MS).unref?.();
setInterval(() => saveCacheCare(), 60_000).unref?.();

/** One line for the header: what cache care saved this week. */
function cacheCareHeadline() {
  const w = cacheLedger.summary(Date.now() - 7 * 86400000);
  return { keepWarm: settings.keepWarm === true, pct: w.pct, saved: w.saved, rebuildCost: w.rebuildCost };
}

function cacheCareReport() {
  const now = Date.now();
  return {
    keepWarm: settings.keepWarm === true,
    learned: learnedKeepWarm(),
    week: cacheLedger.summary(now - 7 * 86400000),
    month: cacheLedger.summary(now - 30 * 86400000),
    probe: cacheCare.probe,
    stats: {
      lanes: keepWarmPlanner.all().length,
      kept: [..._lastBodies.entries()].filter(([k, v]) => k.endsWith('|main') && v.tokens >= KEEP_WARM_MIN_TOKENS).length,
      memoryMB: Math.round(_bodyBytes / 1e5) / 10, pingsLastHour: cacheCare.recentPings.filter(t => now - t < HOUR_MS).length,
    },
  };
}

/** Cache state of one session for the Sessions tab. */
function sessionCacheView(sid, now = Date.now()) {
  const l = keepWarmPlanner.get(sid);
  const c = cacheCare.sessions[sid] || null;
  let state = null, nextPingAt = null;
  if (l && l.touchedAt) {
    const expiresAt = l.touchedAt + l.ttlMs;
    if (l.inflight > 0 || now - l.realAt < l.ttlMs - 60000) state = 'active';
    else if (now > expiresAt) state = 'cold';
    else if (!settings.keepWarm || l.mode === 'never') state = 'warm';
    else if (l.stopped) state = 'stopped';
    else { state = 'kept'; nextPingAt = l.touchedAt + l.ttlMs - 60000; }
  }
  return {
    mode: l?.mode || 'auto', state, stopped: l?.stopped || null, nextPingAt, expiresAt: l?.touchedAt ? l.touchedAt + l.ttlMs : null,
    pingsThisIdle: l?.pings || 0, limit: l?.limit || 0, tokens: l?.tokens || 0, small: !!l && l.tokens < KEEP_WARM_MIN_TOKENS,
    pings: c?.pings || 0, saved: (c?.saved || 0) + (c?.affinitySaved || 0), pingCost: c?.pingCost || 0, warmResumes: c?.warmResumes || 0,
    rebuilds: c?.rebuilds || {}, lastRebuild: c?.lastRebuild || null,
  };
}

// ── Proxy server ──

const proxyServer = createServer((clientReq, clientRes) => {
  // Only this computer may use the accounts (unless CSW_ALLOW_REMOTE=1); web pages never.
  const remote = !ALLOW_REMOTE && (!isLoopbackAddr(clientReq.socket.remoteAddress) || !isLocalHost(clientReq.headers.host));
  if (remote || !originAllowed(clientReq.headers.origin)) {
    clientRes.writeHead(403, { 'Content-Type': 'application/json' });
    clientRes.end(JSON.stringify({ type: 'error', error: { type: 'permission_error', message: remote
      ? 'vdm proxy: only this computer may connect. Set CSW_ALLOW_REMOTE=1 for the dashboard process to allow other devices.'
      : 'vdm proxy: requests from web pages are refused.' } }));
    return;
  }
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

  const maxAttempts = allAccounts.length + 3; // +1 refresh retry, +1 minimal-header retry, +1 same-account burst retry
  const triedTokens = new Set();
  const billingMarkedTokens = new Set(); // tokens marked billing-unavailable this request
  const refreshAttempted = new Set(); // track refresh attempts to prevent infinite loops
  let _bulkRefreshAttempted = false;   // per-request: tried force-refreshing all tokens?
  let _minimalHeaderRetried = false;   // per-request: tried minimal-header last resort?
  let _sameAccountRetried = false;     // per-request: waited out a burst 429 on the pinned account?

  // ── Balance-mode concurrency slot ──
  // heldKey = the account name whose in-flight slot we currently hold (null = none).
  // releaseHeld is idempotent and a no-op outside balance mode. Attaching it to the
  // response 'close' event guarantees the slot is released exactly once when the
  // response completes OR the connection is terminated — covering every return/throw
  // path below (streaming end, switch, passthrough, deadline, exhaustion).
  const balanceMode = isBalanceMode();
  let heldKey = null;
  let clientGone = false;
  const releaseHeld = () => {
    if (heldKey != null) { balanceLimiter.release(heldKey); heldKey = null; }
  };
  // Releasing on response 'close' covers normal completion AND abnormal termination.
  // The clientGone flag also catches a disconnect that lands *during* a slot wait — a
  // slot acquired after the (already-fired, once-only) close listener would otherwise leak.
  clientRes.once('close', () => { clientGone = true; releaseHeld(); });

  // ── Session affinity ──
  // A Claude Code session (one lane per agent: main loop, each subagent) stays on one
  // account while its prompt cache is warm. Moving it re-writes the whole cache on the
  // new account (1.25-2x input price) instead of reading it (~0.1x). Applies whenever the
  // proxy chooses accounts (auto-switch or balance); a cold lane is free to re-place.
  const model = extractModel(body);
  const ttlMs = cacheTtlFromBody(body);
  const sid = extractSessionId(clientReq.headers, body);
  const agent = String(clientReq.headers['x-claude-code-agent-id'] || 'main').slice(0, 64);
  // Cache care: a real request of this session is under way, also while it waits for a slot
  // (no keep-warm ping may overlap it); 'close' fires on every outcome
  cacheCareBegin(sid, agent);
  clientRes.once('close', () => cacheCareEnd(sid, agent));
  const affinityOn = !!sid && settings.sessionAffinity !== false && (balanceMode || settings.autoSwitch);
  let laneWarm = false;
  let pinned = null;          // the lane's account, when it can take this request
  let prevLaneAccount = null; // where the lane was (cold or unusable)  - preferred if it fits
  let pinReason = 'assign';   // recorded when the lane lands on a different account
  // Names/branch lookup reads small files: keep it off this request's path
  if (sid) setImmediate(() => refreshSessionMeta(sid, body).catch(() => {}));
  if (affinityOn) {
    const r = sessionStore.route(sid, agent);
    if (r) {
      laneWarm = r.warm;
      const acct = allAccounts.find(a => a.name === r.account);
      if (!acct) pinReason = 'account-removed';
      else if (!isAccountAvailable(acct.token, acct.expiresAt, model)) pinReason = 'unavailable';
      else if (!r.warm) { pinReason = 'idle'; prevLaneAccount = acct.name; }
      else pinned = acct;
    }
  }
  const pinLane = (acct, reason) => {
    if (!affinityOn || !acct) return;
    noteMove(sid, sessionStore.pin(sid, agent, acct.name, { reason, ttlMs }));
  };
  // Retry target outside balance mode: a session follows the active (keychain) account
  // when it can take the request, else the least-used available account.
  const pickNext = () => {
    if (affinityOn) {
      const active = allAccounts.find(a => a.token === getActiveToken());
      if (active && !triedTokens.has(active.token) && isAccountAvailable(active.token, active.expiresAt, model)) return active;
    }
    return pickBestAccount(triedTokens, model) || pickAnyUntried(triedTokens);
  };
  // The keychain account is Claude Code's own login and where new sessions start. Only
  // move it when the failing account IS the keychain account  - a pinned session failing
  // elsewhere must not drag every other session along.
  const failedIsActive = () => !affinityOn || token === getActiveToken();

  // Switch accounts in balance mode: release the current slot, then acquire one on a
  // different (untried) account. Returns the new account, or null when exhausted/aborted.
  const balanceSwitch = async (excludeTokens) => {
    releaseHeld();
    // Reload fresh (mirrors pickBestAccount) so post-refresh tokens/expiry are current.
    const slot = await acquireBalanceSlot(loadAllAccountTokens(), excludeTokens, { model });
    if (!slot) return null;
    heldKey = slot.account.name;
    if (clientGone) { releaseHeld(); return null; } // client left during the wait — don't leak
    return slot.account;
  };

  // Start with active keychain token, apply rotation strategy
  let token = getActiveToken();
  const activeAcct = allAccounts.find(a => a.token === token);
  let affinityAlt = null; // where the strategy would have sent a warm lane that affinity kept home

  if (balanceMode) {
    // Spread sessions across accounts by load; no keychain write (the active pointer
    // stays stable). A warm lane waits for a slot on its own account. If no account is
    // available, fall through with the keychain token  - the retry loop's exhausted path
    // handles it.
    if (pinned) affinityAlt = balanceAlternative(allAccounts, pinned, model);
    let slot = pinned ? await acquireBalanceSlot(allAccounts, new Set(), { model, only: pinned }) : null;
    if (pinned && !slot) pinReason = 'unavailable';
    if (!slot) {
      const prefer = affinityOn ? (prevLaneAccount || sessionStore.home(sid)) : null;
      slot = await acquireBalanceSlot(allAccounts, new Set(), { model, prefer });
    }
    if (slot) {
      token = slot.account.token;
      heldKey = slot.account.name;
      if (clientGone) releaseHeld(); // client left during the wait — release the slot
      if (slot.account !== pinned) {
        pinLane(slot.account, pinReason);
        const nm = slot.account.label || slot.account.name;
        if (!activeAcct || slot.account.name !== activeAcct.name) {
          log('balance', `→ ${nm} (${balanceLimiter.get(slot.account.name)}/${settings.maxConcurrentPerAccount || 8} in-flight)`);
        }
      }
    }
  } else if (settings.autoSwitch && pinned) {
    // Warm session lane: stay on its account. No strategy run, no keychain write.
    token = pinned.token;
    // For the savings figure only: where would the strategy have sent it?
    const alt = _pickByStrategy({
      strategy: settings.rotationStrategy || 'conserve', intervalMin: settings.rotationIntervalMin || 60,
      currentToken: getActiveToken(), lastRotationTime, accounts: allAccounts, stateManager: accountState,
      excludeTokens: new Set(), model,
    }).account;
    if (alt && alt.name !== pinned.name) affinityAlt = alt.name;
  } else if (settings.autoSwitch) {
    const { account: strategyPick, rotated } = _pickByStrategy({
      strategy: settings.rotationStrategy || 'conserve',
      intervalMin: settings.rotationIntervalMin || 60,
      currentToken: token,
      lastRotationTime,
      accounts: allAccounts,
      stateManager: accountState,
      excludeTokens: new Set(),
      model,
    });

    // The active account only lacks room for this model (e.g. its Fable bucket is used
    // up): route this request elsewhere, but keep the keychain  - everyone else is fine.
    const activeOnlyLacksModel = activeAcct && isAccountAvailable(activeAcct.token, activeAcct.expiresAt)
      && !isAccountAvailable(activeAcct.token, activeAcct.expiresAt, model);
    if (strategyPick && activeOnlyLacksModel && strategyPick.name !== activeAcct.name) {
      token = strategyPick.token;
      const key = `${activeAcct.name}:${model}`;
      if (Date.now() - (_modelRouteLogged.get(key) || 0) > 5 * 60 * 1000) {
        _modelRouteLogged.set(key, Date.now());
        log('proactive', `${activeAcct.label || activeAcct.name} has no ${model} capacity left → ${strategyPick.label || strategyPick.name} for ${model} requests`);
      }
    } else if (strategyPick) {
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
    pinLane(allAccounts.find(a => a.token === token), pinReason);
  }
  if (affinityOn) sessionStore.touch(sid, agent, { ttlMs }); // concurrent requests see the lane warm

  const reqStartedAt = Date.now(); // the cache lifetime counts from the request's start

  // Artifact links in this session's messages (e.g. the Artifact tool's results)
  if (sid && body.indexOf('/artifact/') !== -1) {
    const refs = extractArtifactRefs(body);
    if (refs.size) noteArtifactRefs(sid, refs, allAccounts.find(a => a.token === token)?.name);
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
      const wasActive = preAcct.token === getActiveToken();
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
            // In balance mode, or for a pinned session on a non-active account, don't
            // touch the keychain active pointer  - forward the refreshed token in-memory
            // (heldKey / lane pins are keyed by the stable account name).
            if (!balanceMode && wasActive) {
              try {
                await withSwitchLock(() => {
                  writeKeychain(refreshed.creds);
                  invalidateTokenCache();
                });
              } catch {}
            }
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
    // After a refresh the token is new: fall back to a fresh read of the accounts
    const acct = allAccounts.find(a => a.token === token) || loadAllAccountTokens().find(a => a.token === token);
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
      if (settings.autoSwitch || balanceMode) {
        const next = balanceMode ? await balanceSwitch(triedTokens) : pickNext();
        if (next) {
          log(balanceMode ? 'balance' : 'switch', `  → network error on ${acctName}, switching to ${next.label || next.name}`);
          if (!balanceMode && failedIsActive()) {
            try {
              await withSwitchLock(() => {
                writeKeychain(next.creds);
                invalidateTokenCache();
              });
            } catch (e) {
              log('warn', `Keychain write failed during network-error switch: ${e.message}`);
            }
          }
          token = next.token;
          pinLane(next, 'network-error');
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
      // Unified status "rejected" = a usage window is used up (5h, weekly, or this model's
      // bucket) until its reset. Without it, a short retry-after is a transient burst limit
      // ("Server is temporarily limiting requests").
      const rl = parseRateLimitHeaders(proxyRes.headers);
      const transient = rl.status !== 'rejected' && retryAfter < 60;
      // Returns { what, modelOnly }: which limit hit, and whether only this model's bucket did.
      const markLimit = () => {
        if (rl.status === 'rejected') {
          const r = markAccountRejected(token, acctName, proxyRes.headers);
          return { what: rl.claim || 'limit', modelOnly: r.scope === 'model' };
        }
        markAccountLimited(token, acctName, retryAfter);
        return { what: 'retry-after', modelOnly: false };
      };

      // ── Balance mode: absorb the 429 instead of surfacing it ──
      if (balanceMode) {
        // A warm session lane hitting a short burst: wait it out once on the same account
        // rather than moving the conversation and rebuilding its cache elsewhere.
        const waitSec = Math.max(retryAfter, 1);
        if (transient && affinityOn && laneWarm && !_sameAccountRetried && waitSec <= 10 && Date.now() + waitSec * 1000 < deadline) {
          _sameAccountRetried = true;
          await drainResponse(proxyRes);
          log('balance', `${acctName} → 429 transient — waiting ${waitSec}s on the same account (session affinity)`);
          await new Promise(r => setTimeout(r, waitSec * 1000));
          triedTokens.delete(token);
          continue;
        }
        const coolName = heldKey || acct?.name;
        if (transient) {
          // Transient burst — lightweight backoff, no global rate-limit state pollution.
          balanceCoolDown(coolName, Math.max(retryAfter, BALANCE_MIN_COOLDOWN_SEC));
          logEvent('balance-cooldown', { account: acctName, retryAfter });
          log('balance', `${acctName} → 429 transient (retry-after ${retryAfter}s) — backing off, switching account`);
        } else {
          // Genuine rate limit — mark limited so the pickers/UI/telemetry reflect it.
          const { what } = markLimit();
          logEvent('rate-limited', { account: acctName, retryAfter, limit: what });
          log('balance', `${acctName} → 429 ${what} used up — switching account`);
        }
        // Capture the upstream 429 before draining so we can replay it verbatim if
        // no other account is free (preserves retry-after for Claude Code's own retry).
        const upStatus = proxyRes.statusCode;
        const upHeaders = { ...proxyRes.headers };
        const upBody = await drainResponse(proxyRes);
        const next = await balanceSwitch(triedTokens);
        if (next) {
          token = next.token;
          pinLane(next, transient ? '429-burst' : '429-limit');
          continue;
        }
        if (transient) {
          // All accounts in a transient burst → DON'T manufacture a hard error.
          // Pass the original 429 (with its retry-after) straight through; Claude
          // Code retries on its own — strictly better than a synthesized exhaustion.
          log('balance', '  → all accounts cooling (transient) — passing upstream 429 through');
          delete upHeaders['content-length'];
          delete upHeaders['transfer-encoding'];
          clientRes.writeHead(upStatus, upHeaders);
          clientRes.end(upBody);
          return;
        }
        // Genuine rate limit across all accounts — surface the exhaustion.
        log('balance', '  → all accounts rate limited, returning 429');
        logEvent('all-exhausted', {});
        notify('All Accounts Exhausted', `All ${allAccounts.length} accounts rate-limited. Reset: ${getEarliestReset()}`);
        clientRes.writeHead(429, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: { type: 'rate_limit_error', message: `All ${allAccounts.length} accounts rate limited. Earliest reset: ${getEarliestReset()}` },
        }));
        return;
      }

      // Transient burst 429s (short retry-after) are normal — Claude Code
      // retries on its own (on the same pinned account).  Pass through silently
      // without noisy logging, marking the account as limited, or sending notifications.
      let what = 'transient', modelOnly = false;
      if (!transient) {
        ({ what, modelOnly } = markLimit());
        logEvent('rate-limited', { account: acctName, retryAfter, limit: what });
      }
      log('switch', `${acctName} → 429 ${transient ? 'transient' : what + ' used up'} (retry-after: ${retryAfter}s)`);

      if (!settings.autoSwitch || transient) {
        if (!transient) log('switch', '  → auto-switch OFF, returning 429 as-is');
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.on('error', () => { try { clientRes.end(); } catch {} });
        clientRes.on('close', () => { proxyRes.destroy(); });
        await pipeAndWait(proxyRes, clientRes);
        return;
      }

      await drainResponse(proxyRes);

      // Try next best account
      const next = pickNext();
      if (next) {
        log('switch', `  → switching to ${next.label || next.name}`);
        // A model-only limit (Fable bucket) leaves the account fine for everyone else.
        if (failedIsActive() && !modelOnly) {
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
              invalidateAccountsCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during 429 switch: ${e.message}`);
          }
        }
        token = next.token;
        pinLane(next, '429-limit');
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

      if (!settings.autoSwitch && !balanceMode) {
        log('switch', '  → auto-switch OFF — trying passthrough');
        if (await _passthroughFallback(clientReq, clientRes, body, '401-autoswitch-off')) return;
        clientRes.writeHead(401, { 'Content-Type': 'application/json' });
        clientRes.end(JSON.stringify({
          type: 'error',
          error: { type: 'authentication_error', message: 'Token expired' },
        }));
        return;
      }

      const next = balanceMode ? await balanceSwitch(triedTokens) : pickNext();
      if (next) {
        log(balanceMode ? 'balance' : 'switch', `  → switching to ${next.label || next.name}`);
        if (!balanceMode && failedIsActive()) {
          try {
            await withSwitchLock(() => {
              writeKeychain(next.creds);
              invalidateTokenCache();
            });
          } catch (e) {
            log('warn', `Keychain write failed during 401 switch: ${e.message}`);
          }
        }
        token = next.token;
        pinLane(next, '401');
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

      // Parse error type from response body (do this FIRST, before counter logic)
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

      // Extract error message early so the auth-heuristic can use it
      const errorMessage = parsedError?.error?.message || '';

      // Detect the specific "no body" / empty-body / non-JSON patterns that
      // indicate this is NOT a legitimate request validation error
      const looksLikeAuthIssue =
        !bodyStr ||                                  // truly empty
        !parsedError ||                              // not valid JSON
        errorType === 'authentication_error' ||      // explicit auth error
        errorType === 'permission_error' ||           // permission issue
        /status code|no body|invalid.*token|unauthorized/i.test(errorMessage);  // heuristic

      // Billing errors (credit balance too low) are never fixable by token
      // refresh — skip straight to account switching (Strategy 3).
      const isBillingError = /credit balance|billing.*issue|payment.*required/i.test(errorMessage);

      // ── Content 400: pass through immediately ──
      // If the API returned a well-formed invalid_request_error and it doesn't
      // look like an auth/billing issue, this is a request *body* problem
      // (bad model, invalid params, etc).  Switching accounts or refreshing
      // tokens will never fix it — pass through without polluting the
      // consecutive-400 counter or triggering recovery strategies.
      if (errorType === 'invalid_request_error' && !looksLikeAuthIssue && !isBillingError) {
        log('info', `${acctName} → 400 invalid_request_error (passing through): ${bodyStr.slice(0, 200)}`);
        clientRes.writeHead(400, proxyRes.headers);
        clientRes.end(bodyBuf);
        return;
      }

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

      // Track this 400 for the global consecutive-failure counter.
      // Only auth-looking and billing 400s count — content 400s were already
      // passed through above and should not escalate the counter.
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
      if (settings.autoSwitch || balanceMode) {
        const next = balanceMode ? await balanceSwitch(triedTokens) : pickNext();
        if (next) {
          log(balanceMode ? 'balance' : 'switch', `  → 400 on ${acctName}, switching to ${next.label || next.name}`);
          if (!balanceMode && failedIsActive()) {
            try {
              await withSwitchLock(() => {
                writeKeychain(next.creds);
                invalidateTokenCache();
              });
            } catch (e) {
              log('warn', `Keychain write failed during 400 switch: ${e.message}`);
            }
          }
          token = next.token;
          pinLane(next, '400');
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

    // Token usage: read `usage` from Messages responses as they stream through
    const contentType = proxyRes.headers['content-type'] || '';
    const isMessages = clientReq.method === 'POST' && /^\/v1\/messages(\?|$)/.test(clientReq.url || '');
    const tapKind = !isMessages ? null
      : contentType.includes('text/event-stream') ? 'sse'
      : contentType.includes('application/json') ? 'json' : null;
    if (tapKind) {
      const tap = createUsageTap(tapKind);
      await pipeAndWait(proxyRes, tap, clientRes);
      try {
        const r = tap.result();
        if (r?.usage) recordProxyUsage({ sid, agent, acct, model: r.model || model, usage: r.usage, ttlMs });
        if (r?.usage && proxyRes.statusCode === 200) {
          cacheCareResponse({ sid, agent, acct, model: r.model || model, usage: r.usage, ttlMs, startedAt: reqStartedAt,
            body, headers: clientReq.headers, path: clientReq.url, affinityAlt, pinnedName: pinned?.name || null });
        }
      } catch (e) { log('error', `Usage accounting failed: ${e.message}`); }
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
        inflight: balanceLimiter.get(a.name),
        coolingDown: (_balanceCooldown.get(a.name) || 0) > Date.now(),
        ...(state || {}),
      };
    }),
    balance: {
      enabled: isBalanceMode(),
      cap: settings.maxConcurrentPerAccount || 8,
      totalInflight: balanceLimiter.total(),
      waiting: balanceLimiter.waitingCount(),
    },
    recentEvents: proxyEventLog.slice(0, 20),
  };
}

// ── Graceful shutdown ──

function shutdown(signal) {
  log('info', `Received ${signal}, shutting down...`);
  // Persist usage rollups, session pins and artifact links before exit
  try { flushUsage(); } catch {}
  try { saveSessions(true); } catch {}
  try { if (_historyDirty) writeHistoryFile(); } catch {}
  try { if (_throughputDirty) writeThroughputFile(); } catch {}
  try { saveCacheCare(true); } catch {}
  if (_artifactLinksDirty) try { saveArtifacts(); } catch {}
  try { stopHistory(); } catch {}
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
  onServerListening();
  const s = settings;
  log('info', `API proxy on http://localhost:${PROXY_PORT} (proxy=${s.proxyEnabled ? 'on' : 'off'}, auto-switch=${s.autoSwitch ? 'on' : 'off'}, rotation=${s.rotationStrategy || 'conserve'}, ${loadAllAccountTokens().length} accounts)`);
});
