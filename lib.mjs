// Van Damme-o-Matic  - Core Library
// Pure/testable functions extracted from dashboard.mjs.
// Zero dependencies, uses Node.js built-in modules only.

import { createHash } from 'node:crypto';

// ─────────────────────────────────────────────────
// Fingerprinting
// ─────────────────────────────────────────────────

export function getFingerprint(creds) {
  const token = creds?.claudeAiOauth?.accessToken || '';
  return createHash('sha256').update(token).digest('hex').slice(0, 16);
}

export function getFingerprintFromToken(token) {
  return createHash('sha256').update(token || '').digest('hex').slice(0, 16);
}

// ─────────────────────────────────────────────────
// Header building for proxy forwarding
// ─────────────────────────────────────────────────

// RFC 7230 §6.1: hop-by-hop headers that MUST NOT be forwarded by proxies.
// Also includes `connection` itself — plus any headers named in its value.
export const HOP_BY_HOP = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
  // Not strictly hop-by-hop, but must be recalculated by the proxy:
  'host', 'content-length',
  // Strip accept-encoding: proxy must read/inspect error bodies (400, 401, etc.)
  // and compressed responses break the text-based error parsing. Localhost
  // traffic doesn't benefit from compression anyway.
  'accept-encoding',
  // Strip x-api-key: if Claude Code or another client forwards this header,
  // it can cause the API to bill a different account than the OAuth Bearer
  // token, leading to false "credit balance too low" 400 errors.
  'x-api-key',
]);

/**
 * Strip hop-by-hop headers from a headers object (for passthrough / raw forwarding).
 * Also strips any custom hop-by-hop headers declared in the Connection header.
 */
export function stripHopByHopHeaders(originalHeaders) {
  const connVal = originalHeaders['connection'] || originalHeaders['Connection'] || '';
  const extraHop = new Set(
    connVal.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  );
  const fwd = {};
  for (const [k, v] of Object.entries(originalHeaders)) {
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk) || extraHop.has(lk)) continue;
    fwd[k] = v;
  }
  return fwd;
}

export function buildForwardHeaders(originalHeaders, token) {
  const fwd = stripHopByHopHeaders(originalHeaders);
  if (!token || typeof token !== 'string') {
    throw new Error(`Cannot forward request: token is ${token === null ? 'null' : typeof token}`);
  }
  fwd['authorization'] = `Bearer ${token}`;
  fwd['host'] = 'api.anthropic.com';
  // Ensure OAuth beta
  const betas = (fwd['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
  fwd['anthropic-beta'] = betas.join(',');
  return fwd;
}

// ─────────────────────────────────────────────────
// Unified rate-limit headers
// ─────────────────────────────────────────────────

// Windows Claude Code reads from `anthropic-ratelimit-unified-<suffix>-{utilization,reset}`.
// `7d_oi` ("overage included") is a separate per-model weekly bucket  - Claude Code calls
// it the "Fable limit"  - and only shows up on accounts whose responses carry it.
export const RATE_LIMIT_WINDOWS = [
  ['fiveH', '5h'],
  ['sevenD', '7d'],
  ['sevenDOI', '7d_oi'],
];

// Representative claims that only limit one model family; any other claim blocks the account.
export const MODEL_CLAIMS = {
  seven_day_overage_included: 'fable',  // Claude Code calls this bucket the "Fable limit"
  seven_day_opus: 'opus',
  seven_day_sonnet: 'sonnet',
};

// Utilization at/above this is "nearly full": balance mode only lands new work
// there when every other account is nearly full too.
export const NEAR_FULL_UTILIZATION = 0.9;

/**
 * Parse the unified subscription rate-limit headers of a response.
 * status: 'allowed' | 'allowed_warning' | 'rejected' | null (no unified headers  - e.g.
 * a transient "server is temporarily limiting requests" 429).
 * Each window is { utilization, reset } (0-1 fraction, epoch seconds) or null when absent.
 */
export function parseRateLimitHeaders(headers = {}) {
  const num = (v) => {
    if (v == null || v === '') return undefined;
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  };
  const out = {
    status: headers['anthropic-ratelimit-unified-status'] || null,
    claim: headers['anthropic-ratelimit-unified-representative-claim'] || null,
    reset: num(headers['anthropic-ratelimit-unified-reset']) || 0,
    overageStatus: headers['anthropic-ratelimit-unified-overage-status'] || null,
  };
  for (const [key, suffix] of RATE_LIMIT_WINDOWS) {
    const u = num(headers[`anthropic-ratelimit-unified-${suffix}-utilization`]);
    const r = num(headers[`anthropic-ratelimit-unified-${suffix}-reset`]);
    out[key] = (u === undefined && r === undefined) ? null : { utilization: u ?? 0, reset: r ?? 0 };
  }
  return out;
}

/** Model family for per-model limits: 'fable' | 'opus' | 'sonnet' | null. */
export function modelFamily(model) {
  const m = String(model || '').toLowerCase();
  if (/fable|mythos/.test(m)) return 'fable';
  if (m.includes('opus')) return 'opus';
  if (m.includes('sonnet')) return 'sonnet';
  return null;
}

/** The per-model weekly bucket a model draws from (null = only the shared windows). */
export function modelBucket(model) {
  return modelFamily(model) === 'fable' ? 'sevenDOI' : null;
}

function isWindowExhausted(utilization, resetSec, nowSec) {
  // Unknown reset → don't lock the account out on a stale reading.
  return (utilization || 0) >= 1 && !!resetSec && resetSec > nowSec;
}

/**
 * True when a window this request would draw from is used up (until its reset).
 * Without a model, only the shared 5h / weekly windows count.
 */
export function isAccountExhausted(acctState, model = null, now = Date.now()) {
  if (!acctState) return false;
  const nowSec = Math.floor(now / 1000);
  if (isWindowExhausted(acctState.utilization5h, acctState.resetAt, nowSec)) return true;
  if (isWindowExhausted(acctState.utilization7d, acctState.resetAt7d, nowSec)) return true;
  if (modelBucket(model) === 'sevenDOI' && isWindowExhausted(acctState.utilization7dOI, acctState.resetAt7dOI, nowSec)) return true;
  const family = modelFamily(model);
  if (family && (acctState.modelLimits?.[family] || 0) > nowSec) return true;
  return false;
}

/** Highest utilization among the windows a request for `model` draws from (0-1). */
export function usageScore(acctState, model = null) {
  if (!acctState) return 0;
  let s = Math.max(acctState.utilization5h || 0, acctState.utilization7d || 0);
  if (modelBucket(model) === 'sevenDOI') s = Math.max(s, acctState.utilization7dOI || 0);
  return s;
}

// ─────────────────────────────────────────────────
// Account state management
// ─────────────────────────────────────────────────

export function createAccountStateManager() {
  const state = new Map();

  function update(token, name, headers) {
    const rl = parseRateLimitHeaders(headers);
    const prev = state.get(token);
    // No unified headers (5xx, 404, non-Messages endpoints): nothing learned  - keep state.
    if (!rl.status && !rl.fiveH && !rl.sevenD && !rl.sevenDOI) {
      if (prev) prev.updatedAt = Date.now();
      return;
    }
    const rejected = rl.status === 'rejected' || rl.status === 'limited';
    // A per-model limit stays until it expires or its window reports headroom again.
    let modelLimits = prev?.modelLimits;
    if (modelLimits?.fable && rl.sevenDOI && rl.sevenDOI.utilization < 1) {
      modelLimits = { ...modelLimits };
      delete modelLimits.fable;
    }
    state.set(token, {
      name,
      limited: rejected,
      limitedUntil: rejected ? rl.reset : 0,
      claim: rl.claim,
      expired: false,
      resetAt: rl.fiveH?.reset || 0,
      resetAt7d: rl.sevenD?.reset || 0,
      retryAfter: 0,
      utilization5h: rl.fiveH?.utilization || 0,
      utilization7d: rl.sevenD?.utilization || 0,
      // Not every response carries the per-model bucket  - keep the last reading.
      utilization7dOI: rl.sevenDOI ? rl.sevenDOI.utilization : (prev?.utilization7dOI ?? null),
      resetAt7dOI: rl.sevenDOI ? rl.sevenDOI.reset : (prev?.resetAt7dOI || 0),
      modelLimits,
      updatedAt: Date.now(),
    });
  }

  /**
   * Record a 429 that carries `anthropic-ratelimit-unified-status: rejected`.
   * A per-model claim (Fable bucket, weekly Opus, weekly Sonnet) only blocks that model
   * family; any other claim blocks the whole account until the claim's reset.
   * Returns { scope: 'model' | 'account', family, until } (epoch seconds).
   */
  function markRejected(token, name, headers, now = Date.now()) {
    const rl = parseRateLimitHeaders(headers);
    const prev = state.get(token) || {};
    const nowSec = Math.floor(now / 1000);
    const next = { ...prev, name, updatedAt: now };
    if (rl.fiveH) { next.utilization5h = rl.fiveH.utilization; next.resetAt = rl.fiveH.reset; }
    if (rl.sevenD) { next.utilization7d = rl.sevenD.utilization; next.resetAt7d = rl.sevenD.reset; }
    if (rl.sevenDOI) { next.utilization7dOI = rl.sevenDOI.utilization; next.resetAt7dOI = rl.sevenDOI.reset; }
    const until = rl.reset > nowSec ? rl.reset : 0;
    const family = MODEL_CLAIMS[rl.claim];
    if (family) {
      next.modelLimits = { ...(prev.modelLimits || {}), [family]: until || nowSec + 3600 };
      state.set(token, next);
      return { scope: 'model', family, until: next.modelLimits[family] };
    }
    next.limited = true;
    next.claim = rl.claim;
    // Unknown reset → short back-off; the next response re-learns the real state.
    next.limitedUntil = until || nowSec + 300;
    state.set(token, next);
    return { scope: 'account', until: next.limitedUntil };
  }

  /** Seed state from a persisted snapshot (after a restart), keeping its timestamp. */
  function restore(token, name, data) {
    if (!data) return;
    state.set(token, {
      name,
      limited: !!data.limitedUntil && data.limitedUntil > Math.floor(Date.now() / 1000),
      limitedUntil: data.limitedUntil || 0,
      claim: data.claim || null,
      expired: false,
      resetAt: data.resetAt || 0,
      resetAt7d: data.resetAt7d || 0,
      retryAfter: 0,
      utilization5h: data.utilization5h || 0,
      utilization7d: data.utilization7d || 0,
      utilization7dOI: data.utilization7dOI ?? null,
      resetAt7dOI: data.resetAt7dOI || 0,
      modelLimits: data.modelLimits || undefined,
      updatedAt: data.updatedAt || 0,
    });
  }

  function markLimited(token, name, retryAfterSec = 0) {
    const prev = state.get(token) || {};
    state.set(token, {
      ...prev, name, limited: true,
      retryAfter: retryAfterSec ? Date.now() + retryAfterSec * 1000 : prev.retryAfter || 0,
      updatedAt: Date.now(),
    });
  }

  function markExpired(token, name) {
    const prev = state.get(token) || {};
    state.set(token, { ...prev, name, expired: true, updatedAt: Date.now() });
  }

  function clearBillingCooldown(token) {
    const prev = state.get(token);
    if (prev && prev.retryAfter > 0) {
      state.set(token, { ...prev, retryAfter: 0, updatedAt: Date.now() });
    }
  }

  function get(token) {
    return state.get(token);
  }

  function entries() {
    return state.entries();
  }

  function clear() {
    state.clear();
  }

  function remove(token) {
    state.delete(token);
  }

  /** Move all state to a refreshed token (same account), losing nothing. */
  function transfer(oldToken, newToken) {
    const prev = state.get(oldToken);
    if (!prev || oldToken === newToken) return;
    state.set(newToken, { ...prev });
    state.delete(oldToken);
  }

  return { update, markRejected, restore, transfer, markLimited, markExpired, clearBillingCooldown, get, entries, clear, remove };
}

// ─────────────────────────────────────────────────
// In-flight request tracking (for `balance` load-balancing)
// ─────────────────────────────────────────────────

/**
 * Tracks the number of concurrent in-flight requests per account.
 *
 * Keyed by account NAME (the credential file basename), NOT token/fingerprint:
 * a token refresh changes the fingerprint but keeps the name stable, so an
 * in-place refresh needs zero slot bookkeeping. `release` is underflow-guarded
 * and double-release safe, so the caller's single finally-release can never
 * drive a counter negative.
 */
export function createInflightTracker() {
  const counts = new Map();

  function acquire(name) {
    const n = (counts.get(name) || 0) + 1;
    counts.set(name, n);
    return n;
  }

  function release(name) {
    const n = counts.get(name) || 0;
    if (n <= 1) counts.delete(name);
    else counts.set(name, n - 1);
    return Math.max(0, n - 1);
  }

  function get(name) {
    return counts.get(name) || 0;
  }

  function total() {
    let sum = 0;
    for (const n of counts.values()) sum += n;
    return sum;
  }

  function snapshot() {
    return Object.fromEntries(counts);
  }

  return { acquire, release, get, total, snapshot };
}

/**
 * Concurrency limiter for `balance` mode: wraps an in-flight tracker with a
 * wait-for-slot queue and overflow-on-timeout, so the wait/overflow/wakeup
 * mechanics are unit-testable independently of the proxy.
 *
 * Timers and the clock are injectable for deterministic tests.
 *
 * acquire(pick, { cap, waitMs }):
 *   - pick() returns the currently-best candidate as `{ key, inflight, ...rest }`
 *     or null. It is re-invoked on every loop turn (in-flight counts change while
 *     waiting), so it must read live counts.
 *   - If the best candidate is under `cap`, acquires its slot and returns
 *     `{ ...candidate, overflow: false }`.
 *   - If every candidate is at the cap, waits up to `waitMs` for a freed slot
 *     (woken by release()), then OVERFLOWS onto the best candidate
 *     (`overflow: true`) rather than dropping. Returns null only when pick()
 *     returns null (genuine exhaustion).
 *
 * release(name) frees a slot and wakes the longest-waiting acquirer.
 */
export function createBalanceLimiter({ now = () => Date.now(), setTimer = setTimeout, clearTimer = clearTimeout } = {}) {
  const inflight = createInflightTracker();
  const waiters = []; // [{ resolve, timer }] — FIFO

  function wake() {
    const w = waiters.shift();
    if (w) { clearTimer(w.timer); w.resolve(); }
  }

  function release(name) {
    inflight.release(name);
    wake();
  }

  async function acquire(pick, { cap, waitMs }) {
    const deadline = now() + waitMs;
    for (;;) {
      const best = pick();
      if (!best) return null;
      if (best.inflight < cap) {
        inflight.acquire(best.key);
        return { ...best, overflow: false };
      }
      const remaining = deadline - now();
      if (remaining <= 0) {
        inflight.acquire(best.key);
        return { ...best, overflow: true };
      }
      await new Promise(resolve => {
        const entry = { resolve, timer: null };
        entry.timer = setTimer(() => {
          const i = waiters.indexOf(entry);
          if (i !== -1) waiters.splice(i, 1);
          resolve();
        }, Math.min(remaining, 1000));
        waiters.push(entry);
      });
    }
  }

  return {
    inflight,
    acquire,
    release,
    get: (name) => inflight.get(name),
    total: () => inflight.total(),
    snapshot: () => inflight.snapshot(),
    waitingCount: () => waiters.length,
  };
}

// ─────────────────────────────────────────────────
// Account availability & selection
// ─────────────────────────────────────────────────

/**
 * Can this account take a request right now? `model` (optional) makes the check
 * model-aware: a Fable request also needs headroom in the per-model weekly bucket.
 */
export function isAccountAvailable(token, expiresAt, stateManager, now = Date.now(), model = null) {
  const nowSec = Math.floor(now / 1000);
  const acctState = stateManager.get(token);

  // Token expired according to saved expiresAt
  if (expiresAt && expiresAt < now) return false;
  // Marked expired by a 401
  if (acctState?.expired) return false;
  // Limited: unavailable if ANY active cooldown hasn't passed yet
  if (acctState?.limited) {
    if (acctState.retryAfter && acctState.retryAfter >= now) return false;   // billing cooldown active
    if (acctState.limitedUntil) {
      if (acctState.limitedUntil > nowSec) return false;                     // rejected until the claim resets
    } else if (acctState.resetAt && acctState.resetAt >= nowSec) {
      return false;                                                          // 5h rate-limit active
    }
  }
  // A used-up window (5h, weekly, or this model's bucket) blocks until it resets.
  if (isAccountExhausted(acctState, model, now)) return false;
  return true;
}

export function scoreAccount(token, stateManager) {
  const acctState = stateManager.get(token);
  if (!acctState) return 0; // unknown = fresh, try first
  return acctState.utilization5h || 0;
}

export function pickBestAccount(accounts, stateManager, excludeTokens = new Set(), model = null) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager, Date.now(), model))
    .map(a => ({ ...a, score: scoreAccount(a.token, stateManager) }))
    .sort((a, b) => a.score - b.score);
  return candidates[0] || null;
}

export function pickDrainFirst(accounts, stateManager, excludeTokens = new Set(), model = null) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager, Date.now(), model))
    .map(a => ({ ...a, score: scoreAccount(a.token, stateManager) }))
    .sort((a, b) => b.score - a.score); // highest utilization first
  return candidates[0] || null;
}

/**
 * Score for the "conserve" strategy.
 * Concentrates usage on accounts whose windows are already active.
 * Weekly utilization is primary (scarce resource  - resets once/week).
 * 5hr utilization is secondary tiebreaker.
 * Untouched accounts (0% on both) score 0  - their windows stay dormant.
 */
export function scoreAccountConserve(token, stateManager) {
  const acctState = stateManager.get(token);
  if (!acctState) return 0; // unknown = untouched, preserve it
  const w7d = acctState.utilization7d || 0;
  const w5h = acctState.utilization5h || 0;
  // Weekly dominates (×100), 5hr is tiebreaker (×1)
  return w7d * 100 + w5h;
}

export function pickConserve(accounts, stateManager, excludeTokens = new Set(), model = null) {
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager, Date.now(), model))
    .map(a => ({ ...a, score: scoreAccountConserve(a.token, stateManager) }))
    .sort((a, b) => b.score - a.score); // highest combined utilization first
  return candidates[0] || null;
}

export function pickAnyUntried(accounts, excludeTokens) {
  return accounts.find(a => !excludeTokens.has(a.token)) || null;
}

/**
 * Pick the least-loaded available account for concurrency load-balancing (`balance` mode).
 *
 * Among accounts that are available (not limited/expired/cooling-down/used-up for this
 * model) and not excluded, prefers accounts that are not nearly full, then the lowest load
 * (in-flight requests plus `extraLoad`, e.g. warm session lanes pinned there), then the
 * lowest utilization. `prefer` names an account to take when it has a free slot and
 * headroom (keeps a session's subagents next to their parent). The returned `overCap`
 * flag is true when the chosen account is already at or above `cap`  - the caller decides
 * whether to wait for a slot or overflow.
 *
 * @param {Array}  accounts        - account objects { name, token, expiresAt, ... }
 * @param {object} inflightTracker - createInflightTracker() instance (keyed by account name)
 * @param {object} stateManager    - account state manager
 * @param {number} cap             - max concurrent in-flight per account
 * @param {Set}    excludeTokens   - tokens to skip (already tried this request)
 * @param {number} [now]           - current time (for testing cooldown windows)
 * @param {object} [opts]          - { model, extraLoad: { [name]: n }, prefer: name }
 * @returns {{ account: object, inflight: number, overCap: boolean } | null}
 */
export function pickLeastLoaded(accounts, inflightTracker, stateManager, cap, excludeTokens = new Set(), now = Date.now(), opts = {}) {
  const { model = null, extraLoad = null, prefer = null } = opts;
  const candidates = accounts
    .filter(a => !excludeTokens.has(a.token) && isAccountAvailable(a.token, a.expiresAt, stateManager, now, model))
    .map(a => {
      const inflight = inflightTracker.get(a.name);
      const score = usageScore(stateManager.get(a.token), model);
      return {
        account: a,
        inflight,
        load: inflight + ((extraLoad && extraLoad[a.name]) || 0),
        score,
        nearFull: score >= NEAR_FULL_UTILIZATION ? 1 : 0,
      };
    })
    .sort((x, y) => (x.nearFull - y.nearFull) || (x.load - y.load) || (x.score - y.score));

  let best = candidates[0];
  if (!best) return null;
  if (prefer) {
    const p = candidates.find(c => c.account.name === prefer);
    if (p && !p.nearFull && p.inflight < cap) best = p;
  }
  return { account: best.account, inflight: best.inflight, overCap: best.inflight >= cap };
}

// ─────────────────────────────────────────────────
// Rotation strategies
// ─────────────────────────────────────────────────

export const ROTATION_STRATEGIES = {
  sticky:        { label: 'Sticky',        desc: 'Stay on current account, only switch on rate limit' },
  conserve:      { label: 'Conserve',      desc: 'Max out active accounts first  - untouched windows stay dormant' },
  'round-robin': { label: 'Round-robin',   desc: 'Rotate to lowest-utilization account on a timer' },
  spread:        { label: 'Spread',        desc: 'Always pick lowest utilization (switches often)' },
  'drain-first': { label: 'Drain first',   desc: 'Use highest 5hr-utilization account first' },
  balance:       { label: 'Balance',       desc: 'Spread sessions across accounts by load, capped per account' },
};

export const ROTATION_INTERVALS = [15, 30, 60, 120]; // minutes

/**
 * Pick the proactive account based on rotation strategy.
 * Returns null if the current account should be kept (sticky / timer not elapsed).
 *
 * @param {object} opts
 * @param {string} opts.strategy - 'sticky' | 'conserve' | 'round-robin' | 'spread' | 'drain-first'
 * @param {number} opts.intervalMin - rotation interval in minutes (for round-robin)
 * @param {string|null} opts.currentToken - token currently in the keychain
 * @param {number} opts.lastRotationTime - timestamp of last proactive rotation
 * @param {Array} opts.accounts - all account objects
 * @param {object} opts.stateManager - account state manager
 * @param {Set} opts.excludeTokens - tokens to exclude
 * @param {string} [opts.model] - requested model (skips accounts whose bucket for it is used up)
 * @param {number} [opts.now] - current time (for testing)
 * @returns {{ account: object|null, rotated: boolean }}
 */
export function pickByStrategy(opts) {
  const {
    strategy, intervalMin, currentToken, lastRotationTime,
    accounts, stateManager, excludeTokens = new Set(),
    model = null,
    now = Date.now(),
  } = opts;

  // For all strategies: if current account is unavailable, always pick a replacement
  const currentAcct = accounts.find(a => a.token === currentToken);
  const currentAvailable = currentToken && currentAcct &&
    isAccountAvailable(currentToken, currentAcct.expiresAt, stateManager, now, model);

  if (!currentAvailable) {
    // Must switch  - pick lowest utilization as safe default
    const best = pickBestAccount(accounts, stateManager, excludeTokens, model);
    return { account: best, rotated: !!best };
  }

  switch (strategy) {
    case 'sticky':
      // Never proactively switch  - keep current
      return { account: null, rotated: false };

    case 'conserve': {
      // Pick account with highest weekly utilization (windows already active)
      // Untouched accounts stay dormant  - their windows don't start
      const conserved = pickConserve(accounts, stateManager, excludeTokens, model);
      if (conserved && conserved.token !== currentToken) {
        return { account: conserved, rotated: true };
      }
      return { account: null, rotated: false };
    }

    case 'round-robin': {
      const elapsed = now - (lastRotationTime || 0);
      const intervalMs = (intervalMin || 60) * 60 * 1000;
      if (elapsed < intervalMs) {
        return { account: null, rotated: false }; // timer not elapsed
      }
      const best = pickBestAccount(accounts, stateManager, excludeTokens, model);
      if (best && best.token !== currentToken) {
        return { account: best, rotated: true };
      }
      return { account: null, rotated: false }; // already on best
    }

    case 'spread':
      // Always pick lowest utilization (current behavior)
      const lowest = pickBestAccount(accounts, stateManager, excludeTokens, model);
      if (lowest && lowest.token !== currentToken) {
        return { account: lowest, rotated: true };
      }
      return { account: null, rotated: false };

    case 'drain-first': {
      const drain = pickDrainFirst(accounts, stateManager, excludeTokens, model);
      if (drain && drain.token !== currentToken) {
        return { account: drain, rotated: true };
      }
      return { account: null, rotated: false };
    }

    default:
      return { account: null, rotated: false };
  }
}

// ─────────────────────────────────────────────────
// Earliest reset time
// ─────────────────────────────────────────────────

export function getEarliestReset(stateManager) {
  let earliest = Infinity;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [, acctState] of stateManager.entries()) {
    // Check 5h reset
    if (acctState.resetAt && acctState.resetAt > nowSec && acctState.resetAt < earliest) {
      earliest = acctState.resetAt;
    }
    // Check 7d reset
    if (acctState.resetAt7d && acctState.resetAt7d > nowSec && acctState.resetAt7d < earliest) {
      earliest = acctState.resetAt7d;
    }
  }
  if (earliest === Infinity) return 'unknown';
  const d = new Date(earliest * 1000);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ─────────────────────────────────────────────────
// Probe cost tracking (rolling 7-day window)
// ─────────────────────────────────────────────────

const PROBE_INPUT_TOKENS = 11;
const PROBE_OUTPUT_TOKENS = 5;
const PROBE_LOG_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

export function createProbeTracker(maxAge = PROBE_LOG_MAX_AGE) {
  const log = [];

  function record(ts = Date.now()) {
    log.push({ ts });
    // Prune entries older than max age
    const cutoff = Date.now() - maxAge;
    while (log.length && log[0].ts < cutoff) log.shift();
  }

  function getStats() {
    const cutoff = Date.now() - maxAge;
    const recent = log.filter(p => p.ts >= cutoff);
    const count = recent.length;
    return {
      probeCount7d: count,
      inputTokens: count * PROBE_INPUT_TOKENS,
      outputTokens: count * PROBE_OUTPUT_TOKENS,
    };
  }

  function getLog() {
    return log;
  }

  function load(entries) {
    if (!entries || !entries.length) return;
    const cutoff = Date.now() - maxAge;
    const valid = entries.filter(e => e.ts >= cutoff);
    log.length = 0;
    for (const e of valid) log.push(e);
  }

  function toJSON() {
    return log.slice();
  }

  return { record, getStats, getLog, load, toJSON };
}

// Re-export constants for tests
export { PROBE_INPUT_TOKENS, PROBE_OUTPUT_TOKENS, PROBE_LOG_MAX_AGE };

// ─────────────────────────────────────────────────
// Utilization history (for sparklines & velocity)
// ─────────────────────────────────────────────────

const HISTORY_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const HISTORY_MIN_INTERVAL = 2 * 60 * 1000; // 2 min between points

export { HISTORY_MAX_AGE, HISTORY_MIN_INTERVAL };

export function createUtilizationHistory(maxAge = HISTORY_MAX_AGE, minInterval = HISTORY_MIN_INTERVAL) {
  // Map<fingerprint, Array<{ ts, u5h, u7d }>>
  const history = new Map();

  function record(fingerprint, u5h, u7d, ts = Date.now()) {
    if (!history.has(fingerprint)) history.set(fingerprint, []);
    const arr = history.get(fingerprint);
    // If the last entry is too recent, update it in place (keeps latest value)
    if (arr.length > 0 && ts - arr[arr.length - 1].ts < minInterval) {
      arr[arr.length - 1] = { ts, u5h, u7d };
    } else {
      arr.push({ ts, u5h, u7d });
    }
    // Prune entries older than the window
    const cutoff = ts - maxAge;
    while (arr.length > 0 && arr[0].ts < cutoff) arr.shift();
  }

  function getHistory(fingerprint) {
    return history.get(fingerprint) || [];
  }

  /**
   * Calculate utilization velocity (change per hour) for the 5h window.
   * Uses only the last 30 minutes of data to reflect current usage rate,
   * not stale history from hours ago that inflates the slope.
   * Returns null if insufficient data.
   */
  function getVelocity(fingerprint) {
    const arr = history.get(fingerprint);
    if (!arr || arr.length < 2) return null;
    // Use recent window (last 30 min) for velocity, not entire history
    const recentCutoff = Date.now() - 30 * 60 * 1000;
    const recent = arr.filter(e => e.ts >= recentCutoff);
    if (recent.length < 2) return null;
    const first = recent[0];
    const last = recent[recent.length - 1];
    const timeDeltaHrs = (last.ts - first.ts) / (1000 * 60 * 60);
    if (timeDeltaHrs < 0.16) return null; // need at least ~10 min of recent data
    const utilizationDelta = last.u5h - first.u5h;
    return utilizationDelta / timeDeltaHrs; // change per hour (0-1 scale)
  }

  /**
   * Predict minutes until 5h utilization reaches 1.0 (rate limit).
   * Returns null if velocity is <= 0 or insufficient data.
   */
  function predictMinutesToLimit(fingerprint) {
    const arr = history.get(fingerprint);
    if (!arr || arr.length < 2) return null;
    const velocity = getVelocity(fingerprint);
    if (!velocity || velocity <= 0) return null;
    const current = arr[arr.length - 1].u5h;
    const remaining = 1.0 - current;
    if (remaining <= 0) return 0;
    return Math.round((remaining / velocity) * 60); // minutes
  }

  function getAllFingerprints() {
    return [...history.keys()];
  }

  function load(fingerprint, entries) {
    if (!entries || !entries.length) {
      history.set(fingerprint, []);
      return;
    }
    const cutoff = Date.now() - maxAge;
    const valid = entries.filter(e => e.ts >= cutoff);
    history.set(fingerprint, valid);
  }

  function toJSON() {
    const out = {};
    for (const [fp, arr] of history.entries()) {
      if (arr.length) out[fp] = arr;
    }
    return out;
  }

  function clear() {
    history.clear();
  }

  return { record, getHistory, getVelocity, predictMinutesToLimit, getAllFingerprints, load, toJSON, clear };
}

// ─────────────────────────────────────────────────
// OAuth Token Refresh  - Pure Functions
// ─────────────────────────────────────────────────

/**
 * Build JSON POST body for the OAuth token refresh endpoint.
 */
export function buildRefreshRequestBody(refreshToken, clientId, scope) {
  const body = { grant_type: 'refresh_token', refresh_token: refreshToken };
  if (clientId) body.client_id = clientId;
  if (scope) body.scope = scope;
  return JSON.stringify(body);
}

/**
 * Parse the OAuth refresh endpoint response.
 * Returns { ok, accessToken, refreshToken, expiresIn } on success,
 * or { ok: false, error, retriable } on failure.
 */
export function parseRefreshResponse(statusCode, bodyStr) {
  if (statusCode >= 200 && statusCode < 300) {
    try {
      const data = JSON.parse(bodyStr);
      const accessToken = data.access_token || data.accessToken;
      const refreshToken = data.refresh_token || data.refreshToken;
      const expiresIn = data.expires_in || data.expiresIn || 0;
      if (!accessToken) {
        return { ok: false, error: 'No access_token in response', retriable: false };
      }
      return { ok: true, accessToken, refreshToken: refreshToken || null, expiresIn };
    } catch (e) {
      return { ok: false, error: `Invalid JSON: ${e.message}`, retriable: false };
    }
  }
  // Retriable: 429 (rate limit), 500+ (server errors)
  const retriable = statusCode === 429 || statusCode >= 500;
  let error = `HTTP ${statusCode}`;
  try {
    const data = JSON.parse(bodyStr);
    const raw = data.error_description || data.error || data.message || error;
    error = typeof raw === 'string' ? raw : (raw && raw.message) || JSON.stringify(raw);
  } catch {}
  return { ok: false, error, retriable };
}

/**
 * Convert expires_in (seconds) to an absolute millisecond timestamp.
 */
export function computeExpiresAt(expiresInSec, now = Date.now()) {
  return now + expiresInSec * 1000;
}

/**
 * Immutably build updated credentials, preserving all fields except tokens/expiry.
 */
export function buildUpdatedCreds(oldCreds, newAccessToken, newRefreshToken, newExpiresAt) {
  return {
    ...oldCreds,
    claudeAiOauth: {
      ...oldCreds.claudeAiOauth,
      accessToken: newAccessToken,
      ...(newRefreshToken != null ? { refreshToken: newRefreshToken } : {}),
      expiresAt: newExpiresAt,
    },
  };
}

/**
 * Returns true if the token is within bufferMs of expiry.
 * Returns false for unknown/falsy expiresAt (don't proactively refresh unknown tokens).
 */
export function shouldRefreshToken(expiresAt, bufferMs = 60 * 60 * 1000, now = Date.now()) {
  if (!expiresAt) return false;
  return expiresAt - now <= bufferMs;
}

/**
 * Promise-chain mutex keyed by account name.
 * Ensures only one refresh runs per account at a time.
 */
export function createPerAccountLock() {
  const locks = new Map();

  function withLock(key, fn) {
    const prev = locks.get(key) || Promise.resolve();
    let release;
    const next = new Promise(r => { release = r; });
    locks.set(key, next);
    return prev.then(fn).finally(release);
  }

  return { withLock };
}

// ─────────────────────────────────────────────────
// Session affinity
// ─────────────────────────────────────────────────
//
// Prompt caches live per account: moving a warm conversation to another account
// re-writes its whole cache (1.25-2x input price) instead of reading it (~0.1x).
// A session is the Claude Code process (X-Claude-Code-Session-Id); each agent inside
// it (main loop, every subagent) is a "lane" with its own conversation and cache.
// Lanes are pinned to an account and stay there while their cache is warm.

export const AFFINITY_DEFAULT_TTL_MS = 5 * 60 * 1000;     // default prompt-cache TTL
export const AFFINITY_LONG_TTL_MS = 60 * 60 * 1000;       // `"ttl":"1h"` cache breakpoints
const SESSION_MOVES_MAX = 20;
const SESSION_RECENT_MAX = 20;
const SESSION_RETAIN_MS = 7 * 24 * 60 * 60 * 1000;        // keep idle sessions this long (UI history)
const LANE_RETAIN_MS = 24 * 60 * 60 * 1000;               // drop lanes idle this long

// Request bodies can be megabytes: these helpers take a Buffer or a string and only
// decode the small slices they need.
function textSlice(body, start, end) {
  if (!body) return '';
  return Buffer.isBuffer(body) ? body.subarray(start, end).toString('utf8') : String(body).slice(start, end);
}

/** Prompt-cache TTL a request body asks for (1h when any breakpoint uses it). */
export function cacheTtlFromBody(body) {
  if (!body) return AFFINITY_DEFAULT_TTL_MS;
  return body.indexOf('"ttl":"1h"') !== -1 || body.indexOf('"ttl": "1h"') !== -1
    ? AFFINITY_LONG_TTL_MS : AFFINITY_DEFAULT_TTL_MS;
}

/** Session id from Claude Code's request header, else from `metadata.user_id` in the body. */
export function extractSessionId(headers = {}, body = '') {
  const h = headers['x-claude-code-session-id'];
  if (h) return String(Array.isArray(h) ? h[0] : h);
  const i = body ? body.lastIndexOf('"user_id"') : -1;
  if (i === -1) return null;
  const tail = textSlice(body, i, i + 600);
  const m = tail.match(/session_id\\?"\s*:\s*\\?"([0-9a-f-]{16,})/i) || tail.match(/_session_([0-9a-f-]{16,})/i);
  return m ? m[1] : null;
}

/** Model named in a request body (the SDK writes `model` first; only scan the head). */
export function extractModel(body) {
  const m = textSlice(body, 0, 2048).match(/"model"\s*:\s*"([^"]+)"/);
  return m ? m[1] : null;
}

/**
 * Display label for a session: the user's /rename name when it has one,
 * else `branch:shortId` (or `folder:shortId`, or the short id).
 */
export function sessionLabel(meta = {}, id = '') {
  if (meta.name && meta.nameSource === 'user') return meta.name;
  if (meta.customTitle) return meta.customTitle;
  const short = String(id).slice(0, 8);
  if (meta.branch) return `${meta.branch}:${short}`;
  if (meta.cwd) return `${String(meta.cwd).split('/').filter(Boolean).pop() || meta.cwd}:${short}`;
  return short;
}

/**
 * Affinity health of a session.
 * - strong: no cache-busting (warm) move in the last hour and >=95% of recent requests on one account
 * - ok:     at most one warm move in the last hour and >=70% on one account
 * - weak:   anything worse
 * cacheHit = cache reads / total prompt tokens over recent requests (null = no data yet).
 */
export function sessionAffinity(session, now = Date.now()) {
  const hourAgo = now - 60 * 60 * 1000;
  const warmMoves1h = (session.moves || []).filter(m => m.warm && m.ts >= hourAgo).length;
  const recent = session.recent || [];
  const counts = {};
  let prompt = 0, read = 0;
  for (const r of recent) {
    counts[r.account] = (counts[r.account] || 0) + 1;
    prompt += r.prompt || 0;
    read += r.cacheRead || 0;
  }
  const top = Math.max(0, ...Object.values(counts));
  // Spread over accounts only means something once there are a few requests to judge
  const share = recent.length >= 6 ? top / recent.length : 1;
  let level = 'strong';
  if (warmMoves1h >= 2 || share < 0.7) level = 'weak';
  else if (warmMoves1h === 1 || share < 0.95) level = 'ok';
  return { level, warmMoves1h, share, cacheHit: prompt > 0 ? read / prompt : null, moves: (session.moves || []).length };
}

export function createSessionStore({ now = () => Date.now() } = {}) {
  const sessions = new Map();

  function ensure(id, t = now()) {
    let s = sessions.get(id);
    if (!s) {
      s = { id, firstAt: t, lastAt: t, requests: 0, model: null, meta: {}, lanes: {}, accounts: {}, moves: [], recent: [], artifacts: [] };
      sessions.set(id, s);
    }
    return s;
  }

  /** Where a lane is pinned: { account, warm, idleMs } or null (new lane / unpinned). */
  function route(id, agent = 'main', t = now()) {
    const lane = sessions.get(id)?.lanes[agent];
    if (!lane || !lane.account) return null;
    const idleMs = t - lane.lastAt;
    return { account: lane.account, warm: idleMs < lane.ttlMs, idleMs };
  }

  /**
   * The session's home account: its main lane's account, else its most recently used
   * lane's. A lane released by unpinAll still counts its last account.
   */
  function home(id) {
    const s = sessions.get(id);
    if (!s) return null;
    const acctOf = (lane) => (lane && (lane.account || lane.prevAccount)) || null;
    if (acctOf(s.lanes.main)) return acctOf(s.lanes.main);
    let best = null;
    for (const lane of Object.values(s.lanes)) {
      if (acctOf(lane) && (!best || lane.lastAt > best.lastAt)) best = lane;
    }
    return acctOf(best);
  }

  /**
   * Pin a lane to an account. Returns the recorded move ({ from, to, reason, warm })
   * when the lane changes accounts, else null. A warm move busts the lane's cache.
   */
  function pin(id, agent, account, { reason = 'assign', ttlMs, t = now() } = {}) {
    const s = ensure(id, t);
    const lane = s.lanes[agent];
    if (lane && lane.account === account) {
      lane.lastAt = Math.max(lane.lastAt, t);
      return null;
    }
    const from = lane ? (lane.account || lane.prevAccount || null) : null;
    let move = null;
    if (from && from !== account) {
      move = { ts: t, agent, from, to: account, reason: lane.unpinReason || reason, warm: t - lane.lastAt < lane.ttlMs };
      s.moves.push(move);
      if (s.moves.length > SESSION_MOVES_MAX) s.moves.splice(0, s.moves.length - SESSION_MOVES_MAX);
    }
    s.lanes[agent] = { account, pinnedAt: t, lastAt: t, ttlMs: Math.max(ttlMs || 0, lane?.ttlMs || 0) || AFFINITY_DEFAULT_TTL_MS };
    s.lastAt = Math.max(s.lastAt, t);
    return move;
  }

  /** Mark a lane as used now (keeps its cache window warm). */
  function touch(id, agent, { ttlMs, t = now() } = {}) {
    const s = sessions.get(id);
    if (!s) return;
    s.lastAt = Math.max(s.lastAt, t);
    const lane = s.lanes[agent];
    if (lane) {
      lane.lastAt = Math.max(lane.lastAt, t);
      // Side calls (titles, quick checks) share the lane with a shorter TTL: never shrink it
      if (ttlMs) lane.ttlMs = Math.max(lane.ttlMs || 0, ttlMs);
    }
  }

  /** Record a completed request: per-account totals and the recent-request window. */
  function recordRequest(id, agent, account, usage, { model, ttlMs, t = now() } = {}) {
    const s = ensure(id, t);
    s.lastAt = Math.max(s.lastAt, t);
    s.requests++;
    if (model) s.model = model;
    touch(id, agent, { ttlMs, t });
    const a = s.accounts[account] || (s.accounts[account] = {
      requests: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0, firstAt: t, lastAt: t,
    });
    a.requests++;
    a.lastAt = t;
    const u = usage || {};
    const cacheWrite = (u.cacheWrite5m || 0) + (u.cacheWrite1h || 0);
    a.input += u.input || 0;
    a.output += u.output || 0;
    a.cacheRead += u.cacheRead || 0;
    a.cacheWrite += cacheWrite;
    a.cost += u.cost || 0;
    s.recent.push({ t, account, agent, prompt: (u.input || 0) + (u.cacheRead || 0) + cacheWrite, cacheRead: u.cacheRead || 0 });
    if (s.recent.length > SESSION_RECENT_MAX) s.recent.splice(0, s.recent.length - SESSION_RECENT_MAX);
  }

  /** Release every pin (manual switch): next request re-pins and is recorded as a move. */
  function unpinAll(reason = 'manual-switch') {
    for (const s of sessions.values()) {
      for (const lane of Object.values(s.lanes)) {
        if (!lane.account) continue;
        lane.prevAccount = lane.account;
        lane.account = null;
        lane.unpinReason = reason;
      }
    }
  }

  /** Release pins on one account (it was removed). */
  function unpinAccount(account, reason = 'account-removed') {
    for (const s of sessions.values()) {
      for (const lane of Object.values(s.lanes)) {
        if (lane.account !== account) continue;
        lane.prevAccount = account;
        lane.account = null;
        lane.unpinReason = reason;
      }
    }
  }

  /** Warm lanes per account: { [account]: n }  - the load balance mode expects next. */
  function warmLoad(t = now()) {
    const out = {};
    for (const s of sessions.values()) {
      for (const lane of Object.values(s.lanes)) {
        if (lane.account && t - lane.lastAt < lane.ttlMs) out[lane.account] = (out[lane.account] || 0) + 1;
      }
    }
    return out;
  }

  // Meta lookups run async and can land before the session's first request is booked.
  function setMeta(id, meta) {
    if (meta) Object.assign(ensure(id).meta, meta);
  }

  function addArtifact(id, slug) {
    const s = ensure(id);
    if (s.artifacts.includes(slug)) return false;
    s.artifacts.push(slug);
    if (s.artifacts.length > 100) s.artifacts.shift();
    return true;
  }

  /** Renamed account (same login, new file name)  - keep pins and stats. */
  function renameAccount(from, to) {
    if (!from || !to || from === to) return;
    for (const s of sessions.values()) {
      for (const lane of Object.values(s.lanes)) {
        if (lane.account === from) lane.account = to;
        if (lane.prevAccount === from) lane.prevAccount = to;
      }
      if (s.accounts[from]) {
        s.accounts[to] = s.accounts[to] || s.accounts[from];
        delete s.accounts[from];
      }
      for (const r of s.recent) if (r.account === from) r.account = to;
    }
  }

  function prune(t = now()) {
    for (const [id, s] of sessions) {
      if (t - s.lastAt > SESSION_RETAIN_MS) { sessions.delete(id); continue; }
      for (const [agent, lane] of Object.entries(s.lanes)) {
        if (t - lane.lastAt > LANE_RETAIN_MS) delete s.lanes[agent];
      }
    }
  }

  function get(id) { return sessions.get(id) || null; }
  function all() { return [...sessions.values()]; }
  function size() { return sessions.size; }
  function toJSON() { return { v: 1, sessions: all() }; }
  function load(data) {
    sessions.clear();
    for (const s of data?.sessions || []) {
      if (!s || !s.id) continue;
      sessions.set(s.id, {
        id: s.id, firstAt: s.firstAt || 0, lastAt: s.lastAt || 0, requests: s.requests || 0,
        model: s.model || null, meta: s.meta || {}, lanes: s.lanes || {}, accounts: s.accounts || {},
        moves: s.moves || [], recent: s.recent || [], artifacts: s.artifacts || [],
      });
    }
  }

  return {
    route, home, pin, touch, recordRequest, unpinAll, unpinAccount, warmLoad,
    setMeta, addArtifact, renameAccount, prune, get, all, size, toJSON, load,
  };
}

// ─────────────────────────────────────────────────
// Token usage extraction
// ─────────────────────────────────────────────────

/** Normalize a Messages API `usage` object (cache writes split by TTL). */
export function normalizeUsage(u) {
  if (!u || typeof u !== 'object') return null;
  const write = u.cache_creation_input_tokens || 0;
  const cc = u.cache_creation || {};
  const w1h = typeof cc.ephemeral_1h_input_tokens === 'number' ? cc.ephemeral_1h_input_tokens : 0;
  const w5m = typeof cc.ephemeral_5m_input_tokens === 'number' ? cc.ephemeral_5m_input_tokens : Math.max(0, write - w1h);
  return {
    input: u.input_tokens || 0,
    output: u.output_tokens || 0,
    cacheRead: u.cache_read_input_tokens || 0,
    cacheWrite5m: w5m,
    cacheWrite1h: w1h,
    webSearches: u.server_tool_use?.web_search_requests || 0,
    speed: u.speed || null,
  };
}

const USAGE_NUMERIC = ['input', 'output', 'cacheRead', 'cacheWrite5m', 'cacheWrite1h', 'webSearches'];

/** Merge cumulative usage readings (message_start + message_delta): field-wise max. */
export function mergeUsage(a, b) {
  if (!a) return b ? { ...b } : null;
  if (!b) return { ...a };
  const out = { ...a };
  for (const k of USAGE_NUMERIC) out[k] = Math.max(a[k] || 0, b[k] || 0);
  out.speed = b.speed || a.speed || null;
  return out;
}

/**
 * Incremental parser for a streamed (SSE) Messages response. Feed decoded text as it
 * arrives; result() returns { model, usage } once message_start / message_delta were seen.
 */
export function createSSEUsageParser() {
  let buf = '';
  let event = '';
  let model = '';
  let usage = null;

  function onData(json) {
    let d;
    try { d = JSON.parse(json); } catch { return; }
    if (event === 'message_start' && d.message) {
      if (d.message.model) model = d.message.model;
      usage = mergeUsage(usage, normalizeUsage(d.message.usage));
    } else if (event === 'message_delta' && d.usage) {
      usage = mergeUsage(usage, normalizeUsage(d.usage));
    }
  }

  function feed(text) {
    buf += text;
    const lines = buf.split('\n');
    buf = lines.pop() || '';
    for (const raw of lines) {
      const line = raw.trim();
      if (line.startsWith('event:')) {
        event = line.slice(6).trim();
      } else if (line.startsWith('data:')) {
        if (event === 'message_start' || event === 'message_delta') onData(line.slice(5).trim());
        event = '';
      }
    }
  }

  return { feed, result: () => ({ model, usage }) };
}

/** { model, usage } from a non-streamed Messages response body. */
export function parseJsonUsage(bodyStr) {
  try {
    const d = JSON.parse(bodyStr);
    if (!d || d.type !== 'message' || !d.usage) return null;
    return { model: d.model || '', usage: normalizeUsage(d.usage) };
  } catch { return null; }
}

// ─────────────────────────────────────────────────
// API-equivalent pricing
// ─────────────────────────────────────────────────

// USD per million tokens [pattern, input, output, cache read]. Cache writes bill at
// 1.25x input (5 minute TTL) or 2x input (1 hour TTL). First match wins.
export const MODEL_PRICING = [
  [/fable-5-1|mythos-5-1/, 10, 50, 0.25],
  [/fable|mythos/, 10, 50, 1.0],
  [/opus-5-5/, 4, 20, 0.20],
  [/opus-5/, 5, 25, 0.50],
  [/opus-4-[5-9]/, 5, 25, 0.50],
  [/opus/, 15, 75, 1.50],
  [/sonnet-5/, 2, 10, 0.20],
  [/sonnet/, 3, 15, 0.30],
  [/haiku-4/, 1, 5, 0.10],
  [/haiku-3-5/, 0.8, 4, 0.08],
  [/haiku/, 0.25, 1.25, 0.03],
];
const DEFAULT_PRICING = { input: 3, output: 15, cacheRead: 0.30 };

export function priceFor(model) {
  const m = String(model || '').toLowerCase();
  for (const [re, input, output, cacheRead] of MODEL_PRICING) {
    if (re.test(m)) return { input, output, cacheRead };
  }
  return DEFAULT_PRICING;
}

/** What this usage would cost at API rates (USD). Fast mode bills at 2x. */
export function usageCost(usage, model) {
  if (!usage) return 0;
  const p = priceFor(model);
  const mult = usage.speed === 'fast' ? 2 : 1;
  return mult * (
    (usage.input || 0) * p.input +
    (usage.output || 0) * p.output +
    (usage.cacheRead || 0) * p.cacheRead +
    (usage.cacheWrite5m || 0) * p.input * 1.25 +
    (usage.cacheWrite1h || 0) * p.input * 2
  ) / 1e6;
}

/** Monthly subscription price (USD) for a plan; null for plans the proxy doesn't target. */
export function planMonthlyUsd(subscriptionType, rateLimitTier) {
  const sub = String(subscriptionType || '').toLowerCase();
  const tier = String(rateLimitTier || '').toLowerCase();
  if (sub === 'max' || tier.includes('max')) {
    const m = tier.match(/(\d+)x/);
    return m && parseInt(m[1], 10) >= 20 ? 200 : 100;
  }
  return null;
}

// ─────────────────────────────────────────────────
// Usage rollups (hourly rows, one file per UTC day)
// ─────────────────────────────────────────────────

export const USAGE_SUMS = ['requests', 'input', 'output', 'cacheRead', 'cacheWrite5m', 'cacheWrite1h', 'webSearches'];

export function hourStart(ts) { return Math.floor(ts / 3600000) * 3600000; }
export function utcDay(ts) { return new Date(ts).toISOString().slice(0, 10); }

function rowKey(r) {
  return [r.h, r.account, r.model, r.repo, r.branch, r.fast ? 'f' : ''].join('\u0001');
}

/** A day's rows keyed by (hour, account, model, repo, branch, speed). */
export function createUsageDay(rows = []) {
  const map = new Map();
  for (const r of rows) map.set(rowKey(r), { ...r });

  function add({ ts, account, model, repo = '', branch = '', usage }) {
    if (!usage) return;
    const base = { h: hourStart(ts), account: account || 'unknown', model: model || 'unknown', repo: repo || '', branch: branch || '', fast: usage.speed === 'fast' || undefined };
    const k = rowKey(base);
    let r = map.get(k);
    if (!r) { r = { ...base }; for (const f of USAGE_SUMS) r[f] = 0; map.set(k, r); }
    r.requests++;
    for (const f of USAGE_SUMS) if (f !== 'requests') r[f] += usage[f] || 0;
  }

  return { add, rows: () => [...map.values()], size: () => map.size };
}

/** Prompt tokens a row/total represents (uncached input + cache reads + cache writes). */
export function promptTokens(t) {
  return (t.input || 0) + (t.cacheRead || 0) + (t.cacheWrite5m || 0) + (t.cacheWrite1h || 0);
}

function emptyTotals() {
  const t = { cost: 0 };
  for (const f of USAGE_SUMS) t[f] = 0;
  return t;
}

function addTotals(t, r, cost) {
  for (const f of USAGE_SUMS) t[f] += r[f] || 0;
  t.cost += cost;
}

/**
 * Aggregate usage rows for the Usage tab.
 * opts: { since, until, filter: { repo, branch, model, account }, bucketMs, now }
 * Returns totals, per-model / per-account / per-repo+branch breakdowns and a
 * time series of { t, byModel: { model: tokens } } buckets.
 */
export function summarizeUsage(rows, opts = {}) {
  const { since = 0, until = Infinity, filter = {}, bucketMs = 86400000 } = opts;
  const totals = emptyTotals();
  const byModel = {}, byAccount = {}, byRepo = {};
  const series = new Map();
  const options = { repos: new Set(), branches: new Set(), models: new Set(), accounts: new Set() };
  for (const r of rows) {
    if (r.h < since || r.h >= until) continue;
    if (r.repo) options.repos.add(r.repo);
    options.models.add(r.model);
    options.accounts.add(r.account);
    if (filter.repo && r.repo !== filter.repo) continue;
    if (r.branch && (!filter.repo || r.repo === filter.repo)) options.branches.add(r.branch);
    if (filter.branch && r.branch !== filter.branch) continue;
    if (filter.model && r.model !== filter.model) continue;
    if (filter.account && r.account !== filter.account) continue;
    const cost = usageCost({ ...r, speed: r.fast ? 'fast' : null }, r.model);
    addTotals(totals, r, cost);
    addTotals(byModel[r.model] || (byModel[r.model] = emptyTotals()), r, cost);
    const acct = byAccount[r.account] || (byAccount[r.account] = { ...emptyTotals(), byModel: {} });
    addTotals(acct, r, cost);
    acct.byModel[r.model] = (acct.byModel[r.model] || 0) + cost;
    const repoKey = r.repo || '(no git repo)';
    const repo = byRepo[repoKey] || (byRepo[repoKey] = { ...emptyTotals(), lastTs: 0, branches: {} });
    addTotals(repo, r, cost);
    repo.lastTs = Math.max(repo.lastTs, r.h);
    const br = repo.branches[r.branch || '(none)'] || (repo.branches[r.branch || '(none)'] = { ...emptyTotals(), lastTs: 0, byModel: {} });
    addTotals(br, r, cost);
    br.lastTs = Math.max(br.lastTs, r.h);
    br.byModel[r.model] = (br.byModel[r.model] || 0) + promptTokens(r) + (r.output || 0);
    const b = Math.floor(r.h / bucketMs) * bucketMs;
    const bucket = series.get(b) || (series.set(b, { t: b, byModel: {}, cost: 0 }), series.get(b));
    bucket.byModel[r.model] = (bucket.byModel[r.model] || 0) + promptTokens(r) + (r.output || 0);
    bucket.cost += cost;
  }
  return {
    totals, byModel, byAccount, byRepo,
    series: [...series.values()].sort((a, b) => a.t - b.t),
    options: {
      repos: [...options.repos].sort(), branches: [...options.branches].sort(),
      models: [...options.models].sort(), accounts: [...options.accounts].sort(),
    },
  };
}

// ─────────────────────────────────────────────────
// Artifacts
// ─────────────────────────────────────────────────

/**
 * Artifact ids in a body (Buffer or string): claude.ai/code/artifact/<slug> and
 * claude.ai/artifact/<id>. Only the bytes around each match are decoded.
 */
export function extractArtifactRefs(body) {
  const out = new Set();
  if (!body) return out;
  const re = /claude\.ai\/(?:code\/)?artifact\/([A-Za-z0-9_-]{8,})/;
  let i = body.indexOf('claude.ai/');
  while (i !== -1) {
    const m = textSlice(body, i, i + 200).match(re);
    if (m && m.index === 0) out.add(m[1]);
    i = body.indexOf('claude.ai/', i + 10);
  }
  return out;
}

/** Does an artifact reference (from a URL) point at this frame slug? */
export function artifactRefMatches(ref, slug) {
  if (!ref || !slug) return false;
  if (ref === slug) return true;
  // claude.ai/artifact/<title>-<id> links carry the slug (or its id) at the end.
  return (slug.length >= 8 && ref.endsWith(slug)) || (ref.length >= 8 && slug.endsWith(ref));
}

/**
 * Prompt-cache efficiency over a window, overall and per account / per model, with a
 * daily trend. hit = cache reads / prompt tokens (uncached input + reads + writes);
 * rebuild = cache writes / prompt tokens (cache paid for again, e.g. after a move).
 * Trend values are null on days without traffic.
 */
export function cacheEfficiency(rows, { since = 0, until = Infinity, bucketMs = 86400000 } = {}) {
  const start = Math.floor(since / bucketMs) * bucketMs;
  const slots = Number.isFinite(until) ? Math.max(1, Math.ceil((until - start) / bucketMs)) : 1;
  const blank = () => ({ prompt: 0, read: 0, write: 0, requests: 0, trend: Array.from({ length: slots }, () => ({ prompt: 0, read: 0 })) });
  const overall = blank();
  const byAccount = {}, byModel = {};
  const add = (g, r, prompt, write, slot) => {
    g.prompt += prompt; g.read += r.cacheRead || 0; g.write += write; g.requests += r.requests || 0;
    if (slot >= 0 && slot < slots) { g.trend[slot].prompt += prompt; g.trend[slot].read += r.cacheRead || 0; }
  };
  for (const r of rows) {
    if (r.h < since || r.h >= until) continue;
    const write = (r.cacheWrite5m || 0) + (r.cacheWrite1h || 0);
    const prompt = (r.input || 0) + (r.cacheRead || 0) + write;
    if (!prompt) continue;
    const slot = Math.floor((r.h - start) / bucketMs);
    add(overall, r, prompt, write, slot);
    add(byAccount[r.account] || (byAccount[r.account] = blank()), r, prompt, write, slot);
    add(byModel[r.model] || (byModel[r.model] = blank()), r, prompt, write, slot);
  }
  const finish = (g) => ({
    prompt: g.prompt, read: g.read, write: g.write, requests: g.requests,
    hit: g.prompt ? g.read / g.prompt : null,
    rebuild: g.prompt ? g.write / g.prompt : null,
    trend: g.trend.map(t => (t.prompt ? t.read / t.prompt : null)),
  });
  const mapAll = (o) => Object.fromEntries(Object.entries(o).map(([k, g]) => [k, finish(g)]));
  return { start, bucketMs, overall: finish(overall), byAccount: mapAll(byAccount), byModel: mapAll(byModel) };
}
