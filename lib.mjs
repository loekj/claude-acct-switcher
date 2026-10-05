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

/**
 * Usage over time per account (keyed by account name: a token refresh must not start a new
 * history). One point per fixed time bucket (minInterval): a sample in the same bucket as the
 * last point updates it, so steady traffic gives one point per bucket instead of one point
 * that keeps sliding forward. A field that is null (header missing) keeps its last value.
 */
export function createUtilizationHistory(maxAge = HISTORY_MAX_AGE, minInterval = HISTORY_MIN_INTERVAL) {
  // Map<key, Array<{ ts, u5h, u7d }>> sorted by ts
  const history = new Map();
  const bucket = (ts) => Math.floor(ts / minInterval);
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.min(Math.max(v, 0), 1.5) : null);

  function record(key, u5h, u7d, ts = Date.now()) {
    if (!key) return;
    let a = num(u5h), b = num(u7d);
    if (a === null && b === null) return; // nothing known from this response
    if (!history.has(key)) history.set(key, []);
    const arr = history.get(key);
    // The clock went back (VM restore, manual change): points "from the future" are wrong
    while (arr.length && arr[arr.length - 1].ts > ts + 60000) arr.pop();
    const last = arr[arr.length - 1];
    if (last && ts < last.ts) return; // slightly out of order: ignore
    if (a === null) a = last ? last.u5h : null;
    if (b === null) b = last ? last.u7d : null;
    const point = { ts, u5h: a, u7d: b }; // null = still unknown
    if (last && bucket(last.ts) === bucket(ts)) arr[arr.length - 1] = point;
    else arr.push(point);
    const cutoff = ts - maxAge;
    while (arr.length > 0 && arr[0].ts < cutoff) arr.shift();
  }

  function getHistory(key) {
    return history.get(key) || [];
  }

  /**
   * 5h utilization change per hour over the last 30 minutes (0-1 scale), or null. Only the
   * points since the last drop count: a window reset in between is not "negative usage".
   */
  function getVelocity(key, now = Date.now()) {
    const arr = history.get(key);
    if (!arr || arr.length < 2) return null;
    const recentCutoff = now - 30 * 60 * 1000;
    let recent = arr.filter(e => e.ts >= recentCutoff && typeof e.u5h === 'number');
    for (let i = recent.length - 1; i > 0; i--) {
      if (recent[i].u5h < recent[i - 1].u5h - 0.005) { recent = recent.slice(i); break; }
    }
    if (recent.length < 2) return null;
    const first = recent[0];
    const last = recent[recent.length - 1];
    const timeDeltaHrs = (last.ts - first.ts) / (1000 * 60 * 60);
    if (timeDeltaHrs < 0.16) return null; // need at least ~10 min of data
    return (last.u5h - first.u5h) / timeDeltaHrs;
  }

  /** Minutes until 5h utilization reaches 1.0 at the current pace, or null. */
  function predictMinutesToLimit(key, now = Date.now()) {
    const arr = history.get(key);
    if (!arr || arr.length < 2) return null;
    const velocity = getVelocity(key, now);
    if (!velocity || velocity <= 0) return null;
    const lastKnown = [...arr].reverse().find(e => typeof e.u5h === 'number');
    if (!lastKnown) return null;
    const remaining = 1.0 - lastKnown.u5h;
    if (remaining <= 0) return 0;
    return Math.round((remaining / velocity) * 60);
  }

  function getAllFingerprints() {
    return [...history.keys()];
  }

  /** Replace a key's history (sorted, one point per bucket, inside the window). */
  function load(key, entries, now = Date.now()) {
    const cutoff = now - maxAge;
    const out = [];
    const sorted = (Array.isArray(entries) ? entries : [])
      .filter(e => e && Number.isFinite(e.ts) && e.ts >= cutoff && e.ts <= now + 60000)
      .sort((x, y) => x.ts - y.ts);
    for (const e of sorted) {
      const point = { ts: e.ts, u5h: num(e.u5h), u7d: num(e.u7d) };
      if (out.length && bucket(out[out.length - 1].ts) === bucket(e.ts)) out[out.length - 1] = point;
      else out.push(point);
    }
    history.set(key, out);
  }

  /** Move a history to another key (merged by time when both exist). */
  function rename(oldKey, newKey) {
    if (!history.has(oldKey) || oldKey === newKey) return;
    const merged = [...getHistory(newKey), ...getHistory(oldKey)];
    history.delete(oldKey);
    load(newKey, merged);
  }

  /** Forget a key (an account was removed: its name may be reused by another account). */
  function remove(key) { history.delete(key); }

  /** Drop points (and keys) older than the window: keys nobody records to anymore. */
  function prune(now = Date.now()) {
    const cutoff = now - maxAge;
    for (const [key, arr] of history) {
      while (arr.length > 0 && arr[0].ts < cutoff) arr.shift();
      if (!arr.length) history.delete(key);
    }
  }

  function toJSON() {
    prune();
    const out = {};
    for (const [key, arr] of history.entries()) {
      if (arr.length) out[key] = arr;
    }
    return out;
  }

  function clear() {
    history.clear();
  }

  return { record, getHistory, getVelocity, predictMinutesToLimit, getAllFingerprints, load, rename, remove, prune, toJSON, clear };
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

// ─────────────────────────────────────────────────
// Local-only access (dashboard + proxy)
// ─────────────────────────────────────────────────

const LOOPBACK_V4 = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/** True for a peer on this computer: 127.0.0.0/8, ::1, or IPv4-mapped 127.x. */
export function isLoopbackAddr(addr) {
  if (typeof addr !== 'string') return false;
  const a = addr.toLowerCase();
  if (a === '::1') return true;
  return LOOPBACK_V4.test(a.startsWith('::ffff:') ? a.slice(7) : a);
}

/**
 * True when a Host header names this computer (localhost, 127.x, [::1]). With a port,
 * a Host that carries a different port is refused. Guards against DNS rebinding.
 */
export function isLocalHost(host, port = null) {
  if (typeof host !== 'string' || !host) return false;
  const m = host.toLowerCase().match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/);
  if (!m) return false;
  const [, name, p] = m;
  if (p && port != null && Number(p) !== Number(port)) return false;
  return name === 'localhost' || name === '[::1]' || LOOPBACK_V4.test(name);
}

/** An Origin header is fine when absent, or when it is a page served from this computer. */
export function originAllowed(origin, port = null) {
  if (origin == null || origin === '') return true;
  try {
    const u = new URL(origin);
    return u.protocol === 'http:' && isLocalHost(u.host, port);
  } catch { return false; }
}

/** Same-origin check: the Origin header names exactly the Host the request was sent to. */
export function isSameOrigin(origin, host) {
  if (typeof host !== 'string' || !host) return false;
  try { return new URL(origin).host === host.toLowerCase(); } catch { return false; }
}

// ─────────────────────────────────────────────────
// Token throughput per account (account-card charts)
// ─────────────────────────────────────────────────

export const THROUGHPUT_BUCKET_MS = 5 * 60 * 1000;

/** Chart group of a model: fable | opus | sonnet | haiku | other. */
export function usageFamily(model) {
  return modelFamily(model) || (/haiku/i.test(String(model || '')) ? 'haiku' : 'other');
}

/** All tokens a request moved: uncached input + cache reads + cache writes + output. */
export function totalTokens(u) {
  if (!u) return 0;
  return (u.input || 0) + (u.output || 0) + (u.cacheRead || 0) + (u.cacheWrite5m || 0) + (u.cacheWrite1h || 0);
}

/**
 * Tokens per account in fixed time buckets, split by model family. Kept for maxAge.
 * series() returns [{ t, w, by: { family: tokens } }] for the buckets that saw traffic.
 */
export function createThroughputStore({ bucketMs = THROUGHPUT_BUCKET_MS, maxAge = 26 * 60 * 60 * 1000, now = () => Date.now() } = {}) {
  const data = new Map(); // key → Map<bucketStart, { family: tokens }>
  let startedAt = now();  // first moment this store recorded (older periods come from hourly rollups)

  function add(key, model, tokens, ts = now()) {
    if (!key || !(tokens > 0)) return;
    const t = Math.floor(ts / bucketMs) * bucketMs;
    let buckets = data.get(key);
    if (!buckets) data.set(key, (buckets = new Map()));
    const by = buckets.get(t) || {};
    const fam = usageFamily(model);
    by[fam] = (by[fam] || 0) + tokens;
    buckets.set(t, by);
  }

  function series(key, since, until = now()) {
    const out = [];
    for (const [t, by] of data.get(key) || []) {
      if (t + bucketMs > since && t <= until) out.push({ t, w: bucketMs, by: { ...by } });
    }
    return out.sort((a, b) => a.t - b.t);
  }

  function prune(at = now()) {
    const cutoff = at - maxAge;
    for (const [key, buckets] of data) {
      for (const t of buckets.keys()) if (t + bucketMs <= cutoff) buckets.delete(t);
      if (!buckets.size) data.delete(key);
    }
  }

  function remove(key) { data.delete(key); }

  function rename(oldKey, newKey) {
    const from = data.get(oldKey);
    if (!from || oldKey === newKey) return;
    data.delete(oldKey);
    for (const [t, by] of from) for (const [fam, n] of Object.entries(by)) {
      let buckets = data.get(newKey);
      if (!buckets) data.set(newKey, (buckets = new Map()));
      const cur = buckets.get(t) || {};
      cur[fam] = (cur[fam] || 0) + n;
      buckets.set(t, cur);
    }
  }

  function toJSON() {
    prune();
    const out = {};
    for (const [key, buckets] of data) out[key] = [...buckets.entries()];
    return { v: 1, bucketMs, startedAt, data: out };
  }

  function load(json) {
    data.clear();
    if (!json || json.bucketMs !== bucketMs) return; // a different bucket size: start over
    if (Number.isFinite(json.startedAt)) startedAt = json.startedAt;
    for (const [key, entries] of Object.entries(json.data || {})) {
      const buckets = new Map();
      for (const [t, by] of Array.isArray(entries) ? entries : []) {
        if (!Number.isFinite(t) || t > now() + 60000 || !by || typeof by !== 'object') continue;
        const clean = {};
        for (const [fam, n] of Object.entries(by)) if (Number.isFinite(n) && n > 0) clean[fam] = n;
        if (Object.keys(clean).length) buckets.set(t, clean);
      }
      if (buckets.size) data.set(key, buckets);
    }
    prune();
  }

  return { add, series, prune, rename, remove, toJSON, load, get startedAt() { return startedAt; }, bucketMs };
}

/**
 * Hourly throughput per account from the usage rollups: { account: [{ t, w, by }] }.
 * `scale` divides each value (e.g. 12 to show an hour as an average 5-minute rate).
 */
export function throughputFromRollups(rows, { since = 0, until = Infinity, scale = 1 } = {}) {
  const acc = {};
  for (const r of rows || []) {
    if (!(r.h >= since && r.h < until)) continue;
    const n = totalTokens(r);
    if (!n) continue;
    const perAcct = acc[r.account] || (acc[r.account] = new Map());
    const by = perAcct.get(r.h) || {};
    const fam = usageFamily(r.model);
    by[fam] = (by[fam] || 0) + n / scale;
    perAcct.set(r.h, by);
  }
  const out = {};
  for (const [account, m] of Object.entries(acc)) {
    out[account] = [...m.entries()].sort((a, b) => a[0] - b[0]).map(([t, by]) => ({ t, w: 3600000, by }));
  }
  return out;
}

/**
 * Total tokens per 5 minutes as an evenly spaced series for the account line charts.
 * - step = 5 min: each value is that 5-minute total, from the 5-minute store (`fine`); slots
 *   from before the store existed use their hour's average from the hourly rollups.
 * - step = 1 h: each value is the hour's average per 5 minutes (same unit, same "hot" line).
 * Missing slots are 0: every request goes through the proxy, so no data means no traffic.
 * The running hour is averaged over its elapsed part only.
 */
export function throughputLine({ fine = [], hourly = [], startedAt = 0, now = Date.now(), windowMs, step = THROUGHPUT_BUCKET_MS }) {
  const H = 3600000, F = THROUGHPUT_BUCKET_MS;
  const total = (by) => Object.values(by || {}).reduce((a, b) => a + (b || 0), 0);
  const n = Math.max(1, Math.round(windowMs / step));
  const last = Math.floor(now / step) * step;
  const start = last - (n - 1) * step;
  const hours = new Map(hourly.map(x => [x.t, total(x.by)]));
  const hourAvg = (h) => {
    const v = hours.get(h) || 0;
    const slots = h + H > now ? Math.max(1, Math.ceil((now - h) / F)) : H / F;
    return v / slots;
  };
  const fineMap = new Map(fine.map(x => [Math.floor(x.t / step) * step, total(x.by)]));
  const fineFrom = Math.floor(startedAt / step) * step;
  const values = new Array(n);
  let sum = 0; // real tokens in the window (the running hour is not extrapolated)
  for (let i = 0; i < n; i++) {
    const t = start + i * step;
    if (step === H) { values[i] = Math.round(hourAvg(t)); sum += hours.get(t) || 0; }
    else if (t >= fineFrom) { values[i] = fineMap.get(t) || 0; sum += values[i]; }
    else { const h = Math.floor(t / H) * H; values[i] = Math.round(hourAvg(h)); sum += (hours.get(h) || 0) / (H / F); }
  }
  return { start, step, values, total: Math.round(sum) };
}

// ─────────────────────────────────────────────────
// Cache care: explain cache rebuilds, keep idle caches warm
// ─────────────────────────────────────────────────

export const HOUR_MS = 60 * 60 * 1000;
export const KEEP_WARM_MIN_TOKENS = 30_000;   // smaller prefixes are cheap to rebuild
export const REBUILD_MIN_PROMPT = 20_000;
// Claude Code's side calls (session titles, quick checks) share the session id but carry no
// conversation: a real conversation request includes the system prompt and tools (~15k+ tokens)
export const SIDE_CALL_MAX_TOKENS = 10_000;
const PING_MARGIN_MS = 60 * 1000;             // ping this long before the TTL runs out

/** Per-MTok prices that matter for caching: input, cache read, cache write (for this TTL). */
export function cachePrices(model, ttlMs = HOUR_MS) {
  const p = priceFor(model);
  return { input: p.input, read: p.cacheRead, write: p.input * (ttlMs >= HOUR_MS ? 2 : 1.25) };
}

/** Extra cost (USD) of writing `tokens` again instead of reading them from cache. */
export function rebuildCost(tokens, model, ttlMs = HOUR_MS) {
  const c = cachePrices(model, ttlMs);
  return (tokens || 0) * (c.write - c.read) / 1e6;
}

/** One keep-warm ping costs this fraction of a rebuild (r / (w − r)). */
export function pingCostRatio(model, ttlMs = HOUR_MS) {
  const c = cachePrices(model, ttlMs);
  return c.read / Math.max(c.write - c.read, 1e-9);
}

/** Ski-rental break-even: after this many pings, keeping a cache warm cost a whole rebuild. */
export function breakEvenPings(model, ttlMs = HOUR_MS) {
  return Math.max(1, Math.floor(1 / pingCostRatio(model, ttlMs) + 1e-9));
}

/**
 * Tokens of the lane's previous prompt that had to be written again instead of read: the
 * previous prompt size minus what this request read from cache. 0 when most of it was read
 * (a turn that only appends new content is not a rebuild).
 */
export function lostCacheTokens(cacheRead, prevTokens, minPrompt = REBUILD_MIN_PROMPT) {
  if (!(prevTokens >= minPrompt)) return 0;
  return (cacheRead || 0) < prevTokens * 0.5 ? prevTokens - (cacheRead || 0) : 0;
}

/** Did this response rebuild most of a big prompt instead of reading it from cache? */
export function isCacheRebuild(usage, minPrompt = REBUILD_MIN_PROMPT) {
  if (!usage) return false;
  const write = (usage.cacheWrite5m || 0) + (usage.cacheWrite1h || 0);
  const prompt = (usage.input || 0) + (usage.cacheRead || 0) + write;
  return prompt >= minPrompt && write > prompt * 0.5;
}

const shortHash = (s) => createHash('sha1').update(s).digest('hex').slice(0, 12);
// cache_control markers move every turn without changing what is cached: leave them out
const noMarkers = (k, v) => (k === 'cache_control' ? undefined : v);

/**
 * What decides whether a request can reuse the cache: tools, system, settings, beta header,
 * and each message (cache_control markers ignored). Hashes only; null for a non-JSON body.
 */
export function cacheFingerprint(body, headers = {}) {
  let j;
  try { j = JSON.parse(Buffer.isBuffer(body) ? body.toString('utf8') : String(body)); } catch { return null; }
  if (!j || typeof j !== 'object' || !Array.isArray(j.messages)) return null;
  const settings = { thinking: j.thinking, tool_choice: j.tool_choice, output_config: j.output_config, speed: j.speed, effort: j.effort };
  return {
    model: j.model || null,
    tools: shortHash(JSON.stringify(j.tools || null, noMarkers)),
    system: shortHash(JSON.stringify(j.system || null, noMarkers)),
    settings: shortHash(JSON.stringify(settings, noMarkers)),
    beta: String(headers['anthropic-beta'] || ''),
    msgs: j.messages.map(m => shortHash(JSON.stringify(m, noMarkers))),
  };
}

/**
 * Why a lane had to rebuild its cache, comparing this request with the lane's previous one.
 * Returns { cause, detail }. cause: idle | account | model | tools | system | settings | beta |
 * history | unknown.
 */
export function classifyRebuild(prev, cur, { gapMs = 0, ttlMs = HOUR_MS, prevAccount = null, account = null } = {}) {
  if (!prev || !cur) return { cause: 'unknown', detail: 'no earlier request to compare' };
  if (gapMs > ttlMs) return { cause: 'idle', detail: `idle ${Math.round(gapMs / 60000)} min (cache lasts ${Math.round(ttlMs / 60000)} min)` };
  if (prevAccount && account && prevAccount !== account) return { cause: 'account', detail: `moved from ${prevAccount} to ${account}` };
  if (prev.model !== cur.model) return { cause: 'model', detail: `${prev.model} → ${cur.model}` };
  if (prev.tools !== cur.tools) return { cause: 'tools', detail: 'tool definitions changed' };
  if (prev.system !== cur.system) return { cause: 'system', detail: 'system prompt changed' };
  if (prev.settings !== cur.settings) return { cause: 'settings', detail: 'thinking or other settings changed' };
  if (prev.beta !== cur.beta) return { cause: 'beta', detail: 'anthropic-beta header changed' };
  const n = Math.min(prev.msgs.length, cur.msgs.length);
  for (let i = 0; i < n; i++) {
    if (prev.msgs[i] !== cur.msgs[i]) return { cause: 'history', detail: `message #${i + 1} of ${cur.msgs.length} changed (e.g. compaction)` };
  }
  if (cur.msgs.length < prev.msgs.length) return { cause: 'history', detail: 'conversation got shorter (e.g. compaction)' };
  return { cause: 'unknown', detail: 'same prefix: the cache was dropped upstream' };
}

/**
 * Return curve of idle sessions (Kaplan–Meier). periods: [{ waitMs, returned }]: how long a
 * session was idle (counted from its last cache touch) and whether it came back (false =
 * still idle or closed: censored). Returns surv[k] = P(still away when ping k+1 would be due),
 * with one ping every `periodMs`; surv[0] = 1.
 */
export function returnCurve(periods, { periodMs = HOUR_MS - PING_MARGIN_MS, maxK = 200 } = {}) {
  const events = new Map(), censored = new Map();
  const slot = (ms) => Math.max(0, Math.ceil(ms / periodMs) - 1); // pings needed to be warm at that time
  for (const p of periods || []) {
    const k = Math.min(slot(p.waitMs), maxK + 1);
    const m = p.returned ? events : censored;
    m.set(k, (m.get(k) || 0) + 1);
  }
  const surv = new Array(maxK + 2);
  let s = 1, atRisk = (periods || []).length;
  for (let k = 0; k <= maxK + 1; k++) {
    surv[k] = s;
    const d = events.get(k) || 0;
    if (atRisk > 0) s *= 1 - d / atRisk;
    atRisk -= d + (censored.get(k) || 0);
  }
  return surv;
}

/** Return curve from a Weibull fit (the prior while there is little data). */
export function weibullCurve(shape, scaleMs, { periodMs = HOUR_MS - PING_MARGIN_MS, maxK = 200 } = {}) {
  const surv = new Array(maxK + 2);
  surv[0] = 1;
  for (let k = 1; k <= maxK + 1; k++) surv[k] = Math.exp(-Math.pow((k * periodMs) / scaleMs, shape));
  return surv;
}

/** Measured on real Claude Code use (1,246 idle periods): returns fall off fast, then a long tail. */
export const RETURN_PRIOR = { shape: 0.5, scaleMs: 17.3 * HOUR_MS };

/**
 * How many pings to send for one idle period (look-ahead optimal stopping): the H that
 * maximises Σ P(return needing k pings)·(1 − k·ratio) − P(still away after H pings)·H·ratio,
 * where ratio = one ping's cost / one rebuild's cost. Unlike a one-step "is the next hour
 * worth it" rule, this also handles curves that dip and rise again (evening → next morning).
 */
export function bestPingCount(surv, ratio, maxPings) {
  let best = 0, bestV = 0;
  for (let H = 1; H <= Math.min(maxPings, surv.length - 2); H++) {
    let v = 0;
    for (let k = 1; k <= H; k++) v += (surv[k] - surv[k + 1]) * (1 - k * ratio); // k = 0 needs no ping
    v -= surv[H + 1] * H * ratio;
    if (v > bestV) { bestV = v; best = H; }
  }
  return best;
}

/**
 * Replay recorded idle periods under a ping count: net value as a share of what all those
 * rebuilds cost (1 = every rebuild avoided for free). For checking the policy on real data.
 */
export function backtestPings(periods, pingsFor, ratio, { periodMs = HOUR_MS - PING_MARGIN_MS } = {}) {
  let value = 0, base = 0;
  for (const p of periods) {
    const n = pingsFor(p);
    const size = p.tokens || 1;
    if (!p.returned) { value -= size * ratio * Math.min(n, Math.floor(p.waitMs / periodMs)); continue; }
    base += size;
    const need = Math.max(0, Math.ceil(p.waitMs / periodMs) - 1);
    value += need <= n ? size * (1 - need * ratio) : -size * ratio * n;
  }
  return base ? value / base : 0;
}

/**
 * Keep-warm planner: which idle session lanes to ping, and when. Pure state; the caller
 * does the requests. A lane is one Claude Code session's main conversation.
 *   start/end     a real request begins / its response is closed (any outcome)
 *   finish        a real request's usage arrived (confirms the cache touch)
 *   due(t)        lanes whose cache needs a ping now, best value first
 *   pinged        the outcome of a ping
 * Pings stop for an idle period after `limit` pings (learned per model), a failed ping, a
 * missed window (machine slept), or when the lane is set to "never".
 */
export function createKeepWarmPlanner({ now = () => Date.now(), pingLimit = () => 0 } = {}) {
  const lanes = new Map();
  // Ping a minute before the TTL runs out (a quarter of it for very short TTLs, e.g. in tests)
  const margin = (l) => Math.min(PING_MARGIN_MS, l.ttlMs / 4);

  function lane(sid) {
    let l = lanes.get(sid);
    if (!l) {
      l = { sid, account: null, model: null, ttlMs: HOUR_MS, tokens: 0, touchedAt: 0, realAt: 0, inflight: 0,
            pings: 0, limit: 0, stopped: null, mode: 'auto', warmedThisIdle: false };
      lanes.set(sid, l);
    }
    return l;
  }

  /** A real request of this session starts (no ping may overlap it). */
  function start(sid) {
    lane(sid).inflight++;
  }

  /**
   * A successful conversation request's usage arrived (not side calls, not errors or retries).
   * `startedAt` is when it began: the cache TTL counts from there. Returns:
   *   warmResume  pings kept this cache alive and it was read now
   *   idle        the idle period this request ended ({ waitMs, pings, tokens, model }) or null;
   *               idle time counts from the last real request (pings keep the cache, not the
   *               user, active)
   */
  function finish(sid, { startedAt, account, model, ttlMs, tokens, cacheRead = 0, ok = true } = {}) {
    const l = lane(sid);
    if (!ok) return { warmResume: false, idle: null };
    const at0 = startedAt || now();
    const idle = l.realAt && at0 - l.realAt >= l.ttlMs - margin(l)
      ? { waitMs: at0 - l.realAt, pings: l.pings, tokens: l.tokens, model: l.model } : null;
    const warmResume = l.warmedThisIdle && l.account === account && cacheRead >= l.tokens * 0.9;
    const at = startedAt || now();
    Object.assign(l, { account, model, ttlMs: ttlMs || HOUR_MS, tokens: tokens || 0, touchedAt: at, realAt: at,
                       pings: 0, stopped: null, warmedThisIdle: false });
    l.limit = l.mode === 'never' ? 0 : pingLimit(l);
    return { warmResume, idle };
  }

  function due(t = now()) {
    const out = [];
    for (const l of lanes.values()) {
      if (l.mode === 'never' || l.stopped || l.inflight > 0 || !l.touchedAt || !l.account) continue;
      if (l.tokens < KEEP_WARM_MIN_TOKENS) continue;
      const at = l.touchedAt + l.ttlMs - margin(l);
      if (t < at) continue;
      if (t > l.touchedAt + l.ttlMs) { l.stopped = 'cold'; continue; } // missed it (machine slept)
      if (l.pings >= l.limit) { l.stopped = 'done'; continue; }
      out.push(l);
    }
    // Most valuable first: the biggest caches (equal per-token value across lanes otherwise)
    return out.sort((a, b) => rebuildCost(b.tokens, b.model, b.ttlMs) - rebuildCost(a.tokens, a.model, a.ttlMs));
  }

  /** Outcome of a ping that started at `startedAt`: ok extends the cache; anything else stops. */
  function pinged(sid, { ok, startedAt, reason = 'failed' }) {
    const l = lanes.get(sid);
    if (!l) return;
    if (l.realAt > startedAt || l.inflight > 0) return; // a real request came in meanwhile: stale
    if (ok) { l.pings++; l.touchedAt = startedAt; l.warmedThisIdle = true; }
    else l.stopped = reason;
  }

  function setMode(sid, mode) {
    const l = lane(sid);
    l.mode = ['auto', 'pin', 'never'].includes(mode) ? mode : 'auto';
    l.limit = l.mode === 'never' ? 0 : pingLimit(l);
    if (l.mode !== 'never' && (l.stopped === 'done')) l.stopped = null;
  }

  /** The real request's response is closed (success, error or disconnect). */
  function end(sid) { const l = lanes.get(sid); if (l) l.inflight = Math.max(0, l.inflight - 1); }

  function stop(sid, reason) { const l = lanes.get(sid); if (l) l.stopped = reason; }
  function drop(sid) { lanes.delete(sid); }
  function get(sid) { return lanes.get(sid) || null; }
  function all() { return [...lanes.values()]; }
  function modes() { return Object.fromEntries([...lanes.values()].filter(l => l.mode !== 'auto').map(l => [l.sid, l.mode])); }
  function loadModes(m) { for (const [sid, mode] of Object.entries(m || {})) lane(sid).mode = mode; }

  return { start, end, finish, due, pinged, setMode, stop, drop, get, all, modes, loadModes };
}

/**
 * Daily ledger of what cache care saved and cost (USD at API prices):
 *   keepWarm  pings sent, their cost, warm resumes and the rebuilds they avoided
 *   affinity  moves avoided by keeping a warm session on its account
 *   rebuilds  rebuilds that still happened, by cause, with their extra cost
 */
export function createCacheLedger(saved = null) {
  const days = new Map(Object.entries(saved?.days || {}));
  const day = (t) => {
    const k = new Date(t).toISOString().slice(0, 10);
    let d = days.get(k);
    if (!d) days.set(k, (d = { pings: 0, pingCost: 0, warmResumes: 0, keepWarmSaved: 0, affinityMoves: 0, affinitySaved: 0, rebuilds: {} }));
    return d;
  };
  return {
    ping(cost, t = Date.now()) { const d = day(t); d.pings++; d.pingCost += cost; },
    warmResume(saved, t = Date.now()) { const d = day(t); d.warmResumes++; d.keepWarmSaved += saved; },
    affinity(saved, t = Date.now()) { const d = day(t); d.affinityMoves++; d.affinitySaved += saved; },
    rebuild(cause, cost, t = Date.now()) {
      const r = day(t).rebuilds;
      const c = r[cause] || (r[cause] = { count: 0, cost: 0 });
      c.count++; c.cost += cost;
    },
    /** Totals since `since` (ms). pct = saved ÷ (saved + rebuild cost still paid). */
    summary(since = 0) {
      const s = { pings: 0, pingCost: 0, warmResumes: 0, keepWarmSaved: 0, affinityMoves: 0, affinitySaved: 0, rebuilds: {}, rebuildCost: 0 };
      for (const [k, d] of days) {
        if (Date.parse(k + 'T23:59:59Z') < since) continue;
        for (const f of ['pings', 'pingCost', 'warmResumes', 'keepWarmSaved', 'affinityMoves', 'affinitySaved']) s[f] += d[f];
        for (const [cause, c] of Object.entries(d.rebuilds)) {
          const t = s.rebuilds[cause] || (s.rebuilds[cause] = { count: 0, cost: 0 });
          t.count += c.count; t.cost += c.cost; s.rebuildCost += c.cost;
        }
      }
      s.saved = s.keepWarmSaved - s.pingCost + s.affinitySaved;
      const gross = s.keepWarmSaved + s.affinitySaved;
      s.pct = gross + s.rebuildCost > 0 ? Math.max(0, s.saved) / (gross + s.rebuildCost) : null;
      return s;
    },
    prune(keepDays = 120, t = Date.now()) {
      const cut = new Date(t - keepDays * 86400000).toISOString().slice(0, 10);
      for (const k of days.keys()) if (k < cut) days.delete(k);
    },
    toJSON() { return { v: 1, days: Object.fromEntries(days) }; },
  };
}

/**
 * Set top-level fields of a JSON object text without re-serializing it: every other byte stays
 * as it was (JSON.parse + stringify would reorder number-like keys and could change the prompt
 * the cache was built from). `fields` values are JSON-encoded. Missing fields are added first.
 * Returns null when the text is not a JSON object.
 */
export function setTopLevelJsonFields(text, fields) {
  let i = 0;
  const n = text.length;
  const ws = () => { while (i < n && (text[i] === ' ' || text[i] === '\n' || text[i] === '\r' || text[i] === '\t')) i++; };
  const skipString = () => { // at the opening quote; returns the raw string contents
    const start = ++i;
    while (i < n && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
    if (i >= n) throw new Error('unterminated string');
    return text.slice(start, i++);
  };
  const skipValue = () => {
    ws();
    if (text[i] === '"') { skipString(); return; }
    if (text[i] === '{' || text[i] === '[') {
      let depth = 0;
      while (i < n) {
        const c = text[i];
        if (c === '"') { skipString(); continue; }
        if (c === '{' || c === '[') depth++;
        else if (c === '}' || c === ']') { depth--; if (depth === 0) { i++; return; } }
        i++;
      }
      throw new Error('unterminated value');
    }
    while (i < n && !',}] \n\r\t'.includes(text[i])) i++; // number, true, false, null
  };
  try {
    ws();
    if (text[i] !== '{') return null;
    const open = i++;
    const spans = {};
    ws();
    while (i < n && text[i] !== '}') {
      if (text[i] !== '"') return null;
      const key = JSON.parse('"' + skipString() + '"');
      ws();
      if (text[i++] !== ':') return null;
      ws();
      const vStart = i;
      skipValue();
      if (key in fields && !(key in spans)) spans[key] = [vStart, i];
      ws();
      if (text[i] === ',') { i++; ws(); }
    }
    if (text[i] !== '}') return null;
    const edits = Object.entries(spans).map(([k, [a, b]]) => [a, b, JSON.stringify(fields[k])]).sort((x, y) => y[0] - x[0]);
    let out = text;
    for (const [a, b, v] of edits) out = out.slice(0, a) + v + out.slice(b);
    const missing = Object.keys(fields).filter(k => !(k in spans));
    if (missing.length) {
      const add = missing.map(k => JSON.stringify(k) + ':' + JSON.stringify(fields[k])).join(',');
      const rest = out.slice(open + 1);
      out = out.slice(0, open + 1) + add + (/^\s*\}/.test(rest) ? '' : ',') + rest;
    }
    return out;
  } catch { return null; }
}
