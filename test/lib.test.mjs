// Unit tests for lib.mjs  - pure functions
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders,
  stripHopByHopHeaders,
  HOP_BY_HOP,
  createAccountStateManager,
  createInflightTracker,
  createBalanceLimiter,
  isAccountAvailable,
  scoreAccount,
  pickBestAccount,
  pickAnyUntried,
  pickLeastLoaded,
  pickByStrategy,
  createProbeTracker,
  createUtilizationHistory,
  buildRefreshRequestBody,
  parseRefreshResponse,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
  createPerAccountLock,
} from '../lib.mjs';

// ─────────────────────────────────────────────────
// Existing function tests (sanity checks)
// ─────────────────────────────────────────────────

describe('getFingerprint', () => {
  it('returns 16-char hex for valid creds', () => {
    const fp = getFingerprint({ claudeAiOauth: { accessToken: 'test-token-123' } });
    assert.equal(fp.length, 16);
    assert.match(fp, /^[0-9a-f]{16}$/);
  });

  it('returns consistent fingerprint for same token', () => {
    const creds = { claudeAiOauth: { accessToken: 'my-token' } };
    assert.equal(getFingerprint(creds), getFingerprint(creds));
  });

  it('returns different fingerprints for different tokens', () => {
    const fp1 = getFingerprint({ claudeAiOauth: { accessToken: 'token-a' } });
    const fp2 = getFingerprint({ claudeAiOauth: { accessToken: 'token-b' } });
    assert.notEqual(fp1, fp2);
  });
});

describe('stripHopByHopHeaders', () => {
  it('strips all RFC 7230 hop-by-hop headers', () => {
    const input = {
      'connection': 'keep-alive',
      'keep-alive': 'timeout=5',
      'proxy-authenticate': 'Basic',
      'proxy-authorization': 'Bearer xyz',
      'te': 'trailers',
      'trailer': 'Expires',
      'transfer-encoding': 'chunked',
      'upgrade': 'websocket',
      'host': 'localhost:3334',
      'content-length': '42',
      'accept-encoding': 'gzip, br',
      'x-api-key': 'sk-ant-abc123',
      // These should survive:
      'content-type': 'application/json',
      'authorization': 'Bearer tok',
      'x-custom': 'value',
    };
    const result = stripHopByHopHeaders(input);
    for (const h of HOP_BY_HOP) {
      assert.ok(!(h in result), `${h} should be stripped`);
    }
    assert.equal(result['content-type'], 'application/json');
    assert.equal(result['authorization'], 'Bearer tok');
    assert.equal(result['x-custom'], 'value');
  });

  it('strips x-api-key header to prevent billing conflicts', () => {
    const result = stripHopByHopHeaders({
      'x-api-key': 'sk-ant-abc123',
      'content-type': 'application/json',
      'authorization': 'Bearer oauth-token',
    });
    assert.ok(!('x-api-key' in result), 'x-api-key should be stripped');
    assert.equal(result['content-type'], 'application/json');
    assert.equal(result['authorization'], 'Bearer oauth-token');
  });

  it('strips custom hop-by-hop headers declared in Connection', () => {
    const result = stripHopByHopHeaders({
      'connection': 'X-Custom-Hop, X-Another',
      'x-custom-hop': 'secret',
      'x-another': 'also-secret',
      'x-safe': 'keep-me',
    });
    assert.ok(!('x-custom-hop' in result));
    assert.ok(!('x-another' in result));
    assert.ok(!('connection' in result));
    assert.equal(result['x-safe'], 'keep-me');
  });

  it('handles empty Connection header', () => {
    const result = stripHopByHopHeaders({ 'connection': '', 'content-type': 'text/plain' });
    assert.equal(result['content-type'], 'text/plain');
    assert.ok(!('connection' in result));
  });

  it('handles missing Connection header', () => {
    const result = stripHopByHopHeaders({ 'content-type': 'text/plain' });
    assert.equal(result['content-type'], 'text/plain');
  });
});

describe('buildForwardHeaders', () => {
  it('sets authorization and host headers', () => {
    const headers = buildForwardHeaders({ 'content-type': 'application/json' }, 'test-token');
    assert.equal(headers['authorization'], 'Bearer test-token');
    assert.equal(headers['host'], 'api.anthropic.com');
  });

  it('strips all hop-by-hop headers via stripHopByHopHeaders', () => {
    const headers = buildForwardHeaders({
      'host': 'localhost:3334',
      'connection': 'keep-alive',
      'keep-alive': 'timeout=5',
      'content-length': '42',
      'transfer-encoding': 'chunked',
      'proxy-authorization': 'Basic abc',
      'te': 'trailers',
      'trailer': 'Expires',
      'upgrade': 'websocket',
      'content-type': 'application/json',
    }, 'test-token');
    assert.equal(headers['content-type'], 'application/json');
    assert.equal(headers['host'], 'api.anthropic.com');
    assert.ok(!('connection' in headers));
    assert.ok(!('keep-alive' in headers));
    assert.ok(!('content-length' in headers));
    assert.ok(!('transfer-encoding' in headers));
    assert.ok(!('proxy-authorization' in headers));
    assert.ok(!('te' in headers));
    assert.ok(!('trailer' in headers));
    assert.ok(!('upgrade' in headers));
  });

  it('strips custom Connection-declared headers', () => {
    const headers = buildForwardHeaders({
      'connection': 'X-My-Hop',
      'x-my-hop': 'private-value',
      'content-type': 'application/json',
    }, 'test-token');
    assert.ok(!('x-my-hop' in headers));
    assert.equal(headers['content-type'], 'application/json');
  });

  it('adds oauth beta header', () => {
    const headers = buildForwardHeaders({}, 'test-token');
    assert.ok(headers['anthropic-beta'].includes('oauth-2025-04-20'));
  });

  it('does not duplicate oauth beta if already present', () => {
    const headers = buildForwardHeaders({
      'anthropic-beta': 'oauth-2025-04-20,some-other-beta',
    }, 'test-token');
    const betas = headers['anthropic-beta'].split(',').map(s => s.trim());
    const oauthCount = betas.filter(b => b === 'oauth-2025-04-20').length;
    assert.equal(oauthCount, 1);
  });

  it('strips x-api-key from forwarded headers', () => {
    const headers = buildForwardHeaders({
      'x-api-key': 'sk-ant-abc123',
      'content-type': 'application/json',
    }, 'test-token');
    assert.ok(!('x-api-key' in headers), 'x-api-key should not be forwarded');
    assert.equal(headers['authorization'], 'Bearer test-token');
  });

  it('throws on null token', () => {
    assert.throws(() => buildForwardHeaders({}, null), /Cannot forward request: token is null/);
  });

  it('throws on undefined token', () => {
    assert.throws(() => buildForwardHeaders({}, undefined), /Cannot forward request/);
  });
});

describe('createAccountStateManager', () => {
  it('tracks account state through lifecycle', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', {
      'anthropic-ratelimit-unified-status': 'ok',
      'anthropic-ratelimit-unified-5h-utilization': '0.5',
      'anthropic-ratelimit-unified-7d-utilization': '0.3',
    });
    const state = sm.get('tok1');
    assert.equal(state.name, 'acct1');
    assert.equal(state.limited, false);
    assert.equal(state.expired, false);
    assert.equal(state.utilization5h, 0.5);
    assert.equal(state.utilization7d, 0.3);
  });

  it('remove() deletes entry', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', { 'anthropic-ratelimit-unified-status': 'allowed' });
    assert.ok(sm.get('tok1'));
    sm.remove('tok1');
    assert.equal(sm.get('tok1'), undefined);
  });

  it('remove() on non-existent key is a no-op', () => {
    const sm = createAccountStateManager();
    sm.remove('nonexistent'); // should not throw
    assert.equal(sm.get('nonexistent'), undefined);
  });

  it('clearBillingCooldown() clears retryAfter but preserves rate-limit state', () => {
    const sm = createAccountStateManager();
    // Set up an account with both rate-limit and billing cooldown
    sm.update('tok1', 'acct1', {
      'anthropic-ratelimit-unified-status': 'limited',
      'anthropic-ratelimit-unified-5h-utilization': '0.8',
      'anthropic-ratelimit-unified-7d-utilization': '0.4',
      'anthropic-ratelimit-unified-5h-reset': String(Math.floor(Date.now() / 1000) + 3600),
    });
    // Mark with billing cooldown
    sm.markLimited('tok1', 'acct1', 300);
    const before = sm.get('tok1');
    assert.ok(before.retryAfter > 0, 'retryAfter should be set');
    assert.equal(before.limited, true);

    // Clear billing cooldown
    sm.clearBillingCooldown('tok1');
    const after = sm.get('tok1');
    assert.equal(after.retryAfter, 0, 'retryAfter should be cleared');
    assert.equal(after.limited, true, 'limited flag should be preserved');
    assert.equal(after.utilization5h, 0.8, 'utilization5h should be preserved');
    assert.equal(after.utilization7d, 0.4, 'utilization7d should be preserved');
    assert.ok(after.resetAt > 0, 'resetAt should be preserved');
  });

  it('clearBillingCooldown() is a no-op when retryAfter is already 0', () => {
    const sm = createAccountStateManager();
    sm.update('tok1', 'acct1', { 'anthropic-ratelimit-unified-status': 'ok' });
    const before = sm.get('tok1');
    const beforeUpdatedAt = before.updatedAt;
    sm.clearBillingCooldown('tok1');
    const after = sm.get('tok1');
    assert.equal(after.updatedAt, beforeUpdatedAt, 'should not update when retryAfter is already 0');
  });

  it('clearBillingCooldown() is a no-op for unknown tokens', () => {
    const sm = createAccountStateManager();
    sm.clearBillingCooldown('nonexistent'); // should not throw
    assert.equal(sm.get('nonexistent'), undefined);
  });
});

// ─────────────────────────────────────────────────
// createInflightTracker  - balance mode concurrency counter
// ─────────────────────────────────────────────────

describe('createInflightTracker', () => {
  it('acquire/release increment and decrement', () => {
    const t = createInflightTracker();
    assert.equal(t.get('a'), 0);
    assert.equal(t.acquire('a'), 1);
    assert.equal(t.acquire('a'), 2);
    assert.equal(t.get('a'), 2);
    assert.equal(t.release('a'), 1);
    assert.equal(t.get('a'), 1);
  });

  it('release is underflow-guarded (never negative)', () => {
    const t = createInflightTracker();
    assert.equal(t.release('a'), 0);
    assert.equal(t.get('a'), 0);
    t.acquire('a');
    t.release('a');
    assert.equal(t.release('a'), 0, 'double-release stays at 0');
    assert.equal(t.get('a'), 0);
  });

  it('tracks multiple accounts independently and totals correctly', () => {
    const t = createInflightTracker();
    t.acquire('a'); t.acquire('a'); t.acquire('b');
    assert.equal(t.get('a'), 2);
    assert.equal(t.get('b'), 1);
    assert.equal(t.total(), 3);
    assert.deepEqual(t.snapshot(), { a: 2, b: 1 });
  });

  it('deletes the key at zero so snapshot stays clean', () => {
    const t = createInflightTracker();
    t.acquire('a');
    t.release('a');
    assert.deepEqual(t.snapshot(), {});
    assert.equal(t.total(), 0);
  });
});

// ─────────────────────────────────────────────────
// createBalanceLimiter  - wait / overflow / wakeup mechanics
// ─────────────────────────────────────────────────

describe('createBalanceLimiter', () => {
  it('acquires immediately when the best candidate is under cap', async () => {
    const lim = createBalanceLimiter();
    const r = await lim.acquire(() => ({ key: 'a', inflight: lim.get('a'), account: { name: 'a' } }), { cap: 8, waitMs: 1000 });
    assert.equal(r.overflow, false);
    assert.equal(r.key, 'a');
    assert.equal(r.account.name, 'a', 'passes through extra fields from pick()');
    assert.equal(lim.get('a'), 1);
  });

  it('returns null when pick() reports no available candidate', async () => {
    const lim = createBalanceLimiter();
    const r = await lim.acquire(() => null, { cap: 8, waitMs: 1000 });
    assert.equal(r, null);
    assert.equal(lim.total(), 0);
  });

  it('waits when all at cap, then acquires when a slot is released', async () => {
    const lim = createBalanceLimiter();
    for (let i = 0; i < 8; i++) lim.inflight.acquire('a'); // a at cap
    const pick = () => ({ key: 'a', inflight: lim.get('a') });
    const pending = lim.acquire(pick, { cap: 8, waitMs: 10000 }); // over cap → waits
    // The waiter is registered synchronously (Promise executor runs before await).
    assert.equal(lim.waitingCount(), 1);
    lim.release('a'); // frees a slot → wakes the waiter
    const r = await pending;
    assert.equal(r.overflow, false, 'got a real slot, not an overflow');
    assert.equal(lim.waitingCount(), 0);
    assert.equal(lim.get('a'), 8); // released to 7, re-acquired to 8
  });

  it('overflows onto the best candidate after waitMs when never freed', async () => {
    const lim = createBalanceLimiter();
    lim.inflight.acquire('a'); lim.inflight.acquire('a'); // a=2, cap=2
    const pick = () => ({ key: 'a', inflight: lim.get('a') });
    const r = await lim.acquire(pick, { cap: 2, waitMs: 40 }); // never freed → overflow
    assert.equal(r.overflow, true);
    assert.equal(r.key, 'a');
    assert.equal(lim.get('a'), 3, 'overflow acquires the slot anyway (never drops)');
  });

  it('release wakes exactly one waiter (FIFO), not all', async () => {
    const lim = createBalanceLimiter();
    for (let i = 0; i < 4; i++) lim.inflight.acquire('a'); // cap 4
    const pick = () => ({ key: 'a', inflight: lim.get('a') });
    const p1 = lim.acquire(pick, { cap: 4, waitMs: 10000 });
    const p2 = lim.acquire(pick, { cap: 4, waitMs: 10000 });
    assert.equal(lim.waitingCount(), 2);
    lim.release('a'); // one freed → only one waiter should proceed
    await p1;
    assert.equal(lim.waitingCount(), 1, 'second waiter still waiting');
    lim.release('a');
    await p2;
    assert.equal(lim.waitingCount(), 0);
  });

  it('release on an idle limiter is a safe no-op', () => {
    const lim = createBalanceLimiter();
    lim.release('nobody'); // should not throw
    assert.equal(lim.total(), 0);
    assert.equal(lim.waitingCount(), 0);
  });
});

// ─────────────────────────────────────────────────
// Slot release via response 'close' (real HTTP integration)
// Validates the exact mechanism handleProxyRequest relies on:
// a single `res.once('close', releaseHeld)` must fire on BOTH normal
// completion and abrupt client disconnect, or in-flight slots leak forever.
// ─────────────────────────────────────────────────

describe('balance slot release via response close (http integration)', () => {
  it('releases the slot when the response completes normally', async () => {
    const lim = createBalanceLimiter();
    const server = http.createServer((req, res) => {
      lim.inflight.acquire('a');
      res.once('close', () => lim.release('a'));
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;
    try {
      await new Promise((resolve, reject) => {
        http.get({ port }, res => { res.on('data', () => {}); res.on('end', resolve); res.on('error', reject); })
          .on('error', reject);
      });
      // Let the 'close' event fire on the server side.
      for (let i = 0; i < 20 && lim.total() !== 0; i++) await new Promise(r => setTimeout(r, 10));
      assert.equal(lim.total(), 0, 'slot released after normal response close');
    } finally {
      await new Promise(r => server.close(r));
    }
  });

  it('releases the slot when the client disconnects mid-stream', async () => {
    const lim = createBalanceLimiter();
    let releasedResolve;
    const released = new Promise(r => { releasedResolve = r; });
    const server = http.createServer((req, res) => {
      lim.inflight.acquire('a');
      res.once('close', () => { lim.release('a'); releasedResolve(); });
      res.writeHead(200);
      res.write('chunk'); // never ends — force the client to abort
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;
    try {
      const req = http.get({ port }, res => { res.on('data', () => req.destroy()); });
      req.on('error', () => {}); // expected on destroy
      await released;
      assert.equal(lim.total(), 0, 'slot released on client disconnect');
    } finally {
      await new Promise(r => server.close(r));
    }
  });
});

// ─────────────────────────────────────────────────
// pickLeastLoaded  - balance mode account selection
// ─────────────────────────────────────────────────

describe('pickLeastLoaded', () => {
  const accounts = [
    { name: 'a', token: 'tokA', expiresAt: 0 },
    { name: 'b', token: 'tokB', expiresAt: 0 },
    { name: 'c', token: 'tokC', expiresAt: 0 },
  ];

  it('picks the account with the lowest in-flight count', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    inflight.acquire('a'); inflight.acquire('a'); // a=2
    inflight.acquire('b');                        // b=1, c=0
    const pick = pickLeastLoaded(accounts, inflight, sm, 8);
    assert.equal(pick.account.name, 'c');
    assert.equal(pick.inflight, 0);
    assert.equal(pick.overCap, false);
  });

  it('tiebreaks by 5h utilization when in-flight counts are equal', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    // all 0 in-flight; b has lowest utilization
    sm.update('tokA', 'a', { 'anthropic-ratelimit-unified-5h-utilization': '0.7' });
    sm.update('tokB', 'b', { 'anthropic-ratelimit-unified-5h-utilization': '0.1' });
    sm.update('tokC', 'c', { 'anthropic-ratelimit-unified-5h-utilization': '0.4' });
    const pick = pickLeastLoaded(accounts, inflight, sm, 8);
    assert.equal(pick.account.name, 'b');
  });

  it('excludes excludeTokens', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const pick = pickLeastLoaded(accounts, inflight, sm, 8, new Set(['tokA', 'tokB']));
    assert.equal(pick.account.name, 'c');
  });

  it('excludes cooling-down accounts until retryAfter passes', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const now = 1_000_000;
    // a and b cooling down for 3s; only c is available
    sm.markLimited('tokA', 'a', 3);
    sm.markLimited('tokB', 'b', 3);
    // markLimited stamps retryAfter from real Date.now(); recompute against our `now`
    sm.get('tokA').retryAfter = now + 3000;
    sm.get('tokB').retryAfter = now + 3000;
    let pick = pickLeastLoaded(accounts, inflight, sm, 8, new Set(), now);
    assert.equal(pick.account.name, 'c', 'cooled accounts skipped');
    // after the cooldown window, a/b are available again
    pick = pickLeastLoaded(accounts, inflight, sm, 8, new Set(), now + 4000);
    assert.ok(['a', 'b', 'c'].includes(pick.account.name));
    assert.notEqual(sm.get('tokA').retryAfter > now + 4000, true);
  });

  it('flags overCap when every available account is at the cap', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    for (const n of ['a', 'b', 'c']) { inflight.acquire(n); inflight.acquire(n); } // all at 2
    const pick = pickLeastLoaded(accounts, inflight, sm, 2);
    assert.ok(pick, 'still returns the least-loaded account');
    assert.equal(pick.overCap, true);
  });

  it('returns null when no account is available', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const pick = pickLeastLoaded(accounts, inflight, sm, 8, new Set(['tokA', 'tokB', 'tokC']));
    assert.equal(pick, null);
  });
});

// ─────────────────────────────────────────────────
// buildRefreshRequestBody
// ─────────────────────────────────────────────────

describe('buildRefreshRequestBody', () => {
  it('builds JSON body with grant_type and refresh_token', () => {
    const body = buildRefreshRequestBody('rt-abc123');
    const parsed = JSON.parse(body);
    assert.equal(parsed.grant_type, 'refresh_token');
    assert.equal(parsed.refresh_token, 'rt-abc123');
    assert.equal(parsed.client_id, undefined);
    assert.equal(parsed.scope, undefined);
  });

  it('includes client_id when provided', () => {
    const body = buildRefreshRequestBody('rt-abc123', 'my-client');
    const parsed = JSON.parse(body);
    assert.equal(parsed.client_id, 'my-client');
  });

  it('includes scope when provided', () => {
    const body = buildRefreshRequestBody('rt-abc123', 'my-client', 'user:profile user:inference');
    const parsed = JSON.parse(body);
    assert.equal(parsed.scope, 'user:profile user:inference');
  });

  it('handles special characters in refresh token', () => {
    const body = buildRefreshRequestBody('rt-abc+123/foo=bar');
    const parsed = JSON.parse(body);
    assert.equal(parsed.refresh_token, 'rt-abc+123/foo=bar');
  });
});

// ─────────────────────────────────────────────────
// parseRefreshResponse
// ─────────────────────────────────────────────────

describe('parseRefreshResponse', () => {
  it('parses successful response with snake_case fields', () => {
    const body = JSON.stringify({
      access_token: 'new-at',
      refresh_token: 'new-rt',
      expires_in: 28800,
    });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.accessToken, 'new-at');
    assert.equal(result.refreshToken, 'new-rt');
    assert.equal(result.expiresIn, 28800);
  });

  it('parses successful response with camelCase fields', () => {
    const body = JSON.stringify({
      accessToken: 'new-at',
      refreshToken: 'new-rt',
      expiresIn: 3600,
    });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.accessToken, 'new-at');
    assert.equal(result.refreshToken, 'new-rt');
    assert.equal(result.expiresIn, 3600);
  });

  it('returns error when access_token is missing from success response', () => {
    const body = JSON.stringify({ refresh_token: 'new-rt' });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, false);
    assert.match(result.error, /No access_token/);
  });

  it('returns retriable=false for 400 (bad request / revoked token)', () => {
    const body = JSON.stringify({ error: 'invalid_grant', error_description: 'Token revoked' });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.equal(result.retriable, false);
    assert.match(result.error, /Token revoked/);
  });

  it('returns retriable=true for 429 (rate limit)', () => {
    const result = parseRefreshResponse(429, '{"error":"rate_limited"}');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('returns retriable=true for 500 (server error)', () => {
    const result = parseRefreshResponse(500, 'Internal Server Error');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('returns retriable=true for 503 (service unavailable)', () => {
    const result = parseRefreshResponse(503, '{}');
    assert.equal(result.ok, false);
    assert.equal(result.retriable, true);
  });

  it('handles invalid JSON in error response gracefully', () => {
    const result = parseRefreshResponse(400, 'not json');
    assert.equal(result.ok, false);
    assert.match(result.error, /HTTP 400/);
  });

  it('handles invalid JSON in success response', () => {
    const result = parseRefreshResponse(200, 'not json');
    assert.equal(result.ok, false);
    assert.match(result.error, /Invalid JSON/);
    assert.equal(result.retriable, false);
  });

  it('extracts message from object error fields', () => {
    const body = JSON.stringify({ error: { type: 'invalid_grant', message: 'token revoked' } });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.equal(result.error, 'token revoked');
  });

  it('stringifies object error fields without message instead of [object Object]', () => {
    const body = JSON.stringify({ error: { type: 'invalid_grant' } });
    const result = parseRefreshResponse(400, body);
    assert.equal(result.ok, false);
    assert.ok(!result.error.includes('[object Object]'), `error should not contain [object Object]: ${result.error}`);
    assert.ok(result.error.includes('invalid_grant'), `error should contain the error type: ${result.error}`);
  });

  it('handles null refreshToken in response', () => {
    const body = JSON.stringify({ access_token: 'new-at', expires_in: 3600 });
    const result = parseRefreshResponse(200, body);
    assert.equal(result.ok, true);
    assert.equal(result.refreshToken, null);
  });
});

// ─────────────────────────────────────────────────
// computeExpiresAt
// ─────────────────────────────────────────────────

describe('computeExpiresAt', () => {
  it('adds seconds as milliseconds to now', () => {
    const now = 1000000;
    const result = computeExpiresAt(3600, now);
    assert.equal(result, 1000000 + 3600 * 1000);
  });

  it('uses Date.now() when now is not provided', () => {
    const before = Date.now();
    const result = computeExpiresAt(60);
    const after = Date.now();
    assert.ok(result >= before + 60000);
    assert.ok(result <= after + 60000);
  });

  it('handles zero seconds', () => {
    assert.equal(computeExpiresAt(0, 5000), 5000);
  });
});

// ─────────────────────────────────────────────────
// buildUpdatedCreds
// ─────────────────────────────────────────────────

describe('buildUpdatedCreds', () => {
  const oldCreds = {
    claudeAiOauth: {
      accessToken: 'old-at',
      refreshToken: 'old-rt',
      expiresAt: 1000,
      scopes: ['user:inference'],
      subscriptionType: 'max',
      rateLimitTier: 'default_claude_max_20x',
    },
    someOtherField: 'preserved',
  };

  it('updates accessToken, refreshToken, and expiresAt', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.equal(result.claudeAiOauth.accessToken, 'new-at');
    assert.equal(result.claudeAiOauth.refreshToken, 'new-rt');
    assert.equal(result.claudeAiOauth.expiresAt, 9999);
  });

  it('preserves other claudeAiOauth fields', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.deepEqual(result.claudeAiOauth.scopes, ['user:inference']);
    assert.equal(result.claudeAiOauth.subscriptionType, 'max');
    assert.equal(result.claudeAiOauth.rateLimitTier, 'default_claude_max_20x');
  });

  it('preserves top-level fields', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.equal(result.someOtherField, 'preserved');
  });

  it('does not mutate oldCreds', () => {
    const original = JSON.parse(JSON.stringify(oldCreds));
    buildUpdatedCreds(oldCreds, 'new-at', 'new-rt', 9999);
    assert.deepEqual(oldCreds, original);
  });

  it('skips refreshToken when null', () => {
    const result = buildUpdatedCreds(oldCreds, 'new-at', null, 9999);
    // Should keep the old refresh token
    assert.equal(result.claudeAiOauth.refreshToken, 'old-rt');
  });
});

// ─────────────────────────────────────────────────
// shouldRefreshToken
// ─────────────────────────────────────────────────

describe('shouldRefreshToken', () => {
  const BUFFER = 60 * 60 * 1000; // 1 hour

  it('returns false for falsy expiresAt (0)', () => {
    assert.equal(shouldRefreshToken(0, BUFFER, 1000000), false);
  });

  it('returns false for falsy expiresAt (null)', () => {
    assert.equal(shouldRefreshToken(null, BUFFER, 1000000), false);
  });

  it('returns false for falsy expiresAt (undefined)', () => {
    assert.equal(shouldRefreshToken(undefined, BUFFER, 1000000), false);
  });

  it('returns true when token is already expired', () => {
    const now = 2000000;
    assert.equal(shouldRefreshToken(1000000, BUFFER, now), true);
  });

  it('returns true when within buffer of expiry', () => {
    const now = 1000000;
    const expiresAt = now + 30 * 60 * 1000; // 30 min from now
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), true);
  });

  it('returns false when well beyond buffer', () => {
    const now = 1000000;
    const expiresAt = now + 2 * 60 * 60 * 1000; // 2 hours from now
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), false);
  });

  it('returns true at exactly buffer boundary', () => {
    const now = 1000000;
    const expiresAt = now + BUFFER;
    // expiresAt - now === BUFFER, BUFFER <= BUFFER → true
    assert.equal(shouldRefreshToken(expiresAt, BUFFER, now), true);
  });

  it('uses default buffer of 1 hour', () => {
    const now = 1000000;
    const expiresAt = now + 59 * 60 * 1000; // 59 min (< 1 hour buffer)
    assert.equal(shouldRefreshToken(expiresAt, undefined, now), true);
  });
});

// ─────────────────────────────────────────────────
// createPerAccountLock
// ─────────────────────────────────────────────────

describe('createPerAccountLock', () => {
  it('serializes calls for the same key', async () => {
    const lock = createPerAccountLock();
    const order = [];

    const p1 = lock.withLock('acct1', async () => {
      order.push('start-1');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-1');
      return 'result-1';
    });

    const p2 = lock.withLock('acct1', async () => {
      order.push('start-2');
      return 'result-2';
    });

    const [r1, r2] = await Promise.all([p1, p2]);
    assert.equal(r1, 'result-1');
    assert.equal(r2, 'result-2');
    assert.deepEqual(order, ['start-1', 'end-1', 'start-2']);
  });

  it('allows parallel execution for different keys', async () => {
    const lock = createPerAccountLock();
    const order = [];

    const p1 = lock.withLock('acct1', async () => {
      order.push('start-a');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-a');
    });

    const p2 = lock.withLock('acct2', async () => {
      order.push('start-b');
      await new Promise(r => setTimeout(r, 50));
      order.push('end-b');
    });

    await Promise.all([p1, p2]);
    // Both should start before either ends
    assert.equal(order[0], 'start-a');
    assert.equal(order[1], 'start-b');
  });

  it('releases lock even when fn throws', async () => {
    const lock = createPerAccountLock();

    try {
      await lock.withLock('acct1', async () => {
        throw new Error('test error');
      });
    } catch (e) {
      assert.equal(e.message, 'test error');
    }

    // Should still be able to acquire lock
    const result = await lock.withLock('acct1', async () => 'ok');
    assert.equal(result, 'ok');
  });
});
