// Unit tests for lib.mjs — pure functions
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  getFingerprint,
  getFingerprintFromToken,
  buildForwardHeaders,
  createAccountStateManager,
  isAccountAvailable,
  scoreAccount,
  pickBestAccount,
  pickAnyUntried,
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
    sm.update('tok1', 'acct1', {});
    assert.ok(sm.get('tok1'));
    sm.remove('tok1');
    assert.equal(sm.get('tok1'), undefined);
  });

  it('remove() on non-existent key is a no-op', () => {
    const sm = createAccountStateManager();
    sm.remove('nonexistent'); // should not throw
    assert.equal(sm.get('nonexistent'), undefined);
  });
});

// ─────────────────────────────────────────────────
// buildRefreshRequestBody
// ─────────────────────────────────────────────────

describe('buildRefreshRequestBody', () => {
  it('builds URL-encoded body with grant_type and refresh_token', () => {
    const body = buildRefreshRequestBody('rt-abc123');
    const params = new URLSearchParams(body);
    assert.equal(params.get('grant_type'), 'refresh_token');
    assert.equal(params.get('refresh_token'), 'rt-abc123');
    assert.equal(params.get('client_id'), null);
  });

  it('includes client_id when provided', () => {
    const body = buildRefreshRequestBody('rt-abc123', 'my-client');
    const params = new URLSearchParams(body);
    assert.equal(params.get('client_id'), 'my-client');
  });

  it('handles special characters in refresh token', () => {
    const body = buildRefreshRequestBody('rt-abc+123/foo=bar');
    const params = new URLSearchParams(body);
    assert.equal(params.get('refresh_token'), 'rt-abc+123/foo=bar');
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
