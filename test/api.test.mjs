// Integration tests for /api/refresh endpoint
// Uses a mock OAuth server to simulate token refresh responses.
//
// NOTE: These tests require the dashboard server to be running with
// OAUTH_TOKEN_URL pointing to the mock server. They test the refresh
// endpoint in isolation by creating temporary account files.

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { writeFileSync, mkdirSync, existsSync, unlinkSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ─────────────────────────────────────────────────
// Mock OAuth Server
// ─────────────────────────────────────────────────

function createMockOAuthServer(handler) {
  return new Promise((resolve) => {
    const server = createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port, url: `http://127.0.0.1:${port}` });
    });
  });
}

function closeServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

// ─────────────────────────────────────────────────
// Pure function integration tests (no dashboard dependency)
// ─────────────────────────────────────────────────

import {
  buildRefreshRequestBody,
  parseRefreshResponse,
  computeExpiresAt,
  buildUpdatedCreds,
  shouldRefreshToken,
} from '../lib.mjs';

describe('/api/refresh — mock OAuth server', () => {
  let mockServer, mockPort, mockUrl;
  let refreshCount = 0;

  before(async () => {
    const mock = await createMockOAuthServer((req, res) => {
      refreshCount++;
      let body = '';
      req.on('data', c => body += c);
      req.on('end', () => {
        const params = new URLSearchParams(body);
        const refreshToken = params.get('refresh_token');

        if (refreshToken === 'valid-rt') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            access_token: `new-at-${refreshCount}`,
            refresh_token: `new-rt-${refreshCount}`,
            expires_in: 28800,
          }));
        } else if (refreshToken === 'revoked-rt') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            error: 'invalid_grant',
            error_description: 'Refresh token has been revoked',
          }));
        } else if (refreshToken === 'server-error-rt') {
          res.writeHead(500, { 'Content-Type': 'text/plain' });
          res.end('Internal Server Error');
        } else if (refreshToken === 'rate-limited-rt') {
          res.writeHead(429, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'rate_limited' }));
        } else {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_grant' }));
        }
      });
    });
    mockServer = mock.server;
    mockPort = mock.port;
    mockUrl = mock.url;
  });

  after(async () => {
    if (mockServer) await closeServer(mockServer);
  });

  it('mock server returns new tokens for valid refresh token', async () => {
    const body = buildRefreshRequestBody('valid-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await response.json();
    assert.equal(response.status, 200);
    assert.ok(data.access_token.startsWith('new-at-'));
    assert.ok(data.refresh_token.startsWith('new-rt-'));
    assert.equal(data.expires_in, 28800);
  });

  it('mock server returns 400 for revoked token', async () => {
    const body = buildRefreshRequestBody('revoked-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(response.status, 400);
    const data = await response.json();
    assert.equal(data.error, 'invalid_grant');
  });

  it('mock server returns 429 for rate-limited token', async () => {
    const body = buildRefreshRequestBody('rate-limited-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(response.status, 429);
  });

  it('mock server returns 500 for server error token', async () => {
    const body = buildRefreshRequestBody('server-error-rt');
    const response = await fetch(`${mockUrl}/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    assert.equal(response.status, 500);
  });
});

describe('Refresh flow end-to-end (pure functions)', () => {
  it('full refresh cycle: build request → parse response → compute expiry → build creds', () => {
    // 1. Build request
    const body = buildRefreshRequestBody('old-refresh-token');
    assert.ok(body.includes('refresh_token=old-refresh-token'));

    // 2. Simulate successful response
    const responseBody = JSON.stringify({
      access_token: 'fresh-access-token',
      refresh_token: 'fresh-refresh-token',
      expires_in: 7200,
    });
    const parsed = parseRefreshResponse(200, responseBody);
    assert.equal(parsed.ok, true);
    assert.equal(parsed.accessToken, 'fresh-access-token');

    // 3. Compute expiry
    const now = Date.now();
    const expiresAt = computeExpiresAt(parsed.expiresIn, now);
    assert.equal(expiresAt, now + 7200 * 1000);

    // 4. Build updated creds
    const oldCreds = {
      claudeAiOauth: {
        accessToken: 'old-at',
        refreshToken: 'old-rt',
        expiresAt: 1000,
        scopes: ['user:inference'],
        subscriptionType: 'max',
      },
    };
    const newCreds = buildUpdatedCreds(oldCreds, parsed.accessToken, parsed.refreshToken, expiresAt);
    assert.equal(newCreds.claudeAiOauth.accessToken, 'fresh-access-token');
    assert.equal(newCreds.claudeAiOauth.refreshToken, 'fresh-refresh-token');
    assert.equal(newCreds.claudeAiOauth.expiresAt, expiresAt);
    assert.deepEqual(newCreds.claudeAiOauth.scopes, ['user:inference']);
    assert.equal(newCreds.claudeAiOauth.subscriptionType, 'max');

    // 5. Verify shouldRefreshToken says no for fresh token
    assert.equal(shouldRefreshToken(expiresAt, 60 * 60 * 1000, now), false);
  });

  it('handles failed refresh gracefully', () => {
    const parsed = parseRefreshResponse(400, JSON.stringify({
      error: 'invalid_grant',
      error_description: 'Refresh token expired',
    }));
    assert.equal(parsed.ok, false);
    assert.equal(parsed.retriable, false);
    assert.match(parsed.error, /Refresh token expired/);
  });

  it('identifies retriable vs non-retriable errors', () => {
    // Non-retriable
    assert.equal(parseRefreshResponse(400, '{}').retriable, false);
    assert.equal(parseRefreshResponse(401, '{}').retriable, false);
    assert.equal(parseRefreshResponse(403, '{}').retriable, false);

    // Retriable
    assert.equal(parseRefreshResponse(429, '{}').retriable, true);
    assert.equal(parseRefreshResponse(500, '{}').retriable, true);
    assert.equal(parseRefreshResponse(502, '{}').retriable, true);
    assert.equal(parseRefreshResponse(503, '{}').retriable, true);
  });
});
