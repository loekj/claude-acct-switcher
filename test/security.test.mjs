// Unit tests: local-only access helpers (lib.mjs).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { isLoopbackAddr, isLocalHost, originAllowed, isSameOrigin } from '../lib.mjs';

describe('isLoopbackAddr', () => {
  it('accepts IPv4, IPv6 and IPv4-mapped loopback', () => {
    for (const a of ['127.0.0.1', '127.1.2.3', '::1', '::ffff:127.0.0.1', '::FFFF:127.0.0.1']) {
      assert.equal(isLoopbackAddr(a), true, a);
    }
  });
  it('refuses LAN, public and junk addresses', () => {
    for (const a of ['192.168.1.5', '10.0.0.1', '::ffff:192.168.1.5', 'fe80::1', '128.0.0.1', '', undefined, null, '127.0.0.1.evil']) {
      assert.equal(isLoopbackAddr(a), false, String(a));
    }
  });
});

describe('isLocalHost', () => {
  it('accepts local names, with or without the right port', () => {
    assert.equal(isLocalHost('localhost:3333', 3333), true);
    assert.equal(isLocalHost('LOCALHOST:3333', 3333), true);
    assert.equal(isLocalHost('127.0.0.1:3333', 3333), true);
    assert.equal(isLocalHost('[::1]:3333', 3333), true);
    assert.equal(isLocalHost('localhost', 3333), true);
  });
  it('refuses other ports, rebinding names and garbage', () => {
    assert.equal(isLocalHost('localhost:4444', 3333), false);
    assert.equal(isLocalHost('evil.example:3333', 3333), false);
    assert.equal(isLocalHost('localhost.evil.example:3333', 3333), false);
    assert.equal(isLocalHost('192.168.1.5:3333', 3333), false);
    assert.equal(isLocalHost('', 3333), false);
    assert.equal(isLocalHost(undefined, 3333), false);
  });
  it('ignores the port when none is given', () => {
    assert.equal(isLocalHost('localhost:9999'), true);
  });
});

describe('originAllowed', () => {
  it('allows no Origin (curl, Claude Code) and local pages', () => {
    assert.equal(originAllowed(undefined), true);
    assert.equal(originAllowed(''), true);
    assert.equal(originAllowed('http://localhost:3333', 3333), true);
    assert.equal(originAllowed('http://127.0.0.1:5173'), true);
  });
  it('refuses web pages, opaque origins and wrong ports', () => {
    assert.equal(originAllowed('https://evil.example'), false);
    assert.equal(originAllowed('null'), false);
    assert.equal(originAllowed('http://localhost:4444', 3333), false);
    assert.equal(originAllowed('https://localhost:3333', 3333), false);
  });
});

describe('isSameOrigin', () => {
  it('matches the exact host', () => {
    assert.equal(isSameOrigin('http://localhost:3333', 'localhost:3333'), true);
    assert.equal(isSameOrigin('http://192.168.1.5:3333', '192.168.1.5:3333'), true);
    assert.equal(isSameOrigin('http://localhost:3333', '127.0.0.1:3333'), false);
    assert.equal(isSameOrigin('https://evil.example', 'localhost:3333'), false);
    assert.equal(isSameOrigin('http://localhost:3333', undefined), false);
  });
});
