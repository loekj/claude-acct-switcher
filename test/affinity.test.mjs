// Unit tests: unified rate-limit headers, model-aware availability, balance picking,
// and session affinity (lib.mjs).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  parseRateLimitHeaders,
  modelBucket,
  isAccountExhausted,
  isAccountAvailable,
  createAccountStateManager,
  createInflightTracker,
  pickLeastLoaded,
  pickByStrategy,
  createSessionStore,
  sessionAffinity,
  sessionLabel,
  extractSessionId,
  extractModel,
  cacheTtlFromBody,
  AFFINITY_DEFAULT_TTL_MS,
  AFFINITY_LONG_TTL_MS,
} from '../lib.mjs';

const NOW = 1_800_000_000_000;              // fixed clock (ms)
const NOW_S = Math.floor(NOW / 1000);
const H = (o) => Object.fromEntries(Object.entries(o).map(([k, v]) => [`anthropic-ratelimit-unified-${k}`, String(v)]));

describe('parseRateLimitHeaders', () => {
  it('reads status, claim and every window (incl. the Fable bucket)', () => {
    const rl = parseRateLimitHeaders(H({
      status: 'allowed_warning', 'representative-claim': 'seven_day', reset: NOW_S + 50,
      '5h-utilization': 0.4, '5h-reset': NOW_S + 100,
      '7d-utilization': 0.8, '7d-reset': NOW_S + 900,
      '7d_oi-utilization': 0.97, '7d_oi-reset': NOW_S + 800,
    }));
    assert.equal(rl.status, 'allowed_warning');
    assert.equal(rl.claim, 'seven_day');
    assert.deepEqual(rl.fiveH, { utilization: 0.4, reset: NOW_S + 100 });
    assert.deepEqual(rl.sevenD, { utilization: 0.8, reset: NOW_S + 900 });
    assert.deepEqual(rl.sevenDOI, { utilization: 0.97, reset: NOW_S + 800 });
  });

  it('returns null windows and status when headers are absent (transient 429)', () => {
    const rl = parseRateLimitHeaders({ 'retry-after': '3' });
    assert.equal(rl.status, null);
    assert.equal(rl.fiveH, null);
    assert.equal(rl.sevenDOI, null);
  });
});

describe('modelBucket', () => {
  it('maps Fable/Mythos to the per-model weekly bucket only', () => {
    assert.equal(modelBucket('claude-fable-5-1'), 'sevenDOI');
    assert.equal(modelBucket('claude-mythos-5-1'), 'sevenDOI');
    assert.equal(modelBucket('claude-opus-5-5'), null);
    assert.equal(modelBucket(null), null);
  });
});

describe('createAccountStateManager (unified headers)', () => {
  it('treats status "rejected" as limited until the claim reset', () => {
    const sm = createAccountStateManager();
    sm.update('t', 'a', H({ status: 'rejected', reset: NOW_S + 600, '5h-utilization': 1, '5h-reset': NOW_S + 600 }));
    assert.equal(sm.get('t').limited, true);
    assert.equal(isAccountAvailable('t', 0, sm, NOW), false);
    assert.equal(isAccountAvailable('t', 0, sm, (NOW_S + 601) * 1000), true);
  });

  it('keeps the last Fable-bucket reading when a response omits it', () => {
    const sm = createAccountStateManager();
    sm.update('t', 'a', H({ status: 'allowed', '7d_oi-utilization': 0.5, '7d_oi-reset': NOW_S + 999 }));
    sm.update('t', 'a', H({ status: 'allowed', '5h-utilization': 0.1 }));
    assert.equal(sm.get('t').utilization7dOI, 0.5);
    assert.equal(sm.get('t').resetAt7dOI, NOW_S + 999);
  });

  it('markRejected on the Fable claim blocks only Fable requests', () => {
    const sm = createAccountStateManager();
    const r = sm.markRejected('t', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day_overage_included', reset: NOW_S + 3600 }), NOW);
    assert.equal(r.scope, 'model');
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-fable-5-1'), false);
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-opus-5-5'), true);
  });

  it('markRejected on a shared claim blocks the whole account until reset', () => {
    const sm = createAccountStateManager();
    const r = sm.markRejected('t', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day', reset: NOW_S + 7200 }), NOW);
    assert.equal(r.scope, 'account');
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-opus-5-5'), false);
    // The 5h reset passing does not unblock a weekly rejection.
    sm.get('t').resetAt = NOW_S + 10;
    assert.equal(isAccountAvailable('t', 0, sm, (NOW_S + 60) * 1000), false);
    assert.equal(isAccountAvailable('t', 0, sm, (NOW_S + 7201) * 1000), true);
  });

  it('a later Fable reading below 100% clears the Fable block', () => {
    const sm = createAccountStateManager();
    sm.markRejected('t', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day_overage_included', reset: NOW_S + 3600 }), NOW);
    sm.update('t', 'a', H({ status: 'allowed', '7d_oi-utilization': 0.4, '7d_oi-reset': NOW_S + 3600 }));
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-fable-5-1'), true);
  });

  it('restore() seeds state from a persisted snapshot', () => {
    const sm = createAccountStateManager();
    sm.restore('t', 'a', { utilization5h: 1, resetAt: Math.floor(Date.now() / 1000) + 600, updatedAt: 123 });
    assert.equal(sm.get('t').updatedAt, 123);
    assert.equal(isAccountAvailable('t', 0, sm), false);
  });
});

describe('isAccountExhausted', () => {
  it('flags a used-up 5h or weekly window until its reset', () => {
    assert.equal(isAccountExhausted({ utilization5h: 1, resetAt: NOW_S + 10 }, null, NOW), true);
    assert.equal(isAccountExhausted({ utilization5h: 1, resetAt: NOW_S - 10 }, null, NOW), false);
    assert.equal(isAccountExhausted({ utilization7d: 1.02, resetAt7d: NOW_S + 10 }, null, NOW), true);
  });

  it('ignores a full reading with an unknown reset (no permanent lockout)', () => {
    assert.equal(isAccountExhausted({ utilization5h: 1, resetAt: 0 }, null, NOW), false);
  });

  it('checks the Fable bucket only for Fable requests', () => {
    const s = { utilization7dOI: 1, resetAt7dOI: NOW_S + 10 };
    assert.equal(isAccountExhausted(s, 'claude-fable-5-1', NOW), true);
    assert.equal(isAccountExhausted(s, 'claude-opus-5-5', NOW), false);
  });
});

describe('pickLeastLoaded (balance)', () => {
  const accounts = [
    { name: 'a', token: 'tokA', expiresAt: 0 },
    { name: 'b', token: 'tokB', expiresAt: 0 },
    { name: 'c', token: 'tokC', expiresAt: 0 },
  ];

  it('skips accounts whose 5h window is used up even with zero in-flight', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const reset = Math.floor(Date.now() / 1000) + 3600;
    sm.update('tokA', 'a', H({ status: 'allowed', '5h-utilization': 1, '5h-reset': reset }));
    inflight.acquire('b'); inflight.acquire('b');
    inflight.acquire('c');
    const pick = pickLeastLoaded(accounts, inflight, sm, 8);
    assert.equal(pick.account.name, 'c');
  });

  it('puts nearly-full accounts behind ones with headroom', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    sm.update('tokA', 'a', H({ '5h-utilization': 0.95 }));
    sm.update('tokB', 'b', H({ '7d-utilization': 0.93 }));
    inflight.acquire('c'); inflight.acquire('c'); inflight.acquire('c');
    const pick = pickLeastLoaded(accounts, inflight, sm, 8);
    assert.equal(pick.account.name, 'c');
  });

  it('skips Fable-exhausted accounts only for Fable requests', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const reset = Math.floor(Date.now() / 1000) + 3600;
    sm.update('tokA', 'a', H({ '7d_oi-utilization': 1, '7d_oi-reset': reset }));
    inflight.acquire('b'); inflight.acquire('c');
    assert.equal(pickLeastLoaded(accounts, inflight, sm, 8, new Set(), Date.now(), { model: 'claude-fable-5-1' }).account.name, 'b');
    assert.equal(pickLeastLoaded(accounts, inflight, sm, 8, new Set(), Date.now(), { model: 'claude-opus-5-5' }).account.name, 'a');
  });

  it('counts extra load (warm lanes) and honors prefer when it has a free slot', () => {
    const sm = createAccountStateManager();
    const inflight = createInflightTracker();
    const pick = pickLeastLoaded(accounts, inflight, sm, 8, new Set(), Date.now(), { extraLoad: { a: 2, b: 1 } });
    assert.equal(pick.account.name, 'c');
    const preferred = pickLeastLoaded(accounts, inflight, sm, 8, new Set(), Date.now(), { extraLoad: { a: 2 }, prefer: 'a' });
    assert.equal(preferred.account.name, 'a');
  });
});

describe('pickByStrategy (model-aware)', () => {
  it('replaces the current account when its Fable bucket is used up', () => {
    const sm = createAccountStateManager();
    const reset = Math.floor(Date.now() / 1000) + 3600;
    sm.update('tokA', 'a', H({ '7d_oi-utilization': 1, '7d_oi-reset': reset }));
    const accounts = [{ name: 'a', token: 'tokA' }, { name: 'b', token: 'tokB' }];
    const r = pickByStrategy({ strategy: 'sticky', currentToken: 'tokA', accounts, stateManager: sm, model: 'claude-fable-5-1' });
    assert.equal(r.account.name, 'b');
    const keep = pickByStrategy({ strategy: 'sticky', currentToken: 'tokA', accounts, stateManager: sm, model: 'claude-opus-5-5' });
    assert.equal(keep.account, null);
  });
});

describe('createSessionStore', () => {
  it('pins a lane and routes back to it while warm', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    assert.equal(st.route('s1', 'main'), null);
    assert.equal(st.pin('s1', 'main', 'acctA'), null, 'first pin is not a move');
    t += 60_000;
    assert.deepEqual(st.route('s1', 'main'), { account: 'acctA', warm: true, idleMs: 60_000 });
    t += AFFINITY_DEFAULT_TTL_MS;
    assert.equal(st.route('s1', 'main').warm, false, 'idle past the cache TTL = cold');
  });

  it('records warm vs cold moves', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA');
    t += 1000;
    const warm = st.pin('s1', 'main', 'acctB', { reason: '429' });
    assert.equal(warm.warm, true);
    assert.equal(warm.reason, '429');
    t += AFFINITY_LONG_TTL_MS;
    const cold = st.pin('s1', 'main', 'acctA', { reason: 'rebalance' });
    assert.equal(cold.warm, false);
    assert.equal(st.get('s1').moves.length, 2);
  });

  it('keeps lanes warm for the TTL the requests ask for', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA', { ttlMs: AFFINITY_LONG_TTL_MS });
    t += 30 * 60 * 1000;
    assert.equal(st.route('s1', 'main').warm, true);
  });

  it('unpinAll makes the next pin a recorded move with the given reason', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA');
    st.unpinAll('manual-switch');
    assert.equal(st.route('s1', 'main'), null);
    const move = st.pin('s1', 'main', 'acctB');
    assert.equal(move.from, 'acctA');
    assert.equal(move.reason, 'manual-switch');
  });

  it('warmLoad counts warm lanes per account; home prefers the main lane', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA');
    st.pin('s1', 'agent-1', 'acctB');
    st.pin('s2', 'main', 'acctA');
    assert.deepEqual(st.warmLoad(), { acctA: 2, acctB: 1 });
    assert.equal(st.home('s1'), 'acctA');
  });

  it('recordRequest tracks per-account totals; toJSON/load round-trips', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA');
    st.recordRequest('s1', 'main', 'acctA', { input: 10, output: 5, cacheRead: 900, cacheWrite5m: 90, cost: 0.01 }, { model: 'claude-opus-5-5' });
    const copy = createSessionStore({ now: () => t });
    copy.load(JSON.parse(JSON.stringify(st.toJSON())));
    const s = copy.get('s1');
    assert.equal(s.accounts.acctA.requests, 1);
    assert.equal(s.accounts.acctA.cacheRead, 900);
    assert.equal(s.model, 'claude-opus-5-5');
  });

  it('prune drops idle lanes after a day and idle sessions after a week', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA');
    t += 25 * 60 * 60 * 1000;
    st.prune();
    assert.equal(st.route('s1', 'main'), null);
    assert.ok(st.get('s1'));
    t += 7 * 24 * 60 * 60 * 1000;
    st.prune();
    assert.equal(st.get('s1'), null);
  });

  it('renameAccount carries pins and stats over', () => {
    const st = createSessionStore({ now: () => NOW });
    st.pin('s1', 'main', 'old');
    st.recordRequest('s1', 'main', 'old', { input: 1 });
    st.renameAccount('old', 'new');
    assert.equal(st.route('s1', 'main').account, 'new');
    assert.ok(st.get('s1').accounts.new);
  });
});

describe('sessionAffinity', () => {
  it('strong when nothing moved and requests stay on one account', () => {
    const a = sessionAffinity({ moves: [], recent: [{ account: 'x', prompt: 100, cacheRead: 90 }, { account: 'x', prompt: 100, cacheRead: 95 }] }, NOW);
    assert.equal(a.level, 'strong');
    assert.ok(Math.abs(a.cacheHit - 0.925) < 1e-9);
  });

  it('ok after one warm move in the last hour, weak after two', () => {
    const recent = [{ account: 'x' }];
    assert.equal(sessionAffinity({ moves: [{ ts: NOW - 1000, warm: true }], recent }, NOW).level, 'ok');
    assert.equal(sessionAffinity({ moves: [{ ts: NOW - 1000, warm: true }, { ts: NOW - 2000, warm: true }], recent }, NOW).level, 'weak');
    assert.equal(sessionAffinity({ moves: [{ ts: NOW - 1000, warm: false }], recent }, NOW).level, 'strong', 'cold moves are free');
  });

  it('weak when recent requests are spread over accounts', () => {
    const recent = ['x', 'y', 'x', 'y', 'x', 'y'].map(account => ({ account }));
    assert.equal(sessionAffinity({ moves: [], recent }, NOW).level, 'weak');
    // too few requests to judge spread
    assert.equal(sessionAffinity({ moves: [], recent: recent.slice(0, 3) }, NOW).level, 'strong');
  });
});

describe('session helpers', () => {
  it('sessionLabel prefers the user name, then branch:id', () => {
    assert.equal(sessionLabel({ name: 'customer-flow', nameSource: 'user', branch: 'main' }, 'abcdef123456'), 'customer-flow');
    assert.equal(sessionLabel({ name: 'auto name', nameSource: 'auto', branch: 'feat/x' }, 'abcdef123456'), 'feat/x:abcdef12');
    assert.equal(sessionLabel({ cwd: '/Users/me/git/repo' }, 'abcdef123456'), 'repo:abcdef12');
    assert.equal(sessionLabel({}, 'abcdef123456'), 'abcdef12');
  });

  it('extractSessionId reads the header, then metadata.user_id', () => {
    assert.equal(extractSessionId({ 'x-claude-code-session-id': 'sid-1' }), 'sid-1');
    const uuid = '0f8b7c1e-1111-2222-3333-444455556666';
    assert.equal(extractSessionId({}, `{"metadata":{"user_id":"user_abc_account_x_session_${uuid}"}}`), uuid);
    assert.equal(extractSessionId({}, `{"metadata":{"user_id":"{\\"device_id\\":\\"d\\",\\"session_id\\":\\"${uuid}\\"}"}}`), uuid);
    assert.equal(extractSessionId({}, '{"model":"x"}'), null);
  });

  it('extractModel and cacheTtlFromBody', () => {
    assert.equal(extractModel('{"model":"claude-opus-5-5","messages":[]}'), 'claude-opus-5-5');
    assert.equal(cacheTtlFromBody('{"cache_control":{"type":"ephemeral","ttl":"1h"}}'), AFFINITY_LONG_TTL_MS);
    assert.equal(cacheTtlFromBody('{"cache_control":{"type":"ephemeral"}}'), AFFINITY_DEFAULT_TTL_MS);
  });
});

describe('createSessionStore meta/artifacts before first request', () => {
  it('setMeta and addArtifact create the session when needed', () => {
    const st = createSessionStore({ now: () => NOW });
    st.setMeta('s9', { branch: 'main' });
    assert.equal(sessionLabel(st.get('s9').meta, 's9abcdefgh'), 'main:s9abcdef');
    assert.equal(st.addArtifact('s10', 'slug-1'), true);
    assert.equal(st.addArtifact('s10', 'slug-1'), false);
  });
});

describe('home() after unpinAll', () => {
  it('still reports the last account of a released lane', () => {
    const st = createSessionStore({ now: () => NOW });
    st.pin('s1', 'main', 'acctA');
    st.unpinAll();
    assert.equal(st.home('s1'), 'acctA');
  });
});

describe('review fixes', () => {
  it('a response without unified headers keeps the learned state', () => {
    const sm = createAccountStateManager();
    sm.markRejected('t', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day', reset: NOW_S + 7200 }), NOW);
    sm.update('t', 'a', { 'content-type': 'application/json' }); // e.g. a 500 or a non-Messages endpoint
    assert.equal(sm.get('t').limited, true);
    assert.equal(isAccountAvailable('t', 0, sm, NOW), false);
  });

  it('transfer() moves every field to the refreshed token', () => {
    const sm = createAccountStateManager();
    sm.markRejected('old', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day_overage_included', reset: NOW_S + 3600 }), NOW);
    sm.transfer('old', 'new');
    assert.equal(sm.get('old'), undefined);
    assert.equal(isAccountAvailable('new', 0, sm, NOW, 'claude-fable-5-1'), false);
  });

  it('weekly Opus / Sonnet claims only block that model family', () => {
    const sm = createAccountStateManager();
    const r = sm.markRejected('t', 'a', H({ status: 'rejected', 'representative-claim': 'seven_day_opus', reset: NOW_S + 7200 }), NOW);
    assert.equal(r.scope, 'model');
    assert.equal(r.family, 'opus');
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-opus-5-5'), false);
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-sonnet-5-5'), true);
    assert.equal(isAccountAvailable('t', 0, sm, NOW, 'claude-haiku-4-5'), true);
  });

  it('a short-TTL side call never shrinks a lane on the 1h cache', () => {
    let t = NOW;
    const st = createSessionStore({ now: () => t });
    st.pin('s1', 'main', 'acctA', { ttlMs: AFFINITY_LONG_TTL_MS });
    st.touch('s1', 'main', { ttlMs: AFFINITY_DEFAULT_TTL_MS });
    st.recordRequest('s1', 'main', 'acctA', {}, { ttlMs: AFFINITY_DEFAULT_TTL_MS });
    t += 6 * 60 * 1000;
    assert.equal(st.route('s1', 'main').warm, true);
  });
});
