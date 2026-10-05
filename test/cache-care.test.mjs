// Unit tests: cache care (lib.mjs) — rebuild causes, return curve, keep-warm policy, ledger.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  HOUR_MS, cachePrices, rebuildCost, pingCostRatio, breakEvenPings, isCacheRebuild,
  cacheFingerprint, classifyRebuild, returnCurve, weibullCurve, bestPingCount, backtestPings,
  createKeepWarmPlanner, createCacheLedger, RETURN_PRIOR,
} from '../lib.mjs';

const close = (a, b, eps = 1e-9) => assert.ok(Math.abs(a - b) < eps, `${a} ≈ ${b}`);

describe('cache prices and break-even', () => {
  it('uses the per-model read price and the TTL write price', () => {
    assert.deepEqual(cachePrices('claude-opus-5-5', HOUR_MS), { input: 4, read: 0.2, write: 8 });
    assert.deepEqual(cachePrices('claude-opus-5-5', 5 * 60000), { input: 4, read: 0.2, write: 5 });
    close(rebuildCost(1e6, 'claude-opus-5-5'), 7.8);
    close(pingCostRatio('claude-opus-5-5'), 0.2 / 7.8);
    assert.equal(breakEvenPings('claude-opus-5-5'), 39);
    assert.equal(breakEvenPings('claude-fable-5-1'), 79);
  });

  it('counts only the part of the previous prompt that was not read back', async () => {
    const { lostCacheTokens } = await import('../lib.mjs');
    assert.equal(lostCacheTokens(0, 500_000), 500_000);
    assert.equal(lostCacheTokens(22_000, 21_000), 0);      // a turn that appended a big tool result
    assert.equal(lostCacheTokens(100_000, 500_000), 400_000);
    assert.equal(lostCacheTokens(0, 5_000), 0);            // small: not counted
  });

  it('spots a rebuild only for big prompts that were mostly written', () => {
    assert.equal(isCacheRebuild({ input: 10, cacheRead: 0, cacheWrite1h: 500_000 }), true);
    assert.equal(isCacheRebuild({ input: 10, cacheRead: 490_000, cacheWrite1h: 5_000 }), false);
    assert.equal(isCacheRebuild({ input: 10, cacheWrite5m: 15_000 }), false); // small: not counted
  });
});

describe('cache doctor', () => {
  const body = (over = {}) => JSON.stringify({
    model: 'claude-opus-5-5', thinking: { type: 'adaptive' },
    tools: [{ name: 'Bash', input_schema: {} }],
    system: [{ type: 'text', text: 'You are Claude Code', cache_control: { type: 'ephemeral', ttl: '1h' } }],
    messages: [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'yo' }, { role: 'user', content: [{ type: 'text', text: 'next', cache_control: { type: 'ephemeral' } }] }],
    ...over,
  });

  it('ignores moving cache_control markers', () => {
    const a = cacheFingerprint(body());
    const b = cacheFingerprint(body({ messages: [{ role: 'user', content: 'hi' }, { role: 'assistant', content: 'yo' }, { role: 'user', content: [{ type: 'text', text: 'next' }] }, { role: 'assistant', content: 'ok', cache_control: { type: 'ephemeral' } }] }));
    assert.deepEqual(b.msgs.slice(0, 3), a.msgs);
    assert.equal(classifyRebuild(a, b, { gapMs: 1000 }).cause, 'unknown');
  });

  it('names each cause', () => {
    const a = cacheFingerprint(body(), { 'anthropic-beta': 'x' });
    const cause = (over, ctx = {}, headers = { 'anthropic-beta': 'x' }) => classifyRebuild(a, cacheFingerprint(body(over), headers), { gapMs: 1000, ...ctx }).cause;
    assert.equal(cause({}, { gapMs: 2 * HOUR_MS }), 'idle');
    assert.equal(cause({}, { prevAccount: 'a@x', account: 'b@x' }), 'account');
    assert.equal(cause({ model: 'claude-fable-5-1' }), 'model');
    assert.equal(cause({ tools: [{ name: 'Bash', input_schema: {} }, { name: 'Read', input_schema: {} }] }), 'tools');
    assert.equal(cause({ system: [{ type: 'text', text: 'You are Claude Code. Today is Tuesday.' }] }), 'system');
    assert.equal(cause({ thinking: { type: 'enabled', budget_tokens: 5000 } }), 'settings');
    assert.equal(cause({}, {}, { 'anthropic-beta': 'y' }), 'beta');
    assert.equal(cause({ messages: [{ role: 'user', content: 'summary of earlier' }, { role: 'user', content: 'next' }] }), 'history');
    assert.equal(cacheFingerprint('not json'), null);
  });
});

describe('return curve', () => {
  it('Kaplan–Meier with censoring matches a hand computation', () => {
    const P = HOUR_MS;
    const periods = [
      { waitMs: 0.5 * P, returned: true }, { waitMs: 1.5 * P, returned: true }, { waitMs: 1.5 * P, returned: true },
      { waitMs: 3.5 * P, returned: false }, { waitMs: 2.5 * P, returned: true },
    ];
    const s = returnCurve(periods, { periodMs: P, maxK: 5 });
    [1, 0.8, 0.4, 0.2, 0.2].forEach((v, k) => close(s[k], v));
  });

  it('the Weibull prior falls fast, then keeps a long tail', () => {
    const s = weibullCurve(RETURN_PRIOR.shape, RETURN_PRIOR.scaleMs, { maxK: 48 });
    assert.ok(s[2] < 0.75 && s[24] > 0.25, `${s[2]} ${s[24]}`);
  });
});

describe('ping count (look-ahead)', () => {
  it('keeps going through a quiet night when the morning brings people back', () => {
    // Returns early, almost none for 8 periods (night), many again after (morning)
    const surv = [1];
    const hazard = (k) => (k < 3 ? 0.3 : k < 11 ? 0.005 : 0.4);
    for (let k = 0; k < 40; k++) surv.push(surv[k] * (1 - hazard(k)));
    const ratio = 0.025;
    // A one-step rule ("is the next period worth it?") stops at the night
    let oneStep = 0;
    while (oneStep < 39 && hazard(oneStep + 1) >= ratio) oneStep++;
    assert.equal(oneStep, 2);
    // The look-ahead sees the morning and keeps the cache warm through the night
    assert.ok(bestPingCount(surv, ratio, 39) >= 11, String(bestPingCount(surv, ratio, 39)));
  });

  it('matches a brute-force search, and returns 0 when pinging never pays', () => {
    let seed = 3;
    const rand = () => (seed = (seed * 48271) % 2147483647) / 2147483647;
    for (let trial = 0; trial < 300; trial++) {
      const surv = [1];
      for (let k = 0; k < 30; k++) surv.push(surv[k] * (1 - rand() * rand()));
      const ratio = 0.005 + rand() * 0.2;
      const value = (H) => { let v = 0; for (let k = 1; k <= H; k++) v += (surv[k] - surv[k + 1]) * (1 - k * ratio); return v - surv[H + 1] * H * ratio; };
      let best = 0, bestV = 0;
      for (let H = 1; H <= 28; H++) if (value(H) > bestV + 1e-15) { bestV = value(H); best = H; }
      assert.equal(bestPingCount(surv, ratio, 28), best, 'trial ' + trial);
    }
    // Everyone comes back within the first period: no ping ever helps
    assert.equal(bestPingCount([1, 0, 0, 0, 0], 0.025, 3), 0);
  });

  it('never pings when nobody comes back, and respects the cap', () => {
    const never = new Array(50).fill(1);
    assert.equal(bestPingCount(never, 0.025, 39), 0);
    const always = [1, ...new Array(49).fill(0.0)];
    assert.ok(bestPingCount(always, 0.025, 39) <= 39);
  });

  it('backtest scores a policy on recorded idle periods', () => {
    const P = HOUR_MS - 60000;
    const periods = [{ waitMs: 2 * P, returned: true, tokens: 1 }, { waitMs: 10 * P, returned: false, tokens: 1 }];
    close(backtestPings(periods, () => 0, 0.025), 0);
    // Warm at return needs 1 ping (the last request covers the first period); the one that
    // never came back costs all 3 pings
    close(backtestPings(periods, () => 3, 0.025), (1 - 1 * 0.025) - 3 * 0.025);
  });
});

describe('keep-warm planner', () => {
  const T0 = Date.UTC(2026, 9, 5, 12);
  const setup = (limit = 5) => {
    let t = T0;
    const p = createKeepWarmPlanner({ now: () => t, pingLimit: () => limit });
    const real = (sid, at, extra = {}) => {
      t = at; p.start(sid);
      const r = p.finish(sid, { startedAt: at, account: 'a@x', model: 'claude-opus-5-5', ttlMs: HOUR_MS, tokens: 500_000, cacheRead: 490_000, ...extra });
      p.end(sid);
      return r;
    };
    return { p, real, at: (x) => { t = x; } };
  };

  it('pings a minute before the TTL runs out, counted from the request start', () => {
    const { p, real } = setup();
    real('s1', T0);
    assert.equal(p.due(T0 + HOUR_MS - 2 * 60000).length, 0);
    assert.equal(p.due(T0 + HOUR_MS - 60000)[0].sid, 's1');
  });

  it('never pings during a real request, small caches, or "never" lanes', () => {
    const { p, real } = setup();
    real('s1', T0);
    p.start('s1'); // a real request is still running
    assert.equal(p.due(T0 + HOUR_MS).length, 0);
    p.end('s1');
    real('small', T0, { tokens: 5_000 });
    assert.equal(p.due(T0 + HOUR_MS).some(l => l.sid === 'small'), false);
    real('n', T0); p.setMode('n', 'never');
    assert.equal(p.due(T0 + HOUR_MS).some(l => l.sid === 'n'), false);
  });

  it('stops after its limit, after a failed ping, and after a missed window (sleep)', () => {
    const { p, real } = setup(2);
    real('s1', T0);
    let t = T0 + HOUR_MS - 60000;
    for (let i = 0; i < 2; i++) { assert.equal(p.due(t).length, 1); p.pinged('s1', { ok: true, startedAt: t }); t += HOUR_MS - 60000; }
    assert.equal(p.due(t).length, 0);
    assert.equal(p.get('s1').stopped, 'done');
    real('s2', T0); p.pinged('s2', { ok: false, reason: 'verify' });
    assert.equal(p.due(T0 + HOUR_MS).some(l => l.sid === 's2'), false);
    real('s3', T0);
    assert.equal(p.due(T0 + 3 * HOUR_MS).some(l => l.sid === 's3'), false);
    assert.equal(p.get('s3').stopped, 'cold');
  });

  it('a real request after pings that reads the cache is a warm resume', () => {
    const { p, real } = setup();
    real('s1', T0);
    const t1 = T0 + HOUR_MS - 60000;
    p.pinged('s1', { ok: true, startedAt: t1 });
    p.start('s1');
    const back = p.finish('s1', { startedAt: t1 + 30 * 60000, account: 'a@x', model: 'claude-opus-5-5', ttlMs: HOUR_MS, tokens: 510_000, cacheRead: 500_000 });
    p.end('s1');
    assert.equal(back.warmResume, true);
    assert.ok(back.idle && back.idle.pings === 1 && back.idle.waitMs >= HOUR_MS, JSON.stringify(back.idle)); // idle counted from the real request, not the ping
    // Moved to another account: not a warm resume
    const { p: q, real: realQ } = setup();
    realQ('s1', T0); q.pinged('s1', { ok: true, startedAt: t1 }); q.start('s1');
    assert.equal(q.finish('s1', { startedAt: t1 + 1000, account: 'b@x', tokens: 510_000, cacheRead: 0 }).warmResume, false);
    q.end('s1');
  });

  it('ignores a ping result that arrives after a real request started', () => {
    const { p, real } = setup();
    real('s1', T0);
    const pingAt = T0 + HOUR_MS - 60000;
    real('s1', pingAt + 2000);                 // the user came back while the ping was in flight
    p.pinged('s1', { ok: true, startedAt: pingAt });
    assert.equal(p.get('s1').pings, 0);
    assert.equal(p.get('s1').touchedAt, pingAt + 2000);
  });
});

describe('cache ledger', () => {
  it('sums savings, ping cost and rebuilds into one percentage', () => {
    const l = createCacheLedger();
    const t = Date.UTC(2026, 9, 5, 12);
    l.ping(0.1, t); l.ping(0.1, t);
    l.warmResume(4, t);
    l.affinity(2, t);
    l.rebuild('idle', 3, t); l.rebuild('account', 1, t);
    const s = l.summary(t - 86400000);
    close(s.saved, 4 - 0.2 + 2);
    close(s.rebuildCost, 4);
    close(s.pct, 5.8 / 10);
    assert.equal(s.rebuilds.idle.count, 1);
    const again = createCacheLedger(JSON.parse(JSON.stringify(l.toJSON())));
    close(again.summary(0).saved, s.saved);
  });
});

describe('policy check on synthetic data shaped like real use', () => {
  it('the learned look-ahead matches the best fixed limit without being told one', () => {
    // Heavy-tailed returns (Weibull shape 0.5, scale 17 h) plus 8% sessions that never return
    let seed = 7;
    const rand = () => (seed = (seed * 16807) % 2147483647) / 2147483647;
    const P = HOUR_MS - 60000;
    const make = (n) => Array.from({ length: n }, () => {
      if (rand() < 0.08) return { waitMs: 48 * HOUR_MS * rand(), returned: false, tokens: 500_000 };
      const w = 17 * HOUR_MS * Math.pow(-Math.log(1 - rand()), 1 / 0.5);
      return { waitMs: Math.max(P, w), returned: true, tokens: 500_000 };
    });
    const train = make(600), test = make(600);
    const ratio = pingCostRatio('claude-opus-5-5');
    const learned = bestPingCount(returnCurve(train), ratio, breakEvenPings('claude-opus-5-5'));
    const score = backtestPings(test, () => learned, ratio);
    const bestFixed = Math.max(...[2, 4, 8, 12, 24, 36].map(h => backtestPings(test, () => Math.round(h * HOUR_MS / P), ratio)));
    assert.ok(score >= bestFixed - 0.03, `learned ${score.toFixed(3)} vs best fixed ${bestFixed.toFixed(3)} (H=${learned})`);
    assert.ok(score > 0.2, `learned ${score.toFixed(3)}`); // this synthetic curve allows ~1/3 (real data: 2/3)
  });
});

describe('setTopLevelJsonFields (ping body)', () => {
  it('changes only the named top-level fields, byte for byte', async () => {
    const { setTopLevelJsonFields } = await import('../lib.mjs');
    const body = '{"model":"m","max_tokens":32000,"stream":true,"tools":[{"input_schema":{"properties":{"b":1,"1":2}}}],' +
      '"messages":[{"role":"user","content":"say \\"max_tokens\\":5 and \\u2028 \\ud83d"}],"metadata":{"stream":true,"max_tokens":9}}';
    const out = setTopLevelJsonFields(body, { max_tokens: 0, stream: false });
    assert.equal(out, body.replace('"max_tokens":32000', '"max_tokens":0').replace('"stream":true,"tools"', '"stream":false,"tools"'));
    // JSON.parse + stringify would have reordered "1" before "b": we did not
    assert.ok(out.includes('{"b":1,"1":2}'));
    const j = JSON.parse(out);
    assert.equal(j.max_tokens, 0); assert.equal(j.stream, false);
    assert.deepEqual(j.metadata, { stream: true, max_tokens: 9 });
  });

  it('adds missing fields, keeps whitespace, refuses non-objects', async () => {
    const { setTopLevelJsonFields } = await import('../lib.mjs');
    assert.equal(setTopLevelJsonFields('{ "model": "m" }', { stream: false }), '{"stream":false, "model": "m" }');
    assert.equal(setTopLevelJsonFields('{}', { stream: false }), '{"stream":false}');
    assert.equal(setTopLevelJsonFields('[1,2]', { stream: false }), null);
    assert.equal(setTopLevelJsonFields('{"a":"unterminated', { stream: false }), null);
  });
});
