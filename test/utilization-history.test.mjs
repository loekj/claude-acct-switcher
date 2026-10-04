// Unit tests: per-account usage history behind the account-card charts (lib.mjs).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createUtilizationHistory } from '../lib.mjs';

const MIN = 60 * 1000;
const T0 = Date.UTC(2026, 9, 3, 12, 0);

describe('createUtilizationHistory', () => {
  it('steady traffic gives one point per bucket (it used to collapse into one sliding point)', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    for (let t = 0; t < 60 * MIN; t += 30 * 1000) h.record('acct', t / (600 * MIN), 0.5, T0 + t); // a request every 30 s for an hour
    const pts = h.getHistory('acct');
    assert.equal(pts.length, 30);
    assert.ok(pts.every((p, i) => i === 0 || p.ts - pts[i - 1].ts >= MIN), 'points spread over the hour');
    assert.ok(Math.abs(pts.at(-1).u5h - (59.5 / 600)) < 1e-9, 'each bucket keeps its latest value');
  });

  it('a missing header keeps the last known value instead of dropping to 0', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    h.record('acct', 0.4, 0.7, T0);
    h.record('acct', null, 0.71, T0 + 5 * MIN);
    h.record('acct', 0.45, null, T0 + 10 * MIN);
    h.record('acct', null, null, T0 + 15 * MIN); // nothing known: no point
    assert.deepEqual(h.getHistory('acct').map(p => [p.u5h, p.u7d]), [[0.4, 0.7], [0.4, 0.71], [0.45, 0.71]]);
  });

  it('ignores slightly out-of-order samples and junk values', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    h.record('acct', 0.3, 0.3, T0 + 10 * MIN);
    h.record('acct', 0.9, 0.9, T0 + 10 * MIN - 30000); // 30 s older than the last point
    h.record('acct', NaN, 'x', T0 + 20 * MIN); // nothing usable: no point
    h.record('acct', 7, -1, T0 + 30 * MIN); // clamped
    assert.deepEqual(h.getHistory('acct').map(p => [p.u5h, p.u7d]), [[0.3, 0.3], [1.5, 0]]);
  });

  it('a clock that jumps back drops the points "from the future" instead of freezing', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    h.record('acct', 0.2, 0.2, T0);
    h.record('acct', 0.5, 0.5, T0 + 3 * 60 * MIN);        // clock was 3 hours ahead
    h.record('acct', 0.3, 0.3, T0 + 5 * MIN);             // clock fixed
    h.record('acct', 0.35, 0.3, T0 + 10 * MIN);
    assert.deepEqual(h.getHistory('acct').map(p => p.u5h), [0.2, 0.3, 0.35]);
  });

  it('an unknown first value stays unknown (no fake 0 that skews the pace)', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    const now = T0 + 60 * MIN;
    h.record('acct', null, 0.5, now - 25 * MIN);
    h.record('acct', 0.6, 0.5, now - 10 * MIN);
    h.record('acct', 0.62, 0.5, now);
    assert.equal(h.getHistory('acct')[0].u5h, null);
    assert.ok(Math.abs(h.getVelocity('acct', now) - 0.12) < 1e-9);
  });

  it('prunes old points and keys nobody records to anymore', () => {
    const h = createUtilizationHistory(60 * MIN, 2 * MIN);
    h.record('old', 0.1, 0.1, T0);
    h.record('live', 0.1, 0.1, T0);
    h.record('live', 0.2, 0.2, T0 + 90 * MIN);
    h.prune(T0 + 90 * MIN);
    assert.deepEqual(h.getAllFingerprints(), ['live']);
    assert.equal(h.getHistory('live').length, 1);
  });

  it('rename merges a token-keyed history into the account name', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    const now = Date.now();
    h.record('fp-old', 0.1, 0.5, now - 30 * MIN);
    h.record('acct', 0.2, 0.5, now - 10 * MIN);
    h.rename('fp-old', 'acct');
    assert.deepEqual(h.getHistory('acct').map(p => p.u5h), [0.1, 0.2]);
    assert.deepEqual(h.getAllFingerprints(), ['acct']);
  });

  it('load sorts, drops old points and merges points in the same bucket', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    const now = Date.now();
    h.load('acct', [{ ts: now - MIN, u5h: 0.3, u7d: 0.1 }, { ts: now - 25 * 60 * MIN, u5h: 1, u7d: 1 }, { ts: now - 10 * MIN, u5h: 0.2, u7d: 0.1 }, { ts: now - 10 * MIN + 1, u5h: 0.25, u7d: 0.1 }], now);
    assert.deepEqual(h.getHistory('acct').map(p => p.u5h), [0.25, 0.3]);
  });

  it('velocity ignores a window reset in the last 30 minutes', () => {
    const h = createUtilizationHistory(24 * 60 * MIN, 2 * MIN);
    const now = T0 + 60 * MIN;
    h.record('acct', 0.8, 0.5, now - 28 * MIN);
    h.record('acct', 0.9, 0.5, now - 22 * MIN);
    h.record('acct', 0.02, 0.5, now - 20 * MIN); // the 5h window reset
    h.record('acct', 0.12, 0.5, now);
    const v = h.getVelocity('acct', now);
    assert.ok(Math.abs(v - 0.3) < 1e-9, `velocity ${v}`); // +10 points in 20 minutes
    assert.equal(h.predictMinutesToLimit('acct', now), 176);
  });
});
