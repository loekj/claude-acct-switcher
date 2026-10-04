// Unit tests: token throughput per account (account-card charts) in lib.mjs.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createThroughputStore, throughputFromRollups, usageFamily, totalTokens, THROUGHPUT_BUCKET_MS } from '../lib.mjs';

const T0 = Date.UTC(2026, 9, 3, 12, 0);
const B = THROUGHPUT_BUCKET_MS;

describe('throughput store', () => {
  it('sums tokens per 5-minute bucket and model family', () => {
    const s = createThroughputStore({ now: () => T0 + 60 * 60000 });
    s.add('acct', 'claude-opus-5-5', 1000, T0 + 10);
    s.add('acct', 'claude-opus-4-7', 500, T0 + 4 * 60000);
    s.add('acct', 'claude-fable-5-1', 300, T0 + 60000);
    s.add('acct', 'claude-haiku-4-5', 200, T0 + B + 1);
    s.add('acct', 'claude-opus-5-5', 0, T0); // nothing
    assert.deepEqual(s.series('acct', T0 - 1), [
      { t: T0, w: B, by: { opus: 1500, fable: 300 } },
      { t: T0 + B, w: B, by: { haiku: 200 } },
    ]);
    assert.deepEqual(s.series('other', 0), []);
  });

  it('keeps 26 hours, survives a save and load, and refuses another bucket size', () => {
    let now = T0;
    const s = createThroughputStore({ now: () => now });
    s.add('acct', 'claude-opus-5-5', 10, T0);
    now = T0 + 27 * 3600000;
    s.add('acct', 'claude-opus-5-5', 20, now);
    const json = JSON.parse(JSON.stringify(s.toJSON()));
    assert.equal(json.data.acct.length, 1);
    const again = createThroughputStore({ now: () => now });
    again.load(json);
    assert.equal(again.series('acct', 0)[0].by.opus, 20);
    assert.equal(again.startedAt, T0);
    const other = createThroughputStore({ bucketMs: 60000, now: () => now });
    other.load(json);
    assert.deepEqual(other.series('acct', 0), []);
  });

  it('rename merges a fingerprint key into the account name', () => {
    const s = createThroughputStore({ now: () => T0 });
    s.add('fp', 'claude-opus-5-5', 10, T0);
    s.add('acct', 'claude-opus-5-5', 5, T0);
    s.rename('fp', 'acct');
    assert.equal(s.series('acct', 0)[0].by.opus, 15);
    assert.deepEqual(s.series('fp', 0), []);
  });
});

describe('throughput helpers', () => {
  it('groups models and counts every token kind', () => {
    assert.equal(usageFamily('claude-fable-5-1'), 'fable');
    assert.equal(usageFamily('claude-haiku-4-5-20251001'), 'haiku');
    assert.equal(usageFamily('mystery'), 'other');
    assert.equal(totalTokens({ input: 1, output: 2, cacheRead: 3, cacheWrite5m: 4, cacheWrite1h: 5 }), 15);
  });

  it('builds hourly series per account from usage rollups', () => {
    const rows = [
      { h: T0, account: 'a@x', model: 'claude-opus-5-5', input: 10, output: 10, cacheRead: 100, cacheWrite5m: 0, cacheWrite1h: 0 },
      { h: T0, account: 'a@x', model: 'claude-sonnet-5', input: 12, output: 0, cacheRead: 0, cacheWrite5m: 0, cacheWrite1h: 0 },
      { h: T0 + 3600000, account: 'b@x', model: 'claude-fable-5-1', input: 0, output: 24, cacheRead: 0, cacheWrite5m: 0, cacheWrite1h: 0 },
      { h: T0 - 3600000, account: 'a@x', model: 'claude-opus-5-5', input: 999, output: 0 }, // before `since`
    ];
    const out = throughputFromRollups(rows, { since: T0, scale: 12 });
    assert.deepEqual(out['a@x'], [{ t: T0, w: 3600000, by: { opus: 10, sonnet: 1 } }]);
    assert.deepEqual(out['b@x'], [{ t: T0 + 3600000, w: 3600000, by: { fable: 2 } }]);
  });
});

describe('throughputLine', () => {
  const H = 3600000;
  it('5-minute slots from the store, older slots as their hour average, gaps as 0', async () => {
    const { throughputLine } = await import('../lib.mjs');
    const now = T0 + 2 * H + 7 * 60000;                 // 14:07
    const startedAt = T0 + H + 30 * 60000;              // store since 13:30
    const fine = [{ t: T0 + 2 * H, w: B, by: { opus: 500, fable: 100 } }]; // 14:00-14:05
    const hourly = [{ t: T0, w: H, by: { opus: 1200 } }, { t: T0 + H, w: H, by: { opus: 2400 } }];
    const line = throughputLine({ fine, hourly, startedAt, now, windowMs: 3 * H, step: B });
    assert.equal(line.values.length, 36);
    assert.equal(line.start + 35 * B, T0 + 2 * H + 5 * 60000); // last slot = the running one
    const at = (t) => line.values[(t - line.start) / B];
    assert.equal(at(T0 + 10 * 60000), 100);   // 12:10 → 1200 / 12
    assert.equal(at(T0 + H + 5 * 60000), 200); // 13:05 → 2400 / 12 (before the store)
    assert.equal(at(T0 + H + 40 * 60000), 0);  // 13:40: store running, no traffic
    assert.equal(at(T0 + 2 * H), 600);         // 14:00 from the store, all models summed
  });

  it('hourly slots are the average per 5 minutes; the running hour counts elapsed time only', async () => {
    const { throughputLine } = await import('../lib.mjs');
    const now = T0 + 2 * H + 10 * 60000;
    const hourly = [{ t: T0 + H, w: H, by: { opus: 1200 } }, { t: T0 + 2 * H, w: H, by: { opus: 300, sonnet: 300 } }];
    const line = throughputLine({ hourly, now, windowMs: 3 * H, step: H });
    assert.deepEqual(line.values, [0, 100, 300]); // 600 tokens in the first 10 minutes = 300 per 5 min
  });
});
