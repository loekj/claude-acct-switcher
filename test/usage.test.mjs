// Unit tests: usage extraction, API-equivalent pricing, usage rollups, artifact refs (lib.mjs).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizeUsage,
  mergeUsage,
  createSSEUsageParser,
  parseJsonUsage,
  priceFor,
  usageCost,
  planMonthlyUsd,
  createUsageDay,
  summarizeUsage,
  promptTokens,
  hourStart,
  extractArtifactRefs,
  artifactRefMatches,
} from '../lib.mjs';

const close = (a, b) => assert.ok(Math.abs(a - b) < 1e-9, `${a} ≈ ${b}`);

describe('normalizeUsage', () => {
  it('splits cache writes by TTL and keeps cache reads', () => {
    const u = normalizeUsage({
      input_tokens: 12, output_tokens: 300, cache_read_input_tokens: 90_000,
      cache_creation_input_tokens: 5000,
      cache_creation: { ephemeral_5m_input_tokens: 1000, ephemeral_1h_input_tokens: 4000 },
      server_tool_use: { web_search_requests: 2 },
    });
    assert.deepEqual(u, { input: 12, output: 300, cacheRead: 90_000, cacheWrite5m: 1000, cacheWrite1h: 4000, webSearches: 2, speed: null });
  });

  it('treats an unsplit cache write as 5-minute', () => {
    assert.equal(normalizeUsage({ cache_creation_input_tokens: 700 }).cacheWrite5m, 700);
  });
});

describe('createSSEUsageParser', () => {
  const stream = [
    'event: message_start\n',
    'data: {"type":"message_start","message":{"model":"claude-opus-5-5","usage":{"input_tokens":5,"cache_read_input_tokens":80000,"cache_creation_input_tokens":2000,"output_tokens":1}}}\n\n',
    'event: content_block_delta\ndata: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}\n\n',
    'event: message_delta\ndata: {"type":"message_delta","usage":{"output_tokens":420}}\n\n',
  ].join('');

  it('collects model and final usage across message_start and message_delta', () => {
    const p = createSSEUsageParser();
    p.feed(stream);
    const r = p.result();
    assert.equal(r.model, 'claude-opus-5-5');
    assert.equal(r.usage.output, 420);
    assert.equal(r.usage.cacheRead, 80000);
    assert.equal(r.usage.cacheWrite5m, 2000);
  });

  it('handles events split across arbitrary chunk boundaries', () => {
    const p = createSSEUsageParser();
    for (let i = 0; i < stream.length; i += 7) p.feed(stream.slice(i, i + 7));
    assert.equal(p.result().usage.output, 420);
  });

  it('mergeUsage keeps the larger cumulative reading', () => {
    const m = mergeUsage({ input: 5, output: 1, cacheRead: 10 }, { input: 5, output: 9, cacheRead: 0 });
    assert.equal(m.output, 9);
    assert.equal(m.cacheRead, 10);
  });
});

describe('parseJsonUsage', () => {
  it('reads a non-streamed message', () => {
    const r = parseJsonUsage(JSON.stringify({ type: 'message', model: 'claude-haiku-4-5', usage: { input_tokens: 3, output_tokens: 4 } }));
    assert.equal(r.model, 'claude-haiku-4-5');
    assert.equal(r.usage.output, 4);
  });
  it('ignores other bodies', () => {
    assert.equal(parseJsonUsage('{"input_tokens":5}'), null);
    assert.equal(parseJsonUsage('not json'), null);
  });
});

describe('pricing', () => {
  it('matches current models (most specific first)', () => {
    assert.deepEqual(priceFor('claude-opus-5-5'), { input: 4, output: 20, cacheRead: 0.2 });
    assert.deepEqual(priceFor('claude-fable-5-1'), { input: 10, output: 50, cacheRead: 0.25 });
    assert.deepEqual(priceFor('claude-opus-4-7'), { input: 5, output: 25, cacheRead: 0.5 });
    assert.deepEqual(priceFor('claude-opus-4-1-20250805'), { input: 15, output: 75, cacheRead: 1.5 });
    assert.deepEqual(priceFor('claude-sonnet-5-5'), { input: 2, output: 10, cacheRead: 0.2 });
    assert.deepEqual(priceFor('claude-haiku-4-5-20251001'), { input: 1, output: 5, cacheRead: 0.1 });
  });

  it('costs cache writes at 1.25x (5m) / 2x (1h) input and reads at the cache rate', () => {
    // opus 5.5: 1M of each kind
    const u = { input: 1e6, output: 1e6, cacheRead: 1e6, cacheWrite5m: 1e6, cacheWrite1h: 1e6 };
    close(usageCost(u, 'claude-opus-5-5'), 4 + 20 + 0.2 + 5 + 8);
    close(usageCost({ ...u, speed: 'fast' }, 'claude-opus-5-5'), 2 * (4 + 20 + 0.2 + 5 + 8));
  });

  it('planMonthlyUsd: Max 20x $200, Max 5x $100, others not priced', () => {
    assert.equal(planMonthlyUsd('max', 'default_claude_max_20x'), 200);
    assert.equal(planMonthlyUsd('max', 'default_claude_max_5x'), 100);
    assert.equal(planMonthlyUsd('pro', 'default_claude_pro'), null);
  });
});

describe('usage rollups', () => {
  const t0 = Date.UTC(2026, 9, 3, 10, 15);

  it('rolls requests into hourly rows per account/model/repo/branch', () => {
    const day = createUsageDay();
    const usage = { input: 10, output: 20, cacheRead: 1000, cacheWrite5m: 100, cacheWrite1h: 0, webSearches: 0 };
    day.add({ ts: t0, account: 'a@x', model: 'm1', repo: '/r', branch: 'main', usage });
    day.add({ ts: t0 + 60_000, account: 'a@x', model: 'm1', repo: '/r', branch: 'main', usage });
    day.add({ ts: t0 + 3_600_000, account: 'a@x', model: 'm1', repo: '/r', branch: 'main', usage });
    const rows = day.rows();
    assert.equal(rows.length, 2);
    assert.equal(rows[0].h, hourStart(t0));
    assert.equal(rows[0].requests, 2);
    assert.equal(rows[0].cacheRead, 2000);
    // Rebuilding from saved rows keeps accumulating into the same row.
    const again = createUsageDay(JSON.parse(JSON.stringify(rows)));
    again.add({ ts: t0, account: 'a@x', model: 'm1', repo: '/r', branch: 'main', usage });
    assert.equal(again.size(), 2);
    assert.equal(again.rows()[0].requests, 3);
  });

  it('summarizeUsage totals, filters and buckets', () => {
    const day = createUsageDay();
    const u = (n) => ({ input: n, output: n, cacheRead: n * 10, cacheWrite5m: 0, cacheWrite1h: 0, webSearches: 0 });
    day.add({ ts: t0, account: 'a', model: 'claude-opus-5-5', repo: '/r1', branch: 'main', usage: u(100) });
    day.add({ ts: t0, account: 'b', model: 'claude-fable-5-1', repo: '/r2', branch: 'dev', usage: u(50) });
    const all = summarizeUsage(day.rows());
    assert.equal(all.totals.requests, 2);
    assert.equal(all.totals.cacheRead, 1500);
    assert.deepEqual(all.options.accounts, ['a', 'b']);
    assert.equal(all.series.length, 1);
    const onlyA = summarizeUsage(day.rows(), { filter: { account: 'a' } });
    assert.equal(onlyA.totals.requests, 1);
    close(onlyA.totals.cost, (100 * 4 + 100 * 20 + 1000 * 0.2) / 1e6);
    assert.ok(onlyA.byRepo['/r1'].branches.main);
    assert.equal(promptTokens(onlyA.totals), 1100);
  });
});

describe('artifact refs', () => {
  it('finds code/artifact and artifact links', () => {
    const refs = extractArtifactRefs('see https://claude.ai/code/artifact/0f8b7c1e-aaaa and claude.ai/artifact/my-page-12345678abcd');
    assert.deepEqual([...refs].sort(), ['0f8b7c1e-aaaa', 'my-page-12345678abcd']);
    assert.equal(extractArtifactRefs('no links here').size, 0);
  });

  it('matches a ref to a frame slug exactly or by suffix', () => {
    assert.equal(artifactRefMatches('0f8b7c1e-aaaa', '0f8b7c1e-aaaa'), true);
    assert.equal(artifactRefMatches('my-page-12345678abcd', '12345678abcd'), true);
    assert.equal(artifactRefMatches('other-page', '12345678abcd'), false);
  });
});

describe('body helpers accept Buffers', () => {
  it('extract model, ttl, session id and artifact refs from a Buffer', async () => {
    const { extractModel, cacheTtlFromBody, extractSessionId, AFFINITY_LONG_TTL_MS } = await import('../lib.mjs');
    const body = Buffer.from('{"model":"claude-fable-5-1","system":[{"cache_control":{"type":"ephemeral","ttl":"1h"}}],"messages":[{"content":"https://claude.ai/code/artifact/abcdef12-3456"}],"metadata":{"user_id":"user_x_session_0f8b7c1e-1111-2222-3333-444455556666"}}');
    assert.equal(extractModel(body), 'claude-fable-5-1');
    assert.equal(cacheTtlFromBody(body), AFFINITY_LONG_TTL_MS);
    assert.equal(extractSessionId({}, body), '0f8b7c1e-1111-2222-3333-444455556666');
    assert.deepEqual([...extractArtifactRefs(body)], ['abcdef12-3456']);
  });
});

describe('cacheEfficiency', () => {
  it('computes hit and rebuild ratios per account/model with a daily trend', async () => {
    const { cacheEfficiency, createUsageDay } = await import('../lib.mjs');
    const d0 = Date.UTC(2026, 9, 1);
    const day = createUsageDay();
    day.add({ ts: d0 + 3600e3, account: 'a', model: 'm1', usage: { input: 10, cacheRead: 900, cacheWrite5m: 90 } });
    day.add({ ts: d0 + 86400e3 + 3600e3, account: 'b', model: 'm1', usage: { input: 50, cacheRead: 0, cacheWrite1h: 950 } });
    const eff = cacheEfficiency(day.rows(), { since: d0, until: d0 + 3 * 86400e3 });
    assert.equal(eff.byAccount.a.hit, 0.9);
    assert.equal(eff.byAccount.b.hit, 0);
    assert.equal(eff.byAccount.b.rebuild, 0.95);
    assert.equal(eff.overall.hit, 900 / 2000);
    assert.deepEqual(eff.byModel.m1.trend, [0.9, 0, null]);
    assert.deepEqual(eff.byAccount.a.trend, [0.9, null, null]);
  });
});
