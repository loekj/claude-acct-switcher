// Unit tests: session history (history.mjs) — digest, stats, search queries, handoff,
// line reader and the archive against a fake ~/.claude folder.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, appendFileSync, rmSync, readFileSync, existsSync, statSync, renameSync, readdirSync } from 'node:fs';
import { open } from 'node:fs/promises';
import { join } from 'node:path';
import os from 'node:os';

import {
  createDigester, sessionTitle, parseQuery, ftsMatch, entryMatches, buildHandoff, handoffPrompt,
  sessionCommands, readLines, toolLine, cleanUserText, openArchive, historyPaths, HANDOFF_BUDGET,
} from '../history.mjs';

const T0 = Date.UTC(2026, 9, 1, 10, 0);
const ts = (min) => new Date(T0 + min * 60000).toISOString();
const SID = '0f8b7c1e-1111-2222-3333-444455556666';
const base = (min) => ({ sessionId: SID, cwd: '/r/app', gitBranch: 'feat/x', timestamp: ts(min), entrypoint: 'cli', version: '2.1.0', slug: 'quiet-blue-fox' });

const user = (min, content, extra = {}) => ({ ...base(min), type: 'user', message: { role: 'user', content }, ...extra });
const asst = (min, id, content, usage, model = 'claude-opus-5-5') => ({ ...base(min), type: 'assistant', message: { id, model, role: 'assistant', content, usage } });

function transcript() {
  return [
    { type: 'custom-title', customTitle: '' },
    user(0, 'Fix the VAT engine for Portugal <system-reminder>ignore me</system-reminder>'),
    user(0, 'meta', { isMeta: true }),
    asst(1, 'msg_1', [{ type: 'thinking', thinking: '', signature: 'x' }], { input_tokens: 10, output_tokens: 1, cache_read_input_tokens: 100 }),
    asst(1, 'msg_1', [{ type: 'text', text: 'Looking at it.' }], { input_tokens: 10, output_tokens: 50, cache_read_input_tokens: 100 }),
    asst(1, 'msg_1', [{ type: 'tool_use', name: 'Edit', input: { file_path: '/r/app/vat.js', old_string: 'a', new_string: 'b' } }], { input_tokens: 10, output_tokens: 80, cache_read_input_tokens: 100 }),
    user(2, [{ type: 'tool_result', tool_use_id: 't1', content: 'ok' }]),
    asst(3, 'msg_2', [{ type: 'tool_use', name: 'Bash', input: { command: 'npm test' } }], { input_tokens: 5, output_tokens: 20 }),
    user(4, '<command-name>/compact</command-name>\n<command-message>compact</command-message>\n<command-args></command-args>'),
    { ...base(5), type: 'system', subtype: 'compact_boundary', compactMetadata: { preTokens: 900000 } },
    user(5, 'This session is being continued... Summary: VAT fixed, tests pending.', { isCompactSummary: true }),
    user(6, '<task-notification><task-id>x</task-id></task-notification>'),
    user(7, 'Now open the PR https://github.com/acme/app/pull/42 please'),
    asst(8, 'msg_3', [{ type: 'text', text: 'Done: https://github.com/acme/app/pull/42' }], { input_tokens: 1, output_tokens: 9 }),
    { ...base(9), type: 'system', subtype: 'away_summary', content: 'VAT fix is in PR 42; waiting on review.' },
    { type: 'ai-title', aiTitle: 'Portugal VAT fix' },
  ];
}

function digestAll(lines) {
  const dg = createDigester();
  const records = lines.flatMap(l => dg.feed(l));
  return { dg, records, stats: dg.snapshot() };
}

describe('digest', () => {
  it('keeps prompts, replies, tool lines, commands, compaction and recaps; drops noise', () => {
    const { records } = digestAll(transcript());
    assert.deepEqual(records.map(r => r.r), ['user', 'claude', 'tool', 'tool', 'command', 'compact', 'user', 'claude', 'recap']);
    assert.equal(records[0].x, 'Fix the VAT engine for Portugal');
    assert.equal(records[2].n, 'Edit');
    assert.equal(records[2].f, '/r/app/vat.js');
    assert.equal(records[4].x, '/compact');
    assert.equal(records[5].p, 900000);
    assert.deepEqual(records.map(r => r.i), [...records.keys()]);
  });

  it('counts usage once per message id (last reading wins) and prices it', () => {
    const { stats } = digestAll(transcript());
    assert.equal(stats.usage.output, 80 + 20 + 9);
    assert.equal(stats.usage.cacheRead, 100);
    assert.equal(stats.models['claude-opus-5-5'], 3);
    assert.ok(stats.cost > 0);
  });

  it('collects title fields, prompts, files, links, branch and compactions', () => {
    const { stats } = digestAll(transcript());
    assert.equal(stats.aiTitle, 'Portugal VAT fix');
    assert.equal(stats.firstPrompt, 'Fix the VAT engine for Portugal');
    assert.match(stats.lastPrompt, /open the PR/);
    assert.equal(stats.userTurns, 2);
    assert.deepEqual(stats.files, { '/r/app/vat.js': 1 });
    assert.deepEqual(stats.links, ['https://github.com/acme/app/pull/42']);
    assert.equal(stats.branch, 'feat/x');
    assert.equal(stats.compactions, 1);
    assert.equal(stats.slug, 'quiet-blue-fox');
    assert.equal(stats.firstAt, T0);
  });

  it('resumes from saved state exactly like one pass (incl. a message split across the cut)', () => {
    const lines = transcript();
    const whole = digestAll(lines);
    for (let cut = 1; cut < lines.length; cut++) {
      const a = createDigester();
      const r1 = lines.slice(0, cut).flatMap(l => a.feed(l));
      const b = createDigester(JSON.parse(JSON.stringify(a.state())));
      const r2 = lines.slice(cut).flatMap(l => b.feed(l));
      assert.deepEqual([...r1, ...r2], whole.records, `cut ${cut}`);
      assert.deepEqual(b.snapshot(), whole.stats, `cut ${cut}`);
    }
  });

  it('subagent lines (isSidechain) count usage but add no records', () => {
    const dg = createDigester();
    const r = dg.feed({ ...asst(1, 'msg_s', [{ type: 'text', text: 'sub' }], { input_tokens: 1, output_tokens: 7 }), isSidechain: true });
    assert.equal(r.length, 0);
    assert.equal(dg.snapshot().usage.output, 7);
  });

  it('cleans injected reminders and summarizes tool calls', () => {
    assert.equal(cleanUserText('hi <system-reminder>x\ny</system-reminder> there'), 'hi  there');
    assert.equal(cleanUserText('<pasted_content id="a1">Build it</pasted_content> now'), 'Build it now');
    assert.deepEqual(toolLine('Bash', { command: 'ls -la' }), { x: 'ls -la' });
    assert.equal(toolLine('mcp__x__y', { q: 1 }).x, '{"q":1}');
    assert.equal(toolLine('Write', { file_path: '/a/b.js', content: 'x'.repeat(9999) }).f, '/a/b.js');
  });
});

describe('sessionTitle', () => {
  const e = (stats, extra = {}) => ({ id: SID, stats: { cwd: '/r/app', ...stats }, ...extra });
  it('prefers user names, then Claude Code titles, then branch:id', () => {
    assert.equal(sessionTitle(e({ customTitle: 'mine', aiTitle: 'ai' })), 'mine');
    assert.equal(sessionTitle(e({ aiTitle: 'ai' }, { liveName: 'renamed', liveNameSource: 'user' })), 'renamed');
    assert.equal(sessionTitle(e({ aiTitle: 'ai' }, { liveName: 'auto', liveNameSource: 'auto' })), 'ai');
    assert.equal(sessionTitle(e({ branch: 'feat/x' })), 'feat/x:0f8b7c1e');
    assert.equal(sessionTitle(e({})), 'app:0f8b7c1e');
  });
});

describe('search queries', () => {
  it('splits words, phrases and filters', () => {
    const p = parseQuery('vat "tax engine" file:vat.js branch:feat/x account:"a b" stray:x');
    assert.deepEqual(p.words, ['vat', 'stray:x']);
    assert.deepEqual(p.phrases, ['tax engine']);
    assert.deepEqual(p.filters, { file: 'vat.js', branch: 'feat/x', account: 'a b' });
  });

  it('builds a safe FTS5 query (quotes escaped, last word as prefix)', () => {
    assert.equal(ftsMatch(parseQuery('vat porto')), '"vat" AND "porto"*');
    assert.equal(ftsMatch(parseQuery('"dashboard.mjs" OR')), '"or"* AND "dashboard mjs"');
    assert.equal(ftsMatch(parseQuery('a"b NEAR(')), '"a" AND "b" AND "near"*');
    assert.equal(ftsMatch(parseQuery('file:x')), '');
  });

  it('filters entries by project, branch, file, account, dates and automation', () => {
    const e = { id: SID, project: 'app', automated: false, accounts: { n1: { label: 'a@x' } },
      stats: { cwd: '/r/app', branch: 'feat/x', branches: ['main', 'feat/x'], files: { '/r/app/vat.js': 2 }, firstAt: T0, lastAt: T0 + 3600e3 } };
    assert.equal(entryMatches(e, { branch: 'main' }), true);
    assert.equal(entryMatches(e, { file: 'vat' }), true);
    assert.equal(entryMatches(e, { file: 'nope' }), false);
    assert.equal(entryMatches(e, { account: 'a@x' }), true);
    assert.equal(entryMatches(e, { after: '2026-10-02' }), false);
    assert.equal(entryMatches(e, { before: '2026-10-01' }), true);
    assert.equal(entryMatches(e, { id: '0f8b' }), true);
    assert.equal(entryMatches({ ...e, automated: true }, {}), false);
    assert.equal(entryMatches({ ...e, automated: true }, { automated: true }), true);
  });
});

describe('handoff', () => {
  const { records, stats } = digestAll(transcript());
  const e = { id: SID, stats };

  it('has the how-to, the latest compaction summary, newer messages, files and commands', () => {
    const md = buildHandoff(e, records, { digestPath: '/h/digest.jsonl', planPath: '/p/quiet-blue-fox.md' });
    assert.match(md, /^# Handoff: Portugal VAT fix/);
    assert.match(md, /git status/);
    assert.match(md, /Summary \(written by Claude Code/);
    assert.match(md, /VAT fixed, tests pending/);
    assert.match(md, /open the PR/);
    assert.doesNotMatch(md, /Fix the VAT engine for Portugal\n/); // before the compaction: summarized, not repeated
    assert.match(md, /\/r\/app\/vat\.js/);
    assert.match(md, /npm test/);
    assert.match(md, /\/p\/quiet-blue-fox\.md/);
  });

  it('stays within budget and keeps the newest messages', () => {
    const many = [];
    const dg = createDigester();
    for (let i = 0; i < 3000; i++) many.push(...dg.feed(user(i, `message number ${i} ` + 'x'.repeat(200))));
    const md = buildHandoff({ id: SID, stats: dg.snapshot() }, many, { budget: HANDOFF_BUDGET });
    assert.ok(md.length <= HANDOFF_BUDGET + 2000, `length ${md.length}`);
    assert.match(md, /message number 2999 /);
    assert.doesNotMatch(md, /message number 5 /);
    assert.match(md, /earlier messages left out/);
  });

  it('prompt and commands use the session id, folder and launch command safely', () => {
    assert.match(handoffPrompt(e, '/h/handoff.md'), /read \/h\/handoff\.md/);
    const c = sessionCommands({ id: SID, stats: { cwd: "/r/it's here" } }, 'claude --dangerously-skip-permissions');
    assert.equal(c.resume, `cd -- '/r/it'\\''s here' && claude --dangerously-skip-permissions --resume ${SID}`);
    assert.equal(c.continue, 'vdm history continue 0f8b7c1e');
  });
});

describe('readLines', () => {
  let dir;
  before(() => { dir = mkdtempSync(join(os.tmpdir(), 'vdm-lines-')); });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it('returns complete lines across chunk edges, leaves a half line, skips huge lines', async () => {
    const f = join(dir, 'a.jsonl');
    const huge = 'H'.repeat(5000);
    writeFileSync(f, `{"a":1}\n{"b":"${'y'.repeat(300)}"}\n${huge}\n{"c":3}\n{"half":`);
    const fh = await open(f, 'r');
    const seen = [];
    const end = await readLines(fh, 0, statSync(f).size, (buf, huge) => seen.push(buf ? buf.toString() : `HUGE:${huge.head.slice(0, 3)}`), { chunkSize: 64, hugeBytes: 1000 });
    await fh.close();
    assert.deepEqual(seen.map(s => s.slice(0, 7)), ['{"a":1}', '{"b":"y', 'HUGE:HH', '{"c":3}']);
    assert.equal(end, statSync(f).size - '{"half":'.length);
  });

  it('keeps invalid UTF-8 as replacement characters (no crash)', async () => {
    const f = join(dir, 'b.jsonl');
    writeFileSync(f, Buffer.concat([Buffer.from('{"x":"'), Buffer.from([0xff, 0xfe]), Buffer.from('"}\n')]));
    const fh = await open(f, 'r');
    const seen = [];
    await readLines(fh, 0, statSync(f).size, (buf) => seen.push(JSON.parse(buf.toString())));
    await fh.close();
    assert.equal(seen[0].x, '��');
  });
});

describe('archive (fake ~/.claude)', () => {
  let root, P, archive;
  const projDir = '-r-app';
  const tFile = () => join(P.projects, projDir, `${SID}.jsonl`);
  const write = (lines) => appendFileSync(tFile(), lines.map(l => JSON.stringify(l)).join('\n') + '\n');
  const logs = [];

  before(async () => {
    root = mkdtempSync(join(os.tmpdir(), 'vdm-hist-'));
    P = { ...historyPaths({ CSW_CLAUDE_DIR: join(root, 'claude'), CSW_HISTORY_DIR: join(root, 'history') }),
      config: join(root, 'config.json'), sessionsJson: join(root, 'sessions.json'), accounts: join(root, 'accounts') };
    mkdirSync(join(P.projects, projDir, SID, 'subagents'), { recursive: true });
    mkdirSync(P.accounts, { recursive: true });
    writeFileSync(join(P.accounts, 'auto-1.json'), '{}');
    writeFileSync(join(P.accounts, 'auto-1.label'), 'a@test');
    writeFileSync(P.sessionsJson, JSON.stringify({ v: 1, sessions: [{ id: SID, accounts: { 'auto-1': { requests: 4, cost: 1.5, lastAt: T0 } } }] }));
    writeFileSync(P.config, JSON.stringify({ sessionHistory: true, claudeCommand: 'cc --yolo' }));
    write(transcript().slice(0, 8));
    writeFileSync(join(P.projects, projDir, SID, 'subagents', 'agent-1.jsonl'),
      JSON.stringify(asst(2, 'msg_sub', [{ type: 'text', text: 'sub' }], { input_tokens: 1000, output_tokens: 1000 })) + '\n');
    archive = await openArchive({ P, writer: true, log: (m) => logs.push(m) });
  });
  after(async () => { await archive.close(); rmSync(root, { recursive: true, force: true }); });

  it('is off until the switch is on', async () => {
    const off = await openArchive({ P: { ...P, root: join(root, 'h2'), sessions: join(root, 'h2', 'sessions'), lock: join(root, 'h2', '.lock'), db: join(root, 'h2', 'search.db'), deleted: join(root, 'h2', 'd.json') }, writer: true, config: { enabled: false, exclude: [], retentionDays: 0, claudeCommand: 'claude' } });
    assert.deepEqual(await off.scanOnce(), { skipped: 'off' });
    await off.close();
  });

  it('saves a session as a hard link plus digest, with accounts and agent cost', async () => {
    const r = await archive.scanOnce();
    assert.equal(r.sessions, 1);
    const raw = join(P.sessions, SID, 'raw', `${SID}.jsonl`);
    assert.equal(statSync(raw).ino, statSync(tFile()).ino);
    assert.equal(statSync(join(P.sessions, SID, 'raw', SID, 'subagents', 'agent-1.jsonl')).nlink, 2);
    const list = await archive.list();
    assert.equal(list.count, 1);
    const row = list.sessions[0];
    assert.equal(row.accounts[0].label, 'a@test');
    assert.equal(row.accounts[0].name, 'a@test', 'kept under the account email, not the file name');
    assert.equal(row.agents, 1);
    assert.ok(row.cost > 0.02, `cost ${row.cost}`);
    assert.equal(row.original, true);
  });

  it('only reads new lines on the next scan, and search finds them', async () => {
    const before = (await archive.readDigest(SID)).length;
    write(transcript().slice(8));
    await archive.scanOnce();
    const records = await archive.readDigest(SID);
    assert.ok(records.length > before);
    assert.deepEqual(records.map(r => r.i), [...records.keys()]); // no duplicates, no gaps
    const hit = await archive.list({ q: 'review' });
    assert.equal(hit.total, 1);
    assert.match(hit.sessions[0].snippet, /review/);
    assert.equal((await archive.list({ q: 'nothing-like-this' })).total, 0);
    assert.equal((await archive.list({ q: 'Portugal' })).total, 1); // via the title too
  });

  it('cuts records left by a crash before entry.json was saved', async () => {
    const e = archive.getEntry(SID);
    const digest = join(P.sessions, SID, 'digest.jsonl');
    appendFileSync(digest, JSON.stringify({ i: 999, r: 'user', x: 'ghost' }) + '\n');
    write([user(20, 'after the crash')]);
    await archive.scanOnce();
    const records = await archive.readDigest(SID);
    assert.equal(records.some(r => r.x === 'ghost'), false);
    assert.equal(records.at(-1).x, 'after the crash');
    assert.equal(archive.getEntry(SID).digest.bytes, statSync(digest).size);
    assert.notEqual(e, archive.getEntry(SID), 'a scan replaces the entry only after saving it');
  });

  it('writes a handoff and gives a paste prompt and commands with the custom launcher', async () => {
    const h = await archive.handoff(SID.slice(0, 8));
    assert.ok(existsSync(h.path));
    assert.match(readFileSync(h.path, 'utf8'), /How to use this/);
    assert.match(h.prompt, new RegExp(h.path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    assert.match(h.commands.resume, /cc --yolo --resume/);
  });

  it('keeps the session when Claude Code deletes it, compresses it, and restores it identically', async () => {
    const original = readFileSync(tFile());
    rmSync(join(P.projects, projDir), { recursive: true });
    await archive.scanOnce();
    const e = archive.getEntry(SID);
    assert.equal(e.original, false);
    assert.ok(existsSync(join(P.sessions, SID, 'raw', `${SID}.jsonl.br`)));
    assert.ok(!existsSync(join(P.sessions, SID, 'raw', `${SID}.jsonl`)));
    const d = await archive.detail(SID);
    assert.equal(d.needsRestore, true);
    assert.equal((await archive.list({ q: 'review' })).total, 1); // still searchable

    const r = await archive.restore(SID);
    assert.equal(r.restored, 2); // transcript + subagent file
    assert.deepEqual(readFileSync(tFile()), original);
    assert.ok(Date.now() - statSync(tFile()).mtimeMs < 60_000, 'restored file has a fresh date');
    const again = await archive.restore(SID);
    assert.equal(again.restored, 0); // never overwrites

    await archive.scanOnce();
    assert.equal(archive.getEntry(SID).original, true);
    assert.equal(statSync(join(P.sessions, SID, 'raw', `${SID}.jsonl`)).ino, statSync(tFile()).ino);
    assert.ok(!existsSync(join(P.sessions, SID, 'raw', `${SID}.jsonl.br`)));
    assert.equal((await archive.readDigest(SID)).filter(x => x.x === 'after the crash').length, 1); // no rebuild, no dupes
  });

  it('relinks when Claude Code replaces the file, keeping a longer old copy', async () => {
    const oldIno = statSync(tFile()).ino;
    const tmp = tFile() + '.new';
    writeFileSync(tmp, readFileSync(tFile()).subarray(0, 200));
    renameSync(tmp, tFile());
    await archive.scanOnce();
    const raw = join(P.sessions, SID, 'raw', `${SID}.jsonl`);
    assert.notEqual(statSync(tFile()).ino, oldIno);
    assert.equal(statSync(raw).ino, statSync(tFile()).ino);
    assert.ok(existsSync(raw + '.prev'));
    assert.ok(readdirSync(join(P.sessions, SID)).some(f => f.startsWith('digest.prev-')), 'old digest kept');
  });

  it('a second writer stays read-only', async () => {
    const second = await openArchive({ P, writer: true });
    assert.equal(second.canWrite, false);
    assert.deepEqual(await second.scanOnce(), { skipped: 'read-only' });
    await second.close();
    assert.ok(existsSync(P.lock), 'the first writer keeps its lock');
  });

  it('deletes from the archive only, and never saves that session again', async () => {
    await archive.remove(SID);
    assert.ok(!existsSync(join(P.sessions, SID)));
    assert.ok(existsSync(tFile()), "Claude Code's file is untouched");
    await archive.scanOnce();
    assert.equal((await archive.list()).count, 0);
    assert.throws(() => archive.getEntry(SID), /No saved session/);
  });
});

describe('archive: review regressions', () => {
  const SID2 = 'aaaabbbb-1111-2222-3333-444455556666';
  let root, P, archive;
  const projDir = '-r-two';
  const tFile = () => join(P.projects, projDir, `${SID2}.jsonl`);
  const write = (lines) => appendFileSync(tFile(), lines.map(l => JSON.stringify({ ...l, sessionId: SID2 })).join('\n') + '\n');

  before(async () => {
    root = mkdtempSync(join(os.tmpdir(), 'vdm-hist2-'));
    P = { ...historyPaths({ CSW_CLAUDE_DIR: join(root, 'claude'), CSW_HISTORY_DIR: join(root, 'history') }),
      config: join(root, 'config.json'), sessionsJson: join(root, 'sessions.json'), accounts: join(root, 'accounts') };
    mkdirSync(join(P.projects, projDir), { recursive: true });
    write([user(0, 'first prompt'), user(1, 'second prompt')]);
    archive = await openArchive({ P, writer: true, config: { enabled: true, exclude: [], retentionDays: 0, claudeCommand: 'claude' } });
    await archive.scanOnce();
  });
  after(async () => { await archive.close(); rmSync(root, { recursive: true, force: true }); });

  it('a scan that fails halfway loses and repeats nothing', async () => {
    write([user(2, 'third prompt')]);
    const { chmodSync } = await import('node:fs');
    chmodSync(tFile(), 0o000);
    await archive.scanOnce(); // cannot read: logged, entry unchanged
    chmodSync(tFile(), 0o600);
    await archive.scanOnce();
    const records = await archive.readDigest(SID2);
    assert.deepEqual(records.map(r => r.x), ['first prompt', 'second prompt', 'third prompt']);
    assert.equal(archive.getEntry(SID2).stats.userTurns, 3);
    assert.equal(archive.getEntry(SID2).stats.firstPrompt, 'first prompt');
  });

  it('an assistant line with broken usage is counted as bad, not fatal', async () => {
    write([{ ...asst(3, null, [{ type: 'text', text: 'ok' }], 'not-an-object'), message: { role: 'assistant', content: [{ type: 'text', text: 'ok' }], usage: 'x' } }, user(4, 'fourth prompt')]);
    await archive.scanOnce();
    assert.equal((await archive.readDigest(SID2)).at(-1).x, 'fourth prompt');
  });

  it('a delete during a scan sticks', async () => {
    write([user(5, 'fifth prompt')]);
    const scan = archive.scanOnce();
    await archive.remove(SID2);
    await scan;
    await archive.scanOnce();
    assert.equal((await archive.list()).count, 0);
    assert.ok(!existsSync(join(P.sessions, SID2)));
  });

  it('exclude folders accept ~ and ignore relative paths', async () => {
    const { normalizeFolders } = await import('../history.mjs');
    assert.deepEqual(normalizeFolders(['~/work/', '/abs/x', 'relative', 3, ''], '/home/me'), ['/home/me/work', '/abs/x']);
  });

  it('a one-letter last word is not a prefix search', () => {
    assert.equal(ftsMatch(parseQuery('vat a')), '"vat" AND "a"');
  });
});

describe('archive: final review regressions', () => {
  const A = 'aaaa0000-1111-2222-3333-444455556666';
  const Bid = 'bbbb0000-1111-2222-3333-444455556666';
  let root, P;
  const cfgOn = { enabled: true, exclude: [], retentionDays: 0, claudeCommand: 'claude' };
  const file = (id) => join(P.projects, '-r-x', `${id}.jsonl`);
  const lines = (id, n, word) => Array.from({ length: n }, (_, i) => JSON.stringify({ ...user(i, `${word} message ${i} ` + 'pad '.repeat(50)), sessionId: id })).join('\n') + '\n';

  before(() => {
    root = mkdtempSync(join(os.tmpdir(), 'vdm-hist3-'));
    P = { ...historyPaths({ CSW_CLAUDE_DIR: join(root, 'claude'), CSW_HISTORY_DIR: join(root, 'history') }),
      config: join(root, 'config.json'), sessionsJson: join(root, 'sessions.json'), accounts: join(root, 'accounts') };
    mkdirSync(join(P.projects, '-r-x'), { recursive: true });
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  it('a session deleted before the scan reaches it is not rebuilt', async () => {
    writeFileSync(file(A), lines(A, 4000, 'alpha'));   // big: scanned first (newest), takes a while
    writeFileSync(file(Bid), lines(Bid, 10, 'bravo'));
    const { utimesSync } = await import('node:fs');
    utimesSync(file(Bid), new Date(Date.now() - 60000), new Date(Date.now() - 60000));
    const a = await openArchive({ P, writer: true, config: cfgOn });
    await a.scanOnce();                                  // both saved
    appendFileSync(file(A), lines(A, 4000, 'alpha2'));  // A changes: next scan works on it first
    appendFileSync(file(Bid), lines(Bid, 1, 'bravo2'));
    const scan = a.scanOnce();
    await a.remove(Bid);
    await scan;
    await a.scanOnce();
    assert.ok(!existsSync(join(P.sessions, Bid)), 'B folder not rebuilt');
    assert.equal((await a.list({ q: 'bravo' })).total, 0, 'B not searchable');
    await a.close();
  });

  it('search is rebuilt even when history is off', async () => {
    rmSync(P.db, { force: true });
    for (const ext of ['-wal', '-shm']) rmSync(P.db + ext, { force: true });
    const a = await openArchive({ P, writer: true, config: { ...cfgOn, enabled: false } });
    await a.reindex();
    assert.equal((await a.list({ q: 'alpha2' })).total, 1);
    await a.close();
  });

  it('restore never writes .prev copies into Claude Code\'s folder', async () => {
    const a = await openArchive({ P, writer: true, config: cfgOn });
    const raw = join(P.sessions, A, 'raw');
    mkdirSync(join(raw, A, 'subagents'), { recursive: true });
    writeFileSync(join(raw, A, 'subagents', 'x.jsonl.prev'), 'old');
    rmSync(join(P.projects, '-r-x'), { recursive: true });
    await a.scanOnce();                                  // original gone: compressed (incl. the .prev)
    const r = await a.restore(A);
    assert.ok(r.restored >= 1);
    assert.ok(!existsSync(join(P.projects, '-r-x', A, 'subagents', 'x.jsonl.prev')));
    assert.ok(existsSync(file(A)));
    await a.close();
  });

  it('the lock file always holds a pid', async () => {
    const a = await openArchive({ P, writer: true, config: cfgOn });
    assert.equal(readFileSync(P.lock, 'utf8'), String(process.pid));
    assert.ok(!readdirSync(P.root).some(f => f.endsWith('.tmp')), 'no temp lock left');
    await a.close();
    assert.ok(!existsSync(P.lock));
  });
});
