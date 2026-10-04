#!/usr/bin/env node
// Van Damme-o-Matic  - Session history
//
// Saves Claude Code sessions so they survive Claude Code's 30-day cleanup, keeps a readable
// digest of each one, a full-text index, and builds handoff files to continue a session in
// a new one. Zero dependencies.
//
//   node history.mjs serve        child process of the dashboard (all disk work happens here,
//                                 so the proxy never waits on it)
//   node history.mjs cli <cmd>    the `vdm history` command
//
// The archive (history/ next to this file, mode 0700), one folder per session:
//   sessions/<id>/entry.json      stats + archive state (the source of truth)
//   sessions/<id>/digest.jsonl    readable text, one JSON line per message
//   sessions/<id>/raw/...         the transcript and its folder: hard links while Claude
//                                 Code still has the files, brotli copies once it deleted them
//   sessions/<id>/handoff.md      written on demand
//   search.db                     FTS5 index of the digests (rebuildable)
//   deleted.json                  sessions deleted from the archive (never saved again)
//
// Transcript files are only ever read, linked or unlinked from our own folder; vdm never
// writes to, chmods or touches a file Claude Code owns.

import { createHash, randomUUID } from 'node:crypto';
import {
  readdir, readFile, writeFile, mkdir, rename, unlink, link, lstat, stat, open, rm, chmod, utimes, statfs, copyFile,
} from 'node:fs/promises';
import { createReadStream, createWriteStream, existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { join, dirname, basename, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { execFile } from 'node:child_process';
import zlib from 'node:zlib';
import os from 'node:os';

import { normalizeUsage, mergeUsage, usageCost } from './lib.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────
// Transcript → digest (pure)
// ─────────────────────────────────────────────────

export const SESSION_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const HUGE_LINE_BYTES = 8 * 1024 * 1024; // longer lines (pasted images) are skipped, not parsed
const CAP = { user: 20000, claude: 20000, compact: 120000, recap: 4000, command: 400, tool: 300, prompt: 300 };
const FILES_MAX = 200;
const LINKS_MAX = 20;
const BRANCHES_MAX = 5;
const USAGE_KEYS = ['input', 'output', 'cacheRead', 'cacheWrite5m', 'cacheWrite1h'];
const EDIT_TOOLS = new Set(['Edit', 'MultiEdit', 'Write', 'NotebookEdit']);
const LINK_RE = /https:\/\/(?:github\.com\/[\w.-]+\/[\w.-]+\/pull\/\d+|claude\.ai\/(?:code\/)?artifact\/[\w-]+)/g;
const REMINDER_RE = /<system-reminder>[\s\S]*?<\/system-reminder>/g;
const PASTE_TAG_RE = /<\/?pasted_content\b[^>]*>/g;
const SKIP_USER_RE = /^<(local-command-stdout|local-command-stderr|local-command-caveat|task-notification|bash-stdout|bash-stderr|user-memory-input)\b/;

function wellFormed(s) { return typeof s.toWellFormed === 'function' ? s.toWellFormed() : s; }

/** Cut text to n characters, saying how much was left out. */
export function capText(s, n) {
  s = wellFormed(String(s ?? ''));
  return s.length > n ? `${s.slice(0, n)}… [+${s.length - n} chars]` : s;
}

function oneLine(s, n) {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
}

/** Text a person typed: without the reminders Claude Code injects into user turns. */
export function cleanUserText(s) {
  return String(s ?? '').replace(REMINDER_RE, '').replace(PASTE_TAG_RE, '').trim();
}

function blocksText(content) {
  const parts = [];
  for (const b of content) {
    if (!b || typeof b !== 'object') continue;
    if (b.type === 'text' && typeof b.text === 'string') parts.push(b.text);
    else if (b.type === 'image') parts.push('[image]');
  }
  return parts.join('\n');
}

/** One short line for a tool call: { x: text, f: file it changed or read }. */
export function toolLine(name, input) {
  const i = input && typeof input === 'object' ? input : {};
  const file = i.file_path || i.notebook_path || '';
  switch (name) {
    case 'Edit': case 'MultiEdit': case 'Write': case 'NotebookEdit': case 'Read':
      return { x: capText(file, CAP.tool), f: file || undefined };
    case 'Bash': return { x: capText(i.command || '', CAP.tool) };
    case 'Grep': return { x: capText(`${i.pattern || ''}${i.path ? ' in ' + i.path : ''}`, CAP.tool) };
    case 'Glob': return { x: capText(i.pattern || '', CAP.tool) };
    case 'WebFetch': return { x: capText(i.url || '', CAP.tool) };
    case 'WebSearch': return { x: capText(i.query || '', CAP.tool) };
    case 'Agent': case 'Task': return { x: capText(i.description || i.prompt || '', CAP.tool) };
    case 'Skill': return { x: capText(i.skill || '', CAP.tool) };
    default: {
      let s = '';
      try { s = JSON.stringify(i); } catch { /* unserializable */ }
      return { x: capText(s === '{}' ? '' : s, 200) };
    }
  }
}

function emptyStats() {
  return {
    firstAt: null, lastAt: null, cwd: '', branch: '', branches: [], slug: '', entrypoint: '', version: '',
    customTitle: '', agentName: '', aiTitle: '', firstPrompt: '', lastPrompt: '',
    userTurns: 0, claudeMsgs: 0, toolCalls: 0, compactions: 0,
    models: {}, usage: { input: 0, output: 0, cacheRead: 0, cacheWrite5m: 0, cacheWrite1h: 0 }, cost: 0,
    files: {}, links: [], badLines: 0, hugeLines: 0,
  };
}

/**
 * Turns transcript entries into digest records and running stats. Resumable: state() is
 * plain JSON, and createDigester(state) continues where it stopped.
 *
 * Record: { i, t, r, x, n?, f?, p? }  i = sequence, t = time (ms), r = role
 *   user | claude | tool | compact | recap | command, x = text, n = tool name,
 *   f = file, p = tokens before a compaction.
 *
 * Claude Code writes one line per content block, each carrying the message's usage so far:
 * usage is merged per message.id and counted once, when the next message starts.
 */
export function createDigester(saved = null, { recordsOn = true } = {}) {
  const st = saved ? JSON.parse(JSON.stringify(saved)) : { seq: 0, pending: null, preTokens: null, stats: emptyStats() };
  const s = st.stats;

  const rec = (t, r, x, extra) => ({ i: st.seq++, t, r, x, ...extra });

  function addUsage(target, p) {
    if (!p || !p.usage) return;
    for (const k of USAGE_KEYS) target.usage[k] += p.usage[k] || 0;
    target.cost += usageCost(p.usage, p.model);
    if (p.model && p.model !== '<synthetic>') target.models[p.model] = (target.models[p.model] || 0) + 1;
  }

  function commitPending() {
    const p = st.pending;
    st.pending = null;
    if (p && p.usage) addUsage(s, p);
  }

  function noteBranch(b) {
    s.branch = b;
    const i = s.branches.indexOf(b);
    if (i !== -1) s.branches.splice(i, 1);
    s.branches.push(b);
    if (s.branches.length > BRANCHES_MAX) s.branches.shift();
  }

  function noteLinks(text) {
    if (s.links.length >= LINKS_MAX || !text.includes('https://')) return;
    for (const m of text.matchAll(LINK_RE)) {
      if (!s.links.includes(m[0])) s.links.push(m[0]);
      if (s.links.length >= LINKS_MAX) break;
    }
  }

  function userRecords(e, t) {
    if (e.isMeta) return [];
    const m = e.message || {};
    const c = m.content;
    let text = typeof c === 'string' ? c : Array.isArray(c) ? blocksText(c) : '';
    if (e.isCompactSummary) return [rec(t, 'compact', capText(text, CAP.compact), st.preTokens ? { p: st.preTokens } : undefined)];
    if (!text) return []; // tool results only
    if (text.startsWith('<command-name>')) {
      const name = (text.match(/<command-name>([\s\S]*?)<\/command-name>/) || [])[1] || '';
      const args = (text.match(/<command-args>([\s\S]*?)<\/command-args>/) || [])[1] || '';
      const cmd = `${name.trim()}${args.trim() ? ' ' + args.trim() : ''}`;
      return cmd ? [rec(t, 'command', capText(cmd, CAP.command))] : [];
    }
    if (text.startsWith('<bash-input>')) {
      const cmd = (text.match(/<bash-input>([\s\S]*?)<\/bash-input>/) || [])[1] || '';
      return cmd.trim() ? [rec(t, 'command', capText('! ' + cmd.trim(), CAP.command))] : [];
    }
    if (SKIP_USER_RE.test(text)) return [];
    text = cleanUserText(text);
    if (!text) return [];
    s.userTurns++;
    if (!s.firstPrompt) s.firstPrompt = oneLine(text, CAP.prompt);
    s.lastPrompt = oneLine(text, CAP.prompt);
    noteLinks(text);
    return [rec(t, 'user', capText(text, CAP.user))];
  }

  function assistantRecords(e, t) {
    const m = e.message || {};
    if (m.id) {
      if (!st.pending || st.pending.id !== m.id) { commitPending(); st.pending = { id: m.id, model: m.model || null, usage: null }; }
      if (m.usage) st.pending.usage = mergeUsage(st.pending.usage, normalizeUsage(m.usage));
    } else if (m.usage && m.model !== '<synthetic>') {
      commitPending();
      addUsage(s, { model: m.model, usage: normalizeUsage(m.usage) });
    }
    if (e.isSidechain || !recordsOn) return [];
    const out = [];
    let counted = false;
    for (const b of Array.isArray(m.content) ? m.content : []) {
      if (!b || typeof b !== 'object') continue;
      if (b.type === 'text' && typeof b.text === 'string' && b.text.trim()) {
        if (!counted) { s.claudeMsgs++; counted = true; }
        noteLinks(b.text);
        out.push(rec(t, 'claude', capText(b.text.trim(), CAP.claude)));
      } else if (b.type === 'tool_use') {
        s.toolCalls++;
        const { x, f } = toolLine(b.name, b.input);
        if (f && EDIT_TOOLS.has(b.name) && (s.files[f] || Object.keys(s.files).length < FILES_MAX)) s.files[f] = (s.files[f] || 0) + 1;
        out.push(rec(t, 'tool', x, f ? { n: b.name, f } : { n: b.name }));
      }
    }
    return out;
  }

  /** Feed one parsed transcript entry; returns its digest records (maybe none). */
  function feed(e) {
    if (!e || typeof e !== 'object') return [];
    const t = typeof e.timestamp === 'string' ? Date.parse(e.timestamp) || null : null;
    if (t) {
      if (!s.firstAt || t < s.firstAt) s.firstAt = t;
      if (!s.lastAt || t > s.lastAt) s.lastAt = t;
    }
    if (typeof e.cwd === 'string' && e.cwd) s.cwd = e.cwd;
    if (typeof e.gitBranch === 'string' && e.gitBranch && e.gitBranch !== 'HEAD' && e.gitBranch !== s.branch) noteBranch(e.gitBranch);
    if (typeof e.slug === 'string' && e.slug) s.slug = e.slug;
    if (typeof e.entrypoint === 'string' && e.entrypoint && !s.entrypoint) s.entrypoint = e.entrypoint;
    if (typeof e.version === 'string' && e.version) s.version = e.version;
    switch (e.type) {
      case 'custom-title': if (e.customTitle) s.customTitle = String(e.customTitle); return [];
      case 'agent-name': if (e.agentName) s.agentName = String(e.agentName); return [];
      case 'ai-title': if (e.aiTitle) s.aiTitle = String(e.aiTitle); return [];
      case 'system':
        if (e.subtype === 'compact_boundary') {
          s.compactions++;
          st.preTokens = e.compactMetadata?.preTokens || null;
          return [];
        }
        if (e.subtype === 'away_summary' && typeof e.content === 'string' && e.content.trim() && recordsOn) {
          return [rec(t, 'recap', capText(e.content.trim(), CAP.recap))];
        }
        return [];
      case 'user': return recordsOn ? userRecords(e, t) : [];
      case 'assistant': return assistantRecords(e, t);
      default: return [];
    }
  }

  /** A transcript line that could not be read. */
  function bad({ huge = false, head = '' } = {}) {
    if (huge) {
      s.hugeLines++;
      const ts = head.match(/"timestamp":"([^"]{10,40})"/);
      const t = ts ? Date.parse(ts[1]) : NaN;
      if (Number.isFinite(t)) { if (!s.firstAt || t < s.firstAt) s.firstAt = t; if (!s.lastAt || t > s.lastAt) s.lastAt = t; }
    } else s.badLines++;
  }

  /** Stats including the message still being written. */
  function snapshot() {
    const out = JSON.parse(JSON.stringify(s));
    if (st.pending && st.pending.usage) addUsage(out, st.pending);
    return out;
  }

  return { feed, bad, snapshot, state: () => st };
}

/** Display title: user's name > agent name > live name > Claude Code's title > branch:id. */
export function sessionTitle(e) {
  const id8 = String(e.id || '').slice(0, 8);
  const st = e.stats || {};
  if (st.customTitle) return st.customTitle;
  if (st.agentName) return st.agentName;
  if (e.liveName && e.liveNameSource === 'user') return e.liveName;
  if (st.aiTitle) return st.aiTitle;
  if (e.liveName) return e.liveName;
  if (st.branch) return `${st.branch}:${id8}`;
  const folder = String(st.cwd || '').split('/').filter(Boolean).pop();
  return folder ? `${folder}:${id8}` : id8;
}

// ─────────────────────────────────────────────────
// Search queries (pure)
// ─────────────────────────────────────────────────

const FILTER_KEYS = new Set(['file', 'branch', 'project', 'account', 'before', 'after', 'id']);

/**
 * Split a search box value into free text and filters:
 *   words, "exact phrase", file:x branch:x project:x account:x before:2026-09-01 after:… id:abcd
 */
export function parseQuery(q) {
  const out = { words: [], phrases: [], filters: {} };
  const re = /(\w+):"([^"]*)"|(\w+):(\S+)|"([^"]*)"|(\S+)/g;
  for (const m of String(q || '').matchAll(re)) {
    const key = (m[1] || m[3] || '').toLowerCase();
    const val = m[2] ?? m[4];
    if (key && FILTER_KEYS.has(key)) { if (val) out.filters[key] = val; continue; }
    if (m[5] !== undefined) { if (m[5].trim()) out.phrases.push(m[5].trim()); continue; }
    const word = m[6] ?? (m[0]);
    if (word) out.words.push(word);
  }
  return out;
}

const ftsQuote = (s) => `"${String(s).replace(/"/g, '""')}"`;

/** FTS5 MATCH string: every word and phrase must appear; the last word also matches as a prefix. */
export function ftsMatch(parsed) {
  const parts = [];
  const tokens = (s) => String(s).toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const words = parsed.words.flatMap(tokens);
  words.forEach((w, i) => parts.push(i === words.length - 1 && w.length > 1 ? `${ftsQuote(w)}*` : ftsQuote(w)));
  for (const p of parsed.phrases) {
    const t = tokens(p);
    if (t.length) parts.push(ftsQuote(t.join(' ')));
  }
  return parts.join(' AND ');
}

/** One FTS5 MATCH string per word / phrase (a session must contain each, anywhere). */
export function ftsTerms(parsed) {
  const tokens = (s) => String(s).toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const words = parsed.words.flatMap(tokens);
  const out = words.map((w, i) => (i === words.length - 1 && w.length > 1 ? `${ftsQuote(w)}*` : ftsQuote(w)));
  for (const p of parsed.phrases) {
    const t = tokens(p);
    if (t.length) out.push(ftsQuote(t.join(' ')));
  }
  return out;
}

/** Plain lowercase needles for the scan fallback and for metadata matches. */
export function needles(parsed) {
  return [...parsed.words, ...parsed.phrases].map(s => s.toLowerCase()).filter(Boolean);
}

function dayStart(s, endOfDay = false) {
  const t = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s}T00:00:00` : s);
  return Number.isFinite(t) ? t + (endOfDay ? 86400000 : 0) : null;
}

/** Does a session entry pass the filters (from the query and the dropdowns)? */
export function entryMatches(e, f = {}) {
  const st = e.stats || {};
  const has = (hay, needle) => String(hay || '').toLowerCase().includes(String(needle).toLowerCase());
  if (f.id && !e.id.startsWith(String(f.id).toLowerCase())) return false;
  if (f.project && !has(e.project, f.project) && !has(st.cwd, f.project)) return false;
  if (f.branch && !(st.branches || []).some(b => has(b, f.branch)) && !has(st.branch, f.branch)) return false;
  if (f.file && !Object.keys(st.files || {}).some(p => has(p, f.file)) && !f.fileIds?.has(e.id)) return false;
  if (f.account && !Object.entries(e.accounts || {}).some(([n, a]) => has(n, f.account) || has(a.label, f.account))) return false;
  if (f.after) { const t = dayStart(f.after); if (t && (st.lastAt || 0) < t) return false; }
  if (f.before) { const t = dayStart(f.before, true); if (t && (st.firstAt || 0) >= t) return false; }
  if (f.since && (st.lastAt || 0) < f.since) return false;
  if (!f.automated && e.automated) return false;
  return true;
}

// ─────────────────────────────────────────────────
// Handoff (pure)
// ─────────────────────────────────────────────────

export const HANDOFF_BUDGET = 70000; // characters: fits one Read in the new session

const fmtTime = (t) => (t ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '?');

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

/** Shell commands to continue a session. */
export function sessionCommands(e, claudeCommand = 'claude') {
  const cmd = String(claudeCommand || 'claude').trim() || 'claude';
  const cwd = e.stats?.cwd || '';
  return {
    resume: cwd ? `cd -- ${shq(cwd)} && ${cmd} --resume ${e.id}` : `${cmd} --resume ${e.id}`,
    continue: `vdm history continue ${e.id.slice(0, 8)}`,
  };
}

/** The prompt to paste into a new Claude Code session. */
export function handoffPrompt(e, handoffPath) {
  return `Continue my earlier Claude Code session "${sessionTitle(e)}" (${e.id.slice(0, 8)}). ` +
    `First read ${handoffPath} - it has the summary, the last messages and the files that changed. ` +
    `Then check the repo state (git status, git log) before you change anything.`;
}

function renderRecord(r) {
  const when = r.t ? new Date(r.t).toISOString().slice(11, 16) : '';
  switch (r.r) {
    case 'user': return `### User${when ? ` (${when})` : ''}\n${capText(r.x, 4000)}\n`;
    case 'claude': return `### Claude\n${capText(r.x, 3000)}\n`;
    case 'tool': return `- ${r.n || 'tool'}: ${oneLine(r.x, 200)}\n`;
    case 'command': return `- command: ${oneLine(r.x, 200)}\n`;
    case 'recap': return `> Recap: ${oneLine(r.x, 600)}\n`;
    default: return '';
  }
}

/**
 * Markdown brief that lets a new session continue an old one. Deterministic, no model call:
 * header + how-to, Claude Code's latest compaction summary, the newest messages after it
 * (within the budget), files changed, last commands.
 */
export function buildHandoff(e, records, { digestPath = '', planPath = '', budget = HANDOFF_BUDGET } = {}) {
  const st = e.stats || {};
  const title = sessionTitle(e);
  const head = [];
  head.push(`# Handoff: ${title}`, '');
  head.push('This is a record of an earlier Claude Code session, made by vdm (no AI summary).');
  head.push('Use it to continue that work in this new session.', '');
  head.push(`- Session: ${e.id}`);
  head.push(`- Started: ${fmtTime(st.firstAt)}; last active: ${fmtTime(st.lastAt)}`);
  if (st.cwd) head.push(`- Folder: ${st.cwd}`);
  if (st.branch) head.push(`- Branch: ${st.branch}${st.branches?.length > 1 ? ` (earlier: ${st.branches.slice(0, -1).join(', ')})` : ''}`);
  const models = Object.keys(st.models || {});
  if (models.length) head.push(`- Models: ${models.join(', ')}`);
  head.push(`- Your messages: ${st.userTurns || 0}; compactions: ${st.compactions || 0}`);
  if (st.firstPrompt) head.push(`- It started with: "${st.firstPrompt}"`);
  if (planPath) head.push(`- Plan file of that session: ${planPath}`);
  if (st.links?.length) head.push(`- Links: ${st.links.slice(0, 8).join(' ')}`);
  head.push('');
  head.push('## How to use this');
  head.push('1. Read this whole file.');
  head.push('2. Check the current state first: `git status`, `git log --oneline -15`. The code may have changed since.');
  head.push('3. Do not redo work that is already done. If the next step is not clear, ask the user.');
  if (digestPath) head.push(`4. More detail: every message of the old session is in ${digestPath} (one JSON line per message; search it with grep).`);
  head.push('');

  let lastCompact = -1;
  for (let i = records.length - 1; i >= 0; i--) if (records[i].r === 'compact') { lastCompact = i; break; }

  const tail = [];
  const files = Object.entries(st.files || {}).sort((a, b) => b[1] - a[1]).slice(0, 25);
  if (files.length) {
    tail.push('## Files changed in the session');
    for (const [f, n] of files) tail.push(`- ${f}${n > 1 ? ` (${n} edits)` : ''}`);
    tail.push('');
  }
  const cmds = records.filter(r => r.r === 'tool' && r.n === 'Bash').slice(-10);
  if (cmds.length) {
    tail.push('## Last commands run');
    for (const r of cmds) tail.push(`- \`${oneLine(r.x, 200).replace(/`/g, "'")}\``);
    tail.push('');
  }

  const parts = [head.join('\n')];
  let used = parts[0].length + tail.join('\n').length;

  if (lastCompact >= 0) {
    const c = records[lastCompact];
    const summary = capText(c.x, Math.max(4000, Math.floor((budget - used) * 0.45)));
    const s = `## Summary (written by Claude Code when it compacted the session, ${fmtTime(c.t)})\n\n${summary}\n`;
    parts.push(s);
    used += s.length;
  }

  const convoTitle = lastCompact >= 0 ? '## Conversation after that summary (newest last)' : '## Conversation (newest last)';
  const after = records.slice(lastCompact + 1).filter(r => r.r !== 'compact');
  const chunks = [];
  let room = budget - used - convoTitle.length - 200;
  let i = after.length - 1;
  for (; i >= 0; i--) {
    const text = renderRecord(after[i]);
    if (!text) continue;
    if (text.length > room) break;
    chunks.push(text);
    room -= text.length;
  }
  chunks.reverse();
  const left = i + 1;
  parts.push(`${convoTitle}\n${left > 0 ? `\n[${left} earlier messages left out${digestPath ? ' - see the digest file' : ''}]\n` : ''}\n${chunks.join('\n')}`);
  if (tail.length) parts.push(tail.join('\n'));
  return parts.join('\n');
}

// ─────────────────────────────────────────────────
// Line reader
// ─────────────────────────────────────────────────

/**
 * Read the complete lines of an open file between start and end. Calls onLine(buffer) per
 * line, or onLine(null, { huge: true, head }) for a line over HUGE_LINE_BYTES (skipped without
 * holding it in memory). Returns the offset after the last complete line: a half-written
 * last line is left for the next read.
 */
export async function readLines(fh, start, end, onLine, { chunkSize = 1 << 20, hugeBytes = HUGE_LINE_BYTES } = {}) {
  const buf = Buffer.allocUnsafe(chunkSize);
  let pos = start;
  let lineStart = start;
  let parts = [];
  let partLen = 0;
  let skipping = false;
  let head = '';
  while (pos < end) {
    const { bytesRead } = await fh.read(buf, 0, Math.min(chunkSize, end - pos), pos);
    if (!bytesRead) break;
    let from = 0;
    while (from < bytesRead) {
      const nl = buf.indexOf(10, from);
      if (nl === -1 || nl >= bytesRead) {
        if (!skipping) {
          parts.push(Buffer.from(buf.subarray(from, bytesRead)));
          partLen += bytesRead - from;
          if (partLen > hugeBytes) {
            skipping = true;
            head = Buffer.concat(parts).subarray(0, 4096).toString('utf8');
            parts = []; partLen = 0;
          }
        }
        break;
      }
      if (skipping) {
        await onLine(null, { huge: true, head });
        skipping = false; head = '';
      } else {
        const piece = buf.subarray(from, nl);
        const line = parts.length ? Buffer.concat([...parts, piece]) : piece;
        if (line.length > hugeBytes) await onLine(null, { huge: true, head: line.subarray(0, 4096).toString('utf8') });
        else if (line.length) await onLine(line);
        parts = []; partLen = 0;
      }
      lineStart = pos + nl + 1;
      from = nl + 1;
    }
    pos += bytesRead;
  }
  return lineStart;
}

/** Parse one transcript line; null when it is not JSON. */
export function parseLine(buf) {
  try { return JSON.parse(buf.toString('utf8')); } catch { return null; }
}

// ─────────────────────────────────────────────────
// Paths and settings
// ─────────────────────────────────────────────────

export function historyPaths(env = process.env) {
  const claudeDir = env.CSW_CLAUDE_DIR || join(os.homedir(), '.claude');
  const root = env.CSW_HISTORY_DIR || join(__dirname, 'history');
  return {
    claudeDir,
    projects: join(claudeDir, 'projects'),
    registry: join(claudeDir, 'sessions'),
    plans: join(claudeDir, 'plans'),
    root,
    sessions: join(root, 'sessions'),
    db: join(root, 'search.db'),
    lock: join(root, '.lock'),
    deleted: join(root, 'deleted.json'),
    install: __dirname,
    config: join(__dirname, 'config.json'),
    sessionsJson: join(__dirname, 'sessions.json'),
    accounts: join(__dirname, 'accounts'),
  };
}

/** History settings from config.json (VDM_CLAUDE_CMD overrides the launch command). */
export function loadHistoryConfig(P, env = process.env) {
  let c = {};
  try { c = JSON.parse(readFileSync(P.config, 'utf8')) || {}; } catch { /* defaults */ }
  const days = Number(c.historyRetentionDays);
  return {
    enabled: c.sessionHistory === true,
    retentionDays: Number.isFinite(days) && days > 0 ? Math.floor(days) : 0,
    exclude: normalizeFolders(c.historyExclude),
    claudeCommand: String(env.VDM_CLAUDE_CMD || c.claudeCommand || 'claude').trim() || 'claude',
  };
}

/** Folder list from settings: `~` expanded, trailing slashes dropped, only absolute paths. */
export function normalizeFolders(list, home = os.homedir()) {
  if (!Array.isArray(list)) return [];
  return list.filter(x => typeof x === 'string')
    .map(x => x.trim().replace(/^~(?=\/|$)/, home).replace(/\/+$/, ''))
    .filter(x => x.startsWith('/'));
}

function isExcluded(cwd, exclude) {
  if (!cwd) return false;
  return normalizeFolders(exclude).some(p => cwd === p || cwd.startsWith(p + '/'));
}

// ─────────────────────────────────────────────────
// Search index (node:sqlite FTS5, optional)
// ─────────────────────────────────────────────────

const ROLE_WEIGHT = { user: 2, recap: 1.5, compact: 1.2, claude: 1, command: 1, tool: 0.8 };
const SEARCH_SCHEMA = '2';

async function openSearchIndex(file, { readOnly = false, log = () => {} } = {}) {
  let sqlite;
  try { sqlite = await import('node:sqlite'); } catch { return null; }
  const tryOpen = () => {
    const db = new sqlite.DatabaseSync(file, readOnly ? { readOnly: true } : {});
    db.exec('PRAGMA busy_timeout = 3000');
    if (!readOnly) {
      db.exec('PRAGMA journal_mode = WAL');
      db.exec('CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)');
      // Schema 2 adds prefix indexes (fast search-as-you-type). An older index is rebuilt.
      if (db.prepare("SELECT v FROM meta WHERE k = 'schema'").get()?.v !== SEARCH_SCHEMA) {
        db.exec('DROP TABLE IF EXISTS docs');
        db.exec("DELETE FROM meta WHERE k = 'epoch'");
      }
      db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS docs USING fts5(text, sid UNINDEXED, seq UNINDEXED, role UNINDEXED,
          tokenize = 'unicode61 remove_diacritics 2', prefix = '2 3')`);
      db.prepare("INSERT OR REPLACE INTO meta (k, v) VALUES ('schema', ?)").run(SEARCH_SCHEMA);
    }
    db.prepare('SELECT count(*) FROM docs WHERE docs MATCH ?').get('"probe"');
    return db;
  };
  let db;
  try { db = tryOpen(); } catch (err) {
    if (readOnly) return null;
    log(`search index unreadable (${err.message}): rebuilding it`);
    try { await rename(file, `${file}.corrupt-${Date.now()}`); } catch { /* missing */ }
    for (const ext of ['-wal', '-shm']) { try { await unlink(file + ext); } catch { /* missing */ } }
    try { db = tryOpen(); } catch (err2) { log(`search index disabled: ${err2.message}`); return null; }
  }
  if (!readOnly) {
    const row = db.prepare("SELECT v FROM meta WHERE k = 'epoch'").get();
    if (!row) db.prepare("INSERT INTO meta (k, v) VALUES ('epoch', ?)").run(randomUUID());
  }
  const epoch = db.prepare("SELECT v FROM meta WHERE k = 'epoch'").get()?.v || '';
  const ins = readOnly ? null : db.prepare('INSERT INTO docs (text, sid, seq, role) VALUES (?, ?, ?, ?)');
  const del = readOnly ? null : db.prepare('DELETE FROM docs WHERE sid = ?');
  // No ORDER BY rank: ranking every match of a common word is what makes FTS slow. Rows
  // come back in index order, capped, and are weighted here.
  const find = db.prepare(`SELECT sid, seq, role, snippet(docs, 0, char(2), char(3), '…', 14) AS snip, bm25(docs) AS score
    FROM docs WHERE docs MATCH ? LIMIT ?`);
  const countBySid = db.prepare('SELECT sid, count(*) AS n FROM docs WHERE docs MATCH ? GROUP BY sid');
  const sidsWithRole = db.prepare('SELECT DISTINCT sid FROM docs WHERE docs MATCH ? AND role = ?');
  const each = (stmt, ...args) => (typeof stmt.iterate === 'function' ? stmt.iterate(...args) : stmt.all(...args));
  return {
    epoch,
    add(sid, records) {
      db.exec('BEGIN');
      try {
        for (const r of records) {
          const text = r.r === 'tool' ? `${r.n || ''} ${r.x}` : r.x;
          if (text) ins.run(wellFormed(text), sid, r.i, r.r);
        }
        db.exec('COMMIT');
      } catch (err) { db.exec('ROLLBACK'); throw err; }
    },
    remove(sid) { del.run(sid); },
    /** Map sid → { score, hits, snip, seq } (higher score = better). */
    search(match, limit = 3000) {
      const out = new Map();
      const rows = find.all(match, limit);
      out.complete = rows.length < limit;
      for (const row of rows) {
        const w = (ROLE_WEIGHT[row.role] || 1) * -row.score;
        const cur = out.get(row.sid);
        if (!cur) out.set(row.sid, { score: w, hits: 1, snip: row.snip, seq: row.seq, best: w });
        else {
          cur.score += w; cur.hits++;
          if (w > cur.best) { cur.best = w; cur.snip = row.snip; cur.seq = row.seq; }
        }
      }
      return out;
    },
    /**
     * Sessions that contain every term somewhere (not necessarily in one message).
     * Score: how often each term occurs, plus a bonus when one message has them all.
     */
    sessions(terms, rowMatch, { phrase = '', total = 100 } = {}) {
      let acc = null;
      for (const t of terms) {
        const found = new Map(countBySid.all(t).map(r => [r.sid, r.n]));
        const idf = Math.log(1 + total / Math.max(1, found.size)); // rare words count more
        if (!acc) { acc = new Map([...found].map(([sid, n]) => [sid, { score: idf * Math.log1p(n), hits: n, snip: '', seq: null }])); continue; }
        for (const [sid, v] of acc) {
          const n = found.get(sid);
          if (!n) acc.delete(sid); else { v.score += idf * Math.log1p(n); v.hits += n; }
        }
      }
      if (!acc) return new Map();
      // The words side by side (what people usually mean by "hard link") count most
      if (phrase) {
        for (const r of countBySid.all(phrase)) {
          const v = acc.get(r.sid);
          if (v) v.score += 10 + 2 * Math.log1p(r.n);
        }
      }
      const together = rowMatch && terms.length > 1 ? this.search(rowMatch, 2000) : null;
      if (together && together.complete) {
        for (const [sid, r] of together) {
          const v = acc.get(sid);
          if (v) { v.score += 5 + r.best; v.snip = r.snip; v.seq = r.seq; }
        }
      }
      return acc;
    },
    /** Sessions with a match in one role only (file: searches tool lines). */
    sessionsWithRole(match, role) {
      return new Set(sidsWithRole.all(match, role).map(r => r.sid));
    },
    /** One snippet per session (one query for the whole page), from the first term that has one. */
    snippets(sids, terms) {
      const out = new Map();
      for (const t of terms) {
        const want = sids.filter(id => !out.has(id));
        if (!want.length) break;
        const stmt = db.prepare(`SELECT sid, seq, snippet(docs, 0, char(2), char(3), '…', 14) AS snip
          FROM docs WHERE docs MATCH ? AND sid IN (${want.map(() => '?').join(',')})`);
        for (const r of each(stmt, t, ...want)) {
          if (!out.has(r.sid)) out.set(r.sid, { snip: r.snip, seq: r.seq });
          if (out.size === sids.length) break;
        }
      }
      return out;
    },
    close() { try { db.close(); } catch { /* closed */ } },
  };
}

// ─────────────────────────────────────────────────
// Archive
// ─────────────────────────────────────────────────

const LINK_UNSUPPORTED = new Set(['EXDEV', 'EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'EMLINK', 'EACCES']);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

async function exists(p) { try { await lstat(p); return true; } catch { return false; } }

async function writeJsonAtomic(file, data) {
  const tmp = `${file}.tmp-${process.pid}`;
  await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
  await rename(tmp, file);
}

async function hashRange(file, from, to) {
  if (to <= from) return '';
  let fh;
  try {
    fh = await open(file, 'r');
    const buf = Buffer.alloc(to - from);
    const { bytesRead } = await fh.read(buf, 0, buf.length, from);
    return createHash('sha1').update(buf.subarray(0, bytesRead)).digest('hex');
  } catch { return null; } finally { if (fh) await fh.close().catch(() => {}); }
}

/** Files under dir (regular files only, no symlinks), as paths relative to dir. */
async function walkFiles(dir, depth = 3, base = dir) {
  const out = [];
  let ents = [];
  try { ents = await readdir(dir, { withFileTypes: true }); } catch { return out; }
  for (const d of ents) {
    const p = join(dir, d.name);
    if (d.isDirectory() && depth > 0) out.push(...await walkFiles(p, depth - 1, base));
    else if (d.isFile()) out.push(relative(base, p));
  }
  return out;
}

function gitAsync(cwd, args) {
  return new Promise((resolve) => {
    execFile('git', ['-C', cwd, ...args], { timeout: 3000, encoding: 'utf8' }, (err, out) => resolve(err ? null : String(out).trim()));
  });
}

const HELD_LOCKS = new Set(); // lock files this process holds (a second archive here is read-only too)

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (err) { return err.code === 'EPERM'; }
}

/**
 * Open the archive. As writer (one process at a time, via the .lock file) it can scan and
 * change things; otherwise it is read-only.
 */
export async function openArchive({ P = historyPaths(), writer = false, log = () => {}, config = null } = {}) {
  let cfg = config || loadHistoryConfig(P);
  const entries = new Map();
  let deleted = {};
  let canWrite = false;
  let search = null;
  let scanning = null;
  let lastScan = null;
  let scanError = null;
  let backfill = null; // { done, total } while the first pass runs
  let closing = false; // stop between sessions when the process is asked to exit
  const busy = new Map(); // session id → its save in progress (a delete waits for it)
  const wantWriter = writer;
  let accountLabels = new Map();

  const sessDir = (id) => join(P.sessions, id);
  const entryFile = (id) => join(sessDir(id), 'entry.json');
  const digestFile = (id) => join(sessDir(id), 'digest.jsonl');
  const rawDir = (id) => join(sessDir(id), 'raw');

  async function acquireLock() {
    await mkdir(P.root, { recursive: true, mode: 0o700 });
    try { await chmod(P.root, 0o700); } catch { /* not ours */ }
    const tmp = `${P.lock}.${process.pid}.tmp`;
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        await writeFile(tmp, String(process.pid), { mode: 0o600 });
        await link(tmp, P.lock); // fails if a lock exists: never two writers
        HELD_LOCKS.add(P.lock);
        return true;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        let pid = NaN;
        try { pid = parseInt(await readFile(P.lock, 'utf8'), 10); } catch { /* vanished */ }
        if (pid === process.pid ? HELD_LOCKS.has(P.lock) : pidAlive(pid)) return false;
        try { await unlink(P.lock); } catch { /* raced */ }
      } finally {
        try { await unlink(tmp); } catch { /* gone */ }
      }
    }
    return false;
  }

  async function releaseLock() {
    if (!canWrite) return;
    try {
      const pid = parseInt(await readFile(P.lock, 'utf8'), 10);
      if (pid === process.pid) await unlink(P.lock);
    } catch { /* gone */ }
    HELD_LOCKS.delete(P.lock);
  }

  async function loadEntries() {
    try { deleted = JSON.parse(await readFile(P.deleted, 'utf8')) || {}; } catch { deleted = {}; }
    let ids = [];
    try { ids = (await readdir(P.sessions)).filter(id => SESSION_ID_RE.test(id)); } catch { /* empty */ }
    for (const id of ids) {
      if (deleted[id]) {
        // A delete that was interrupted (shutdown, failed rm): finish it
        if (canWrite) await rm(sessDir(id), { recursive: true, force: true, maxRetries: 3 }).catch(() => {});
        continue;
      }
      try { entries.set(id, JSON.parse(await readFile(entryFile(id), 'utf8'))); } catch { /* half-made: rescan fixes */ }
    }
  }

  function newEntry(id) {
    return {
      v: 1, id, projectDir: '', original: false, goneAt: null, automated: false,
      src: null, raw: { mode: 'link', note: '' },
      digest: { offset: 0, tailHash: '', state: null, indexed: 0, epoch: '', gen: 0, bytes: 0 },
      agents: {}, agentStats: { count: 0, cost: 0, tokens: 0 },
      stats: emptyStats(), accounts: {}, liveName: '', liveNameSource: '', repoRoot: '', project: '',
      bytes: { shared: 0, own: 0 }, savedAt: 0,
    };
  }

  /** Write entry.json; false when the session was deleted meanwhile (then nothing is written). */
  async function saveEntry(e) {
    if (deleted[e.id]) return false;
    e.savedAt = Date.now();
    await mkdir(sessDir(e.id), { recursive: true, mode: 0o700 });
    await writeJsonAtomic(entryFile(e.id), e);
    return true;
  }

  /** Account file name → { id (email when known), label } from accounts/<name>.email|.label. */
  function readAccountLabels() {
    const m = new Map();
    const read = (f) => { try { return readFileSync(join(P.accounts, f), 'utf8').trim(); } catch { return ''; } };
    try {
      for (const f of readdirSync(P.accounts)) {
        if (!f.endsWith('.json')) continue;
        const name = f.slice(0, -5);
        const email = read(`${name}.email`), label = read(`${name}.label`);
        m.set(name, { id: email || (label.includes('@') ? label : '') || name, label: label || email || name });
      }
    } catch { /* no accounts dir */ }
    return m;
  }

  async function readRegistry() {
    const map = new Map();
    let files = [];
    try { files = (await readdir(P.registry)).filter(f => f.endsWith('.json')); } catch { return map; }
    for (const f of files) {
      try {
        const j = JSON.parse(await readFile(join(P.registry, f), 'utf8'));
        if (j && j.sessionId) map.set(j.sessionId, { name: j.name || '', nameSource: j.nameSource || '' });
      } catch { /* being rewritten */ }
    }
    return map;
  }

  async function readVdmSessions() {
    const map = new Map();
    try {
      const j = JSON.parse(await readFile(P.sessionsJson, 'utf8'));
      for (const s of j?.sessions || []) if (s && s.id) map.set(s.id, s);
    } catch { /* none yet */ }
    return map;
  }

  /** Link src into the archive at dst. 'ok' | 'linked' | 'gone' | 'unsupported'. */
  async function ensureLink(src, dst) {
    let sst;
    try { sst = await lstat(src); } catch { return 'gone'; }
    if (!sst.isFile()) return 'gone';
    let old = null;
    try { old = await lstat(dst); } catch { /* new */ }
    if (old && old.ino === sst.ino && old.dev === sst.dev) return 'ok';
    await mkdir(dirname(dst), { recursive: true, mode: 0o700 });
    // Claude Code replaced the file with a shorter one: keep the longer copy we had
    if (old && old.isFile() && old.size > sst.size) {
      try { await rename(dst, `${dst}.prev`); } catch { /* keep going */ }
    }
    const tmp = `${dst}.lnk-${process.pid}`;
    try { await unlink(tmp); } catch { /* none */ }
    try { await link(src, tmp); } catch (err) {
      if (LINK_UNSUPPORTED.has(err.code)) return 'unsupported';
      throw err;
    }
    try { await rename(tmp, dst); } catch (err) { try { await unlink(tmp); } catch { /* gone */ } throw err; }
    try { await unlink(`${dst}.br`); } catch { /* none */ }
    return 'linked';
  }

  /** Continue the digest of a transcript from where it stopped (or rebuild it). */
  async function digestSession(e, file, size) {
    const d = e.digest;
    let start = d.offset || 0;
    let reset = false;
    // A crash between appending records and saving entry.json leaves extra records: cut them
    let onDisk = 0;
    try { onDisk = (await stat(digestFile(e.id))).size; } catch { /* none yet */ }
    if (onDisk > (d.bytes || 0)) {
      const fh = await open(digestFile(e.id), 'r+');
      try { await fh.truncate(d.bytes || 0); } finally { await fh.close(); }
      if (search) { try { search.remove(e.id); } catch { /* index error */ } }
      d.epoch = ''; d.indexed = 0; // re-indexed from the digest after this scan
    } else if (onDisk < (d.bytes || 0)) reset = true; // digest lost or cut: rebuild it
    if (size < start) reset = true;
    else if (start > 0 && (await hashRange(file, Math.max(0, start - 64), start)) !== d.tailHash) reset = true;
    if (reset) {
      log(`${e.id.slice(0, 8)}: transcript changed under us, rebuilding its digest (old one kept)`);
      try { await rename(digestFile(e.id), join(sessDir(e.id), `digest.prev-${Date.now()}.jsonl`)); } catch { /* none */ }
      if (search) { try { search.remove(e.id); } catch { /* index error */ } }
      start = 0;
      d.offset = 0; d.tailHash = '';
      d.state = null; d.indexed = 0; d.bytes = 0; d.gen = (d.gen || 0) + 1;
    }
    if (start >= size && !reset) return false;

    const dg = createDigester(d.state);
    let batch = [];
    const flush = async () => {
      if (!batch.length) return;
      const text = batch.map(r => JSON.stringify(r)).join('\n') + '\n';
      await writeFile(digestFile(e.id), text, { flag: 'a', mode: 0o600 });
      d.bytes = (d.bytes || 0) + Buffer.byteLength(text);
      if (search && d.epoch === search.epoch) {
        try { search.add(e.id, batch); d.indexed += batch.length; } catch (err) { log(`index ${e.id.slice(0, 8)}: ${err.message}`); }
      }
      batch = [];
    };
    if (search && d.epoch !== search.epoch && start === 0) { d.epoch = search.epoch; d.indexed = 0; }
    let fh;
    let end = start;
    try {
      fh = await open(file, 'r');
      end = await readLines(fh, start, size, async (buf, huge) => {
        if (!buf) { dg.bad(huge); return; }
        const entry = parseLine(buf);
        if (!entry) { dg.bad(); return; }
        let recs;
        try { recs = dg.feed(entry); } catch { dg.bad(); return; }
        for (const r of recs) batch.push(r);
        if (batch.length >= 2000) await flush();
      });
    } finally { if (fh) await fh.close().catch(() => {}); }
    await flush();
    d.offset = end;
    d.tailHash = await hashRange(file, Math.max(0, end - 64), end);
    d.state = dg.state();
    e.stats = dg.snapshot();
    return true;
  }

  /** Usage of subagent transcripts (<id>/subagents/*.jsonl): stats only, no records. */
  async function digestAgents(e, folder) {
    const dir = join(folder, 'subagents');
    let files = [];
    try { files = (await readdir(dir)).filter(f => f.endsWith('.jsonl')); } catch { return; }
    for (const f of files) {
      const file = join(dir, f);
      let st;
      try { st = await stat(file); } catch { continue; }
      const a = e.agents[f] || (e.agents[f] = { offset: 0, tailHash: '', state: null });
      if (st.size < a.offset || (a.offset > 0 && (await hashRange(file, Math.max(0, a.offset - 64), a.offset)) !== a.tailHash)) {
        Object.assign(a, { offset: 0, tailHash: '', state: null });
      }
      if (st.size <= a.offset) continue;
      const dg = createDigester(a.state, { recordsOn: false });
      let fh;
      try {
        fh = await open(file, 'r');
        a.offset = await readLines(fh, a.offset, st.size, (buf) => { if (buf) { try { dg.feed(parseLine(buf)); } catch { /* bad line */ } } });
      } catch { continue; } finally { if (fh) await fh.close().catch(() => {}); }
      a.tailHash = await hashRange(file, Math.max(0, a.offset - 64), a.offset);
      a.state = dg.state();
      a.cost = dg.snapshot().cost;
      a.tokens = Object.values(dg.snapshot().usage).reduce((x, y) => x + y, 0);
    }
    const list = Object.values(e.agents);
    e.agentStats = { count: list.length, cost: list.reduce((x, a) => x + (a.cost || 0), 0), tokens: list.reduce((x, a) => x + (a.tokens || 0), 0) };
  }

  async function peekCwd(file) {
    let fh;
    try {
      fh = await open(file, 'r');
      const buf = Buffer.alloc(64 * 1024);
      const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
      const m = buf.subarray(0, bytesRead).toString('utf8').match(/"cwd":"((?:[^"\\]|\\.)*)"/);
      return m ? JSON.parse(`"${m[1]}"`) : '';
    } catch { return ''; } finally { if (fh) await fh.close().catch(() => {}); }
  }

  async function resolveProject(e) {
    const cwd = e.stats.cwd;
    if (!cwd || e.repoRoot || !(await exists(cwd))) {
      if (!e.project) e.project = basename(e.repoRoot || cwd || '') || '';
      return;
    }
    let root = await gitAsync(cwd, ['rev-parse', '--path-format=absolute', '--git-common-dir']);
    root = root ? root.replace(/\/\.git\/?$/, '') : (await gitAsync(cwd, ['rev-parse', '--show-toplevel'])) || '';
    e.repoRoot = root || '';
    e.project = basename(root || cwd) || '';
  }

  async function sizeOf(dir) {
    let shared = 0, own = 0;
    for (const rel of await walkFiles(dir, 4)) {
      try {
        const st = await lstat(join(dir, rel));
        if (st.nlink > 1) shared += st.size; else own += st.size;
      } catch { /* raced */ }
    }
    return { shared, own };
  }

  /** Save (or update) one session found in Claude Code's projects folder. */
  async function processSession(t, registry, vdm) {
    const prev = entries.get(t.id);
    const fresh = !prev;
    // A copy: if anything fails halfway, the entry in memory and on disk stays as it was,
    // and the next scan cuts any half-written digest back to it.
    const e = prev ? structuredClone(prev) : newEntry(t.id);
    const sameSrc = e.src && e.src.ino === t.st.ino && e.src.size === t.st.size && e.src.mtimeMs === t.st.mtimeMs;
    let changed = fresh || !e.original || e.projectDir !== t.dir;
    e.original = true; e.goneAt = null; e.projectDir = t.dir; e.compressed = false;
    const rawMissing = e.raw.mode === 'link' && !(await exists(join(rawDir(t.id), `${t.id}.jsonl`)));

    if (!sameSrc || rawMissing || fresh) {
      await mkdir(sessDir(t.id), { recursive: true, mode: 0o700 });
      if (e.raw.mode !== 'none') {
        const r = await ensureLink(t.path, join(rawDir(t.id), `${t.id}.jsonl`));
        if (r === 'unsupported') {
          e.raw = { mode: 'none', note: 'Hard links are not possible here, so only the readable text is saved.' };
          log(`${t.id.slice(0, 8)}: cannot hard-link transcripts (${t.path}); saving the digest only`);
        } else if (r !== 'gone') e.raw.mode = 'link';
        if (e.raw.mode === 'link') {
          const folder = join(P.projects, t.dir, t.id);
          for (const rel of await walkFiles(folder, 3)) {
            try { await ensureLink(join(folder, rel), join(rawDir(t.id), t.id, rel)); } catch (err) { log(`link ${rel}: ${err.message}`); }
          }
        }
      }
      if (await digestSession(e, t.path, t.st.size)) changed = true;
      await digestAgents(e, join(P.projects, t.dir, t.id));
      e.src = { ino: t.st.ino, size: t.st.size, mtimeMs: t.st.mtimeMs };
      e.automated = /^sdk|print|headless/i.test(e.stats.entrypoint || '');
      changed = true;
    }

    const live = registry.get(t.id);
    if (live && (live.name !== e.liveName || live.nameSource !== e.liveNameSource)) {
      e.liveName = live.name; e.liveNameSource = live.nameSource; changed = true;
    }
    if (mergeAccounts(e, vdm.get(t.id))) changed = true;
    if (changed) {
      if (!e.repoRoot) await resolveProject(e);
      e.bytes = await sizeOf(rawDir(t.id));
      if (await saveEntry(e)) entries.set(t.id, e);
    }
    return changed;
  }

  /**
   * Keep the proxy's per-account totals (the proxy forgets sessions after 7 days), keyed by
   * account email so they stay with the account across re-logins.
   */
  function mergeAccounts(e, s) {
    if (!s || !s.accounts) return false;
    let changed = false;
    for (const [name, a] of Object.entries(s.accounts)) {
      const info = accountLabels.get(name);
      const id = info?.id || name;
      if (id !== name && e.accounts[name]) { // saved earlier under the file name
        e.accounts[id] = e.accounts[id] || e.accounts[name];
        delete e.accounts[name];
        changed = true;
      }
      const cur = e.accounts[id];
      const label = info?.label || cur?.label || '';
      if (!cur || (a.requests || 0) > (cur.requests || 0) || cur.label !== label) {
        e.accounts[id] = { requests: a.requests || 0, cost: a.cost || 0, lastAt: a.lastAt || 0, label };
        changed = true;
      }
    }
    return changed;
  }

  /** Claude Code deleted the transcript: compress our copies (they are now the only ones). */
  async function compressOrphans(e) {
    const dir = rawDir(e.id);
    let done = true;
    for (const rel of await walkFiles(dir, 4)) {
      if (closing) return false;
      // Temp files of a process that died (a stale .lnk would keep a file "shared" forever)
      const stale = rel.match(/\.(?:lnk|tmp|br\.tmp)-(\d+)$/);
      if (stale) {
        const pid = Number(stale[1]);
        if (pid !== process.pid && !pidAlive(pid)) { try { await unlink(join(dir, rel)); } catch { /* gone */ } }
        continue;
      }
      if (rel.endsWith('.br')) continue;
      const file = join(dir, rel);
      let st;
      try { st = await lstat(file); } catch { continue; }
      if (st.nlink > 1) { done = false; continue; } // Claude Code still has this file: try again on a later scan
      try {
        const fs = await statfs(dir);
        if (fs.bavail * fs.bsize < st.size / 2 + 200 * 1024 * 1024) { done = false; scanError = 'Disk is almost full: old sessions are kept uncompressed for now.'; continue; }
      } catch { /* statfs unsupported */ }
      const tmp = `${file}.br.tmp-${process.pid}`;
      try {
        await pipeline(
          createReadStream(file),
          zlib.createBrotliCompress({ params: {
            [zlib.constants.BROTLI_PARAM_QUALITY]: 5,
            [zlib.constants.BROTLI_PARAM_MODE]: zlib.constants.BROTLI_MODE_TEXT,
            [zlib.constants.BROTLI_PARAM_SIZE_HINT]: st.size,
          } }),
          createWriteStream(tmp, { mode: 0o600, flush: true }),
        );
        await rename(tmp, `${file}.br`);
        await unlink(file);
      } catch (err) {
        done = false;
        try { await unlink(tmp); } catch { /* none */ }
        log(`compress ${e.id.slice(0, 8)}/${rel}: ${err.message}`);
      }
      await sleep(5);
    }
    return done;
  }

  async function deleteSession(id, { tombstone = true } = {}) {
    if (!SESSION_ID_RE.test(id)) throw new Error('bad session id');
    const dir = sessDir(id);
    if (relative(P.sessions, dir) !== id) throw new Error('bad path');
    if (tombstone) {
      // First, so a scan that is saving this session right now drops it instead
      deleted[id] = Date.now();
      await writeJsonAtomic(P.deleted, deleted);
    }
    const saving = busy.get(id);
    if (saving) await saving.catch(() => {});
    entries.delete(id);
    await rm(dir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    if (search) { try { search.remove(id); } catch { /* index error */ } }
  }

  /** A process that wanted to save but found the lock taken retries on each scan. */
  async function tryBecomeWriter() {
    if (canWrite || !wantWriter || !(await acquireLock())) return canWrite;
    canWrite = true;
    if (search) search.close();
    search = await openSearchIndex(P.db, { readOnly: false, log });
    entries.clear();
    await loadEntries();
    log('the other vdm process stopped: this one saves sessions now');
    return true;
  }

  async function scanOnce() {
    if (scanning) return scanning;
    if (!cfg.enabled) return { skipped: 'off' };
    if (!canWrite && !wantWriter) return { skipped: 'read-only' };
    scanning = (async () => {
      if (!canWrite && !(await tryBecomeWriter())) return { skipped: 'read-only' };
      const started = Date.now();
      scanError = null;
      accountLabels = readAccountLabels();
      const [registry, vdm] = await Promise.all([readRegistry(), readVdmSessions()]);
      const found = [];
      let dirs = [];
      try { dirs = await readdir(P.projects, { withFileTypes: true }); } catch { /* no projects yet */ }
      for (const d of dirs) {
        if (!d.isDirectory()) continue;
        let files = [];
        try { files = await readdir(join(P.projects, d.name)); } catch { continue; }
        for (const f of files) {
          if (!f.endsWith('.jsonl')) continue;
          const id = f.slice(0, -6);
          if (!SESSION_ID_RE.test(id) || deleted[id]) continue;
          const path = join(P.projects, d.name, f);
          try {
            const st = await lstat(path);
            if (st.isFile()) found.push({ id, dir: d.name, path, st });
          } catch { /* deleted meanwhile */ }
        }
      }
      found.sort((a, b) => b.st.mtimeMs - a.st.mtimeMs);
      const seen = new Set();
      const firstPass = entries.size === 0;
      if (firstPass) backfill = { done: 0, total: found.length };
      let changed = 0;
      for (const t of found) {
        if (closing) return { aborted: true };
        seen.add(t.id);
        try {
          const known = entries.get(t.id);
          const cwd = known?.stats?.cwd || await peekCwd(t.path);
          if (isExcluded(cwd, cfg.exclude) || deleted[t.id]) continue;
          const saving = processSession(t, registry, vdm);
          busy.set(t.id, saving);
          try { if (await saving) changed++; } finally { busy.delete(t.id); }
        } catch (err) {
          log(`save ${t.id.slice(0, 8)}: ${err.message}`);
          if (/ENOSPC/.test(err.message)) scanError = 'Disk is full: new sessions are not being saved.';
        }
        if (backfill) backfill.done++;
        await sleep(firstPass ? 15 : 2);
      }
      backfill = null;
      for (const e of entries.values()) {
        if (closing) return { aborted: true };
        if (seen.has(e.id)) continue;
        let dirty = false;
        if (e.original) { e.original = false; e.goneAt = Date.now(); dirty = true; }
        if (mergeAccounts(e, vdm.get(e.id))) dirty = true;
        if (!e.compressed && e.raw.mode === 'link') {
          e.compressed = await compressOrphans(e);
          e.bytes = await sizeOf(rawDir(e.id));
          dirty = true;
        }
        if (dirty) await saveEntry(e).catch(err => log(`save ${e.id.slice(0, 8)}: ${err.message}`));
      }
      if (cfg.retentionDays > 0) {
        const cut = Date.now() - cfg.retentionDays * 86400000;
        for (const e of [...entries.values()]) {
          if (!e.original && (e.stats.lastAt || e.savedAt) < cut) {
            await deleteSession(e.id, { tombstone: false }).catch(err => log(`retention ${e.id.slice(0, 8)}: ${err.message}`));
          }
        }
      }
      // A search index that was deleted or rebuilt: re-add every digest
      if (search) await reindexStale();
      lastScan = { at: Date.now(), ms: Date.now() - started, sessions: found.length, changed };
      return lastScan;
    })().catch(err => { scanError = err.message; log(`scan failed: ${err.message}`); return { error: err.message }; })
      .finally(() => { scanning = null; backfill = null; });
    return scanning;
  }

  async function readDigest(id) {
    let text = '';
    try { text = await readFile(digestFile(id), 'utf8'); } catch { return []; }
    const out = [];
    for (const line of text.split('\n')) {
      if (!line) continue;
      try { out.push(JSON.parse(line)); } catch { /* torn line */ }
    }
    return out;
  }

  /** Re-add digests to a search index that was deleted, rebuilt or migrated (one run at a time). */
  let reindexing = null;
  function reindexStale() {
    if (!search || !canWrite) return Promise.resolve();
    if (reindexing) return reindexing;
    reindexing = (async () => {
      for (const e of [...entries.values()]) {
        if (closing) return;
        if (deleted[e.id] || (e.digest.epoch === search.epoch && e.digest.indexed > 0)) continue;
        const records = await readDigest(e.id);
        if (!records.length || deleted[e.id]) continue;
        try {
          search.remove(e.id);
          search.add(e.id, records);
          const next = { ...e, digest: { ...e.digest, epoch: search.epoch, indexed: records.length } };
          if (await saveEntry(next)) entries.set(e.id, next);
          else { entries.delete(e.id); search.remove(e.id); }
        } catch (err) { log(`reindex ${e.id.slice(0, 8)}: ${err.message}`); return; }
        await sleep(5);
      }
    })().finally(() => { reindexing = null; });
    return reindexing;
  }

  function resolveId(ref) {
    const r = String(ref || '').toLowerCase().trim();
    if (SESSION_ID_RE.test(r)) return entries.has(r) ? r : null;
    if (r.length < 4 || !/^[0-9a-f-]+$/.test(r)) return null;
    const hits = [...entries.keys()].filter(id => id.startsWith(r));
    if (hits.length > 1) { const err = new Error(`"${ref}" matches ${hits.length} sessions: use more characters`); err.code = 'AMBIGUOUS'; throw err; }
    return hits[0] || null;
  }

  function getEntry(ref) {
    const id = resolveId(ref);
    const e = id && entries.get(id);
    if (!e) { const err = new Error(`No saved session "${ref}"`); err.code = 'NOT_FOUND'; throw err; }
    return e;
  }

  function row(e, live) {
    const st = e.stats || {};
    return {
      id: e.id, title: sessionTitle(e), project: e.project || basename(st.cwd || ''), cwd: st.cwd || '',
      branch: st.branch || '', branches: st.branches || [], firstAt: st.firstAt, lastAt: st.lastAt,
      userTurns: st.userTurns || 0, compactions: st.compactions || 0, models: Object.keys(st.models || {}),
      cost: (st.cost || 0) + (e.agentStats?.cost || 0), agents: e.agentStats?.count || 0,
      tokens: USAGE_KEYS.reduce((x, k) => x + (st.usage?.[k] || 0), 0) + (e.agentStats?.tokens || 0),
      accounts: Object.entries(e.accounts || {}).map(([name, a]) => ({ name, label: a.label || name, requests: a.requests, cost: a.cost })),
      original: !!e.original, rawMode: e.raw?.mode || 'none', automated: !!e.automated, live: !!live,
      firstPrompt: st.firstPrompt || '', lastPrompt: st.lastPrompt || '',
      topFiles: Object.entries(st.files || {}).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([f]) => f),
      links: (st.links || []).slice(0, 3), bytes: e.bytes || { shared: 0, own: 0 },
    };
  }

  async function scanSearch(n, ids, budgetMs = 2000) {
    const out = new Map();
    const t0 = Date.now();
    let partial = false;
    for (const id of ids) {
      if (Date.now() - t0 > budgetMs) { partial = true; break; }
      const records = await readDigest(id);
      let hit = null, hits = 0;
      const seenWords = new Set();
      for (const r of records) {
        const text = String(r.r === 'tool' ? `${r.n} ${r.x}` : r.x).toLowerCase();
        let any = false;
        for (const w of n) if (text.includes(w)) { seenWords.add(w); any = true; }
        if (any) {
          hits++;
          if (text.includes(n[0]) && (!hit || (ROLE_WEIGHT[r.r] || 1) > (ROLE_WEIGHT[hit.r] || 1))) hit = r;
        }
      }
      if (hit && seenWords.size === n.length) {
        const text = String(hit.r === 'tool' ? `${hit.n} ${hit.x}` : hit.x);
        const at = text.toLowerCase().indexOf(n[0]);
        const from = Math.max(0, at - 60);
        const snip = (from > 0 ? '…' : '') + text.slice(from, at) + '\u0002' + text.slice(at, at + n[0].length) + '\u0003' + text.slice(at + n[0].length, at + n[0].length + 80) + '…';
        out.set(id, { score: hits * (ROLE_WEIGHT[hit.r] || 1), hits, snip, seq: hit.i });
      }
    }
    return { hits: out, partial };
  }

  /** List sessions, newest first, optionally searched and filtered. */
  async function list({ q = '', project = '', branch = '', account = '', days = 0, automated = false, offset = 0, limit = 50 } = {}) {
    const registry = await readRegistry();
    const parsed = parseQuery(q);
    const filters = { ...parsed.filters, automated };
    if (project) filters.project = project;
    if (branch) filters.branch = branch;
    if (account) filters.account = account;
    if (days > 0) filters.since = Date.now() - days * 86400000;
    // file: also matches files a session read, searched or named in a command (tool lines)
    if (filters.file && search) {
      const m = ftsMatch({ words: [], phrases: [filters.file] });
      try { if (m) filters.fileIds = search.sessionsWithRole(m, 'tool'); } catch { /* bad query */ }
    }
    let pool = [...entries.values()].filter(e => entryMatches(e, filters));
    const n = needles(parsed);
    let hits = null, engine = null, partial = false;
    if (n.length) {
      const terms = ftsTerms(parsed);
      if (search && !terms.length) {
        engine = 'meta';
        hits = new Map();
      } else if (search) {
        engine = 'fts';
        const words = parsed.words.flatMap(w => w.toLowerCase().split(/[^\p{L}\p{N}]+/u)).filter(Boolean);
        const phrase = words.length > 1 ? `"${words.join(' ')}"` : '';
        try { hits = search.sessions(terms, ftsMatch(parsed), { phrase, total: entries.size }); } catch (err) { log(`search: ${err.message}`); hits = new Map(); }
      } else {
        engine = 'scan';
        const r = await scanSearch(n, pool.sort((a, b) => (b.stats.lastAt || 0) - (a.stats.lastAt || 0)).map(e => e.id));
        hits = r.hits; partial = r.partial;
      }
      // Titles, branches, folders and ids count too (they are not in the digest)
      for (const e of pool) {
        const meta = `${sessionTitle(e)} ${e.stats.branch} ${(e.stats.branches || []).join(' ')} ${e.stats.cwd} ${e.id}`.toLowerCase();
        if (n.every(w => meta.includes(w))) {
          const h = hits.get(e.id);
          if (h) h.score += 50; else hits.set(e.id, { score: 50, hits: 0, snip: '', seq: null, meta: true });
        }
      }
      pool = pool.filter(e => hits.has(e.id));
      pool.sort((a, b) => (hits.get(b.id).score - hits.get(a.id).score) || ((b.stats.lastAt || 0) - (a.stats.lastAt || 0)));
    } else {
      pool.sort((a, b) => (b.stats.lastAt || 0) - (a.stats.lastAt || 0));
    }
    const all = [...entries.values()];
    const facets = {
      projects: [...new Set(all.map(e => e.project).filter(Boolean))].sort(),
      branches: [...new Set(all.flatMap(e => e.stats.branches || []).filter(Boolean))].sort(),
      accounts: [...new Map(all.flatMap(e => Object.entries(e.accounts || {}).map(([nme, a]) => [nme, a.label || nme]))).entries()]
        .map(([name, label]) => ({ name, label })).sort((a, b) => a.label.localeCompare(b.label)),
    };
    const storage = all.reduce((acc, e) => ({ shared: acc.shared + (e.bytes?.shared || 0), own: acc.own + (e.bytes?.own || 0) + (e.digest?.bytes || 0) }), { shared: 0, own: 0 });
    for (const f of [P.db, `${P.db}-wal`]) { try { storage.own += (await stat(f)).size; } catch { /* none */ } }
    const lim = Math.min(Math.max(1, limit | 0), 500);
    const pageEntries = pool.slice(offset | 0, (offset | 0) + lim);
    if (hits && engine === 'fts') {
      const need = pageEntries.filter(e => { const h = hits.get(e.id); return h && !h.snip && h.hits; }).map(e => e.id);
      if (need.length) {
        try { for (const [id, sn] of search.snippets(need, ftsTerms(parsed))) Object.assign(hits.get(id), sn); } catch { /* no snippets */ }
      }
    }
    const page = pageEntries.map(e => {
      const r = row(e, registry.has(e.id));
      const h = hits?.get(e.id);
      if (h) { r.snippet = h.snip || ''; r.hitSeq = h.seq; r.hitCount = h.hits; }
      return r;
    });
    return {
      total: pool.length, sessions: page, facets, storage, count: all.length, writer: canWrite,
      automatedHidden: automated ? 0 : all.filter(e => e.automated).length,
      search: n.length ? { engine, partial } : null,
    };
  }

  async function detail(ref) {
    const e = getEntry(ref);
    const registry = await readRegistry();
    const r = row(e, registry.has(e.id));
    const cwdExists = !!(e.stats.cwd && await exists(e.stats.cwd));
    const originalNow = !!e.projectDir && await exists(join(P.projects, e.projectDir, `${e.id}.jsonl`));
    const records = await readDigest(e.id);
    return {
      ...r,
      stats: { ...e.stats, files: undefined, models: e.stats.models },
      files: Object.entries(e.stats.files || {}).sort((a, b) => b[1] - a[1]).slice(0, 50),
      allLinks: e.stats.links || [],
      repoRoot: e.repoRoot, projectDir: e.projectDir, goneAt: e.goneAt, rawNote: e.raw?.note || '',
      cwdExists, canResume: cwdExists && (originalNow || (e.raw?.mode !== 'none' && await hasRaw(e.id))),
      needsRestore: !originalNow,
      commands: sessionCommands(e, cfg.claudeCommand),
      digestPath: digestFile(e.id),
      messages: records.length,
      prompts: records.filter(x => x.r === 'user').map(x => ({ i: x.i, t: x.t, x: oneLine(x.x, 140) })),
      compactionMarks: records.filter(x => x.r === 'compact').map(x => ({ i: x.i, t: x.t })),
    };
  }

  async function hasRaw(id) {
    return (await exists(join(rawDir(id), `${id}.jsonl`))) || (await exists(join(rawDir(id), `${id}.jsonl.br`)));
  }

  /** A page of digest records: from a sequence number, or around one (to show a search hit). */
  async function messages(ref, { from = null, around = null, limit = 200 } = {}) {
    const e = getEntry(ref);
    const records = await readDigest(e.id);
    const lim = Math.min(Math.max(1, limit | 0), 1000);
    let start;
    if (around != null) {
      const idx = records.findIndex(r => r.i >= Number(around));
      start = Math.max(0, (idx === -1 ? records.length : idx) - Math.floor(lim / 4));
    } else if (from != null) {
      const idx = records.findIndex(r => r.i >= Number(from));
      start = idx === -1 ? records.length : idx;
    } else start = Math.max(0, records.length - lim); // newest page
    return { id: e.id, total: records.length, start, records: records.slice(start, start + lim) };
  }

  async function handoff(ref) {
    const e = getEntry(ref);
    const records = await readDigest(e.id);
    const planPath = e.stats.slug ? join(P.plans, `${e.stats.slug}.md`) : '';
    const md = buildHandoff(e, records, { digestPath: digestFile(e.id), planPath: planPath && await exists(planPath) ? planPath : '' });
    const file = join(sessDir(e.id), 'handoff.md');
    await writeFile(`${file}.tmp-${process.pid}`, md, { mode: 0o600 });
    await rename(`${file}.tmp-${process.pid}`, file);
    return { id: e.id, path: file, chars: md.length, prompt: handoffPrompt(e, file), commands: sessionCommands(e, cfg.claudeCommand) };
  }

  /** The archived transcript to download: { file, compressed }. */
  async function transcriptFile(ref) {
    const e = getEntry(ref);
    const plain = join(rawDir(e.id), `${e.id}.jsonl`);
    if (await exists(plain)) return { id: e.id, file: plain, compressed: false };
    if (await exists(`${plain}.br`)) return { id: e.id, file: `${plain}.br`, compressed: true };
    if (e.original) return { id: e.id, file: join(P.projects, e.projectDir, `${e.id}.jsonl`), compressed: false };
    const err = new Error('No full copy of this session was saved (only the readable text).');
    err.code = 'NOT_FOUND';
    throw err;
  }

  /**
   * Put a session Claude Code deleted back in its projects folder so `claude --resume` finds it.
   * Never overwrites (link(tmp, final) fails if the file exists); gives the file today's date
   * so Claude Code's 30-day cleanup does not delete it again right away.
   */
  async function restore(ref) {
    const e = getEntry(ref);
    if (!e.projectDir || /[/\\]|^\.\.?$/.test(e.projectDir)) throw new Error('Unknown project folder for this session');
    const destDir = join(P.projects, e.projectDir);
    const files = [];
    for (const rel of await walkFiles(rawDir(e.id), 4)) {
      if (/\.(lnk|tmp)-\d+$/.test(rel) || /\.br\.tmp-\d+$/.test(rel)) continue;
      const out = rel.endsWith('.br') ? rel.slice(0, -3) : rel;
      if (out.endsWith('.prev')) continue;
      if (out !== `${e.id}.jsonl` && !out.startsWith(`${e.id}/`)) continue;
      files.push({ src: join(rawDir(e.id), rel), dst: join(destDir, out), compressed: rel.endsWith('.br') });
    }
    if (!files.some(f => f.dst === join(destDir, `${e.id}.jsonl`))) throw new Error('No full copy of this session was saved (only the readable text).');
    let restored = 0, skipped = 0;
    const now = new Date();
    // Temp files of an interrupted restore by a process that is gone
    for (const f of await readdir(destDir).catch(() => [])) {
      const m = f.match(/^\..+\.vdm-restore-(\d+)$/);
      if (m && f.includes(e.id) && !pidAlive(Number(m[1]))) await unlink(join(destDir, f)).catch(() => {});
    }
    for (const f of files) {
      if (await exists(f.dst)) { skipped++; continue; }
      await mkdir(dirname(f.dst), { recursive: true });
      const tmp = join(dirname(f.dst), `.${basename(f.dst)}.vdm-restore-${process.pid}`);
      try {
        if (f.compressed) await pipeline(createReadStream(f.src), zlib.createBrotliDecompress(), createWriteStream(tmp, { mode: 0o600, flush: true }));
        else await copyFile(f.src, tmp);
        await utimes(tmp, now, now);
        try { await link(tmp, f.dst); restored++; } catch (err) { if (err.code === 'EEXIST') skipped++; else throw err; }
      } finally { try { await unlink(tmp); } catch { /* gone */ } }
    }
    return { id: e.id, restored, skipped, path: join(destDir, `${e.id}.jsonl`), commands: sessionCommands(e, cfg.claudeCommand) };
  }

  function status() {
    return {
      enabled: cfg.enabled, writer: canWrite, sessions: entries.size, scanning: !!scanning, pid: process.pid,
      backfill, lastScan, error: scanError, search: search ? 'fts' : 'scan', root: P.root,
      claudeCommand: cfg.claudeCommand, retentionDays: cfg.retentionDays, exclude: cfg.exclude,
    };
  }

  function setConfig(next) {
    const wasOn = cfg.enabled;
    cfg = { ...cfg, ...next };
    if (!wasOn && cfg.enabled) scanOnce();
  }

  async function close() {
    closing = true;
    if (scanning) { try { await scanning; } catch { /* logged */ } }
    if (search) search.close();
    await releaseLock();
  }

  // ── open ──
  if (writer) canWrite = await acquireLock();
  await loadEntries();
  if (existsSync(P.db) || canWrite) search = await openSearchIndex(P.db, { readOnly: !canWrite, log });

  return {
    scanOnce, list, detail, messages, handoff, restore, transcriptFile, status, setConfig, close,
    reindex: () => reindexStale(),
    remove: async (ref) => { if (!canWrite) throw new Error('read-only'); const e = getEntry(ref); await deleteSession(e.id); return { id: e.id, deleted: true }; },
    getEntry, readDigest, get canWrite() { return canWrite; }, get config() { return cfg; },
  };
}

// ─────────────────────────────────────────────────
// Child process of the dashboard
// ─────────────────────────────────────────────────

const SCAN_EVERY_MS = 2 * 60 * 1000;

async function serve() {
  const log = (m) => { try { process.stdout.write(`${m}\n`); } catch { /* pipe closed */ } };
  const P = historyPaths();
  const archive = await openArchive({ P, writer: true, log });
  if (!archive.canWrite) log('another vdm process is saving sessions: this one is read-only');
  let timer = null;
  const schedule = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => { await archive.scanOnce(); schedule(); }, SCAN_EVERY_MS);
    timer.unref?.();
  };
  const ops = {
    status: () => archive.status(),
    scan: () => { archive.scanOnce(); return archive.status(); },
    config: (a) => { archive.setConfig(a || {}); return archive.status(); },
    list: (a) => archive.list(a),
    get: (a) => archive.detail(a.id),
    messages: (a) => archive.messages(a.id, a),
    handoff: (a) => archive.handoff(a.id),
    restore: (a) => archive.restore(a.id),
    remove: (a) => archive.remove(a.id),
    transcript: (a) => archive.transcriptFile(a.id),
  };
  process.on('message', async (msg) => {
    if (!msg || typeof msg !== 'object' || !msg.op) return;
    const reply = (body) => { try { process.send({ id: msg.id, ...body }); } catch { /* parent gone */ } };
    const fn = ops[msg.op];
    if (!fn) return reply({ ok: false, error: `unknown op ${msg.op}` });
    try { reply({ ok: true, result: await fn(msg.args || {}) }); } catch (err) { reply({ ok: false, error: err.message, code: err.code || null }); }
  });
  const shutdown = async () => { clearTimeout(timer); await archive.close(); process.exit(0); };
  process.on('disconnect', shutdown);
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
  try { process.send({ ready: true, status: archive.status() }); } catch { /* no parent */ }
  archive.reindex().catch((err) => log(`reindex: ${err.message}`));
  if (archive.config.enabled) archive.scanOnce().then(schedule); else schedule();
}

// ─────────────────────────────────────────────────
// CLI (vdm history …)
// ─────────────────────────────────────────────────

const C = process.stdout.isTTY ? { b: '\x1b[1m', d: '\x1b[2m', c: '\x1b[36m', y: '\x1b[33m', g: '\x1b[32m', r: '\x1b[31m', n: '\x1b[0m' } : { b: '', d: '', c: '', y: '', g: '', r: '', n: '' };
const ago = (t) => {
  if (!t) return '?';
  const m = Math.round((Date.now() - t) / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  if (m < 48 * 60) return `${Math.round(m / 60)}h ago`;
  return `${Math.round(m / 1440)}d ago`;
};
const money = (n) => `$${(n || 0) < 10 ? (n || 0).toFixed(2) : Math.round(n || 0)}`;

async function dashboardCall(method, path) {
  const port = process.env.CSW_PORT || '3333';
  const res = await fetch(`http://localhost:${port}${path}`, { method, signal: AbortSignal.timeout(15000) });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `dashboard answered ${res.status}`);
  return body;
}

function printRows(rows) {
  for (const r of rows) {
    const where = [r.project, r.branch].filter(Boolean).join(' · ');
    const flags = [r.live ? `${C.g}live${C.n}` : '', r.original ? '' : `${C.y}saved copy${C.n}`, r.compactions ? `compacted ×${r.compactions}` : ''].filter(Boolean).join(' ');
    console.log(`  ${C.c}${r.id.slice(0, 8)}${C.n}  ${C.b}${r.title}${C.n}  ${C.d}${where}${C.n}`);
    console.log(`            ${C.d}${ago(r.lastAt)} · ${r.userTurns} messages · ${money(r.cost)}${r.accounts.length ? ' · ' + r.accounts.map(a => a.label).join(', ') : ''}${C.n}${flags ? '  ' + flags : ''}`);
    if (r.snippet) console.log(`            ${r.snippet.replace(/\u0002/g, C.y).replace(/\u0003/g, C.n).replace(/\s+/g, ' ')}`);
    else if (r.firstPrompt) console.log(`            ${C.d}"${r.firstPrompt.slice(0, 110)}"${C.n}`);
  }
}

async function cli(argv) {
  const [cmd = 'list', ...rest] = argv;
  const P = historyPaths();
  const archive = await openArchive({ P, writer: false });
  const flag = (name) => { const i = rest.indexOf(name); if (i === -1) return null; const v = rest[i + 1]; rest.splice(i, 2); return v; };
  const has = (name) => { const i = rest.indexOf(name); if (i === -1) return false; rest.splice(i, 1); return true; };
  try {
    switch (cmd) {
      case 'list': case 'search': {
        const days = Number(flag('--days')) || 0;
        const all = has('--all');
        const q = rest.map(a => (/\s/.test(a) && !a.includes('"') ? `"${a}"` : a)).join(' ');
        const res = await archive.list({ q: cmd === 'search' ? q : '', days, automated: all, limit: Number(flag('--limit')) || 20 });
        if (!archive.config.enabled && !res.count) {
          console.log(`\n  Session history is off. Turn it on: ${C.c}vdm config history on${C.n}\n`);
          return 0;
        }
        console.log('');
        if (!res.sessions.length) console.log(`  ${C.d}No sessions found.${C.n}`);
        printRows(res.sessions);
        console.log(`\n  ${C.d}${res.total} of ${res.count} sessions${res.search?.partial ? ' (search stopped early: narrow it down)' : ''}${res.automatedHidden ? ` · ${res.automatedHidden} automated hidden (--all)` : ''}${C.n}`);
        console.log(`  ${C.d}Next: vdm history show <id> · prompt <id> · continue <id> · resume <id>${C.n}\n`);
        return 0;
      }
      case 'show': {
        const d = await archive.detail(rest[0]);
        console.log(`\n  ${C.b}${d.title}${C.n}  ${C.d}${d.id}${C.n}`);
        console.log(`  ${C.d}Folder:${C.n} ${d.cwd || '?'}${d.cwdExists ? '' : ` ${C.y}(gone)${C.n}`}`);
        if (d.branch) console.log(`  ${C.d}Branch:${C.n} ${d.branch}`);
        console.log(`  ${C.d}When:${C.n}   ${d.firstAt ? new Date(d.firstAt).toLocaleString() : '?'} → ${d.lastAt ? new Date(d.lastAt).toLocaleString() : '?'}`);
        console.log(`  ${C.d}Size:${C.n}   ${d.userTurns} of your messages · ${d.compactions} compactions · ${money(d.cost)} at API prices`);
        if (d.accounts.length) console.log(`  ${C.d}Accounts:${C.n} ${d.accounts.map(a => `${a.label} (${a.requests})`).join(', ')}`);
        if (d.firstPrompt) console.log(`  ${C.d}First:${C.n}  "${d.firstPrompt}"`);
        if (d.lastPrompt) console.log(`  ${C.d}Last:${C.n}   "${d.lastPrompt}"`);
        if (d.files.length) console.log(`  ${C.d}Files:${C.n}  ${d.files.slice(0, 6).map(([f]) => f.split('/').pop()).join(', ')}`);
        console.log('');
        console.log(`  ${C.b}Continue in a new session:${C.n} ${C.c}vdm history continue ${d.id.slice(0, 8)}${C.n}  ${C.d}(or: vdm history prompt ${d.id.slice(0, 8)})${C.n}`);
        console.log(`  ${C.b}Resume exactly:${C.n}            ${C.c}vdm history resume ${d.id.slice(0, 8)}${C.n}${d.needsRestore ? `  ${C.d}(restores the file first)${C.n}` : ''}`);
        console.log('');
        return 0;
      }
      case 'prompt': {
        const e = archive.getEntry(rest[0]);
        let h;
        try { h = await dashboardCall('POST', `/api/history/${e.id}/handoff`); } catch { h = await archive.handoff(e.id); }
        process.stdout.write(h.prompt + '\n');
        return 0;
      }
      case 'launch': {
        // For `vdm history resume|continue`: prints folder, launch command and argument, one per line
        const mode = rest[0];
        const e = archive.getEntry(rest[1]);
        const cwd = e.stats.cwd;
        let dir = cwd && existsSync(cwd) ? cwd : (e.repoRoot && existsSync(e.repoRoot) ? e.repoRoot : '');
        if (mode === 'resume') {
          if (!cwd || !existsSync(cwd)) {
            console.error(`The folder of this session is gone: ${cwd || '?'}`);
            if (e.stats.branch && e.repoRoot) console.error(`Recreate it: git -C '${e.repoRoot}' worktree add '${cwd}' ${e.stats.branch}`);
            console.error(`Or start fresh from a handoff: vdm history continue ${e.id.slice(0, 8)}`);
            return 2;
          }
          if (!e.original) {
            let r;
            try { r = await dashboardCall('POST', `/api/history/${e.id}/restore`); } catch { r = await archive.restore(e.id); }
            if (r.restored) console.error(`Restored the session file from the archive.`);
          }
          dir = cwd;
        }
        if (!dir) dir = process.cwd();
        if (/[\n\r]/.test(dir)) { console.error('Folder name has a line break; cannot launch.'); return 2; }
        let arg = e.id;
        if (mode === 'continue') {
          let h;
          try { h = await dashboardCall('POST', `/api/history/${e.id}/handoff`); } catch { h = await archive.handoff(e.id); }
          arg = h.path;
        }
        process.stdout.write(`${dir}\n${archive.config.claudeCommand}\n${arg}\n`);
        return 0;
      }
      case 'restore': {
        const e = archive.getEntry(rest[0]);
        let r;
        try { r = await dashboardCall('POST', `/api/history/${e.id}/restore`); } catch { r = await archive.restore(e.id); }
        console.log(r.restored ? `  ${C.g}✓${C.n} Restored ${r.path}` : `  ${C.d}Nothing to restore: Claude Code still has this session.${C.n}`);
        console.log(`  Resume it: ${C.c}${r.commands.resume}${C.n}`);
        return 0;
      }
      case 'delete': {
        const e = archive.getEntry(rest[0]);
        try { await dashboardCall('POST', `/api/history/${e.id}/delete`); } catch (err) {
          if (!/fetch failed|ECONNREFUSED|timeout/i.test(err.message)) throw err;
          const w = await openArchive({ P, writer: true });
          if (!w.canWrite) throw new Error('Another vdm process is saving sessions. Delete it from the History tab.');
          await w.remove(e.id);
          await w.close();
        }
        console.log(`  ${C.g}✓${C.n} Deleted ${e.id.slice(0, 8)} from the archive (Claude Code's own file is untouched). vdm will not save it again.`);
        return 0;
      }
      case 'scan': {
        try { await dashboardCall('POST', '/api/history/scan'); console.log('  Scan started in the dashboard.'); } catch {
          const w = await openArchive({ P, writer: true });
          if (!w.canWrite) throw new Error('Another vdm process is saving sessions.');
          const r = await w.scanOnce();
          await w.close();
          console.log(r.skipped === 'off' ? '  Session history is off (vdm config history on).' : `  Scanned ${r.sessions} sessions (${r.changed} updated) in ${r.ms} ms.`);
        }
        return 0;
      }
      default:
        console.error(`Unknown history command: ${cmd}`);
        return 1;
    }
  } catch (err) {
    console.error(`${C.r}${err.message}${C.n}`);
    return 1;
  } finally {
    await archive.close();
  }
}

// ─────────────────────────────────────────────────

function isMainModule() {
  try { return !!process.argv[1] && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
}
const isMain = isMainModule();
if (isMain) {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === 'serve') {
    try { os.setPriority(10); } catch { /* not allowed */ }
    serve().catch((err) => { console.error(`history: ${err.stack || err.message}`); process.exit(1); });
  } else if (mode === 'cli') {
    cli(args).then((code) => process.exit(code), (err) => { console.error(err.message); process.exit(1); });
  } else {
    console.error('usage: history.mjs serve | cli <list|search|show|prompt|launch|restore|delete|scan> …');
    process.exit(1);
  }
}
