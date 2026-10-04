// The upgrade bridge in install-hooks.sh: an older `vdm upgrade` copies a fixed list of four
// files, then sources install-hooks.sh. The bridge must copy the newer modules (history.mjs)
// before that upgrade's RETURN trap deletes its checkout — and do nothing anywhere else.
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import os from 'node:os';

const REPO = new URL('..', import.meta.url).pathname;

// The shape of cmd_upgrade in vdm v4 and older (set -euo pipefail, RETURN trap, fixed copy list)
const OLD_UPGRADE = `
set -euo pipefail
SCRIPT_DIR="$INSTALL"
cmd_upgrade() {
  local tmpdir
  tmpdir=$(mktemp -d)
  trap "rm -rf '$tmpdir'" RETURN
  cp -R "$CHECKOUT"/. "$tmpdir"/
  cp "$tmpdir/vdm"               "$SCRIPT_DIR/vdm"
  cp "$tmpdir/dashboard.mjs"     "$SCRIPT_DIR/dashboard.mjs"
  cp "$tmpdir/lib.mjs"           "$SCRIPT_DIR/lib.mjs"
  cp "$tmpdir/install-hooks.sh"  "$SCRIPT_DIR/install-hooks.sh"
  if [[ -f "$SCRIPT_DIR/install-hooks.sh" ]]; then
    source "$SCRIPT_DIR/install-hooks.sh"
    if has_legacy_hooks; then
      remove_legacy_hooks || true
    else
      remove_legacy_hooks 2>/dev/null || true
    fi
  fi
  echo UPGRADED
}
cmd_upgrade
`;

describe('upgrade bridge (install-hooks.sh)', () => {
  let root, checkout, install, home;
  before(() => {
    root = mkdtempSync(join(os.tmpdir(), 'vdm-upgrade-'));
    checkout = join(root, 'checkout');
    install = join(root, 'install');
    home = join(root, 'home');
    for (const d of [checkout, install, home]) mkdirSync(d, { recursive: true });
    for (const f of ['vdm', 'dashboard.mjs', 'lib.mjs', 'history.mjs', 'install-hooks.sh']) copyFileSync(join(REPO, f), join(checkout, f));
    writeFileSync(join(install, 'config.json'), '{}');
  });
  after(() => rmSync(root, { recursive: true, force: true }));

  it('an old upgrade also lands history.mjs, and still finishes', () => {
    const out = execFileSync('/bin/bash', ['-c', OLD_UPGRADE], { env: { PATH: process.env.PATH, HOME: home, INSTALL: install, CHECKOUT: checkout }, encoding: 'utf8' });
    assert.match(out, /UPGRADED/);
    assert.ok(existsSync(join(install, 'history.mjs')), 'history.mjs copied');
    assert.equal(readFileSync(join(install, 'history.mjs'), 'utf8'), readFileSync(join(REPO, 'history.mjs'), 'utf8'));
    assert.ok(!existsSync(join(install, '.history.mjs.new')), 'no temp file left');
  });

  it('finishes an old upgrade itself and exits before bash reads the overwritten vdm', () => {
    const inst = join(root, 'install2');
    mkdirSync(inst);
    const script = OLD_UPGRADE
      .replace('SCRIPT_DIR="$INSTALL"', 'SCRIPT_DIR="$INSTALL"\ncmd_dashboard() { echo "DASHBOARD $1"; }\nlog_activity() { echo "LOG $*"; }')
      .replace('  local tmpdir', '  local tmpdir current_hash=v4 latest_hash=v5 dashboard_was_running=true');
    const out = execFileSync('/bin/bash', ['-c', script + '\necho AFTER-THE-FUNCTION'], { env: { PATH: process.env.PATH, HOME: home, INSTALL: inst, CHECKOUT: checkout }, encoding: 'utf8' });
    assert.ok(existsSync(join(inst, 'history.mjs')));
    assert.match(out, /DASHBOARD start/);
    assert.match(out, /Upgraded/);
    assert.match(out, /LOG upgrade/);
    assert.doesNotMatch(out, /UPGRADED|AFTER-THE-FUNCTION/); // exited inside the bridge
  });

  it('copies nothing when sourced outside an upgrade', () => {
    const other = join(root, 'other');
    mkdirSync(other);
    execFileSync('/bin/bash', ['-c', 'set -euo pipefail; SCRIPT_DIR="$INSTALL"; tmpdir="$CHECKOUT"; source "$CHECKOUT/install-hooks.sh"; echo OK'],
      { env: { PATH: process.env.PATH, HOME: home, INSTALL: other, CHECKOUT: checkout }, encoding: 'utf8' });
    assert.ok(!existsSync(join(other, 'history.mjs')));
  });
});
