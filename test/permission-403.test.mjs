/**
 * A 403 must move to another account, not keep hammering the same one.
 *
 * Measured on a real account (an account whose org has OAuth disabled, 27/08/2026): Anthropic
 * answers `403 permission_error / oauth_not_allowed_for_organization` for an
 * organization that has OAuth turned off. That is a permanent property of the
 * account, not a transient failure — the token is valid, the subscription is
 * live, and the health probe reports nothing unusual because it never gets a
 * rate-limit header to disagree with.
 *
 * The proxy had branches for 429, 401 and 400, but not for 403, so the request
 * fell through to "return whatever upstream said". Three consecutive requests
 * chose the same account and got the same 403, while two perfectly healthy
 * accounts sat idle: verified by sending the same body to all four tokens
 * directly, which returned 200 / 403 / 200 / 429.
 *
 * Worse than the failed request: `spread` picks the *least used* account, and an
 * account that can never serve traffic stays at 0% forever, so it is picked
 * first every single time. One unusable account starves the whole rotation.
 *
 * This exercises the real branch lifted out of dashboard.mjs, so it fails
 * against the old code instead of against a re-implementation of it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
// Normalised to LF: a CRLF checkout would break the source slicing below.
const src = readFileSync(join(here, '..', 'dashboard.mjs'), 'utf8').replace(/\r\n/g, '\n');

test('the proxy has a 403 branch at all', () => {
  assert.ok(/if \(status === 403\)/.test(src),
    'no `status === 403` branch: a permission error will be returned to the client ' +
    'while other healthy accounts sit idle');
});

test('the 403 branch is classified as permanent, not retried on the same account', () => {
  const at = src.indexOf('if (status === 403)');
  assert.ok(at > 0, '403 branch missing');
  const branch = src.slice(at, at + 2500);

  // It must remember the account as unusable...
  assert.ok(/markAccountPermissionBlocked/.test(branch),
    'the 403 branch must record the account as blocked, or the next request picks it again');
  // ...and move on rather than replaying the same token.
  assert.ok(/pickBestAccount|balanceSwitch|pickAnyUntried/.test(branch),
    'the 403 branch must select a different account');
  assert.ok(/continue;/.test(branch),
    'the 403 branch must retry the request on the new account');
});

test('a permission block is not treated as a rate limit', () => {
  const at = src.indexOf('if (status === 403)');
  const branch = src.slice(at, at + 2500);
  // A rate limit expires; "OAuth not allowed for this organization" does not.
  // Filing it under the 429 machinery would clear it on the next window rollover
  // and put the account straight back into rotation.
  assert.ok(!/markAccountLimited\(/.test(branch),
    'a permission error must not go through markAccountLimited: a normal rate-limit ' +
    'cooldown expires quickly and would put the unusable account straight back into ' +
    'rotation, so it gets its own longer-lived marker');
});

test('the block is scoped so a shared 403 cannot lock everyone out', () => {
  const at = src.indexOf('if (status === 403)');
  const branch = src.slice(at, at + 2500);
  // If every account answers 403 the cause is the request, not the accounts.
  // Returning the upstream response then is correct; silently blocking all of
  // them would take the whole tool down until a restart.
  assert.ok(/no other account|all accounts|exhaust|passthrough/i.test(branch),
    'the 403 branch must handle "every account refused" by surfacing the error, ' +
    'not by marking every account dead');
});
