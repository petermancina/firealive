#!/usr/bin/env node
'use strict';

// check-no-legacy-2fa.js -- gate: the legacy TOTP/2FA feature stays removed.
//
// The TOTP two-factor feature (R3f) is removed platform-wide in B6i. Login is
// FIDO2 hardware-key + PIN only; the only MFA is a hardware passkey
// (webauthn_credentials + mfa-stepup + routes/mfa.js). This gate prevents the
// dead columns, the TOTP / MFA-config endpoints, and any TOTP login branch
// from creeping back. It asserts on schema-column and route DEFINITIONS (not
// bare strings) so it does not false-positive on comments or forbidden-route
// lists.
//
// B6i-1 asserts the Regional server. B6i-2 extends this with the GD server
// (mfa_secret / mfa_enabled / password_hash columns; /api/auth/mfa-* routes).

const fs = require('fs');
const path = require('path');

const REPO = path.resolve(__dirname, '..');
const problems = [];
const check = (name, cond) => { if (!cond) problems.push(name); };
const read = (rel) => { try { return fs.readFileSync(path.join(REPO, rel), 'utf8'); } catch (e) { return ''; } };

// Extract a "CREATE TABLE [IF NOT EXISTS] <name> ( ... );" body so column
// assertions target only that table's definition.
function createBody(src, table) {
  const re = new RegExp('CREATE TABLE\\s+(?:IF NOT EXISTS\\s+)?"?' + table + '"?\\s*\\(([\\s\\S]*?)\\n\\s*\\);');
  const m = src.match(re);
  return m ? m[1] : null;
}

// ---- Regional server: no dead totp_* columns ----
const init = read('server/db/init.js');
const regUsers = createBody(init, 'users');
check('regional users CREATE TABLE found', regUsers !== null);
check('regional users has no totp_ column', regUsers !== null && !/\btotp_\w+\s+(TEXT|INTEGER|BLOB)/i.test(regUsers));
check('regional init.js has no totp_ addCol()', !/addCol\(\s*['"]totp_/.test(init));
check('regional init.js has no "ADD COLUMN totp_"', !/ADD COLUMN\s+totp_/i.test(init));

// ---- Regional server: no TOTP / MFA-config route definitions ----
let mfaRouteDef = '';
for (const f of fs.readdirSync(path.join(REPO, 'server/routes')).filter((n) => n.endsWith('.js'))) {
  const src = read('server/routes/' + f);
  if (/router\.(get|post|put|delete)\(\s*['"]\/mfa\/totp\//.test(src)) mfaRouteDef = f + ' -> /mfa/totp';
  if (/router\.(get|post|put|delete)\(\s*['"]\/mfa\/config\b/.test(src)) mfaRouteDef = f + ' -> /mfa/config';
}
check('regional defines no /mfa/totp or /mfa/config route', mfaRouteDef === '');

// ---- Regional server: login route carries no TOTP branch ----
check('regional auth.js has no TOTP', !/totp/i.test(read('server/routes/auth.js')));

// ---- Positive: the strong MFA stack is present ----
check('webauthn_credentials table present', createBody(init, 'webauthn_credentials') !== null);
check('mfa-stepup middleware present', read('server/middleware/mfa-stepup.js').length > 0);
check('mfa passkey/cert self-service route present', read('server/routes/mfa.js').length > 0);

// ---- Report ----
if (problems.length) {
  console.error('check-no-legacy-2fa: FAILED (' + problems.length + ')');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log('check-no-legacy-2fa passed: legacy TOTP/2FA stays removed on the Regional server; the FIDO2 passkey stack (webauthn_credentials + mfa-stepup + routes/mfa.js) is present.');
process.exit(0);
