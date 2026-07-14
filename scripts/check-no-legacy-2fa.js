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
// Covers both servers: the Regional (totp_* columns; /mfa/totp + /mfa/config
// routes) and the GD (mfa_secret / mfa_enabled / password_hash columns;
// /api/auth/mfa-setup|confirm|verify routes).

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

// ---- GD server: no dead legacy-auth columns ----
const gdInit = read('packages/global-dashboard-server/db-init.js');
const gdUsers = createBody(gdInit, 'users');
check('GD users CREATE TABLE found', gdUsers !== null);
check('GD users has no mfa_secret / mfa_enabled / password_hash', gdUsers !== null && !/\b(mfa_secret|mfa_enabled|password_hash)\b/.test(gdUsers));

// ---- GD server: no legacy /api/auth/mfa-* (TOTP) route definitions ----
// (The /api/mfa/* passkey + cert routes are the canonical stack -- keep them.
//  Only the dash-form /api/auth/mfa-setup|confirm|verify are the dead TOTP
//  endpoints.) The GD defines its auth routes in index.js via app.METHOD.
let gdMfaRoute = '';
const gdSources = [['index.js', read('packages/global-dashboard-server/index.js')]];
try {
  for (const f of fs.readdirSync(path.join(REPO, 'packages/global-dashboard-server/routes')).filter((n) => n.endsWith('.js'))) {
    gdSources.push([f, read('packages/global-dashboard-server/routes/' + f)]);
  }
} catch (e) { /* routes dir optional */ }
for (const pair of gdSources) {
  if (/(app|router)\.(get|post|put|delete)\(\s*['"][^'"]*\/auth\/mfa-(setup|confirm|verify)/.test(pair[1])) gdMfaRoute = pair[0];
}
check('GD defines no /api/auth/mfa-setup|confirm|verify route', gdMfaRoute === '');

// ---- Positive: the GD passkey store is present ----
check('GD webauthn_credentials table present', createBody(gdInit, 'webauthn_credentials') !== null);

// ---- Report ----
if (problems.length) {
  console.error('check-no-legacy-2fa: FAILED (' + problems.length + ')');
  for (const p of problems) console.error('  - ' + p);
  process.exit(1);
}
console.log('check-no-legacy-2fa passed: legacy TOTP/2FA stays removed on both the Regional and GD servers; the FIDO2 passkey stack is present on each.');
process.exit(0);
