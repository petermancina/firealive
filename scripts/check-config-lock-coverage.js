#!/usr/bin/env node
//
// FIREALIVE -- Config-Lock Coverage Guard (CI)  [B6j-2, both-server v2]
//
// The config lock is only as strong as the registry it gates from, so this guard
// fails the build if either server's config-write registry has drifted from the
// code. It replaces the MC-only v1 (which scanned a hardcoded list of mixed
// routers under ROOT/server only) with a both-server enumerator that walks EVERY
// mount in each server's index.js, attributes routes to the exact router variable
// mounted (so a `.accessRouter` sub-export is not conflated with its parent), and
// resolves each mutating endpoint to its full mounted path.
//
// Two coverage models, by necessity:
//
//   * GD  -- STRICT. The Global Dashboard is the CISO's machine and its mutating
//     surface is small, so every mutating endpoint MUST be gated or listed in
//     GD_OPERATIONAL_ALLOWLIST (each entry carrying a one-line reason). Airtight:
//     a new GD config-write of ANY shape that is not registered fails the build.
//
//   * MC  -- SHAPED. The Regional Server has ~200 open operational endpoints, so a
//     strict allow-list is impractical. Instead every config-write-SHAPED mutating
//     endpoint (a PUT .../config, a /signing-keys/... trust write, or a
//     /fido-roots|/fido-aaguids anchor write) MUST be gated or listed in
//     MC_SHAPE_ALLOWLIST. Closes the v1 holes: it now scans ALL mounts (not a
//     hardcoded list) and recognises trust-write shapes (not just PUT .../config).
//
// Plus, for BOTH servers:
//   * NO-STALE -- every CONFIG_WRITE_PATHS entry and CONFIG_WRITE_MOUNTS prefix
//     corresponds to a real route (catches a removed/renamed route or a typo).
//   * WIRING   -- registered config paths actually sit behind the chokepoint.
//     GD applies one broad `app.use('/api', configLockChokepoint())`; every GD
//     mount that serves a config path must be mounted AFTER it. MC applies the
//     chokepoint per mount; every registered MC mount / feature router / the HA
//     config router must carry configLockChokepoint().
//
// Run:  node scripts/check-config-lock-coverage.js
// Exits non-zero (failing CI) with a list of problems, or 0 when consistent.
//
// AGPL-3.0-or-later
//

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const MUT = ['POST', 'PUT', 'PATCH', 'DELETE'];
const failures = [];
const fail = (m) => failures.push(m);

// ---------------------------------------------------------------------------
// Enumerator: parse a server's index.js for app.use('/api...', ..., router)
// mounts, attribute each route to the exact variable mounted, resolve full paths.
// ---------------------------------------------------------------------------
function mainExportVar(src) {
  const m = src.match(/module\.exports\s*=\s*(\w+)\s*;/);
  return m ? m[1] : 'router';
}

// Map an export PROPERTY name to the internal variable the routes are attached
// to. A file may do `const router = Router(); module.exports = { configRouter:
// router }` -- the mount says `.configRouter` but the routes live on `router`.
// Handles both `module.exports = { PROP: VAR, ... }` and `X.PROP = VAR`.
function exportPropMap(src) {
  const map = {};
  const obj = src.match(/module\.exports\s*=\s*\{([\s\S]*?)\}/);
  if (obj) {
    const re = /(\w+)\s*:\s*(\w+)/g;
    let m;
    while ((m = re.exec(obj[1])) !== null) map[m[1]] = m[2];
  }
  const asg = /(?:module\.exports|\w+)\.(\w+)\s*=\s*(\w+)\s*;/g;
  let a;
  while ((a = asg.exec(src)) !== null) map[a[1]] = a[2];
  return map;
}

// Resolve `const NAME = require('./routes/FILE')` aliases so a property mount
// like `ha.configRouter` maps back to its file + the sub-router variable.
function aliasMap(indexSrc) {
  const map = {};
  const re = /const\s+(\w+)\s*=\s*require\(\s*'(\.\/routes\/[^']+)'\s*\)\s*;/g;
  let m;
  while ((m = re.exec(indexSrc)) !== null) map[m[1]] = m[2];
  return map;
}

function enumerateServer(cfg) {
  const indexSrc = fs.readFileSync(path.join(cfg.dir, 'index.js'), 'utf8');
  const indexLines = indexSrc.split('\n');
  const alias = aliasMap(indexSrc);
  const rows = [];

  // Two mount forms:
  //   A) app.use('/api...', ..., require('./routes/X')[.prop])
  //   B) app.use('/api...', ..., ALIAS.prop)   (ALIAS = require('./routes/X'))
  const reReq = /app\.use\(\s*'(\/api[^']*)'\s*,[^\n]*require\(\s*'(\.\/routes\/[^']+)'\s*\)(?:\.(\w+))?/;
  const reAlias = /app\.use\(\s*'(\/api[^']*)'\s*,[^\n]*?(\w+)\.(\w+)\s*\)\s*;/;

  indexLines.forEach((line, i) => {
    let prefix, file, prop;
    let m = line.match(reReq);
    if (m) {
      prefix = m[1]; file = m[2]; prop = m[3] || null;
    } else {
      m = line.match(reAlias);
      if (!m) return;
      if (!alias[m[2]]) return; // not a routes alias (some other middleware)
      prefix = m[1]; file = alias[m[2]]; prop = m[3];
    }
    const fp = path.join(cfg.dir, file + (file.endsWith('.js') ? '' : '.js'));
    if (!fs.existsSync(fp)) return;
    const src = fs.readFileSync(fp, 'utf8');
    // Resolve the mounted property (.configRouter) to the internal variable the
    // routes are actually attached to; fall back to the property / main export.
    const routerVar = prop ? (exportPropMap(src)[prop] || prop) : mainExportVar(src);
    src.split('\n').forEach((rl) => {
      const rm = rl.match(/(\w+)\.(get|post|put|patch|delete)\(\s*'([^']*)'/);
      if (!rm) return;
      if (rm[1] !== routerVar) return; // attribute only to the mounted variable
      const method = rm[2].toUpperCase();
      if (!MUT.includes(method)) return;
      const sub = rm[3] === '/' ? '' : rm[3];
      const full = prefix + sub;
      rows.push({ method, full, file, prefix, mountLine: i + 1 });
    });
  });

  // Inline handlers defined directly on the app in index.js (not in a mounted
  // route file): app.METHOD('/api/...'). The mount prefix IS the full path.
  // These flow through the broad chokepoint on the GD and would otherwise be
  // invisible to the coverage check.
  indexLines.forEach((line, i) => {
    const im = line.match(/\bapp\.(get|post|put|patch|delete)\(\s*'(\/api[^']*)'/);
    if (!im) return;
    const method = im[1].toUpperCase();
    if (!MUT.includes(method)) return;
    rows.push({ method, full: im[2], file: 'index.js', prefix: im[2], mountLine: i + 1 });
  });

  // Deduplicate on method+full (a file mounted at >1 prefix, or repeated).
  const uniq = [...new Map(rows.map((r) => [r.method + ' ' + r.full, r])).values()];
  for (const r of uniq) r.gated = cfg.isFn(r.method, r.full);
  return { rows: uniq, indexLines };
}

// A config-write SHAPE: a PUT .../config, a /signing-keys/... trust-root write,
// or a /fido-roots|/fido-aaguids attestation-anchor write.
function looksConfigShape(method, full) {
  if (!MUT.includes(method)) return false;
  if (method === 'PUT' && /\/config$/.test(full)) return true;
  if (/\/signing-keys?(\/|$)/.test(full)) return true;
  if (/\/fido-roots(\/|$)|\/fido-aaguids(\/|$)/.test(full)) return true;
  return false;
}

// ---------------------------------------------------------------------------
// Allow-lists (each entry a deliberate decision, not a suppression).
// ---------------------------------------------------------------------------

// GD STRICT: every GD mutating endpoint must be gated or listed here. Each entry
// is a deliberate "operational, safe while the config is locked" decision -- none
// writes platform config. Grouped: backup/restore/lock control, HA data plane,
// auth/MFA credential lifecycle, inbound MC ingest, operational actions.
const GD_OPERATIONAL_ALLOWLIST = new Map([
  ['POST /api/backup', 'operational: triggers a backup run (no config change)'],
  ['POST /api/backup/:id/verify', 'operational: verifies a stored backup'],
  ['POST /api/backup/chain/verify', 'operational: verifies the backup chain'],
  ['POST /api/cloud-vuln-access', 'inbound announce sub-router (no auth mw); not a config write'],
  ['POST /api/cloud/package', 'operational: builds a cloud deployment package'],
  ['POST /api/config/lock', 'lock control: must work while locked (CONFIG_LOCK_EXEMPT)'],
  ['POST /api/config/lock/unlock-options', 'lock control: unlock recovery path'],
  ['POST /api/instance/anchor-challenge', 'inbound MC identity handshake (no config change)'],
  ['POST /api/restore-approvals', 'restore approval workflow (own two-person control)'],
  ['POST /api/restore-approvals/:id/approve', 'restore approval workflow'],
  ['POST /api/restore-approvals/:id/deny', 'restore approval workflow'],
  ['POST /api/restore/execute-chain/:id', 'internal restore: gated by approval + passkey step-up'],
  ['POST /api/restore/execute/:id', 'internal restore: gated by approval + passkey step-up'],
  // B6k. Taking a pre-upgrade restore point writes a backup and changes no
  // configuration, so it must stay usable while the lock is engaged: requiring
  // an unlock in order to protect the deployment before an upgrade would be
  // backwards, and the moment before an upgrade is when a GD should be at its
  // most locked down. The gates live on CONSUMING the artifact -- an
  // anchor-signed, single-use, one-version-deep authorization checked by an
  // offline tool with the server stopped -- not on producing it.
  ['POST /api/restore-points', 'operational: takes a pre-upgrade restore point (a backup; no config change)'],
  ['POST /api/self-protection/integration-health/run', 'operational: runs an integration health probe'],
  // HA peer data plane (pinned mTLS, mounted OUTSIDE the config-lock): runtime
  // replication/heartbeat/lease + inbound pairing handshake steps. Must keep
  // working while locked; new pairing is blocked at the admin-initiated side.
  ['POST /api/ha/peer/replicate', 'inbound peer data-plane (mTLS): active->standby replication, runs while locked'],
  ['POST /api/ha/peer/heartbeat', 'inbound peer data-plane (mTLS): liveness heartbeat'],
  ['POST /api/ha/peer/lease', 'inbound peer data-plane (mTLS): failover lease renewal'],
  ['POST /api/ha/peer/pair-secret', 'inbound peer handshake (mTLS): only reachable during admin-initiated pairing (gated)'],
  ['POST /api/ha/peer/pair-baseline', 'inbound peer handshake (mTLS): only reachable during admin-initiated pairing (gated)'],
  ['POST /api/ha/peer/unpair', 'inbound peer-initiated unpair (mTLS), not an operator config change'],
  ['POST /api/ha/pair-init', 'inbound joining-node pair-init (token-authed), mounted outside the config-lock'],
  ['POST /api/ha/self-test', 'operational: runs an HA self-test diagnostic, no config change'],
  // Inline app.METHOD handlers in index.js. Auth / MFA credential lifecycle:
  // login + step-up must work while locked (you authenticate to unlock);
  // enrollment + revoke are governed by auth step-up, not the config-lock (their
  // config-lock treatment is deferred to O3 machine-credential hardening).
  ['POST /api/auth/login-webauthn/options', 'auth: passkey login challenge; must work while locked'],
  ['POST /api/auth/login-webauthn/verify', 'auth: passkey login; must work while locked'],
  ['POST /api/auth/device-key/challenge', 'auth: device-key login challenge'],
  ['POST /api/auth/device-key', 'auth: device-key login'],
  ['POST /api/auth/enroll/cert', 'auth credential lifecycle (enroll); governed by auth step-up, not the config-lock (O3)'],
  ['POST /api/auth/enroll/passkey/options', 'auth credential lifecycle (enroll); governed by auth step-up (O3)'],
  ['POST /api/auth/enroll/passkey/verify', 'auth credential lifecycle (enroll); governed by auth step-up (O3)'],
  ['POST /api/mfa/stepup/options', 'auth: MFA step-up challenge; must work while locked (unlock needs it)'],
  ['POST /api/mfa/passkey/register-options', 'auth credential lifecycle (enroll); governed by auth step-up (O3)'],
  ['POST /api/mfa/passkey/register-verify', 'auth credential lifecycle (enroll); governed by auth step-up (O3)'],
  ['DELETE /api/mfa/passkeys/:id', 'auth credential lifecycle (revoke a compromised key); governed by auth step-up (O3)'],
  ['POST /api/mfa/certs/revoke', 'auth credential lifecycle (revoke); governed by auth step-up (O3)'],
  // Inbound MC data plane (the GD receives MC telemetry/handshakes and must keep
  // ingesting while locked); not operator config changes.
  ['POST /api/ingest/metrics', 'inbound: MC metrics ingest, runs while locked'],
  ['POST /api/ingest/compliance-reports', 'inbound: MC compliance-report ingest'],
  ['POST /api/ingest/leaderboard', 'inbound: MC leaderboard ingest'],
  ['POST /api/mc/:id/full-report-requests', 'inbound: an MC queues a full-report request'],
  ['POST /api/mc/me/signing-key-status', 'inbound: an MC reports its own signing-key status'],
  ['POST /api/mc/me/pending-requests', 'inbound: an MC polls its pending requests'],
  // Operational actions (run/generate/trigger/manage) -- no platform-config write.
  ['PUT /api/notifications/:id/acknowledge', 'operational: acknowledge a single notification'],
  ['POST /api/auto-update/check-now', 'operational: trigger an update check (the schedule config PUT /api/auto-update/config is gated)'],
  ['POST /api/reports/generate', 'operational: generate a report on demand'],
  ['POST /api/compromise-scan', 'operational: run a compromise scan'],
  ['POST /api/regression-test', 'operational: run the regression self-test'],
  ['POST /api/cicd/generate', 'operational: generate CI/CD artifacts (the secret rotate is gated separately)'],
  ['POST /api/cicd/runs', 'operational: record a CI/CD run'],
  ['POST /api/backup/full-suite', 'operational: triggers a full-suite backup run'],
  ['POST /api/troubleshoot', 'operational: run diagnostics'],
  ['POST /api/gd/query', 'operational: internal read-only query (substring filter)'],
  ['POST /api/forensic-exports', 'operational: create a forensic export (evidence gathering)'],
  ['DELETE /api/forensic-exports/:id', 'operational: manage forensic exports'],
]);

// MC SHAPED: config-write-shaped endpoints that are genuinely operational (no
// security/trust dimension), so they are intentionally NOT frozen while locked.
const MC_SHAPE_ALLOWLIST = new Map([
  ['PUT /api/sla/config', 'operational: P1/P2 MTTA/MTTR metric targets, no trust/secret surface'],
  ['PUT /api/helper-pay/config', 'operational: workforce pay-differential policy, no trust/secret surface'],
]);

// ---------------------------------------------------------------------------
// Server configs.
// ---------------------------------------------------------------------------
const GD_DIR = path.join(ROOT, 'packages', 'global-dashboard-server');
const MC_DIR = path.join(ROOT, 'server');

const gdReg = require(path.join(GD_DIR, 'services', 'gd-config-write-routes.js'));
const mcReg = require(path.join(MC_DIR, 'middleware', 'config-write-routes.js'));

// The MC feature routers (bare /api mounts) checked for chokepoint wiring, and
// the HA property mount, mirror the v1 guard's MC-specific wiring checks.
const MC_FEATURE_IDS = ['021', '022', '023', '024', '025', '027', '030'];

// ===========================================================================
// GD -- STRICT coverage
// ===========================================================================
{
  const { rows, indexLines } = enumerateServer({
    dir: GD_DIR,
    isFn: gdReg.isGdConfigWriteRequest,
  });

  for (const r of rows) {
    if (r.gated) continue;
    const key = r.method + ' ' + r.full;
    if (GD_OPERATIONAL_ALLOWLIST.has(key)) continue;
    fail(
      `[GD] mutating endpoint neither gated nor allow-listed: ${key} ` +
        `(${path.relative(ROOT, path.join(GD_DIR, r.file))}) -- register it in ` +
        'gd-config-write-routes.js or add a reasoned GD_OPERATIONAL_ALLOWLIST entry'
    );
  }

  // NO-STALE: every registered GD path corresponds to a real enumerated route.
  const seen = new Set(rows.map((r) => r.method + ' ' + r.full));
  for (const e of gdReg.CONFIG_WRITE_PATHS) {
    if (!seen.has(e.method + ' ' + e.path)) {
      fail(`[GD] stale registry path (no matching route): ${e.method} ${e.path}`);
    }
  }

  // WIRING: the single broad chokepoint mount exists, and every GD mount that
  // serves a config path sits AFTER it (so the chokepoint actually fronts it).
  const ckLine = indexLines.findIndex(
    (l) => l.includes("app.use('/api'") && l.includes('configLockChokepoint()')
  );
  if (ckLine < 0) {
    fail("[GD] broad chokepoint mount missing: app.use('/api', configLockChokepoint())");
  } else {
    for (const r of rows) {
      if (r.gated && r.mountLine < ckLine + 1) {
        fail(
          `[GD] config route mounted BEFORE the chokepoint (line ${r.mountLine} < ` +
            `${ckLine + 1}): ${r.method} ${r.full} -- move its mount after the chokepoint`
        );
      }
    }
  }
}

// ===========================================================================
// MC -- SHAPED coverage
// ===========================================================================
{
  const { rows, indexLines } = enumerateServer({
    dir: MC_DIR,
    isFn: mcReg.isConfigWriteRequest,
  });

  for (const r of rows) {
    if (r.gated) continue;
    if (!looksConfigShape(r.method, r.full)) continue;
    const key = r.method + ' ' + r.full;
    if (MC_SHAPE_ALLOWLIST.has(key)) continue;
    fail(
      `[MC] config-write-shaped endpoint not gated: ${key} ` +
        `(${path.relative(ROOT, path.join(MC_DIR, r.file))}) -- gate it (add ` +
        'configLockChokepoint() to its mount + register the path) or, if truly ' +
        'operational, add a reasoned MC_SHAPE_ALLOWLIST entry'
    );
  }

  // NO-STALE.
  const seen = new Set(rows.map((r) => r.method + ' ' + r.full));
  for (const e of mcReg.CONFIG_WRITE_PATHS) {
    if (!seen.has(e.method + ' ' + e.path)) {
      fail(`[MC] stale registry path (no matching route): ${e.method} ${e.path}`);
    }
  }

  // WIRING: registered mounts + feature routers + HA property mount carry the
  // chokepoint (per-mount model).
  for (const mount of mcReg.CONFIG_WRITE_MOUNTS) {
    const line = indexLines.find((l) => l.includes(`'${mount}'`) && l.includes('app.use('));
    if (!line) fail(`[MC] config mount not found in index.js: ${mount}`);
    else if (!line.includes('configLockChokepoint()'))
      fail(`[MC] config mount not gated by chokepoint: ${mount}`);
  }
  for (const n of MC_FEATURE_IDS) {
    const needle = `require('./routes/v${n}-features')`;
    const line = indexLines.find((l) => l.includes(needle));
    if (!line) fail(`[MC] feature router mount not found: v${n}-features`);
    else if (!line.includes('configLockChokepoint()'))
      fail(`[MC] feature router not gated by chokepoint: v${n}-features`);
  }
  const haMount = indexLines.find(
    (l) => l.includes('ha.configRouter') && l.includes('app.use(')
  );
  if (!haMount) fail('[MC] HA config router mount not found: ha.configRouter');
  else if (!haMount.includes('configLockChokepoint()'))
    fail('[MC] HA config router not gated by chokepoint: ha.configRouter');

  // WIRING (exact-path): every registered EXACT path in CONFIG_WRITE_PATHS is
  // served by a CHOKED mount, so a specifically-registered config write is gated
  // explicitly and never depends on middleware-order fallthrough to a bare-/api
  // feature-router chokepoint. This closes the earlier false-green where a
  // registered exact path whose serving mount was unchoked shipped ungated (B6j
  // found reports/config + notifications/config this way). Mount-gated OPERATIONAL
  // sub-routes under a config mount -- e.g. /api/audit/event, registered before the
  // choked /api/audit mount so audit logging still works while locked -- are not in
  // CONFIG_WRITE_PATHS and are intentionally bypassed, so they are not checked here;
  // the config MOUNTS themselves are verified above. MC-only (the GD uses one broad
  // chokepoint, checked in the GD block).
  const rowByKey = new Map(rows.map((r) => [r.method + ' ' + r.full, r]));
  for (const e of mcReg.CONFIG_WRITE_PATHS) {
    const r = rowByKey.get(e.method + ' ' + e.path);
    if (!r) continue; // no matching route -- flagged by NO-STALE above
    const mountText = indexLines[r.mountLine - 1] || '';
    if (!mountText.includes('configLockChokepoint()')) {
      fail(
        `[MC] registered config path served by an UNCHOKED mount (line ${r.mountLine}): ` +
          `${e.method} ${e.path} -- add configLockChokepoint() to its serving mount`
      );
    }
  }
}

// ===========================================================================
if (failures.length > 0) {
  console.error('Config-lock coverage guard FAILED:');
  for (const f of failures) console.error('  - ' + f);
  console.error(
    `\n${failures.length} problem(s). The config lock must gate every config ` +
      'write on both the Regional Server and the Global Dashboard.'
  );
  process.exit(1);
}

console.log(
  'Config-lock coverage guard passed (both servers): GD strict + MC shaped ' +
    'coverage, registry, and wiring consistent.'
);
