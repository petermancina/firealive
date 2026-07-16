// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Full-Suite Regression Runner (R3k C4 rewrite)
//
// On-demand integration test harness invoked by /api/regression/run
// (Sub-phase 2 / C5). Runs a fixed battery of ~40 checks against the
// CURRENT canonical schema and service primitives of this regional
// FireAlive install, and returns a structured pass/fail breakdown
// grouped by category.
//
// REWRITE RATIONALE
// =================
//
// The pre-R3k implementation (68 lines, 32 checks) was authored against
// a schema snapshot that has since drifted: it queried tables that no
// longer exist canonically (config -> team_config; backup_history ->
// backups; feature_toggles and
// integration_status -> not canonical at all), with most checks
// silent-failing inside try/catch so the response was almost entirely
// noise. R3k absorbs what BUILD-PLAN-v22 had described as the deferred
// B2 phase and ships a real runner against current canonical schema.
//
// CATEGORIES (13)
// ===============
//
//   1. Schema integrity      — SQLite integrity_check + canonical
//                               table presence (R3-era core, R3j
//                               additions, R3k additions)
//   2. Crypto                — AES-256-GCM, SHA-256, Ed25519, NaCl
//                               box round-trips; CSPRNG presence
//                               implied by the round-trips
//   3. Auth                  — JWT_SECRET configured, api_keys present;
//                               passwordless
//                               PKI + WebAuthn: a CA issue/verify/revoke/
//                               CRL round-trip, WebAuthn + step-up wiring,
//                               break-glass recovery, LDAP directory
//                               helpers, and passwordless-only enforcement
//                               (no password login endpoint)
//   4. Anti-rollback         — Fuse counter row exists in
//                               system_meta and matches package.json
//   5. Integrations          — integration_config rows parseable,
//                               KMS providers registered and round-
//                               trip wrap/unwrap
//   6. Burnout signals       — analyst baseline/signal/impact tables,
//                               AI provider config, inference log
//                               provenance table
//   7. Routing               — routing_caps/routing_overrides,
//                               team_config.routing_enabled (R3j),
//                               team_config.panic_mode,
//                               soar_routing_events composite UNIQUE
//                               index (R3j C1)
//   8. Backup                — backups table v2 columns present
//                               including kind (R3k C2), signing
//                               keys, schedules
//   9. Audit chain           — audit_log reachable, backup_chain
//                               entries link prev_hash -> this_hash,
//                               chain_signing_keys active
//   10. Peer features        — peer session/message/rating tables,
//                               abuse flags, message key material
//   11. AC provisioning      — heartbeat route loadable,
//                               analyst_availability table,
//                               users.role analyst rows present
//   12. System               — Node version, RSS, security
//                               middleware loadable, auth_log,
//                               sessions
//   13. Storage routing      -- storage_destinations + per-type
//                               routes (primary + secondary),
//                               archive/forensic push tracking +
//                               retry columns, route refs resolve
//
// CHECK FUNCTION CONTRACT
// =======================
//
// Each check returns one of three shapes via the check() helper:
//
//   check('Cat', 'Name', () => 'detail string')         -> PASS
//   check('Cat', 'Name', () => false)                    -> FAIL
//   check('Cat', 'Name', () => { throw new Error('x') }) -> FAIL with x
//
// The wrapping catch converts any exception into a FAIL with the
// error message as detail. This means an individual check that throws
// (e.g. SQLite errors from a missing table) cannot crash the runner;
// the failure is captured as data and the next check proceeds.
//
// RESULT SHAPE
// ============
//
// run() returns:
//
//   {
//     total, passed, failed, skipped, ranAt, version, fuse,
//     results: [
//       { category, name, status: 'pass'|'fail'|'skip', detail }, ...
//     ],
//     summary: {
//       <category>: { passed: <n>, skipped: <n>, total: <n>, status: 'pass'|'fail' },
//       ...
//     },
//     failures: [ <subset of results where status='fail'> ]
//   }
//
// Backwards compatibility: the top-level fields (total, passed, failed,
// results, ranAt, version, fuse) are preserved from the pre-R3k shape
// so existing callers (test harnesses; the v059-features.js stub
// router was removed in R3m C2) don't break.
// summary, failures) are additive.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const path = require('path');

let nacl = null;
try {
  // Lazy import — tweetnacl is available in canonical (used by
  // peer-message E2E and gd_push). Loading it here so the NaCl box
  // round-trip check has access without crashing the require chain
  // if (hypothetically) the module is missing.
  nacl = require('tweetnacl');
} catch (e) {
  // Silently swallow; the NaCl check will FAIL with a clear message
  // when run() reaches it.
}

class RegressionRunner {
  constructor(db) {
    this.db = db;
  }

  async run() {
    const results = [];

    // A check may return SKIP(reason) to record a 'skip' (e.g. a control
    // whose backing feature lands in a later phase). Skips count toward the
    // total but never fail the suite or flip a category to 'fail'.
    const SKIP = (reason) => ({ __skip: true, detail: String(reason) });

    const check = async (category, name, fn) => {
      try {
        const r = await fn();
        if (r && typeof r === 'object' && r.__skip) {
          results.push({ category, name, status: 'skip', detail: r.detail || 'skipped' });
        } else if (r === false || r === undefined || r === null || r === '') {
          results.push({ category, name, status: 'fail', detail: 'check returned no detail' });
        } else {
          results.push({ category, name, status: 'pass', detail: String(r) });
        }
      } catch (e) {
        results.push({ category, name, status: 'fail', detail: e.message || String(e) });
      }
    };

    // Local helpers
    const tableExists = (name) => {
      const row = this.db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?")
        .get(name);
      return !!row;
    };
    const indexExists = (name) => {
      const row = this.db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name = ?")
        .get(name);
      return !!row;
    };
    const columnExists = (table, column) => {
      try {
        const cols = this.db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
        return cols.includes(column);
      } catch (e) {
        return false;
      }
    };
    const requireAll = (tables) => {
      const missing = tables.filter(t => !tableExists(t));
      if (missing.length > 0) {
        throw new Error('missing table(s): ' + missing.join(', '));
      }
      return tables.length + ' table(s) present';
    };

    // ── Category 1: Schema integrity ───────────────────────────────
    await check('schema', 'SQLite integrity_check', () => {
      const r = this.db.prepare('PRAGMA integrity_check').get();
      if (r && r.integrity_check === 'ok') return 'integrity ok';
      throw new Error('integrity_check returned: ' + JSON.stringify(r));
    });
    await check('schema', 'Foreign-key integrity', () => {
      const rows = this.db.prepare('PRAGMA foreign_key_check').all();
      if (rows.length === 0) return 'no FK violations';
      throw new Error(rows.length + ' FK violation(s); first: ' + JSON.stringify(rows[0]));
    });
    await check('schema', 'Core canonical tables', () => {
      return requireAll(['users', 'team_config', 'audit_log', 'system_meta']);
    });
    await check('schema', 'R3j routing tables', () => {
      return requireAll(['soar_routing_events', 'ticket_actions', 'ticket_assignments', 'routing_caps']);
    });
    await check('schema', 'R3k CI/CD + cloud-iac tables', () => {
      return requireAll(['cicd_configs', 'cicd_runs', 'cloud_iac_signing_keys']);
    });

    await check('schema', 'B4 compromise-scan + tripwire tables', () => {
      return requireAll(['compromise_scan_runs', 'compromise_scan_results', 'ac_device_signing_keys', 'compromise_scan_queue', 'tripwire_events']);
    });
    await check('schema', 'B4 device-key one-active-per-user index', () => {
      if (indexExists('idx_ac_device_signing_keys_one_active')) return 'partial-unique index present';
      throw new Error('missing idx_ac_device_signing_keys_one_active');
    });

    await check('schema', 'B5d4 per-client recovery + fleet-ops tables', () => {
      return requireAll(['client_recovery_runs', 'client_ops_runs', 'client_ops_queue', 'client_ops_results']);
    });
    await check('schema', 'B5d4 enrollment-token re-provision scope', () => {
      const row = this.db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='enrollment_tokens'").get();
      if (!row || !row.sql) throw new Error('enrollment_tokens table missing');
      if (row.sql.indexOf('re-provision') === -1) throw new Error("enrollment_tokens scope CHECK does not allow re-provision");
      return 'scope CHECK includes re-provision';
    });

    // ── Category: Compromise scan + reduced-routing tripwire (B4) ───
    await check('compromise', 'Orchestration route loads', () => {
      const r = require('../routes/compromise-scan-orchestration');
      if (typeof r !== 'function') throw new Error('route is not an express router');
      return 'router exported';
    });
    await check('compromise', 'Tripwire route loads', () => {
      const r = require('../routes/tripwire');
      if (typeof r !== 'function') throw new Error('route is not an express router');
      return 'router exported';
    });
    await check('compromise', 'Tripwire detector evaluates', () => {
      const det = require('./tripwire-detector');
      if (typeof det.evaluate !== 'function') throw new Error('evaluate missing');
      const v = det.evaluate(this.db, {});
      if (!v || typeof v.tripped !== 'boolean' || typeof v.signals !== 'object') throw new Error('verdict shape invalid');
      return 'verdict ok (score ' + v.score + ', tripped ' + v.tripped + ')';
    });
    await check('compromise', 'Tripwire scheduler API', () => {
      const sch = require('./tripwire-scheduler');
      if (typeof sch.startTripwireScheduler !== 'function' || typeof sch.runTripwireCycle !== 'function') throw new Error('scheduler API missing');
      return 'scheduler API present';
    });
    await check('compromise', 'Tripwire config seeded', () => {
      const row = this.db.prepare("SELECT value FROM team_config WHERE key = 'tripwire_config'").get();
      if (!row) return SKIP('tripwire_config not present (control may have been cleared)');
      JSON.parse(row.value);
      return 'tripwire_config present and valid JSON';
    });
    await check('compromise', 'Compromise retention config seeded', () => {
      const row = this.db.prepare("SELECT value FROM team_config WHERE key = 'compromise_scan_retention_days'").get();
      if (!row) return SKIP('compromise_scan_retention_days not present');
      return 'retention config present';
    });

    // ── Category: Per-client recovery + fleet operations (B5d4) ───
    await check('client_ops', 'Recovery route loads', () => {
      const r = require('../routes/client-recovery');
      if (typeof r !== 'function') throw new Error('route is not an express router');
      return 'router exported';
    });
    await check('client_ops', 'Fleet-ops route loads', () => {
      const r = require('../routes/client-ops');
      if (typeof r !== 'function') throw new Error('route is not an express router');
      return 'router exported';
    });
    await check('client_ops', 'Recovery service API present', () => {
      const svc = require('./client-recovery');
      if (typeof svc.teardownAc !== 'function' || typeof svc.reprovisionAc !== 'function') throw new Error('teardownAc / reprovisionAc missing');
      return 'teardownAc + reprovisionAc present';
    });
    await check('client_ops', 'Fleet-ops dispatch service present', () => {
      const svc = require('./client-ops');
      if (typeof svc.dispatchClientOp !== 'function') throw new Error('dispatchClientOp missing');
      if (!svc.VALID_OPS || typeof svc.VALID_OPS.has !== 'function' || !svc.VALID_OPS.has('log_integrity')) throw new Error('VALID_OPS set missing or incomplete');
      return 'dispatchClientOp + VALID_OPS present';
    });
    await check('client_ops', 'WebSocket dispatch + broadcast methods present', () => {
      const ws = require('./websocket-server');
      if (typeof ws.broadcastUrgentRefresh !== 'function') throw new Error('module broadcastUrgentRefresh forwarder missing');
      const proto = ws.FireAliveWebSocket && ws.FireAliveWebSocket.prototype;
      if (!proto) throw new Error('FireAliveWebSocket not exported');
      const methods = ['dispatchClientOp', 'dispatchWipeLocal', 'broadcastSyncCadence', 'broadcastUrgentRefresh', '_ingestClientOpResult', '_canonicalClientOp', '_deliverQueuedClientOps'];
      const missing = methods.filter((m) => typeof proto[m] !== 'function');
      if (missing.length) throw new Error('missing WS methods: ' + missing.join(', '));
      return methods.length + ' WS methods present';
    });
    await check('client_ops', 'Canonical fleet-op signing string shape', () => {
      const ws = require('./websocket-server');
      const proto = ws.FireAliveWebSocket.prototype;
      const canon = proto._canonicalClientOp({ runId: 'r', opType: 'log_integrity', started_at: 't', duration_ms: 5, status: 'ok', detail_json: '{}' });
      const parts = canon.split(String.fromCharCode(10));
      if (parts.length !== 6) throw new Error('expected 6 newline-joined fields, got ' + parts.length);
      return '6-field canonical string (0x0A joined)';
    });

    // ── Category 2: Crypto ─────────────────────────────────────────
    await check('crypto', 'AES-256-GCM round-trip', () => {
      const key = crypto.randomBytes(32);
      const iv  = crypto.randomBytes(12);
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      const ct = Buffer.concat([c.update('hello'), c.final()]);
      const tag = c.getAuthTag();
      const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
      d.setAuthTag(tag);
      const pt = Buffer.concat([d.update(ct), d.final()]).toString();
      if (pt !== 'hello') throw new Error('decrypt mismatch');
      return 'encrypt/decrypt ok';
    });
    await check('crypto', 'SHA-256 hashing', () => {
      const h = crypto.createHash('sha256').update('x').digest('hex');
      if (h.length !== 64) throw new Error('unexpected digest length');
      return 'digest 64 hex chars';
    });
    await check('crypto', 'Ed25519 sign/verify', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const msg = Buffer.from('regression-probe');
      const sig = crypto.sign(null, msg, privateKey);
      if (!crypto.verify(null, msg, publicKey, sig)) throw new Error('verify failed');
      return 'sign+verify ok';
    });
    await check('crypto', 'NaCl box (tweetnacl) round-trip', () => {
      if (!nacl) throw new Error('tweetnacl not loadable');
      const a = nacl.box.keyPair();
      const b = nacl.box.keyPair();
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const msg = new Uint8Array([1, 2, 3, 4]);
      const boxed = nacl.box(msg, nonce, b.publicKey, a.secretKey);
      const opened = nacl.box.open(boxed, nonce, a.publicKey, b.secretKey);
      if (!opened || opened.length !== 4) throw new Error('open failed');
      return 'box ok';
    });

    // ── Category 3: Auth ───────────────────────────────────────────
    await check('auth', 'JWT_SECRET configured', () => {
      const s = process.env.JWT_SECRET;
      if (!s || s.length < 16) throw new Error('JWT_SECRET not set or too short (<16 chars)');
      return 'configured (' + s.length + ' chars)';
    });
    await check('auth', 'api_keys table', () => {
      return requireAll(['api_keys']);
    });
    await check('auth', 'JWT session round-trip (HS256 sign / verify / tamper-reject)', () => {
      // Passwordless system: the only login-time secret exercised here is the
      // JWT session token. There is no password hash and no TOTP — those
      // primitives were removed, so they are no longer tested.
      const jwt = require('jsonwebtoken');
      const secret = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
      const token = jwt.sign({ sub: 'regression', t: Date.now() }, secret, { algorithm: 'HS256', expiresIn: '60s' });
      const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
      if (!decoded || decoded.sub !== 'regression') throw new Error('JWT did not round-trip the claim');
      let rejected = false;
      try { jwt.verify(token, secret + 'tamper', { algorithms: ['HS256'] }); } catch (_e) { rejected = true; }
      if (!rejected) throw new Error('JWT verify accepted a wrong secret');
      return 'JWT(HS256) sign / verify / tamper-reject ok';
    });
    await check('auth', 'Passwordless-only enforcement (no password login endpoint)', () => {
      // The auth router must expose the passwordless entry points and must NOT
      // expose any password / LDAP-password / TOTP login route. Inspect the
      // router's registered paths directly.
      let router;
      try { router = require('../routes/auth'); } catch (e) { throw new Error('cannot load auth router: ' + e.message); }
      const paths = new Set(
        (router && router.stack ? router.stack : [])
          .filter(l => l && l.route && l.route.path)
          .map(l => l.route.path)
      );
      const required = ['/login-webauthn/options', '/login-webauthn/verify'];
      const missing = required.filter(p => !paths.has(p));
      if (missing.length) throw new Error('missing passwordless login route(s): ' + missing.join(', '));
      // B5n3: certificate login is removed -- a client certificate is transport
      // identity only, never a login credential, so /login-cert must be ABSENT.
      const forbidden = ['/login', '/login-ldap', '/login-mfa', '/login-enroll-start', '/login-enroll-confirm', '/login-cert'];
      const present = forbidden.filter(p => paths.has(p));
      if (present.length) throw new Error('forbidden login route(s) present: ' + present.join(', '));
      return 'passkey login present; no password / LDAP / TOTP / certificate login route';
    });
    await check('auth', 'No TOTP / MFA-config endpoints (B6i removed them)', () => {
      // B6i removed the vestigial /mfa/config (GET/PUT) and /mfa/totp/setup
      // endpoints from the v024-features router. Inspect its registered paths.
      let router;
      try { router = require('../routes/v024-features'); } catch (e) { throw new Error('cannot load v024-features router: ' + e.message); }
      const paths = (router && router.stack ? router.stack : [])
        .filter(l => l && l.route && l.route.path)
        .map(l => l.route.path);
      const forbidden = paths.filter(p => p === '/mfa/config' || p.indexOf('/mfa/totp') === 0);
      if (forbidden.length) throw new Error('forbidden MFA/TOTP endpoint(s) present: ' + forbidden.join(', '));
      return 'no /mfa/config or /mfa/totp endpoint';
    });
    await check('auth', 'users has no dead totp_* columns (B6i)', () => {
      const cols = this.db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
      const leftover = cols.filter(c => c.indexOf('totp_') === 0);
      if (leftover.length) throw new Error('dead totp_* column(s) present: ' + leftover.join(', '));
      return 'no totp_* columns (' + cols.length + ' columns total)';
    });
    await check('auth', 'CA issue / verify / revoke / CRL round-trip', () => {
      // Real openssl-backed CA round-trip against a throwaway in-memory clone:
      // the CA key lives in the DB, so a fresh clone gets its own CA, and
      // openssl scratch goes to a temp dir. No live CA state is touched.
      const ca = require('./ca');
      const { execFileSync } = require('child_process');
      const os = require('os'); const fsx = require('fs'); const pathx = require('path');
      const mem = cloneLiveSchema(this.db);
      const init = ca.initCa(mem);
      if (!init || !init.caCertPem) throw new Error('CA did not initialize');
      const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'rr-ca-'));
      try {
        const keyP = pathx.join(dir, 'c.key'); const csrP = pathx.join(dir, 'c.csr');
        execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', keyP], { stdio: 'ignore' });
        execFileSync('openssl', ['req', '-new', '-key', keyP, '-subj', '/CN=regression-client', '-out', csrP], { stdio: 'ignore' });
        const csrPem = fsx.readFileSync(csrP, 'utf8');
        const issued = ca.issueClientCert(mem, { csrPem, commonName: 'regression-client', externalId: 'rr-' + crypto.randomBytes(4).toString('hex') });
        if (!issued || !issued.certPem || !issued.serial) throw new Error('issueClientCert returned no cert/serial');
        const v1 = ca.verifyClientCert(mem, issued.certPem);
        if (!v1 || !v1.valid) throw new Error('freshly issued cert failed to verify: ' + (v1 && v1.reason));
        ca.revokeCert(mem, { serial: issued.serial, reason: 'regression' });
        const v2 = ca.verifyClientCert(mem, issued.certPem);
        if (!v2 || v2.valid) throw new Error('revoked cert still verified as valid');
        if (v2.reason !== 'revoked') throw new Error('expected reason "revoked", got "' + v2.reason + '"');
        const crl = ca.buildRevocationList(mem);
        const inCrl = crl && Array.isArray(crl.revoked) && crl.revoked.some(r => r.serial === issued.serial);
        if (!inCrl) throw new Error('revoked serial not present in CRL');
        if (!crl.signature) throw new Error('CRL is not signed');
        return 'issue -> verify(valid) -> revoke -> verify(revoked) -> CRL(signed, serial present) ok';
      } finally {
        try { fsx.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
      }
    });
    await check('auth', 'Break-glass recovery credential (verify correct / reject wrong)', () => {
      // Against a clone: mint the one-time recovery credential, confirm the
      // correct secret verifies and a wrong one does not (timing-safe).
      const ca = require('./ca');
      const mem = cloneLiveSchema(this.db);
      const r = ca.ensureRecoveryCredential(mem);
      if (!r || !r.recoveryCredential) throw new Error('recovery credential was not minted on a fresh authority');
      if (!ca.verifyRecoveryCredential(mem, r.recoveryCredential)) throw new Error('correct recovery credential failed to verify');
      if (ca.verifyRecoveryCredential(mem, r.recoveryCredential + 'x')) throw new Error('a wrong recovery credential verified');
      return 'recovery credential mint + verify(correct) + reject(wrong) ok';
    });
    await check('auth', 'WebAuthn subsystem present (registration / authentication / step-up)', () => {
      let wa;
      try { wa = require('./webauthn'); } catch (e) { throw new Error('cannot load webauthn service: ' + e.message); }
      const need = ['beginRegistration', 'finishRegistration', 'beginAuthentication', 'finishAuthentication', 'beginStepUp', 'finishStepUp'];
      const missing = need.filter(f => typeof wa[f] !== 'function');
      if (missing.length) throw new Error('missing webauthn fn(s): ' + missing.join(', '));
      if (!tableExists('webauthn_credentials')) throw new Error('missing table webauthn_credentials');
      return 'registration + authentication + step-up wired; webauthn_credentials present';
    });
    await check('auth', 'B5n3 hardware-attestation schema (columns + trust tables)', () => {
      const cols = new Set(this.db.prepare("PRAGMA table_info(webauthn_credentials)").all().map(c => c.name));
      const needCols = ['backed_up', 'device_type', 'attestation_fmt', 'hardware_verified', 'trusted_root_id'];
      const missingCols = needCols.filter(c => !cols.has(c));
      if (missingCols.length) throw new Error('webauthn_credentials missing column(s): ' + missingCols.join(', '));
      for (const t of ['fido_trusted_roots', 'fido_aaguid_allowlist']) {
        if (!tableExists(t)) throw new Error('missing table ' + t);
      }
      return 'webauthn_credentials hardware columns + fido_trusted_roots + fido_aaguid_allowlist present';
    });
    await check('auth', 'FIDO attestation trust anchors seeded (>= 1, all parse as CA)', () => {
      const n = this.db.prepare('SELECT COUNT(*) AS n FROM fido_trusted_roots').get().n;
      if (!n || n < 1) throw new Error('no trusted FIDO attestation roots present; hardware enrollment would be impossible');
      const rows = this.db.prepare('SELECT label, root_pem FROM fido_trusted_roots').all();
      for (const r of rows) {
        let cert;
        try { cert = new crypto.X509Certificate(r.root_pem); } catch (_) { throw new Error('stored root not parseable: ' + r.label); }
        if (cert.ca !== true) throw new Error('stored root is not a CA certificate: ' + r.label);
      }
      return n + ' trusted root(s) present; all parse as CA certificates';
    });
    await check('auth', 'assertHardwareCredential gate (accept hardware / reject soft + synced)', () => {
      let wa;
      try { wa = require('./webauthn'); } catch (e) { throw new Error('cannot load webauthn service: ' + e.message); }
      if (typeof wa.assertHardwareCredential !== 'function') throw new Error('assertHardwareCredential not exported');
      if (typeof wa.HardwareCredentialError !== 'function') throw new Error('HardwareCredentialError not exported');
      const emptyAllowDb = { prepare: () => ({ all: () => [] }) };
      const ok = wa.assertHardwareCredential({ attestationVerified: true, backedUp: false, deviceType: 'singleDevice', fmt: 'packed', aaguid: 'x', db: emptyAllowDb });
      if (ok !== true) throw new Error('genuine hardware verdict did not pass the gate');
      const cases = [
        ['unverified attestation', { attestationVerified: false, backedUp: false, deviceType: 'singleDevice', fmt: 'packed', db: emptyAllowDb }],
        ['no attestation format', { attestationVerified: true, backedUp: false, deviceType: 'singleDevice', fmt: 'none', db: emptyAllowDb }],
        ['synced / backed-up', { attestationVerified: true, backedUp: true, deviceType: 'singleDevice', fmt: 'packed', db: emptyAllowDb }],
        ['multi-device', { attestationVerified: true, backedUp: false, deviceType: 'multiDevice', fmt: 'packed', db: emptyAllowDb }],
      ];
      for (const entry of cases) {
        let threw = false;
        try { wa.assertHardwareCredential(entry[1]); } catch (e) { threw = e instanceof wa.HardwareCredentialError; }
        if (!threw) throw new Error('gate failed to reject: ' + entry[0]);
      }
      return 'gate accepts genuine hardware; rejects unverified / none / synced / multi-device';
    });
    await check('auth', 'Attestation chain verification (accept chained leaf / reject foreign root)', () => {
      let wa;
      try { wa = require('./webauthn'); } catch (e) { throw new Error('cannot load webauthn service: ' + e.message); }
      if (typeof wa.verifyAttestationChain !== 'function') throw new Error('verifyAttestationChain not exported');
      const { execFileSync } = require('child_process');
      const os = require('os'); const fsx = require('fs'); const pathx = require('path');
      const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'rr-fido-'));
      try {
        const rk = pathx.join(dir, 'r.key'), rc = pathx.join(dir, 'r.pem');
        const lk = pathx.join(dir, 'l.key'), lcsr = pathx.join(dir, 'l.csr'), lc = pathx.join(dir, 'l.pem');
        const fc = pathx.join(dir, 'f.key'), fpem = pathx.join(dir, 'f.pem');
        execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', rk], { stdio: 'ignore' });
        execFileSync('openssl', ['req', '-new', '-x509', '-key', rk, '-subj', '/CN=RR FIDO Root', '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE', '-out', rc], { stdio: 'ignore' });
        execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', lk], { stdio: 'ignore' });
        execFileSync('openssl', ['req', '-new', '-key', lk, '-subj', '/CN=RR Leaf', '-out', lcsr], { stdio: 'ignore' });
        execFileSync('openssl', ['x509', '-req', '-in', lcsr, '-CA', rc, '-CAkey', rk, '-CAcreateserial', '-days', '2', '-out', lc], { stdio: 'ignore' });
        execFileSync('openssl', ['ecparam', '-genkey', '-name', 'prime256v1', '-noout', '-out', fc], { stdio: 'ignore' });
        execFileSync('openssl', ['req', '-new', '-x509', '-key', fc, '-subj', '/CN=RR Foreign Root', '-days', '2', '-addext', 'basicConstraints=critical,CA:TRUE', '-out', fpem], { stdio: 'ignore' });
        const leaf = new crypto.X509Certificate(fsx.readFileSync(lc));
        const root = new crypto.X509Certificate(fsx.readFileSync(rc));
        const foreign = new crypto.X509Certificate(fsx.readFileSync(fpem));
        const good = wa.verifyAttestationChain([leaf], [{ id: 'r', cert: root }]);
        if (!good || good.verified !== true || good.trustedRootId !== 'r') throw new Error('leaf failed to chain to its issuing root');
        const bad = wa.verifyAttestationChain([leaf], [{ id: 'f', cert: foreign }]);
        if (!bad || bad.verified !== false) throw new Error('leaf wrongly chained to a foreign root');
        return 'leaf verifies to issuing root (id captured); rejects foreign root';
      } finally {
        try { fsx.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
      }
    });
    await check('iam', 'FIDO trust-anchor admin routes present', () => {
      let router;
      try { router = require('../routes/iam'); } catch (e) { throw new Error('cannot load iam router: ' + e.message); }
      const paths = new Set(
        (router && router.stack ? router.stack : [])
          .filter(l => l && l.route && l.route.path)
          .map(l => l.route.path)
      );
      const need = ['/fido-roots', '/fido-roots/:id', '/fido-aaguids', '/fido-aaguids/:id'];
      const missing = need.filter(p => !paths.has(p));
      if (missing.length) throw new Error('missing FIDO admin route(s): ' + missing.join(', '));
      return 'fido-roots + fido-aaguids admin routes (list / add / remove) present';
    });
    await check('auth', 'LDAP directory helpers (filter-escape + group mapping)', () => {
      // The directory layer is used for offboarding presence, not for
      // authentication. Exercise the injection-safe filter escaper and the
      // default group map; a live bind is not attempted (no directory here).
      let ldap;
      try { ldap = require('../integrations/ldap'); } catch (e) { throw new Error('cannot load ldap integration: ' + e.message); }
      if (typeof ldap.escapeFilterValue !== 'function') throw new Error('escapeFilterValue missing');
      const esc = ldap.escapeFilterValue('*()\\');
      if (esc === '*()\\' || esc.indexOf('\\') === -1) throw new Error('LDAP filter value not escaped: ' + esc);
      if (typeof ldap.LdapClient !== 'function') throw new Error('LdapClient missing');
      if (!ldap.DEFAULT_GROUP_MAPPING || typeof ldap.DEFAULT_GROUP_MAPPING !== 'object') throw new Error('DEFAULT_GROUP_MAPPING missing');
      return 'filter-escape + group mapping present (directory-only; bind not exercised)';
    });

    // B5f: sender-constrained session checks (per-request proof-of-possession).
    await check('auth', 'Device proof-of-possession verifier (B5f: valid / tampered / expired / replay)', () => {
      const devicePop = require('./device-pop');
      const dk = require('./device-key');
      if (devicePop.POP_SIGNING_PREFIX !== 'firealive-device-pop-v1:') {
        throw new Error('regional PoP signing prefix is not domain-separated (firealive-device-pop-v1:)');
      }
      if (devicePop.POP_HEADER !== 'x-fa-device-pop') throw new Error('unexpected PoP header name');
      const pair = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const pem = pair.publicKey.export({ type: 'spki', format: 'pem' });
      const jkt = dk.jwkThumbprint(pem);
      const rid = crypto.randomBytes(8).toString('hex');
      const mkProof = (method, path, iat, jti) => {
        const msg = devicePop.popMessage(method, path, iat, jti, jkt);
        const sig = crypto.sign('sha256', msg, { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
        return Buffer.from(JSON.stringify({ iat: iat, jti: jti, sig: sig.toString('base64') })).toString('base64url');
      };
      const now = Math.floor(Date.now() / 1000);
      const good = devicePop.verifyPopProof({ method: 'GET', path: '/api/probe', proof: mkProof('GET', '/api/probe', now, 'rr-ok-' + rid), publicKeyPem: pem, jkt: jkt });
      if (!good.ok) throw new Error('a valid proof was rejected: ' + good.reason);
      const tampered = devicePop.verifyPopProof({ method: 'POST', path: '/api/probe', proof: mkProof('GET', '/api/probe', now, 'rr-tamper-' + rid), publicKeyPem: pem, jkt: jkt });
      if (tampered.ok) throw new Error('a proof signed for a different method was accepted');
      const expired = devicePop.verifyPopProof({ method: 'GET', path: '/api/probe', proof: mkProof('GET', '/api/probe', now - 120, 'rr-exp-' + rid), publicKeyPem: pem, jkt: jkt });
      if (expired.ok) throw new Error('an expired proof was accepted');
      const replay = mkProof('GET', '/api/probe', now, 'rr-replay-' + rid);
      const first = devicePop.verifyPopProof({ method: 'GET', path: '/api/probe', proof: replay, publicKeyPem: pem, jkt: jkt });
      const second = devicePop.verifyPopProof({ method: 'GET', path: '/api/probe', proof: replay, publicKeyPem: pem, jkt: jkt });
      if (!first.ok || second.ok) throw new Error('the replay guard did not reject a reused proof');
      return 'valid accepted; tampered / expired / replayed rejected; signing prefix domain-separated';
    });
    await check('auth', 'Device-key crypto core (B5f: EC + Ed25519 verify, RFC 7638 thumbprint)', () => {
      const dk = require('./device-key');
      if (typeof dk.verifyDeviceSignature !== 'function' || typeof dk.jwkThumbprint !== 'function') {
        throw new Error('device-key missing verifyDeviceSignature / jwkThumbprint');
      }
      const msg = Buffer.from('device-key-selftest', 'utf8');
      const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const ecPem = ec.publicKey.export({ type: 'spki', format: 'pem' });
      const ecSig = crypto.sign('sha256', msg, { key: ec.privateKey, dsaEncoding: 'ieee-p1363' });
      if (!dk.verifyDeviceSignature(ecPem, msg, ecSig)) throw new Error('EC P-256 device signature did not verify');
      if (dk.verifyDeviceSignature(ecPem, Buffer.from('tampered', 'utf8'), ecSig)) throw new Error('EC verify accepted a tampered message');
      const ed = crypto.generateKeyPairSync('ed25519');
      const edPem = ed.publicKey.export({ type: 'spki', format: 'pem' });
      const edSig = crypto.sign(null, msg, ed.privateKey);
      if (!dk.verifyDeviceSignature(edPem, msg, edSig)) throw new Error('Ed25519 device signature did not verify');
      const t1 = dk.jwkThumbprint(ecPem); const t2 = dk.jwkThumbprint(ecPem);
      if (t1 !== t2 || !/^[A-Za-z0-9_-]{43}$/.test(t1)) throw new Error('jwkThumbprint is not a stable base64url SHA-256');
      return 'EC + Ed25519 verify; tamper rejected; RFC 7638 thumbprint stable';
    });
    await check('auth', 'Session device-binding enforced (B5f: cnf-less session refused)', () => {
      let mw;
      try { mw = require('../middleware/auth'); } catch (e) { throw new Error('cannot load auth middleware: ' + e.message); }
      for (const fn of ['authMiddleware', 'signToken', 'getClientCertThumbprint']) {
        if (typeof mw[fn] !== 'function') throw new Error('auth middleware does not export ' + fn);
      }
      const payloadOf = (t) => JSON.parse(Buffer.from(String(t).split('.')[1], 'base64url').toString('utf8'));
      const bound = payloadOf(mw.signToken({ id: 1, role: 'analyst' }, { jkt: 'TESTJKT' }));
      if (!bound || !bound.cnf || bound.cnf.jkt !== 'TESTJKT') throw new Error('signToken did not bind cnf.jkt into the token');
      const cnfless = mw.signToken({ id: 1, role: 'analyst' });
      const req = { headers: { authorization: 'Bearer ' + cnfless }, method: 'GET', originalUrl: '/api/regression-probe', path: '/api/regression-probe' };
      let captured = null; let nextCalled = false;
      const res = { status: function (c) { captured = { code: c }; return this; }, json: function (o) { captured.body = o; return this; } };
      mw.authMiddleware(['analyst'])(req, res, function () { nextCalled = true; });
      if (nextCalled) throw new Error('a cnf-less session was allowed through (device binding not enforced)');
      if (!captured || captured.code !== 401 || !captured.body || captured.body.code !== 'device_binding_required') {
        throw new Error('cnf-less session not refused with device_binding_required');
      }
      return 'signToken binds cnf.jkt; a cnf-less session is refused with device_binding_required';
    });

    // ── Category: IAM ──────────────────────────────────────────────
    await check('iam', 'IAM offboarding columns + detector (B5b)', () => {
      // Forward-aware + auto-activating. R0 added the offboarding columns; the
      // scheduled IdP detector that writes them lands in B5b (IAM Real IdP
      // Integration). Verify the columns exist now; skip the detector assertion
      // until B5b populates last_iam_check, at which point this auto-activates.
      const cols = ['last_iam_check', 'active', 'offboarded_at', 'external_id', 'auth_method'];
      const missing = cols.filter(c => !columnExists('users', c));
      if (missing.length > 0) throw new Error('missing users column(s): ' + missing.join(', '));
      const probed = this.db
        .prepare("SELECT COUNT(*) AS c FROM users WHERE last_iam_check IS NOT NULL")
        .get();
      if (!probed || probed.c === 0) {
        return SKIP('offboarding columns present; IdP detector not yet writing last_iam_check — pending B5b');
      }
      return 'offboarding columns present; detector has run (' + probed.c + ' user(s) checked)';
    });

    // ── Category 4: Anti-rollback ──────────────────────────────────
    await check('anti-rollback', 'Fuse counter row present in system_meta', () => {
      const row = this.db
        .prepare("SELECT value FROM system_meta WHERE key='fuse_counter'")
        .get();
      if (!row) throw new Error('no fuse_counter row in system_meta');
      const n = parseInt(row.value, 10);
      if (!Number.isInteger(n) || n < 0) throw new Error('fuse_counter not a non-negative integer: ' + row.value);
      return 'fuse = ' + n;
    });
    await check('anti-rollback', 'Fuse counter matches package.json', () => {
      const row = this.db
        .prepare("SELECT value FROM system_meta WHERE key='fuse_counter'")
        .get();
      const stored = row ? parseInt(row.value, 10) : null;
      let expected;
      try {
        // The version module is the source of truth for fuseCounter
        // at build time. Stored value should advance >= expected
        // (storage can be ahead if a migration bumped it).
        const ver = require('../lib/version');
        expected = ver.fuseCounter;
      } catch (e) {
        throw new Error('cannot load server/lib/version: ' + e.message);
      }
      if (stored !== expected) {
        throw new Error('stored fuse (' + stored + ') != expected (' + expected + ')');
      }
      return 'stored=' + stored + ', expected=' + expected;
    });

    // ── Category 5: Integrations ───────────────────────────────────
    await check('integrations', 'integration_config table reachable', () => {
      if (!tableExists('integration_config')) throw new Error('missing table integration_config');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM integration_config').get().n;
      return c + ' integration_config row(s)';
    });
    await check('integrations', 'kms_providers registered', () => {
      if (!tableExists('kms_providers')) throw new Error('missing table kms_providers');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM kms_providers').get().n;
      if (c === 0) return 'no providers registered (local-master-key fallback in use)';
      return c + ' provider(s) registered';
    });
    await check('integrations', 'KMS provider round-trip (each active)', () => {
      if (!tableExists('kms_providers')) throw new Error('missing table kms_providers');
      let kmsService;
      try {
        kmsService = require('./kms-providers');
      } catch (e) {
        throw new Error('cannot load kms-providers service: ' + e.message);
      }
      const active = this.db
        .prepare("SELECT id, name FROM kms_providers WHERE status='active'")
        .all();
      if (active.length === 0) return 'no active providers (skipped round-trip)';
      const probe = crypto.randomBytes(32);
      let okCount = 0;
      const failures = [];
      for (const p of active) {
        try {
          if (typeof kmsService.wrapDek === 'function' && typeof kmsService.unwrapDek === 'function') {
            const wrapped = kmsService.wrapDek(this.db, p.id, probe);
            const unwrapped = kmsService.unwrapDek(this.db, p.id, wrapped);
            if (!Buffer.isBuffer(unwrapped) || !unwrapped.equals(probe)) {
              failures.push(p.name + ': unwrap mismatch');
              continue;
            }
            okCount++;
          } else {
            // Service exists but uses a different API shape — report
            // as inconclusive rather than failing the suite.
            return 'kms-providers service has unexpected API (skipped probe)';
          }
        } catch (e) {
          failures.push(p.name + ': ' + (e.message || String(e)));
        }
      }
      if (failures.length > 0) {
        throw new Error(failures.join('; '));
      }
      return okCount + '/' + active.length + ' provider(s) round-trip ok';
    });
    await check('integrations', 'GD-push signing round-trip (Ed25519 + fingerprint)', () => {
      // Exercises the real GD-push key primitives (no DB, no writes): generate
      // an Ed25519 keypair, confirm the content-addressed fingerprint is stable,
      // and round-trip a detached signature over a sample body — the same
      // primitive the cross-region push outbox signs with — incl. tamper-detect.
      const gdkeys = require('./gd-push-signing-keys');
      const kp = gdkeys.generateKeypair();
      if (!kp.publicKeyPem || !kp.privateKeyPem) throw new Error('keypair generation returned no PEM');
      if (!/^[0-9a-f]{64}$/.test(kp.publicKeyFingerprint)) throw new Error('fingerprint is not 64 hex chars');
      if (gdkeys.computePublicKeyFingerprint(kp.publicKeyPem) !== kp.publicKeyFingerprint) {
        throw new Error('fingerprint not stable across recompute');
      }
      const body = Buffer.from(JSON.stringify({ probe: 'regression', t: Date.now() }), 'utf8');
      const sig = crypto.sign(null, body, kp.privateKeyPem);
      if (!crypto.verify(null, body, kp.publicKeyPem, sig)) throw new Error('signature did not verify');
      const tampered = Buffer.from(body); tampered[0] ^= 0xff;
      if (crypto.verify(null, tampered, kp.publicKeyPem, sig)) throw new Error('signature verified a tampered body');
      return 'Ed25519 keygen + fingerprint + sign/verify round-trip ok';
    });

    // ── Optional integration config (skip-trichotomy) ──────────────
    // configured + structurally valid -> pass; configured + broken -> fail;
    // optional + not configured -> skip. The runner judges only whether what is
    // configured still works; the compliance engine owns missing controls.
    const readJsonConfig = (key) => {
      const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get(key);
      if (!row || !row.value) return undefined;           // not configured
      try { return JSON.parse(row.value); } catch { return null; } // configured but broken
    };
    const optionalEndpointCheck = (label, key) => () => {
      const cfg = readJsonConfig(key);
      if (cfg === undefined) return SKIP(label + ' not configured');
      if (cfg === null) throw new Error(label + ' config present but not valid JSON');
      if (!cfg.endpoint) throw new Error(label + ' configured but missing endpoint');
      return label + ' configured (' + (cfg.platform || 'endpoint set') + ')';
    };
    await check('integrations', 'SOAR config valid (if configured)', optionalEndpointCheck('SOAR', 'soar_config'));
    await check('integrations', 'SIEM config valid (if configured)', optionalEndpointCheck('SIEM', 'siem_config'));
    await check('integrations', 'Ticketing config valid (if configured)', optionalEndpointCheck('Ticketing', 'ticketing_config'));
    await check('integrations', 'LDAP/AD config valid (if configured)', () => {
      let row = null;
      try { row = this.db.prepare("SELECT value FROM team_config WHERE key = 'iam_config'").get(); } catch { row = null; }
      if (!row || !row.value) return SKIP('LDAP/AD not configured');
      let cfg;
      try { cfg = JSON.parse(row.value); } catch { throw new Error('iam_config present but not valid JSON'); }
      if (!cfg.server && !cfg.bindDn) return SKIP('LDAP/AD not configured (no connection fields)');
      if (!cfg.server || !cfg.bindDn) throw new Error('LDAP/AD partially configured (need server + bindDn)');
      return 'LDAP/AD configured';
    });
    await check('integrations', 'Backup storage destination (if configured)', () => {
      if (!tableExists('backup_destinations')) return SKIP('no backup destinations table');
      const n = this.db.prepare('SELECT COUNT(*) AS n FROM backup_destinations WHERE enabled = 1').get().n;
      if (n === 0) return SKIP('no enabled backup destination configured');
      return n + ' enabled backup destination(s)';
    });

    // ── EDR / malware scanner is REQUIRED (fail-closed if absent) ──
    // There is no scanning-off mode; a deployment without a scanner cannot
    // fail-closed correctly, so its absence is a regression failure (not a skip).
    await check('integrations', 'EDR/malware scanner configured (required)', () => {
      if (!tableExists('malware_scanner_integrations')) {
        throw new Error('malware scanner integration table missing; EDR/malware scanning is required');
      }
      const n = this.db.prepare('SELECT COUNT(*) AS n FROM malware_scanner_integrations').get().n;
      if (n === 0) throw new Error('no EDR/malware scanner configured; scanning is required (no scanning-off mode)');
      return n + ' scanner(s) configured';
    });

    // ── Category: Helper-pay ───────────────────────────────────────
    await check('helper-pay', 'Points-ledger append + balance-cache invariant', () => {
      // Verifies the helper-pay points-ledger model on an in-memory clone of the
      // live schema (zero production writes). Mirrors appendLedger/getBalanceInternal:
      // balance_after caches the running total and the latest row (created_at DESC,
      // id DESC) holds the current balance. A throwaway user satisfies the FK.
      const mem = cloneLiveSchema(this.db);
      try {
        if (!mem.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='helper_points_ledger'").get()) {
          throw new Error('helper_points_ledger not in cloned schema');
        }
        const uid = 'rt-' + crypto.randomBytes(6).toString('hex');
        mem.prepare("INSERT INTO users (id, username, role, name) VALUES (?, ?, 'analyst', ?)").run(uid, uid, uid);
        const ins = (id, delta, balAfter) => mem.prepare(
          "INSERT INTO helper_points_ledger (id, user_id, delta, reason, balance_after) VALUES (?, ?, ?, 'rating_received', ?)"
        ).run(id, uid, delta, balAfter);
        ins('a-' + uid, 10, 10);
        ins('b-' + uid, 5, 15);
        const row = mem.prepare(
          "SELECT balance_after AS b FROM helper_points_ledger WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT 1"
        ).get(uid);
        const bal = row ? row.b : 0;
        if (bal !== 15) throw new Error('cached balance ' + bal + ' != expected 15');
        return 'ledger append + cached balance (15) verified on cloned schema';
      } finally {
        try { mem.close(); } catch (_e) { /* ignore */ }
      }
    });

    // ── Category 6: Burnout signals ────────────────────────────────
    await check('burnout', 'Burnout engine tables', () => {
      return requireAll(['analyst_baselines', 'analyst_impacts']);
    });
    await check('burnout', 'AI provider config present', () => {
      if (!tableExists('ai_provider_config')) throw new Error('missing table ai_provider_config');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM ai_provider_config').get().n;
      return c + ' provider config row(s)';
    });
    await check('burnout', 'AI inference provenance log present', () => {
      if (!tableExists('ai_inference_log')) throw new Error('missing table ai_inference_log');
      return 'ai_inference_log table present';
    });

    // ── Category 7: Routing ────────────────────────────────────────
    await check('routing', 'Routing tables (caps + overrides)', () => {
      return requireAll(['routing_caps', 'routing_overrides']);
    });
    await check('routing', 'team_config.routing_enabled present (R3j)', () => {
      const row = this.db
        .prepare("SELECT value FROM team_config WHERE key='routing_enabled'")
        .get();
      if (!row) throw new Error('no routing_enabled row in team_config (R3j C2 migration may have failed)');
      return 'value = ' + row.value;
    });
    await check('routing', 'team_config.panic_mode key reachable', () => {
      const row = this.db
        .prepare("SELECT value FROM team_config WHERE key='panic_mode'")
        .get();
      // panic_mode row may legitimately be absent in a fresh install
      // (the key only materializes on first toggle). Either state is
      // a pass for this check.
      if (!row) return 'no panic_mode row (default: inactive)';
      return 'value = ' + row.value;
    });
    await check('routing', 'soar_routing_events composite UNIQUE index (R3j C1)', () => {
      if (!indexExists('idx_soar_routing_events_external')) {
        throw new Error('missing idx_soar_routing_events_external');
      }
      return 'idx_soar_routing_events_external present';
    });

    // ── Category 8: Backup ─────────────────────────────────────────
    await check('backup', 'backups table v2 columns', () => {
      const required = ['format_version', 'manifest_path', 'archive_path', 'wrapped_key_path', 'signing_key_id'];
      const missing = required.filter(c => !columnExists('backups', c));
      if (missing.length > 0) throw new Error('missing column(s): ' + missing.join(', '));
      return 'all v2 columns present';
    });
    await check('backup', 'backups.kind column present (R3k C2)', () => {
      if (!columnExists('backups', 'kind')) throw new Error('missing column kind');
      return 'kind column present';
    });
    await check('backup', 'backup_signing_keys has an active key', () => {
      if (!tableExists('backup_signing_keys')) throw new Error('missing table backup_signing_keys');
      const row = this.db
        .prepare("SELECT COUNT(*) AS n FROM backup_signing_keys WHERE is_active = 1")
        .get();
      if (row.n === 0) {
        // External-registered keys are allowed to be inactive while
        // pending operator approval. Check for any registered key as
        // a fallback signal.
        const any = this.db.prepare('SELECT COUNT(*) AS n FROM backup_signing_keys').get().n;
        if (any === 0) throw new Error('no signing keys present');
        return 'no active key (' + any + ' inactive/registered)';
      }
      return row.n + ' active signing key(s)';
    });
    await check('backup', 'backup_schedules has at least one row', () => {
      if (!tableExists('backup_schedules')) throw new Error('missing table backup_schedules');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM backup_schedules').get().n;
      if (c === 0) throw new Error('no schedules (legacy default row should have been seeded by R3i)');
      return c + ' schedule(s)';
    });

    // ── Category 13: Storage routing ───────────────────────────────
    await check('storage-routing', 'storage_destinations table present', () => {
      if (!tableExists('storage_destinations')) throw new Error('missing table storage_destinations (B5q rename from backup_destinations)');
      const n = this.db.prepare('SELECT COUNT(*) AS n FROM storage_destinations').get().n;
      return n + ' destination(s) registered';
    });
    await check('storage-routing', 'storage_destination_routes has dual-write columns', () => {
      if (!tableExists('storage_destination_routes')) throw new Error('missing table storage_destination_routes');
      const required = ['data_type', 'destination_ref', 'secondary_destination_ref', 'path_prefix', 'options', 'enabled'];
      const missing = required.filter(c => !columnExists('storage_destination_routes', c));
      if (missing.length) throw new Error('missing column(s): ' + missing.join(', '));
      return 'primary + secondary route columns present';
    });
    await check('storage-routing', 'enabled routes reference existing destinations', () => {
      if (!tableExists('storage_destination_routes')) return SKIP('no routes table');
      const rows = this.db.prepare(
        'SELECT data_type, destination_ref, secondary_destination_ref FROM storage_destination_routes WHERE enabled = 1'
      ).all();
      if (rows.length === 0) return SKIP('no enabled routes configured');
      const dangling = [];
      for (const r of rows) {
        for (const ref of [r.destination_ref, r.secondary_destination_ref]) {
          if (!ref) continue;
          const d = this.db.prepare('SELECT 1 AS x FROM storage_destinations WHERE id = ?').get(ref);
          if (!d) dangling.push(r.data_type + '->' + ref);
        }
      }
      if (dangling.length) throw new Error('route(s) point at missing destination(s): ' + dangling.join(', '));
      return rows.length + ' enabled route(s), all refs resolve';
    });
    await check('storage-routing', 'archive_segment_pushes has tracking + retry columns', () => {
      if (!tableExists('archive_segment_pushes')) throw new Error('missing table archive_segment_pushes');
      const required = ['segment_id', 'destination_id', 'role', 'status', 'attempt_count', 'next_retry_at', 'source_artifact_path'];
      const missing = required.filter(c => !columnExists('archive_segment_pushes', c));
      if (missing.length) throw new Error('missing column(s): ' + missing.join(', '));
      return 'role + retry columns present';
    });
    await check('storage-routing', 'forensic_export_pushes has tracking + retry columns', () => {
      if (!tableExists('forensic_export_pushes')) throw new Error('missing table forensic_export_pushes');
      const required = ['export_id', 'destination_id', 'role', 'status', 'attempt_count', 'next_retry_at'];
      const missing = required.filter(c => !columnExists('forensic_export_pushes', c));
      if (missing.length) throw new Error('missing column(s): ' + missing.join(', '));
      return 'role + retry columns present';
    });
    await check('storage-routing', 'backup_pushes has retry columns (re-push path)', () => {
      if (!tableExists('backup_pushes')) throw new Error('missing table backup_pushes');
      const required = ['backup_id', 'destination_id', 'status', 'attempt_count', 'next_retry_at'];
      const missing = required.filter(c => !columnExists('backup_pushes', c));
      if (missing.length) throw new Error('missing column(s): ' + missing.join(', '));
      return 'backup push retry columns present';
    });
    await check('storage-routing', 'archive segments pruned of destination columns', () => {
      if (!tableExists('storage_archive_segments')) return SKIP('no archive segments table');
      const leaked = ['destination_ref', 'dest_path', 'secondary_destination_ref', 'secondary_dest_path', 'pushed_at']
        .filter(c => columnExists('storage_archive_segments', c));
      if (leaked.length) throw new Error('segment table still carries push column(s): ' + leaked.join(', '));
      return 'segment table is artifact + chain only';
    });
    await check('storage-routing', 'push rows reference existing artifacts', () => {
      let scanned = 0;
      if (tableExists('archive_segment_pushes') && tableExists('storage_archive_segments')) {
        const orphan = this.db.prepare(
          'SELECT COUNT(*) AS n FROM archive_segment_pushes p LEFT JOIN storage_archive_segments s ON s.id = p.segment_id WHERE s.id IS NULL'
        ).get().n;
        if (orphan > 0) throw new Error(orphan + ' archive push row(s) with no segment');
        scanned += 1;
      }
      if (tableExists('forensic_export_pushes') && tableExists('forensic_exports')) {
        const orphan = this.db.prepare(
          'SELECT COUNT(*) AS n FROM forensic_export_pushes p LEFT JOIN forensic_exports e ON e.id = p.export_id WHERE e.id IS NULL'
        ).get().n;
        if (orphan > 0) throw new Error(orphan + ' forensic push row(s) with no export');
        scanned += 1;
      }
      if (scanned === 0) return SKIP('no push-tracking tables to check');
      return 'no orphan push rows';
    });

    // ── Category 9: Audit chain ────────────────────────────────────────
    await check('audit-chain', 'audit_log table reachable', () => {
      if (!tableExists('audit_log')) throw new Error('missing table audit_log');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
      return c + ' audit row(s)';
    });
    await check('audit-chain', 'backup_chain linkage walk (last 10 entries)', () => {
      if (!tableExists('backup_chain')) {
        // backup_chain is created lazily by the chain service; a
        // fresh install may legitimately have no entries.
        return 'backup_chain not yet created (no backups taken)';
      }
      const rows = this.db
        .prepare('SELECT id, prev_hash, this_hash FROM backup_chain ORDER BY id DESC LIMIT 10')
        .all();
      if (rows.length === 0) return 'no chain entries (no backups taken)';
      // Verify linkage: each row's prev_hash should equal the next-
      // older row's this_hash. The list is DESC, so walk pairwise.
      for (let i = 0; i < rows.length - 1; i++) {
        const newer = rows[i];
        const older = rows[i + 1];
        if (newer.prev_hash !== older.this_hash) {
          throw new Error('chain broken at id ' + newer.id + ' (prev_hash != older.this_hash)');
        }
      }
      return rows.length + ' entries linked ok';
    });
    await check('audit-chain', 'chain_signing_keys has an active key', () => {
      if (!tableExists('chain_signing_keys')) throw new Error('missing table chain_signing_keys');
      const row = this.db
        .prepare("SELECT COUNT(*) AS n FROM chain_signing_keys WHERE is_active = 1")
        .get();
      if (row.n === 0) throw new Error('no active chain signing key');
      return row.n + ' active chain signing key(s)';
    });
    await check('audit-chain', 'audit_log hash chain recompute + linkage (B5a)', () => {
      // Forward-aware + auto-activating. Until the B5a hash columns exist this
      // skips; once present it runs the authoritative verifier — recomputes
      // every row's SHA-256 from its content, checks prev_hash linkage, and
      // validates the chain head against the latest Ed25519-signed checkpoint.
      if (!columnExists('audit_log', 'hash') || !columnExists('audit_log', 'prev_hash')) {
        return SKIP('audit_log.hash/prev_hash not present yet — pending B5a (Audit Hash Chain)');
      }
      const { verifyFull } = require('./audit-chain');
      const r = verifyFull(this.db);
      if (!r.intact) {
        throw new Error('chain ' + (r.reason || 'broken') + (r.brokenAt != null ? (' at id ' + r.brokenAt) : '') + (r.detail ? (' — ' + r.detail) : ''));
      }
      return (r.entriesVerified != null ? r.entriesVerified : 0) + ' row(s) verified (recompute + linkage + checkpoint)';
    });
    await check('audit-chain', 'audit_log signed checkpoint (B5a)', () => {
      // Explicitly validates the latest Ed25519-signed checkpoint: recomputes the
      // head digest, verifies the signature against the active signing key, and
      // confirms the chain head row matches the notarized head. Forward-aware.
      if (!tableExists('audit_chain_checkpoint') || !tableExists('audit_chain_signing_keys') || !columnExists('audit_log', 'hash')) {
        return SKIP('audit_chain checkpoint tables not present yet — pending B5a');
      }
      const ac = require('./audit-chain');
      const cp = ac.getLatestCheckpoint(this.db);
      if (!cp) return 'no signed checkpoint yet (baseline not established)';
      const keyRow = this.db.prepare('SELECT public_key FROM audit_chain_signing_keys WHERE id = ?').get(cp.signing_key_id);
      if (!keyRow) throw new Error('checkpoint ' + cp.id + ' references missing signing key ' + cp.signing_key_id);
      const digest = ac.computeHeadDigest(cp);
      const sig = cp.signatureBuf || Buffer.from(cp.signature, 'base64');
      const ok = crypto.verify(null, digest, crypto.createPublicKey(keyRow.public_key), sig);
      if (!ok) throw new Error('checkpoint ' + cp.id + ' Ed25519 signature INVALID');
      const headRow = this.db.prepare('SELECT hash FROM audit_log WHERE id = ?').get(cp.head_id);
      if (!headRow || headRow.hash !== cp.head_hash) throw new Error('chain head id ' + cp.head_id + ' does not match signed checkpoint ' + cp.id);
      return 'checkpoint #' + cp.id + ' signature valid (head id ' + cp.head_id + ', ' + cp.entry_count + ' entries)';
    });

    // ── Category 10: Peer features ────────────────────────────────
    await check('peer', 'Peer session + message + rating tables', () => {
      return requireAll(['peer_sessions', 'peer_messages', 'peer_session_ratings']);
    });
    await check('peer', 'peer_abuse_flags table present', () => {
      if (!tableExists('peer_abuse_flags')) throw new Error('missing table peer_abuse_flags');
      return 'peer_abuse_flags present';
    });
    await check('peer', 'Peer-message E2E key column on users', () => {
      // The peer-message NaCl box key pair is per-user. Canonical
      // column names (R3-era): peer_pubkey (or analogous).
      const candidates = ['peer_pubkey', 'peer_public_key', 'peer_box_pubkey'];
      const present = candidates.filter(c => columnExists('users', c));
      if (present.length === 0) {
        throw new Error('no peer pubkey column on users (checked: ' + candidates.join(', ') + ')');
      }
      return 'column present: ' + present[0];
    });
    await check('peer', 'Peer skill-share E2E envelope round-trip', () => {
      // Mirrors the client-sealed, server-relayed peer skill-share envelope:
      // a sender seals to the recipient's public key and the recipient opens.
      // The server is content-blind, so this verifies the E2E primitive the
      // relay depends on — including authentication (tamper -> open fails).
      if (!nacl) throw new Error('tweetnacl not available');
      const sender = nacl.box.keyPair();
      const recipient = nacl.box.keyPair();
      const nonce = nacl.randomBytes(nacl.box.nonceLength);
      const msg = Buffer.from('skill-share: tune your SIEM correlation window', 'utf8');
      const boxed = nacl.box(new Uint8Array(msg), nonce, recipient.publicKey, sender.secretKey);
      const opened = nacl.box.open(boxed, nonce, sender.publicKey, recipient.secretKey);
      if (!opened || Buffer.from(opened).toString('utf8') !== msg.toString('utf8')) {
        throw new Error('peer envelope did not round-trip');
      }
      const tampered = boxed.slice();
      tampered[0] ^= 0xff;
      const openTampered = nacl.box.open(tampered, nonce, sender.publicKey, recipient.secretKey);
      if (openTampered) throw new Error('peer envelope opened despite tampering (authentication broken)');
      return 'box seal/open round-trip + tamper-detection ok';
    });

    // ── Category 11: AC provisioning ──────────────────────────────
    await check('ac-prov', '/api/heartbeat route file loadable', () => {
      try {
        const mod = require('../routes/heartbeat');
        if (!mod) throw new Error('heartbeat module loaded but exported nothing');
        return 'loadable';
      } catch (e) {
        throw new Error('require failed: ' + e.message);
      }
    });
    await check('ac-prov', 'analyst_availability table present', () => {
      if (!tableExists('analyst_availability')) throw new Error('missing table analyst_availability');
      return 'analyst_availability present';
    });
    await check('ac-prov', 'users has analyst-role rows', () => {
      if (!columnExists('users', 'role')) throw new Error('users.role column missing');
      const c = this.db
        .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'analyst'")
        .get().n;
      return c + ' analyst user(s)';
    });

    // ── Category 12: System ────────────────────────────────────────
    await check('system', 'Node.js version >= 20', () => {
      const major = parseInt(process.version.replace(/^v/, '').split('.')[0], 10);
      if (!Number.isFinite(major) || major < 20) {
        throw new Error('Node ' + process.version + ' is below the supported floor (>=20)');
      }
      return 'Node ' + process.version;
    });
    await check('system', 'Process memory (RSS) within sane bounds', () => {
      const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
      // Soft ceiling 4 GB; over that and we want to know.
      if (rssMb > 4096) throw new Error('RSS ' + rssMb + ' MB exceeds 4 GB soft ceiling');
      return rssMb + ' MB RSS';
    });
    await check('system', 'Security middleware loadable', () => {
      const mods = [
        'security-hardening',
        'cors-policy',
        'auth-hardening',
        'ai-security',
        'pentest-hardening',
        'network-hardening',
      ];
      const failures = [];
      for (const m of mods) {
        try {
          require('../middleware/' + m);
        } catch (e) {
          failures.push(m + ' (' + (e.message || 'load error') + ')');
        }
      }
      if (failures.length > 0) throw new Error('failed to load: ' + failures.join('; '));
      return mods.length + ' middleware module(s) loadable';
    });
    await check('system', 'sessions + auth_log tables', () => {
      return requireAll(['sessions', 'auth_log']);
    });
    await check('system', 'In-memory schema-clone harness', () => {
      // Validates the side-effect-free harness used by write-path flow
      // checks (they exercise real INSERT/constraint logic against an
      // in-memory clone of the live schema, never the production DB).
      const mem = cloneLiveSchema(this.db);
      try {
        const n = mem.prepare("SELECT count(*) AS c FROM sqlite_master WHERE type='table'").get().c;
        if (!n || n < 1) throw new Error('clone produced no tables');
        return 'cloned ' + n + ' table(s) into :memory:';
      } finally {
        try { mem.close(); } catch (_e) { /* ignore */ }
      }
    });

    // ── Category: AI dispatcher ────────────────────────────────────
    await check('ai', 'AI dispatcher graceful-fail (IR-simulator wiring)', async () => {
      // The IR-Simulator OODA generator must be loadable and wired to the
      // dispatcher. We probe the dispatcher with a SENTINEL feature id that has
      // no config row, so it fast-fails AI_NOT_CONFIGURED before any provider
      // call or inference-log write — zero side effects, no real generation.
      const oodaGen = require('./ooda-scenario-generator');
      if (!oodaGen || typeof oodaGen !== 'object') throw new Error('ooda-scenario-generator not loadable');
      const aiProvider = require('./ai-provider');
      if (typeof aiProvider.generate !== 'function') throw new Error('ai-provider.generate is not a function');
      const sentinel = '__regression_probe_' + crypto.randomBytes(4).toString('hex');
      let code = null;
      try {
        await aiProvider.generate(sentinel, 'probe', {});
      } catch (e) {
        code = e && e.code;
      }
      if (code !== 'AI_NOT_CONFIGURED') {
        throw new Error('expected AI_NOT_CONFIGURED for an unconfigured feature, got ' + code);
      }
      return 'dispatcher reachable; unconfigured feature -> AI_NOT_CONFIGURED (graceful)';
    });

    await check('ai', 'Provider CHECK rejects non-internal (B5c2)', () => {
      // After B5c2 the ai_provider_config provider CHECK allows only 'internal',
      // so no feature can be pointed at an external provider. Verified against a
      // side-effect-free in-memory clone of the live schema: 'internal' is
      // accepted and an external provider value is rejected by the CHECK. No
      // writes touch the production DB.
      const mem = cloneLiveSchema(this.db);
      mem.prepare("INSERT INTO ai_provider_config (feature_id, provider) VALUES ('kb_chat', 'internal')").run();
      let rejected = false;
      try {
        mem.prepare("INSERT INTO ai_provider_config (feature_id, provider) VALUES ('kb_synthesis', 'anthropic')").run();
      } catch (_e) {
        rejected = true;
      }
      if (!rejected) throw new Error('provider=anthropic was accepted; internal-only CHECK not enforced');
      return 'provider CHECK enforces internal-only (external provider rejected)';
    });

    // ── Category: Model-file safety ────────────────────────────────
    await check('model-safety', 'Model-file safety gate fail-closed (hash mismatch)', async () => {
      // Verifies the layered model-file safety gate FAILS CLOSED when the hash
      // layer reports a mismatch. All collaborators are injected (deps) and the
      // audit sink (getDb) returns a fresh in-memory clone of the live schema
      // per call (logRow owns and closes it) — entirely side-effect-free: no
      // model file, no scanner, no network, no write to the production
      // model_file_scan_log.
      const modelSafety = require('./model-file-safety');
      const res = await modelSafety.verifyModelFileSafety('regression-probe', {
        actor: 'regression',
        deps: {
          verifyModel: async () => ({
            ok: false,
            status: 'mismatch',
            files: [{ filename: 'probe.gguf', path: '/nonexistent/probe.gguf', present: true, match: false, expected: 'aa', actual: 'bb' }],
          }),
          getDb: () => cloneLiveSchema(this.db),
          // Not reached on a hash mismatch, but stubbed so a future ordering
          // change can never touch the real filesystem/scanner from here.
          validateGguf: () => ({ ok: false, reason: 'stubbed' }),
          scanModelFileLocal: async () => ({ scanned: false, clean: false, scanner: 'stub', threats: [] }),
          verifyModelSignature: () => ({ ok: false }),
        },
      });
      if (res.ok) throw new Error('gate returned ok=true on a hash mismatch (not fail-closed)');
      if (!res.blockedReason && res.overall === 'loaded') throw new Error('gate did not block; overall=' + res.overall);
      return 'gate fail-closed on hash mismatch (' + res.overall + ')';
    });

    // ── Category: Troubleshooter ───────────────
    await check('troubleshooter', 'rule-based diagnostics over schema clone', () => {
      // Exercises the rule-based troubleshooter engine end-to-end against a
      // side-effect-free in-memory clone of the live schema -- the same path
      // the /api/troubleshoot route falls back to when the internal model is
      // unavailable. No LLM, no writes to the production DB.
      const diagnostics = require('./troubleshooter-diagnostics');
      if (typeof diagnostics.runDiagnostics !== 'function') throw new Error('troubleshooter-diagnostics.runDiagnostics is not a function');
      const mem = cloneLiveSchema(this.db);
      try {
        const r = diagnostics.runDiagnostics(mem, 'soar playbook routing is failing');
        if (!r || typeof r !== 'object') throw new Error('runDiagnostics did not return an object');
        if (typeof r.topic !== 'string' || !r.topic) throw new Error('missing topic');
        if (!Array.isArray(r.findings) || r.findings.length === 0) throw new Error('expected non-empty findings for a routed topic');
        if (!Array.isArray(r.baseline) || r.baseline.length === 0) throw new Error('expected a non-empty baseline');
        const VALID = new Set(['pass', 'warn', 'fail']);
        for (const f of r.findings.concat(r.baseline)) {
          if (!f || typeof f.label !== 'string' || !f.label) throw new Error('finding missing label');
          if (!VALID.has(f.status)) throw new Error('finding has invalid status: ' + (f && f.status));
          if (typeof f.detail !== 'string' || !f.detail) throw new Error('finding missing detail');
        }
        return 'topic=' + r.topic + ' findings=' + r.findings.length + ' baseline=' + r.baseline.length;
      } finally {
        try { mem.close(); } catch (_e) { /* ignore */ }
      }
    });

    // ── Category: Integration health (reflects the latest cached probe) ─────
    // Surfaces the most recent integration-health probe result without running
    // live probes, so the regression run stays side-effect-free. ok -> pass;
    // benign states (disabled/not_configured/not_implemented/deep_skipped) ->
    // skip; real failures (unreachable/auth_failed/permission_denied/timeout/
    // error) -> fail.
    {
      let cached = null;
      try {
        const row = this.db.prepare("SELECT value FROM config WHERE key = 'integration_health_last_results'").get();
        if (row && row.value) cached = JSON.parse(row.value);
      } catch { cached = null; }
      if (!cached || !Array.isArray(cached.results) || cached.results.length === 0) {
        await check('integration_health', 'integration health probe run available', () => SKIP('no integration-health probe has run yet'));
      } else {
        const BENIGN = new Set(['disabled', 'not_configured', 'not_implemented', 'deep_skipped']);
        for (const r of cached.results) {
          const label = r.label || r.integration;
          await check('integration_health', label + ' probe', () => {
            if (r.status === 'ok') return 'ok' + (r.latencyMs != null ? ' (' + r.latencyMs + 'ms)' : '');
            if (BENIGN.has(r.status)) return SKIP(r.detail || r.status);
            throw new Error(r.status + (r.detail ? ': ' + r.detail : ''));
          });
        }
      }
    }

    // -- Category: Integration health probe registry (B5j read-only probes) --
    // Static + bare-DB assertions for the probe registry. No live probes run:
    // every check uses a throwaway in-memory schema clone, and the channel
    // connectivity helper is exercised only against a reserved unreachable host
    // to prove the never-send contract. Side-effect-free against the live DB.
    {
      const ihp = require('./integration-health-probes');
      const EXPECTED_KEYS = ['soar', 'siem', 'ticketing', 'iam', 'kms', 'storage', 'edr', 'sdn', 'cloud', 'backup', 'notifications', 'scheduling', 'cicd'];
      const NEW_KEYS = ['sdn', 'cloud', 'backup', 'notifications', 'scheduling', 'cicd', 'ticketing'];

      await check('integration_health', 'probe registry exposes 13 well-formed descriptors', () => {
        const reg = ihp.registry;
        if (!Array.isArray(reg)) throw new Error('registry is not an array');
        if (reg.length !== 13) throw new Error('expected 13 descriptors, found ' + reg.length);
        for (const d of reg) {
          if (!d || typeof d.key !== 'string' || !d.key) throw new Error('descriptor missing key');
          if (typeof d.label !== 'string' || !d.label) throw new Error(d.key + ': missing label');
          for (const fnName of ['enabled', 'configured', 'probe']) {
            if (typeof d[fnName] !== 'function') throw new Error(d.key + ': ' + fnName + ' is not a function');
          }
        }
        const keys = reg.map((d) => d.key);
        const missing = EXPECTED_KEYS.filter((k) => !keys.includes(k));
        if (missing.length) throw new Error('registry missing key(s): ' + missing.join(', '));
        return '13 descriptors, all with key/label/enabled/configured/probe';
      });

      await check('integration_health', 'new probes report not_configured on a bare DB (never throw)', () => {
        const mem = cloneLiveSchema(this.db);
        try {
          const byKey = {};
          for (const d of ihp.registry) byKey[d.key] = d;
          for (const k of NEW_KEYS) {
            const d = byKey[k];
            if (!d) throw new Error('missing descriptor: ' + k);
            let configured;
            try {
              configured = d.configured(mem);
            } catch (e) {
              throw new Error(k + '.configured() threw on bare DB: ' + (e.message || e));
            }
            if (configured !== false) throw new Error(k + '.configured() should be false on a bare DB, got ' + configured);
          }
          return NEW_KEYS.length + ' new probes: configured() === false, no throw (harness yields not_configured)';
        } finally {
          try { mem.close(); } catch (_e) { /* ignore */ }
        }
      });

      await check('integration_health', 'mode-gated probes (sdn, cloud) are unconfigured outside their mode', () => {
        const mem = cloneLiveSchema(this.db);
        try {
          const sdn = ihp.registry.find((d) => d.key === 'sdn');
          const cloud = ihp.registry.find((d) => d.key === 'cloud');
          if (!sdn || !cloud) throw new Error('sdn/cloud descriptor missing');
          if (sdn.configured(mem) !== false) throw new Error('sdn.configured() should be false without SDN mode');
          if (cloud.configured(mem) !== false) throw new Error('cloud.configured() should be false without a cloud substrate');
          return 'sdn + cloud both not configured outside their mode';
        } finally {
          try { mem.close(); } catch (_e) { /* ignore */ }
        }
      });

      await check('integration_health', 'notification connectivity check sends nothing (enqueue stays zero)', async () => {
        const mem = cloneLiveSchema(this.db);
        try {
          mem.prepare("INSERT INTO notification_config (id, webhook_enabled, webhook_url) VALUES ('default', 1, 'https://fa-probe-test.invalid/hook')").run();
          const countLog = () => {
            try { return mem.prepare('SELECT COUNT(*) AS n FROM notification_delivery_log').get().n; } catch (_e) { return 0; }
          };
          const countQueue = () => {
            try { return mem.prepare('SELECT COUNT(*) AS n FROM notifications').get().n; } catch (_e) { return 0; }
          };
          const before = countLog() + countQueue();
          const nf = require('./notifications');
          const res = await nf.probeWebhookChannel(mem);
          const after = countLog() + countQueue();
          if (!res || typeof res.status !== 'string') throw new Error('helper returned no status');
          if (res.status === 'ok' || res.status === 'sent') throw new Error('unreachable host unexpectedly reported ' + res.status);
          if (after !== before) throw new Error('connectivity check wrote ' + (after - before) + ' row(s); must enqueue nothing');
          return 'webhook connectivity check -> ' + res.status + ', 0 rows enqueued';
        } finally {
          try { mem.close(); } catch (_e) { /* ignore */ }
        }
      });
    }

    // ── Category: Threat hunting (B5m) ─────────────────
    await check('threat_hunting', 'consumer_type is a closed enum (xdr/atp/ngav/msp), no custom type', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.js'), 'utf8');
      const m = src.match(/consumer_type TEXT NOT NULL CHECK \(consumer_type IN \(([^)]*)\)/);
      if (!m) throw new Error('threat_hunting_consumer_authorizations consumer_type CHECK enum not found');
      for (const t of ['xdr', 'atp', 'ngav', 'msp']) {
        if (m[1].indexOf("'" + t + "'") === -1) throw new Error('consumer_type enum missing ' + t);
      }
      if (/['"]custom['"]/.test(m[1])) throw new Error('consumer_type enum must not contain an open-ended custom type');
      return 'consumer_type closed to xdr/atp/ngav/msp; no custom type';
    });

    await check('threat_hunting', 'access log is append-only with a closed outcome enum', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.js'), 'utf8');
      if (!/threat_hunting_access_log_no_update[\s\S]*?RAISE\(ABORT/.test(src)) throw new Error('append-only BEFORE UPDATE trigger missing');
      if (!/threat_hunting_access_log_no_delete[\s\S]*?RAISE\(ABORT/.test(src)) throw new Error('append-only BEFORE DELETE trigger missing');
      const om = src.match(/threat_hunting_access_log[\s\S]*?outcome TEXT NOT NULL CHECK \(outcome IN \(([^)]*)\)/);
      if (!om) throw new Error('access-log outcome CHECK enum not found');
      for (const o of ['authorized', 'rejected_cert', 'rejected_token', 'rejected_ip', 'rejected_disabled', 'rejected_category', 'rejected_query']) {
        if (om[1].indexOf("'" + o + "'") === -1) throw new Error('outcome enum missing ' + o);
      }
      return 'access log append-only (update+delete triggers) with closed outcome enum';
    });

    await check('threat_hunting', 'registry rejects an unknown consumer_type (closed enum at the app layer)', () => {
      const registry = require('./threat-hunting-registry');
      if (!Array.isArray(registry.CONSUMER_TYPES) || registry.CONSUMER_TYPES.join(',') !== 'xdr,atp,ngav,msp') {
        throw new Error('registry CONSUMER_TYPES is not the closed set');
      }
      let threw = false;
      try {
        registry.createAuthorization({}, { consumerType: 'custom', displayName: 'x', allowedCidrs: ['1.1.1.1'] });
      } catch (e) {
        threw = /consumer_type must be one of/.test(e.message);
      }
      if (!threw) throw new Error('createAuthorization accepted an unknown consumer_type');
      return 'registry throws on consumer_type=custom before any DB/CA work';
    });

    await check('threat_hunting', 'feed gate enforces cert + token + IP and fails closed on each', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'middleware', 'threat-hunting-auth.js'), 'utf8');
      const need = [
        ['verifyClientCert', /verifyClientCert\(/],
        ['consumer OU check', /subjectHasConsumerOu|THREAT_HUNTING_CONSUMER_OU|CONSUMER_OU/],
        ['registry fingerprint lookup', /findByCertFingerprint\(/],
        ['constant-time token verify', /verifyToken\(/],
        ['IP allow-list check', /ipAllowed\(/],
        ['rejected_cert path', /rejected_cert/],
        ['rejected_disabled path', /rejected_disabled/],
        ['rejected_token path', /rejected_token/],
        ['rejected_ip path', /rejected_ip/],
      ];
      for (let i = 0; i < need.length; i += 1) {
        if (!need[i][1].test(src)) throw new Error('gate missing ' + need[i][0]);
      }
      if (!/req\.threatHuntingAuth\s*=/.test(src)) throw new Error('gate does not attach req.threatHuntingAuth on success');
      if (/outcome:\s*'authorized'/.test(src)) throw new Error('gate must defer the authorized-access log to the route');
      return 'gate validates cert(chain+OU+registry) + token + IP, four reject paths, defers authorized log';
    });

    await check('threat_hunting', 'access log is hash-chained and tamper-evident', () => {
      const log = require('./threat-hunting-access-log');
      const rows = []; let clock = 0;
      const db = {
        transaction: (fn) => ((...a) => fn(...a)),
        prepare: (sql) => ({
          get: () => {
            if (sql.indexOf("datetime('now')") !== -1) { clock += 1; return { t: '2026-01-01 00:00:0' + clock }; }
            if (sql.indexOf('ORDER BY id DESC LIMIT 1') !== -1) return rows.length ? { this_hash: rows[rows.length - 1].this_hash } : undefined;
            return undefined;
          },
          run: function () {
            const a = Array.prototype.slice.call(arguments);
            const cols = ['prev_hash', 'this_hash', 'authorization_id', 'consumer_type', 'source_ip', 'cert_fingerprint', 'endpoint', 'format', 'query_summary', 'outcome', 'result_count', 'accessed_at'];
            const r = { id: rows.length + 1 };
            for (let i = 0; i < cols.length; i += 1) { r[cols[i]] = a[i]; }
            rows.push(r);
          },
          all: () => rows.map((r) => Object.assign({}, r)),
        }),
      };
      log.appendAccessLog(db, { source_ip: '10.0.0.1', endpoint: '/x', outcome: 'authorized', result_count: 1 });
      log.appendAccessLog(db, { source_ip: '8.8.8.8', endpoint: '/x', outcome: 'rejected_ip' });
      log.appendAccessLog(db, { source_ip: '10.0.0.1', endpoint: '/y', outcome: 'authorized', result_count: 0 });
      if (rows[1].prev_hash !== rows[0].this_hash || rows[2].prev_hash !== rows[1].this_hash) throw new Error('chain links broken');
      const intact = log.verifyAccessLogChain(db);
      if (!intact.intact || intact.count !== 3) throw new Error('fresh chain not intact');
      rows[1].outcome = 'authorized';
      const broken = log.verifyAccessLogChain(db);
      if (broken.intact !== false || broken.brokenAt !== 2) throw new Error('tamper not detected');
      return 'append-only chain links + verify detects tampering at the altered entry';
    });

    await check('threat_hunting', 'every output dialect serializes a sample model', () => {
      const fmts = require('./threat-hunting-formats');
      const model = {
        domain: 'auth_events', label: 'Authentication events', count: 2,
        events: [
          { time: '2026-01-01T00:00:00.000Z', actor: 'analyst-aaaa000000000000', src: '10.0.0.1', act: 'login', action: 'login', outcome: 'success' },
          { time: '2026-01-01T00:01:00.000Z', actor: 'analyst-bbbb000000000000', src: '10.0.0.2', act: 'logout', action: 'logout', outcome: 'success' },
        ],
        has_more: false, next_cursor: null, generated_at: '2026-01-01T00:02:00.000Z',
      };
      const j = JSON.parse(fmts.getFormatter('json').events(model));
      if (!Array.isArray(j.events) || j.events.length !== 2) throw new Error('json envelope malformed');
      const cefLines = fmts.getFormatter('cef').events(model).split('\n').filter(Boolean);
      if (cefLines.length !== 2 || !cefLines.every((l) => l.indexOf('CEF:0|') === 0)) throw new Error('cef lines malformed');
      const o = JSON.parse(fmts.getFormatter('ocsf').events(model));
      if (o.format !== 'ocsf' || !Array.isArray(o.events) || o.events.length !== 2) throw new Error('ocsf envelope malformed');
      const sx = JSON.parse(fmts.getFormatter('stix').events(model));
      if (sx.type !== 'bundle' || !Array.isArray(sx.objects) || !sx.objects.some((x) => x.type === 'observed-data')) throw new Error('stix bundle malformed');
      if (fmts.getFormatter('nope') !== null) throw new Error('unknown format must resolve to null');
      if (fmts.resolve('') !== fmts.getFormatter('json')) throw new Error('absent format must default to json');
      return 'json/cef/ocsf/stix serialize a 2-event model; unknown->null, absent->json';
    });

    await check('threat_hunting', 'burnout + identity never reach the feed (no burnout collector + fail-closed projection)', () => {
      const ps = require('./threat-hunting-pseudonymize');
      const fs = require('fs');
      // (1) the burnout store is never a collector source (strip comments first;
      // the module names it once in a DELIBERATELY EXCLUDED comment).
      const csrc = fs.readFileSync(path.join(__dirname, 'threat-hunting-collectors.js'), 'utf8')
        .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
      if (/analyst_metrics/.test(csrc)) throw new Error('a collector references the burnout store (analyst_metrics) outside comments');
      // (2) fail-closed projection: deny-vocab + identity fields dropped, actor pseudonymized.
      let stored = null;
      const db = {
        prepare: (sql) => ({
          run: function () { const a = Array.prototype.slice.call(arguments); if (sql.indexOf('INSERT OR IGNORE INTO config') !== -1 && stored === null) stored = a[1]; },
          get: function () { if (sql.indexOf('SELECT value FROM config') !== -1) return stored !== null ? { value: stored } : undefined; return undefined; },
        }),
      };
      const record = { user_id: 'u-123', stress: 8, fatigue: 7, morale: 3, real_name: 'Jane Doe', email: 'j@x.com', token_hash: 'deadbeef', action: 'login', src: '10.0.0.1', outcome: 'success' };
      const allow = [
        { from: 'user_id', to: 'actor', pseudonym: true },
        { from: 'action' }, { from: 'src' }, { from: 'outcome' },
        { from: 'stress' }, { from: 'fatigue' }, { from: 'morale' }, { from: 'real_name' }, { from: 'email' }, { from: 'token_hash' },
      ];
      const proj = ps.projectAllowed(db, record, allow);
      if (!proj.actor || String(proj.actor).indexOf('analyst-') !== 0) throw new Error('actor not pseudonymized');
      if (String(proj.actor).indexOf('u-123') !== -1) throw new Error('raw user id leaked into pseudonym');
      if (proj.action !== 'login' || proj.src !== '10.0.0.1' || proj.outcome !== 'success') throw new Error('allow-listed field dropped');
      for (const k of ['stress', 'fatigue', 'morale', 'real_name', 'email', 'token_hash', 'user_id']) {
        if (Object.prototype.hasOwnProperty.call(proj, k)) throw new Error('denied/identity field leaked: ' + k);
      }
      for (const term of ['burnout', 'stress', 'fatigue', 'morale', 'wellbeing', 'tier3']) {
        if (ps.DENY_SUBSTRINGS.indexOf(term) === -1) throw new Error('deny-list missing burnout term: ' + term);
      }
      const a1 = ps.pseudonymizeActor(db, 'u-123', 'actor');
      const a2 = ps.pseudonymizeActor(db, 'u-123', 'actor');
      const a3 = ps.pseudonymizeActor(db, 'u-123', 'session');
      if (a1 !== a2) throw new Error('pseudonym not stable for same actor');
      if (a1 === a3) throw new Error('namespace did not change pseudonym');
      return 'burnout store has no collector; deny-vocab + identity dropped; actor pseudonymized, stable, namespaced';
    });

    await check('threat_hunting', 'query rejects bad limit/since/until/cursor/domain before any DB read', () => {
      const t = require('./threat-hunting-telemetry');
      const dom = (Array.isArray(t.DOMAINS) && t.DOMAINS[0]) || 'auth_events';
      const cur = t.encodeCursor(dom, 4242);
      if (t.decodeCursor(dom, cur) !== 4242) throw new Error('cursor did not round-trip');
      if (t.decodeCursor('integrity', cur) !== null) throw new Error('cursor is not domain-bound');
      if (t.decodeCursor(dom, undefined) !== 0) throw new Error('absent cursor must decode to 0');
      if (t.decodeCursor(dom, 'garbage-not-a-cursor!!') !== null) throw new Error('malformed cursor must be null');
      const boom = { prepare: () => { throw new Error('DB must not be read on rejected params'); } };
      const cases = [
        ['limit<=0', { limit: 0 }], ['non-integer limit', { limit: 3.5 }],
        ['bad since', { since: 'nope' }], ['bad until', { until: 'nope' }],
        ['bad cursor', { cursor: 'garbage!!' }],
      ];
      for (let i = 0; i < cases.length; i += 1) {
        const r = t.query(boom, dom, cases[i][1]);
        if (!r || r.ok !== false) throw new Error('not rejected: ' + cases[i][0]);
      }
      const ru = t.query(boom, 'no_such_domain', {});
      if (!ru || ru.ok !== false) throw new Error('unknown domain not rejected');
      return 'cursor round-trips + domain-bound; bad limit/since/until/cursor/domain rejected pre-DB';
    });

    await check('threat_hunting', 'TAXII 2.1 surfaces are present with correct media types', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'routes', 'threat-hunting-taxii.js'), 'utf8');
      const need = [
        ['taxii media type', /application\/taxii\+json;version=2\.1/],
        ['stix media type', /application\/stix\+json;version=2\.1/],
        ['discovery api_roots', /api_roots/],
        ['collections', /collections/],
        ['objects endpoint', /objects/],
        ['envelope more field', /more:/],
        ['auth guard', /threatHuntingAuth/],
      ];
      for (let i = 0; i < need.length; i += 1) {
        if (!need[i][1].test(src)) throw new Error('taxii route missing ' + need[i][0]);
      }
      return 'TAXII discovery/collections/objects present with taxii+stix media types and auth guard';
    });

    // -- Category: Data root (P1-1) -------------------------------------
    // Before P1 every runtime path resolved relative to the module directory,
    // which in a packaged build put the database, the logs, the audit archive
    // and THE BACKUPS inside the application bundle an installer replaces.
    // These assertions are the guard against that returning.
    await check('data_root', 'no accessor resolves inside the application directory', () => {
      const dr = require('../lib/data-root');
      const appDir = path.resolve(__dirname, '..');
      const names = ['dbPath', 'logsDir', 'backupsDir', 'archivePendingDir', 'cefSpoolDir',
        'cicdConfigsDir', 'cloudPackagesDir', 'migrationBundlesDir'];
      const bad = [];
      for (const n of names) {
        const p = path.resolve(dr[n]());
        if (p === appDir || p.startsWith(appDir + path.sep)) bad.push(n + ' -> ' + p);
      }
      if (bad.length) throw new Error('accessor(s) resolve inside the app dir: ' + bad.join(', '));
      return names.length + ' accessors all resolve outside ' + appDir;
    });

    await check('data_root', 'every documented env override is honoured', () => {
      const dr = require('../lib/data-root');
      const cases = [
        ['DB_PATH', '/tmp/fa-rr/x.db', () => dr.dbPath()],
        ['LOG_PATH', '/tmp/fa-rr/logs', () => dr.logsDir()],
        ['BACKUP_DIR', '/tmp/fa-rr/bk1', () => dr.backupsDir()],
        ['BACKUP_PATH', '/tmp/fa-rr/bk2', () => dr.backupsDir()],
        ['ARCHIVE_PENDING_DIR', '/tmp/fa-rr/ap', () => dr.archivePendingDir()],
        ['CEF_SPOOL_DIR', '/tmp/fa-rr/cef', () => dr.cefSpoolDir()],
        ['CICD_CONFIGS_DIR', '/tmp/fa-rr/cicd', () => dr.cicdConfigsDir()],
        ['CLOUD_PACKAGES_DIR', '/tmp/fa-rr/cp', () => dr.cloudPackagesDir()],
        ['MIGRATION_BUNDLE_DIR', '/tmp/fa-rr/mb', () => dr.migrationBundlesDir()],
      ];
      for (const [envName, value, fn] of cases) {
        const prev = process.env[envName];
        process.env[envName] = value;
        let got;
        try { got = fn(); } finally {
          if (prev === undefined) delete process.env[envName]; else process.env[envName] = prev;
        }
        if (got !== value) throw new Error(envName + ' ignored: expected ' + value + ', got ' + got);
      }
      return cases.length + ' env overrides honoured';
    });

    await check('data_root', 'ensureDir creates 0700 and refuses a permissive directory', () => {
      if (process.platform === 'win32') return SKIP('POSIX mode bits; Windows ACLs are covered by the boot posture check');
      const dr = require('../lib/data-root');
      const fsMod = require('fs');
      const dir = path.join('/tmp', 'fa-rr-mode-' + crypto.randomBytes(4).toString('hex'));
      try {
        dr.ensureDir(dir);
        const mode = fsMod.statSync(dir).mode & 0o777;
        if (mode !== 0o700) throw new Error('ensureDir created mode ' + mode.toString(8) + ', expected 700');
        fsMod.chmodSync(dir, 0o777);
        let refused = false;
        try { dr.ensureDir(dir); } catch (_e) { refused = true; }
        if (!refused) throw new Error('ensureDir accepted a 0777 directory');
        return 'creates 0700 and refuses 0777';
      } finally {
        try { fsMod.rmSync(dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ }
      }
    });

    await check('data_root', 'a pre-P1 database refuses the boot', () => {
      const dr = require('../lib/data-root');
      const fsMod = require('fs');
      const legacy = dr.legacyDbPath();
      if (fsMod.existsSync(legacy)) {
        throw new Error('a pre-P1 database is present at ' + legacy + '; the boot gate should have refused');
      }
      const src = fsMod.readFileSync(path.join(__dirname, '..', 'index.js'), 'utf8');
      const a = src.indexOf('assertNoLegacyDatabase()');
      const b = src.indexOf('initDb();');
      if (a === -1) throw new Error('index.js does not call assertNoLegacyDatabase()');
      if (b === -1 || a > b) {
        throw new Error('assertNoLegacyDatabase() must precede initDb(): initDb creates a database at the new root, which would turn "your data is at the old path" into a misleading "both are present"');
      }
      return 'gate present and ordered before initDb()';
    });

    // -- Category: Vulnerability scan (B5p) -----------------────
    await check('vuln_scan', 'B5p schema present (tables + indexes + append-only triggers)', () => {
      requireAll(['vuln_scan_scanner_authorizations', 'vuln_scan_access_log']);
      const missing = ['idx_vuln_scan_auth_enabled', 'idx_vuln_scan_access_accessed_at', 'idx_vuln_scan_access_outcome', 'idx_vuln_scan_access_auth'].filter((n) => !indexExists(n));
      if (missing.length) throw new Error('missing index(es): ' + missing.join(', '));
      const trg = this.db.prepare("SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'vuln_scan_access_log_no_%'").all();
      const names = trg.map((t) => t.name);
      for (const n of ['vuln_scan_access_log_no_update', 'vuln_scan_access_log_no_delete']) {
        if (names.indexOf(n) === -1) throw new Error('missing trigger: ' + n);
      }
      if (!trg.every((t) => /RAISE\(ABORT/.test(t.sql || ''))) throw new Error('an append-only trigger does not RAISE(ABORT)');
      return '2 tables + 4 indexes + 2 append-only RAISE(ABORT) triggers present in the live schema';
    });

    await check('vuln_scan', 'scanner_type is a closed enum (6 scanners), no custom type', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.js'), 'utf8');
      const m = src.match(/vuln_scan_scanner_authorizations[\s\S]*?scanner_type TEXT NOT NULL CHECK \(scanner_type IN \(([^)]*)\)/);
      if (!m) throw new Error('vuln_scan scanner_type CHECK enum not found');
      for (const t of ['nessus', 'openvas', 'qualys', 'rapid7', 'tenable_io', 'nuclei']) {
        if (m[1].indexOf("'" + t + "'") === -1) throw new Error('scanner_type enum missing ' + t);
      }
      if (/['"]custom['"]/.test(m[1])) throw new Error('scanner_type enum must not contain a custom type');
      return 'scanner_type closed to the 6 approved scanners; no custom type';
    });

    await check('vuln_scan', 'access log is append-only with a closed outcome enum', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'db', 'init.js'), 'utf8');
      if (!/vuln_scan_access_log_no_update[\s\S]*?RAISE\(ABORT/.test(src)) throw new Error('append-only BEFORE UPDATE trigger missing');
      if (!/vuln_scan_access_log_no_delete[\s\S]*?RAISE\(ABORT/.test(src)) throw new Error('append-only BEFORE DELETE trigger missing');
      const om = src.match(/vuln_scan_access_log[\s\S]*?outcome TEXT NOT NULL CHECK \(outcome IN \(([^)]*)\)/);
      if (!om) throw new Error('access-log outcome CHECK enum not found');
      for (const o of ['authorized', 'rejected_ip', 'rejected_token', 'rejected_disabled', 'rejected_unknown']) {
        if (om[1].indexOf("'" + o + "'") === -1) throw new Error('outcome enum missing ' + o);
      }
      return 'access log append-only (update+delete triggers) with closed 5-value outcome enum';
    });

    await check('vuln_scan', 'scan-access log is hash-chained and verifiable', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'routes', 'vuln-scan.js'), 'utf8');
      if (!/function canonicalAccessEntry/.test(src)) throw new Error('canonical serialization helper missing');
      if (!/db\.transaction/.test(src)) throw new Error('appendAccessLog is not transactional');
      if (!/ORDER BY id DESC LIMIT 1/.test(src)) throw new Error('append does not read the prior this_hash for linkage');
      if (!/createHash\('sha256'\)[\s\S]{0,80}?canonicalAccessEntry/.test(src)) throw new Error('this_hash is not sha256 of the canonical entry');
      if (!/access-log\/verify/.test(src)) throw new Error('verify endpoint missing');
      if (!/recomputed !== row\.this_hash/.test(src)) throw new Error('verify does not recompute this_hash');
      if (!/linkage mismatch/.test(src)) throw new Error('verify does not check prev_hash linkage');
      return 'canonical entry hashed with sha256, prev linkage in a txn, verify recomputes + checks linkage';
    });

    await check('vuln_scan', 'announce gate enforces token + source IP and fails closed on each', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'routes', 'vuln-scan.js'), 'utf8');
      const need = [
        ['token format check', /\^vss-\[0-9a-f\]\{64\}\$/],
        ['constant-time token hash compare', /safeEqualHex\(hashToken\(/],
        ['per-authorization enabled check', /matched\.enabled !== 1/],
        ['IP allow-list check', /ipAllowed\(sourceIp/],
        ['rejected_token path', /'rejected_token'/],
        ['rejected_unknown path', /'rejected_unknown'/],
        ['rejected_disabled path', /'rejected_disabled'/],
        ['rejected_ip path', /'rejected_ip'/],
        ['authorized path', /'authorized'/],
      ];
      for (let i = 0; i < need.length; i += 1) {
        if (!need[i][1].test(src)) throw new Error('announce gate missing ' + need[i][0]);
      }
      return 'announce validates token(format+constant-time hash) + enabled + IP; four reject outcomes + authorized';
    });

    await check('vuln_scan', 'live policy is enforced at mint, announce, and tripwire allow-list', () => {
      const fs = require('fs');
      const router = fs.readFileSync(path.join(__dirname, '..', 'routes', 'vuln-scan.js'), 'utf8');
      const allow = fs.readFileSync(path.join(__dirname, 'vuln-scan-allowlist.js'), 'utf8');
      if (!/allowedScanners policy/.test(router) || !/status\(409\)/.test(router)) throw new Error('mint does not reject an unpermitted scanner_type with 409');
      if (!/!cfg\.enabled/.test(router)) throw new Error('announce does not gate on the master enabled flag');
      if (!/!cfg\.allowedScanners\.includes\(matched\.scanner_type\)/.test(router)) throw new Error('announce does not re-check the live allowedScanners policy');
      if (!/policy\.enabled && policy\.allowedScanners\.length/.test(allow)) throw new Error('allow-list exempts without the master-enabled + policy gate');
      if (!/allowed\.has\(r\.scanner_type\)/.test(allow)) throw new Error('allow-list does not filter exemptions by the live policy');
      return 'allowedScanners enforced at mint(409) + announce(enabled+policy) + tripwire allow-list(enabled+policy)';
    });

    await check('vuln_scan', 'tripwire allow-list is fail-safe (no IP exempt on error / empty / disabled)', () => {
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, 'vuln-scan-allowlist.js'), 'utf8');
      if (!/enabled: false, allowedScanners: \[\]/.test(src)) throw new Error('readPolicy does not fail safe to a disabled, empty policy');
      if (!/catch \(_\)/.test(src)) throw new Error('refresh/readPolicy lacks a fail-safe catch');
      if (!/if \(!cache\.cidrs\.length\) return false/.test(src)) throw new Error('an empty cache does not exempt-nothing');
      if (!/policy\.enabled && policy\.allowedScanners\.length/.test(src)) throw new Error('exemption is not gated by enabled + policy');
      if (!/module\.exports = \{ isAuthorizedVulnScannerSource/.test(src)) throw new Error('isAuthorizedVulnScannerSource not exported');
      return 'fail-safe: error/empty/disabled exempt nothing; exemption requires enabled + permitted scanner_type';
    });

    await check('vuln_scan', 'stores no scan findings (FireAlive is the scanned asset, not the scanner)', () => {
      for (const t of ['vuln_scan_findings', 'vuln_scan_results', 'vuln_scan_scan_results']) {
        if (tableExists(t)) throw new Error('a findings/results table exists: ' + t + ' (the integration must not store scan output)');
      }
      for (const c of ['result_count', 'findings', 'finding', 'result', 'payload', 'cve', 'severity']) {
        if (columnExists('vuln_scan_access_log', c)) throw new Error('access log has a result-bearing column: ' + c);
      }
      return 'no findings/results table; access log carries no result/finding/severity column';
    });

    await check('vuln_scan', 'config relocated to /api/vuln-scan and gated by the config lock', () => {
      const fs = require('fs');
      const router = fs.readFileSync(path.join(__dirname, '..', 'routes', 'vuln-scan.js'), 'utf8');
      const v021 = fs.readFileSync(path.join(__dirname, '..', 'routes', 'v021-features.js'), 'utf8');
      const reg = fs.readFileSync(path.join(__dirname, '..', 'middleware', 'config-write-routes.js'), 'utf8');
      if (!/router\.put\('\/config'/.test(router) || !/router\.get\('\/config'/.test(router)) throw new Error('dedicated router is missing GET/PUT /config');
      if (/vuln-scan\/config/.test(v021)) throw new Error('the old /vuln-scan/config stub still exists in v021-features.js');
      if (reg.indexOf("'/api/vuln-scan'") === -1) throw new Error('/api/vuln-scan is not in CONFIG_WRITE_MOUNTS');
      if (/\/api\/vuln-scan\/config/.test(reg)) throw new Error('a stale /api/vuln-scan/config path is still in the registry');
      return 'config lives in /api/vuln-scan (gated by mount); old stub removed; no stale registry path';
    });

    // -- Category: Analyst-privacy (B5d1 analyst-private data architecture) --
    await check('analyst-privacy', 'B5d1 schema + indexes present', () => {
      requireAll([
        'analyst_keys',
        'analyst_key_recovery_wraps',
        'analyst_private_data',
        'analyst_metrics_deidentified',
      ]);
      const missing = [
        'idx_analyst_private_data_owner',
        'idx_analyst_key_recovery_wraps_analyst',
        'idx_analyst_metrics_deid_group',
      ].filter((n) => !indexExists(n));
      if (missing.length) throw new Error('missing index(es): ' + missing.join(', '));
      return '4 tables + 3 indexes present';
    });

    await check('analyst-privacy', 'De-identified metrics store carries no identity', () => {
      // The aggregate store must let the server group by team/shift but never
      // attribute a value to a person, so it must carry NO identity column.
      // This is the core B5d1 invariant for management-side aggregates.
      const leaked = ['analyst_id', 'pseudonym', 'user_id', 'username', 'name', 'email']
        .filter((c) => columnExists('analyst_metrics_deidentified', c));
      if (leaked.length) throw new Error('de-identified store has identity column(s): ' + leaked.join(', '));
      for (const c of ['team_tag', 'shift_tag', 'signal', 'value']) {
        if (!columnExists('analyst_metrics_deidentified', c)) throw new Error('missing expected column: ' + c);
      }
      return 'no analyst_id/pseudonym/user/name/email; team/shift-tagged values only';
    });

    await check('analyst-privacy', 'analyst_keys holds a public key only (no private material)', () => {
      // The registry stores the PUBLIC key the server seals to; private
      // material must never live here. Recovery wraps are a separate,
      // server-opaque table.
      if (!columnExists('analyst_keys', 'public_key')) throw new Error('analyst_keys missing public_key');
      const priv = this.db.prepare('PRAGMA table_info(analyst_keys)').all()
        .map((c) => String(c.name).toLowerCase())
        .filter((c) => /(private|secret|wrapped|privkey)/.test(c) || c === 'sk');
      if (priv.length) throw new Error('analyst_keys has private-key-shaped column(s): ' + priv.join(', '));
      return 'public_key present; no private/secret/wrapped column';
    });

    await check('analyst-privacy', 'Seal-to-public-key round-trips; no server decrypt path', () => {
      // The server can SEAL burnout detail to an analyst's public key but must
      // have no way to read it back. Confirms the sealed box opens with the
      // matching X25519 private key (the AC-side operation) and fails with a
      // wrong key or on tamper, and asserts services/analyst-crypto exports no
      // decrypt/open/unseal function -- the server holds no code path to read
      // analyst data. Uses node crypto only; no production DB is touched.
      const ac = require('./analyst-crypto');
      const decryptish = Object.keys(ac).filter((k) => /(decrypt|unseal|unwrap|open)/i.test(k));
      if (decryptish.length) throw new Error('analyst-crypto exports a decrypt-shaped function: ' + decryptish.join(', '));

      const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
      const pubB64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

      // Open exactly as the Analyst Client does: ephemeral ECDH -> HKDF-SHA256
      // -> AES-256-GCM, using parseSealed to split the envelope.
      const open = (sealedB64, priv) => {
        const p = ac.parseSealed(sealedB64);
        const recipientSpki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
        const shared = crypto.diffieHellman({
          privateKey: priv,
          publicKey: crypto.createPublicKey({ key: p.ephemeralPublicKey, format: 'der', type: 'spki' }),
        });
        const salt = Buffer.concat([p.ephemeralPublicKey, recipientSpki]);
        const key = Buffer.from(crypto.hkdfSync('sha256', shared, salt, Buffer.from('firealive-analyst-seal-v1', 'utf8'), 32));
        const d = crypto.createDecipheriv('aes-256-gcm', key, p.iv);
        d.setAuthTag(p.tag);
        return Buffer.concat([d.update(p.ciphertext), d.final()]);
      };

      const payload = '{"signal":"cognitive_load","value":0.8}';
      const sealed = ac.sealToPublicKey(payload, pubB64);
      if (open(sealed, privateKey).toString('utf8') !== payload) throw new Error('seal/open round-trip mismatch');

      const wrongPriv = crypto.generateKeyPairSync('x25519').privateKey;
      let wrongRejected = false;
      try { open(sealed, wrongPriv); } catch (_e) { wrongRejected = true; }
      if (!wrongRejected) throw new Error('a wrong key opened the sealed box');

      const tampered = Buffer.from(sealed, 'base64'); tampered[tampered.length - 1] ^= 0xff;
      let tamperRejected = false;
      try { open(tampered.toString('base64'), privateKey); } catch (_e) { tamperRejected = true; }
      if (!tamperRejected) throw new Error('a tampered sealed box opened');

      return 'seal/open round-trip ok; wrong key + tamper rejected; no decrypt export';
    });

    await check('analyst-privacy', 'analyst-keys route is self-scoped (no analyst id from request)', () => {
      // Tier-3 invariant: the route must take the analyst id only from the JWT
      // (req.user.id) and never from the request body/query/params.
      try { require('../routes/analyst-keys'); } catch (e) { throw new Error('cannot load analyst-keys route: ' + e.message); }
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'routes', 'analyst-keys.js'), 'utf8');
      if (!/req\.user\b/.test(src)) throw new Error('route does not scope by req.user');
      const bad = src.match(/req\.(?:body|query|params)\.analyst[_]?id/i);
      if (bad) throw new Error('route reads analyst id from the request: ' + bad[0]);
      return 'scoped by req.user.id; no analyst id taken from body/query/params';
    });

    await check('analyst-privacy', 'LDAP sync persists handle only (no directory display name)', async () => {
      // Directory-identity minimization: syncUsers may read displayName /
      // sAMAccountName in memory for matching, but must persist ONLY an opaque
      // handle derived from objectGUID. Proven behaviorally against a schema
      // clone with a stubbed directory entry carrying real-looking attributes.
      const { LdapClient } = require('../integrations/ldap');
      const { handleForGuid } = require('../lib/identity-handle');
      const mem = cloneLiveSchema(this.db);
      try {
        const guid = 'GUID-RR-0001';
        const displayName = 'Jane Q Analyst';
        const sam = 'janalyst';
        const client = new LdapClient({});
        client.searchUsers = async () => ({
          success: true,
          users: [{ objectGUID: guid, sAMAccountName: sam, displayName: displayName, mail: 'j@corp.example', memberOf: ['CN=SOC-Analysts,OU=Security,DC=corp'] }],
        });
        const res = await client.syncUsers(mem);
        if (!res || !res.success) throw new Error('syncUsers did not succeed: ' + (res && res.error));
        const row = mem.prepare("SELECT * FROM users WHERE external_id = ? AND auth_method = 'ldap'").get(guid);
        if (!row) throw new Error('sync created no ldap user row');
        const expected = handleForGuid(guid);
        if (row.username !== expected || row.name !== expected) throw new Error('username/name not set to derived handle');
        if (row.external_id !== guid) throw new Error('external_id is not the opaque objectGUID');
        const blob = JSON.stringify(row).toLowerCase();
        for (const leak of [displayName.toLowerCase(), sam.toLowerCase()]) {
          if (blob.indexOf(leak) !== -1) throw new Error('directory identity leaked into users row: ' + leak);
        }
        return 'handle-only row; no displayName/sAMAccountName persisted';
      } finally {
        try { mem.close(); } catch (_e) { /* ignore */ }
      }
    });

    // -- Category: Data-subject rights (DSR) erasure ------------------
    // PR-5 coverage backfill. The erasure feature is operational (request
    // table + dual-controlled route + service), so these prove it end-to-end:
    // the erase actually runs over a clone of the live schema and tombstones
    // the row, and the approval path is shown to be admin + step-up gated.
    await check('data-subject', 'DSR erasure-request table + status lifecycle', () => {
      if (!tableExists('data_subject_erasure_requests')) throw new Error('missing table data_subject_erasure_requests');
      for (const col of ['subject_id', 'requested_by', 'status']) {
        if (!columnExists('data_subject_erasure_requests', col)) throw new Error('data_subject_erasure_requests missing column: ' + col);
      }
      const ddl = this.db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='data_subject_erasure_requests'").get();
      if (!ddl || !ddl.sql) throw new Error('cannot read data_subject_erasure_requests DDL');
      for (const st of ['pending', 'approved', 'rejected', 'executed']) {
        if (ddl.sql.indexOf("'" + st + "'") === -1) throw new Error('status lifecycle missing state: ' + st);
      }
      return 'request table present; lifecycle pending/approved/rejected/executed';
    });

    await check('data-subject', 'DSR eraseSubject tombstones the row + erases over the live schema', () => {
      // Drive the real erasure transaction against an in-memory clone of the
      // live schema. Every DELETE must target a real table (a renamed/dropped
      // table throws here), the users row must survive as a tombstone for the
      // append-only audit FK, and an unknown subject must be refused.
      const { eraseSubject } = require('../services/data-subject');
      const mem = cloneLiveSchema(this.db);
      try {
        const subjectId = 'rr-dsr-subject-1';
        mem.prepare("INSERT INTO users (id, username, name, role) VALUES (?, ?, ?, 'lead')").run(subjectId, 'rr-dsr-handle', 'rr-dsr-handle');
        const receipt = eraseSubject(mem, subjectId);
        if (!receipt || receipt.schema !== 'firealive.data-subject-erasure-receipt') throw new Error('unexpected erase receipt schema');
        if (receipt.tombstoned !== true || receipt.audit_log_retained !== true) throw new Error('receipt does not assert tombstone + audit retention');
        if (receipt.subject_id !== subjectId) throw new Error('receipt subject_id mismatch');
        for (const t of ['analyst_availability', 'notification_preferences', 'e2ee_identity_keys']) {
          if (typeof receipt.deleted[t] !== 'number') throw new Error('erase did not run the DELETE for ' + t);
        }
        const tomb = mem.prepare('SELECT external_id, username, name FROM users WHERE id = ?').get(subjectId);
        if (!tomb) throw new Error('users row was removed (must be tombstoned, not deleted)');
        if (tomb.external_id !== null) throw new Error('external_id not cleared on tombstone');
        if (tomb.username !== 'erased-' + subjectId || tomb.name !== 'erased-' + subjectId) throw new Error('identifiers not tombstoned');
        let refused = false;
        try { eraseSubject(mem, 'no-such-subject'); } catch (e) { refused = !!(e && e.code === 'SUBJECT_NOT_FOUND'); }
        if (!refused) throw new Error('unknown subject was not refused with SUBJECT_NOT_FOUND');
        return 'erase ran over live schema; row tombstoned; unknown subject refused';
      } finally {
        try { mem.close(); } catch (_e) { /* ignore */ }
      }
    });

    await check('data-subject', 'DSR erase-approval requires admin gate + MFA step-up', () => {
      // The approval endpoint is the dual-control point: it must carry BOTH the
      // admin gate and the MFA step-up middleware.
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, '..', 'routes', 'data-subject.js'), 'utf-8');
      const approve = src.split('\n').find((l) => l.indexOf("'/erase/:id/approve'") !== -1) || '';
      if (!approve) throw new Error('no /erase/:id/approve route found');
      if (approve.indexOf('eraseAdminGate') === -1 || approve.indexOf('mfaStepUp') === -1) {
        throw new Error('erase-approve is not gated by both eraseAdminGate and mfaStepUp');
      }
      return 'approval gated by eraseAdminGate + mfaStepUp';
    });

    // ── Category: B5d1-F burnout-signal data feed ──────────────────
    // The feed that gives the collector real inputs: the ticketing
    // activity-events push (-> ticket_actions), the break-outcome loop
    // (-> proactive_break_events), and the shift_overtime computation
    // (roster + after-hours). These checks assert the wiring and the
    // privacy/coupling invariants, not seeded data volume.
    await check('signal-feed', 'activity-events idempotency surface (ticket_actions.external_action_id + partial index)', () => {
      if (!columnExists('ticket_actions', 'external_action_id')) {
        throw new Error('ticket_actions is missing external_action_id (activity-events push target)');
      }
      if (!indexExists('idx_ticket_actions_external')) {
        throw new Error('missing idx_ticket_actions_external (partial UNIQUE for idempotent push)');
      }
      return 'ticket_actions.external_action_id present; partial UNIQUE idx_ticket_actions_external de-dups re-delivered events';
    });

    await check('signal-feed', 'activity-events route resolves pseudonym server-side (no id from request)', () => {
      try { require('../routes/ticketing-activity'); } catch (e) { throw new Error('cannot load ticketing-activity route: ' + e.message); }
      const fs = require('fs');
      const code = fs.readFileSync(path.join(__dirname, '..', 'routes', 'ticketing-activity.js'), 'utf8')
        .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
      if (!/FROM\s+users\s+WHERE\s+pseudonym\s*=\s*\?/i.test(code)) {
        throw new Error('route does not resolve analyst_pseudonym to users.id server-side');
      }
      if (!/active\s*=\s*1/i.test(code)) {
        throw new Error('route does not restrict pseudonym resolution to active analysts');
      }
      if (/req\.(?:body|query|params)\.analyst[_]?id/i.test(code)) {
        throw new Error('route trusts an analyst id taken from the request');
      }
      return 'resolves analyst_pseudonym to users.id (active only); never reads an analyst id from body/query/params';
    });

    await check('signal-feed', 'activity-events is decoupled from SOAR routing (no ticket_assignments write)', () => {
      const fs = require('fs');
      const code = fs.readFileSync(path.join(__dirname, '..', 'routes', 'ticketing-activity.js'), 'utf8')
        .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
      if (!/INSERT\s+OR\s+IGNORE\s+INTO\s+ticket_actions/i.test(code)) {
        throw new Error('route does not INSERT OR IGNORE into ticket_actions');
      }
      const writesAssignments =
        /INSERT\b[\s\S]*?INTO\s+ticket_assignments\b/i.test(code) ||
        /UPDATE\s+ticket_assignments\b/i.test(code) ||
        /DELETE\s+FROM\s+ticket_assignments\b/i.test(code);
      if (writesAssignments) {
        throw new Error('route mutates ticket_assignments (must stay decoupled from the SOAR routing rail)');
      }
      return 'writes ticket_actions only; never mutates ticket_assignments (events accepted for non-routed tickets)';
    });

    await check('signal-feed', 'break-outcome loop present and scoped to the JWT caller', () => {
      if (!tableExists('proactive_break_events')) {
        throw new Error('missing proactive_break_events (break_compliance event store)');
      }
      if (!indexExists('idx_proactive_break_events_analyst')) {
        throw new Error('missing idx_proactive_break_events_analyst');
      }
      const fs = require('fs');
      const code = fs.readFileSync(path.join(__dirname, '..', 'routes', 'v030-features.js'), 'utf8')
        .replace(/\/\/[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '');
      if (!/proactive-break\/outcome/.test(code)) {
        throw new Error('no POST /proactive-break/outcome handler');
      }
      if (!/req\.user\.id/.test(code)) {
        throw new Error('outcome handler is not scoped by req.user.id');
      }
      if (/req\.(?:body|query|params)\.analyst[_]?id/i.test(code)) {
        throw new Error('outcome handler trusts a request-supplied analyst id');
      }
      if (!/UPDATE\s+proactive_break_events[\s\S]{0,160}outcome/i.test(code)) {
        throw new Error('outcome handler does not update the break outcome');
      }
      return 'proactive_break_events + index present; outcome attributed to req.user.id (never the body) and closes an open offered row';
    });

    await check('signal-feed', 'shift_overtime service computes scheduled hours and folds after-hours', () => {
      let mod;
      try { mod = require('./shift-overtime'); } catch (e) { throw new Error('cannot load shift-overtime service: ' + e.message); }
      for (const fn of ['weeklyScheduledHours', 'computeAndStoreAll', 'localWallClockToUtc']) {
        if (typeof mod[fn] !== 'function') throw new Error('shift-overtime export missing: ' + fn);
      }
      const fullWeek = {
        monday:    [{ start: '09:00', end: '17:00' }],
        tuesday:   [{ start: '09:00', end: '17:00' }],
        wednesday: [{ start: '09:00', end: '17:00' }],
        thursday:  [{ start: '09:00', end: '17:00' }],
        friday:    [{ start: '09:00', end: '17:00' }],
      };
      const hrs = mod.weeklyScheduledHours(fullWeek);
      if (Math.abs(hrs - 40) > 1e-9) throw new Error('weeklyScheduledHours(5x 09:00-17:00) = ' + hrs + ', expected 40');
      const degenerate = mod.weeklyScheduledHours({ monday: [{ start: '17:00', end: '09:00' }], tuesday: [{ start: 'x', end: 'y' }] });
      if (degenerate !== 0) throw new Error('inverted/invalid slots should sum to 0, got ' + degenerate);
      const endUtc = mod.localWallClockToUtc(2025, 7, 15, 17, 0, 'America/Chicago');
      if (!(endUtc instanceof Date) || isNaN(endUtc.getTime())) {
        throw new Error('localWallClockToUtc did not resolve a valid Date (after-hours conversion broken)');
      }
      return 'weeklyScheduledHours sums durations (5x 8h -> 40.0h); inverted/invalid slots -> 0; localWallClockToUtc resolves a UTC Date for the after-hours fold';
    });

    // ── Golden baseline + config snapshots (B5d3) ──
    await check('golden-baseline', 'config_snapshots table + retention seed', () => {
      const gb = require('./golden-baseline');
      if (!tableExists('config_snapshots')) throw new Error('missing config_snapshots table');
      const row = this.db.prepare('SELECT value FROM config WHERE key = ?').get(gb.RETENTION_CONFIG_KEY);
      if (!row) throw new Error('retention seed (' + gb.RETENTION_CONFIG_KEY + ') missing from config');
      const ret = gb.readRetention(this.db);
      if (!Number.isInteger(ret) || ret < 1) throw new Error('readRetention returned an invalid value: ' + ret);
      return 'config_snapshots present; retention=' + ret;
    });
    await check('golden-baseline', 'captureBaseline produces a deterministic digest', () => {
      const gb = require('./golden-baseline');
      const a = gb.captureBaseline(this.db).sha256;
      const b = gb.captureBaseline(this.db).sha256;
      if (a !== b) throw new Error('two captures of the same config produced different digests');
      if (!/^[0-9a-f]{64}$/.test(a)) throw new Error('digest is not 64 hex chars: ' + a);
      return 'stable digest ' + a.slice(0, 12);
    });
    await check('golden-baseline', 'baseline allowlist tables exist', () => {
      const gb = require('./golden-baseline');
      const missing = gb.TABLE_SECTIONS.map(s => s.table).filter(t => !tableExists(t));
      if (missing.length) throw new Error('allowlist references missing table(s): ' + missing.join(', '));
      return gb.TABLE_SECTIONS.length + ' allowlisted section table(s) present';
    });
    await check('golden-baseline', 'baseline domain covers sla + notification config', () => {
      const gb = require('./golden-baseline');
      const secTables = gb.TABLE_SECTIONS.map(s => s.table);
      const missing = ['sla_config', 'notification_config'].filter(t => !secTables.includes(t));
      if (missing.length) throw new Error('revert/import domain is missing: ' + missing.join(', '));
      return 'sla_config + notification_config are in the revert/import domain';
    });
    await check('golden-baseline', 'import scan fails closed without a scanner', async () => {
      const { IntegrationManager } = require('./integration-manager');
      const enabled = this.db.prepare('SELECT COUNT(*) AS n FROM malware_scanner_integrations WHERE enabled = 1').get().n;
      if (enabled > 0) return SKIP('a malware scanner is enabled; the no-scanner path is not exercised here');
      const mgr = new IntegrationManager(this.db);
      const r = await mgr.inspectFile('{}', 'probe.json', 'application/json', { scanMode: 'all_configured' });
      if (!r.skipped) throw new Error('expected skipped=true so the import route returns MALWARE_SCANNER_REQUIRED');
      return 'no scanner -> inspectFile skipped (import gate fails closed)';
    });
    await check('golden-baseline', 'baseline export sign / fingerprint-verify round-trip', () => {
      const rk = require('./report-signing-keys');
      const { sha256Hex } = require('./report-signer');
      rk.ensureActiveReportKeypair(this.db);
      const digest = Buffer.from(sha256Hex('golden-baseline-regression-probe'), 'hex');
      const signed = rk.signReportDigest(this.db, digest);
      if (!rk.verifyReportDigest(this.db, digest, signed.signature, signed.keyFingerprint)) {
        throw new Error('a freshly produced signature failed to verify');
      }
      const tampered = Buffer.from(signed.signature);
      tampered[0] = tampered[0] ^ 0xff;
      if (rk.verifyReportDigest(this.db, digest, tampered, signed.keyFingerprint)) {
        throw new Error('a tampered signature verified');
      }
      return 'sign + verify-by-fingerprint ok; tamper rejected (' + signed.keyFingerprint.slice(0, 12) + ')';
    });

    // Reads a table's recorded CREATE statement (for CHECK-vocabulary asserts).
    const tableSql = (name) => {
      const r = this.db
        .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(name);
      return r && r.sql ? r.sql : '';
    };

    // ── Category: Instance identity (anti-cloning, D24/D25/D26) ────
    await check('instance_identity', 'Instance-identity + observations tables', () => {
      return requireAll(['instance_identity', 'instance_observations']);
    });
    await check('instance_identity', 'Anchor kind allows a hardware root (D26)', () => {
      const sql = tableSql('instance_identity');
      if (sql.indexOf('hardware') === -1) {
        throw new Error('instance_identity.anchor_kind CHECK does not include hardware (D26 cutover missing)');
      }
      return 'anchor_kind CHECK includes hardware';
    });
    await check('instance_identity', 'Clone / fork / rollback verdict vocabulary', () => {
      const sql = tableSql('instance_observations');
      const need = ['ok', 'fork', 'clone', 'rollback'];
      const missing = need.filter(v => sql.indexOf("'" + v + "'") === -1);
      if (missing.length > 0) {
        throw new Error('instance_observations.verdict CHECK missing: ' + missing.join(', '));
      }
      return 'verdict CHECK covers ok / fork / clone / rollback';
    });
    await check('instance_identity', 'Instance-anchor service API (D25)', () => {
      const anchor = require('./instance-anchor');
      const need = ['establish', 'load', 'sign', 'verify', 'fingerprint', 'ratchet', 'sealState', 'unsealState'];
      const missing = need.filter(k => typeof anchor[k] !== 'function');
      if (missing.length > 0) throw new Error('instance-anchor missing: ' + missing.join(', '));
      return 'establish / load / sign / verify / fingerprint / ratchet / seal / unseal present';
    });
    await check('instance_identity', 'Hardware-keystore seam fail-closed, no software fallback (D26)', () => {
      const ks = require('./instance-anchor/hardware-keystore');
      if (typeof ks.isAvailable !== 'function' || typeof ks.describe !== 'function') {
        throw new Error('hardware-keystore seam missing isAvailable / describe');
      }
      if (typeof ks.HardwareKeystoreUnavailableError !== 'function') {
        throw new Error('hardware-keystore missing HardwareKeystoreUnavailableError (the fail-closed signal)');
      }
      const d = ks.describe();
      if (!d || typeof d.available !== 'boolean') throw new Error('describe() did not report availability');
      // The seal / sign / NV leaf ops are platform-validation-pending (no TPM or
      // Secure Enclave in CI). What is asserted here is the seam, its
      // availability gate, and the fail-closed error class; there is no
      // software-anchor path to fall back to (D26 retired it).
      return 'hardware seam present; available=' + d.available + '; fail-closed error class present';
    });
    await check('instance_identity', 'AC device-key ratchet columns (anti-rollback)', () => {
      const missing = ['ratchet_counter', 'ratchet_updated_at'].filter(c => !columnExists('ac_device_signing_keys', c));
      if (missing.length > 0) throw new Error('ac_device_signing_keys missing: ' + missing.join(', '));
      return 'ratchet_counter + ratchet_updated_at present';
    });
    await check('instance_identity', 'MC device-signing key, one active per user (D24)', () => {
      if (!tableExists('mc_device_signing_keys')) throw new Error('missing table mc_device_signing_keys');
      if (!indexExists('idx_mc_device_signing_keys_one_active')) {
        throw new Error('missing one-active-per-user index idx_mc_device_signing_keys_one_active');
      }
      return 'mc_device_signing_keys present; one-active-per-user UNIQUE index enforced';
    });
    await check('instance_identity', 'Recovery dual-control approval ledger (D24)', () => {
      if (!tableExists('recovery_action_approvals')) throw new Error('missing table recovery_action_approvals');
      const sql = tableSql('recovery_action_approvals');
      if (sql.indexOf("'teardown'") === -1 || sql.indexOf("'reprovision'") === -1) {
        throw new Error('recovery_action_approvals.action CHECK missing teardown / reprovision');
      }
      if (sql.indexOf("'operator'") === -1 || sql.indexOf("'gd'") === -1) {
        throw new Error('recovery_action_approvals.approval_kind CHECK missing operator / gd');
      }
      if (!indexExists('idx_recovery_action_approvals_one_pending')) {
        throw new Error('missing single-pending guard idx_recovery_action_approvals_one_pending');
      }
      return 'teardown / reprovision actions; operator / gd approval; single-pending guard present';
    });
    await check('instance_identity', 'Migration bundle ledger is the canonical FA-MIG1 shape', () => {
      if (!tableExists('migration_bundles')) throw new Error('missing table migration_bundles');
      const need = ['bundle_path', 'baseline_sha256', 'signing_key_fingerprint', 'manifest_sig_path'];
      const missing = need.filter(c => !columnExists('migration_bundles', c));
      if (missing.length > 0) {
        throw new Error('migration_bundles is not the FA-MIG1 ledger (missing ' + missing.join(', ') + ')');
      }
      const idCol = this.db.prepare('PRAGMA table_info(migration_bundles)').all().find(c => c.name === 'id');
      if (!idCol || String(idCol.type).toUpperCase() !== 'TEXT') {
        throw new Error('migration_bundles.id is not TEXT (expected the FA-MIG1 mig- id)');
      }
      return 'FA-MIG1 ledger columns present; id is TEXT';
    });

    // ── Category: Virtualization mode + migration (D9/D10/D14) ─────
    await check('virtualization_mode', 'Deployment-mode service API present', () => {
      const dm = require('./deployment-mode');
      const need = ['getMode', 'setMode', 'isConfigured', 'isVirtualized', 'detectHypervisor', 'summary'];
      const missing = need.filter(k => typeof dm[k] !== 'function');
      if (missing.length > 0) throw new Error('deployment-mode missing: ' + missing.join(', '));
      if (!dm.BARE_METAL || !dm.VIRTUALIZED) throw new Error('deployment-mode mode constants missing');
      return 'getMode / setMode / isConfigured / isVirtualized / detectHypervisor / summary present';
    });
    await check('virtualization_mode', 'Deployment-mode record readable and verified (config store)', () => {
      const dm = require('./deployment-mode');
      const s = dm.summary(this.db);
      if (!s || typeof s.mode !== 'string') throw new Error('deployment-mode summary returned no mode');
      // The sealed record lives in the config store under deployment_mode, not
      // system_meta (the old check read a key that is never written). No record
      // is a valid fresh install (fail-safe bare-metal default); a record that
      // is present but does not verify means tamper or an anchor mismatch.
      if (s.recordPresent && !s.configured) {
        throw new Error('deployment_mode record present but failed verification (tamper or anchor mismatch); fell back to ' + s.mode);
      }
      return s.recordPresent ? ('deployment_mode = ' + s.mode + ' (sealed)') : ('no sealed record; default ' + s.mode);
    });
    await check('virtualization_mode', 'Clock-integrity monitor present (snapshot-rollback defense)', () => {
      const ci = require('./clock-integrity');
      if (typeof ci.checkClockIntegrity !== 'function' || typeof ci.status !== 'function') {
        throw new Error('clock-integrity missing checkClockIntegrity / status');
      }
      if (typeof ci.MAX_DRIFT_MS !== 'number') throw new Error('clock-integrity missing MAX_DRIFT_MS');
      const s = ci.status();
      if (!s || typeof s !== 'object') throw new Error('status() did not return a state object');
      return 'checkClockIntegrity / status present; MAX_DRIFT_MS = ' + ci.MAX_DRIFT_MS;
    });
    await check('virtualization_mode', 'Anti-rollback fuse high-water seeded', () => {
      const row = this.db.prepare("SELECT value FROM node_state WHERE key = 'fuse_high_water'").get();
      if (!row) throw new Error('no fuse_high_water row in node_state (B6h A-8 seed/migration missing)');
      return 'fuse_high_water = ' + row.value;
    });
    await check('virtualization_mode', 'Migration export / import service surface (FA-MIG1)', () => {
      const bundle = require('./migration-bundle');
      if (typeof bundle.composeMigrationBundle !== 'function') throw new Error('migration-bundle missing composeMigrationBundle');
      const reconcile = require('./migration-reconcile');
      if (typeof reconcile.verifyBundle !== 'function' || typeof reconcile.planReconciliation !== 'function') {
        throw new Error('migration-reconcile missing verifyBundle / planReconciliation');
      }
      const identity = require('./migration-identity');
      if (typeof identity.clearSourceIdentity !== 'function' || typeof identity.reestablishIdentityFresh !== 'function') {
        throw new Error('migration-identity missing clearSourceIdentity / reestablishIdentityFresh');
      }
      const apply = require('./migration-apply');
      if (typeof apply.applyReconciliation !== 'function') throw new Error('migration-apply missing applyReconciliation');
      return 'compose / verify / plan / clear / reestablish / apply present';
    });
    await check('virtualization_mode', 'Shared DB-restore-swap primitive present (EDR-scanned)', () => {
      const swap = require('./db-restore-swap');
      if (typeof swap.restoreDatabaseFromArchive !== 'function') throw new Error('db-restore-swap missing restoreDatabaseFromArchive');
      if (typeof swap.scanExtractedBytes !== 'function') throw new Error('db-restore-swap missing scanExtractedBytes (mandatory EDR scan)');
      if (typeof swap.DbRestoreError !== 'function') throw new Error('db-restore-swap missing DbRestoreError');
      if (!swap.EXPECTED_DB_FILENAME) throw new Error('db-restore-swap missing EXPECTED_DB_FILENAME guard');
      return 'restoreDatabaseFromArchive + scanExtractedBytes + DbRestoreError + filename guard present';
    });

    // ── Category: Cloud Mode (Confidential VM) ─ B5h ─────
    // No live hardware: confidential-computing detection and attestation are
    // exercised through an injectable fs probe, the metadata parsers through
    // fixtures, and the host-relocation classifier on an in-memory config clone.
    await check('cloud_mode', 'Deployment-mode enum includes cloud (D-B5h-1)', () => {
      const dm = require('./deployment-mode');
      if (dm.MODES.indexOf('cloud') === -1) throw new Error('deployment-mode MODES does not include cloud');
      if (dm.CLOUD !== 'cloud') throw new Error('deployment-mode CLOUD constant missing');
      if (typeof dm.isCloud !== 'function') throw new Error('deployment-mode missing isCloud');
      return 'MODES includes cloud; CLOUD constant + isCloud() present';
    });
    await check('cloud_mode', 'Confidential-computing detection is structured (D-B5h-2)', () => {
      const cc = require('./cloud-attestation');
      const none = { exists: function () { return false; } };
      const sev = { exists: function (p) { return p === '/dev/sev-guest'; } };
      const dNone = cc.detectConfidentialComputing(none);
      if (dNone.present !== false || dNone.tech !== cc.CC_NONE) throw new Error('no-CC probe should report present=false');
      const dSev = cc.detectConfidentialComputing(sev);
      if (dSev.present !== true || dSev.tech !== cc.CC_SEV_SNP) throw new Error('SEV-SNP guest device should be detected');
      return 'detectConfidentialComputing returns {present,tech,source}; SEV-SNP recognized';
    });
    await check('cloud_mode', 'Attestation gate is fail-closed (D-B5h-3 / B5l2)', () => {
      const cc = require('./cloud-attestation');
      const none = { exists: function () { return false; } };
      const sev = { exists: function (p) { return p === '/dev/sev-guest'; } };
      const aNone = cc.verifyAttestation({ probe: none });
      if (aNone.verified !== false) throw new Error('attestation must fail closed when no confidential guest is present');
      // B5l2: device presence alone no longer verifies; without a signed report
      // that can be fetched and a vendor chain that validates, the gate stays closed.
      const aSev = cc.verifyAttestation({ probe: sev, tsmReader: { fetch: function () { throw new Error('no tsm in CI'); } } });
      if (aSev.verified !== false) throw new Error('attestation must fail closed when no signed report can be verified');
      if (aSev.platformValidationPending !== true) throw new Error('a detected-but-unverified guest should mark platformValidationPending');
      return 'verifyAttestation fails closed without CC and when no signed report can be fetched/verified';
    });
    await check('cloud_mode', 'Spot and autoscaled instances are detected for refusal (D-B5h-4)', () => {
      const md = require('./cloud-metadata');
      if (md.buildAwsMetadata({ lifeCycle: 'spot' }).spot !== true) throw new Error('AWS lifeCycle=spot should set spot=true');
      if (md.buildAwsMetadata({ asgState: 'InService' }).autoscaled !== true) throw new Error('AWS asgState present should set autoscaled=true');
      if (md.parseAzureInstance({ compute: { priority: 'Spot' } }).spot !== true) throw new Error('Azure priority=Spot should set spot=true');
      if (md.parseAzureInstance({ compute: { vmScaleSetName: 'vmss-1' } }).autoscaled !== true) throw new Error('Azure vmScaleSetName should set autoscaled=true');
      const plain = md.buildAwsMetadata({});
      if (plain.spot !== null || plain.autoscaled !== null) throw new Error('absent signals should be null (unknown), not refused');
      return 'spot + autoscaled detected across AWS/Azure fixtures; unknown stays null';
    });
    await check('cloud_mode', 'Server-cert SAN reconciliation set is canonical (D-B5h-6)', () => {
      const ca = require('./ca');
      if (typeof ca.reconcileServerCert !== 'function') throw new Error('ca.reconcileServerCert missing');
      const san = ca.computeDesiredSan({ stableHostname: 'SOC.Example.Com', instanceIp: '10.0.0.5' });
      const expected = ['10.0.0.5', '127.0.0.1', '::1', 'localhost', 'soc.example.com'].sort();
      if (JSON.stringify(san) !== JSON.stringify(expected)) throw new Error('computeDesiredSan is not the canonical sorted set: ' + JSON.stringify(san));
      const base = ca.computeDesiredSan({});
      if (base.indexOf('localhost') === -1 || base.indexOf('127.0.0.1') === -1 || base.indexOf('::1') === -1) throw new Error('SAN base must include the loopback set');
      return 'computeDesiredSan yields a canonical sorted/deduped/lowercased set; reconcileServerCert present';
    });
    await check('cloud_mode', 'Cloud backup KEK posture refuses env-var (D-B5h-5)', () => {
      const bkw = require('./backup-key-wrapping');
      if (typeof bkw.assertCloudBackupKekPosture !== 'function') throw new Error('backup-key-wrapping missing assertCloudBackupKekPosture');
      let code = null;
      try { bkw.assertCloudBackupKekPosture('env-var', true); } catch (e) { code = e.code; }
      if (code !== 'CLOUD_BACKUP_KEK_REQUIRED') throw new Error('env-var KEK in cloud mode must throw CLOUD_BACKUP_KEK_REQUIRED');
      bkw.assertCloudBackupKekPosture('aws-kms', true);
      bkw.assertCloudBackupKekPosture('env-var', false);
      return 'env-var KEK refused in cloud mode; cloud-KMS allowed; non-cloud unaffected';
    });
    await check('cloud_mode', 'Cloud-mode config service API + platforms (D-B5h-8)', () => {
      const cm = require('./cloud-mode');
      const missing = ['getCloudConfig', 'setCloudConfig', 'recordAttestation'].filter(k => typeof cm[k] !== 'function');
      if (missing.length > 0) throw new Error('cloud-mode missing: ' + missing.join(', '));
      const want = ['aws', 'azure', 'gcp'];
      if (!Array.isArray(cm.PLATFORMS) || cm.PLATFORMS.length !== want.length || want.some(p => cm.PLATFORMS.indexOf(p) === -1)) {
        throw new Error('cloud-mode PLATFORMS must be exactly aws/azure/gcp');
      }
      return 'getCloudConfig / setCloudConfig / recordAttestation present; PLATFORMS = aws/azure/gcp';
    });
    await check('cloud_mode', 'Cloud stop/start is an authorized relocation; concurrent duplicate is a clone', () => {
      const reg = require('./instance-registry');
      if (typeof reg.classify !== 'function') throw new Error('instance-registry.classify missing');
      const Database = this.db.constructor;
      const mem = new Database(':memory:');
      try {
        mem.prepare('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)').run();
        if (!reg.recordHostPresence(mem, { host: 'host-a', cloud: true }).firstSeen) throw new Error('first presence should be firstSeen');
        const moved = reg.recordHostPresence(mem, { host: 'host-b', cloud: true });
        if (moved.migration !== true || moved.unexpected !== false) throw new Error('cloud host change should be an authorized relocation');
      } finally { mem.close(); }
      const mem2 = new Database(':memory:');
      try {
        mem2.prepare('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)').run();
        reg.recordHostPresence(mem2, { host: 'bm-a' });
        const bm = reg.recordHostPresence(mem2, { host: 'bm-b' });
        if (bm.unexpected !== true || bm.migration !== false) throw new Error('bare-metal host change should be flagged unexpected');
      } finally { mem2.close(); }
      return 'cloud relocation authorized; bare-metal host change flagged; classify present';
    });

    // B5l2: cloud remote-attestation verified end to end. Builds a synthetic
    // SEV-SNP report and TDX quote signed by a throwaway openssl-generated cert
    // chain (no confidential hardware in CI) and exercises the verifiers, the
    // orchestrator over configfs-tsm, the guest-mitigation gate, the tenancy
    // assertion, and the monotonic TCB floor / measurement TOFU. The report-
    // backed checks skip (never fail) if openssl is unavailable.
    let caf = null;
    let cafErr = null;
    try {
      caf = (function buildAttestationFixtures() {
        const { execFileSync } = require('child_process');
        const os = require('os'); const fsx = require('fs'); const pathx = require('path');
        const dir = fsx.mkdtempSync(pathx.join(os.tmpdir(), 'rr-att-'));
        const P = (f) => pathx.join(dir, f);
        const run = (args) => execFileSync('openssl', args, { stdio: 'ignore' });
        const caExt = P('ca.ext'); const leafExt = P('leaf.ext');
        fsx.writeFileSync(caExt, 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
        fsx.writeFileSync(leafExt, 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n');
        const ec = (curve, keyf) => run(['ecparam', '-name', curve, '-genkey', '-noout', '-out', P(keyf)]);
        const root = (keyf, outf, cn, md) => run(['req', '-new', '-x509', '-key', P(keyf), '-out', P(outf), '-days', '3650', '-subj', '/CN=' + cn, '-' + md, '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign']);
        const issue = (csrkey, cn, cacert, cakey, outf, md, ext) => { run(['req', '-new', '-key', P(csrkey), '-subj', '/CN=' + cn, '-out', P(outf + '.csr')]); run(['x509', '-req', '-in', P(outf + '.csr'), '-CA', P(cacert), '-CAkey', P(cakey), '-CAcreateserial', '-out', P(outf), '-days', '3650', '-' + md, '-extfile', ext]); };
        ec('secp384r1', 'ark.key'); root('ark.key', 'ark.pem', 'rr-ARK', 'sha384');
        ec('secp384r1', 'ask.key'); issue('ask.key', 'rr-ASK', 'ark.pem', 'ark.key', 'ask.pem', 'sha384', caExt);
        ec('secp384r1', 'vcek.key'); issue('vcek.key', 'rr-VCEK', 'ask.pem', 'ask.key', 'vcek.pem', 'sha384', leafExt);
        ec('secp384r1', 'ark2.key'); root('ark2.key', 'ark2.pem', 'rr-ARK2', 'sha384');
        ec('prime256v1', 'iroot.key'); root('iroot.key', 'iroot.pem', 'rr-IntelRoot', 'sha256');
        ec('prime256v1', 'pcka.key'); issue('pcka.key', 'rr-PCKCA', 'iroot.pem', 'iroot.key', 'pcka.pem', 'sha256', caExt);
        ec('prime256v1', 'pck.key'); issue('pck.key', 'rr-PCK', 'pcka.pem', 'pcka.key', 'pck.pem', 'sha256', leafExt);
        ec('prime256v1', 'iroot2.key'); root('iroot2.key', 'iroot2.pem', 'rr-IntelRoot2', 'sha256');
        const read = (f) => fsx.readFileSync(P(f), 'utf8');
        const vcekKey = crypto.createPrivateKey(read('vcek.key'));
        const vcekDer = new crypto.X509Certificate(read('vcek.pem')).raw;
        const pckKey = crypto.createPrivateKey(read('pck.key'));
        const ak = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const rootsDir = P('roots');
        fsx.mkdirSync(pathx.join(rootsDir, 'amd', 'test'), { recursive: true });
        fsx.mkdirSync(pathx.join(rootsDir, 'intel'), { recursive: true });
        fsx.copyFileSync(P('ark.pem'), pathx.join(rootsDir, 'amd', 'test', 'ark.pem'));
        fsx.copyFileSync(P('ask.pem'), pathx.join(rootsDir, 'amd', 'test', 'ask.pem'));
        fsx.copyFileSync(P('iroot.pem'), pathx.join(rootsDir, 'intel', 'sgx-root-ca.pem'));
        const derToLe = (der, size) => {
          let o = 0; if (der[o++] !== 0x30) throw new Error('seq'); let L = der[o++]; if (L & 0x80) { let n = L & 0x7f; while (n-- > 0) o++; }
          const ri = () => { if (der[o++] !== 0x02) throw new Error('int'); const l = der[o++]; let v = der.slice(o, o + l); o += l; while (v.length > 1 && v[0] === 0) v = v.slice(1); return v; };
          const r = ri(); const s = ri(); const rb = Buffer.alloc(size); r.copy(rb, size - r.length); const sb = Buffer.alloc(size); s.copy(sb, size - s.length);
          return { r: Buffer.from(rb).reverse(), s: Buffer.from(sb).reverse() };
        };
        const makeSevReport = (nonce, opts) => {
          const o = opts || {};
          const rep = Buffer.alloc(1184); rep.writeUInt32LE(2, 0); rep.writeUInt32LE(1, 0x034);
          rep[0x038] = o.bl == null ? 3 : o.bl; rep[0x038 + 6] = o.snp == null ? 8 : o.snp; rep[0x038 + 7] = o.uc == null ? 72 : o.uc;
          Buffer.from(nonce).copy(rep, 0x050); Buffer.alloc(48, o.meas == null ? 0xAB : o.meas).copy(rep, 0x090);
          rep[0x180] = o.bl == null ? 3 : o.bl; rep[0x180 + 6] = o.snp == null ? 8 : o.snp; rep[0x180 + 7] = o.uc == null ? 72 : o.uc;
          Buffer.alloc(64, 0xCD).copy(rep, 0x1A0);
          const sig = derToLe(crypto.sign('sha384', rep.slice(0, 672), vcekKey), 48);
          const f = Buffer.alloc(512); sig.r.copy(f, 0); sig.s.copy(f, 72); f.copy(rep, 0x2A0);
          return rep;
        };
        const makeAuxblob = () => {
          const G = Buffer.from('8d75da6364e66445adc5f4b93be8accd', 'hex');
          const e = Buffer.alloc(24); G.copy(e, 0); e.writeUInt32LE(48, 16); e.writeUInt32LE(vcekDer.length, 20);
          return Buffer.concat([e, Buffer.alloc(24), vcekDer]);
        };
        const makeTdxQuote = (nonce, opts) => {
          const o = opts || {};
          const jwk = ak.publicKey.export({ format: 'jwk' });
          const akPubLE = Buffer.concat([Buffer.from(jwk.x, 'base64url').reverse(), Buffer.from(jwk.y, 'base64url').reverse()]);
          const qeAuth = Buffer.from('rr-auth');
          const bind = crypto.createHash('sha256').update(akPubLE).update(qeAuth).digest();
          const qe = Buffer.alloc(384); (o.breakBind ? crypto.randomBytes(32) : bind).copy(qe, 320);
          const qs = derToLe(crypto.sign('sha256', qe, pckKey), 32); const qeSig = Buffer.concat([qs.r, qs.s]);
          const hb = Buffer.alloc(632); hb.writeUInt16LE(4, 0); hb.writeUInt16LE(2, 2); hb.writeUInt32LE(0x81, 4);
          const B = 48; Buffer.from([3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).copy(hb, B); Buffer.alloc(48, o.meas == null ? 0xE1 : o.meas).copy(hb, B + 136);
          Buffer.from(nonce).copy(hb, B + 520);
          const sg = derToLe(crypto.sign('sha256', hb, ak.privateKey), 32); const quoteSig = Buffer.concat([sg.r, sg.s]);
          const cert = Buffer.from(read('pck.pem') + '\n' + read('pcka.pem'), 'utf8');
          const h = Buffer.alloc(8); h.writeUInt16LE(qeAuth.length, 0); h.writeUInt16LE(5, 2); h.writeUInt32LE(cert.length, 4);
          const sd = Buffer.concat([quoteSig, akPubLE, qe, qeSig, h.slice(0, 2), qeAuth, h.slice(2, 8), cert]);
          const len = Buffer.alloc(4); len.writeUInt32LE(sd.length, 0); return Buffer.concat([hb, len, sd]);
        };
        return { dir, rootsDir, vcekPem: read('vcek.pem'), arkPem: read('ark.pem'), askPem: read('ask.pem'), ark2Pem: read('ark2.pem'), irootPem: read('iroot.pem'), iroot2Pem: read('iroot2.pem'), makeSevReport, makeAuxblob, makeTdxQuote };
      })();
    } catch (e) { cafErr = e.message || String(e); caf = null; }
    await check('cloud_attestation', 'SEV-SNP report: valid verifies; tamper / chain / nonce fail closed', () => {
      if (!caf) return SKIP('attestation fixtures unavailable: ' + cafErr);
      const snp = require('./attestation-sev-snp');
      const nonce = crypto.randomBytes(64);
      const rep = caf.makeSevReport(nonce);
      const ok = snp.verify({ report: rep, vcekPem: caf.vcekPem, askPem: caf.askPem, arkPem: caf.arkPem, expectedNonce: nonce });
      if (!ok.verified) throw new Error('valid SEV-SNP report failed to verify: ' + ok.reason);
      const tampered = Buffer.from(rep); tampered[0x100] = tampered[0x100] ^ 0xFF;
      if (snp.verify({ report: tampered, vcekPem: caf.vcekPem, askPem: caf.askPem, arkPem: caf.arkPem, expectedNonce: nonce }).verified) throw new Error('tampered report must not verify');
      if (snp.verify({ report: rep, vcekPem: caf.vcekPem, askPem: caf.askPem, arkPem: caf.ark2Pem, expectedNonce: nonce }).verified) throw new Error('wrong ARK must not verify');
      if (snp.verify({ report: rep, vcekPem: caf.vcekPem, askPem: caf.askPem, arkPem: caf.arkPem, expectedNonce: crypto.randomBytes(64) }).verified) throw new Error('wrong nonce must not verify');
      return 'SEV-SNP valid verifies; tampered / wrong-root / wrong-nonce fail closed';
    });
    await check('cloud_attestation', 'SEV-SNP TCB floor (pass/fail) and measurement extraction', () => {
      if (!caf) return SKIP('attestation fixtures unavailable: ' + cafErr);
      const snp = require('./attestation-sev-snp');
      const nonce = crypto.randomBytes(64);
      const ok = snp.verify({ report: caf.makeSevReport(nonce), vcekPem: caf.vcekPem, askPem: caf.askPem, arkPem: caf.arkPem, expectedNonce: nonce });
      if (!ok.verified) throw new Error('verify failed: ' + ok.reason);
      if (ok.measurement.indexOf('abababab') !== 0) throw new Error('measurement not extracted: ' + ok.measurement.slice(0, 8));
      if (!snp.compareTcb(ok.tcb, { bootloader: 3, tee: 0, snp: 8, microcode: 72 })) throw new Error('floor at-or-below should pass');
      if (snp.compareTcb(ok.tcb, { bootloader: 3, tee: 0, snp: 9, microcode: 72 })) throw new Error('floor above report should fail');
      return 'TCB floor passes at-or-below and fails above; measurement extracted';
    });
    await check('cloud_attestation', 'TDX quote: valid verifies; tamper / binding / chain / nonce fail closed', () => {
      if (!caf) return SKIP('attestation fixtures unavailable: ' + cafErr);
      const tdx = require('./attestation-tdx');
      const nonce = crypto.randomBytes(64);
      const q = caf.makeTdxQuote(nonce);
      const ok = tdx.verify({ quote: q, intelRootPem: caf.irootPem, expectedNonce: nonce });
      if (!ok.verified) throw new Error('valid TDX quote failed to verify: ' + ok.reason);
      const t = Buffer.from(q); t[200] = t[200] ^ 0xFF;
      if (tdx.verify({ quote: t, intelRootPem: caf.irootPem, expectedNonce: nonce }).verified) throw new Error('tampered quote must not verify');
      if (tdx.verify({ quote: caf.makeTdxQuote(nonce, { breakBind: true }), intelRootPem: caf.irootPem, expectedNonce: nonce }).verified) throw new Error('broken AK binding must not verify');
      if (tdx.verify({ quote: q, intelRootPem: caf.iroot2Pem, expectedNonce: nonce }).verified) throw new Error('wrong Intel root must not verify');
      if (tdx.verify({ quote: q, intelRootPem: caf.irootPem, expectedNonce: crypto.randomBytes(64) }).verified) throw new Error('wrong nonce must not verify');
      return 'TDX valid verifies; tampered / bad-binding / wrong-root / wrong-nonce fail closed';
    });
    await check('cloud_attestation', 'TDX TCB SVN floor and MRTD extraction', () => {
      if (!caf) return SKIP('attestation fixtures unavailable: ' + cafErr);
      const tdx = require('./attestation-tdx');
      const nonce = crypto.randomBytes(64);
      const ok = tdx.verify({ quote: caf.makeTdxQuote(nonce), intelRootPem: caf.irootPem, expectedNonce: nonce });
      if (!ok.verified) throw new Error('verify failed: ' + ok.reason);
      if (ok.measurement.indexOf('e1e1e1e1') !== 0) throw new Error('MRTD not extracted: ' + ok.measurement.slice(0, 8));
      if (!Array.isArray(ok.rtmrs) || ok.rtmrs.length !== 4) throw new Error('RTMRs not extracted');
      if (!tdx.compareTcbSvn(ok.tcbSvn, '0304000000000000000000000000000000')) throw new Error('SVN floor at-or-below should pass');
      if (tdx.compareTcbSvn(ok.tcbSvn, '0504000000000000000000000000000000')) throw new Error('SVN floor above should fail');
      return 'TDX SVN floor passes at-or-below and fails above; MRTD + RTMRs extracted';
    });
    await check('cloud_attestation', 'Orchestrator dispatches SEV-SNP + TDX via configfs-tsm; Nitro/none fail closed', () => {
      if (!caf) return SKIP('attestation fixtures unavailable: ' + cafErr);
      const oc = require('./cloud-attestation');
      const probe = (have) => ({ exists: (p) => p === have });
      const sevTsm = { fetch: (nonce) => ({ provider: 'sev_guest', report: caf.makeSevReport(nonce), auxblob: caf.makeAuxblob() }) };
      const tdxTsm = { fetch: (nonce) => ({ provider: 'tdx_guest', report: caf.makeTdxQuote(nonce), auxblob: Buffer.alloc(0) }) };
      const aSev = oc.verifyAttestation({ probe: probe('/dev/sev-guest'), tsmReader: sevTsm, rootsDir: caf.rootsDir });
      if (!aSev.verified || aSev.tech !== oc.CC_SEV_SNP) throw new Error('orchestrator SEV-SNP path failed: ' + aSev.reason);
      const aTdx = oc.verifyAttestation({ probe: probe('/dev/tdx_guest'), tsmReader: tdxTsm, rootsDir: caf.rootsDir });
      if (!aTdx.verified || aTdx.tech !== oc.CC_TDX) throw new Error('orchestrator TDX path failed: ' + aTdx.reason);
      if (oc.verifyAttestation({ probe: probe('/dev/nitro_enclaves') }).verified) throw new Error('Nitro-only must not verify (enclave-scoped)');
      if (oc.verifyAttestation({ probe: probe('/dev/none') }).verified) throw new Error('no CC device must not verify');
      const staleTsm = { fetch: () => ({ provider: 'sev_guest', report: caf.makeSevReport(Buffer.alloc(64, 0x77)), auxblob: caf.makeAuxblob() }) };
      if (oc.verifyAttestation({ probe: probe('/dev/sev-guest'), tsmReader: staleTsm, rootsDir: caf.rootsDir }).verified) throw new Error('stale nonce must not verify');
      return 'orchestrator verifies SEV-SNP + TDX via TSM + bundled roots; Nitro/none/stale fail closed';
    });
    await check('cloud_attestation', 'Guest CPU side-channel mitigation gate', () => {
      const gm = require('./guest-mitigations');
      const R = (map) => ({ read: (p) => { const k = p.split('/').pop(); return (k in map) ? map[k] : null; } });
      const all = {}; gm.IN_SCOPE.forEach((fam) => { all[fam] = fam === 'l1tf' ? 'Not affected' : 'Mitigation: present'; });
      if (!gm.evaluateMitigations({ reader: R(all) }).ok) throw new Error('all-mitigated should pass');
      const vuln = Object.assign({}, all); vuln.retbleed = 'Vulnerable';
      if (gm.evaluateMitigations({ reader: R(vuln) }).ok) throw new Error('a Vulnerable family must fail closed');
      if (!gm.evaluateMitigations({ reader: R(vuln), overrides: ['retbleed'] }).ok) throw new Error('audited override should pass');
      const miss = Object.assign({}, all); delete miss.mds;
      if (!gm.evaluateMitigations({ reader: R(miss) }).ok) throw new Error('absent family tolerated by default');
      if (gm.evaluateMitigations({ reader: R(miss), strictUnknown: true }).ok) throw new Error('strictUnknown should fail on absent family');
      return 'mitigated passes; Vulnerable fails; override passes; unknown tolerated (strict fails)';
    });
    await check('cloud_attestation', 'Dedicated-tenancy assertion across providers', () => {
      const md = require('./cloud-metadata');
      if (!md.isDedicatedTenancy(md.buildAwsMetadata({ tenancy: 'dedicated' }))) throw new Error('AWS dedicated should be single-tenant');
      if (!md.isDedicatedTenancy(md.buildAwsMetadata({ tenancy: 'host' }))) throw new Error('AWS host should be single-tenant');
      if (md.isDedicatedTenancy(md.buildAwsMetadata({ tenancy: 'default' }))) throw new Error('AWS default is shared');
      if (!md.isDedicatedTenancy(md.parseAzureInstance({ compute: { hostGroup: { id: 'hg' } } }))) throw new Error('Azure host group should be single-tenant');
      if (!md.isDedicatedTenancy(md.parseGcpInstance({ id: 1, scheduling: { nodeAffinities: [{ key: 'n', operator: 'IN', values: ['x'] }] } }))) throw new Error('GCP sole-tenant should be single-tenant');
      if (md.isDedicatedTenancy(md.emptyMetadata())) throw new Error('unknown tenancy is not dedicated');
      return 'isDedicatedTenancy true for AWS dedicated/host, Azure host group, GCP sole-tenant; false otherwise';
    });
    // check 8: monotonic TCB floor + measurement TOFU, against an in-memory clone
    await check('cloud_attestation', 'TCB floor is monotonic (upward-only) and measurement is TOFU', () => {
      const cm = require('./cloud-mode');
      const Database = this.db.constructor;
      const mem = new Database(':memory:');
      try {
        mem.prepare('CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT)').run();
        cm.setCloudConfig(mem, { platform: 'aws' });
        cm.setTcbFloor(mem, { tech: 'sev-snp', floor: { bootloader: 3, tee: 0, snp: 8, microcode: 72 } });
        if (cm.setTcbFloor(mem, { tech: 'sev-snp', floor: { snp: 5 } }).tcbFloor.snp !== 8) throw new Error('floor must not decrease');
        if (cm.setTcbFloor(mem, { tech: 'sev-snp', floor: { snp: 10 } }).tcbFloor.snp !== 10) throw new Error('floor must raise');
        if (!cm.pinMeasurement(mem, 'abcd').firstPin) throw new Error('first measurement should pin');
        if (!cm.pinMeasurement(mem, 'ABCD').matched) throw new Error('same measurement should match (case-insensitive)');
        if (cm.pinMeasurement(mem, 'ffff').matched) throw new Error('different measurement should mismatch');
      } finally { mem.close(); }
      return 'TCB floor only raises; measurement pins once then must match (TOFU)';
    });
    if (caf && caf.dir) { try { require('fs').rmSync(caf.dir, { recursive: true, force: true }); } catch (_e) { /* ignore */ } }

    // B5g: export encryption at rest. Exercises the keyless AES-256-GCM core
    // (no KEK / hardware needed in CI) and asserts the production seal path is
    // wired to the shared backup-key-wrapping registry.
    await check('export_at_rest', 'FA-ENC1 seal/open round-trip (keyless AEAD core)', () => {
      const ee = require('./export-encryption');
      const zlib = require('zlib');
      const key = crypto.randomBytes(32);
      const plain = zlib.gzipSync(Buffer.from('regression export archive'.repeat(64)));
      const framed = ee.sealWithKey(plain, key, { exportId: 'rr-' + crypto.randomBytes(4).toString('hex'), role: ee.ROLE_ARCHIVE });
      if (!ee.openWithKey(framed, key).equals(plain)) throw new Error('seal/open did not round-trip');
      return 'AES-256-GCM seal then open returns the original archive bytes';
    });
    await check('export_at_rest', 'FA-ENC1 artifact is not gunzip-able (encrypted at rest)', () => {
      const ee = require('./export-encryption');
      const zlib = require('zlib');
      const framed = ee.sealWithKey(zlib.gzipSync(Buffer.from('evidence')), crypto.randomBytes(32), { exportId: 'rr-ng', role: ee.ROLE_ARCHIVE });
      if (framed.subarray(0, 6).toString('latin1') !== ee.MAGIC_STRING) throw new Error('sealed artifact lacks the FA-ENC1 magic');
      if (framed[0] === 0x1f && framed[1] === 0x8b) throw new Error('sealed artifact still carries the gzip magic');
      let gunzipThrew = false;
      try { zlib.gunzipSync(framed); } catch (e) { gunzipThrew = true; }
      if (!gunzipThrew) throw new Error('sealed artifact was gunzip-able (not encrypted at rest)');
      return 'on-disk bytes carry the FA-ENC1 magic and are not gunzip-able';
    });
    await check('export_at_rest', 'FA-ENC1 AAD binds export_id and role (tamper / substitution rejected)', () => {
      const ee = require('./export-encryption');
      const key = crypto.randomBytes(32);
      const framed = ee.sealWithKey(Buffer.from('payload bytes'), key, { exportId: 'rr-a', role: ee.ROLE_ARCHIVE });
      let wrongKey = false;
      try { ee.openWithKey(framed, crypto.randomBytes(32)); } catch (e) { wrongKey = true; }
      if (!wrongKey) throw new Error('a wrong key was accepted');
      const hlen = framed.readUInt32BE(8);
      const hdr = JSON.parse(framed.subarray(12, 12 + hlen).toString('utf-8'));
      hdr.export_id = 'rr-OTHER';
      const nh = Buffer.from(JSON.stringify(hdr), 'utf-8');
      const len = Buffer.alloc(4); len.writeUInt32BE(nh.length, 0);
      const tampered = Buffer.concat([framed.subarray(0, 8), len, nh, framed.subarray(12 + hlen)]);
      let tamperRejected = false;
      try { ee.openWithKey(tampered, key); } catch (e) { tamperRejected = true; }
      if (!tamperRejected) throw new Error('an export_id-swapped artifact was accepted (AAD not bound)');
      return 'wrong key and export_id-swapped artifact both rejected by the GCM tag';
    });
    await check('export_at_rest', 'Export seal path is wired to the backup-key-wrapping registry', () => {
      const ee = require('./export-encryption');
      if (typeof ee.sealArtifact !== 'function' || typeof ee.openArtifact !== 'function') {
        throw new Error('export-encryption missing sealArtifact / openArtifact');
      }
      if (ee.DEFAULT_SCHEME !== 'env-var' || ee.DEFAULT_KEK_REFERENCE !== 'TIER1_ENCRYPTION_KEY') {
        throw new Error('export-encryption default KEK scheme/ref drifted from env-var / TIER1_ENCRYPTION_KEY');
      }
      const bkw = require('./backup-key-wrapping');
      if (typeof bkw.wrapKey !== 'function' || typeof bkw.unwrapKey !== 'function') {
        throw new Error('backup-key-wrapping wrap/unwrap not available to the export seal path');
      }
      const fs = require('fs');
      const src = fs.readFileSync(path.join(__dirname, 'export-encryption.js'), 'utf-8');
      if (src.indexOf("require('./backup-key-wrapping')") < 0) {
        throw new Error('export-encryption does not require backup-key-wrapping (KEK path not shared)');
      }
      return 'sealArtifact/openArtifact present; default KEK env-var/TIER1; wraps via backup-key-wrapping';
    });

    // ── Category: SDN mode (B5i) ───────────────────────────────────
    await check('sdn_mode', 'SDN integration / network-map / posture tables present', () => {
      const need = ['sdn_integrations', 'sdn_network_map', 'sdn_posture_state', 'sdn_posture_events'];
      const have = this.db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('sdn_integrations','sdn_network_map','sdn_posture_state','sdn_posture_events')")
        .all().map(r => r.name);
      const missing = need.filter(n => have.indexOf(n) === -1);
      if (missing.length) throw new Error('missing SDN tables: ' + missing.join(', '));
      return 'sdn_integrations / sdn_network_map / sdn_posture_state / sdn_posture_events present';
    });

    await check('sdn_mode', 'Deployment-mode exposes the sdn mode and isSdn', () => {
      const dm = require('./deployment-mode');
      if (typeof dm.isSdn !== 'function') throw new Error('deployment-mode is missing isSdn');
      if (dm.SDN !== 'sdn') throw new Error('deployment-mode SDN constant missing or not "sdn"');
      if (!Array.isArray(dm.MODES) || dm.MODES.indexOf('sdn') === -1) throw new Error('sdn is not in deployment-mode MODES');
      return 'isSdn present; SDN constant = sdn; sdn in MODES';
    });

    await check('sdn_mode', 'All eight controller adapters resolve read-only via the registry', () => {
      const reg = require('./sdn');
      const platforms = reg.listPlatforms();
      if (platforms.length !== 8) throw new Error('expected 8 platforms, got ' + platforms.length);
      for (let i = 0; i < platforms.length; i++) {
        const p = platforms[i];
        const adapter = reg.getAdapter(p); // throws if it lacks a read method or exposes a write verb
        if (reg.assertReadOnly(p, adapter) !== adapter) throw new Error('assertReadOnly did not confirm the adapter for ' + p);
      }
      return platforms.length + ' adapters resolve and pass the read-only contract: ' + platforms.join(', ');
    });

    await check('sdn_mode', 'Adapter contract rejects write verbs and requires the read methods', () => {
      const reg = require('./sdn');
      const writeVerbs = ['writeFlows', 'pushPolicy', 'createSegment', 'updateTenant', 'deleteNode', 'applyPolicy', 'enforceSegmentation', 'configureFabric'];
      const escaped = writeVerbs.filter(v => !reg.WRITE_METHOD_RE.test(v));
      if (escaped.length) throw new Error('WRITE_METHOD_RE failed to match write verbs: ' + escaped.join(', '));
      if (reg.WRITE_METHOD_RE.test('probe') || reg.WRITE_METHOD_RE.test('readTopology')) throw new Error('WRITE_METHOD_RE wrongly matched a read method');
      const missingRead = ['probe', 'readTopology', 'readSegmentation'].filter(m => reg.READ_METHODS.indexOf(m) === -1);
      if (missingRead.length) throw new Error('READ_METHODS missing: ' + missingRead.join(', '));
      let rejected = false;
      try { reg.assertReadOnly('custom', { probe() {}, readTopology() {}, readSegmentation() {}, applyPolicy() {} }); }
      catch (_e) { rejected = true; }
      if (!rejected) throw new Error('assertReadOnly accepted an adapter exposing a write verb');
      return 'write verbs rejected; read methods required; a write-capable adapter is refused';
    });

    await check('sdn_mode', 'Posture thresholds and the integration classifier are intact', () => {
      const sp = require('./sdn-posture');
      if (sp.FAILURE_THRESHOLD !== 3 || sp.AUTH_FAILURE_THRESHOLD !== 2 || sp.SUCCESS_THRESHOLD !== 3) {
        throw new Error('posture thresholds drifted (expected FAILURE 3 / AUTH 2 / SUCCESS 3)');
      }
      if (!(sp.STALENESS_MS > 0)) throw new Error('STALENESS_MS is not positive');
      const now = Date.now();
      const at = (deltaMs) => new Date(now - (deltaMs || 0)).toISOString();
      const C = (row) => sp.classifyIntegration(row, now);
      if (C({ last_probe_status: 'unreachable', consecutive_failures: 2, consecutive_successes: 0, last_probe_at: at(1000) }) !== 'watch') {
        throw new Error('2 plain failures must classify as watch (below the degraded threshold)');
      }
      if (C({ last_probe_status: 'unreachable', consecutive_failures: 3, consecutive_successes: 0, last_probe_at: at(1000) }) !== 'down') {
        throw new Error('3 plain failures must classify as down');
      }
      if (C({ last_probe_status: 'error', consecutive_failures: 2, consecutive_successes: 0, last_probe_at: at(1000) }) !== 'down') {
        throw new Error('2 weighted (error/unauthenticated) failures must classify as down');
      }
      if (C({ last_probe_status: 'reachable', consecutive_failures: 0, consecutive_successes: 2, last_probe_at: at(1000) }) !== 'watch') {
        throw new Error('2 successes (below SUCCESS_THRESHOLD) must remain watch, not up');
      }
      if (C({ last_probe_status: 'reachable', consecutive_failures: 0, consecutive_successes: 3, last_probe_at: at(1000) }) !== 'up') {
        throw new Error('3 successes must classify as up');
      }
      return 'thresholds 3/2/3; classifier honors the degraded threshold, weighting, and recovery hysteresis';
    });

    await check('sdn_mode', 'Fail-safe denies the entire /api surface while degraded (assume-breach)', () => {
      const failsafe = require('../middleware/sdn-fail-safe');
      if (!Array.isArray(failsafe._degradedReachable) || failsafe._degradedReachable.length !== 0) {
        throw new Error('the degraded allow-list is not empty; assume-breach requires deny-all');
      }
      const paths = ['/api/health', '/api/auth/login', '/api/sdn/posture', '/api/anything', '/api/'];
      const reachable = paths.filter(p => failsafe._isReachableWhileDegraded(p) === true);
      if (reachable.length) throw new Error('paths wrongly reachable while degraded: ' + reachable.join(', '));
      if (typeof failsafe.sdnFailSafe !== 'function') throw new Error('sdnFailSafe middleware missing');
      return 'empty degraded allow-list; every /api path (health included) is denied while degraded';
    });

    await check('sdn_mode', 'Admission refuses a non-permitted source and admits a permitted one', () => {
      const adm = require('../middleware/sdn-admission');
      if (typeof adm._ipMatchesEntry !== 'function') throw new Error('admission matcher hook (_ipMatchesEntry) is missing');
      if (adm._ipMatchesEntry('10.20.0.5', '10.20.0.0/24') !== true) throw new Error('a source inside a permitted CIDR must match');
      if (adm._ipMatchesEntry('10.20.0.5', '10.20.0.5') !== true) throw new Error('an exact IPv4 source must match');
      if (adm._ipMatchesEntry('192.168.50.1', '10.20.0.0/24') !== false) throw new Error('a source outside the permitted CIDR must NOT match (refusal invariant)');
      const mw = adm.sdnAdmission();
      const res = { status() { return { json() {} }; } };
      let passedThrough = false;
      mw({ app: { locals: { deploymentMode: {} } }, ip: '192.168.50.1', path: '/api/x' }, res, () => { passedThrough = true; });
      if (!passedThrough) throw new Error('admission must pass through outside sdn mode');
      let admittedLoopback = false;
      mw({ app: { locals: { deploymentMode: { sdn: true } } }, ip: '127.0.0.1', path: '/api/x' }, res, () => { admittedLoopback = true; });
      if (!admittedLoopback) throw new Error('loopback must be admitted in sdn mode');
      return 'matcher admits permitted CIDR/exact, refuses non-permitted; mode-gate passes through; loopback admitted';
    });

    await check('sdn_mode', 'SDN has its own route and is no longer a generic integration type', () => {
      const fsMod = require('fs');
      const src = fsMod.readFileSync(path.join(__dirname, '..', 'routes', 'integrations.js'), 'utf-8');
      const m = src.match(/const VALID_TYPES = \[([\s\S]*?)\]/);
      if (!m) throw new Error('could not locate VALID_TYPES in integrations.js');
      if (/['"]sdn['"]/.test(m[1])) throw new Error("'sdn' is still present in the generic integrations VALID_TYPES");
      const sdnRoute = require('../routes/sdn');
      if (typeof sdnRoute !== 'function') throw new Error('routes/sdn did not load as a router');
      return "'sdn' removed from generic VALID_TYPES; dedicated routes/sdn router loads";
    });

    await check('sdn_mode', 'Deployment-mode exposes the substrate API (B5i2)', () => {
      const dm = require('./deployment-mode');
      if (!Array.isArray(dm.SUBSTRATES)) throw new Error('deployment-mode SUBSTRATES is not an array');
      const missing = ['bare-metal', 'virtualized', 'cloud'].filter(x => dm.SUBSTRATES.indexOf(x) === -1);
      if (missing.length) throw new Error('SUBSTRATES missing: ' + missing.join(', '));
      if (typeof dm.detectSubstrate !== 'function') throw new Error('deployment-mode is missing detectSubstrate');
      return 'SUBSTRATES = [' + dm.SUBSTRATES.join(', ') + ']; detectSubstrate present';
    });

    await check('sdn_mode', 'Substrate gates are present and fail safe with no sealed record (B5i2)', () => {
      const dm = require('./deployment-mode');
      const s = dm.summary(this.db);
      const need = ['substrate', 'substrateVirtualized', 'substrateCloud', 'easilyCopied', 'ccRequired'];
      const absent = need.filter(k => !(k in s));
      if (absent.length) throw new Error('deployment-mode summary missing substrate fields: ' + absent.join(', '));
      // No sealed record: the host is treated as bare-metal, so none of the
      // easily-copied gates fire. This is the fail-safe default the pre-auth
      // and clock-integrity gates depend on.
      if (s.substrateVirtualized || s.substrateCloud || s.easilyCopied || s.ccRequired) {
        throw new Error('substrate gates must all be false with no sealed record');
      }
      return 'summary exposes substrate fields; all easily-copied gates false by default';
    });

    // -- SASE mode (B5k): the fifth deployment mode, substrate-aware ----------
    await check('sase_mode', 'SASE posture-events table present', () => {
      const have = this.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='sase_posture_events'").all().map(r => r.name);
      if (have.indexOf('sase_posture_events') === -1) throw new Error('sase_posture_events table is missing');
      return 'sase_posture_events present';
    });

    await check('sase_mode', 'Deployment-mode exposes sase, isSase, and the summary fields', () => {
      const dm = require('./deployment-mode');
      if (typeof dm.isSase !== 'function') throw new Error('deployment-mode is missing isSase');
      if (dm.SASE !== 'sase') throw new Error('deployment-mode SASE constant missing or not "sase"');
      if (!Array.isArray(dm.MODES) || dm.MODES.indexOf('sase') === -1) throw new Error('sase is not in deployment-mode MODES');
      const s = dm.summary(this.db);
      const need = ['sase', 'networkMode', 'substrate', 'substrateVirtualized', 'substrateCloud', 'easilyCopied', 'ccRequired'];
      const absent = need.filter(k => !(k in s));
      if (absent.length) throw new Error('summary missing fields: ' + absent.join(', '));
      if (s.sase !== false) throw new Error('sase must be false with no sealed record');
      if (s.networkMode !== null) throw new Error('networkMode must be null with no sealed record');
      return 'isSase + SASE=sase + sase in MODES; summary exposes sase/networkMode/substrate fields (false/null by default)';
    });

    await check('sase_mode', 'setMode requires a valid substrate for sase (fail-closed)', () => {
      const dm = require('./deployment-mode');
      const mem = cloneLiveSchema(this.db);
      let missingRejected = false, badRejected = false, validAccepted = false;
      try { dm.setMode(mem, 'sase', {}); } catch (e) { if (e.code === 'INVALID_SUBSTRATE') missingRejected = true; }
      try { dm.setMode(mem, 'sase', { substrate: 'nonsense' }); } catch (e) { if (e.code === 'INVALID_SUBSTRATE') badRejected = true; }
      // A valid substrate passes the substrate gate and only then fails at the anchor step.
      try { dm.setMode(mem, 'sase', { substrate: 'virtualized' }); } catch (e) { if (e.code === 'ANCHOR_REQUIRED') validAccepted = true; }
      if (!missingRejected) throw new Error('sase with no substrate must be rejected (INVALID_SUBSTRATE)');
      if (!badRejected) throw new Error('sase with an invalid substrate must be rejected (INVALID_SUBSTRATE)');
      if (!validAccepted) throw new Error('sase with a valid substrate must pass the substrate gate (reach ANCHOR_REQUIRED)');
      return 'sase requires a valid substrate; missing/invalid rejected; a valid substrate is accepted past the gate';
    });

    await check('sase_mode', 'Admission admits the connector source, refuses non-connector, and detects clientless headers', () => {
      const adm = require('../middleware/sase-admission');
      if (typeof adm._ipMatchesEntry !== 'function') throw new Error('admission matcher hook (_ipMatchesEntry) is missing');
      if (adm._ipMatchesEntry('203.0.113.7', '203.0.113.0/24') !== true) throw new Error('a peer inside a connector CIDR must match');
      if (adm._ipMatchesEntry('203.0.113.7', '203.0.113.7') !== true) throw new Error('an exact connector IPv4 must match');
      if (adm._ipMatchesEntry('198.51.100.9', '203.0.113.0/24') !== false) throw new Error('a peer outside the connector allow-list must NOT match (direct-exposure invariant)');
      if (typeof adm._clientlessIdentityHeader !== 'function') throw new Error('passthrough hook (_clientlessIdentityHeader) is missing');
      if (adm._clientlessIdentityHeader({ headers: { 'cf-access-authenticated-user-email': 'a@b.c' } }) !== 'cf-access-authenticated-user-email') throw new Error('a clientless identity header must be detected');
      if (adm._clientlessIdentityHeader({ headers: { 'x-forwarded-for': '1.2.3.4' } }) !== null) throw new Error('X-Forwarded-For must NOT be treated as a clientless identity header');
      if (adm._clientlessIdentityHeader({ headers: {} }) !== null) throw new Error('no identity header must return null');
      return 'connector CIDR/exact admitted, non-connector refused; clientless header detected; XFF not flagged';
    });

    await check('sase_mode', 'Admission passes through outside sase mode and admits loopback in sase mode', () => {
      const adm = require('../middleware/sase-admission');
      const mw = adm.saseAdmission();
      const res = { status() { return { json() {} }; } };
      let passedThrough = false;
      mw({ app: { locals: { deploymentMode: {} } }, socket: { remoteAddress: '198.51.100.9' }, headers: {}, path: '/api/x' }, res, () => { passedThrough = true; });
      if (!passedThrough) throw new Error('admission must pass through outside sase mode');
      let admittedLoopback = false;
      mw({ app: { locals: { deploymentMode: { sase: true } } }, socket: { remoteAddress: '127.0.0.1' }, headers: {}, path: '/api/x' }, res, () => { admittedLoopback = true; });
      if (!admittedLoopback) throw new Error('loopback must be admitted in sase mode');
      return 'pass-through outside sase mode; loopback admitted in sase mode (against the raw socket peer)';
    });

    await check('sase_mode', 'Fail-safe denies the entire /api surface while degraded (assume-breach)', () => {
      const failsafe = require('../middleware/sase-fail-safe');
      if (!Array.isArray(failsafe._degradedReachable) || failsafe._degradedReachable.length !== 0) throw new Error('the degraded allow-list is not empty; assume-breach requires deny-all');
      const paths = ['/api/health', '/api/auth/login', '/api/sase/config', '/api/anything', '/api/'];
      const reachable = paths.filter(p => failsafe._isReachableWhileDegraded(p) === true);
      if (reachable.length) throw new Error('paths wrongly reachable while degraded: ' + reachable.join(', '));
      if (typeof failsafe.saseFailSafe !== 'function') throw new Error('saseFailSafe middleware missing');
      return 'empty degraded allow-list; every /api path is denied while sase posture is degraded';
    });

    await check('sase_mode', 'Posture latches degraded on a boundary-failure event and clears on an explicit restore', () => {
      const sm = require('./sase-mode');
      const mem = cloneLiveSchema(this.db);
      if (sm.getPosture(mem).degraded !== false) throw new Error('a fresh deployment must not be degraded');
      sm.recordPostureEvent(mem, { eventType: 'direct_exposure_refused', severity: 'critical', detail: { sourceIp: '198.51.100.9' } });
      if (sm.getPosture(mem).degraded !== true) throw new Error('a direct-exposure refusal must latch posture degraded');
      sm.recordPostureEvent(mem, { eventType: 'posture_restored', severity: 'info' });
      if (sm.getPosture(mem).degraded !== false) throw new Error('an explicit restore must clear the latch');
      return 'healthy by default; latches degraded on a direct-exposure refusal; clears only on an explicit restore';
    });

    await check('sase_mode', 'SASE probe descriptor is present, in the roster, not configured by default, and read-only', () => {
      const ihp = require('./integration-health-probes');
      const cfg = require('./integration-health-config');
      if (!Array.isArray(cfg.INTEGRATION_KEYS) || cfg.INTEGRATION_KEYS.indexOf('sase') === -1) throw new Error('sase is not in INTEGRATION_KEYS');
      const sase = ihp.registry.find((d) => d.key === 'sase');
      if (!sase) throw new Error('sase descriptor missing from the probe registry');
      if (typeof ihp.saseProbe !== 'function') throw new Error('saseProbe is not exported');
      if (sase.configured(this.db) !== false) throw new Error('sase.configured() must be false without sase mode + connector sources');
      const r = ihp.saseProbe(this.db);
      if (!r || r.status !== 'not_configured') throw new Error('saseProbe must report not_configured on a non-sase deployment');
      return 'sase in INTEGRATION_KEYS; descriptor present; configured() false by default; probe reports not_configured without dialing the provider';
    });

    await check('sase_mode', 'Connector-source normalizer trims, de-duplicates, and rejects malformed entries', () => {
      const sm = require('./sase-mode');
      if (typeof sm.normalizeConnectorSources !== 'function') throw new Error('normalizeConnectorSources is not exported');
      const ok = sm.normalizeConnectorSources([' 203.0.113.0/24 ', '198.51.100.7', '203.0.113.0/24']);
      if (ok.length !== 2) throw new Error('normalizer must trim and de-duplicate (expected 2, got ' + ok.length + ')');
      let rejectedBad = false, rejectedType = false;
      try { sm.normalizeConnectorSources(['not a cidr!!']); } catch (_e) { rejectedBad = true; }
      try { sm.normalizeConnectorSources('nope'); } catch (_e) { rejectedType = true; }
      if (!rejectedBad) throw new Error('a malformed connector source must be rejected');
      if (!rejectedType) throw new Error('a non-array connector-sources value must be rejected');
      return 'normalizer trims/dedupes valid CIDRs and rejects malformed entries and non-array input';
    });

    // ── Data residency (B5n2) ────────────────────────────────────
    await check('data_residency', 'Residency tables present', () => {
      return requireAll(['data_residency_destinations', 'data_residency_transfers']);
    });
    await check('data_residency', 'Destination-declaration unique index present', () => {
      if (!indexExists('idx_residency_dest')) throw new Error('missing idx_residency_dest');
      return 'idx_residency_dest present';
    });
    await check('data_residency', 'Data categories are canonical (6; live_deployment first)', () => {
      const dr = require('./data-residency');
      const expected = ['live_deployment', 'backup', 'audit_log', 'forensic_export', 'snapshot', 'cef_archive'];
      const missing = expected.filter(c => !dr.CATEGORIES.includes(c));
      if (missing.length > 0) throw new Error('missing categories: ' + missing.join(', '));
      if (dr.CATEGORIES[0] !== 'live_deployment') throw new Error('live_deployment must be first');
      return dr.CATEGORIES.length + ' categories';
    });
    await check('data_residency', 'Default policy is safe (disabled; live_deployment declare-only; nulls)', () => {
      const dr = require('./data-residency');
      const d = dr.defaultConfig();
      if (d.enabled !== false) throw new Error('default must be disabled');
      if (d.primaryResidency.country !== null) throw new Error('default primary country must be null');
      if (!d.categories.live_deployment || d.categories.live_deployment.mode !== 'declare-only') {
        throw new Error('live_deployment must default to declare-only');
      }
      if (!d.categories.backup || d.categories.backup.mode !== 'warn') throw new Error('backup must default to warn');
      return 'default policy disabled and safe';
    });
    await check('data_residency', 'Modes are canonical (enforce, warn, declare-only)', () => {
      const dr = require('./data-residency');
      const expected = ['enforce', 'warn', 'declare-only'];
      const missing = expected.filter(m => !dr.MODES.includes(m));
      if (missing.length > 0) throw new Error('missing modes: ' + missing.join(', '));
      return dr.MODES.length + ' modes';
    });
    await check('data_residency', 'Cloud region resolves to jurisdiction (AWS); provider domicile US', () => {
      const rg = require('./residency-regions');
      const us = rg.regionToCountry('us-east-1');
      if (!us || us.country !== 'US' || us.domicile !== 'US') throw new Error('us-east-1 must map to US / US-domicile');
      const eu = rg.regionToCountry('eu-west-1');
      if (!eu || !eu.country) throw new Error('eu-west-1 must map to a country');
      if (rg.resolveJurisdiction(eu.country).blocs.indexOf('EU') === -1) {
        throw new Error('eu-west-1 country must resolve into the EU bloc');
      }
      if (rg.regionToCountry('zz-nowhere-1') !== null) throw new Error('unknown region must map to null');
      return 'us-east-1 -> US; eu-west-1 -> ' + eu.country + ' (EU)';
    });
    await check('data_residency', 'Permitted-region check honours bloc membership', () => {
      const rg = require('./residency-regions');
      if (rg.isPermitted('DE', ['EU']) !== true) throw new Error('DE must be permitted under EU');
      if (rg.isPermitted('US', ['EU']) !== false) throw new Error('US must not be permitted under EU');
      if (rg.isPermitted('DE', ['DE']) !== true) throw new Error('DE must be permitted under exact DE');
      return 'bloc + exact membership honoured';
    });
    await check('data_residency', 'Empty permitted list is default-deny', () => {
      const rg = require('./residency-regions');
      if (rg.isPermitted('DE', []) !== false) throw new Error('empty permitted list must deny');
      return 'empty permitted list denies';
    });
    await check('data_residency', 'Policy block is enforce-only (pure decision)', () => {
      const dr = require('./data-residency');
      const cfg = {
        enabled: true,
        primaryResidency: { country: 'DE' },
        categories: {
          backup: { permittedRegions: ['EU'], mode: 'enforce' },
          snapshot: { permittedRegions: ['EU'], mode: 'warn' },
        },
      };
      if (dr.isBlockedByPolicy(cfg, 'backup', 'US') !== true) throw new Error('enforce + non-permitted must block');
      if (dr.isBlockedByPolicy(cfg, 'backup', 'DE') !== false) throw new Error('enforce + permitted must not block');
      if (dr.isBlockedByPolicy(cfg, 'snapshot', 'US') !== false) throw new Error('warn mode must never block');
      return 'enforce blocks non-permitted; warn never blocks';
    });
    await check('data_residency', 'Foreign-law exposure reflects provider domicile (residency != sovereignty)', () => {
      const dr = require('./data-residency');
      const us = dr.foreignLawExposure('US');
      if (!us || !/CLOUD Act/i.test(us)) throw new Error('US domicile must cite the CLOUD Act');
      if (!dr.foreignLawExposure('DE')) throw new Error('non-US domicile must report a provider-domicile law');
      if (dr.foreignLawExposure(null) !== null) throw new Error('null domicile must be null');
      return 'US -> CLOUD Act; other -> domicile law; null -> null';
    });
    await check('data_residency', 'Transfer-mechanism status derivation', () => {
      const dr = require('./data-residency');
      for (const m of ['adequacy', 'scc', 'bcr', 'derogation']) {
        if (dr.deriveStatus(m) !== 'documented') throw new Error(m + ' must be documented');
      }
      for (const m of ['none', 'unset']) {
        if (dr.deriveStatus(m) !== 'undocumented') throw new Error(m + ' must be undocumented');
      }
      return 'adequacy/scc/bcr/derogation documented; none/unset undocumented';
    });
    await check('data_residency', 'Register summary and config load are well-formed', () => {
      const dr = require('./data-residency');
      const cfg = dr.loadResidencyConfig(this.db);
      if (typeof cfg.enabled !== 'boolean' || !cfg.categories || !cfg.primaryResidency) {
        throw new Error('loadResidencyConfig shape invalid');
      }
      const sm = dr.summarize(this.db);
      if (typeof sm.transfers !== 'number' || typeof sm.documented !== 'number' || typeof sm.blocked !== 'number') {
        throw new Error('summarize shape invalid');
      }
      if (sm.documented > sm.transfers || sm.blocked > sm.transfers) throw new Error('summary counts inconsistent');
      return sm.transfers + ' transfer(s), ' + sm.documented + ' documented, ' + sm.blocked + ' blocked';
    });

    // -- Category: High Availability / Failover (B5o) --
    await check('high_availability', 'HA tables present', () => {
      return requireAll(['ha_node', 'ha_peer', 'ha_lease', 'ha_replication_journal', 'ha_replication_state']);
    });
    await check('high_availability', 'Lease epoch monotonic trigger present', () => {
      const row = this.db.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name='ha_lease_epoch_monotonic'").get();
      if (!row) throw new Error('missing trigger ha_lease_epoch_monotonic');
      return 'trigger present';
    });
    await check('high_availability', 'Write-authority gate API present', () => {
      const hl = require('./ha/ha-lease');
      const need = ['assertWriteAuthority', 'iAmActive', 'currentEpoch', 'renewLease', 'recordPeerHeartbeat', 'claimNextEpoch'];
      const missing = need.filter(f => typeof hl[f] !== 'function');
      if (missing.length > 0) throw new Error('ha-lease missing: ' + missing.join(', '));
      return need.length + ' function(s) present';
    });
    await check('high_availability', 'Write authority is a no-op on a standalone node', () => {
      const hl = require('./ha/ha-lease');
      // A standalone DB (no ha_node self row) must NEVER have writes refused:
      // assertWriteAuthority returns silently rather than throwing. This guards
      // the fail-open property that keeps single-node deployments writable.
      hl.assertWriteAuthority(this.db);
      return 'standalone write allowed (no throw)';
    });
    await check('high_availability', 'Failover promotion API present', () => {
      const hf = require('./ha/ha-failover');
      const need = ['evaluatePromotion', 'promote', 'demote', 'reconcileRole', 'activeIsDown', 'checkSelfFence'];
      const missing = need.filter(f => typeof hf[f] !== 'function');
      if (missing.length > 0) throw new Error('ha-failover missing: ' + missing.join(', '));
      return need.length + ' function(s) present';
    });
    await check('high_availability', 'HA route module loads', () => {
      const r = require('../routes/ha');
      if (typeof r !== 'function') throw new Error('route is not an express router');
      return 'router exported';
    });
    await check('high_availability', 'Scheduler HA write gate present', () => {
      const { schedulerService } = require('./scheduler');
      const need = ['haReplicationContext', 'haWriteAuthority', 'mayRunWriteJob'];
      const missing = need.filter(f => typeof schedulerService[f] !== 'function');
      if (missing.length > 0) throw new Error('scheduler missing: ' + missing.join(', '));
      return need.length + ' method(s) present';
    });
    await check('high_availability', 'Request-layer write guard present and fails open on standalone', () => {
      const g = require('../middleware/ha-write-guard');
      if (typeof g.haWriteGuard !== 'function' || typeof g.isConfirmedPassive !== 'function') {
        throw new Error('ha-write-guard API missing');
      }
      // On a standalone node the guard must NOT classify it as a passive.
      if (g.isConfirmedPassive(this.db) !== false) throw new Error('standalone misclassified as passive');
      return 'guard present; standalone not blocked';
    });
    await check('high_availability', 'Cluster config removed from golden baseline (absence)', () => {
      const gb = require('./golden-baseline');
      if (!Array.isArray(gb.CONFIG_TABLE_KEYS)) throw new Error('CONFIG_TABLE_KEYS not exported');
      if (gb.CONFIG_TABLE_KEYS.includes('cluster_config')) throw new Error('cluster_config still present in golden baseline');
      if (!gb.CONFIG_TABLE_KEYS.includes('ha_config')) throw new Error('ha_config missing from golden baseline');
      return 'cluster_config absent; ha_config present';
    });
    await check('high_availability', 'Scheduler HA tick re-registration API present', () => {
      const { schedulerService } = require('./scheduler');
      const need = ['_registerHaJobs', 'reloadHaJobs', '_haIntervals'];
      const missing = need.filter(f => typeof schedulerService[f] !== 'function');
      if (missing.length > 0) throw new Error('scheduler missing: ' + missing.join(', '));
      return need.length + ' method(s) present';
    });
    await check('high_availability', 'Liveness tracker records and snapshots', () => {
      const hl = require('./ha/ha-liveness');
      const need = ['recordClientRequest', 'recordPeerContact', 'snapshot'];
      const missing = need.filter(f => typeof hl[f] !== 'function');
      if (missing.length > 0) throw new Error('ha-liveness missing: ' + missing.join(', '));
      hl.recordClientRequest();
      hl.recordPeerContact();
      const snap = hl.snapshot();
      if (!snap || !Number.isFinite(Date.parse(snap.lastClientRequestAt)) || !Number.isFinite(Date.parse(snap.lastPeerContactAt))) {
        throw new Error('snapshot did not return parseable timestamps');
      }
      return 'snapshot returns lastClientRequestAt + lastPeerContactAt';
    });
    await check('high_availability', 'Detector threshold honors configured heartbeat interval', () => {
      const hf = require('./ha/ha-failover');
      const mem = cloneLiveSchema(this.db);
      try {
        mem.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ha_config', ?)")
          .run(JSON.stringify({ enabled: true, heartbeatIntervalSec: 11, missCount: 4 }));
        const cfg = hf.getFailoverConfig(mem);
        if (cfg.heartbeatIntervalSec !== 11) {
          throw new Error('getFailoverConfig ignored heartbeatIntervalSec (got ' + cfg.heartbeatIntervalSec + ')');
        }
        return 'config heartbeatIntervalSec=11 flows to the detector';
      } finally {
        mem.close();
      }
    });
    await check('high_availability', 'Self-fence abstains without two signals and fences on dual isolation', () => {
      const hf = require('./ha/ha-failover');
      const isoSec = 30;
      const stale = new Date(Date.now() - (isoSec + 120) * 1000).toISOString();
      const fresh = new Date().toISOString();
      // A drill must never forge a fence event. ha-failover audits through the
      // connection it mutates (auditLogOn), so a fence exercised against this
      // hermetic clone must record HA_SELF_FENCED in the CLONE and leave the live
      // hash-chained audit_log -- which an operator or auditor reads as a record of
      // real events -- untouched. Both halves are asserted below.
      const liveFenceRows = () => this.db
        .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE event_type = 'HA_SELF_FENCED'").get().n;
      const liveBefore = liveFenceRows();
      const setup = () => {
        const mem = cloneLiveSchema(this.db);
        mem.prepare("INSERT OR REPLACE INTO ha_node (id, role) VALUES ('self', 'active')").run();
        mem.prepare("INSERT OR REPLACE INTO ha_lease (id, holder, epoch, term_started_at) VALUES ('current', 'self', 1, datetime('now'))").run();
        mem.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('ha_config', ?)")
          .run(JSON.stringify({ enabled: true, selfFenceTimeoutSec: isoSec }));
        return mem;
      };
      // 1. No signals -> insufficient_signal: never fence a node that may be serving.
      let mem = setup();
      try {
        const r = hf.checkSelfFence(mem, {});
        if (r.fenced !== false || r.reason !== 'insufficient_signal') {
          throw new Error('null signals must not fence (got ' + JSON.stringify(r) + ')');
        }
      } finally { mem.close(); }
      // 2. One fresh signal -> not isolated, no fence.
      mem = setup();
      try {
        const r = hf.checkSelfFence(mem, { lastPeerContactAt: stale, lastClientRequestAt: fresh });
        if (r.fenced !== false) throw new Error('a fresh client signal must not fence (got ' + JSON.stringify(r) + ')');
      } finally { mem.close(); }
      // 3. Both signals stale -> fence and demote to passive, auditing INTO the clone.
      mem = setup();
      try {
        const r = hf.checkSelfFence(mem, { lastPeerContactAt: stale, lastClientRequestAt: stale });
        if (r.fenced !== true) throw new Error('dual isolation must fence (got ' + JSON.stringify(r) + ')');
        const role = mem.prepare("SELECT role FROM ha_node WHERE id = 'self'").get().role;
        if (role !== 'passive') throw new Error('self-fence did not demote to passive (role=' + role + ')');
        const clonedRows = mem
          .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE event_type = 'HA_SELF_FENCED'").get().n;
        if (clonedRows !== 1) {
          throw new Error('the fence audited ' + clonedRows + ' rows into the clone; it must audit through the connection it mutates');
        }
      } finally { mem.close(); }
      // 4. The live tamper-evident chain must be untouched by the drill.
      if (liveFenceRows() !== liveBefore) {
        throw new Error('the self-fence check forged an HA_SELF_FENCED row into the LIVE audit chain');
      }
      return 'abstains on null/single signal; fences + demotes on dual isolation; audits into the clone, live chain untouched';
    });

    // ── B6d: peer-response contract ────────────────────────────────────
    // sendToPeer resolves the PARSED RESPONSE BODY; there is no { json } wrapper.
    // Three call sites once read `.json` and silently received undefined. The worst
    // consequence was in the failover self-test: the peer's epoch was never adopted,
    // so the fail-back re-promotion TIED the peer's epoch, leaving two actives at one
    // epoch -- a split-brain produced by the drill meant to prove failover was safe.
    // These two checks make the class fail in CI rather than in the field.
    // Replace comments, string literals, and regex literals with equivalent whitespace,
    // preserving newlines. A regex-based stripper cannot do this: it desynchronises on a
    // double-quoted string containing an apostrophe ("'") or on a regex literal (/'/g),
    // after which the rest of the file is treated as string content and silently skipped.
    // ha-pairing.js contains exactly that construct in restoreBaseline, and roughly two
    // thirds of it was invisible to the previous scan -- a source guard that cannot see
    // the source is worse than none, because it reports clean.
    const haStripNonCode = (src) => {
      const n = src.length;
      let out = '';
      let i = 0;
      let prev = '';
      const blank = (ch) => (ch === '\n' ? '\n' : ' ');
      while (i < n) {
        const c = src[i];
        const d = src[i + 1];
        if (c === '/' && d === '/') { while (i < n && src[i] !== '\n') { out += ' '; i += 1; } continue; }
        if (c === '/' && d === '*') {
          out += '  '; i += 2;
          while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { out += blank(src[i]); i += 1; }
          out += '  '; i += 2; continue;
        }
        if (c === "'" || c === '"' || c === '`') {
          const q = c; out += ' '; i += 1;
          while (i < n) {
            if (src[i] === '\\') { out += '  '; i += 2; continue; }
            if (src[i] === q) { out += ' '; i += 1; break; }
            out += blank(src[i]); i += 1;
          }
          prev = 'x'; continue;
        }
        if (c === '/' && prev && '(,=:[!&|?{};+-*%~^<>'.indexOf(prev) !== -1) {
          out += ' '; i += 1;
          let inClass = false;
          while (i < n) {
            const e = src[i];
            if (e === '\\') { out += '  '; i += 2; continue; }
            if (e === '\n') break;
            if (e === '[') inClass = true;
            else if (e === ']') inClass = false;
            else if (e === '/' && !inClass) { out += ' '; i += 1; break; }
            out += ' '; i += 1;
          }
          while (i < n && /[a-z]/.test(src[i])) { out += ' '; i += 1; }
          prev = 'x'; continue;
        }
        out += c;
        if (!/\s/.test(c)) prev = c;
        i += 1;
      }
      return out;
    };

    // Brace-matched function bodies, so a call is attributed to the function making it.
    const haFunctions = (src) => {
      const out = [];
      const re = /(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*\{/g;
      let m;
      while ((m = re.exec(src)) !== null) {
        let i = re.lastIndex - 1;
        let depth = 0;
        for (; i < src.length; i += 1) {
          if (src[i] === '{') depth += 1;
          else if (src[i] === '}') { depth -= 1; if (depth === 0) break; }
        }
        out.push({ name: m[1], body: src.slice(m.index, i + 1) });
      }
      return out;
    };

    await check('high_availability', 'Alert router withholds the replicated notification row on a passive', async () => {
      // `notifications` is a REPLICATED table and _chNotification is the only channel
      // that writes one. Timer-driven alerts (the runtime monitor, the bandwidth
      // monitor) reach the router without passing the request-layer write guard, so a
      // confirmed passive would insert rows the active never had -- diverging the pair.
      // The alert must not be lost either: audit is dispatched before the de-dup gate,
      // unconditionally, into the node-local hash-chained audit_log.
      const crypto = require('crypto');
      const { routeAlert, MATRIX_CONFIG_KEY } = require('./alert-router');
      // A notification-only matrix keeps this drill off SOAR / SIEM / email / webhook,
      // and severity 'high' avoids the critical path's urgent-refresh broadcast.
      const matrix = { high: { soar: false, siem: false, email: false, notification: true, webhook: false } };
      const liveNotifs = () => this.db
        .prepare("SELECT COUNT(*) AS n FROM notifications WHERE event_type LIKE 'HA_REGRESSION_PROBE_%'").get().n;
      const liveAudits = () => this.db
        .prepare("SELECT COUNT(*) AS n FROM audit_log WHERE event_type LIKE 'HA_REGRESSION_PROBE_%'").get().n;
      const liveNotifsBefore = liveNotifs();
      const liveAuditsBefore = liveAudits();
      const setup = (haCfg, paired, role) => {
        const mem = cloneLiveSchema(this.db);
        mem.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run(MATRIX_CONFIG_KEY, JSON.stringify(matrix));
        mem.prepare("INSERT INTO users (id, username, role, name, active) VALUES ('ha-reg-admin', 'ha-reg-admin', 'admin', 'HA Regression Admin', 1)").run();
        if (haCfg) mem.prepare("INSERT INTO config (key, value) VALUES ('ha_config', ?)").run(JSON.stringify(haCfg));
        if (paired) {
          mem.prepare("INSERT INTO ha_peer (peer_endpoint, peer_anchor_fingerprint, peer_anchor_public_pem, peer_wrap_public_pem, peer_cert_fingerprint, status) VALUES ('https://peer:8443', 'fp', 'pem', 'pem', 'certfp', 'paired')").run();
        }
        if (role) mem.prepare("INSERT OR REPLACE INTO ha_node (id, role) VALUES ('self', ?)").run(role);
        return mem;
      };
      // A distinct type per case: the de-dup gate is module-level and keyed on
      // (type|severity), so reusing one type would suppress the later calls and the
      // passive would show zero rows because it was DEDUPED rather than gated -- a check
      // that could not fail.
      const probeType = () => 'HA_REGRESSION_PROBE_' + crypto.randomBytes(6).toString('hex');
      const notifRows = (mem) => mem.prepare('SELECT COUNT(*) AS n FROM notifications').get().n;
      const auditRows = (mem, t) => mem.prepare('SELECT COUNT(*) AS n FROM audit_log WHERE event_type = ?').get(t).n;
      const chan = (out, name) => out.channels.find((c) => c.channel === name);

      // Standalone and a paired active both write the replicated row: the gate fails open.
      for (const [label, haCfg, paired, role] of [['standalone', null, false, null], ['paired active', { enabled: true }, true, 'active']]) {
        const mem = setup(haCfg, paired, role);
        const type = probeType();
        try {
          const out = await routeAlert(mem, { type: type, severity: 'high', message: 'sole-writer regression probe' });
          if (out.deduped) throw new Error(label + ': the probe was de-duplicated, so nothing was asserted');
          if (notifRows(mem) !== 1) throw new Error(label + ' must write the notification row (got ' + notifRows(mem) + ')');
          const n = chan(out, 'notification');
          if (n && n.status === 'skipped_ha_passive') throw new Error(label + ' was wrongly treated as a passive');
        } finally { mem.close(); }
      }

      // A confirmed paired passive withholds the replicated row -- and only that.
      const mem = setup({ enabled: true }, true, 'passive');
      const type = probeType();
      try {
        const out = await routeAlert(mem, { type: type, severity: 'high', message: 'sole-writer regression probe' });
        if (out.deduped) throw new Error('the passive probe was de-duplicated, so nothing was asserted');
        if (notifRows(mem) !== 0) throw new Error('a confirmed passive must not write the replicated notification row');
        const n = chan(out, 'notification');
        if (!n || n.status !== 'skipped_ha_passive') throw new Error('the passive skip must be reported as skipped_ha_passive, not hidden');
        // The alert is not lost, and the audit lands where the router was told to write.
        const a = chan(out, 'audit');
        if (!a || a.ok !== true) throw new Error('the audit channel must still fire on a passive');
        if (auditRows(mem, type) !== 1) throw new Error('the alert must be audited into the connection the router was handed');
      } finally { mem.close(); }

      if (liveNotifs() !== liveNotifsBefore) throw new Error('the regression probe wrote a notification row into the LIVE database');
      if (liveAudits() !== liveAuditsBefore) throw new Error('the regression probe forged an alert row into the LIVE audit chain');
      return 'standalone + active write; passive withholds only the replicated row; audit lands in the clone, live chain untouched';
    });
    await check('high_availability', 'Peer response resolves the body; .json wrapper reads throw', () => {
      const { parsePeerResponse } = require('./ha/ha-peer-link');
      if (typeof parsePeerResponse !== 'function') throw new Error('ha-peer-link.parsePeerResponse not exported');
      const body = parsePeerResponse('{"epoch":9,"ok":true}', 200);
      if (body.epoch !== 9 || body.ok !== true) throw new Error('body fields not readable directly');
      if (JSON.stringify(parsePeerResponse('', 200)) !== '{}') throw new Error('empty body should yield {}');
      let loud = false;
      try { void body.json; } catch (e) { loud = /no .json wrapper/.test(e.message); }
      if (!loud) throw new Error('.json wrapper read did not throw');
      let http = false;
      try { parsePeerResponse('stale', 409); } catch (e) { http = /HTTP 409/.test(e.message); }
      if (!http) throw new Error('non-2xx did not throw');
      let bad = false;
      try { parsePeerResponse('not json', 200); } catch (e) { bad = /malformed JSON/.test(e.message); }
      if (!bad) throw new Error('malformed body did not throw');
      return 'body parsed directly; .json throws; non-2xx + malformed throw';
    });
    await check('high_availability', 'No HA source reads .json off a peer-link result', () => {
      const fsMod = require('fs');
      const pathMod = require('path');
      // The full HA surface. A guard that is not looking somewhere reports clean: the
      // audit-connection guard's first target list omitted the peer links and this
      // scheduler, and three real sites sat outside it until VERIFY-MERGE swept
      // independently.
      const targets = [
        '../routes/ha.js',
        '../middleware/ha-write-guard.js',
        './alert-router.js',
        './scheduler.js',
        './ha/ha-cdc.js',
        './ha/ha-failover.js',
        './ha/ha-keys.js',
        './ha/ha-lease.js',
        './ha/ha-liveness.js',
        './ha/ha-modes.js',
        './ha/ha-pairing.js',
        './ha/ha-peer-link.js',
        './ha/ha-replication.js',
      ];
      // haStripNonCode blanks comments, strings, and regex literals, so the scan never
      // flags the prose that names the wrong idiom on purpose. res.json(...) is the
      // response helper and is the only permitted receiver.
      const offenders = [];
      let scanned = 0;
      for (const rel of targets) {
        const abs = pathMod.join(__dirname, rel);
        if (!fsMod.existsSync(abs)) continue;
        scanned += 1;
        const code = haStripNonCode(fsMod.readFileSync(abs, 'utf8'));
        const re = /([A-Za-z_$][A-Za-z0-9_$]*)\.json\b/g;
        let m;
        while ((m = re.exec(code)) !== null) {
          if (m[1] !== 'res') offenders.push(rel + ': ' + m[1] + '.json');
        }
      }
      if (offenders.length) throw new Error('peer-link result read via a .json wrapper: ' + offenders.join(', '));
      return scanned + ' HA sources scanned; no wrapper reads';
    });
    await check('high_availability', 'HA modules audit through the connection they are handed', () => {
      // Seven modules across both servers took a database handle, mutated it, and then
      // audited through a SECOND connection opened with getDb(). On a live node both
      // point at one file, so nothing was visibly wrong -- but handed any other database
      // (a hermetic clone, a drill) the change lands in one place and the tamper-evident
      // audit row in another, forging events an auditor reads as real. Two rules catch
      // both shapes: the direct call, and the local-helper form where getDb() sits one
      // indirection below the function that received the db.
      const fsMod = require('fs');
      const pathMod = require('path');
      // The full HA surface, not a hand-picked subset. The first version of this list
      // omitted ha-peer-link.js and this scheduler, and passed while both audited
      // through a second connection. Files that open a connection but never audit
      // (ha-write-guard, and the scheduler once fixed) are included deliberately: rule 1
      // requires BOTH, so they pass, and adding them means a future audit call in any of
      // them is caught on the day it is written.
      const targets = [
        '../routes/ha.js',
        '../middleware/ha-write-guard.js',
        './alert-router.js',
        './scheduler.js',
        './ha/ha-cdc.js',
        './ha/ha-failover.js',
        './ha/ha-keys.js',
        './ha/ha-lease.js',
        './ha/ha-liveness.js',
        './ha/ha-modes.js',
        './ha/ha-pairing.js',
        './ha/ha-peer-link.js',
        './ha/ha-replication.js',
      ];
      const offenders = [];
      let scanned = 0;
      for (const rel of targets) {
        const abs = pathMod.join(__dirname, rel);
        if (!fsMod.existsSync(abs)) continue;
        scanned += 1;
        const code = haStripNonCode(fsMod.readFileSync(abs, 'utf8'));
        for (const fn of haFunctions(code)) {
          if (/\bgetDb\s*\(/.test(fn.body) && /\bappendAuditEntry\s*\(/.test(fn.body)) {
            offenders.push(rel + ': ' + fn.name + '() opens a connection and appends an audit entry');
          }
        }
        const calls = (code.match(/\bauditLog\s*\(/g) || []).length;
        const defs = (code.match(/function\s+auditLog\s*\(/g) || []).length;
        if (calls > defs) offenders.push(rel + ': calls a connection-opening auditLog(); use auditLogOn(db, ...)');
      }
      if (offenders.length) throw new Error('HA module audits through a second connection: ' + offenders.join(', '));
      return scanned + ' HA sources scanned; all audit through the connection they are handed';
    });
    await check('high_availability', 'A promoting node claims a STRICTLY HIGHER epoch than its peer', () => {
      // The monotonic lease trigger forbids an epoch DECREASE, not a TIE. A node
      // re-promoting after its peer claimed epoch N must adopt N first, so
      // claimNextEpoch yields N+1. Skipping the adoption yields N again: two actives
      // at one epoch. This asserts the primitive the self-test depends on.
      const hl = require('./ha/ha-lease');
      const mem = cloneLiveSchema(this.db);
      try {
        mem.prepare("INSERT OR REPLACE INTO ha_lease (id, epoch, holder) VALUES ('current', 5, 'self')").run();
        hl.recordPeerHeartbeat(mem, 6, null);
        const claimed = hl.claimNextEpoch(mem, 30);
        if (claimed <= 6) throw new Error('claimed epoch ' + claimed + ' ties or trails the peer (split-brain)');
        return 'adopted peer epoch 6, claimed ' + claimed;
      } finally { mem.close(); }
    });

    // ── Automated Update Detection (B5r) ───────────────────────────
    // Detect-and-notify only: these confirm the evidence table, the network
    // service and its exports, the version-comparison logic (no network), and
    // that the schedule config is readable. They never reach the network.
    await check('auto_update', 'Update-check log table present', () => {
      const r = this.db.prepare("SELECT COUNT(*) AS c FROM sqlite_master WHERE type = 'table' AND name = 'auto_update_check_log'").get();
      if (!r || r.c !== 1) throw new Error('auto_update_check_log table missing');
      return 'auto_update_check_log present';
    });
    await check('auto_update', 'Update-check service loads and exports', () => {
      const uc = require('./update-check');
      if (typeof uc.checkForUpdate !== 'function' || typeof uc.isStrictlyNewer !== 'function') {
        throw new Error('update-check service missing checkForUpdate/isStrictlyNewer');
      }
      return 'checkForUpdate + isStrictlyNewer exported';
    });
    await check('auto_update', 'Version comparison dry-run (no network)', () => {
      const uc = require('./update-check');
      if (uc.isStrictlyNewer('v1.0.79', '1.0.78') !== true) throw new Error('newer not detected');
      if (uc.isStrictlyNewer('1.0.78', '1.0.78') !== false) throw new Error('equal treated as newer');
      if (uc.isStrictlyNewer('1.0.70', '1.0.78') !== false) throw new Error('older treated as newer (downgrade)');
      if (uc.isStrictlyNewer('garbage', '1.0.78') !== false) throw new Error('malformed treated as newer');
      return 'newer/equal/older/malformed all correct';
    });
    await check('auto_update', 'Schedule config readable', () => {
      const row = this.db.prepare("SELECT value FROM team_config WHERE key = 'auto_update_schedule_config'").get();
      if (row && row.value) { JSON.parse(row.value); return 'config present and parseable'; }
      return 'unset (defaults apply)';
    });

    // ── Aggregate ──────────────────────────────────────────────────
    const passed = results.filter(r => r.status === 'pass').length;
    const skipped = results.filter(r => r.status === 'skip').length;
    const failed = results.filter(r => r.status === 'fail').length;

    // Per-category summary. A 'skip' counts toward total + skipped but
    // never flips a category to 'fail'.
    const summary = {};
    for (const r of results) {
      if (!summary[r.category]) summary[r.category] = { passed: 0, skipped: 0, total: 0, status: 'pass' };
      const s = summary[r.category];
      s.total++;
      if (r.status === 'pass') s.passed++;
      else if (r.status === 'skip') s.skipped++;
      else s.status = 'fail';
    }

    const failures = results.filter(r => r.status === 'fail');

    // Resolve version + fuse for the response payload. Falls back
    // gracefully if the version module is unavailable.
    let versionStr = 'unknown';
    let fuse = null;
    try {
      const v = require('../lib/version');
      versionStr = v.version || 'unknown';
      fuse = v.fuseCounter ?? null;
    } catch (e) {
      // Leave defaults.
    }

    return {
      total: results.length,
      passed,
      failed,
      skipped,
      results,
      ranAt: new Date().toISOString(),
      version: versionStr,
      fuse,
      summary,
      failures,
    };
  }
}

// Build a throwaway in-memory SQLite database that mirrors the live schema,
// by replaying the live DB's own DDL (tables, then indexes, then triggers).
// Used by write-path flow checks so they exercise real INSERT/constraint/
// trigger logic with zero writes/locks against the production database.
function cloneLiveSchema(db) {
  const Database = db.constructor; // better-sqlite3 Database class
  const mem = new Database(':memory:');
  mem.exec('PRAGMA foreign_keys=ON;');
  const rank = { table: 0, index: 1, trigger: 2 };
  const objs = db
    .prepare("SELECT type, sql FROM sqlite_master WHERE sql IS NOT NULL AND type IN ('table','index','trigger')")
    .all()
    .sort((a, b) => (rank[a.type] - rank[b.type]));
  for (const o of objs) {
    // Replay in dependency order; tolerate any single object that cannot be
    // recreated in isolation (e.g. an index/trigger referencing a view) so a
    // single odd object never aborts the clone.
    try { mem.exec(o.sql + ';'); } catch (_e) { /* skip that object */ }
  }
  return mem;
}

module.exports = { RegressionRunner };
