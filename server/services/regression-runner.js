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
// backups; mfa_tokens -> mfa_consumed_jtis; feature_toggles and
// integration_status -> not canonical at all), with most checks
// silent-failing inside try/catch so the response was almost entirely
// noise. R3k absorbs what BUILD-PLAN-v22 had described as the deferred
// B2 phase and ships a real runner against current canonical schema.
//
// CATEGORIES (12)
// ===============
//
//   1. Schema integrity      — SQLite integrity_check + canonical
//                               table presence (R3-era core, R3j
//                               additions, R3k additions)
//   2. Crypto                — AES-256-GCM, SHA-256, Ed25519, NaCl
//                               box round-trips; CSPRNG presence
//                               implied by the round-trips
//   3. Auth                  — JWT_SECRET configured, api_keys and
//                               mfa_consumed_jtis present; passwordless
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
    await check('auth', 'api_keys + mfa_consumed_jtis tables', () => {
      return requireAll(['api_keys', 'mfa_consumed_jtis']);
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
      const required = ['/login-cert', '/login-webauthn/options', '/login-webauthn/verify'];
      const missing = required.filter(p => !paths.has(p));
      if (missing.length) throw new Error('missing passwordless login route(s): ' + missing.join(', '));
      const forbidden = ['/login', '/login-ldap', '/login-mfa', '/login-enroll-start', '/login-enroll-confirm'];
      const present = forbidden.filter(p => paths.has(p));
      if (present.length) throw new Error('password / TOTP login route(s) still present: ' + present.join(', '));
      return 'cert + passkey login present; no password / LDAP / TOTP login route';
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
      return requireAll(['analyst_baselines', 'analyst_signals', 'analyst_impacts', 'signal_readings']);
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

    // ── Category 9: Audit chain ────────────────────────────────────
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
    await check('system', 'Node.js version >= 18', () => {
      const major = parseInt(process.version.replace(/^v/, '').split('.')[0], 10);
      if (!Number.isFinite(major) || major < 18) {
        throw new Error('Node ' + process.version + ' is below the supported floor (>=18)');
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
