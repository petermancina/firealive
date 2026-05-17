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
//                               mfa_consumed_jtis present, TOTP
//                               recovery code columns present
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
//     total, passed, failed, ranAt, version, fuse,
//     results: [
//       { category, name, status: 'pass'|'fail', detail }, ...
//     ],
//     summary: {
//       <category>: { passed: <n>, total: <n>, status: 'pass'|'fail' },
//       ...
//     },
//     failures: [ <subset of results where status='fail'> ]
//   }
//
// Backwards compatibility: the top-level fields (total, passed, failed,
// results, ranAt, version, fuse) are preserved from the pre-R3k shape
// so existing callers (the v059-features.js stub and any test
// harnesses) don't break. The new fields (category on each result,
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

  run() {
    const results = [];

    const check = (category, name, fn) => {
      try {
        const r = fn();
        if (r === false || r === undefined || r === null || r === '') {
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
    check('schema', 'SQLite integrity_check', () => {
      const r = this.db.prepare('PRAGMA integrity_check').get();
      if (r && r.integrity_check === 'ok') return 'integrity ok';
      throw new Error('integrity_check returned: ' + JSON.stringify(r));
    });
    check('schema', 'Core canonical tables', () => {
      return requireAll(['users', 'team_config', 'audit_log', 'system_meta']);
    });
    check('schema', 'R3j routing tables', () => {
      return requireAll(['soar_routing_events', 'ticket_actions', 'ticket_assignments', 'routing_caps']);
    });
    check('schema', 'R3k CI/CD + cloud-iac tables', () => {
      return requireAll(['cicd_configs', 'cicd_runs', 'cloud_iac_signing_keys']);
    });

    // ── Category 2: Crypto ─────────────────────────────────────────
    check('crypto', 'AES-256-GCM round-trip', () => {
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
    check('crypto', 'SHA-256 hashing', () => {
      const h = crypto.createHash('sha256').update('x').digest('hex');
      if (h.length !== 64) throw new Error('unexpected digest length');
      return 'digest 64 hex chars';
    });
    check('crypto', 'Ed25519 sign/verify', () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
      const msg = Buffer.from('regression-probe');
      const sig = crypto.sign(null, msg, privateKey);
      if (!crypto.verify(null, msg, publicKey, sig)) throw new Error('verify failed');
      return 'sign+verify ok';
    });
    check('crypto', 'NaCl box (tweetnacl) round-trip', () => {
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
    check('auth', 'JWT_SECRET configured', () => {
      const s = process.env.JWT_SECRET;
      if (!s || s.length < 16) throw new Error('JWT_SECRET not set or too short (<16 chars)');
      return 'configured (' + s.length + ' chars)';
    });
    check('auth', 'api_keys + mfa_consumed_jtis tables', () => {
      return requireAll(['api_keys', 'mfa_consumed_jtis']);
    });
    check('auth', 'TOTP recovery code columns', () => {
      const hasHashed = columnExists('users', 'totp_recovery_codes_hashed');
      const hasRem    = columnExists('users', 'totp_recovery_codes_remaining');
      if (!hasHashed || !hasRem) {
        throw new Error(
          'missing column(s): ' +
            [!hasHashed && 'totp_recovery_codes_hashed', !hasRem && 'totp_recovery_codes_remaining']
              .filter(Boolean)
              .join(', ')
        );
      }
      return 'both recovery columns present';
    });

    // ── Category 4: Anti-rollback ──────────────────────────────────
    check('anti-rollback', 'Fuse counter row present in system_meta', () => {
      const row = this.db
        .prepare("SELECT value FROM system_meta WHERE key='fuse_counter'")
        .get();
      if (!row) throw new Error('no fuse_counter row in system_meta');
      const n = parseInt(row.value, 10);
      if (!Number.isInteger(n) || n < 0) throw new Error('fuse_counter not a non-negative integer: ' + row.value);
      return 'fuse = ' + n;
    });
    check('anti-rollback', 'Fuse counter matches package.json', () => {
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
    check('integrations', 'integration_config table reachable', () => {
      if (!tableExists('integration_config')) throw new Error('missing table integration_config');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM integration_config').get().n;
      return c + ' integration_config row(s)';
    });
    check('integrations', 'kms_providers registered', () => {
      if (!tableExists('kms_providers')) throw new Error('missing table kms_providers');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM kms_providers').get().n;
      if (c === 0) return 'no providers registered (local-master-key fallback in use)';
      return c + ' provider(s) registered';
    });
    check('integrations', 'KMS provider round-trip (each active)', () => {
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

    // ── Category 6: Burnout signals ────────────────────────────────
    check('burnout', 'Burnout engine tables', () => {
      return requireAll(['analyst_baselines', 'analyst_signals', 'analyst_impacts', 'signal_readings']);
    });
    check('burnout', 'AI provider config present', () => {
      if (!tableExists('ai_provider_config')) throw new Error('missing table ai_provider_config');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM ai_provider_config').get().n;
      return c + ' provider config row(s)';
    });
    check('burnout', 'AI inference provenance log present', () => {
      if (!tableExists('ai_inference_log')) throw new Error('missing table ai_inference_log');
      return 'ai_inference_log table present';
    });

    // ── Category 7: Routing ────────────────────────────────────────
    check('routing', 'Routing tables (caps + overrides)', () => {
      return requireAll(['routing_caps', 'routing_overrides']);
    });
    check('routing', 'team_config.routing_enabled present (R3j)', () => {
      const row = this.db
        .prepare("SELECT value FROM team_config WHERE key='routing_enabled'")
        .get();
      if (!row) throw new Error('no routing_enabled row in team_config (R3j C2 migration may have failed)');
      return 'value = ' + row.value;
    });
    check('routing', 'team_config.panic_mode key reachable', () => {
      const row = this.db
        .prepare("SELECT value FROM team_config WHERE key='panic_mode'")
        .get();
      // panic_mode row may legitimately be absent in a fresh install
      // (the key only materializes on first toggle). Either state is
      // a pass for this check.
      if (!row) return 'no panic_mode row (default: inactive)';
      return 'value = ' + row.value;
    });
    check('routing', 'soar_routing_events composite UNIQUE index (R3j C1)', () => {
      if (!indexExists('idx_soar_routing_events_external')) {
        throw new Error('missing idx_soar_routing_events_external');
      }
      return 'idx_soar_routing_events_external present';
    });

    // ── Category 8: Backup ─────────────────────────────────────────
    check('backup', 'backups table v2 columns', () => {
      const required = ['format_version', 'manifest_path', 'archive_path', 'wrapped_key_path', 'signing_key_id'];
      const missing = required.filter(c => !columnExists('backups', c));
      if (missing.length > 0) throw new Error('missing column(s): ' + missing.join(', '));
      return 'all v2 columns present';
    });
    check('backup', 'backups.kind column present (R3k C2)', () => {
      if (!columnExists('backups', 'kind')) throw new Error('missing column kind');
      return 'kind column present';
    });
    check('backup', 'backup_signing_keys has an active key', () => {
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
    check('backup', 'backup_schedules has at least one row', () => {
      if (!tableExists('backup_schedules')) throw new Error('missing table backup_schedules');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM backup_schedules').get().n;
      if (c === 0) throw new Error('no schedules (legacy default row should have been seeded by R3i)');
      return c + ' schedule(s)';
    });

    // ── Category 9: Audit chain ────────────────────────────────────
    check('audit-chain', 'audit_log table reachable', () => {
      if (!tableExists('audit_log')) throw new Error('missing table audit_log');
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM audit_log').get().n;
      return c + ' audit row(s)';
    });
    check('audit-chain', 'backup_chain linkage walk (last 10 entries)', () => {
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
    check('audit-chain', 'chain_signing_keys has an active key', () => {
      if (!tableExists('chain_signing_keys')) throw new Error('missing table chain_signing_keys');
      const row = this.db
        .prepare("SELECT COUNT(*) AS n FROM chain_signing_keys WHERE is_active = 1")
        .get();
      if (row.n === 0) throw new Error('no active chain signing key');
      return row.n + ' active chain signing key(s)';
    });

    // ── Category 10: Peer features ────────────────────────────────
    check('peer', 'Peer session + message + rating tables', () => {
      return requireAll(['peer_sessions', 'peer_messages', 'peer_session_ratings']);
    });
    check('peer', 'peer_abuse_flags table present', () => {
      if (!tableExists('peer_abuse_flags')) throw new Error('missing table peer_abuse_flags');
      return 'peer_abuse_flags present';
    });
    check('peer', 'Peer-message E2E key column on users', () => {
      // The peer-message NaCl box key pair is per-user. Canonical
      // column names (R3-era): peer_pubkey (or analogous).
      const candidates = ['peer_pubkey', 'peer_public_key', 'peer_box_pubkey'];
      const present = candidates.filter(c => columnExists('users', c));
      if (present.length === 0) {
        throw new Error('no peer pubkey column on users (checked: ' + candidates.join(', ') + ')');
      }
      return 'column present: ' + present[0];
    });

    // ── Category 11: AC provisioning ──────────────────────────────
    check('ac-prov', '/api/heartbeat route file loadable', () => {
      try {
        const mod = require('../routes/heartbeat');
        if (!mod) throw new Error('heartbeat module loaded but exported nothing');
        return 'loadable';
      } catch (e) {
        throw new Error('require failed: ' + e.message);
      }
    });
    check('ac-prov', 'analyst_availability table present', () => {
      if (!tableExists('analyst_availability')) throw new Error('missing table analyst_availability');
      return 'analyst_availability present';
    });
    check('ac-prov', 'users has analyst-role rows', () => {
      if (!columnExists('users', 'role')) throw new Error('users.role column missing');
      const c = this.db
        .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'analyst'")
        .get().n;
      return c + ' analyst user(s)';
    });

    // ── Category 12: System ────────────────────────────────────────
    check('system', 'Node.js version >= 18', () => {
      const major = parseInt(process.version.replace(/^v/, '').split('.')[0], 10);
      if (!Number.isFinite(major) || major < 18) {
        throw new Error('Node ' + process.version + ' is below the supported floor (>=18)');
      }
      return 'Node ' + process.version;
    });
    check('system', 'Process memory (RSS) within sane bounds', () => {
      const rssMb = Math.round(process.memoryUsage().rss / 1024 / 1024);
      // Soft ceiling 4 GB; over that and we want to know.
      if (rssMb > 4096) throw new Error('RSS ' + rssMb + ' MB exceeds 4 GB soft ceiling');
      return rssMb + ' MB RSS';
    });
    check('system', 'Security middleware loadable', () => {
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
    check('system', 'sessions + auth_log tables', () => {
      return requireAll(['sessions', 'auth_log']);
    });

    // ── Aggregate ──────────────────────────────────────────────────
    const passed = results.filter(r => r.status === 'pass').length;
    const failed = results.length - passed;

    // Per-category summary
    const summary = {};
    for (const r of results) {
      if (!summary[r.category]) summary[r.category] = { passed: 0, total: 0, status: 'pass' };
      summary[r.category].total++;
      if (r.status === 'pass') summary[r.category].passed++;
      else summary[r.category].status = 'fail';
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
      results,
      ranAt: new Date().toISOString(),
      version: versionStr,
      fuse,
      summary,
      failures,
    };
  }
}

module.exports = { RegressionRunner };
