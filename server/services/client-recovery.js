// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Per-Client AC Recovery (tear-down + re-provision-and-rebind)
//
// Recovery of a single compromised analyst client, distinct from offboarding.
// The machine is quarantined, wiped, and re-imaged with a clean AC by the org's
// own IT tooling (golden image / SCCM / Intune); FireAlive's job is to evict the
// compromised client's credentials and then re-bind a clean AC to the SAME
// analyst identity so all server-side data flows back untouched.
//
// teardownAc — server-side eviction:
//   - revoke the AC's active client cert(s) (issued_certs -> revoked)
//   - retire its device signing key(s) (ac_device_signing_keys active -> 0)
//   - delete its passkey credential(s) (webauthn_credentials)
//   After this the compromised box can no longer authenticate. If the AC is
//   still connected, a best-effort wipe_local is dispatched over the WebSocket
//   to clear its local files (the dispatch method lands in a later commit; the
//   call is guarded so this service is sound until then). The analyst's key and
//   recovery wraps (analyst_keys / analyst_key_recovery_wraps) are PRESERVED --
//   recovery is not offboarding, so no crypto-erase runs and the sealed history
//   stays recoverable.
//
// reprovisionAc — re-bind:
//   Mints a fresh single-use enrollment token under the 're-provision' scope,
//   bound to the same user id (same UUID + pseudonym). On the clean AC the
//   analyst redeems it to re-enroll a passkey + cert + device key; the analyst
//   private key is re-wrapped (not re-minted) under the new passkey using the
//   recovery code, and the server-side operational data re-syncs. The plaintext
//   token is returned once for secure delivery; only its SHA-256 hash is stored.
//
// Neither function audits or opens its own DB connection: the route layer owns
// the connection and writes the audit trail. The recovery lifecycle is tracked
// in client_recovery_runs (one row per recovery, advanced as it progresses).
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const ca = require('./ca');

function newId() {
  return crypto.randomBytes(16).toString('hex');
}

function notFound() {
  const e = new Error('analyst not found');
  e.code = 'USER_NOT_FOUND';
  return e;
}

function notAnalyst() {
  const e = new Error('per-client recovery applies to analyst clients only');
  e.code = 'NOT_AN_ANALYST';
  return e;
}

// ── teardownAc(db, userId, { initiatedBy, reason, wsServer }) ─────────────────
// Returns { recoveryRunId, certsRevoked: [serial...], deviceKeyRetired,
//           passkeysDeleted, wipeDispatched }.
function teardownAc(db, userId, opts = {}) {
  const initiatedBy = opts.initiatedBy || null;
  const reason = opts.reason || null;
  const wsServer = opts.wsServer || null;

  const user = db.prepare('SELECT id, role, pseudonym FROM users WHERE id = ?').get(userId);
  if (!user) throw notFound();
  if (user.role !== 'analyst') throw notAnalyst();

  // Atomic eviction + run record. revokeCert is a plain SELECT/UPDATE on this
  // same connection (no internal transaction), so it composes inside db.transaction.
  let summary = null;
  const run = db.transaction(() => {
    const activeCerts = db
      .prepare("SELECT serial FROM issued_certs WHERE user_id = ? AND status = 'active'")
      .all(userId);
    const certsRevoked = [];
    for (const c of activeCerts) {
      const r = ca.revokeCert(db, { serial: c.serial, reason: 'ac_teardown' });
      if (r && r.revoked) certsRevoked.push(c.serial);
    }

    const devRes = db
      .prepare("UPDATE ac_device_signing_keys SET active = 0, retired_at = datetime('now') WHERE user_id = ? AND active = 1")
      .run(userId);

    const pkRes = db
      .prepare('DELETE FROM webauthn_credentials WHERE user_id = ?')
      .run(userId);

    const recoveryRunId = newId();
    db.prepare(`
      INSERT INTO client_recovery_runs
        (id, user_id, pseudonym_at_run, status, initiated_by, reason,
         certs_revoked_json, device_key_retired, passkey_deleted, updated_at)
      VALUES (?, ?, ?, 'torn_down', ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      recoveryRunId,
      userId,
      user.pseudonym || null,
      initiatedBy,
      reason,
      JSON.stringify(certsRevoked),
      devRes.changes > 0 ? 1 : 0,
      pkRes.changes > 0 ? 1 : 0
    );

    summary = {
      recoveryRunId,
      certsRevoked,
      deviceKeyRetired: devRes.changes > 0,
      passkeysDeleted: pkRes.changes,
    };
  });
  run();

  // Best-effort local wipe over the WebSocket (side-effect; outside the tx).
  // dispatchWipeLocal is added in a later commit; until then this is a no-op.
  let wipeDispatched = false;
  if (wsServer && typeof wsServer.dispatchWipeLocal === 'function') {
    try {
      wipeDispatched = !!wsServer.dispatchWipeLocal(userId);
    } catch (_e) {
      wipeDispatched = false;
    }
  }
  if (wipeDispatched) {
    db.prepare("UPDATE client_recovery_runs SET wipe_dispatched = 1, updated_at = datetime('now') WHERE id = ?")
      .run(summary.recoveryRunId);
  }

  return Object.assign({}, summary, { wipeDispatched });
}

// ── reprovisionAc(db, userId, { initiatedBy }) ───────────────────────────────
// Returns { recoveryRunId, enrollmentToken, expiresAt, expiresInDays }.
// enrollmentToken is the plaintext, shown once; only its hash is persisted.
function reprovisionAc(db, userId, opts = {}) {
  const initiatedBy = opts.initiatedBy || null;

  const user = db.prepare('SELECT id, role, pseudonym FROM users WHERE id = ?').get(userId);
  if (!user) throw notFound();
  if (user.role !== 'analyst') throw notAnalyst();

  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const tokenId = newId();

  let out = null;
  const run = db.transaction(() => {
    db.prepare(`
      INSERT INTO enrollment_tokens (id, user_id, token_hash, expires_at, created_by, scope)
      VALUES (?, ?, ?, datetime('now', '+7 days'), ?, 're-provision')
    `).run(tokenId, userId, tokenHash, initiatedBy);

    const expiresAt = db
      .prepare('SELECT expires_at FROM enrollment_tokens WHERE id = ?')
      .get(tokenId).expires_at;

    // Advance the open recovery run if one exists (the normal flow, after a
    // tear-down), otherwise open a fresh run at token_issued.
    const openRun = db
      .prepare("SELECT id FROM client_recovery_runs WHERE user_id = ? AND status IN ('initiated', 'torn_down') ORDER BY created_at DESC LIMIT 1")
      .get(userId);

    let recoveryRunId;
    if (openRun) {
      recoveryRunId = openRun.id;
      db.prepare("UPDATE client_recovery_runs SET status = 'token_issued', enrollment_token_id = ?, updated_at = datetime('now') WHERE id = ?")
        .run(tokenId, recoveryRunId);
    } else {
      recoveryRunId = newId();
      db.prepare(`
        INSERT INTO client_recovery_runs
          (id, user_id, pseudonym_at_run, status, initiated_by, enrollment_token_id, updated_at)
        VALUES (?, ?, ?, 'token_issued', ?, ?, datetime('now'))
      `).run(recoveryRunId, userId, user.pseudonym || null, initiatedBy, tokenId);
    }

    out = { recoveryRunId, enrollmentToken: token, expiresAt, expiresInDays: 7 };
  });
  run();

  return out;
}

module.exports = { teardownAc, reprovisionAc };
