// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Crypto-Erase (offboarding key destruction)
//
// On offboarding, an analyst's sealed private data must become permanently
// unrecoverable. The server never held the unwrapped private key (it lives on the
// analyst's device, safeStorage-sealed), so the cryptographic erase destroys the
// two server-side artifacts that could otherwise reconstruct access:
//   - the recovery wraps (analyst_key_recovery_wraps): the private key wrapped
//     under the analyst's PRF / recovery-code factors, the only server-side path
//     back to the plaintext key.
//   - the key record itself (analyst_keys): marked 'erased', which also stops all
//     future sealing because the collector gate requires status='active'.
// The sealed rows (analyst_private_data) are then deleted as well: once the key is
// gone they are permanently unreadable noise, and removing them keeps no residual
// personal data of a departed analyst (data minimization -- no framework in scope
// mandates retaining this employee telemetry, and GDPR/CCPA favor its erasure).
// The de-identified team aggregates carry no analyst identity and are untouched,
// so historical team trends survive an offboarding.
//
// Trigger model: NOT instant. Offboarding sets active=0 (which immediately stops
// monitoring and de-enrolls the analyst via the gate) but leaves the keys intact.
// sweepDueErasures() destroys the keys only after a configurable grace period has
// elapsed since offboarded_at, so a fraudulent or mistaken offboarding can be
// reversed (re-activation clears offboarded_at) before anything is destroyed. The
// recovery wraps and sealed rows also persist in server backups until those age
// out, so a restore remains a recovery path within the backup-retention window.
// ═══════════════════════════════════════════════════════════════════════════════

const DEFAULT_GRACE_DAYS = 30;

// Destroy the server-side key material for one analyst and the now-unreadable
// sealed rows. Deletes run before the status flip so the operation is re-entrant:
// if it is interrupted, the key is still 'active' and the next sweep completes it
// (the deletes are no-ops the second time). Idempotent. Returns a summary for the
// audit trail.
function cryptoEraseAnalyst(db, analystId) {
  const wrapRes = db
    .prepare('DELETE FROM analyst_key_recovery_wraps WHERE analyst_id = ?')
    .run(analystId);
  const sealedRes = db
    .prepare('DELETE FROM analyst_private_data WHERE analyst_id = ?')
    .run(analystId);
  const keyRes = db
    .prepare("UPDATE analyst_keys SET status = 'erased', updated_at = datetime('now') WHERE analyst_id = ? AND status = 'active'")
    .run(analystId);
  return {
    analystId,
    keyErased: keyRes.changes > 0,
    wrapsDeleted: wrapRes.changes,
    sealedDeleted: sealedRes.changes,
  };
}

// Configured grace period (days) between offboarding and key destruction.
// Operators may lengthen it (more time to catch a fraudulent offboarding) or
// shorten it; an invalid or missing value falls back to the default.
function graceDays(db) {
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'key_erase_grace_days'").get();
    const n = r ? parseInt(r.value, 10) : NaN;
    return Number.isFinite(n) && n >= 0 ? n : DEFAULT_GRACE_DAYS;
  } catch (e) {
    return DEFAULT_GRACE_DAYS;
  }
}

// Crypto-erase every analyst whose offboarding grace period has elapsed and who
// still holds an active key. Driven by offboarded_at, so every offboarding path
// is covered without per-path wiring; re-activation (which clears offboarded_at)
// removes an analyst from the sweep. datetime() normalizes both stored timestamp
// formats (ISO-8601 from some paths, 'YYYY-MM-DD HH:MM:SS' from others). Runs from
// the daily scheduled jobs.
function sweepDueErasures(db) {
  const days = graceDays(db);
  let due = [];
  try {
    due = db
      .prepare(
        'SELECT u.id FROM users u ' +
          "JOIN analyst_keys k ON k.analyst_id = u.id AND k.status = 'active' " +
          'WHERE u.active = 0 AND u.offboarded_at IS NOT NULL ' +
          "AND datetime(u.offboarded_at) <= datetime('now', ?)"
      )
      .all('-' + days + ' days');
  } catch (e) {
    due = [];
  }
  const erased = [];
  for (const row of due) {
    try {
      erased.push(cryptoEraseAnalyst(db, row.id));
    } catch (e) {
      /* skip a single failure and continue the sweep */
    }
  }
  return { graceDays: days, erasedCount: erased.length, erased };
}

module.exports = { cryptoEraseAnalyst, sweepDueErasures, graceDays, DEFAULT_GRACE_DAYS };
