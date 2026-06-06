// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Routes (Analyst Client)
//
// Every route here is hard-scoped to the caller's own identity (req.user.id from
// the JWT); there is no analyst_id request parameter and no admin-on-behalf path.
//
// Private data uses two models:
//   - /private-data: sealed to the analyst's own public key (analyst_private_data).
//     The server stores opaque ciphertext it cannot open; only the analyst's own
//     device, holding the private key, can read it. This is the B5d1 model and
//     supersedes the old server-decryptable Tier-3 signals path.
//   - /lighter-queue, /consent: Tier-3 (the analyst's id is encrypted for
//     anonymity), an anonymous routing-cap reduction, and a consent trail.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { encryptTier3 } = require('../services/encryption');
const { parseSealed } = require('../services/analyst-crypto');
const { auditLog } = require('../middleware/audit');

// ── GET /api/analysts/private-data — my sealed private data (server cannot read) ─
// Self-scoped by JWT. Returns opaque ciphertext rows for the analyst to open on
// their own device; the server never decrypts. Optional ?kind= filter
// (reading|interpretation) and ?limit=.
router.get('/private-data', (req, res) => {
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  const kind = req.query.kind;
  if (kind && kind !== 'reading' && kind !== 'interpretation') {
    return res.status(400).json({ error: 'kind must be reading or interpretation' });
  }

  let limit = parseInt(req.query.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0) {
    limit = 100;
  } else if (limit > 500) {
    limit = 500;
  }

  const db = getDb();
  try {
    let rows;
    if (kind) {
      rows = db.prepare(
        'SELECT id, kind, ciphertext, key_version, recorded_at FROM analyst_private_data ' +
          'WHERE analyst_id = ? AND kind = ? ORDER BY recorded_at DESC LIMIT ?'
      ).all(analystId, kind, limit);
    } else {
      rows = db.prepare(
        'SELECT id, kind, ciphertext, key_version, recorded_at FROM analyst_private_data ' +
          'WHERE analyst_id = ? ORDER BY recorded_at DESC LIMIT ?'
      ).all(analystId, limit);
    }

    res.json({
      items: rows.map((r) => ({
        id: r.id,
        kind: r.kind,
        ciphertext: r.ciphertext,
        keyVersion: r.key_version,
        recordedAt: r.recorded_at,
      })),
      meta: { count: rows.length, kind: kind || null, limit },
    });
  } finally {
    db.close();
  }
});

// ── POST /api/analysts/private-data — store a client-sealed blob (opaque to server) ─
// The analyst's device seals the data to its OWN public key and sends only the
// ciphertext. The server validates the sealed wire format but cannot decrypt it;
// the analyst's private key, held only on the device, is required to open it.
router.post('/private-data', (req, res) => {
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  const { kind, ciphertext, keyVersion } = req.body || {};
  if (kind !== 'reading' && kind !== 'interpretation') {
    return res.status(400).json({ error: 'kind must be reading or interpretation' });
  }
  if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
    return res.status(400).json({ error: 'ciphertext (sealed, base64) is required' });
  }

  // Validate the sealed wire format only — never decrypt. This rejects garbage
  // while preserving zero server access to the plaintext.
  try {
    parseSealed(ciphertext);
  } catch (e) {
    return res.status(400).json({ error: 'ciphertext is not a valid sealed blob' });
  }

  const db = getDb();
  try {
    const info = db.prepare(
      'INSERT INTO analyst_private_data (analyst_id, kind, ciphertext, key_version) VALUES (?, ?, ?, ?)'
    ).run(analystId, kind, ciphertext, Number.isInteger(keyVersion) ? keyVersion : 1);
    res.json({ ok: true, id: info.lastInsertRowid });
  } finally {
    db.close();
  }
});

// ── POST /api/analysts/lighter-queue — request lighter queue (anonymous) ─────
router.post('/lighter-queue', (req, res) => {
  const { duration, maxComplexity, reason } = req.body;
  const db = getDb();
  const crypto = require('crypto');

  // Encrypt analyst ID so management can never see who requested
  const analystEncrypted = encryptTier3(req.user.id);

  // Calculate expiry
  const durationMap = { '1_shift': 8, '24hr': 24, '72hr': 72, '1_week': 168 };
  const hours = durationMap[duration] || 8;
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  db.prepare(
    'INSERT INTO lighter_queue_requests (duration, max_complexity, analyst_id_encrypted, expires_at) VALUES (?, ?, ?, ?)'
  ).run(duration, maxComplexity || 2, analystEncrypted, expiresAt);

  // Lower the routing cap through the same model the collector uses: an upsert
  // (so the reduction also lands for an analyst with no routing_caps row yet —
  // a bare UPDATE silently no-ops there), a ratchet-down MIN (a request can only
  // lower the cap, never raise it), and the is_override guard so an active
  // management override (for example an emergency cap raised during an all-hands
  // incident) is left untouched. The request is recorded above regardless, so it
  // stays actionable even while an override is in force.
  const cap = maxComplexity || 2;
  db.prepare(
    'INSERT INTO routing_caps (analyst_id, max_complexity, is_override, updated_at) ' +
      "VALUES (?, ?, 0, datetime('now')) " +
      'ON CONFLICT(analyst_id) DO UPDATE SET ' +
      'max_complexity = MIN(max_complexity, excluded.max_complexity), ' +
      "updated_at = datetime('now') " +
      'WHERE COALESCE(is_override, 0) != 1'
  ).run(req.user.id, cap);

  db.close();

  // Audit log does NOT include analyst identity
  auditLog(null, 'LIGHTER_QUEUE_REQUEST', `duration=${duration} cap=${maxComplexity}`, req.ip);
  res.json({ ok: true, expiresAt });
});

// ── GET /api/analysts/consent-log — my consent trail ─────────────────────────
router.get('/consent-log', (req, res) => {
  const db = getDb();
  const entries = db.prepare(
    'SELECT action, detail, created_at FROM analyst_consent_log WHERE analyst_id = ? ORDER BY created_at DESC LIMIT 100'
  ).all(req.user.id);
  db.close();
  res.json({ entries });
});

// ── POST /api/analysts/consent — log consent event ───────────────────────────
router.post('/consent', (req, res) => {
  const { action, detail } = req.body;
  const db = getDb();
  db.prepare(
    'INSERT INTO analyst_consent_log (analyst_id, action, detail) VALUES (?, ?, ?)'
  ).run(req.user.id, action, detail || 'Anonymous — no name/signals transmitted');
  db.close();
  res.json({ ok: true });
});

module.exports = router;
