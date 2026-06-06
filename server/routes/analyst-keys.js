// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Keys Routes (Analyst Client, B5d1 PR A)
//
// Per-analyst X25519 keypair custody. The server stores and serves the PUBLIC
// key only and seals burnout detail to it (services/analyst-crypto.js); it
// never holds a private key. Recovery wraps are server-opaque copies of the
// private key, each wrapped under a factor the server cannot unwrap (a passkey
// PRF, a backup authenticator, or an offline recovery code). They are stored
// for re-provision recovery in B5d4 and are never a server escrow: with no
// unwrap factor, the server cannot derive the key from these blobs.
//
// Tier-3 invariant: the analyst id always comes from req.user.id (the JWT),
// never from the request body or a query param. Mounted under
// authMiddleware(['analyst']).
//
// POST /api/analyst-keys/register — register or rotate the calling analyst's
//                                   public key plus its recovery wraps.
// GET  /api/analyst-keys/me       — the calling analyst's public key + wraps,
//                                   for per-session unlock and recovery.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { isValidPublicKey } = require('../services/analyst-crypto');

// Recovery-wrap factors recognized here, kept in lockstep with the
// analyst_key_recovery_wraps CHECK constraint in db/init.js.
const ALLOWED_FACTORS = ['prf_primary', 'prf_backup', 'recovery_code'];

const MAX_WRAPS = 16; // a handful of authenticators + recovery codes, no more
const MAX_WRAP_B64 = 8192; // a wrapped 32-byte key is tiny; cap generously
const MAX_LABEL = 120;

// Strict base64 shape check (mirrors the validation in abuse-review-key.js /
// e2ee-keys.js); the 32-byte X25519 length is then enforced by isValidPublicKey.
function isB64(value, maxLen) {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= maxLen &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(value)
  );
}

// ── POST /register ───────────────────────────────────────────────────────────
// Body: { public_key (base64 X25519), algo?, recovery_wraps?: [ { factor,
// wrapped_sk (base64), label? } ] }. Replaces this analyst's recovery-wrap set
// with the submitted one. A changed public key is treated as a rotation and
// bumps key_version.
router.post('/register', (req, res) => {
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  const body = req.body || {};
  if (!isB64(body.public_key, MAX_WRAP_B64) || !isValidPublicKey(body.public_key)) {
    return res.status(400).json({ error: 'public_key must be a base64 X25519 public key' });
  }
  const keyAlgo =
    typeof body.algo === 'string' && body.algo.length > 0 && body.algo.length <= 64
      ? body.algo
      : 'x25519-sealedbox';

  const wraps = Array.isArray(body.recovery_wraps) ? body.recovery_wraps : [];
  if (wraps.length > MAX_WRAPS) {
    return res.status(400).json({ error: 'too many recovery wraps' });
  }
  for (const wrap of wraps) {
    if (!wrap || !ALLOWED_FACTORS.includes(wrap.factor)) {
      return res.status(400).json({ error: 'invalid recovery wrap factor', allowed: ALLOWED_FACTORS });
    }
    if (!isB64(wrap.wrapped_sk, MAX_WRAP_B64)) {
      return res.status(400).json({ error: 'each recovery wrap needs a base64 wrapped_sk' });
    }
  }

  const db = getDb();
  try {
    const existing = db
      .prepare('SELECT public_key, key_version FROM analyst_keys WHERE analyst_id = ?')
      .get(analystId);
    const rotating = !!existing && existing.public_key !== body.public_key;
    const keyVersion = existing ? (rotating ? existing.key_version + 1 : existing.key_version) : 1;

    const apply = db.transaction(() => {
      if (existing) {
        db.prepare(
          "UPDATE analyst_keys SET public_key = ?, algo = ?, key_version = ?, status = 'active', updated_at = datetime('now') WHERE analyst_id = ?"
        ).run(body.public_key, keyAlgo, keyVersion, analystId);
      } else {
        db.prepare(
          'INSERT INTO analyst_keys (analyst_id, public_key, algo, key_version) VALUES (?, ?, ?, ?)'
        ).run(analystId, body.public_key, keyAlgo, keyVersion);
      }
      db.prepare('DELETE FROM analyst_key_recovery_wraps WHERE analyst_id = ?').run(analystId);
      const insertWrap = db.prepare(
        'INSERT INTO analyst_key_recovery_wraps (analyst_id, factor, wrapped_sk, label, key_version) VALUES (?, ?, ?, ?, ?)'
      );
      for (const wrap of wraps) {
        const label =
          typeof wrap.label === 'string' && wrap.label.trim().length > 0
            ? wrap.label.trim().slice(0, MAX_LABEL)
            : null;
        insertWrap.run(analystId, wrap.factor, Buffer.from(wrap.wrapped_sk, 'base64'), label, keyVersion);
      }
    });
    apply();

    // PR E wires the re-encrypt-on-enrollment migration here
    // (services/analyst-migration.js): on first enrollment, historical burnout
    // rows are resealed to this public key and the old copies deleted. Until
    // that ships nothing is sealed, so registration is purely additive.

    // Audit metadata only -- the stored key is public and no key material is
    // logged; record who enrolled and the resulting key version.
    auditLog(
      analystId,
      'ANALYST_KEY_REGISTERED',
      `key_version ${keyVersion}, rotated ${rotating}, wraps ${wraps.length}`,
      req.ip
    );

    return res.json({ ok: true, key_version: keyVersion, rotated: rotating, recovery_wraps: wraps.length });
  } catch (err) {
    logger.error('analyst-keys: register failed', { analystId, error: err.message });
    return res.status(500).json({ error: 'failed to register analyst key' });
  } finally {
    db.close();
  }
});

// ── GET /me ──────────────────────────────────────────────────────────────────
// Returns the calling analyst's own public key and recovery wraps. The wraps
// are returned base64-encoded; they are useless without the unwrap factor the
// server does not hold, so serving them to the authenticated owner is what
// makes re-provision recovery possible.
router.get('/me', (req, res) => {
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  const db = getDb();
  try {
    const key = db
      .prepare(
        'SELECT public_key, algo, key_version, status, created_at, updated_at FROM analyst_keys WHERE analyst_id = ?'
      )
      .get(analystId);
    if (!key) {
      return res.json({ enrolled: false });
    }
    const wraps = db
      .prepare(
        'SELECT factor, wrapped_sk, label, key_version, created_at FROM analyst_key_recovery_wraps WHERE analyst_id = ? ORDER BY id'
      )
      .all(analystId);

    return res.json({
      enrolled: true,
      public_key: key.public_key,
      algo: key.algo,
      key_version: key.key_version,
      status: key.status,
      created_at: key.created_at,
      updated_at: key.updated_at,
      recovery_wraps: wraps.map((wrap) => ({
        factor: wrap.factor,
        wrapped_sk: Buffer.from(wrap.wrapped_sk).toString('base64'),
        label: wrap.label || null,
        key_version: wrap.key_version,
        created_at: wrap.created_at,
      })),
    });
  } catch (err) {
    logger.error('analyst-keys: fetch /me failed', { analystId, error: err.message });
    return res.status(500).json({ error: 'failed to fetch analyst key' });
  } finally {
    db.close();
  }
});

module.exports = router;
