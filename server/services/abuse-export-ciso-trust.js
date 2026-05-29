// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse-Export CISO Trust Anchor (U4 PR 5-C)
//
// Regional-side management of the pinned CISO approval public key(s) in
// abuse_export_ciso_trust. The two-person legal-hold export is enforced by a
// CISO-signed approval token; this service holds the public key that token is
// verified against, and refuses to pin a key whose fingerprint does not match
// the value confirmed OUT-OF-BAND.
//
// The fingerprint check is enforced HERE, in code, recomputed from the key
// bytes — never trusted from the caller's input. That is what makes this a
// trust root rather than a convenience cache: a hostile server (or a hostile
// admin) that swaps the key cannot make the new key's fingerprint equal the
// one an operator verified out-of-band and the reviewer's device pinned
// independently, so the swap is detectable.
//
// Public keys only. No private material is ever stored or handled here.
// Distinct key family from the report-signing, abuse-vault-chain (channel),
// reviewer-request, and forensic/legal-hold/backup families.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

function normalizeFingerprint(fp) {
  return String(fp || '').trim().toLowerCase().replace(/[^0-9a-f]/g, '');
}

function computeFingerprint(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// Parse a PEM SPKI public key and require it to be Ed25519.
function parseEd25519Public(publicKeyPem) {
  const key = crypto.createPublicKey({ key: publicKeyPem, format: 'pem' });
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('CISO approval key must be Ed25519');
  }
  return key;
}

/**
 * pinCisoKey(db, { publicKeyPem, expectedFingerprint, label?, pinnedByUserId? })
 *
 * Recomputes the fingerprint from the key bytes and refuses to store on
 * mismatch (the out-of-band check, enforced in code). Retires any existing
 * active pin first (single active enforced by the unique partial index).
 * Re-pinning the already-active key is a no-op. Returns
 * { id, fingerprint, alreadyActive }.
 */
function pinCisoKey(db, { publicKeyPem, expectedFingerprint, label = null, pinnedByUserId = null } = {}) {
  if (!publicKeyPem || !expectedFingerprint) {
    throw new Error('pinCisoKey: publicKeyPem and expectedFingerprint are required');
  }
  const key = parseEd25519Public(publicKeyPem);
  const actual = computeFingerprint(key);
  const expected = normalizeFingerprint(expectedFingerprint);
  if (actual !== expected) {
    throw new Error(`CISO key fingerprint mismatch: computed ${actual}, expected ${expected}`);
  }
  const pemNormalized = key.export({ type: 'spki', format: 'pem' }).toString();
  return db.transaction(() => {
    const existing = db.prepare('SELECT id, fingerprint FROM abuse_export_ciso_trust WHERE active = 1 LIMIT 1').get();
    if (existing) {
      if (existing.fingerprint === actual) {
        return { id: existing.id, fingerprint: actual, alreadyActive: true };
      }
      db.prepare("UPDATE abuse_export_ciso_trust SET active = 0, retired_at = datetime('now') WHERE id = ?").run(existing.id);
    }
    const id = 'avct-' + crypto.randomUUID();
    db.prepare(
      'INSERT INTO abuse_export_ciso_trust (id, public_key, fingerprint, label, active, pinned_by_user_id) VALUES (?, ?, ?, ?, 1, ?)'
    ).run(id, pemNormalized, actual, label, pinnedByUserId);
    return { id, fingerprint: actual, alreadyActive: false };
  })();
}

/** getActiveCisoTrust(db) — the currently pinned key, or null. */
function getActiveCisoTrust(db) {
  const row = db.prepare('SELECT id, public_key, fingerprint, label, pinned_at FROM abuse_export_ciso_trust WHERE active = 1 LIMIT 1').get();
  if (!row) return null;
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    fingerprint: row.fingerprint,
    label: row.label,
    pinnedAt: row.pinned_at,
  };
}

/** getCisoTrustByFingerprint(db, fp) — any pinned key (active or retired) by fingerprint, or null. */
function getCisoTrustByFingerprint(db, fingerprint) {
  const fp = normalizeFingerprint(fingerprint);
  if (!fp) return null;
  const row = db.prepare('SELECT id, public_key, fingerprint, label, active FROM abuse_export_ciso_trust WHERE fingerprint = ?').get(fp);
  if (!row) return null;
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    publicKeyPem: row.public_key,
    fingerprint: row.fingerprint,
    label: row.label,
    active: row.active === 1,
  };
}

/**
 * verifyWithPinnedKey(db, { fingerprint, messageBytes, signatureHex })
 *
 * Verify a detached Ed25519 signature over messageBytes against the pinned CISO
 * key identified by fingerprint. Returns false (never throws) if the key is
 * unknown, the signature is malformed, or verification fails. This is the
 * regional-side sanity check; the reviewer's device performs the authoritative
 * verification against its own independently pinned copy.
 */
function verifyWithPinnedKey(db, { fingerprint, messageBytes, signatureHex } = {}) {
  const trust = getCisoTrustByFingerprint(db, fingerprint);
  if (!trust) return false;
  let sig;
  try {
    sig = Buffer.from(signatureHex, 'hex');
  } catch (e) {
    return false;
  }
  try {
    return crypto.verify(null, messageBytes, trust.publicKey, sig);
  } catch (e) {
    return false;
  }
}

module.exports = {
  computeFingerprint,
  pinCisoKey,
  getActiveCisoTrust,
  getCisoTrustByFingerprint,
  verifyWithPinnedKey,
};
