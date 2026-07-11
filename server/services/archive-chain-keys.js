// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Archive Chain Signing Keys Service (B5q)
//
// Manages the dedicated Ed25519 signing family for the sealed archive-segment
// chain (storage_archive_segments). The archive-segment primitive signs each
// segment's manifest with the active key here; verifyChain re-verifies every
// segment manifest against the fingerprint recorded on the segment.
//
// This family is intentionally separate from the backup / forensic / audit
// signing families -- it is its own table (archive_chain_signing_keys) -- so a
// compromise of one custody chain's signing key cannot forge another's. It
// mirrors forensic-export.js's signing-key helpers; the only differences are
// the table name and the 'acsk-' id prefix.
//
// Key material:
//   public_key             PEM SPKI, plaintext (no confidentiality concern)
//   private_key_encrypted  Tier-1-KEK-wrapped via encryptConfig (AES-256-GCM
//                          under the hardware-sealed Tier-1 KEK); decrypted
//                          just-in-time per signing op and never cached at
//                          module scope.
//   fingerprint            SHA-256 hex of the SPKI DER bytes -- the stable
//                          identifier recorded on each segment for the
//                          verification lookup, so manifests stay verifiable
//                          across key rotation.
//
// Schema: db/init.js -> archive_chain_signing_keys (id TEXT PK, public_key,
// private_key_encrypted, fingerprint UNIQUE, active, created_at, rotated_at).
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');

// ── Active-key lifecycle ──────────────────────────────────────────────────

/**
 * ensureActiveSigningKey(db)
 *
 * Boot-time idempotent helper (called from the server boot hook). If no row
 * in archive_chain_signing_keys has active = 1, generate a fresh Ed25519
 * keypair, Tier-1-KEK-wrap the private key, and insert it. Safe to call on
 * every start.
 *
 * Returns { id, publicKeyPem, fingerprint, isNewlyCreated }.
 */
function ensureActiveSigningKey(db) {
  const existing = db
    .prepare(
      'SELECT id, public_key, fingerprint FROM archive_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (existing) {
    return {
      id: existing.id,
      publicKeyPem: existing.public_key,
      fingerprint: existing.fingerprint,
      isNewlyCreated: false,
    };
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privateKeyEncrypted = sealTier1('archive_chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });

  // Fingerprint = SHA-256 of the raw SPKI bytes, hex (stable across PEM quirks).
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex');
  const id = 'acsk-' + crypto.randomUUID();

  db.prepare(
    'INSERT INTO archive_chain_signing_keys (id, public_key, private_key_encrypted, fingerprint, active) VALUES (?, ?, ?, ?, 1)'
  ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);

  return { id, publicKeyPem, fingerprint, isNewlyCreated: true };
}

/**
 * loadActivePrivateKey(db)
 *
 * Load and decrypt the active private key for signing. The raw key is
 * returned as a KeyObject and never cached -- the caller signs and discards.
 * Throws if no active key exists.
 *
 * Returns { id, publicKeyPem, privateKey, fingerprint }.
 */
function loadActivePrivateKey(db) {
  const row = db
    .prepare(
      'SELECT id, public_key, private_key_encrypted, fingerprint FROM archive_chain_signing_keys WHERE active = 1 LIMIT 1'
    )
    .get();
  if (!row) {
    throw new Error('No active archive chain signing key found');
  }
  const { pem } = openTier1('archive_chain_signing_keys.private_key_encrypted', row.private_key_encrypted);
  const privateKey = crypto.createPrivateKey({ key: pem, format: 'pem' });
  return {
    id: row.id,
    publicKeyPem: row.public_key,
    privateKey,
    fingerprint: row.fingerprint,
  };
}

// ── Sign / verify ──────────────────────────────────────────────────────────

/**
 * signManifest(db, manifestBytes)
 *
 * Sign manifest bytes (Buffer or string) with the active signing key. Returns
 * the signature hex-encoded (stored in storage_archive_segments.manifest_
 * signature) plus the signing key id and fingerprint, which the caller records
 * on the segment so verifyChain can find the right public key later even after
 * rotation.
 *
 * Returns { signature, signingKeyId, fingerprint }  (signature is hex).
 */
function signManifest(db, manifestBytes) {
  if (!Buffer.isBuffer(manifestBytes) && typeof manifestBytes !== 'string') {
    throw new Error('signManifest: manifestBytes must be a Buffer or string');
  }
  const { id, privateKey, fingerprint } = loadActivePrivateKey(db);
  const bytes = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes);
  // Ed25519 in Node: crypto.sign(null, message, privateKey); algorithm is
  // implicit because the key type fixes it. Hex for the TEXT manifest_signature.
  const signature = crypto.sign(null, bytes, privateKey).toString('hex');
  return { signature, signingKeyId: id, fingerprint };
}

/**
 * getVerificationKeyByFingerprint(db, fingerprint)
 *
 * Resolve a public key (KeyObject) for verification by its content-addressed
 * fingerprint. Returns null if no key with that fingerprint exists or the
 * stored PEM fails to parse.
 */
function getVerificationKeyByFingerprint(db, fingerprint) {
  if (typeof fingerprint !== 'string' || !fingerprint) return null;
  const row = db
    .prepare(
      'SELECT public_key FROM archive_chain_signing_keys WHERE fingerprint = ? LIMIT 1'
    )
    .get(fingerprint);
  if (!row) return null;
  try {
    return crypto.createPublicKey({ key: row.public_key, format: 'pem' });
  } catch (_err) {
    return null;
  }
}

/**
 * verifyManifest(db, manifestBytes, signatureHex, fingerprint)
 *
 * Verify a segment manifest signature by the recorded fingerprint. Returns
 * true only if the fingerprint resolves to a known public key AND the
 * signature is a valid Ed25519 signature over manifestBytes. Returns false
 * (never throws) on a malformed/unknown fingerprint or a signature mismatch.
 * It never throws -- bad inputs return false so verifyChain can report the
 * broken segment rather than crash.
 */
function verifyManifest(db, manifestBytes, signatureHex, fingerprint) {
  if (typeof signatureHex !== 'string' || !/^[0-9a-fA-F]*$/.test(signatureHex)) {
    return false;
  }
  const signature = Buffer.from(signatureHex, 'hex');
  // Ed25519 signatures are always 64 bytes; reject other sizes early.
  if (signature.length !== 64) return false;
  const verKey = getVerificationKeyByFingerprint(db, fingerprint);
  if (!verKey) return false;
  const bytes = Buffer.isBuffer(manifestBytes) ? manifestBytes : Buffer.from(manifestBytes);
  return crypto.verify(null, bytes, verKey, signature);
}

// ── Rotation + listing ─────────────────────────────────────────────────────

/**
 * rotateKeypair(db)
 *
 * Retire the current active key (active = 0, rotated_at set) and generate a
 * fresh active keypair, in one transaction. Old rows are retained so
 * historical segment manifests stay verifiable by fingerprint.
 *
 * Returns the new active key's { id, publicKeyPem, fingerprint }.
 */
function rotateKeypair(db) {
  const now = new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
  const tx = db.transaction(() => {
    db.prepare(
      'UPDATE archive_chain_signing_keys SET active = 0, rotated_at = ? WHERE active = 1'
    ).run(now);

    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
    const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const privateKeyEncrypted = sealTier1('archive_chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    const fingerprint = crypto.createHash('sha256').update(spkiDer).digest('hex');
    const id = 'acsk-' + crypto.randomUUID();

    db.prepare(
      'INSERT INTO archive_chain_signing_keys (id, public_key, private_key_encrypted, fingerprint, active) VALUES (?, ?, ?, ?, 1)'
    ).run(id, publicKeyPem, privateKeyEncrypted, fingerprint);

    return { id, publicKeyPem, fingerprint };
  });
  return tx();
}

/**
 * listKeys(db)
 *
 * Public-side metadata for every archive signing key (never returns private
 * material). Newest first.
 *
 * Returns array of { id, publicKeyPem, fingerprint, active, createdAt, rotatedAt }.
 */
function listKeys(db) {
  const rows = db
    .prepare(
      'SELECT id, public_key, fingerprint, active, created_at, rotated_at FROM archive_chain_signing_keys ORDER BY created_at DESC, id DESC'
    )
    .all();
  return rows.map((r) => ({
    id: r.id,
    publicKeyPem: r.public_key,
    fingerprint: r.fingerprint,
    active: r.active === 1,
    createdAt: r.created_at,
    rotatedAt: r.rotated_at,
  }));
}

module.exports = {
  ensureActiveSigningKey,
  loadActivePrivateKey,
  signManifest,
  verifyManifest,
  getVerificationKeyByFingerprint,
  rotateKeypair,
  listKeys,
};
