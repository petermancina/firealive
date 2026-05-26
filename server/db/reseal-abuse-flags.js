// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — one-time re-seal of peer/board abuse flags to Model B (U3 PR G)
//
// Before the cutover, peer_session and board_post abuse flags were stored as
// Model A: Tier-3 AES-256-GCM blobs the server (and, via the MC, leads) could
// decrypt. lead_chat was already Model B: a sealed box only the independent
// Abuse Review Console can open. The cutover unifies everything on Model B, so
// no abuse content is ever server- or lead-readable. This migration converts the
// EXISTING peer/board flags: it decrypts the legacy Tier-3 copy it can still read
// and re-seals the SAME plaintext to the abuse-review public key, overwriting the
// column with the sealed box. After it runs, the Tier-3 copy is gone and only the
// reviewer (private key holder) can read the content.
//
// Faithful by construction: it uses the low-level decrypt() -- NOT decryptTier3,
// which JSON.parses -- so the exact bytes the server stored (a raw flagger note,
// a raw post body, or a JSON context string) are recovered verbatim and sealed
// verbatim. The reviewer opens byte-identical content, exactly as for a lead_chat
// flag the client sealed directly.
//
// Safety:
//   - Deferred until an abuse-review key is registered. With no recipient key the
//     migration does nothing (and logs), so a flag is never overwritten into a
//     state no one can open. It converts on a later startup once a key exists.
//   - Idempotent. A sealed box begins with the abuse-seal MAGIC ("FAS1"); a Tier-3
//     blob begins with a random 12-byte IV. Already-sealed blobs are skipped, so
//     re-running is safe and only stragglers (e.g. flags created before the
//     "seal new flags to Model B" change) get converted.
//   - Per-flag and non-fatal. Each flag is converted in its own transaction; a
//     failure (e.g. a key/format problem) leaves that one flag as Model A and is
//     logged, never aborting startup or other flags.
//   - lead_chat is never touched (already Model B; not in RESEAL_TARGET_TYPES).
//
// The server can SEAL (the public key is not secret) but cannot OPEN -- see
// server/services/abuse-seal.js (seal-only). Run from initDb() at startup.
// ═══════════════════════════════════════════════════════════════════════════════

const { decrypt } = require('../services/encryption');
const { sealToReviewer, isSealed } = require('../services/abuse-seal');

// Legacy server-readable (Model A) target types only. lead_chat is already Model B.
const RESEAL_TARGET_TYPES = ['peer_session', 'board_post'];

function toBuf(b) {
  if (b == null) return null;
  return Buffer.isBuffer(b) ? b : Buffer.from(b);
}

// The active abuse-review public key as SPKI-DER base64 -- the same format
// GET /api/abuse-review-key serves and a flagger client seals to. public_key is
// stored as a BLOB of the SPKI-DER bytes (see abuse-review-key.js). Returns null
// when no key is registered.
function getActiveReviewerPubB64(db) {
  const row = db.prepare(
    'SELECT public_key FROM abuse_review_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1'
  ).get();
  if (!row || row.public_key == null) return null;
  return toBuf(row.public_key).toString('base64');
}

// Re-seal one legacy Tier-3 (Model A) blob to a Model B sealed box. Returns a
// sealed Buffer, or the original blob untouched if it is null/empty or already
// sealed (idempotent).
function resealBlob(blob, pubB64) {
  const buf = toBuf(blob);
  if (buf == null || buf.length === 0) return blob;
  if (isSealed(buf)) return blob;
  const plaintext = decrypt(buf); // low-level: exact stored string, no JSON.parse
  return Buffer.from(sealToReviewer(pubB64, plaintext), 'base64');
}

// Convert every peer_session / board_post flag (and its evidence vault row, if
// any) from Model A to Model B. Returns { resealed, skipped, failed, deferred }.
function resealAbuseFlags(db, log) {
  const out = { resealed: 0, skipped: 0, failed: 0, deferred: false };
  const note = (m) => { if (log && typeof log.log === 'function') log.log(m); };
  const warn = (m) => { if (log && typeof (log.error || log.warn) === 'function') (log.error || log.warn)(m); };

  let pubB64 = null;
  try {
    pubB64 = getActiveReviewerPubB64(db);
  } catch (e) {
    note('reseal-abuse-flags: skipped (abuse_review_keys not present yet)');
    out.deferred = true;
    return out;
  }
  if (!pubB64) {
    note('reseal-abuse-flags: deferred until an abuse-review key is registered');
    out.deferred = true;
    return out;
  }

  let flags;
  try {
    const ph = RESEAL_TARGET_TYPES.map(() => '?').join(', ');
    flags = db.prepare(
      `SELECT id, content_encrypted FROM peer_abuse_flags WHERE target_type IN (${ph})`
    ).all(...RESEAL_TARGET_TYPES);
  } catch (e) {
    note('reseal-abuse-flags: skipped (peer_abuse_flags not present yet)');
    out.deferred = true;
    return out;
  }

  for (const flag of flags) {
    try {
      const vault = db.prepare(
        'SELECT sealed_content_encrypted, context_encrypted FROM peer_abuse_evidence_vault WHERE flag_id = ?'
      ).get(flag.id);

      const flagBuf = toBuf(flag.content_encrypted);
      const scBuf = vault ? toBuf(vault.sealed_content_encrypted) : null;
      const ctxBuf = vault ? toBuf(vault.context_encrypted) : null;
      const flagNeeds = flagBuf != null && flagBuf.length > 0 && !isSealed(flagBuf);
      const scNeeds = scBuf != null && scBuf.length > 0 && !isSealed(scBuf);
      const ctxNeeds = ctxBuf != null && ctxBuf.length > 0 && !isSealed(ctxBuf);

      if (!flagNeeds && !scNeeds && !ctxNeeds) { out.skipped++; continue; }

      // Seal OUTSIDE the transaction so a crypto failure never opens one.
      const newFlag = flagNeeds ? resealBlob(flag.content_encrypted, pubB64) : null;
      const newSc = scNeeds ? resealBlob(vault.sealed_content_encrypted, pubB64) : null;
      const newCtx = ctxNeeds ? resealBlob(vault.context_encrypted, pubB64) : null;

      const tx = db.transaction(() => {
        if (flagNeeds) {
          db.prepare('UPDATE peer_abuse_flags SET content_encrypted = ? WHERE id = ?').run(newFlag, flag.id);
        }
        if (vault && (scNeeds || ctxNeeds)) {
          db.prepare(
            'UPDATE peer_abuse_evidence_vault SET sealed_content_encrypted = ?, context_encrypted = ? WHERE flag_id = ?'
          ).run(
            scNeeds ? newSc : toBuf(vault.sealed_content_encrypted),
            ctxNeeds ? newCtx : toBuf(vault.context_encrypted),
            flag.id
          );
        }
      });
      tx();
      out.resealed++;
    } catch (e) {
      out.failed++;
      warn(`reseal-abuse-flags: flag ${flag.id} left as Model A (non-fatal): ${e.message}`);
    }
  }

  note(`reseal-abuse-flags: resealed ${out.resealed}, skipped ${out.skipped} already Model B, ${out.failed} deferred (non-fatal)`);
  return out;
}

module.exports = { resealAbuseFlags, resealBlob, getActiveReviewerPubB64, RESEAL_TARGET_TYPES };
