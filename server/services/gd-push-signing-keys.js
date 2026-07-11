// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Signing Keys Service
//
// Manages the Ed25519 keypair this MC uses to sign every outbound push to
// its connected GD. Public keys are stored plaintext (the GD needs to
// verify with them; no confidentiality concern); private keys are Tier-1
// AES-256-GCM-encrypted via encryptConfig and decrypted just-in-time
// only when the gd-push-signer service needs to sign a request. The raw
// private key is never cached at module scope — every signing operation
// decrypts from the DB.
//
// DELIBERATELY SEPARATE FROM chain-signing-keys.js AND backup-signing-keys.js
//
// The MC-to-GD trust channel is a distinct cryptographic concern from
// backup integrity and chain audit. A compromise of the GD-push key
// MUST NOT compromise backup signatures or chain entries. The three
// services share no state, no in-memory KeyObject instances, no DB
// tables. They are intentional duplicates (~150 lines of boilerplate
// each) — the security separation justifies the duplication. Same
// rationale as the chain vs backup signing-key separation in R3d-2.
//
// All three services use the SAME Tier-1 KEK (TIER1_ENCRYPTION_KEY) for
// at-rest encryption of private keys. Cryptographic key separation comes
// from the Ed25519 keypairs being distinct, not from at-rest key
// separation.
//
// Schema lives in db/init.js -> gd_push_signing_keys table. Same
// rotation model as chain_signing_keys / backup_signing_keys: one
// active keypair at a time (is_active = 1), old keypairs retained with
// is_active = 0 + rotated_out_at so a brief verification grace window
// exists across rotations.
//
// R3g PR3 PHASE 5 — STAGE / COMMIT / ROLLBACK SEMANTICS (C25)
//
// Before Phase 5, this service exposed atomic rotation:
// rotatePushKeypair() generated a new keypair, demoted the prior one,
// promoted the new one — all in one transaction. That model worked
// when the GD auto-trusted whatever an api_key-authenticated MC
// submitted (the old C12 design), but it cannot work under
// Foundational Rule 22 (BUILD-PLAN-v18): the new key must be reviewed
// and approved by a CISO before it becomes trusted.
//
// The new flow splits rotation across three calls bridged by the
// GD-side approval workflow (Commits 18-22):
//
//   1. stageNewPushKeypair(db) — locally generate a keypair and
//      insert it with is_active=0. The PRIOR active key stays active
//      and continues signing pushes. The staged row's id is what the
//      caller submits to the GD (C18 endpoint) and what gets stored
//      in gd_push_config.pending_signing_key_id.
//
//   2. (Time passes — CISO reviews and approves on the GD side.)
//
//   3a. commitStagedKeypair(db, stagedId) — when the C28 push tick
//       observes 'approved' from the GD's status endpoint, atomically
//       demote the prior is_active=1 and promote the staged row. From
//       this point forward the new key signs outbound pushes; the
//       prior key's row stays in the table with is_active=0 +
//       rotated_out_at=now for verification-grace-window purposes on
//       the GD side (the GD's signing_keys.approval_status STAYS
//       'approved' on the demoted row; see Commit 22's grace-window
//       query).
//
//   3b. rollbackStagedKeypair(db, stagedId) — when the C28 push tick
//       observes 'rejected', delete the staged row. The prior active
//       key continues unaffected. The operator can stage a fresh
//       keypair and try again.
//
// rotatePushKeypair AND ensureActivePushKeypair NOW THROW
//
// Both pre-Phase-5 functions are kept in the module but rewritten as
// loud-fail stubs that throw an Error directing the caller to the
// stage/commit/rollback flow. Any code path that hasn't been migrated
// fails clearly at runtime rather than silently auto-activating an
// unapproved key. The /rotate admin route (C26) and the gd-config
// initial-handshake path (C27) are the two consumers that get
// rewritten in subsequent commits.
//
// FINGERPRINTS
//
// Each key row carries a public_key_fingerprint — SHA-256 hex of the
// SPKI DER bytes, lowercase, 64 chars. Same format as
// backup_signing_keys.public_key_fingerprint. Used as the
// X-FA-Key-Fingerprint header value on every outbound push so the GD
// can resolve which row in its signing_keys trust registry to verify
// against.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');

// ── Keypair generation + fingerprint ──────────────────────────────────────

/**
 * Generate a fresh Ed25519 keypair. Returns:
 *   {
 *     publicKeyPem:           string  (PEM-encoded SPKI, safe to store plaintext)
 *     privateKeyPem:          string  (PEM-encoded PKCS#8, MUST be encrypted before storage)
 *     publicKeyFingerprint:   string  (SHA-256 hex of SPKI DER bytes, 64 chars)
 *   }
 *
 * Ed25519 key sizes are fixed: public 32 bytes raw, private 32 bytes raw.
 * PEM wrapping adds the SPKI/PKCS8 envelope plus base64 + header lines.
 * The fingerprint hashes the DER bytes (not the PEM text) so it's stable
 * across deployments regardless of PEM whitespace or line-ending quirks.
 */
function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const publicKeyFingerprint = computePublicKeyFingerprint(publicKeyPem);
  return { publicKeyPem, privateKeyPem, publicKeyFingerprint };
}

/**
 * computePublicKeyFingerprint(publicKeyPem)
 *
 * Compute the universal content-addressed identifier for a public key:
 * SHA-256 hex of the SPKI DER bytes. 64 hex chars (lowercase). Stable
 * across deployments and across PEM normalization (line endings, trailing
 * newlines, header whitespace) because it hashes the DER, not the PEM.
 *
 * Same format as backup-signing-keys.computePublicKeyFingerprint so an
 * operator can grep across MC and GD logs for a single fingerprint and
 * see the full key history (registration, rotation, verification events)
 * across both sides of the trust channel.
 *
 * Throws if the PEM doesn't parse — callers should pre-validate or
 * catch.
 */
function computePublicKeyFingerprint(publicKeyPem) {
  if (typeof publicKeyPem !== 'string' || !publicKeyPem.trim()) {
    throw new Error('computePublicKeyFingerprint: publicKeyPem must be a non-empty string');
  }
  let keyObj;
  try {
    keyObj = crypto.createPublicKey(publicKeyPem);
  } catch (err) {
    throw new Error(`computePublicKeyFingerprint: failed to parse public key PEM: ${err.message}`);
  }
  const der = keyObj.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// ── DB-level helpers (private) ────────────────────────────────────────────

function getActiveRow(db) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, private_key_encrypted,
           is_active, created_at
    FROM gd_push_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, public_key_fingerprint, is_active,
           created_at, rotated_out_at, notes
    FROM gd_push_signing_keys
    WHERE id = ?
  `).get(id);
}

// ── Public API ────────────────────────────────────────────────────────────

/**
 * ensureActivePushKeypair(db)
 *
 * R3g PR3 PHASE 5 (C25) — this function is intentionally disabled.
 *
 * Pre-Phase-5 this was a boot-time idempotent helper: if no row had
 * is_active=1, generate a fresh Ed25519 keypair and insert it as
 * is_active=1. That semantics auto-activated a key locally without
 * any CISO approval on the GD side, which violates Foundational Rule
 * 22 (BUILD-PLAN-v18: trust establishment requires authentication an
 * api_key thief wouldn't have). An MC that auto-creates an active key
 * starts signing pushes against a key the GD doesn't trust yet.
 *
 * The replacement flow is stage / commit / rollback:
 *   - Use stageNewPushKeypair(db) to insert a new keypair with
 *     is_active=0 ('staged').
 *   - Submit the staged key to the GD's POST /api/mc/:id/signing-key
 *     endpoint (which lands it as approval_status='pending_approval').
 *   - On CISO approval (observed via the GD's status endpoint),
 *     commitStagedKeypair(db, stagedId) atomically demotes the prior
 *     active key and promotes the staged one.
 *   - On rejection, rollbackStagedKeypair(db, stagedId) deletes the
 *     staged row.
 *
 * Callers reaching this function are evidence of a code path that
 * wasn't migrated to the stage flow. The throw is intentional: silent
 * fallback to the old auto-activate behavior is the worse failure
 * mode.
 */
function ensureActivePushKeypair(db) {
  throw new Error(
    'ensureActivePushKeypair is disabled under R3g PR3 Phase 5: signing keys must be ' +
    'staged (stageNewPushKeypair), submitted to the GD for CISO approval, and committed ' +
    '(commitStagedKeypair) only after approval is observed. See gd-push-signing-keys.js ' +
    'header for the new flow.'
  );
}

/**
 * getActivePushKey(db)
 *
 * Return everything the gd-push-signer service needs to sign a fresh
 * outbound push. Decrypts the private key just-in-time. The KeyObject
 * returned for privateKey can be passed directly to crypto.sign().
 *
 * Throws if no active keypair exists — callers should call
 * ensureActivePushKeypair(db) before the first push (typically as part
 * of the GD-config handshake flow, not at server boot, since most MCs
 * never enable GD-push).
 *
 * Returns: {
 *   id,
 *   publicKey: KeyObject,
 *   privateKey: KeyObject,
 *   publicKeyPem,
 *   publicKeyFingerprint
 * }
 */
function getActivePushKey(db) {
  const row = getActiveRow(db);
  if (!row) {
    throw new Error('no active GD-push signing key exists; call ensureActivePushKeypair(db) before signing');
  }
  const { pem: privateKeyPem } = openTier1('gd_push_signing_keys.private_key_encrypted', row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
    publicKeyFingerprint: row.public_key_fingerprint,
  };
}

/**
 * getActiveFingerprint(db)
 *
 * Convenience accessor returning ONLY the active key's fingerprint
 * string — no private-key decrypt, no KeyObject construction. Used by
 * code paths that need to display or log the current key identity
 * without invoking the signer (e.g. the gd-config status endpoint, the
 * admin signing-key inspection UI, audit-log entries about which key
 * was used).
 *
 * Returns the fingerprint string or null if no active key exists.
 */
function getActiveFingerprint(db) {
  const row = db.prepare(`
    SELECT public_key_fingerprint
    FROM gd_push_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
  return row ? row.public_key_fingerprint : null;
}

/**
 * rotatePushKeypair(db, options)
 *
 * R3g PR3 PHASE 5 (C25) — this function is intentionally disabled.
 *
 * Pre-Phase-5 this performed an atomic rotation: generate keypair,
 * demote prior, promote new — all in one local transaction. The GD
 * side trusted whatever an api_key-authenticated MC submitted (the
 * C12 design), so a local-only atomic rotation was fine.
 *
 * Under Phase 5's manual CISO approval flow, rotation can't be local
 * only — the new key isn't trusted by the GD until the CISO approves
 * it. The replacement is the stage / commit / rollback trio
 * (stageNewPushKeypair / commitStagedKeypair / rollbackStagedKeypair)
 * orchestrated by the C26 /rotate route + the C28 push tick.
 *
 * Throws on call to surface any code path that hasn't been migrated.
 */
function rotatePushKeypair(db, options = {}) {
  throw new Error(
    'rotatePushKeypair is disabled under R3g PR3 Phase 5: gold-standard rotation requires ' +
    'CISO approval, never local-only atomic-swap. Use stageNewPushKeypair to insert a new ' +
    'is_active=0 row, submit it to the GD for approval, then commitStagedKeypair after the ' +
    'C28 push tick observes "approved" from the GD status endpoint.'
  );
}

/**
 * stageNewPushKeypair(db, options)
 *
 * R3g PR3 PHASE 5 (C25). Generate a fresh Ed25519 keypair and insert
 * it into gd_push_signing_keys with is_active=0. The prior active key
 * (if any) is left untouched — it continues signing pushes while the
 * staged key awaits CISO approval on the GD side.
 *
 * The caller (C26 /rotate route or C27 initial-handshake path) takes
 * the returned id and publicKeyPem and submits to the GD's
 * POST /api/mc/<mc_id>/signing-key endpoint. The id is also stored in
 * gd_push_config.pending_signing_key_id so the C28 push tick knows
 * which row to commit when it observes 'approved'.
 *
 * options:
 *   notes (string, optional) — stored in the new row's notes column.
 *                              Defaults to 'staged for handshake'.
 *
 * Returns: {
 *   id,
 *   publicKeyPem,
 *   publicKeyFingerprint
 * }
 *
 * Does NOT return privateKeyPem — that's encrypted and stays in the
 * DB. The encrypted private key is only ever decrypted via
 * getActivePushKey, after the staged key has been committed.
 */
function stageNewPushKeypair(db, options = {}) {
  const { notes = 'staged for handshake' } = options;

  const { publicKeyPem, privateKeyPem, publicKeyFingerprint } = generateKeypair();
  const privateKeyEncrypted = sealTier1('gd_push_signing_keys.private_key_encrypted', { pem: privateKeyPem });

  const result = db.prepare(`
    INSERT INTO gd_push_signing_keys
      (public_key, public_key_fingerprint, private_key_encrypted,
       is_active, notes)
    VALUES (?, ?, ?, 0, ?)
  `).run(publicKeyPem, publicKeyFingerprint, privateKeyEncrypted, notes);

  return {
    id: result.lastInsertRowid,
    publicKeyPem,
    publicKeyFingerprint,
  };
}

/**
 * commitStagedKeypair(db, stagedId)
 *
 * R3g PR3 PHASE 5 (C25). Atomically demote any current is_active=1
 * row and promote the staged row (stagedId) to is_active=1. Wrapped
 * in a SQLite transaction so the swap either fully succeeds or leaves
 * the existing active key in place.
 *
 * Pre-conditions enforced:
 *   - stagedId must be a positive integer
 *   - The target row must exist
 *   - The target row must currently be is_active=0 with
 *     rotated_out_at IS NULL (i.e. truly staged, not a previously-
 *     rotated-out key being resurrected — the latter is blocked
 *     because the GD's signing-keys service rejects fingerprint
 *     re-submission of rotated-out keys; this local check makes the
 *     two sides agree)
 *
 * On commit:
 *   - Prior is_active=1 row (if any) gets is_active=0,
 *     rotated_out_at=now
 *   - Staged row gets is_active=1
 *
 * Returns: {
 *   newId,
 *   newPublicKeyFingerprint,
 *   priorId | null,
 *   priorPublicKeyFingerprint | null
 * }
 *
 * The caller (C28 push tick) uses the returned prior/new fingerprints
 * for audit-log correlation: "rotation committed locally, prior=X,
 * new=Y".
 *
 * Throws if pre-conditions fail.
 */
function commitStagedKeypair(db, stagedId) {
  if (!Number.isInteger(stagedId) || stagedId <= 0) {
    throw new Error('commitStagedKeypair: stagedId must be a positive integer');
  }

  return db.transaction(() => {
    const target = db.prepare(`
      SELECT id, public_key_fingerprint, is_active, rotated_out_at
      FROM gd_push_signing_keys
      WHERE id = ?
    `).get(stagedId);

    if (!target) {
      throw new Error(`commitStagedKeypair: gd_push_signing_keys.id=${stagedId} not found`);
    }
    if (target.is_active === 1) {
      throw new Error(`commitStagedKeypair: gd_push_signing_keys.id=${stagedId} is already active`);
    }
    if (target.rotated_out_at) {
      throw new Error(
        `commitStagedKeypair: gd_push_signing_keys.id=${stagedId} was previously rotated out; ` +
        'a rotated key cannot be promoted again. Stage a fresh keypair.'
      );
    }

    const prior = db.prepare(`
      SELECT id, public_key_fingerprint
      FROM gd_push_signing_keys
      WHERE is_active = 1
    `).get();

    if (prior) {
      db.prepare(`
        UPDATE gd_push_signing_keys
        SET is_active = 0,
            rotated_out_at = datetime('now')
        WHERE id = ?
      `).run(prior.id);
    }

    db.prepare(`
      UPDATE gd_push_signing_keys
      SET is_active = 1
      WHERE id = ?
    `).run(stagedId);

    return {
      newId: stagedId,
      newPublicKeyFingerprint: target.public_key_fingerprint,
      priorId: prior ? prior.id : null,
      priorPublicKeyFingerprint: prior ? prior.public_key_fingerprint : null,
    };
  })();
}

/**
 * rollbackStagedKeypair(db, stagedId)
 *
 * R3g PR3 PHASE 5 (C25). Delete a staged keypair row that didn't get
 * approved by the CISO. The C28 push tick calls this when it observes
 * 'rejected' from the GD's status endpoint. The prior active key (if
 * any) is unaffected and continues signing pushes.
 *
 * SAFETY: only deletes rows with is_active=0 AND rotated_out_at IS
 * NULL. A row that's currently active (is_active=1) or has been
 * rotated out (rotated_out_at set) is never deleted by this function,
 * even if the caller passes the wrong id. This protects against
 * accidental destruction of historical keys that the GD's grace-window
 * verifier might still be matching against.
 *
 * stagedId must be a positive integer.
 *
 * Returns: {
 *   deleted: boolean,        // true if a row was deleted
 *   fingerprint: string | null  // fingerprint of the deleted row, for audit
 * }
 *
 * NOT a hard error if the row doesn't exist or has already been
 * promoted — returns { deleted: false }. This lets the C28 tick be
 * idempotent: if it observes 'rejected' and tries to rollback but the
 * row is already gone (race with manual cleanup), the operation is a
 * no-op rather than an error.
 */
function rollbackStagedKeypair(db, stagedId) {
  if (!Number.isInteger(stagedId) || stagedId <= 0) {
    throw new Error('rollbackStagedKeypair: stagedId must be a positive integer');
  }

  return db.transaction(() => {
    const target = db.prepare(`
      SELECT id, public_key_fingerprint, is_active, rotated_out_at
      FROM gd_push_signing_keys
      WHERE id = ?
    `).get(stagedId);

    if (!target || target.is_active === 1 || target.rotated_out_at) {
      return { deleted: false, fingerprint: null };
    }

    db.prepare(`DELETE FROM gd_push_signing_keys WHERE id = ? AND is_active = 0 AND rotated_out_at IS NULL`).run(stagedId);
    return { deleted: true, fingerprint: target.public_key_fingerprint };
  })();
}

/**
 * listPushKeys(db)
 *
 * Admin UI listing — returns every keypair's public-side metadata.
 * Never returns private keys (they're not even SELECTed).
 *
 * Returns: array of {
 *   id, publicKeyPem, publicKeyFingerprint, isActive, createdAt,
 *   rotatedOutAt, notes
 * }
 */
function listPushKeys(db) {
  const rows = db.prepare(`
    SELECT
      id,
      public_key,
      public_key_fingerprint,
      is_active,
      created_at,
      rotated_out_at,
      notes
    FROM gd_push_signing_keys
    ORDER BY created_at DESC
  `).all();

  return rows.map(r => ({
    id: r.id,
    publicKeyPem: r.public_key,
    publicKeyFingerprint: r.public_key_fingerprint,
    isActive: r.is_active === 1,
    createdAt: r.created_at,
    rotatedOutAt: r.rotated_out_at,
    notes: r.notes,
  }));
}

module.exports = {
  generateKeypair,
  computePublicKeyFingerprint,
  ensureActivePushKeypair,
  getActivePushKey,
  getActiveFingerprint,
  rotatePushKeypair,
  // R3g PR3 Phase 5 (C25): stage / commit / rollback flow
  stageNewPushKeypair,
  commitStagedKeypair,
  rollbackStagedKeypair,
  listPushKeys,
};
