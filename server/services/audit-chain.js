// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Log Integrity (Hash Chain + Signed Checkpoints)
//
// Makes the long-standing "append-only SHA-256 hash chain" audit claim real
// and tamper-evident against an attacker who holds DB write access.
//
// THREE LEGS OF TAMPER-EVIDENCE
//
//   1. Per-row SHA-256 hash chain over ALL content fields. Each audit_log
//      row stores hash = SHA-256( prev_hash || canonical(payload) || timestamp ).
//      Detects any single-row edit, delete, or reorder via recompute + linkage.
//
//   2. Ed25519-signed checkpoints. Because FireAlive is open source, the hash
//      formula is public — an attacker with DB write could edit a row and
//      recompute every subsequent hash to repair the chain. So the chain HEAD
//      (head id + head hash + entry count + time) is periodically signed with a
//      dedicated audit-chain key and stored append-only in audit_chain_checkpoint.
//      The attacker can recompute the chain but cannot forge a signed head
//      without the private key, so pre-checkpoint tampering is caught. This is
//      the industry-standard "signed log head / digest" approach (CT signed
//      tree-heads, QLDB digests) — the right pattern for a HIGH-VOLUME log,
//      versus per-row signing (which would put the key on the hot path of every
//      API request). audit_log fires on every request; backup_chain does not —
//      hence checkpoints here, per-entry signatures there.
//
//   3. SIEM CEF ship-out (already in middleware/audit.js). An independent
//      external copy; the third leg, catching even key+checkpoint compromise
//      via divergence when SIEM_ENABLED=true.
//
// DELIBERATELY SEPARATE KEY FAMILY
//
//   The audit chain uses its OWN Ed25519 key family (audit_chain_signing_keys),
//   never the backup/forensic keys — same rationale chain-signing-keys.js gives:
//   a compromise of one custody chain's key must not compromise another's.
//   Private keys are Tier-1 AES-256-GCM-encrypted at rest via encryptConfig and
//   decrypted just-in-time; the raw private key is never cached at module scope.
//
// HONEST BASELINE FRAMING
//
//   The backfill does NOT alter existing rows (rewriting audit content would
//   itself be tampering). It chains and notarizes the CURRENT rows as the
//   baseline. Integrity is "from baseline establishment at deployment" — any
//   edit to any row from that point on breaks the chain. Pre-deployment
//   tampering is not retroactively detectable, because there was no chain.
//
// Schema (db/init.js): audit_log gains hash/prev_hash (added by migrateAuditChain
// guarded ALTER); audit_chain_checkpoint + audit_chain_signing_keys are created
// in the always-run schema. audit_log no-update/no-delete triggers are created
// by migrateAuditChain AFTER the backfill (a trigger present at boot would abort
// the backfill UPDATEs on the upgrade path).
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { sealTier1, openTier1 } = require('./tier1-seal');

const PAYLOAD_VERSION = 1;
const MIGRATION_MARKER = 'audit_chain_backfilled';

// ── Canonical JSON (recursive key-sort; re-implemented locally per house pattern) ──

function canonicalizeJson(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean' || typeof value === 'number') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalizeJson).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalizeJson(value[k])).join(',') + '}';
  }
  throw new Error(`canonicalizeJson: unsupported value type ${typeof value}`);
}

// ── Timestamp (SQLite 'YYYY-MM-DD HH:MM:SS' UTC; generated in JS so the hashed
//    value equals the stored value — never rely on the column default) ──

function nowSqlite() {
  const d = new Date();
  const pad = n => String(n).padStart(2, '0');
  return (
    d.getUTCFullYear() + '-' +
    pad(d.getUTCMonth() + 1) + '-' +
    pad(d.getUTCDate()) + ' ' +
    pad(d.getUTCHours()) + ':' +
    pad(d.getUTCMinutes()) + ':' +
    pad(d.getUTCSeconds())
  );
}

// ── Canonical payload + row hash ──────────────────────────────────────────
//
// Covers ALL content fields (so editing ANY of them breaks the chain) except
// id (assigned by the engine), timestamp (concatenated separately, mirroring
// backup-chain), and hash/prev_hash (the chain linkage itself). Fields are
// null-normalized so heterogeneous inserts hash deterministically.

function buildPayload(row) {
  return {
    v: PAYLOAD_VERSION,
    user_id: row.user_id == null ? null : String(row.user_id),
    event_type: row.event_type == null ? null : String(row.event_type),
    detail: row.detail == null ? null : String(row.detail),
    ip_address: row.ip_address == null ? null : String(row.ip_address),
    cef_message: row.cef_message == null ? null : String(row.cef_message),
  };
}

/**
 * computeRowHash(prevHash, row, timestamp) -> { hashHex, hashBytes }
 * prevHash: hex string OR null (genesis uses '' in the input, not "null").
 */
function computeRowHash(prevHash, row, timestamp) {
  const prevHashStr = prevHash || '';
  const canonical = canonicalizeJson(buildPayload(row));
  const input = prevHashStr + canonical + timestamp;
  const hashBytes = crypto.createHash('sha256').update(input, 'utf-8').digest();
  return { hashHex: hashBytes.toString('hex'), hashBytes };
}

// ── Audit-chain signing key family (own table; modeled on chain-signing-keys.js) ──

function generateKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

function getActiveKeyRow(db) {
  return db.prepare(`
    SELECT id, public_key, private_key_encrypted, is_active, created_at
    FROM audit_chain_signing_keys
    WHERE is_active = 1
    LIMIT 1
  `).get();
}

function getKeyRowById(db, id) {
  return db.prepare(`
    SELECT id, public_key, is_active, created_at, rotated_out_at, notes
    FROM audit_chain_signing_keys
    WHERE id = ?
  `).get(id);
}

/**
 * ensureActiveAuditChainKey(db) — boot/lazy idempotent. Generates and inserts a
 * fresh Ed25519 keypair if none is active. Returns { id, publicKeyPem, isNewlyCreated }.
 */
function ensureActiveAuditChainKey(db) {
  const existing = getActiveKeyRow(db);
  if (existing) {
    return { id: existing.id, publicKeyPem: existing.public_key, isNewlyCreated: false };
  }
  const { publicKeyPem, privateKeyPem } = generateKeypair();
  const privateKeyEncrypted = sealTier1('audit_chain_signing_keys.private_key_encrypted', { pem: privateKeyPem });
  const result = db.prepare(`
    INSERT INTO audit_chain_signing_keys
      (public_key, private_key_encrypted, is_active, notes)
    VALUES (?, ?, 1, 'auto-generated at server boot')
  `).run(publicKeyPem, privateKeyEncrypted);
  return { id: result.lastInsertRowid, publicKeyPem, isNewlyCreated: true };
}

function getActiveAuditChainKey(db) {
  const row = getActiveKeyRow(db);
  if (!row) {
    throw new Error('no active audit-chain signing key; call ensureActiveAuditChainKey(db) first');
  }
  const { pem: privateKeyPem } = openTier1('audit_chain_signing_keys.private_key_encrypted', row.private_key_encrypted);
  return {
    id: row.id,
    publicKey: crypto.createPublicKey(row.public_key),
    privateKey: crypto.createPrivateKey(privateKeyPem),
    publicKeyPem: row.public_key,
  };
}

function getAuditChainVerificationKey(db, signingKeyId) {
  const row = getKeyRowById(db, signingKeyId);
  if (!row) return null;
  return { id: row.id, publicKey: crypto.createPublicKey(row.public_key), isActive: row.is_active === 1 };
}

function signHead(db, digestBytes) {
  if (!Buffer.isBuffer(digestBytes) || digestBytes.length !== 32) {
    throw new Error('signHead: expected 32-byte SHA-256 digest');
  }
  const { id, privateKey } = getActiveAuditChainKey(db);
  const signature = crypto.sign(null, digestBytes, privateKey);
  return { signature, signingKeyId: id };
}

function verifyHead(db, digestBytes, signature, signingKeyId) {
  if (!Buffer.isBuffer(signature) || signature.length !== 64) return false;
  if (!Buffer.isBuffer(digestBytes) || digestBytes.length !== 32) return false;
  const verKey = getAuditChainVerificationKey(db, signingKeyId);
  if (!verKey) return false;
  return crypto.verify(null, digestBytes, verKey.publicKey, signature);
}

// ── Append (serialized: head-read + INSERT inside db.transaction so concurrent
//    callers can't both see the same head and fork prev_hash — SQLite serializes
//    write transactions; identical guarantee to backup-chain.appendChainEntry) ──

function getHeadRow(db) {
  return db.prepare(`
    SELECT id, hash, prev_hash, timestamp
    FROM audit_log
    ORDER BY id DESC
    LIMIT 1
  `).get();
}

function _appendCore(db, fields) {
  const head = getHeadRow(db);
  const prevHash = head ? head.hash : null;
  const timestamp = nowSqlite();
  const row = {
    user_id: fields.userId ?? null,
    event_type: fields.eventType,
    detail: fields.detail ?? null,
    ip_address: fields.ip ?? null,
    cef_message: fields.cef ?? null,
  };
  const { hashHex } = computeRowHash(prevHash, row, timestamp);
  const result = db.prepare(`
    INSERT INTO audit_log (timestamp, user_id, event_type, detail, ip_address, cef_message, hash, prev_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(timestamp, row.user_id, row.event_type, row.detail, row.ip_address, row.cef_message, hashHex, prevHash);
  return { id: result.lastInsertRowid, hash: hashHex, prev_hash: prevHash, timestamp };
}

/**
 * appendAuditEntry(db, { userId, eventType, detail, ip, cef })
 * The single chained-write path for the MC audit log. Returns { id, hash, prev_hash, timestamp }.
 */
function appendAuditEntry(db, fields) {
  if (!fields || typeof fields !== 'object' || !fields.eventType) {
    throw new Error('appendAuditEntry: { eventType } required');
  }
  return db.transaction(() => _appendCore(db, fields))();
}

// ── Checkpoints ───────────────────────────────────────────────────────────

function computeHeadDigest(cp) {
  const canonical = canonicalizeJson({
    v: PAYLOAD_VERSION,
    head_id: cp.head_id,
    head_hash: cp.head_hash,
    entry_count: cp.entry_count,
    created_at: cp.created_at,
  });
  return crypto.createHash('sha256').update(canonical, 'utf-8').digest();
}

function getLatestCheckpoint(db) {
  const row = db.prepare(`
    SELECT id, head_id, head_hash, entry_count, signature, signing_key_id, created_at
    FROM audit_chain_checkpoint
    ORDER BY id DESC
    LIMIT 1
  `).get();
  if (!row) return null;
  return { ...row, signatureBuf: Buffer.from(row.signature, 'base64') };
}

/**
 * createCheckpoint(db) — notarize the current chain head. Returns the checkpoint
 * row, or null if the audit log is empty (nothing to notarize yet).
 */
function createCheckpoint(db) {
  ensureActiveAuditChainKey(db);
  const head = getHeadRow(db);
  if (!head) return null;
  const count = db.prepare('SELECT COUNT(*) AS c FROM audit_log').get().c;
  const created_at = nowSqlite();
  const fields = { head_id: head.id, head_hash: head.hash, entry_count: count, created_at };
  const digest = computeHeadDigest(fields);
  const { signature, signingKeyId } = signHead(db, digest);
  const result = db.prepare(`
    INSERT INTO audit_chain_checkpoint (head_id, head_hash, entry_count, signature, signing_key_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(fields.head_id, fields.head_hash, fields.entry_count, signature.toString('base64'), signingKeyId, created_at);
  return { id: result.lastInsertRowid, ...fields, signing_key_id: signingKeyId };
}

// ── Verification ────────────────────────────────────────────────────────────
//
// Returns { intact, entriesVerified, brokenAt, reason, detail, head, checkpoint }.
// reason ∈ 'linkage' | 'content' | 'checkpoint' | 'signature'.
//   linkage   — a row's prev_hash != the prior row's stored hash (insert/delete/reorder)
//   content   — a row's stored hash != recompute from its content (edited in place)
//   checkpoint— the stored hash at the signed head_id != the signed head_hash
//               (full chain rewrite, or the head row was altered/deleted)
//   signature — the latest checkpoint's signature does not verify (forged checkpoint)

function _walk(db, fromId) {
  const rows = fromId
    ? db.prepare('SELECT id, timestamp, user_id, event_type, detail, ip_address, cef_message, hash, prev_hash FROM audit_log WHERE id >= ? ORDER BY id ASC, rowid ASC').all(fromId)
    : db.prepare('SELECT id, timestamp, user_id, event_type, detail, ip_address, cef_message, hash, prev_hash FROM audit_log ORDER BY id ASC, rowid ASC').all();

  if (rows.length === 0) {
    return { intact: true, entriesVerified: 0, head: null };
  }
  // Anchor: genesis walk starts at null; a bounded walk trusts the first row's
  // stored prev_hash as the anchor.
  let runningPrev = fromId ? rows[0].prev_hash : null;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if ((r.prev_hash || null) !== (runningPrev || null)) {
      return { intact: false, brokenAt: r.id, reason: 'linkage', detail: `prev_hash linkage mismatch at id ${r.id}`, head: null };
    }
    const expected = computeRowHash(runningPrev, r, r.timestamp).hashHex;
    if (r.hash !== expected) {
      return { intact: false, brokenAt: r.id, reason: 'content', detail: `content hash mismatch at id ${r.id}`, head: null };
    }
    runningPrev = r.hash;
  }
  const last = rows[rows.length - 1];
  return { intact: true, entriesVerified: rows.length, head: { id: last.id, hash: last.hash } };
}

function _checkpointStatus(db, head) {
  const cp = getLatestCheckpoint(db);
  if (!cp) return { checkpoint: null };
  const digest = computeHeadDigest(cp);
  if (!verifyHead(db, digest, cp.signatureBuf, cp.signing_key_id)) {
    return { broken: { intact: false, brokenAt: cp.head_id, reason: 'signature', detail: `checkpoint ${cp.id} signature invalid` } };
  }
  const rowAtHead = db.prepare('SELECT id, hash FROM audit_log WHERE id = ?').get(cp.head_id);
  if (!rowAtHead || rowAtHead.hash !== cp.head_hash) {
    return { broken: { intact: false, brokenAt: cp.head_id, reason: 'checkpoint', detail: `chain head at id ${cp.head_id} does not match signed checkpoint ${cp.id}` } };
  }
  return {
    checkpoint: {
      id: cp.id, head_id: cp.head_id, head_hash: cp.head_hash,
      entry_count: cp.entry_count, signing_key_id: cp.signing_key_id, created_at: cp.created_at,
    },
  };
}

/**
 * verifyFull(db, { sinceId }) — recompute the whole chain (or from sinceId) AND
 * validate it against the latest signed checkpoint.
 */
function verifyFull(db, { sinceId = null } = {}) {
  const walk = _walk(db, sinceId);
  if (!walk.intact) return walk;
  const cp = _checkpointStatus(db, walk.head);
  if (cp.broken) return { ...cp.broken, entriesVerified: walk.entriesVerified };
  return { intact: true, entriesVerified: walk.entriesVerified, head: walk.head, checkpoint: cp.checkpoint };
}

/**
 * verifyIncremental(db) — verify from the latest signed checkpoint's head forward
 * (O(new rows)); used by the periodic scheduler. Falls back to a full walk when
 * there is no checkpoint yet.
 */
function verifyIncremental(db) {
  const cp = getLatestCheckpoint(db);
  if (!cp) return verifyFull(db);
  // First confirm the checkpoint itself still verifies against its signed head.
  const digest = computeHeadDigest(cp);
  if (!verifyHead(db, digest, cp.signatureBuf, cp.signing_key_id)) {
    return { intact: false, brokenAt: cp.head_id, reason: 'signature', detail: `checkpoint ${cp.id} signature invalid` };
  }
  const rowAtHead = db.prepare('SELECT id, hash FROM audit_log WHERE id = ?').get(cp.head_id);
  if (!rowAtHead || rowAtHead.hash !== cp.head_hash) {
    return { intact: false, brokenAt: cp.head_id, reason: 'checkpoint', detail: `chain head at id ${cp.head_id} does not match signed checkpoint ${cp.id}` };
  }
  // Verify rows AFTER the checkpoint head (anchored on the trusted head hash).
  const walk = _walk(db, cp.head_id);
  if (!walk.intact) return walk;
  return {
    intact: true,
    entriesVerified: walk.entriesVerified,
    head: walk.head || { id: cp.head_id, hash: cp.head_hash },
    checkpoint: { id: cp.id, head_id: cp.head_id, head_hash: cp.head_hash, entry_count: cp.entry_count, created_at: cp.created_at },
  };
}

// ── Migration (run-once, guarded) ──────────────────────────────────────────
//
// Order is load-bearing: ALTER (guarded) -> backfill existing rows -> baseline
// checkpoint -> CREATE the audit_log no-update/no-delete triggers (AFTER the
// backfill UPDATEs) -> set the marker. The checkpoint + signing-key tables are
// created by the always-run schema in db/init.js, not here.

function _hasColumn(db, table, col) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}

function _getMarker(db) {
  try {
    const r = db.prepare("SELECT value FROM team_config WHERE key = ?").get(MIGRATION_MARKER);
    return r ? r.value : null;
  } catch (_) { return null; }
}

function _setMarker(db) {
  db.prepare(`
    INSERT INTO team_config (key, value, updated_by, updated_at)
    VALUES (?, 'true', 'SYSTEM', datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = 'true', updated_at = datetime('now')
  `).run(MIGRATION_MARKER);
}

function migrateAuditChain(db) {
  // 1. Guarded ALTER (idempotent across reboots).
  if (!_hasColumn(db, 'audit_log', 'hash')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN hash TEXT');
  }
  if (!_hasColumn(db, 'audit_log', 'prev_hash')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN prev_hash TEXT');
  }

  // Always ensure a signing key exists (cheap, idempotent) so checkpoints work.
  ensureActiveAuditChainKey(db);

  // 2. Already migrated? Triggers + backfill are one-time; return.
  if (_getMarker(db) === 'true') return { migrated: false, reason: 'already-done' };

  // 3. Backfill existing rows into the chain (content unchanged; we only set
  //    hash/prev_hash). Wrapped in a transaction.
  const backfill = db.transaction(() => {
    const rows = db.prepare(
      'SELECT id, timestamp, user_id, event_type, detail, ip_address, cef_message FROM audit_log ORDER BY id ASC, rowid ASC'
    ).all();
    let prev = null;
    const upd = db.prepare('UPDATE audit_log SET hash = ?, prev_hash = ? WHERE id = ?');
    for (const r of rows) {
      const { hashHex } = computeRowHash(prev, r, r.timestamp);
      upd.run(hashHex, prev, r.id);
      prev = hashHex;
    }
    return rows.length;
  });
  const backfilled = backfill();

  // 4. Baseline signed checkpoint over the post-backfill head.
  createCheckpoint(db);

  // 5. NOW create the immutability triggers (after the backfill UPDATEs).
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS audit_log_no_update
    BEFORE UPDATE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is not permitted');
    END;
  `);
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
    BEFORE DELETE ON audit_log
    BEGIN
      SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is not permitted');
    END;
  `);

  // 6. Mark done.
  _setMarker(db);
  return { migrated: true, backfilled };
}

module.exports = {
  // append + verify (primary API)
  appendAuditEntry,
  verifyFull,
  verifyIncremental,
  createCheckpoint,
  getLatestCheckpoint,
  // key family
  ensureActiveAuditChainKey,
  // migration
  migrateAuditChain,
  // helpers (exported for regression + tests)
  canonicalizeJson,
  computeRowHash,
  computeHeadDigest,
  buildPayload,
  nowSqlite,
  PAYLOAD_VERSION,
};
