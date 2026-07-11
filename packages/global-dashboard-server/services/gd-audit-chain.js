// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Audit Log Integrity (Hash Chain + Signed Checkpoints)
//
// GD-server twin of the management console's services/audit-chain.js. Same
// three-leg design — per-row SHA-256 hash chain + Ed25519-signed checkpoints
// (+ the operator's own external log shipping). The only differences from the
// MC module are the GD audit_log column set (user_id, event_type, detail, ip,
// severity — no cef_message; ip not ip_address; plus severity), the GD's
// at-rest encryption helper (gd-encryption), and the GD config-table migration
// marker. The signing key family is the GD's own (audit_chain_signing_keys),
// distinct from report/abuse-export/MC-trust keys.
//
// The backfill does NOT alter existing rows; it chains and notarizes the
// current rows as the baseline, then installs the append-only triggers.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const path = require('path');
const { DB_PATH } = require('../db-init');
const { sealTier1, openTier1 } = require('./gd-tier1-seal');

const PAYLOAD_VERSION = 1;
const MIGRATION_MARKER = 'gd_audit_chain_backfilled';

// ── Canonical JSON (recursive key-sort) ────────────────────────────────────

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

// ── Canonical payload + row hash (GD column set) ────────────────────────────

function buildPayload(row) {
  return {
    v: PAYLOAD_VERSION,
    user_id: row.user_id == null ? null : String(row.user_id),
    event_type: row.event_type == null ? null : String(row.event_type),
    detail: row.detail == null ? null : String(row.detail),
    ip: row.ip == null ? null : String(row.ip),
    severity: row.severity == null ? null : String(row.severity),
  };
}

function computeRowHash(prevHash, row, timestamp) {
  const prevHashStr = prevHash || '';
  const canonical = canonicalizeJson(buildPayload(row));
  const input = prevHashStr + canonical + timestamp;
  const hashBytes = crypto.createHash('sha256').update(input, 'utf-8').digest();
  return { hashHex: hashBytes.toString('hex'), hashBytes };
}

// ── Audit-chain signing key family (own table; uses gd-encryption) ──────────

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
    throw new Error('no active GD audit-chain signing key; call ensureActiveAuditChainKey(db) first');
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

// ── Append (serialized via db.transaction) ──────────────────────────────────

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
    ip: fields.ip ?? null,
    severity: fields.severity ?? 'info',
  };
  const { hashHex } = computeRowHash(prevHash, row, timestamp);
  const result = db.prepare(`
    INSERT INTO audit_log (timestamp, user_id, event_type, detail, ip, severity, hash, prev_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(timestamp, row.user_id, row.event_type, row.detail, row.ip, row.severity, hashHex, prevHash);
  return { id: result.lastInsertRowid, hash: hashHex, prev_hash: prevHash, timestamp };
}

/**
 * appendGdAuditEntry(db, { userId, eventType, detail, ip, severity })
 * The single chained-write path for the GD audit log. severity defaults to 'info'.
 */
// Is this handle the real, durable audit chain -- the configured live database?
//
// A ':memory:' clone (the regression's hermetic copies) or any other file is not.
// The question is deliberately NOT "was a connection supplied": in production every
// caller supplies a live handle, so keying off injection would be a proxy that
// happens to correlate with tests, and would suppress real events.
//
// This exists so that outbound delivery of an audit event -- SIEM, SOAR, a paged
// operator -- can be gated on the event actually landing on the chain. A promotion
// or a self-fence exercised against a scratch database records where the change
// happened and emits nothing, so a drill can neither forge a row into the
// tamper-evident log an auditor reads nor page a SOC with a fence that never
// occurred. The Regional Server's middleware/audit.js carries the same predicate.
//
// db-init's require of this module is lazy (inside a migration function), so the
// top-level require of DB_PATH here does not create a cycle in either load order.
function isLiveChain(db) {
  try {
    if (!db || typeof db.name !== 'string' || !db.name || db.name === ':memory:') {
      return false;
    }
    return path.resolve(db.name) === path.resolve(DB_PATH);
  } catch (pathErr) {
    return false;
  }
}

function appendGdAuditEntry(db, fields) {
  if (!fields || typeof fields !== 'object' || !fields.eventType) {
    throw new Error('appendGdAuditEntry: { eventType } required');
  }
  return db.transaction(() => _appendCore(db, fields))();
}

// ── Checkpoints ─────────────────────────────────────────────────────────────

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

// ── Verification ──────────────────────────────────────────────────────────

function _walk(db, fromId) {
  const rows = fromId
    ? db.prepare('SELECT id, timestamp, user_id, event_type, detail, ip, severity, hash, prev_hash FROM audit_log WHERE id >= ? ORDER BY id ASC, rowid ASC').all(fromId)
    : db.prepare('SELECT id, timestamp, user_id, event_type, detail, ip, severity, hash, prev_hash FROM audit_log ORDER BY id ASC, rowid ASC').all();

  if (rows.length === 0) {
    return { intact: true, entriesVerified: 0, head: null };
  }
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

function _checkpointStatus(db) {
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

function verifyFull(db, { sinceId = null } = {}) {
  const walk = _walk(db, sinceId);
  if (!walk.intact) return walk;
  const cp = _checkpointStatus(db);
  if (cp.broken) return { ...cp.broken, entriesVerified: walk.entriesVerified };
  return { intact: true, entriesVerified: walk.entriesVerified, head: walk.head, checkpoint: cp.checkpoint };
}

function verifyIncremental(db) {
  const cp = getLatestCheckpoint(db);
  if (!cp) return verifyFull(db);
  const digest = computeHeadDigest(cp);
  if (!verifyHead(db, digest, cp.signatureBuf, cp.signing_key_id)) {
    return { intact: false, brokenAt: cp.head_id, reason: 'signature', detail: `checkpoint ${cp.id} signature invalid` };
  }
  const rowAtHead = db.prepare('SELECT id, hash FROM audit_log WHERE id = ?').get(cp.head_id);
  if (!rowAtHead || rowAtHead.hash !== cp.head_hash) {
    return { intact: false, brokenAt: cp.head_id, reason: 'checkpoint', detail: `chain head at id ${cp.head_id} does not match signed checkpoint ${cp.id}` };
  }
  const walk = _walk(db, cp.head_id);
  if (!walk.intact) return walk;
  return {
    intact: true,
    entriesVerified: walk.entriesVerified,
    head: walk.head || { id: cp.head_id, hash: cp.head_hash },
    checkpoint: { id: cp.id, head_id: cp.head_id, head_hash: cp.head_hash, entry_count: cp.entry_count, created_at: cp.created_at },
  };
}

// ── Migration (run-once, guarded; GD config-table marker) ────────────────────

function _hasColumn(db, table, col) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}

function _getMarker(db) {
  try {
    const r = db.prepare('SELECT value FROM config WHERE key = ?').get(MIGRATION_MARKER);
    return r ? r.value : null;
  } catch (_) { return null; }
}

function _setMarker(db) {
  db.prepare(`
    INSERT INTO config (key, value) VALUES (?, 'true')
    ON CONFLICT(key) DO UPDATE SET value = 'true'
  `).run(MIGRATION_MARKER);
}

function migrateGdAuditChain(db) {
  if (!_hasColumn(db, 'audit_log', 'hash')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN hash TEXT');
  }
  if (!_hasColumn(db, 'audit_log', 'prev_hash')) {
    db.exec('ALTER TABLE audit_log ADD COLUMN prev_hash TEXT');
  }

  ensureActiveAuditChainKey(db);

  if (_getMarker(db) === 'true') return { migrated: false, reason: 'already-done' };

  const backfill = db.transaction(() => {
    const rows = db.prepare(
      'SELECT id, timestamp, user_id, event_type, detail, ip, severity FROM audit_log ORDER BY id ASC, rowid ASC'
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

  createCheckpoint(db);

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

  _setMarker(db);
  return { migrated: true, backfilled };
}

module.exports = {
  isLiveChain,
  appendGdAuditEntry,
  verifyFull,
  verifyIncremental,
  createCheckpoint,
  getLatestCheckpoint,
  ensureActiveAuditChainKey,
  migrateGdAuditChain,
  canonicalizeJson,
  computeRowHash,
  computeHeadDigest,
  buildPayload,
  nowSqlite,
  PAYLOAD_VERSION,
};
