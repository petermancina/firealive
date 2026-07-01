// =============================================================================
// FIREALIVE GD -- Backup Chain Service
//
// Hash-chained, Ed25519-signed audit log of backup operations. Each chain entry
// references the previous entry's hash (Bitcoin-style), making any tampering
// forward-detectable: changing one entry breaks every entry after it. Twins the
// Regional backup-chain, with one adaptation: the GD signs chain entries with the
// same fingerprint-addressed backup signing family (gd-backup-signing-keys) that
// signs manifests, consolidating the Regional's separate manifest-vs-chain key
// split into one backup-domain family. Entries record the signing key's
// fingerprint (not a local id), so verification survives rotation and works
// across deployments.
//
// HASH CHAIN FORMAT
//
//   prev_hash        SHA-256 hex (64 chars) of the previous entry's this_hash.
//                    NULL in DB for the genesis entry; empty string for hash
//                    computation.
//   this_hash        SHA-256 hex of: prev_hash_str || canonical_payload ||
//                    created_at_str  (|| is byte concatenation). canonical_payload
//                    is canonical-JSON (recursive key sort, no whitespace, UTF-8).
//                    created_at_str is the SQLite-format timestamp generated in JS
//                    at append time.
//   signature        Ed25519 over this_hash bytes (the 32-byte digest, not the
//                    hex string). Stored base64.
//   signing_key_fingerprint
//                    SHA-256 hex of the signer's SPKI DER -- the backup signing
//                    key that produced the signature.
//
// EVENT TYPES (CHECK constraint enforces these in the schema)
//   CREATE            backup created
//   VERIFY            chain self-verification ran
//   RESTORE_REQUEST   restore initiated for a backup
//   RESTORE_COMPLETE  restore applied
//   DELETE_DENIED     attempted backup deletion that was refused
//
// ATOMICITY
//   appendChainEntry wraps the head-read + INSERT in db.transaction() so
//   concurrent callers can't both see the same head and produce entries with
//   duplicate prev_hash values. SQLite serializes write transactions; this gives
//   linear chain ordering.
//
// VERIFICATION SEMANTICS
//   verifyFullChain walks genesis to head. verifyChainUpToBackup(backupId) walks
//   genesis to the CREATE entry of backupId, so a partial chain compromise AFTER
//   backup X doesn't render X un-restorable.
//
// SCHEMA
//   See db-init.js -> backup_chain table. Two append-only triggers (BEFORE UPDATE
//   / BEFORE DELETE) reject SQL-level tampering; INSERTs remain permitted.
// =============================================================================

const crypto = require('crypto');
const backupKeysSvc = require('./gd-backup-signing-keys');

const VALID_EVENT_TYPES = new Set([
  'CREATE',
  'VERIFY',
  'RESTORE_REQUEST',
  'RESTORE_COMPLETE',
  'DELETE_DENIED',
]);

const PAYLOAD_VERSION = 1;

// -- Canonical JSON -----------------------------------------------------------
//
// Recursive key sort + JSON.stringify, intentionally re-implemented locally so
// this module has zero cross-module dependency on manifest internals -- chain
// integrity must not depend on the manifest format ever drifting. Object keys
// sorted at every depth; arrays preserve order; no whitespace; UTF-8 bytes.

function canonicalizeJson(value) {
  if (value === null) return 'null';
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

// -- Timestamp generation -----------------------------------------------------
//
// SQLite-style 'YYYY-MM-DD HH:MM:SS' (UTC), matching FireAlive's schema
// convention. Generated in JS so this_hash can be computed before INSERT.

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

// -- Hash computation ---------------------------------------------------------

/**
 * Compute the this_hash of a chain entry. Returns { hashHex, hashBytes }
 * (hashBytes is what gets signed). prevHash is a hex string OR null; genesis
 * entries pass null and computation uses empty string, NOT the literal "null".
 */
function computeThisHash(prevHash, payload, createdAt) {
  const prevHashStr = prevHash || '';
  const canonical = canonicalizeJson(payload);
  const input = prevHashStr + canonical + createdAt;
  const hashBytes = crypto.createHash('sha256').update(input, 'utf-8').digest();
  return { hashHex: hashBytes.toString('hex'), hashBytes };
}

// -- DB-level helpers (private) -----------------------------------------------

function getHeadRow(db) {
  return db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_fingerprint,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    ORDER BY id DESC
    LIMIT 1
  `).get();
}

// -- Public API ---------------------------------------------------------------

/**
 * Append a new entry to the chain. Atomic via db.transaction().
 *
 * options:
 *   eventType   one of VALID_EVENT_TYPES; required
 *   backupId    string|null; soft reference to a backup row
 *   payload     plain JSON-serializable object; canonicalized and bound into the hash
 *   actorUserId optional; merged into payload as actor_user_id for convenience
 *
 * Returns { id, prevHash, thisHash, signingKeyFingerprint, createdAt, payload
 * (canonicalized) }. Throws on invalid eventType, no active backup signing key,
 * or a SQL constraint failure.
 */
function appendChainEntry(db, options) {
  if (!options || typeof options !== 'object') {
    throw new Error('appendChainEntry: options object required');
  }
  const { eventType, backupId = null, payload = {}, actorUserId } = options;
  if (!VALID_EVENT_TYPES.has(eventType)) {
    throw new Error(`appendChainEntry: invalid eventType '${eventType}' (valid: ${[...VALID_EVENT_TYPES].join(', ')})`);
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    throw new Error('appendChainEntry: payload must be a plain object');
  }
  if (backupId !== null && typeof backupId !== 'string') {
    throw new Error('appendChainEntry: backupId must be string or null');
  }

  // Build the payload deterministically. Top-level fields enforced for every
  // entry so verifiers know what to expect; caller fields merge alongside.
  const fullPayload = {
    v: PAYLOAD_VERSION,
    event_type: eventType,
    backup_id: backupId,
    ...(actorUserId !== undefined ? { actor_user_id: actorUserId } : {}),
    ...payload,
  };

  return db.transaction(() => {
    const head = getHeadRow(db);
    const prevHash = head ? head.this_hash : null;
    const createdAt = nowSqlite();

    const { hashHex: thisHash, hashBytes } = computeThisHash(prevHash, fullPayload, createdAt);
    const { signature, signingKeyFingerprint } = backupKeysSvc.signManifest(db, hashBytes);

    const canonicalPayload = canonicalizeJson(fullPayload);

    const result = db.prepare(`
      INSERT INTO backup_chain
        (prev_hash, this_hash, signature, signing_key_fingerprint,
         event_type, backup_id, payload, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      prevHash,
      thisHash,
      signature.toString('base64'),
      signingKeyFingerprint,
      eventType,
      backupId,
      canonicalPayload,
      createdAt,
    );

    return {
      id: result.lastInsertRowid,
      prevHash,
      thisHash,
      signingKeyFingerprint,
      createdAt,
      payload: canonicalPayload,
    };
  })();
}

/**
 * Verify a single chain entry's internal consistency: recompute this_hash from
 * prev_hash + payload + created_at and match the stored value, then verify the
 * Ed25519 signature against the signing key with the entry's fingerprint.
 * Returns { ok, reason? }. reason: 'hash_mismatch' | 'signature_invalid' |
 * 'malformed_payload'. Does NOT verify chain linkage (that's the walker's job).
 */
function verifyEntry(db, entry) {
  let payloadObj;
  try {
    payloadObj = JSON.parse(entry.payload);
  } catch (err) {
    return { ok: false, reason: 'malformed_payload', detail: err.message };
  }

  const { hashHex, hashBytes } = computeThisHash(entry.prev_hash, payloadObj, entry.created_at);
  if (hashHex !== entry.this_hash) {
    return { ok: false, reason: 'hash_mismatch', expected: entry.this_hash, computed: hashHex };
  }

  const sigBuf = Buffer.from(entry.signature, 'base64');
  const sigValid = backupKeysSvc.verifyManifestByFingerprint(db, hashBytes, sigBuf, entry.signing_key_fingerprint);
  if (!sigValid) {
    return { ok: false, reason: 'signature_invalid' };
  }

  return { ok: true };
}

/**
 * Walk the chain from genesis up to an optional ending id (inclusive). Per entry:
 * (1) prev_hash matches the previous entry's this_hash (or NULL at genesis),
 * (2) this_hash recomputes, (3) Ed25519 signature verifies.
 *
 * Returns { ok: true, entriesVerified, lastVerifiedId, reachedStopAt } or
 * { ok: false, entriesVerified, brokenAtId, reason, detail? }.
 */
function walkChain(db, stopAtId = null) {
  const stmt = db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_fingerprint,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    ORDER BY id ASC
  `);

  let prevThisHash = null;
  let entriesVerified = 0;
  let lastVerifiedId = null;
  let reachedStopAt = false;

  for (const entry of stmt.iterate()) {
    // Linkage check
    const expectedPrev = prevThisHash;  // NULL for genesis (first iteration)
    if (entry.prev_hash !== expectedPrev) {
      return {
        ok: false,
        entriesVerified,
        brokenAtId: entry.id,
        reason: 'broken_linkage',
        detail: `entry ${entry.id} prev_hash=${entry.prev_hash} but expected predecessor's this_hash=${expectedPrev}`,
      };
    }

    // Internal consistency check
    const v = verifyEntry(db, entry);
    if (!v.ok) {
      return {
        ok: false,
        entriesVerified,
        brokenAtId: entry.id,
        reason: v.reason,
        detail: v.detail || (v.expected ? `expected=${v.expected} computed=${v.computed}` : undefined),
      };
    }

    entriesVerified++;
    lastVerifiedId = entry.id;
    prevThisHash = entry.this_hash;

    if (stopAtId !== null && entry.id === stopAtId) {
      reachedStopAt = true;
      break;
    }
  }

  if (stopAtId !== null && !reachedStopAt) {
    return {
      ok: false,
      entriesVerified,
      brokenAtId: null,
      reason: 'stop_id_not_found',
      detail: `requested stop at chain id ${stopAtId} but no such entry exists`,
    };
  }

  return { ok: true, entriesVerified, lastVerifiedId, reachedStopAt };
}

/**
 * Verify the full chain from genesis to head.
 */
function verifyFullChain(db) {
  return walkChain(db, null);
}

/**
 * Verify the chain from genesis up to the CREATE entry for backupId. A partial
 * chain compromise AFTER backup X does not block restore of X. Returns the
 * walkChain shape plus chainEntryId (the CREATE entry verified). Uses the
 * earliest CREATE entry if several exist for the same backup_id.
 */
function verifyChainUpToBackup(db, backupId) {
  if (typeof backupId !== 'string' || !backupId) {
    throw new Error('verifyChainUpToBackup: backupId required');
  }
  const createEntry = db.prepare(`
    SELECT id FROM backup_chain
    WHERE backup_id = ? AND event_type = 'CREATE'
    ORDER BY id ASC
    LIMIT 1
  `).get(backupId);
  if (!createEntry) {
    return {
      ok: false,
      entriesVerified: 0,
      brokenAtId: null,
      reason: 'no_create_entry',
      detail: `no CREATE chain entry exists for backup_id ${backupId}`,
    };
  }
  const result = walkChain(db, createEntry.id);
  return { ...result, chainEntryId: createEntry.id };
}

/**
 * Look up a chain entry by backup_id + event_type. Returns the row or null; if
 * several match, returns the most recent.
 */
function getChainEntryForBackup(db, backupId, eventType = 'CREATE') {
  if (!VALID_EVENT_TYPES.has(eventType)) {
    throw new Error(`getChainEntryForBackup: invalid eventType '${eventType}'`);
  }
  return db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_fingerprint,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    WHERE backup_id = ? AND event_type = ?
    ORDER BY id DESC
    LIMIT 1
  `).get(backupId, eventType);
}

/**
 * Get the most recent (head) chain entry. Returns null if the chain is empty.
 */
function getCurrentHead(db) {
  return getHeadRow(db);
}

/**
 * Stats for admin/UI: total entries, head, and last VERIFY status (if any).
 */
function getChainStats(db) {
  const total = db.prepare("SELECT COUNT(*) AS c FROM backup_chain").get().c;
  const head = getHeadRow(db);
  const lastVerify = db.prepare(`
    SELECT id, payload, created_at FROM backup_chain
    WHERE event_type = 'VERIFY'
    ORDER BY id DESC
    LIMIT 1
  `).get();
  return {
    totalEntries: total,
    head: head ? { id: head.id, eventType: head.event_type, backupId: head.backup_id, createdAt: head.created_at } : null,
    lastVerify: lastVerify ? {
      id: lastVerify.id,
      createdAt: lastVerify.created_at,
      payload: (() => { try { return JSON.parse(lastVerify.payload); } catch { return null; } })(),
    } : null,
  };
}

module.exports = {
  // public API
  appendChainEntry,
  verifyEntry,
  walkChain,
  verifyFullChain,
  verifyChainUpToBackup,
  getChainEntryForBackup,
  getCurrentHead,
  getChainStats,

  // exposed for testing
  canonicalizeJson,
  computeThisHash,
  nowSqlite,

  // constants
  VALID_EVENT_TYPES: [...VALID_EVENT_TYPES],
  PAYLOAD_VERSION,
};
