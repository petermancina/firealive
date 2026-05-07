// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Chain Service
//
// Hash-chained, Ed25519-signed audit log of backup operations. Each
// chain entry references the previous entry's hash (Bitcoin-style),
// making any tampering forward-detectable: changing one entry breaks
// every entry after it.
//
// HASH CHAIN FORMAT
//
//   prev_hash        SHA-256 hex (64 chars) of previous entry's
//                    this_hash. NULL in DB for the genesis entry;
//                    empty string for hash computation purposes.
//
//   this_hash        SHA-256 hex of:
//                      prev_hash_str || canonical_payload || created_at_str
//                    where || is byte concatenation. canonical_payload
//                    is canonical-JSON serialization (recursive key sort,
//                    no whitespace, UTF-8 bytes). created_at_str is the
//                    ISO timestamp generated in JS at append time.
//
//   signature        Ed25519 over this_hash bytes (the 32-byte digest,
//                    not the hex string). Stored base64 in DB.
//
// EVENT TYPES (CHECK constraint enforces these in the schema)
//
//   CREATE              backup created
//   VERIFY              chain self-verification ran
//   RESTORE_REQUEST     restore initiated for a backup
//   RESTORE_COMPLETE    restore applied
//   DELETE_DENIED       attempted backup deletion that was refused
//
// ATOMICITY
//
// appendChainEntry wraps the head-read + INSERT in db.transaction()
// so concurrent callers can't both see the same head and produce
// entries with duplicate prev_hash values. SQLite serializes write
// transactions; this serialization gives us linear chain ordering.
//
// VERIFICATION SEMANTICS
//
// verifyFullChain walks from genesis to head. verifyChainUpTo(backupId)
// walks from genesis to the CREATE entry of backupId. Partial chain
// compromises after a backup don't render that backup un-restorable --
// the restore service uses verifyChainUpTo so a broken entry AFTER
// backup X doesn't block restore of X.
//
// SCHEMA
//
// See db/init.js -> backup_chain table. Two append-only triggers
// (BEFORE UPDATE / BEFORE DELETE) reject SQL-level tampering. INSERTs
// remain permitted (append-only means writes-as-appends, not
// no-writes).
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const chainKeysSvc = require('./chain-signing-keys');

const VALID_EVENT_TYPES = new Set([
  'CREATE',
  'VERIFY',
  'RESTORE_REQUEST',
  'RESTORE_COMPLETE',
  'DELETE_DENIED',
]);

const PAYLOAD_VERSION = 1;

// ── Canonical JSON ───────────────────────────────────────────────────────
//
// Recursive key sort + JSON.stringify. Same rules as backup-manifest.js
// canonicalization (intentionally re-implemented locally so this module
// has zero cross-module dependencies on manifest internals -- chain
// integrity should not depend on the manifest format ever drifting).
//
// Properties:
//   - Object keys sorted alphabetically at every depth
//   - Arrays preserve insertion order (semantically meaningful)
//   - No whitespace
//   - UTF-8 bytes
//   - Round-trip stable: parse(serialize(x)) deep-equals x AND
//     serialize(parse(serialize(x))) byte-equals serialize(x)

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

// ── Timestamp generation ─────────────────────────────────────────────────
//
// SQLite-style 'YYYY-MM-DD HH:MM:SS' (UTC), matching the rest of
// FireAlive's schema convention. Generated in JS so we can compute
// this_hash before INSERT.

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

// ── Hash computation ─────────────────────────────────────────────────────

/**
 * Compute the this_hash of a chain entry given its inputs.
 *
 * Returns: { hashHex, hashBytes }  (hashBytes is what we sign)
 *
 * prevHash: hex string OR null. Genesis entries pass null; computation
 *           uses empty string, NOT the literal string "null".
 * payload:  any JSON-serializable value
 * createdAt: SQLite-format timestamp string
 */
function computeThisHash(prevHash, payload, createdAt) {
  const prevHashStr = prevHash || '';
  const canonical = canonicalizeJson(payload);
  const input = prevHashStr + canonical + createdAt;
  const hashBytes = crypto.createHash('sha256').update(input, 'utf-8').digest();
  return { hashHex: hashBytes.toString('hex'), hashBytes };
}

// ── DB-level helpers (private) ───────────────────────────────────────────

function getHeadRow(db) {
  return db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_id,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    ORDER BY id DESC
    LIMIT 1
  `).get();
}

function getEntryById(db, id) {
  return db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_id,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    WHERE id = ?
  `).get(id);
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * appendChainEntry(db, options)
 *
 * Append a new entry to the chain. Atomic via db.transaction().
 *
 * options:
 *   eventType   one of VALID_EVENT_TYPES; required
 *   backupId    string|null; soft reference to a backup row
 *   payload     plain JSON-serializable object; will be canonicalized
 *               and bound into the hash
 *   actorUserId optional; will be merged into payload as actor_user_id
 *               for convenience (callers may also include it directly
 *               in payload -- explicit option is just ergonomics)
 *
 * Returns:
 *   {
 *     id, prevHash, thisHash, signingKeyId, createdAt,
 *     payload                 // the canonicalized payload as stored
 *   }
 *
 * Throws on:
 *   - invalid eventType
 *   - no active chain signing key (call ensureActiveChainKeypair at boot)
 *   - SQL constraint failure (CHECK, FK, etc.)
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

  // Build the payload deterministically. Top-level fields enforced for
  // every entry so verifiers know what to expect. Caller-supplied fields
  // merge in alongside; canonicalization sorts them.
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
    const { signature, signingKeyId } = chainKeysSvc.signChainEntry(db, hashBytes);

    const canonicalPayload = canonicalizeJson(fullPayload);

    const result = db.prepare(`
      INSERT INTO backup_chain
        (prev_hash, this_hash, signature, signing_key_id,
         event_type, backup_id, payload, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      prevHash,
      thisHash,
      signature.toString('base64'),
      signingKeyId,
      eventType,
      backupId,
      canonicalPayload,
      createdAt,
    );

    return {
      id: result.lastInsertRowid,
      prevHash,
      thisHash,
      signingKeyId,
      createdAt,
      payload: canonicalPayload,
    };
  })();
}

/**
 * Verify a single chain entry's internal consistency:
 *   - Recompute this_hash from prev_hash + payload + created_at;
 *     match stored value
 *   - Verify Ed25519 signature against signing_key_id's public key
 *
 * Returns: { ok, reason? }
 *   reason values: 'hash_mismatch', 'signature_invalid', 'malformed_payload'
 *
 * Does NOT verify chain linkage (prev_hash matching predecessor's
 * this_hash) -- that's the chain walker's job.
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
  const sigValid = chainKeysSvc.verifyChainEntry(db, hashBytes, sigBuf, entry.signing_key_id);
  if (!sigValid) {
    return { ok: false, reason: 'signature_invalid' };
  }

  return { ok: true };
}

/**
 * Walk the chain from genesis up to an optional ending id (inclusive).
 *
 * Verification per entry:
 *   1. prev_hash matches the previous entry's this_hash
 *      (or is NULL if this is the genesis entry)
 *   2. this_hash recomputes correctly
 *   3. Ed25519 signature verifies
 *
 * stopAtId: optional. If provided, walk stops after verifying the
 *           entry with this id. Used by verifyChainUpTo for restore
 *           preconditions.
 *
 * Returns:
 *   { ok: true, entriesVerified: N, lastVerifiedId, reachedStopAt }
 *   { ok: false, entriesVerified: N, brokenAtId, reason, detail? }
 */
function walkChain(db, stopAtId = null) {
  const stmt = db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_id,
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
 * Verify the chain from genesis up to the CREATE entry for the given
 * backupId. Used by the restore service as a precondition: a partial
 * chain compromise AFTER backup X does not block restore of X, only
 * compromises before/at X do.
 *
 * Returns the same shape as walkChain plus a `chainEntryId` field
 * pointing to the CREATE entry verified.
 *
 * If multiple CREATE entries exist for the same backup_id (shouldn't
 * happen but defensively), uses the EARLIEST (smallest id).
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
 * Look up a chain entry by backup_id + event_type.
 *
 * Returns the row or null. If multiple matches (e.g. multiple VERIFY
 * entries for the same backup), returns the most recent.
 */
function getChainEntryForBackup(db, backupId, eventType = 'CREATE') {
  if (!VALID_EVENT_TYPES.has(eventType)) {
    throw new Error(`getChainEntryForBackup: invalid eventType '${eventType}'`);
  }
  return db.prepare(`
    SELECT id, prev_hash, this_hash, signature, signing_key_id,
           event_type, backup_id, payload, created_at
    FROM backup_chain
    WHERE backup_id = ? AND event_type = ?
    ORDER BY id DESC
    LIMIT 1
  `).get(backupId, eventType);
}

/**
 * Get the most recent (head) chain entry. Returns null if chain is empty.
 */
function getCurrentHead(db) {
  return getHeadRow(db);
}

/**
 * Stats for admin/UI: total entries, head id, head timestamp, last
 * verification status (if any VERIFY entries exist).
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
