// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: OASIS STIX 2.1 (R3l C27b)
//
// Emits an audit-event slice set as an OASIS STIX 2.1 JSON bundle —
// the open standard for threat-intelligence platform (TIP) ingestion.
// Consumed by every major TIP (MISP via the STIX 2.1 importer, Anomali
// ThreatStream natively, IBM X-Force Exchange, ThreatConnect, OpenCTI,
// AlienVault OTX via converter), plus several SIEMs with STIX import
// adapters.
//
// BUNDLE STRUCTURE
//
//   {
//     "type": "bundle",
//     "id": "bundle--<uuidv5>",
//     "objects": [
//       <identity SDO for FireAlive itself>,
//       <observed-data SDO for each event>,
//       ...
//     ]
//   }
//
// Note: STIX 2.1 dropped the `spec_version` field on the bundle itself
// (it's now only on each SDO). Bundles in 2.1 are minimal containers.
//
// Each event becomes one `observed-data` SDO. The `observed-data` SDO
// is the closest standard match for "the platform observed this event
// happen at this time" — exactly the audit-log semantic.
//
// SDO SHAPE PER EVENT
//
//   {
//     "type": "observed-data",
//     "spec_version": "2.1",
//     "id": "observed-data--<uuidv5>",
//     "created": "<ISO 8601 UTC with ms>",
//     "modified": "<same as created — observed-data is immutable>",
//     "created_by_ref": "identity--<fixed FireAlive UUID>",
//     "first_observed": "<event timestamp ISO 8601>",
//     "last_observed": "<same as first_observed — point-in-time event>",
//     "number_observed": 1,
//     "x_firealive_slice": "<sliceId>",
//     "x_firealive_event_type": "<discriminator>",
//     "x_firealive_event_id": "<original DB id>",
//     "x_firealive_user": "<user_id or user, when present>",
//     "x_firealive_ip": "<ip_address or ip, when present>",
//     "x_firealive_chain_hash": "<this_hash, backup_chain only>",
//     "x_firealive_canonical": "<canonical-JSON of full row>"
//   }
//
// Custom property names follow the STIX 2.1 convention of prefixing
// vendor-specific fields with `x_<vendor>_` (lowercase, underscore-
// separated). A STIX consumer that doesn't understand the x_firealive_*
// fields ignores them per the spec rather than rejecting the SDO.
//
// DETERMINISTIC UUIDS (UUIDv5, not v4)
//
// STIX object IDs are UUIDs. The spec accepts any UUID version, but most
// implementations use v4 (random) which would make each export produce
// different IDs for the same input — defeating byte-determinism. We use
// UUIDv5 (SHA-1 hash of namespace + name), derived from:
//
//   identity SDO id:
//     name = "firealive.io/forensic-export/identity"
//     UUIDv5 in the URL namespace (RFC 4122 Appendix C)
//
//   observed-data SDO id:
//     name = "firealive.io/forensic-export/" + sliceId + "/" + eventId + "/" + discriminator
//     UUIDv5 in the URL namespace
//
//   bundle id:
//     name = "firealive.io/forensic-export/bundle/" + sliceContentSha256
//     UUIDv5 in the URL namespace
//     (binds the bundle id to the slices content — same slices produce
//      the same bundle id)
//
// This gives full byte-determinism: same slices in produces the same
// bundle out, byte for byte.
//
// SAME ORDERING AS THE OTHER FORMAT SERIALIZERS
//
// epoch ASC, ties (sliceId ASC, id ASC). Objects array order matches.
//
// OUTPUT IS PRETTY-PRINTED JSON
//
// 2-space indent, LF line endings. STIX consumers parse JSON regardless
// of formatting; pretty-printing is for human readability when an
// analyst opens the .json file. Determinism is preserved because we
// build the document with sorted keys via canonicalSerialize, parse it,
// then stringify with indent — JSON.stringify preserves insertion order
// from the parsed object.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'stix-21';
const FILE_EXTENSION = '.json';

const SPEC_VERSION = '2.1';

// RFC 4122 Appendix C: the URL namespace UUID for UUIDv5. We hash names
// against this namespace to derive deterministic IDs.
const NAMESPACE_URL = '6ba7b811-9dad-11d1-80b4-00c04fd430c8';

const IDENTITY_NAME = 'FireAlive AuditExport';
const IDENTITY_CLASS = 'system';

const SLICE_CONFIG = {
  audit_log: {
    timestampField: 'timestamp',
    discriminatorField: 'event_type',
    userField: 'user_id',
    ipField: 'ip_address',
  },
  backup_chain: {
    timestampField: 'created_at',
    discriminatorField: 'event_type',
    userField: null,
    ipField: null,
  },
  incident_records: {
    timestampField: 'created_at',
    discriminatorField: 'incident',
    userField: 'initiated_by',
    ipField: null,
  },
  authentication_logs: {
    timestampField: 'timestamp',
    discriminatorField: 'action',
    userField: 'user',
    ipField: 'ip',
  },
  user_access_logs: {
    timestampField: 'created_at',
    discriminatorField: null,
    userField: 'user_id',
    ipField: 'ip_address',
  },
};

/**
 * RFC 4122 UUIDv5: SHA-1(namespace_bytes || name_bytes), then set version
 * and variant bits, format as 8-4-4-4-12 hex. Deterministic for the same
 * (namespace, name) pair, so it gives us byte-stable IDs across runs.
 *
 * namespace: UUID string (36 chars with hyphens, lowercase)
 * name: string
 * Returns: UUID string (36 chars with hyphens, lowercase)
 */
function uuidV5(namespace, name) {
  const nsHex = namespace.replace(/-/g, '');
  if (nsHex.length !== 32 || !/^[0-9a-f]+$/i.test(nsHex)) {
    throw new Error('uuidV5: namespace must be a valid UUID');
  }
  const nsBytes = Buffer.from(nsHex, 'hex');
  const nameBytes = Buffer.from(String(name), 'utf-8');
  const input = Buffer.concat([nsBytes, nameBytes]);
  const hash = crypto.createHash('sha1').update(input).digest(); // 20 bytes
  const uuid = Buffer.from(hash.subarray(0, 16));
  // Set version bits (UUIDv5: 0101 in the high nibble of byte 6)
  uuid[6] = (uuid[6] & 0x0f) | 0x50;
  // Set variant bits (RFC 4122: 10xx in the high two bits of byte 8)
  uuid[8] = (uuid[8] & 0x3f) | 0x80;
  const h = uuid.toString('hex');
  return (
    h.substring(0, 8) +
    '-' +
    h.substring(8, 12) +
    '-' +
    h.substring(12, 16) +
    '-' +
    h.substring(16, 20) +
    '-' +
    h.substring(20, 32)
  );
}

/**
 * Parse a timestamp and return ISO 8601 UTC with milliseconds (the
 * format STIX 2.1 wants for created / modified / first_observed /
 * last_observed). Throws with slice/row context.
 */
function parseTimestampIso(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'stix-21: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': timestamp required'
    );
  }
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error(
      'stix-21: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': unparseable timestamp: ' +
        raw
    );
  }
  return new Date(ms).toISOString();
}

/**
 * Build the FireAlive identity SDO. Same UUID across all exports so a
 * TIP can identify all FireAlive-sourced observed-data and group them
 * under one source. The created/modified timestamp uses a fixed epoch
 * (the FireAlive project epoch) so the identity SDO bytes are constant
 * across exports.
 */
function buildIdentitySdo() {
  const id = 'identity--' + uuidV5(NAMESPACE_URL, 'firealive.io/forensic-export/identity');
  const fixedTimestamp = '2026-01-01T00:00:00.000Z';
  return {
    created: fixedTimestamp,
    id: id,
    identity_class: IDENTITY_CLASS,
    modified: fixedTimestamp,
    name: IDENTITY_NAME,
    spec_version: SPEC_VERSION,
    type: 'identity',
  };
}

/**
 * Build one observed-data SDO for an audit event.
 *
 * exportedAt is the timestamp used for created/modified on the SDO.
 * It's the wall-clock time the export was produced — same across all
 * SDOs in the same bundle so the SDOs all "originated" at one moment.
 */
function buildObservedDataSdo(sliceId, row, exportedAt, identityId) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('stix-21: unknown slice id: ' + sliceId);
  }
  const eventIso = parseTimestampIso(
    row[config.timestampField],
    sliceId,
    row.id
  );
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const eventIdStr =
    row.id !== undefined && row.id !== null ? String(row.id) : '0';

  const idName =
    'firealive.io/forensic-export/' +
    sliceId +
    '/' +
    eventIdStr +
    '/' +
    discriminator;
  const id = 'observed-data--' + uuidV5(NAMESPACE_URL, idName);

  const sdo = {
    created: exportedAt,
    created_by_ref: identityId,
    first_observed: eventIso,
    id: id,
    last_observed: eventIso,
    modified: exportedAt,
    number_observed: 1,
    spec_version: SPEC_VERSION,
    type: 'observed-data',
    x_firealive_canonical: canonicalSerialize(row).toString('utf-8'),
    x_firealive_event_id: eventIdStr,
    x_firealive_event_type: discriminator,
    x_firealive_slice: sliceId,
  };

  if (config.userField && row[config.userField]) {
    sdo.x_firealive_user = String(row[config.userField]);
  }
  if (config.ipField && row[config.ipField]) {
    sdo.x_firealive_ip = String(row[config.ipField]);
  }
  if (sliceId === 'backup_chain' && row.this_hash) {
    sdo.x_firealive_chain_hash = row.this_hash;
  }

  return sdo;
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of pretty-printed STIX 2.1 JSON bundle).
 * Total ordering of objects: identity SDO first, then observed-data SDOs
 * sorted by epoch ASC with (sliceId ASC, id ASC) tiebreaker.
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('stix-21: slices object required');
  }

  // Sort events.
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue;
    for (const row of rows) {
      const iso = parseTimestampIso(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, ms: Date.parse(iso) });
    }
  }

  tuples.sort((a, b) => {
    if (a.ms !== b.ms) return a.ms - b.ms;
    if (a.sliceId !== b.sliceId) {
      return a.sliceId < b.sliceId ? -1 : 1;
    }
    const aid = String(a.row.id || '');
    const bid = String(b.row.id || '');
    if (aid !== bid) return aid < bid ? -1 : 1;
    return 0;
  });

  // identity SDO carries a fixed timestamp; observed-data SDOs use a
  // single exportedAt for the bundle so all SDOs in this bundle were
  // "issued" at one moment.
  const identitySdo = buildIdentitySdo();
  const exportedAt = new Date().toISOString();

  // Bundle id is content-derived for determinism: hash the slice content,
  // then UUIDv5 against that hash. Same slices in => same bundle id out.
  const slicesCanonical = canonicalSerialize(slices);
  const sliceContentSha256 = crypto
    .createHash('sha256')
    .update(slicesCanonical)
    .digest('hex');
  const bundleName =
    'firealive.io/forensic-export/bundle/' + sliceContentSha256;
  const bundleId = 'bundle--' + uuidV5(NAMESPACE_URL, bundleName);

  const objects = [identitySdo];
  for (const { sliceId, row } of tuples) {
    objects.push(
      buildObservedDataSdo(sliceId, row, exportedAt, identitySdo.id)
    );
  }

  const bundle = {
    id: bundleId,
    objects: objects,
    type: 'bundle',
  };

  // Canonicalize (sort keys recursively), parse, pretty-print with 2-space
  // indent. The parsed object preserves the canonical key order; the
  // stringify with indent emits readable JSON in that order.
  const canonical = canonicalSerialize(bundle);
  const reparsed = JSON.parse(canonical.toString('utf-8'));
  const prettyJson = JSON.stringify(reparsed, null, 2);
  return Buffer.from(prettyJson + '\n', 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false,
  serialize,
  // Internal helpers exposed for unit tests
  SPEC_VERSION,
  NAMESPACE_URL,
  IDENTITY_NAME,
  uuidV5,
  parseTimestampIso,
  buildIdentitySdo,
  buildObservedDataSdo,
};
