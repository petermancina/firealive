// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Sleuth Kit Bodyfile v3 (R3l C23)
//
// Emits an audit-event slice set as a Sleuth Kit bodyfile v3, the canonical
// input format for `mactime` and other timeline-analysis tools in the
// Sleuth Kit / Autopsy stack. Each event from each slice becomes one line.
// Total ordering: timestamp ascending; ties broken by (slice_id, id).
//
// BODYFILE V3 FORMAT
//
//   MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
//
// 11 fields, pipe-delimited, LF-terminated, one event per line. All
// timestamps are Unix epoch seconds (integer). MD5 is the canonical-JSON
// content hash of the event (NOT a cryptographic guarantee — Sleuth Kit
// fixed MD5 in its spec; we honor the spec rather than substituting a
// stronger hash that would break downstream tool compatibility).
//
// AUDIT-EVENT-TO-BODYFILE MAPPING
//
// Audit events are not filesystem entries, so we map each event to a
// virtual read-only "file":
//
//   MD5             MD5 of canonical-JSON of the event
//   name            "<slice_id>/<discriminator>:<id>"
//                     - audit_log    → event_type
//                     - backup_chain → event_type
//                     - auth_log     → action
//                     - sessions     → "SESSION"  (no event_type column)
//   inode           numeric event id (sessions: hash to int if id is string)
//   mode_as_string  "-rw-r--r--"  (synthetic; all events read-only)
//   UID             numeric if user id is numeric, else 0
//   GID             0
//   size            byte length of canonical-JSON of the event
//   atime           event timestamp as Unix epoch seconds
//   mtime           same as atime (single-time-stamp events)
//   ctime           same as atime
//   crtime          same as atime
//
// Why all four timestamps equal: audit events are point-in-time
// observations, not files with separate access/modify/change/create
// metadata. mactime will surface each event as a single row in the
// timeline, which is the desired behavior.
//
// TIMESTAMP PARSING
//
// SQLite stores timestamps in two flavors used by this codebase:
//
//   - "YYYY-MM-DD HH:MM:SS"   (SQLite datetime('now') default)
//   - "YYYY-MM-DDTHH:MM:SS.sssZ"  (ISO 8601 from new Date().toISOString())
//
// Both parse via Date.parse(); we throw if a row has an unparseable
// timestamp rather than emit a bodyfile line with epoch 0 (which would
// silently corrupt the timeline).
//
// DELIMITER ESCAPING
//
// Pipe characters in event content (most commonly in audit_log.detail
// or backup_chain.payload) would break the bodyfile parser. We replace
// '|' with '%7C' in name field components; the rest of the event content
// only contributes to the MD5 and size fields, so internal pipes there
// do not affect the bodyfile structure.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'sleuth-kit-bodyfile';
const FILE_EXTENSION = '.bodyfile';
const SYNTHETIC_MODE = '-rw-r--r--';

// Per-slice timestamp column and discriminator column. The discriminator
// is the textual classification that goes into the bodyfile `name` field
// alongside the id — auditors reading mactime output can tell at a glance
// what kind of event each row represents.
const SLICE_CONFIG = {
  audit_log: { timestampField: 'timestamp', discriminatorField: 'event_type' },
  backup_chain: { timestampField: 'created_at', discriminatorField: 'event_type' },
  incident_records: { timestampField: 'created_at', discriminatorField: 'incident' },
  authentication_logs: { timestampField: 'timestamp', discriminatorField: 'action' },
  user_access_logs: { timestampField: 'created_at', discriminatorField: null }, // sessions has no event_type
};

/**
 * Parse a timestamp value into Unix epoch seconds. Accepts either of:
 *   - "YYYY-MM-DD HH:MM:SS"   (SQLite datetime default, UTC-naive)
 *   - "YYYY-MM-DDTHH:MM:SS.sssZ"  (ISO 8601)
 *
 * Returns: integer (epoch seconds).
 * Throws if the input is null/undefined or cannot be parsed.
 */
function parseTimestamp(raw) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error('sleuth-kit-bodyfile: timestamp required, got: ' + String(raw));
  }
  // Normalize SQLite default ("YYYY-MM-DD HH:MM:SS") to ISO by replacing
  // the space with T and appending Z. Date.parse otherwise treats the
  // bare form as local time, which would drift the timeline by the
  // server's offset.
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error('sleuth-kit-bodyfile: unparseable timestamp: ' + raw);
  }
  return Math.floor(ms / 1000);
}

/**
 * Coerce a user identifier to a numeric UID for the bodyfile UID field.
 * Returns 0 for null/undefined/empty. Returns the integer if the input
 * is a number or a numeric string. Otherwise hashes the string to a
 * 32-bit stable integer so repeated runs against the same data produce
 * the same UID (auditors expect the same user to show the same UID
 * across exports).
 */
function coerceUid(raw) {
  if (raw === null || raw === undefined || raw === '') return 0;
  if (typeof raw === 'number' && Number.isInteger(raw)) return raw;
  if (typeof raw === 'string' && /^\d+$/.test(raw)) {
    const n = parseInt(raw, 10);
    if (Number.isSafeInteger(n)) return n;
  }
  // Stable string-to-int: first 8 hex chars of SHA-256, interpreted as
  // unsigned 32-bit. Collisions are possible but rare and acceptable for
  // a UID field that's primarily for human readability in mactime.
  const hex = crypto
    .createHash('sha256')
    .update(String(raw))
    .digest('hex')
    .slice(0, 8);
  return parseInt(hex, 16);
}

/**
 * Coerce an inode value. Same numeric/hash rule as coerceUid.
 */
function coerceInode(raw) {
  return coerceUid(raw);
}

/**
 * Escape pipe characters in a name field component so they don't break
 * bodyfile parsing. URL-encode just the pipe; leave everything else as
 * the caller passed it.
 */
function escapeNameComponent(s) {
  return String(s).replace(/\|/g, '%7C');
}

/**
 * Resolve which column holds the user identifier for a given slice.
 * Different slices have different naming conventions in their schema.
 */
function userIdField(sliceId) {
  switch (sliceId) {
    case 'audit_log':
    case 'user_access_logs':
      return 'user_id';
    case 'authentication_logs':
      return 'user';
    case 'backup_chain':
    case 'incident_records':
      // No user column in these slices; UID will be 0.
      return null;
    default:
      return null;
  }
}

/**
 * Build a single bodyfile line for one event. Returns the formatted
 * string WITHOUT a trailing newline; the caller concatenates with '\n'.
 */
function buildLine(sliceId, row) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('sleuth-kit-bodyfile: unknown slice id: ' + sliceId);
  }

  const epoch = parseTimestamp(row[config.timestampField]);
  const eventJson = canonicalSerialize(row);
  const md5 = crypto.createHash('md5').update(eventJson).digest('hex');
  const size = eventJson.length;

  const idPart = row.id !== undefined && row.id !== null ? String(row.id) : '0';
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const name =
    escapeNameComponent(sliceId) +
    '/' +
    escapeNameComponent(discriminator) +
    ':' +
    escapeNameComponent(idPart);

  const inode = coerceInode(row.id);
  const uidField = userIdField(sliceId);
  const uid = uidField ? coerceUid(row[uidField]) : 0;
  const gid = 0;

  // 11-field bodyfile v3 line. All times equal (event is point-in-time).
  return [
    md5,
    name,
    inode,
    SYNTHETIC_MODE,
    uid,
    gid,
    size,
    epoch, // atime
    epoch, // mtime
    epoch, // ctime
    epoch, // crtime
  ].join('|');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * slices: { sliceId: [rows] }
 *
 * Returns: Buffer (UTF-8 encoding of the bodyfile content, LF-terminated
 * lines, no trailing blank line beyond the final LF).
 *
 * Total ordering is timestamp ASC, ties broken by (sliceId ASC, id ASC)
 * so a given input always produces a byte-identical bodyfile. This is
 * the determinism the manifest's slice SHA-256 relies on for stable
 * verification across exports.
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('sleuth-kit-bodyfile: slices object required');
  }

  // Collect (sliceId, row, epoch) tuples for sort.
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) {
      // Unknown slice in input — skip silently rather than throw, so a
      // future slice id added in another commit doesn't break this
      // serializer at runtime. Empty bodyfile is a valid degraded result.
      continue;
    }
    for (const row of rows) {
      let epoch;
      try {
        epoch = parseTimestamp(row[config.timestampField]);
      } catch (e) {
        // Surface the error with slice context so the operator can
        // identify which row corrupted the timeline.
        throw new Error(
          'sleuth-kit-bodyfile: ' + sliceId + ' row ' + (row.id || '?') + ': ' + e.message
        );
      }
      tuples.push({ sliceId, row, epoch });
    }
  }

  tuples.sort((a, b) => {
    if (a.epoch !== b.epoch) return a.epoch - b.epoch;
    if (a.sliceId !== b.sliceId) {
      return a.sliceId < b.sliceId ? -1 : 1;
    }
    const aid = String(a.row.id || '');
    const bid = String(b.row.id || '');
    if (aid !== bid) return aid < bid ? -1 : 1;
    return 0;
  });

  const lines = tuples.map((t) => buildLine(t.sliceId, t.row));
  const body = lines.length > 0 ? lines.join('\n') + '\n' : '';
  return Buffer.from(body, 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: true,
  serialize,
  // Internal helpers exposed for unit tests
  parseTimestamp,
  coerceUid,
  coerceInode,
  escapeNameComponent,
  buildLine,
};
