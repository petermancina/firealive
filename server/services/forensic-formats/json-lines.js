// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: JSON Lines (R3l C24)
//
// Emits an audit-event slice set as JSON Lines (JSONL) — one complete JSON
// object per line, LF-terminated. JSONL is the canonical line-oriented
// format for SIEM ingestion (Splunk, ELK, Sumo, Datadog), AWS S3 Select,
// and most stream-processing pipelines.
//
// LINE SHAPE
//
//   {"ts":<epoch>,"slice":"<sliceId>","seq":<n>,"event":{<row>},"hmac":"<hex>"}
//
// Field ordering within each line is alphabetical (canonicalSerialize from
// audit-export-shared) so the entire file is byte-deterministic given the
// same slices input. The line writer uses the same canonicalize logic the
// manifest does, so verification tools see one consistent JSON convention
// across the whole archive.
//
// Fields:
//
//   ts     integer Unix epoch seconds (NOT ISO 8601 — per the plan; epoch
//          is what SIEM correlators and timeline tools expect)
//   slice  source slice id (audit_log, backup_chain, etc.)
//   seq    monotonic 1-based sequence number within this file. Lets a
//          downstream tool detect missing or duplicated lines via simple
//          counter inspection without parsing every record.
//   event  the row as fetched from the slice's table, with original
//          column names preserved (so the event is recognizable to anyone
//          who knows the FireAlive schema). Timestamps INSIDE event keep
//          their original string form — the top-level ts is the parsed
//          epoch derived from that string.
//   hmac   HMAC-SHA256, hex-lowercase, over canonicalSerialize of the line
//          object WITHOUT the hmac field. Lets a tool verify each line
//          independently without parsing the manifest.
//
// PER-LINE HMAC: DEFENSE IN DEPTH, NOT THE PRIMARY INTEGRITY GUARANTEE
//
// The HMAC key is derived deterministically from the slices content:
//
//   hmacKey = HMAC-SHA256("FIREALIVE-FORENSIC-JSONL-V1", canonicalJson(slices))
//
// Anyone with the slices can recompute the key — so the per-line HMAC does
// NOT provide secret-keyed authentication. The PRIMARY integrity guarantee
// is the manifest's slice SHA-256 (recorded in the manifest) and the
// Ed25519 signature over the canonical manifest. The per-line HMAC adds:
//
//   1. Self-contained verifiability of individual lines without needing
//      to fetch the manifest. Useful when a SIEM ingests one line at a
//      time and rejects malformed input.
//
//   2. Detection of casual line-level tampering (e.g., a downstream
//      operator hand-editing a JSONL row to alter a user_id). Without
//      access to the slices used to derive the key, an attacker cannot
//      recompute a valid HMAC for a modified line.
//
//   3. Cross-line tamper detection via the seq monotonicity invariant
//      and the manifest's row-count assertion (recorded in the slice's
//      line_count field).
//
// An attacker WITH access to the slices used to derive the key can forge
// HMACs trivially. The defense against that attacker is the manifest's
// Ed25519 signature, not this HMAC. The per-line HMAC is for the
// "auditor reviewing the JSONL in isolation" use case, not the "attacker
// who has full write access to the export bundle" case.
//
// EPOCH TIMESTAMP PARSING
//
// Same logic as C23 sleuth-kit-bodyfile: accepts "YYYY-MM-DD HH:MM:SS"
// (SQLite default) and "YYYY-MM-DDTHH:MM:SS.sssZ" (ISO 8601). The SQLite
// default is treated as UTC by normalizing space-to-T and appending Z
// before Date.parse. Unparseable timestamps throw with slice/row context.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'json-lines';
const FILE_EXTENSION = '.jsonl';

// Domain separator for the HMAC key derivation. Bumping the version
// suffix invalidates prior derived keys; verifier tooling must know
// which version produced the file (recorded in the manifest's
// output_formats list, which is part of the Ed25519-signed bytes).
const HMAC_KEY_DOMAIN = 'FIREALIVE-FORENSIC-JSONL-V1';

// Per-slice timestamp column. Matches C23's mapping.
const SLICE_TIMESTAMP_FIELD = {
  audit_log: 'timestamp',
  backup_chain: 'created_at',
  incident_records: 'created_at',
  authentication_logs: 'timestamp',
  user_access_logs: 'created_at',
};

/**
 * Parse a timestamp value into Unix epoch seconds. Accepts the two
 * timestamp flavors this codebase emits (SQLite default and ISO 8601).
 * Throws on null/undefined/unparseable input.
 */
function parseTimestamp(raw) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error('json-lines: timestamp required, got: ' + String(raw));
  }
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error('json-lines: unparseable timestamp: ' + raw);
  }
  return Math.floor(ms / 1000);
}

/**
 * Derive the per-export HMAC key from the slices content. Deterministic:
 * the same slices produce the same key, so verifier tooling can
 * reconstruct it.
 *
 * Returns: Buffer (32 bytes — HMAC-SHA256 output)
 */
function deriveHmacKey(slices) {
  const slicesCanonical = canonicalSerialize(slices);
  return crypto
    .createHmac('sha256', HMAC_KEY_DOMAIN)
    .update(slicesCanonical)
    .digest();
}

/**
 * Compute HMAC-SHA256 of canonicalSerialize(lineWithoutHmac) using the
 * per-export key. Returns lowercase hex.
 */
function computeLineHmac(key, lineWithoutHmac) {
  const lineBytes = canonicalSerialize(lineWithoutHmac);
  return crypto.createHmac('sha256', key).update(lineBytes).digest('hex');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * slices: { sliceId: [rows] }
 *
 * Returns: Buffer (UTF-8 encoding of the JSONL content; LF-terminated
 * lines; no trailing blank line beyond the final LF on the last record).
 *
 * Total ordering: epoch ASC, ties broken by (sliceId ASC, id ASC). Same
 * deterministic sort as C23 — the entire export bundle uses one ordering
 * convention so auditors can correlate rows across formats.
 *
 * seq is assigned AFTER sorting so it matches the line position in the
 * file (1-based).
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('json-lines: slices object required');
  }

  const hmacKey = deriveHmacKey(slices);

  // Collect (sliceId, row, epoch) for sort. Unknown slice ids without a
  // configured timestamp field are silently skipped (matches C23's
  // forward-compatible posture).
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const tsField = SLICE_TIMESTAMP_FIELD[sliceId];
    if (!tsField) continue;
    for (const row of rows) {
      let epoch;
      try {
        epoch = parseTimestamp(row[tsField]);
      } catch (e) {
        throw new Error(
          'json-lines: ' + sliceId + ' row ' + (row.id || '?') + ': ' + e.message
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

  const out = [];
  let seq = 1;
  for (const { sliceId, row, epoch } of tuples) {
    const lineWithoutHmac = {
      event: row,
      seq: seq,
      slice: sliceId,
      ts: epoch,
    };
    const hmac = computeLineHmac(hmacKey, lineWithoutHmac);
    const fullLine = {
      ...lineWithoutHmac,
      hmac,
    };
    // canonicalSerialize produces the line bytes; appending '\n' gives a
    // valid JSONL line. The trailing newline is consistent across lines
    // so a tool that line-splits by '\n' gets exactly N lines for N
    // events.
    out.push(canonicalSerialize(fullLine));
    out.push(Buffer.from('\n', 'utf-8'));
    seq += 1;
  }

  return Buffer.concat(out);
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: true,
  serialize,
  // Internal helpers exposed for unit tests
  HMAC_KEY_DOMAIN,
  parseTimestamp,
  deriveHmacKey,
  computeLineHmac,
};
