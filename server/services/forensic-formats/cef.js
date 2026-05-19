// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Common Event Format (R3l C26)
//
// Emits an audit-event slice set as ArcSight Common Event Format (CEF) — the
// most widely-supported SIEM ingestion format across the industry. Every
// major SIEM (Splunk via CIM, IBM QRadar via DSM, ArcSight ESM natively,
// LogRhythm, Sumo, FortiSIEM, Microsoft Sentinel via parsing) consumes CEF
// directly or with a thin parser.
//
// CEF V0 LINE FORMAT
//
//   CEF:0|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
//
// 7 header fields separated by '|' (pipe), followed by an Extension section
// that is space-separated key=value pairs. Header fields have their own
// escaping rules; extension fields have separate escaping rules.
//
// HEADER ESCAPING (positions 2-7)
//
//   '\' becomes '\\'
//   '|' becomes '\|'
//   No other escapes.
//
// EXTENSION ESCAPING (key=value pairs in the final field)
//
//   '\' becomes '\\'
//   '=' becomes '\='
//   '\n' (LF) becomes '\n' (literal backslash-n)
//   '\r' (CR) becomes '\r' (literal backslash-r)
//   No other escapes; spaces inside values are NOT escaped — multi-value
//   strings must be wrapped in some other delimiter if they need to
//   preserve spaces (we use canonical JSON for that case).
//
// MAPPING AUDIT EVENTS TO CEF
//
//   CEF:0|FireAlive|AuditExport|r3l-v1|<SignatureID>|<Name>|<Severity>|<Extension>
//
//   SignatureID    "<sliceId>:<event_type>"  e.g., "audit_log:USER_LOGIN"
//   Name           Human-readable description — same as SignatureID for
//                    audit events (the discriminator is the most useful
//                    short label)
//   Severity       Integer 0-10 mapped by event classification (see
//                    SEVERITY_BY_PATTERN below). Default 3 (informational).
//
//   Extension (standard CEF dictionary keys where applicable + cs* custom):
//
//     rt           Receipt time in epoch milliseconds — what most SIEM
//                    correlators use as the canonical event time
//     suser        Source user (user_id / user column)
//     src          Source IP (ip_address / ip column)
//     act          Action (auth_log.action column)
//     outcome      "success" | "failure" derived from event_type pattern
//     cs1          Slice id     cs1Label=slice
//     cs2          Event id     cs2Label=event_id
//     cs3          Canonical JSON of the full event row  cs3Label=event
//     cs4          this_hash (backup_chain only)  cs4Label=chain_hash
//     externalId   Event id (also exposed as cs2 — duplicated to
//                    populate both CEF-dictionary externalId and the
//                    custom cs2 slot for SIEMs that prefer one over
//                    the other)
//
// SEVERITY HEURISTIC
//
// A simple pattern-match on the event_type / action discriminator. The
// heuristic is intentionally conservative — failures and security events
// get 5-7; lifecycle events get 3-4; informational events default to 3.
// SIEM correlators apply their own scoring on top, so this is just a
// reasonable starting weight, not an authoritative severity assessment.
//
// LINE ORDERING
//
// epoch ASC, ties broken by (sliceId ASC, id ASC). Same deterministic
// sort as C23/C24/C25. CEF is single-line per event; no header line at
// the file level (SIEMs do not expect a CSV-style header in CEF).
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'cef';
const FILE_EXTENSION = '.cef';

const CEF_VERSION = '0';
const DEVICE_VENDOR = 'FireAlive';
const DEVICE_PRODUCT = 'AuditExport';
const DEVICE_VERSION = 'r3l-v1';

// Per-slice timestamp column and discriminator column. The discriminator
// is what populates SignatureID and Name in the CEF header.
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
    discriminatorField: null, // sessions has no event_type
    userField: 'user_id',
    ipField: 'ip_address',
  },
};

// Severity heuristic: pattern -> integer severity (CEF 0-10 scale).
// Order matters — the first matching regex wins, so most-specific
// patterns come first.
const SEVERITY_BY_PATTERN = [
  // High-severity security events
  { re: /LOGIN_FAILED|AUTH_FAILED|MFA_FAILED/i, severity: 6 },
  { re: /DELETE_DENIED|UNAUTHORIZED|FORBIDDEN|TAMPER/i, severity: 7 },
  { re: /COMPROMISE|EXPLOIT|MALWARE_DETECTED/i, severity: 9 },
  // Privileged operations
  { re: /RESTORE_|DELETE_|RELEASE_/i, severity: 7 },
  { re: /VERIFY|EXPORT_CREATED|HOLD_CREATED/i, severity: 4 },
  // Lifecycle events
  { re: /CREATE|UPDATE|MODIFY/i, severity: 4 },
  { re: /LOGIN|LOGOUT|AUTH_SUCCESS|MFA_SUCCESS/i, severity: 3 },
];

const DEFAULT_SEVERITY = 3;

/**
 * Parse a timestamp value into Unix epoch milliseconds. Same dual-format
 * logic as the prior format serializers (SQLite default + ISO 8601).
 * CEF's rt extension key wants epoch milliseconds (not seconds).
 */
function parseTimestampMs(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'cef: ' + sliceId + ' row ' + (rowId || '?') + ': timestamp required'
    );
  }
  let normalized = String(raw);
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(normalized)) {
    normalized = normalized.replace(' ', 'T') + 'Z';
  }
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) {
    throw new Error(
      'cef: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': unparseable timestamp: ' +
        raw
    );
  }
  return ms;
}

/**
 * Map an event discriminator to a CEF severity (0-10) using the
 * SEVERITY_BY_PATTERN heuristic. Falls back to DEFAULT_SEVERITY (3).
 */
function deriveSeverity(discriminator) {
  if (!discriminator) return DEFAULT_SEVERITY;
  const s = String(discriminator);
  for (const { re, severity } of SEVERITY_BY_PATTERN) {
    if (re.test(s)) return severity;
  }
  return DEFAULT_SEVERITY;
}

/**
 * Derive a CEF outcome value ("success" or "failure") from the
 * discriminator. Returns null for events that have no clear outcome
 * interpretation (so the extension is omitted rather than guessed).
 */
function deriveOutcome(discriminator) {
  if (!discriminator) return null;
  const s = String(discriminator).toUpperCase();
  if (/FAILED|DENIED|REJECTED|UNAUTHORIZED|FORBIDDEN/.test(s)) {
    return 'failure';
  }
  if (/SUCCESS|COMPLETE|VERIFIED|CREATED/.test(s)) {
    return 'success';
  }
  return null;
}

/**
 * Escape a CEF header field (positions 2-7 between '|' separators).
 * Rules: '\' -> '\\' and '|' -> '\|'. Nothing else is escaped.
 */
function escapeHeaderField(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

/**
 * Escape a CEF extension value. Rules:
 *   '\' -> '\\'
 *   '=' -> '\='
 *   LF  -> '\n' (literal backslash-n, NOT actual newline byte)
 *   CR  -> '\r' (literal backslash-r)
 * Nothing else (including spaces, which CEF parsers handle by reading up
 * to the next ' <key>=' or end of line).
 */
function escapeExtensionValue(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

/**
 * Build the CEF extension section (key=value pairs space-separated) for
 * a single event. Returns the string without leading/trailing whitespace.
 */
function buildExtension(sliceId, row, ms) {
  const config = SLICE_CONFIG[sliceId];
  const pairs = [];

  pairs.push('rt=' + ms);

  const discriminator = config.discriminatorField
    ? row[config.discriminatorField]
    : null;

  if (config.userField && row[config.userField]) {
    pairs.push('suser=' + escapeExtensionValue(row[config.userField]));
  }
  if (config.ipField && row[config.ipField]) {
    pairs.push('src=' + escapeExtensionValue(row[config.ipField]));
  }
  if (sliceId === 'authentication_logs' && row.action) {
    pairs.push('act=' + escapeExtensionValue(row.action));
  }
  const outcome = deriveOutcome(discriminator);
  if (outcome) {
    pairs.push('outcome=' + outcome);
  }

  // Custom string slots with labels for SIEM dashboards
  pairs.push('cs1=' + escapeExtensionValue(sliceId));
  pairs.push('cs1Label=slice');

  if (row.id !== undefined && row.id !== null) {
    pairs.push('cs2=' + escapeExtensionValue(String(row.id)));
    pairs.push('cs2Label=event_id');
    pairs.push('externalId=' + escapeExtensionValue(String(row.id)));
  }

  const rowJson = canonicalSerialize(row).toString('utf-8');
  pairs.push('cs3=' + escapeExtensionValue(rowJson));
  pairs.push('cs3Label=event');

  if (sliceId === 'backup_chain' && row.this_hash) {
    pairs.push('cs4=' + escapeExtensionValue(row.this_hash));
    pairs.push('cs4Label=chain_hash');
  }

  return pairs.join(' ');
}

/**
 * Build a single complete CEF line for one event.
 */
function buildLine(sliceId, row) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('cef: unknown slice id: ' + sliceId);
  }
  const ms = parseTimestampMs(row[config.timestampField], sliceId, row.id);
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const signatureId = sliceId + ':' + discriminator;
  const name = signatureId; // human-readable for now equals SignatureID
  const severity = deriveSeverity(discriminator);

  const header =
    'CEF:' +
    CEF_VERSION +
    '|' +
    escapeHeaderField(DEVICE_VENDOR) +
    '|' +
    escapeHeaderField(DEVICE_PRODUCT) +
    '|' +
    escapeHeaderField(DEVICE_VERSION) +
    '|' +
    escapeHeaderField(signatureId) +
    '|' +
    escapeHeaderField(name) +
    '|' +
    severity +
    '|';

  const extension = buildExtension(sliceId, row, ms);
  return header + extension;
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of the CEF stream; one event per line,
 * LF-terminated, no header line at the file level).
 *
 * Total ordering: epoch ASC, ties (sliceId ASC, id ASC).
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('cef: slices object required');
  }
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue;
    for (const row of rows) {
      const ms = parseTimestampMs(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, ms });
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
  CEF_VERSION,
  DEVICE_VENDOR,
  DEVICE_PRODUCT,
  DEVICE_VERSION,
  SEVERITY_BY_PATTERN,
  parseTimestampMs,
  deriveSeverity,
  deriveOutcome,
  escapeHeaderField,
  escapeExtensionValue,
  buildExtension,
  buildLine,
};
