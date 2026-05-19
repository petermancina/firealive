// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Forensic Format: Windows Event Log XML (EVTX) (R3l C27a)
//
// Emits an audit-event slice set as Windows Event Log XML — the textual
// representation of the Windows EVTX (.evtx) binary format. EVTX XML is
// consumed by:
//
//   - Windows Event Viewer (via XML export/import)
//   - Splunk Add-on for Windows (via wineventlog input)
//   - Microsoft Sentinel (via Log Analytics WindowsEvent table)
//   - Most security correlation tools that parse Windows logs
//
// The XML schema is the same one Microsoft publishes for EVTX export:
// each <Event> has a <System> section (provider, event id, timestamp,
// channel, computer) and an optional <EventData> section (the row's
// columns as <Data Name="..."> children).
//
// SCHEMA
//
//   <?xml version="1.0" encoding="utf-8"?>
//   <Events>
//     <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
//       <System>
//         <Provider Name="FireAlive-AuditExport"
//                   Guid="{fixed-guid-for-the-provider}"/>
//         <EventID Qualifiers="0">{numeric event id}</EventID>
//         <Version>0</Version>
//         <Level>{1-5}</Level>
//         <Task>0</Task>
//         <Opcode>0</Opcode>
//         <Keywords>0x8020000000000000</Keywords>
//         <TimeCreated SystemTime="{ISO 8601 UTC}"/>
//         <EventRecordID>{seq}</EventRecordID>
//         <Correlation/>
//         <Execution ProcessID="0" ThreadID="0"/>
//         <Channel>{derived from slice}</Channel>
//         <Computer>firealive</Computer>
//         <Security/>
//       </System>
//       <EventData>
//         <Data Name="slice">{sliceId}</Data>
//         <Data Name="event_type">{discriminator}</Data>
//         <Data Name="user">{user_id/user}</Data>
//         ...one <Data> per row column...
//         <Data Name="canonical">{canonical-JSON of the row}</Data>
//       </EventData>
//     </Event>
//     ...
//   </Events>
//
// PROVIDER GUID
//
// Windows providers are identified by GUID. We use a fixed GUID derived
// from the namespace UUID of "firealive.io/forensic-export/audit". The
// GUID is constant across all FireAlive forensic exports so a SIEM can
// register a single provider definition and route all FireAlive events
// to one channel/dashboard.
//
//   {a8f1e3c4-7d92-4b58-9c20-firealive001}
//
// (The last 12 hex chars spell "firealive001" — purely cosmetic for
// human recognition; the GUID is functionally arbitrary.)
//
// LEVEL MAPPING (Windows convention)
//
//   1   Critical    severe / immediate action required
//   2   Error       error condition
//   3   Warning     potential issue
//   4   Information default for normal events
//   5   Verbose     detailed diagnostic information
//
// FireAlive severity (0-10 from CEF) maps approximately:
//   0-3  -> Level 4 (Information)
//   4-5  -> Level 3 (Warning)
//   6-7  -> Level 2 (Error)
//   8-10 -> Level 1 (Critical)
//
// CHANNEL MAPPING (slice -> Channel)
//
//   audit_log              -> "FireAlive/AuditLog"
//   backup_chain           -> "FireAlive/BackupChain"
//   incident_records       -> "FireAlive/Incident"
//   authentication_logs    -> "FireAlive/Authentication"
//   user_access_logs       -> "FireAlive/Session"
//
// XML ESCAPING (XML 1.0 spec)
//
//   '&'  -> '&amp;'
//   '<'  -> '&lt;'
//   '>'  -> '&gt;'
//   '"'  -> '&quot;'   (only inside attribute values; we escape it
//                         everywhere for safety)
//   "'"  -> '&apos;'   (only inside attribute values; we escape it
//                         everywhere for safety)
//
// Control characters (0x00-0x1F except TAB, LF, CR) are invalid in XML
// 1.0 and must be stripped. We strip them with no replacement rather
// than substituting (the canonical-JSON cs3 equivalent preserves them
// if needed for verification).
//
// ORDERING
//
// epoch ASC, ties (sliceId ASC, id ASC). Same as the other format
// serializers. EventRecordID is assigned post-sort and is 1-based, so
// the record id matches the line order in the output.
// ═══════════════════════════════════════════════════════════════════════════════

'use strict';

const crypto = require('crypto');

const { canonicalSerialize } = require('../audit-export-shared');

const FORMAT_ID = 'evtx-xml';
const FILE_EXTENSION = '.xml';

// Fixed provider GUID; functional arbitrary, cosmetic last 12 chars.
// Format: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}, lowercase.
const PROVIDER_NAME = 'FireAlive-AuditExport';
const PROVIDER_GUID = '{a8f1e3c4-7d92-4b58-9c20-f1rea11ve001}';
const COMPUTER = 'firealive';

const SLICE_CONFIG = {
  audit_log: {
    timestampField: 'timestamp',
    discriminatorField: 'event_type',
    channel: 'FireAlive/AuditLog',
    userField: 'user_id',
  },
  backup_chain: {
    timestampField: 'created_at',
    discriminatorField: 'event_type',
    channel: 'FireAlive/BackupChain',
    userField: null,
  },
  incident_records: {
    timestampField: 'created_at',
    discriminatorField: 'incident',
    channel: 'FireAlive/Incident',
    userField: 'initiated_by',
  },
  authentication_logs: {
    timestampField: 'timestamp',
    discriminatorField: 'action',
    channel: 'FireAlive/Authentication',
    userField: 'user',
  },
  user_access_logs: {
    timestampField: 'created_at',
    discriminatorField: null,
    channel: 'FireAlive/Session',
    userField: 'user_id',
  },
};

const SEVERITY_BY_PATTERN = [
  { re: /COMPROMISE|EXPLOIT|MALWARE_DETECTED/i, severity: 9 },
  { re: /LOGIN_FAILED|AUTH_FAILED|MFA_FAILED/i, severity: 6 },
  { re: /DELETE_DENIED|UNAUTHORIZED|FORBIDDEN|TAMPER/i, severity: 7 },
  { re: /RESTORE_|DELETE_|RELEASE_/i, severity: 7 },
  { re: /VERIFY|EXPORT_CREATED|HOLD_CREATED/i, severity: 4 },
  { re: /CREATE|UPDATE|MODIFY/i, severity: 4 },
  { re: /LOGIN|LOGOUT|AUTH_SUCCESS|MFA_SUCCESS/i, severity: 3 },
];

/**
 * Parse a timestamp into a Date object (UTC). Same dual-format handling
 * as the other format serializers. Throws with slice/row context if
 * unparseable.
 */
function parseTimestampDate(raw, sliceId, rowId) {
  if (raw === null || raw === undefined || raw === '') {
    throw new Error(
      'evtx-xml: ' +
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
      'evtx-xml: ' +
        sliceId +
        ' row ' +
        (rowId || '?') +
        ': unparseable timestamp: ' +
        raw
    );
  }
  return new Date(ms);
}

/**
 * Derive a FireAlive severity score (0-10) then map it to a Windows
 * EVTX Level (1-5). Default severity 3 maps to Level 4 (Information).
 */
function deriveLevel(discriminator) {
  let severity = 3;
  if (discriminator) {
    const s = String(discriminator);
    for (const { re, severity: sev } of SEVERITY_BY_PATTERN) {
      if (re.test(s)) {
        severity = sev;
        break;
      }
    }
  }
  if (severity >= 8) return 1; // Critical
  if (severity >= 6) return 2; // Error
  if (severity >= 4) return 3; // Warning
  return 4; // Information
}

/**
 * Derive a numeric EventID from the discriminator. EVTX consumers expect
 * a small positive integer; we hash the discriminator string and take
 * the lower 16 bits, then clamp to the 0-65535 EVTX range. Stable across
 * runs so the same event_type always maps to the same EventID for
 * dashboarding.
 */
function deriveEventId(discriminator) {
  if (!discriminator) return 0;
  const hex = crypto
    .createHash('sha256')
    .update(String(discriminator))
    .digest('hex')
    .slice(0, 4); // 16 bits = 4 hex chars
  return parseInt(hex, 16);
}

/**
 * Strip XML 1.0-invalid control characters (anything 0x00-0x1F except
 * TAB 0x09, LF 0x0A, CR 0x0D). Returns the input with invalid bytes
 * removed.
 */
function stripInvalidXmlChars(s) {
  if (s === null || s === undefined) return '';
  // eslint-disable-next-line no-control-regex
  return String(s).replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

/**
 * Escape XML reserved characters. Apply after stripInvalidXmlChars.
 */
function escapeXml(s) {
  return stripInvalidXmlChars(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Format a Date as ISO 8601 UTC with milliseconds (the EVTX
 * SystemTime attribute convention).
 */
function formatSystemTime(d) {
  return d.toISOString();
}

/**
 * Build the <EventData> children list for a row. Each non-null column
 * becomes one <Data Name="<col>"><value></Data> child. Adds a final
 * <Data Name="canonical"> child with the canonical-JSON of the row for
 * verification round-trip.
 */
function buildEventData(sliceId, row) {
  const lines = [];
  lines.push('    <EventData>');
  for (const key of Object.keys(row).sort()) {
    const val = row[key];
    if (val === null || val === undefined) continue;
    lines.push(
      '      <Data Name="' +
        escapeXml(key) +
        '">' +
        escapeXml(val) +
        '</Data>'
    );
  }
  // canonical-JSON of the full row for verification
  const canonical = canonicalSerialize(row).toString('utf-8');
  lines.push(
    '      <Data Name="canonical">' + escapeXml(canonical) + '</Data>'
  );
  lines.push('      <Data Name="slice">' + escapeXml(sliceId) + '</Data>');
  lines.push('    </EventData>');
  return lines.join('\n');
}

/**
 * Build one complete <Event> element for a row. seq is the
 * 1-based EventRecordID assigned by the orchestrator post-sort.
 */
function buildEventElement(sliceId, row, seq) {
  const config = SLICE_CONFIG[sliceId];
  if (!config) {
    throw new Error('evtx-xml: unknown slice id: ' + sliceId);
  }
  const ts = parseTimestampDate(
    row[config.timestampField],
    sliceId,
    row.id
  );
  const discriminator = config.discriminatorField
    ? row[config.discriminatorField] || 'unknown'
    : 'SESSION';
  const eventId = deriveEventId(discriminator);
  const level = deriveLevel(discriminator);

  const lines = [];
  lines.push(
    '  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
  );
  lines.push('    <System>');
  lines.push(
    '      <Provider Name="' +
      escapeXml(PROVIDER_NAME) +
      '" Guid="' +
      escapeXml(PROVIDER_GUID) +
      '"/>'
  );
  lines.push('      <EventID Qualifiers="0">' + eventId + '</EventID>');
  lines.push('      <Version>0</Version>');
  lines.push('      <Level>' + level + '</Level>');
  lines.push('      <Task>0</Task>');
  lines.push('      <Opcode>0</Opcode>');
  lines.push('      <Keywords>0x8020000000000000</Keywords>');
  lines.push(
    '      <TimeCreated SystemTime="' +
      escapeXml(formatSystemTime(ts)) +
      '"/>'
  );
  lines.push('      <EventRecordID>' + seq + '</EventRecordID>');
  lines.push('      <Correlation/>');
  lines.push('      <Execution ProcessID="0" ThreadID="0"/>');
  lines.push('      <Channel>' + escapeXml(config.channel) + '</Channel>');
  lines.push('      <Computer>' + escapeXml(COMPUTER) + '</Computer>');
  lines.push('      <Security/>');
  lines.push('    </System>');
  lines.push(buildEventData(sliceId, row));
  lines.push('  </Event>');
  return lines.join('\n');
}

/**
 * serialize(slices) — orchestrator entry point.
 *
 * Returns: Buffer (UTF-8 encoding of a well-formed XML document).
 * Total ordering: epoch ASC, (sliceId ASC, id ASC). EventRecordID
 * assigned post-sort, 1-based.
 */
function serialize(slices) {
  if (!slices || typeof slices !== 'object') {
    throw new Error('evtx-xml: slices object required');
  }
  const tuples = [];
  for (const sliceId of Object.keys(slices)) {
    const rows = Array.isArray(slices[sliceId]) ? slices[sliceId] : [];
    const config = SLICE_CONFIG[sliceId];
    if (!config) continue;
    for (const row of rows) {
      const ts = parseTimestampDate(
        row[config.timestampField],
        sliceId,
        row.id
      );
      tuples.push({ sliceId, row, ms: ts.getTime() });
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

  const out = [];
  out.push('<?xml version="1.0" encoding="utf-8"?>');
  out.push('<Events>');
  let seq = 1;
  for (const { sliceId, row } of tuples) {
    out.push(buildEventElement(sliceId, row, seq));
    seq += 1;
  }
  out.push('</Events>');
  return Buffer.from(out.join('\n') + '\n', 'utf-8');
}

module.exports = {
  formatId: FORMAT_ID,
  fileExtension: FILE_EXTENSION,
  lineOriented: false, // multi-line structured XML, not one-event-per-line
  serialize,
  // Internal helpers exposed for unit tests
  PROVIDER_NAME,
  PROVIDER_GUID,
  COMPUTER,
  parseTimestampDate,
  deriveLevel,
  deriveEventId,
  stripInvalidXmlChars,
  escapeXml,
  formatSystemTime,
  buildEventData,
  buildEventElement,
};
