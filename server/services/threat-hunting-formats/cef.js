// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Output Formatter: CEF (B5m)
//
// Emits one ArcSight CEF line per event, built from the ALREADY-PROJECTED model.
// It does NOT reuse the raw stored audit cef_message: that string carries the
// un-pseudonymized user and detail, so reusing it would defeat the feed's
// pseudonymization. Here suser is always the pseudonym the collectors produced.
//
//   CEF:0|FireAlive|ThreatHunting|thr-v1|<domain>:<disc>|<name>|<sev>|<ext>
//
// Well-known fields map to standard CEF keys (rt, suser, src, act, outcome); the
// remaining projected fields are packed losslessly as compact JSON in msg (the
// last extension key, so spaces in it never confuse a parser). Header and
// extension escaping follow the same rules as the forensic CEF exporter.
// ═══════════════════════════════════════════════════════════════════════════════

const CEF_VERSION = '0';
const VENDOR = 'FireAlive';
const PRODUCT = 'ThreatHunting';
const VERSION = 'thr-v1';
const CONTENT_TYPE = 'text/plain; charset=utf-8';

// Per-domain: which projected field is the event time and which is the
// discriminator (drives SignatureID, act, severity, outcome).
const DOMAIN_CEF = {
  auth_events: { time: 'timestamp', disc: 'action' },
  sessions: { time: 'created_at', disc: null },
  audit_trail: { time: 'timestamp', disc: 'event_type' },
  integrity: { time: 'received_at', disc: 'status' },
};

function escapeHeaderField(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/\\/g, '\\\\').replace(/\|/g, '\\|');
}

function escapeExtensionValue(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/\\/g, '\\\\')
    .replace(/=/g, '\\=')
    .replace(/\n/g, '\\n')
    .replace(/\r/g, '\\r');
}

// SQLite 'YYYY-MM-DD HH:MM:SS' is UTC; convert to epoch ms, else null.
function toEpochMs(ts) {
  if (typeof ts !== 'string' || !ts) return null;
  let s = ts.trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) s = s.replace(' ', 'T') + 'Z';
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

function deriveSeverity(domain, disc) {
  const d = String(disc || '').toLowerCase();
  if (domain === 'integrity') {
    if (d === 'fail') return 8;
    if (d === 'unreachable') return 6;
    if (d === 'warning') return 5;
    if (d === 'inconclusive') return 4;
    return 2;
  }
  if (/lock|fail|deny|denied|reject|revoke|delete|disable|tamper/.test(d)) return 7;
  return 3;
}

function deriveOutcome(domain, disc) {
  const d = String(disc || '').toLowerCase();
  if (domain === 'integrity') {
    if (d === 'clean') return 'success';
    if (d === 'fail' || d === 'warning') return 'failure';
    return null;
  }
  if (/lock|fail|deny|denied|reject/.test(d)) return 'failure';
  if (/login|success|grant|issue/.test(d)) return 'success';
  return null;
}

function buildLine(domain, event) {
  const e = event || {};
  const cfg = DOMAIN_CEF[domain] || { time: null, disc: null };
  const discVal = cfg.disc && e[cfg.disc] != null
    ? e[cfg.disc]
    : (domain === 'sessions' ? 'SESSION' : 'event');
  const signatureId = String(domain || 'threat-hunting') + ':' + discVal;
  const severity = deriveSeverity(domain, discVal);

  const header = 'CEF:' + CEF_VERSION + '|'
    + escapeHeaderField(VENDOR) + '|'
    + escapeHeaderField(PRODUCT) + '|'
    + escapeHeaderField(VERSION) + '|'
    + escapeHeaderField(signatureId) + '|'
    + escapeHeaderField(signatureId) + '|'
    + severity + '|';

  const used = {};
  const pairs = [];
  const ms = toEpochMs(cfg.time ? e[cfg.time] : null);
  if (ms !== null) { pairs.push('rt=' + ms); used[cfg.time] = true; }
  if (e.actor !== undefined) { pairs.push('suser=' + escapeExtensionValue(e.actor)); used.actor = true; }
  if (e.source_ip !== undefined) { pairs.push('src=' + escapeExtensionValue(e.source_ip)); used.source_ip = true; }
  if (cfg.disc && e[cfg.disc] !== undefined) { pairs.push('act=' + escapeExtensionValue(e[cfg.disc])); used[cfg.disc] = true; }
  const outcome = deriveOutcome(domain, discVal);
  if (outcome) pairs.push('outcome=' + outcome);

  const rest = {};
  let restCount = 0;
  for (const k of Object.keys(e)) {
    if (used[k]) continue;
    rest[k] = e[k];
    restCount += 1;
  }
  if (restCount > 0) pairs.push('msg=' + escapeExtensionValue(JSON.stringify(rest)));

  return header + pairs.join(' ');
}

function events(model) {
  const m = model || {};
  const rows = Array.isArray(m.events) ? m.events : [];
  const domain = m.domain || 'threat-hunting';
  const lines = [];
  for (const e of rows) lines.push(buildLine(domain, e));
  return lines.join('\n');
}

function summary(model) {
  const m = model || {};
  const header = 'CEF:' + CEF_VERSION + '|'
    + escapeHeaderField(VENDOR) + '|'
    + escapeHeaderField(PRODUCT) + '|'
    + escapeHeaderField(VERSION) + '|'
    + 'summary:resource' + '|'
    + 'Threat-hunting summary' + '|'
    + '1' + '|';
  const pairs = [];
  const ms = toEpochMs(m.generated_at);
  if (ms !== null) pairs.push('rt=' + ms);
  pairs.push('msg=' + escapeExtensionValue(JSON.stringify({
    resource_metrics: m.resource_metrics || {},
    integrity: m.integrity || {},
  })));
  return header + pairs.join(' ');
}

module.exports = {
  key: 'cef',
  contentType: CONTENT_TYPE,
  events: events,
  summary: summary,
  // exposed for tests
  escapeHeaderField: escapeHeaderField,
  escapeExtensionValue: escapeExtensionValue,
  deriveSeverity: deriveSeverity,
};
