// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Feed Routes (B5m)
//
// The native pull surface for the threat-hunting telemetry, alongside the TAXII
// server. Endpoints:
//
//   GET /domains        what can be queried + the available formats + the
//                       authorization's default format
//   GET /summary        aggregate resource counts + compromise indicators
//   GET /:domain        a domain's events (auth_events / sessions / audit_trail /
//                       integrity), paginated and time-windowed
//
// The output dialect is chosen per request: ?format=json|cef|ocsf|stix, defaulting
// to the authorization's default format. An explicitly-requested unknown format is
// rejected (closed set). Mounted behind the three-factor gate, so
// req.threatHuntingAuth is set; a defensive check refuses to serve otherwise.
// Every access is recorded (authorized with the result count, or rejected_query).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const telemetry = require('../services/threat-hunting-telemetry');
const formats = require('../services/threat-hunting-formats');
const { appendAccessLog } = require('../services/threat-hunting-access-log');

function closeDb(db) { try { db.close(); } catch (_) { /* ignore */ } }
function dbNow(db) {
  try { const r = db.prepare("SELECT datetime('now') AS t").get(); return r && r.t ? r.t : null; }
  catch (_) { return null; }
}

function authDefaultFormat(req) {
  return (req.threatHuntingAuth && req.threatHuntingAuth.defaultFormat) || formats.DEFAULT_FORMAT;
}

// Resolve the output formatter. An explicit unknown format is an error; an absent
// one uses the authorization's default.
function pickFormat(req) {
  const requested = req.query.format;
  if (requested !== undefined && requested !== null && requested !== '') {
    const fm = formats.getFormatter(requested);
    return fm ? { formatter: fm } : { error: 'unknown format: ' + String(requested).slice(0, 32) };
  }
  const def = authDefaultFormat(req);
  return { formatter: formats.getFormatter(def) || formats.getFormatter(formats.DEFAULT_FORMAT) };
}

function writeAccess(db, req, outcome, format, count, querySummary) {
  const a = req.threatHuntingAuth || {};
  try {
    appendAccessLog(db, {
      authorization_id: a.authorizationId || null,
      consumer_type: a.consumerType || null,
      source_ip: a.sourceIp || null,
      cert_fingerprint: a.certFingerprint || null,
      endpoint: a.endpoint || String(req.originalUrl || '').slice(0, 256),
      format: format || null,
      query_summary: querySummary ? String(querySummary).slice(0, 256) : null,
      outcome: outcome,
      result_count: (typeof count === 'number' ? count : null),
    });
  } catch (_) { /* logging must never break the response */ }
}

// Defensive: never serve without the gate having run.
router.use(function (req, res, next) {
  if (!req.threatHuntingAuth) return res.status(401).json({ error: 'threat-hunting authorization required' });
  next();
});

// ── Discovery: what can be queried ───────────────────────────────────────────
router.get('/domains', function (req, res) {
  const db = getDb();
  try {
    writeAccess(db, req, 'authorized', 'json', null, 'domains');
    res.type('application/json; charset=utf-8').json({
      domains: telemetry.listDomains(),
      formats: formats.FORMATS,
      default_format: authDefaultFormat(req),
    });
  } finally { closeDb(db); }
});

// ── Summary ──────────────────────────────────────────────────────────────────
router.get('/summary', function (req, res) {
  const pf = pickFormat(req);
  const db = getDb();
  try {
    if (pf.error) {
      writeAccess(db, req, 'rejected_query', null, null, pf.error);
      return res.status(400).json({ error: pf.error });
    }
    const sum = telemetry.summary(db);
    const body = pf.formatter.summary({
      generated_at: sum.generated_at,
      resource_metrics: sum.resource_metrics,
      integrity: sum.integrity,
    });
    writeAccess(db, req, 'authorized', pf.formatter.key, null, 'summary');
    res.type(pf.formatter.contentType).send(body);
  } finally { closeDb(db); }
});

// ── Domain query ─────────────────────────────────────────────────────────────
router.get('/:domain', function (req, res) {
  const domain = req.params.domain;
  const pf = pickFormat(req);
  const fmtKey = pf.formatter ? pf.formatter.key : null;
  const db = getDb();
  try {
    if (pf.error) {
      writeAccess(db, req, 'rejected_query', null, null, pf.error);
      return res.status(400).json({ error: pf.error });
    }
    if (!telemetry.isDomain(domain)) {
      writeAccess(db, req, 'rejected_query', fmtKey, null, 'unknown domain: ' + String(domain).slice(0, 64));
      return res.status(404).json({ error: 'unknown domain' });
    }
    const result = telemetry.query(db, domain, {
      limit: req.query.limit,
      cursor: req.query.cursor,
      since: req.query.since,
      until: req.query.until,
    });
    if (!result.ok) {
      writeAccess(db, req, 'rejected_query', fmtKey, null, domain + ':' + result.reason);
      return res.status(400).json({ error: result.reason });
    }
    const body = pf.formatter.events({
      domain: result.domain,
      label: result.label,
      generated_at: dbNow(db),
      count: result.count,
      events: result.events,
      has_more: result.has_more,
      next_cursor: result.next_cursor,
    });
    writeAccess(db, req, 'authorized', fmtKey, result.count, domain + ':' + fmtKey);
    res.type(pf.formatter.contentType).send(body);
  } finally { closeDb(db); }
});

module.exports = router;
