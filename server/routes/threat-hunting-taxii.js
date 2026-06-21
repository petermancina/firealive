// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting TAXII 2.1 Server (B5m)
//
// Serves the STIX 2.1 telemetry over TAXII 2.1: Discovery, API Root, Collections,
// Objects, and Manifest. One collection per telemetry domain (auth_events,
// sessions, audit_trail, integrity), each with a deterministic UUID id. The
// objects endpoint runs the bounded telemetry query, serializes via the STIX
// formatter, and returns the STIX objects inside a TAXII envelope; the manifest
// endpoint returns metadata for the observed-data objects.
//
// This router is mounted BEHIND the three-factor gate, so req.threatHuntingAuth
// is always set; a defensive router-level check refuses to serve if it is not.
// Every access is recorded to the append-only access log (authorized with the
// result count, or rejected_query). Collections are read-only (can_write false).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const telemetry = require('../services/threat-hunting-telemetry');
const stix = require('../services/threat-hunting-formats/stix');
const { appendAccessLog } = require('../services/threat-hunting-access-log');

const TAXII_TYPE = 'application/taxii+json;version=2.1';
const STIX_MEDIA = 'application/stix+json;version=2.1';
const API_ROOT = 'feed';
const MAX_CONTENT_LENGTH = 104857600; // 100 MiB

function collectionId(domain) {
  return stix.uuidv5(stix.STIX_SCO_NS, 'threat-hunting-collection:' + domain);
}

const COLLECTIONS = telemetry.listDomains().map(function (d) {
  return {
    domain: d.key,
    id: collectionId(d.key),
    title: d.label,
    description: 'FireAlive threat-hunting telemetry: ' + d.label,
  };
});

// Resolve a path id (collection UUID or the readable domain key) to a domain.
const BY_ID = {};
for (const c of COLLECTIONS) { BY_ID[c.id] = c.domain; BY_ID[c.domain] = c.domain; }
function resolveDomain(param) {
  return Object.prototype.hasOwnProperty.call(BY_ID, param) ? BY_ID[param] : null;
}
function collectionFor(domain) {
  for (const c of COLLECTIONS) if (c.domain === domain) return c;
  return null;
}

function closeDb(db) { try { db.close(); } catch (_) { /* ignore */ } }
function dbNow(db) {
  try { const r = db.prepare("SELECT datetime('now') AS t").get(); return r && r.t ? r.t : null; }
  catch (_) { return null; }
}

function absBase(req) { return req.protocol + '://' + req.get('host'); }
function apiRootUrl(req) { return absBase(req) + req.baseUrl + '/' + API_ROOT + '/'; }

function taxiiError(res, status, title, description) {
  return res.status(status).type(TAXII_TYPE).json({ title: title, description: description, http_status: status });
}
function notApiRoot(req) { return req.params.root !== API_ROOT; }

function writeAccess(db, req, outcome, count, querySummary) {
  const a = req.threatHuntingAuth || {};
  try {
    appendAccessLog(db, {
      authorization_id: a.authorizationId || null,
      consumer_type: a.consumerType || null,
      source_ip: a.sourceIp || null,
      cert_fingerprint: a.certFingerprint || null,
      endpoint: a.endpoint || String(req.originalUrl || '').slice(0, 256),
      format: 'stix',
      query_summary: querySummary ? String(querySummary).slice(0, 256) : null,
      outcome: outcome,
      result_count: (typeof count === 'number' ? count : null),
    });
  } catch (_) { /* logging must never break the response */ }
}

// Defensive: never serve without the gate having run.
router.use(function (req, res, next) {
  if (!req.threatHuntingAuth) return taxiiError(res, 401, 'Unauthorized', 'threat-hunting authorization required');
  next();
});

// ── Discovery ────────────────────────────────────────────────────────────────
router.get('/', function (req, res) {
  const db = getDb();
  try {
    writeAccess(db, req, 'authorized', null, 'taxii:discovery');
    res.type(TAXII_TYPE).json({
      title: 'FireAlive Threat-Hunting TAXII Server',
      description: 'Read-only STIX 2.1 telemetry from a FireAlive instance for authorized threat-hunting consumers.',
      contact: 'security',
      default: apiRootUrl(req),
      api_roots: [apiRootUrl(req)],
    });
  } finally { closeDb(db); }
});

// ── API Root ─────────────────────────────────────────────────────────────────
router.get('/:root', function (req, res) {
  if (notApiRoot(req)) return taxiiError(res, 404, 'Not Found', 'unknown API root');
  const db = getDb();
  try {
    writeAccess(db, req, 'authorized', null, 'taxii:api-root');
    res.type(TAXII_TYPE).json({
      title: 'FireAlive Threat-Hunting',
      description: 'Telemetry from a FireAlive instance for authorized threat-hunting consumers.',
      versions: [TAXII_TYPE],
      max_content_length: MAX_CONTENT_LENGTH,
    });
  } finally { closeDb(db); }
});

// ── Collections list ─────────────────────────────────────────────────────────
router.get('/:root/collections', function (req, res) {
  if (notApiRoot(req)) return taxiiError(res, 404, 'Not Found', 'unknown API root');
  const db = getDb();
  try {
    writeAccess(db, req, 'authorized', null, 'taxii:collections');
    res.type(TAXII_TYPE).json({
      collections: COLLECTIONS.map(function (c) {
        return {
          id: c.id,
          title: c.title,
          description: c.description,
          can_read: true,
          can_write: false,
          media_types: [STIX_MEDIA],
        };
      }),
    });
  } finally { closeDb(db); }
});

// ── Single collection ────────────────────────────────────────────────────────
router.get('/:root/collections/:cid', function (req, res) {
  if (notApiRoot(req)) return taxiiError(res, 404, 'Not Found', 'unknown API root');
  const domain = resolveDomain(req.params.cid);
  if (!domain) return taxiiError(res, 404, 'Not Found', 'unknown collection');
  const c = collectionFor(domain);
  const db = getDb();
  try {
    writeAccess(db, req, 'authorized', null, 'taxii:collection:' + domain);
    res.type(TAXII_TYPE).json({
      id: c.id,
      title: c.title,
      description: c.description,
      can_read: true,
      can_write: false,
      media_types: [STIX_MEDIA],
    });
  } finally { closeDb(db); }
});

// ── Objects ──────────────────────────────────────────────────────────────────
router.get('/:root/collections/:cid/objects', function (req, res) {
  if (notApiRoot(req)) return taxiiError(res, 404, 'Not Found', 'unknown API root');
  const domain = resolveDomain(req.params.cid);
  if (!domain) return taxiiError(res, 404, 'Not Found', 'unknown collection');
  const db = getDb();
  try {
    const result = telemetry.query(db, domain, {
      limit: req.query.limit,
      cursor: req.query.next,
      since: req.query.added_after,
    });
    if (!result.ok) {
      writeAccess(db, req, 'rejected_query', null, 'objects:' + domain + ':' + result.reason);
      return taxiiError(res, 400, 'Bad Request', result.reason);
    }
    const bundle = JSON.parse(stix.events({
      domain: domain,
      events: result.events,
      generated_at: dbNow(db),
    }));
    writeAccess(db, req, 'authorized', result.count, 'objects:' + domain);
    const envelope = { more: result.has_more === true, objects: bundle.objects };
    if (result.next_cursor) envelope.next = result.next_cursor;
    res.type(TAXII_TYPE).json(envelope);
  } finally { closeDb(db); }
});

// ── Manifest ─────────────────────────────────────────────────────────────────
router.get('/:root/collections/:cid/manifest', function (req, res) {
  if (notApiRoot(req)) return taxiiError(res, 404, 'Not Found', 'unknown API root');
  const domain = resolveDomain(req.params.cid);
  if (!domain) return taxiiError(res, 404, 'Not Found', 'unknown collection');
  const db = getDb();
  try {
    const result = telemetry.query(db, domain, {
      limit: req.query.limit,
      cursor: req.query.next,
      since: req.query.added_after,
    });
    if (!result.ok) {
      writeAccess(db, req, 'rejected_query', null, 'manifest:' + domain + ':' + result.reason);
      return taxiiError(res, 400, 'Bad Request', result.reason);
    }
    const bundle = JSON.parse(stix.events({
      domain: domain,
      events: result.events,
      generated_at: dbNow(db),
    }));
    const manifestObjects = bundle.objects
      .filter(function (o) { return o.type === 'observed-data'; })
      .map(function (o) {
        return { id: o.id, date_added: o.created, version: o.modified, media_type: STIX_MEDIA };
      });
    writeAccess(db, req, 'authorized', result.count, 'manifest:' + domain);
    const envelope = { more: result.has_more === true, objects: manifestObjects };
    if (result.next_cursor) envelope.next = result.next_cursor;
    res.type(TAXII_TYPE).json(envelope);
  } finally { closeDb(db); }
});

module.exports = router;
