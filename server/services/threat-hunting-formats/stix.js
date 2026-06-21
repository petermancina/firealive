// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Output Formatter: STIX 2.1 (B5m)
//
// Serializes the ALREADY-PROJECTED model as a STIX 2.1 bundle, which the TAXII
// endpoints serve. Each event becomes an observed-data SDO plus the cyber-
// observables it references: an ipv4-addr / ipv6-addr SCO for the source IP and a
// user-account SCO whose account_login is the pseudonym (never a raw user). SCO
// ids are deterministic UUIDv5 over the id-contributing properties, so the same
// IP or actor across events is one SCO in the bundle. All objects are attributed
// to a stable FireAlive identity. Fields without a STIX home ride on the
// observed-data as x_firealive_* custom properties, so nothing is lost.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const CONTENT_TYPE = 'application/stix+json;version=2.1';
// STIX 2.1 namespace for deterministic cyber-observable (SCO) UUIDv5 ids.
const STIX_SCO_NS = '00abedb4-aa42-466c-9c01-fed23315a9b7';
const IDENTITY_CREATED = '2025-01-01T00:00:00.000Z';

const TIME_FIELD = {
  auth_events: 'timestamp',
  sessions: 'created_at',
  audit_trail: 'timestamp',
  integrity: 'received_at',
};

function uuidv4() {
  const b = crypto.randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
}

function uuidv5(namespace, name) {
  const nsBytes = Buffer.from(String(namespace).replace(/-/g, ''), 'hex');
  const digest = crypto.createHash('sha1').update(Buffer.concat([nsBytes, Buffer.from(String(name), 'utf8')])).digest();
  const b = Buffer.from(digest.slice(0, 16));
  b[6] = (b[6] & 0x0f) | 0x50;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = b.toString('hex');
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
}

const IDENTITY_ID = 'identity--' + uuidv5(STIX_SCO_NS, 'firealive-threat-hunting-identity');

function toEpochMs(ts) {
  if (typeof ts !== 'string' || !ts) return null;
  let s = ts.trim();
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s)) s = s.replace(' ', 'T') + 'Z';
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

function toStixTime(ts, fallbackMs) {
  const ms = toEpochMs(ts);
  const at = ms !== null ? ms : (typeof fallbackMs === 'number' ? fallbackMs : Date.now());
  return new Date(at).toISOString();
}

function isIpv4(s) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(s); }
function isIpv6(s) { return typeof s === 'string' && s.indexOf(':') !== -1; }

function ipv4Sco(ip) {
  const name = JSON.stringify({ value: ip });
  return { type: 'ipv4-addr', spec_version: '2.1', id: 'ipv4-addr--' + uuidv5(STIX_SCO_NS, name), value: ip };
}
function ipv6Sco(ip) {
  const name = JSON.stringify({ value: ip });
  return { type: 'ipv6-addr', spec_version: '2.1', id: 'ipv6-addr--' + uuidv5(STIX_SCO_NS, name), value: ip };
}
function userAccountSco(login) {
  const name = JSON.stringify({ account_login: login });
  return { type: 'user-account', spec_version: '2.1', id: 'user-account--' + uuidv5(STIX_SCO_NS, name), account_login: login };
}

function identityObject() {
  return {
    type: 'identity', spec_version: '2.1', id: IDENTITY_ID,
    created: IDENTITY_CREATED, modified: IDENTITY_CREATED,
    name: 'FireAlive Threat-Hunting Feed', identity_class: 'system',
  };
}

// Build the SCOs + observed-data SDO for one projected event.
function buildEventObjects(domain, event, fallbackMs) {
  const e = event || {};
  const timeField = TIME_FIELD[domain] || 'timestamp';
  const scos = [];
  const refs = [];

  if (e.source_ip != null && e.source_ip !== '') {
    const ip = String(e.source_ip);
    let sco = null;
    if (isIpv4(ip)) sco = ipv4Sco(ip);
    else if (isIpv6(ip)) sco = ipv6Sco(ip);
    if (sco) { scos.push(sco); refs.push(sco.id); }
  }
  if (e.actor != null && e.actor !== '') {
    const ua = userAccountSco(String(e.actor));
    scos.push(ua); refs.push(ua.id);
  }
  // observed-data requires at least one object reference.
  if (refs.length === 0) {
    const anon = userAccountSco('anonymous');
    scos.push(anon); refs.push(anon.id);
  }

  const t = toStixTime(e[timeField], fallbackMs);
  const extra = {};
  for (const k of Object.keys(e)) {
    if (k === 'actor' || k === 'source_ip' || k === timeField) continue;
    extra[k] = e[k];
  }

  const observedData = {
    type: 'observed-data', spec_version: '2.1',
    id: 'observed-data--' + uuidv4(),
    created: t, modified: t,
    created_by_ref: IDENTITY_ID,
    first_observed: t, last_observed: t, number_observed: 1,
    object_refs: refs,
    x_firealive_domain: String(domain),
    x_firealive_event: extra,
  };
  return { scos: scos, observedData: observedData };
}

function events(model) {
  const m = model || {};
  const rows = Array.isArray(m.events) ? m.events : [];
  const domain = m.domain || 'threat-hunting';
  const fallbackMs = toEpochMs(m.generated_at);

  const objects = [identityObject()];
  const seen = {};
  for (const e of rows) {
    const built = buildEventObjects(domain, e, fallbackMs);
    for (const sco of built.scos) {
      if (!seen[sco.id]) { seen[sco.id] = true; objects.push(sco); }
    }
    objects.push(built.observedData);
  }
  return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuidv4(), objects: objects });
}

function summary(model) {
  const m = model || {};
  const t = toStixTime(m.generated_at, Date.now());
  const note = {
    type: 'note', spec_version: '2.1',
    id: 'note--' + uuidv4(),
    created: t, modified: t,
    created_by_ref: IDENTITY_ID,
    abstract: 'FireAlive threat-hunting summary',
    content: JSON.stringify({
      resource_metrics: m.resource_metrics || {},
      integrity: m.integrity || {},
    }),
    object_refs: [IDENTITY_ID],
  };
  return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuidv4(), objects: [identityObject(), note] });
}

module.exports = {
  key: 'stix',
  contentType: CONTENT_TYPE,
  events: events,
  summary: summary,
  // exposed for tests
  buildEventObjects: buildEventObjects,
  uuidv5: uuidv5,
  uuidv4: uuidv4,
  IDENTITY_ID: IDENTITY_ID,
  STIX_SCO_NS: STIX_SCO_NS,
};
