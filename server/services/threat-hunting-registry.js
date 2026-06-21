// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Authorization Registry (B5m)
//
// CRUD + lookup for threat_hunting_consumer_authorizations: the registry of
// external threat-hunting consumers (EDR / XDR / ATP / NGAV / MSP) authorized to
// pull FireAlive's own security telemetry. Each authorization binds three
// independent factors the feed gate requires together:
//   - a FireAlive-CA-issued consumer client cert (fingerprint stored here),
//   - a bearer token (only the salted SHA-256 hash is stored), and
//   - a CIDR allow-list.
// The cert/key/token are returned ONCE at creation and are never retrievable
// again. consumer_type is a closed set (xdr/atp/ngav/msp) enforced here and by
// the table CHECK; there is no open-ended type. Every function takes the caller's
// db handle; the caller owns the connection lifecycle.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const ca = require('./ca');

const TOKEN_PREFIX = 'th-';
const CONSUMER_TYPES = ['xdr', 'atp', 'ngav', 'msp'];
const FORMATS = ['json', 'cef', 'ocsf', 'stix'];

function hashToken(token, salt) {
  return crypto.createHash('sha256').update(salt + ':' + token).digest('hex');
}

// Constant-time compare of two hex strings of equal length.
function safeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  } catch (_) {
    return false;
  }
}

function parseJsonArray(val) {
  try {
    const a = JSON.parse(val);
    return Array.isArray(a) ? a : [];
  } catch (_) {
    return [];
  }
}

// Validate an allow-list array: non-empty strings, each a plausible IP or CIDR.
function sanitizeCidrs(input) {
  if (!Array.isArray(input)) return null;
  const out = [];
  for (const raw of input) {
    if (typeof raw !== 'string') return null;
    const s = raw.trim();
    if (!s || s.length > 64) return null;
    if (!/^[0-9a-fA-F:.\/]+$/.test(s)) return null;
    out.push(s);
  }
  return out;
}

// Public projection: never includes token_hash / token_salt. The cert
// fingerprint is a public identifier (not a secret) and is surfaced so an admin
// can confirm which cert is bound.
function publicAuthorization(row) {
  return {
    id: row.id,
    consumer_type: row.consumer_type,
    display_name: row.display_name,
    allowed_cidrs: parseJsonArray(row.allowed_cidrs),
    cert_fingerprint: row.cert_fingerprint,
    default_format: row.default_format,
    enabled: row.enabled === 1,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_access_at: row.last_access_at,
    last_access_source_ip: row.last_access_source_ip,
    revoked_at: row.revoked_at,
    notes: row.notes,
  };
}

function normalizeNotes(notes) {
  return notes != null ? String(notes).slice(0, 1024) : null;
}

// Create a new consumer authorization: issue the client cert, mint the bearer
// token, and persist the binding atomically. Returns the secrets (cert, key,
// token) ONCE; afterward only the cert fingerprint and the salted token hash
// remain, so the secrets cannot be retrieved again.
function createAuthorization(db, opts) {
  const o = opts || {};
  const consumerType = String(o.consumerType || '').trim();
  if (CONSUMER_TYPES.indexOf(consumerType) === -1) {
    throw new Error('consumer_type must be one of: ' + CONSUMER_TYPES.join(', '));
  }
  const displayName = String(o.displayName || '').trim();
  if (!displayName) throw new Error('display_name is required');
  const cidrs = sanitizeCidrs(o.allowedCidrs);
  if (cidrs === null) throw new Error('allowed_cidrs must be an array of IP or CIDR strings');
  if (!cidrs.length) throw new Error('allowed_cidrs must contain at least one entry');
  let defaultFormat = String(o.defaultFormat || 'json').trim();
  if (FORMATS.indexOf(defaultFormat) === -1) defaultFormat = 'json';

  const id = crypto.randomBytes(16).toString('hex');
  const token = TOKEN_PREFIX + crypto.randomBytes(32).toString('hex');
  const salt = crypto.randomBytes(16).toString('hex');
  const tokenHash = hashToken(token, salt);
  const notes = normalizeNotes(o.notes);

  const cert = db.transaction(() => {
    const c = ca.issueThreatHuntingConsumerCert(db, { displayName: displayName });
    db.prepare(
      'INSERT INTO threat_hunting_consumer_authorizations ' +
        '(id, consumer_type, display_name, allowed_cidrs, cert_fingerprint, cert_serial, token_hash, token_salt, default_format, created_by, notes) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(id, consumerType, displayName, JSON.stringify(cidrs), c.fingerprint, c.serial, tokenHash, salt, defaultFormat, o.createdBy || null, notes);
    return c;
  })();

  const row = db.prepare('SELECT * FROM threat_hunting_consumer_authorizations WHERE id = ?').get(id);
  return {
    authorization: publicAuthorization(row),
    // returned exactly once; never stored or retrievable again:
    token: token,
    certPem: cert.certPem,
    keyPem: cert.keyPem,
    caCertPem: cert.caCertPem,
  };
}

function listAuthorizations(db) {
  const rows = db
    .prepare('SELECT * FROM threat_hunting_consumer_authorizations ORDER BY created_at DESC')
    .all();
  return rows.map(publicAuthorization);
}

function getAuthorization(db, id) {
  const row = db.prepare('SELECT * FROM threat_hunting_consumer_authorizations WHERE id = ?').get(id);
  return row ? publicAuthorization(row) : null;
}

// Update only the mutable policy fields. consumer_type, the bound cert, and the
// token are immutable -- to change those, revoke and re-create.
function updateAuthorization(db, id, patch) {
  const row = db.prepare('SELECT * FROM threat_hunting_consumer_authorizations WHERE id = ?').get(id);
  if (!row) return null;
  const p = patch || {};
  const next = {
    display_name: row.display_name,
    allowed_cidrs: row.allowed_cidrs,
    default_format: row.default_format,
    enabled: row.enabled,
    notes: row.notes,
  };
  if (p.displayName !== undefined) {
    const dn = String(p.displayName).trim();
    if (!dn) throw new Error('display_name cannot be empty');
    next.display_name = dn;
  }
  if (p.allowedCidrs !== undefined) {
    const cidrs = sanitizeCidrs(p.allowedCidrs);
    if (cidrs === null || !cidrs.length) {
      throw new Error('allowed_cidrs must be a non-empty array of IP or CIDR strings');
    }
    next.allowed_cidrs = JSON.stringify(cidrs);
  }
  if (p.defaultFormat !== undefined) {
    const f = String(p.defaultFormat).trim();
    if (FORMATS.indexOf(f) === -1) throw new Error('default_format must be one of: ' + FORMATS.join(', '));
    next.default_format = f;
  }
  if (p.enabled !== undefined) next.enabled = p.enabled ? 1 : 0;
  if (p.notes !== undefined) next.notes = normalizeNotes(p.notes);

  db.prepare(
    "UPDATE threat_hunting_consumer_authorizations SET display_name = ?, allowed_cidrs = ?, default_format = ?, enabled = ?, notes = ?, updated_at = datetime('now') WHERE id = ?"
  ).run(next.display_name, next.allowed_cidrs, next.default_format, next.enabled, next.notes, id);
  return getAuthorization(db, id);
}

// Revoke: disable the row, stamp revoked_at, and revoke the bound cert through
// the CA's local revocation list so a presented-but-revoked cert is rejected.
function revokeAuthorization(db, id) {
  const row = db.prepare('SELECT * FROM threat_hunting_consumer_authorizations WHERE id = ?').get(id);
  if (!row) return { revoked: false, reason: 'not_found' };
  db.prepare(
    "UPDATE threat_hunting_consumer_authorizations SET enabled = 0, revoked_at = datetime('now'), updated_at = datetime('now') WHERE id = ?"
  ).run(id);
  let certRevoked = false;
  try {
    const r = ca.revokeCert(db, { serial: row.cert_serial, reason: 'threat-hunting authorization revoked' });
    certRevoked = !!(r && r.revoked);
  } catch (_) { /* the row is already disabled; cert revocation is best-effort */ }
  return { revoked: true, certRevoked: certRevoked };
}

// Gate lookup: returns the FULL row (including enabled / revoked_at) so the gate
// can distinguish a disabled authorization from a clean match.
function findByCertFingerprint(db, fingerprint) {
  if (typeof fingerprint !== 'string' || !fingerprint) return null;
  return (
    db
      .prepare('SELECT * FROM threat_hunting_consumer_authorizations WHERE cert_fingerprint = ?')
      .get(fingerprint) || null
  );
}

// Constant-time bearer-token check against a specific authorization row.
function verifyToken(row, token) {
  if (!row || typeof token !== 'string' || !token) return false;
  return safeEqualHex(hashToken(token, row.token_salt), row.token_hash);
}

// Stamp the last successful access (called by the gate on an authorized pull).
function touchAccess(db, id, sourceIp) {
  try {
    db.prepare(
      "UPDATE threat_hunting_consumer_authorizations SET last_access_at = datetime('now'), last_access_source_ip = ? WHERE id = ?"
    ).run(typeof sourceIp === 'string' ? sourceIp.slice(0, 64) : null, id);
  } catch (_) { /* non-fatal */ }
}

module.exports = {
  createAuthorization,
  listAuthorizations,
  getAuthorization,
  updateAuthorization,
  revokeAuthorization,
  findByCertFingerprint,
  verifyToken,
  touchAccess,
  publicAuthorization,
  hashToken,
  safeEqualHex,
  CONSUMER_TYPES,
  FORMATS,
};
