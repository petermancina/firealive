// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Geo-Fence Policy & Management Route (B5n)
//
// Admin management of login geo-fencing. Mounted (server/index.js) at
// /api/geo-fence behind the admin JWT and the config-lock chokepoint. The GeoIP
// database upload lives separately at /api/geoip/database (routes/geoip-database).
//
//   GET  /config                 current { enabled, enforceGeoLogin, trustedNetworks }
//   PUT  /config                 update the policy (validates every trusted CIDR)
//   GET  /users                  users + their assigned country (no real names)
//   PUT  /users/:id/country      assign or clear a user's country (2-letter ISO)
//   GET  /exceptions             per-user travel exceptions (with an expired flag)
//   POST /exceptions             add an exception (country, optional future expiry)
//   DELETE /exceptions/:id        remove an exception
//   POST /resolve                admin test: resolve an IP to a country, and (with
//                                a userId) dry-run the geo-fence decision
//   GET  /events                 recent geo audit events (closed event-type list)
//
// The config shape is the B5n trusted-network model { enabled, enforceGeoLogin,
// trustedNetworks: [CIDR] } -- it replaces the obsolete per-client list. Writes
// are audited; the upload route handles the database, this handles policy.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { checkGeoFence, loadGeoConfig } = require('../services/geo-fence');
const geoipService = require('../services/geoip/geoip-service');
const { normalizeIp, classifyIp, parseIp } = require('../services/geoip/ip-utils');

const router = express.Router();

// Geo audit event types surfaced by GET /events (closed list).
const GEO_EVENT_TYPES = [
  'GEO_FENCE_VIOLATION',
  'GEO_FENCE_BLOCKED',
  'GEO_CONFIG_MISCONFIGURED',
  'GEO_DB_UPDATED',
  'GEO_DB_REJECTED',
  'GEO_EXCEPTION_ADDED',
  'GEO_EXCEPTION_REMOVED',
  'GEO_USER_COUNTRY_SET',
  'GEO_FENCE_CONFIG_UPDATED',
];

function isCountryCode(c) {
  return typeof c === 'string' && /^[A-Za-z]{2}$/.test(c.trim());
}

// Validate a trusted-network entry: an exact IP or a CIDR, IPv4 or IPv6.
function isValidCidr(s) {
  if (typeof s !== 'string') return false;
  const c = s.trim();
  if (!c) return false;
  const slash = c.indexOf('/');
  if (slash === -1) return parseIp(c) !== null;
  const net = parseIp(c.slice(0, slash));
  if (!net) return false;
  const bitsRaw = c.slice(slash + 1);
  if (!/^\d{1,3}$/.test(bitsRaw)) return false;
  const bits = Number(bitsRaw);
  const max = net.version === 4 ? 32 : 128;
  return bits >= 0 && bits <= max;
}

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

// ── Config ────────────────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  const db = getDb();
  try {
    return res.json(loadGeoConfig(db));
  } catch (e) {
    return res.status(500).json({ error: 'failed to load geo-fence config' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.put('/config', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const b = req.body;
    const enabled = b.enabled === true;
    const enforceGeoLogin = b.enforceGeoLogin !== false; // default true
    const trustedNetworks = [];
    if (b.trustedNetworks !== undefined) {
      if (!Array.isArray(b.trustedNetworks)) {
        return res.status(400).json({ error: 'trustedNetworks must be an array' });
      }
      for (const c of b.trustedNetworks) {
        if (!isValidCidr(c)) {
          return res.status(400).json({ error: 'invalid CIDR or IP in trustedNetworks: ' + String(c) });
        }
        trustedNetworks.push(String(c).trim());
      }
    }
    const cfg = { enabled: enabled, enforceGeoLogin: enforceGeoLogin, trustedNetworks: trustedNetworks };
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('geo_fence_config', ?)").run(JSON.stringify(cfg));
    auditLog(
      actorOf(req),
      'GEO_FENCE_CONFIG_UPDATED',
      'enabled=' + enabled + ' enforce=' + enforceGeoLogin + ' trusted=' + trustedNetworks.length,
      req.ip
    );
    return res.json({ success: true, config: cfg });
  } catch (e) {
    return res.status(500).json({ error: 'failed to save geo-fence config' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Per-user country assignment ─────────────────────────────────────────────
router.get('/users', (req, res) => {
  const db = getDb();
  try {
    const users = db
      .prepare(
        "SELECT id, username, role, pseudonym, geo_country, active FROM users WHERE role != 'anon_author' ORDER BY username"
      )
      .all();
    return res.json({ users: users });
  } catch (e) {
    return res.status(500).json({ error: 'failed to list users' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.put('/users/:id/country', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const id = req.params.id;
    const raw = req.body.country;
    let country = null;
    if (raw !== null && raw !== undefined && String(raw).trim() !== '') {
      if (!isCountryCode(raw)) {
        return res.status(400).json({ error: 'country must be a 2-letter ISO-3166-1 alpha-2 code, or empty to clear' });
      }
      country = String(raw).trim().toUpperCase();
    }
    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(id);
    if (!user) return res.status(404).json({ error: 'user not found' });
    db.prepare('UPDATE users SET geo_country = ? WHERE id = ?').run(country, id);
    auditLog(actorOf(req), 'GEO_USER_COUNTRY_SET', 'user=' + id + ' country=' + (country || 'cleared'), req.ip);
    return res.json({ success: true, userId: id, country: country });
  } catch (e) {
    return res.status(500).json({ error: 'failed to set user country' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Travel exceptions ────────────────────────────────────────────────────────
router.get('/exceptions', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare(
        'SELECT e.id, e.user_id, e.country, e.reason, e.added_by, e.added_at, e.expires_at, u.username '
          + 'FROM geo_login_exceptions e LEFT JOIN users u ON u.id = e.user_id ORDER BY e.id DESC'
      )
      .all();
    const now = Date.now();
    const out = rows.map((r) => {
      let expired = false;
      if (r.expires_at && String(r.expires_at).trim()) {
        const t = Date.parse(r.expires_at);
        expired = isNaN(t) || t <= now;
      }
      return Object.assign({}, r, { expired: expired });
    });
    return res.json({ exceptions: out });
  } catch (e) {
    return res.status(500).json({ error: 'failed to list exceptions' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.post('/exceptions', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const b = req.body;
    const userId = typeof b.userId === 'string' ? b.userId.trim() : '';
    if (!userId) return res.status(400).json({ error: 'userId is required' });
    if (!isCountryCode(b.country)) {
      return res.status(400).json({ error: 'country must be a 2-letter ISO-3166-1 alpha-2 code' });
    }
    const country = String(b.country).trim().toUpperCase();

    let expiresAt = null;
    if (b.expiresAt !== null && b.expiresAt !== undefined && String(b.expiresAt).trim() !== '') {
      const t = Date.parse(b.expiresAt);
      if (isNaN(t)) return res.status(400).json({ error: 'expiresAt must be a valid date' });
      if (t <= Date.now()) return res.status(400).json({ error: 'expiresAt must be in the future' });
      expiresAt = String(b.expiresAt).trim();
    }
    const reason = typeof b.reason === 'string' ? b.reason.trim().slice(0, 500) : null;

    const user = db.prepare('SELECT id FROM users WHERE id = ?').get(userId);
    if (!user) return res.status(404).json({ error: 'user not found' });

    const actor = actorOf(req);
    const info = db
      .prepare('INSERT INTO geo_login_exceptions (user_id, country, reason, added_by, expires_at) VALUES (?, ?, ?, ?, ?)')
      .run(userId, country, reason, actor, expiresAt);
    auditLog(
      actor,
      'GEO_EXCEPTION_ADDED',
      'user=' + userId + ' country=' + country + (expiresAt ? ' expires=' + expiresAt : ' (no expiry)'),
      req.ip
    );
    return res.json({ success: true, id: info.lastInsertRowid });
  } catch (e) {
    return res.status(500).json({ error: 'failed to add exception' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.delete('/exceptions/:id', (req, res) => {
  const db = getDb();
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'invalid id' });
    const row = db.prepare('SELECT user_id, country FROM geo_login_exceptions WHERE id = ?').get(id);
    if (!row) return res.status(404).json({ error: 'exception not found' });
    db.prepare('DELETE FROM geo_login_exceptions WHERE id = ?').run(id);
    auditLog(actorOf(req), 'GEO_EXCEPTION_REMOVED', 'user=' + row.user_id + ' country=' + row.country, req.ip);
    return res.json({ success: true });
  } catch (e) {
    return res.status(500).json({ error: 'failed to remove exception' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Admin resolve / dry-run test ─────────────────────────────────────────────
router.post('/resolve', requireObjectBody, (req, res) => {
  const db = getDb();
  try {
    const ipRaw = typeof req.body.ip === 'string' ? req.body.ip.trim() : '';
    if (!ipRaw) return res.status(400).json({ error: 'ip is required' });

    const country = geoipService.resolveCountry(ipRaw);
    const out = {
      ip: ipRaw,
      normalized: normalizeIp(ipRaw),
      ipClass: classifyIp(ipRaw),
      country: country || null,
      dbLoaded: geoipService.isLoaded(),
      decision: null,
    };
    const userId = typeof req.body.userId === 'string' ? req.body.userId.trim() : '';
    if (userId) {
      const user = db.prepare('SELECT id, geo_country FROM users WHERE id = ?').get(userId);
      out.decision = user ? checkGeoFence(db, user, ipRaw) : null;
    }
    return res.json(out);
  } catch (e) {
    return res.status(500).json({ error: 'resolve failed' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── Recent geo audit events ──────────────────────────────────────────────────
router.get('/events', (req, res) => {
  const db = getDb();
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
    const placeholders = GEO_EVENT_TYPES.map(() => '?').join(',');
    const rows = db
      .prepare(
        'SELECT id, timestamp, user_id, event_type, detail, ip_address FROM audit_log WHERE event_type IN ('
          + placeholders
          + ') ORDER BY id DESC LIMIT ?'
      )
      .all.apply(null, GEO_EVENT_TYPES.concat([limit]));
    return res.json({ events: rows });
  } catch (e) {
    return res.status(500).json({ error: 'failed to load geo events' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;
