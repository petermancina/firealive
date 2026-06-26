// ===========================================================================
// FIREALIVE -- Vulnerability Scan: Authorization + Access-Logging Integration
//
// The on-prem peer of cloud_vuln (server/routes/cloud-vuln-scan.js). This is an
// INTEGRATION (same family as cloud_vuln, EDR File Inspection, and threat-
// hunting), NOT a scanner. FireAlive does not run scans and does not ingest,
// parse, or store findings -- scan results live in the scanner's own
// application. This route lets an admin AUTHORIZE external on-prem / network
// vulnerability scanners (Nessus, OpenVAS, Qualys, Rapid7, Tenable.io, Nuclei)
// to scan the FireAlive instance itself, and records EVERY scan access in an
// append-only, hash-chained log so the SOC has a tamper-evident record of when
// FireAlive was scanned. Network-layer blocking remains the operator's firewall
// responsibility; this is the application-layer authorization + audit trail.
//
// TWO routers (mounted separately in server/index.js):
//   module.exports        -- admin management router  -> /api/vuln-scan (admin JWT)
//     GET    /config                     -- policy: enabled / allowedScanners / schedule
//     PUT    /config                     -- update the policy
//     GET    /authorizations             -- list (token material never returned)
//     POST   /authorizations             -- create; returns the bearer token ONCE
//     PUT    /authorizations/:id          -- update (name/cidrs/enabled/notes)
//     DELETE /authorizations/:id          -- revoke
//     GET    /access-log                  -- paginated scan-access log
//     GET    /access-log/verify           -- recompute + verify the hash chain
//   module.exports.accessRouter -- scan-access recorder -> /api/vuln-scan-access
//     POST   /                            -- gated by per-authorization bearer
//                                            token + source-IP/CIDR allow-list;
//                                            logs authorized/rejected access.
//                                            NOT behind admin JWT (a scanner /
//                                            scan harness presents the token).
//
// GATE (two factors, by design): the announce endpoint returns only an
// authorize/reject verdict and exposes no data; the security-sensitive surface
// is the tripwire IP exemption (services/vuln-scan-allowlist.js), which is
// IP-keyed by necessity, so a transport factor would harden a no-op surface.
// The rigor is in: a salted-hash bearer token (constant-time compare), a
// per-authorization source-IP/CIDR allow-list, tight CIDR validation, the
// hash-chained tamper-evident log, and LIVE POLICY ENFORCEMENT at three points
// -- mint (an authorization may only be created for a permitted scanner_type),
// the announce gate (a matched authorization whose scanner_type is no longer
// permitted, or with the feature disabled, is rejected), and the tripwire
// allowlist refresh -- so removing a scanner type from policy (or disabling the
// feature) stops authorizing and exempting it without mutating any row.
//
// Token model mirrors cloud_vuln / apikeys: a high-entropy token is generated,
// returned in plaintext ONCE on creation, and only a salted SHA-256 hash is
// stored. Hash chain: this_hash = SHA-256(canonical(entry)).
// ===========================================================================

const router = require('express').Router();
const accessRouter = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

const VALID_SCANNERS = ['nessus', 'openvas', 'qualys', 'rapid7', 'tenable_io', 'nuclei'];
const VALID_SCHEDULES = ['daily', 'weekly', 'monthly', 'manual'];

// -- Helpers ----------------------------------------------------------------

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

// Normalize an IPv4-mapped IPv6 address ("::ffff:1.2.3.4") to plain IPv4.
function normalizeIp(ip) {
  if (typeof ip !== 'string') return '';
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  return m ? m[1] : ip;
}

function ipv4ToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const o = Number(p);
    if (!Number.isInteger(o) || o < 0 || o > 255) return null;
    n = (n * 256) + o;
  }
  return n >>> 0;
}

// Match a source IP against one allow-list entry. IPv4 supports exact and CIDR
// (a.b.c.d/nn). IPv6 supports exact match (full IPv6 CIDR math is intentionally
// out of scope -- operators list explicit IPv6 sources or rely on the firewall).
function ipMatchesEntry(ip, entry) {
  ip = normalizeIp(ip).trim();
  entry = String(entry || '').trim();
  if (!ip || !entry) return false;
  if (entry.indexOf('/') === -1) return ip === normalizeIp(entry);
  const [net, bitsRaw] = entry.split('/');
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(normalizeIp(net));
  if (ipInt === null || netInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) {
    return false; // non-IPv4 CIDR: no match (use exact entries for IPv6)
  }
  if (bits === 0) return true;
  const mask = bits === 32 ? 0xffffffff : (~(0xffffffff >>> bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function ipAllowed(ip, cidrs) {
  if (!Array.isArray(cidrs)) return false;
  return cidrs.some((c) => ipMatchesEntry(ip, c));
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
// Rejects empty lists, oversized entries, and anything outside the IP/CIDR
// character set -- tight validation so the tripwire exemption cannot be widened
// by a malformed or wildcard entry.
function sanitizeCidrs(input) {
  if (!Array.isArray(input)) return null;
  if (input.length === 0 || input.length > 64) return null;
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

function publicAuthorization(row) {
  return {
    id: row.id,
    scanner_type: row.scanner_type,
    display_name: row.display_name,
    allowed_cidrs: parseJsonArray(row.allowed_cidrs),
    enabled: row.enabled === 1,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_scan_at: row.last_scan_at,
    last_scan_source_ip: row.last_scan_source_ip,
    notes: row.notes,
  };
}

// Read the live policy (enabled / allowedScanners / schedule) from team_config.
// Fail-safe: any error or missing/garbled config yields a disabled, empty policy.
function readConfig(db) {
  try {
    const r = db.prepare("SELECT value FROM team_config WHERE key = 'vuln_scan_config'").get();
    if (!r) return { enabled: false, allowedScanners: [], schedule: 'weekly' };
    const cfg = JSON.parse(r.value);
    return {
      enabled: !!(cfg && cfg.enabled === true),
      allowedScanners: (cfg && Array.isArray(cfg.allowedScanners))
        ? cfg.allowedScanners.filter((s) => VALID_SCANNERS.includes(s))
        : [],
      schedule: (cfg && VALID_SCHEDULES.includes(cfg.schedule)) ? cfg.schedule : 'weekly',
    };
  } catch (_) {
    return { enabled: false, allowedScanners: [], schedule: 'weekly' };
  }
}

// Canonical serialization of an access-log entry for the hash chain. Fixed
// field order, NUL-separated; any field change breaks the chain.
function canonicalAccessEntry(e) {
  return [
    e.prev_hash || '',
    e.authorization_id || '',
    e.scanner_type || '',
    e.source_ip || '',
    e.outcome || '',
    e.request_path || '',
    e.user_agent || '',
    e.detail || '',
    e.accessed_at || '',
  ].join('\u0000');
}

// Append one entry to the hash-chained scan-access log. Reads the prior
// this_hash, computes this_hash = SHA-256(canonical), and inserts -- all inside
// a transaction so prev_hash linkage is consistent under concurrency.
function appendAccessLog(db, fields) {
  const tx = db.transaction((f) => {
    const accessedAt = db.prepare("SELECT datetime('now') AS t").get().t;
    const prevRow = db
      .prepare('SELECT this_hash FROM vuln_scan_access_log ORDER BY id DESC LIMIT 1')
      .get();
    const prevHash = prevRow ? prevRow.this_hash : null;
    const entry = {
      prev_hash: prevHash,
      authorization_id: f.authorization_id || null,
      scanner_type: f.scanner_type || null,
      source_ip: f.source_ip,
      outcome: f.outcome,
      request_path: f.request_path || null,
      user_agent: f.user_agent || null,
      detail: f.detail || null,
      accessed_at: accessedAt,
    };
    const thisHash = crypto
      .createHash('sha256')
      .update(canonicalAccessEntry(entry))
      .digest('hex');
    db.prepare(
      'INSERT INTO vuln_scan_access_log ' +
        '(prev_hash, this_hash, authorization_id, scanner_type, source_ip, outcome, request_path, user_agent, detail, accessed_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      entry.prev_hash, thisHash, entry.authorization_id, entry.scanner_type,
      entry.source_ip, entry.outcome, entry.request_path,
      entry.user_agent, entry.detail, entry.accessed_at
    );
    return Object.assign({}, entry, { this_hash: thisHash });
  });
  return tx(fields);
}

// ======================== ADMIN MANAGEMENT ROUTER ==========================
// All endpoints below assume an admin JWT (enforced at mount in server/index.js).

// -- Policy config (the allowed-scanner / schedule policy) -------------------
router.get('/config', (req, res) => {
  const db = getDb();
  try {
    res.json({ config: readConfig(db), validScanners: VALID_SCANNERS, validSchedules: VALID_SCHEDULES });
  } catch (err) {
    logger.error('vuln-scan config get error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to read vuln-scan config' });
  } finally {
    db.close();
  }
});

router.put('/config', (req, res) => {
  const { enabled, allowedScanners, schedule } = req.body || {};
  if (typeof enabled !== 'boolean') {
    return res.status(400).json({ error: 'enabled must be a boolean' });
  }
  if (!Array.isArray(allowedScanners)) {
    return res.status(400).json({ error: 'allowedScanners must be an array' });
  }
  for (const s of allowedScanners) {
    if (!VALID_SCANNERS.includes(s)) {
      return res.status(400).json({ error: 'Invalid scanner in allowedScanners', validScanners: VALID_SCANNERS });
    }
  }
  if (schedule !== undefined && !VALID_SCHEDULES.includes(schedule)) {
    return res.status(400).json({ error: 'Invalid schedule', validSchedules: VALID_SCHEDULES });
  }
  const uniqScanners = Array.from(new Set(allowedScanners));
  const config = {
    enabled,
    allowedScanners: uniqScanners,
    schedule: VALID_SCHEDULES.includes(schedule) ? schedule : 'weekly',
    updatedAt: new Date().toISOString(),
  };
  const db = getDb();
  try {
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('vuln_scan_config', ?, ?)")
      .run(JSON.stringify(config), req.user.id);
    auditLog(req.user.id, 'VULN_SCAN_CONFIG_UPDATED', `enabled=${enabled} scanners=${uniqScanners.join(',')} schedule=${config.schedule}`, req.ip);
    res.json({ config: readConfig(db) });
  } catch (err) {
    logger.error('vuln-scan config put error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to save vuln-scan config' });
  } finally {
    db.close();
  }
});

// -- List authorizations -----------------------------------------------------
router.get('/authorizations', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare('SELECT * FROM vuln_scan_scanner_authorizations ORDER BY created_at DESC')
      .all();
    res.json({ authorizations: rows.map(publicAuthorization), validScanners: VALID_SCANNERS });
  } catch (err) {
    logger.error('vuln-scan list authorizations error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to list scanner authorizations' });
  } finally {
    db.close();
  }
});

// -- Create authorization (returns the bearer token ONCE) --------------------
router.post('/authorizations', (req, res) => {
  const { scanner_type, display_name, allowed_cidrs, notes } = req.body || {};
  if (!VALID_SCANNERS.includes(scanner_type)) {
    return res.status(400).json({ error: 'Invalid scanner_type', validScanners: VALID_SCANNERS });
  }
  if (typeof display_name !== 'string' || !display_name.trim() || display_name.length > 128) {
    return res.status(400).json({ error: 'display_name required (1-128 chars)' });
  }
  const cidrs = sanitizeCidrs(allowed_cidrs);
  if (cidrs === null) {
    return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array (max 64) of IP / CIDR strings' });
  }
  if (notes != null && (typeof notes !== 'string' || notes.length > 1000)) {
    return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
  }

  const db = getDb();
  try {
    // Live policy (mint-time): an authorization may be created only for a
    // scanner type the current policy permits.
    const cfg = readConfig(db);
    if (!cfg.allowedScanners.includes(scanner_type)) {
      return res.status(409).json({
        error: 'scanner_type is not in the current allowedScanners policy; add it under Config first',
        allowedScanners: cfg.allowedScanners,
      });
    }

    const id = crypto.randomBytes(16).toString('hex');
    const token = `vss-${crypto.randomBytes(32).toString('hex')}`;
    const salt = crypto.randomBytes(16).toString('hex');
    const tokenHash = hashToken(token, salt);
    db.prepare(
      'INSERT INTO vuln_scan_scanner_authorizations ' +
        '(id, scanner_type, display_name, allowed_cidrs, token_hash, token_salt, enabled, created_by, notes) ' +
        'VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)'
    ).run(
      id, scanner_type, display_name.trim(), JSON.stringify(cidrs),
      tokenHash, salt, req.user.id, notes != null ? notes : null
    );
    auditLog(req.user.id, 'VULN_SCAN_AUTH_CREATED', `scanner=${scanner_type} name="${display_name.trim()}" cidrs=${cidrs.length}`, req.ip);
    const row = db.prepare('SELECT * FROM vuln_scan_scanner_authorizations WHERE id = ?').get(id);
    // token returned ONCE -- never retrievable again
    res.status(201).json({ authorization: publicAuthorization(row), token });
  } catch (err) {
    logger.error('vuln-scan create authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to create scanner authorization' });
  } finally {
    db.close();
  }
});

// -- Update authorization ----------------------------------------------------
router.put('/authorizations/:id', (req, res) => {
  const { display_name, allowed_cidrs, enabled, notes } = req.body || {};
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM vuln_scan_scanner_authorizations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Authorization not found' });

    const next = {
      display_name: row.display_name,
      allowed_cidrs: row.allowed_cidrs,
      enabled: row.enabled,
      notes: row.notes,
    };
    if (display_name !== undefined) {
      if (typeof display_name !== 'string' || !display_name.trim() || display_name.length > 128) {
        return res.status(400).json({ error: 'display_name must be 1-128 chars' });
      }
      next.display_name = display_name.trim();
    }
    if (allowed_cidrs !== undefined) {
      const cidrs = sanitizeCidrs(allowed_cidrs);
      if (cidrs === null) return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array (max 64) of IP / CIDR strings' });
      next.allowed_cidrs = JSON.stringify(cidrs);
    }
    if (enabled !== undefined) next.enabled = enabled ? 1 : 0;
    if (notes !== undefined) {
      if (notes != null && (typeof notes !== 'string' || notes.length > 1000)) return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
      next.notes = notes != null ? notes : null;
    }

    db.prepare(
      "UPDATE vuln_scan_scanner_authorizations SET display_name = ?, allowed_cidrs = ?, enabled = ?, notes = ?, updated_at = datetime('now') WHERE id = ?"
    ).run(next.display_name, next.allowed_cidrs, next.enabled, next.notes, req.params.id);
    auditLog(req.user.id, 'VULN_SCAN_AUTH_UPDATED', `id=${req.params.id} enabled=${next.enabled}`, req.ip);
    const updated = db.prepare('SELECT * FROM vuln_scan_scanner_authorizations WHERE id = ?').get(req.params.id);
    res.json({ authorization: publicAuthorization(updated) });
  } catch (err) {
    logger.error('vuln-scan update authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to update scanner authorization' });
  } finally {
    db.close();
  }
});

// -- Revoke authorization ----------------------------------------------------
router.delete('/authorizations/:id', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare('SELECT id, scanner_type, display_name FROM vuln_scan_scanner_authorizations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Authorization not found' });
    db.prepare('DELETE FROM vuln_scan_scanner_authorizations WHERE id = ?').run(req.params.id);
    auditLog(req.user.id, 'VULN_SCAN_AUTH_REVOKED', `id=${req.params.id} scanner=${row.scanner_type} name="${row.display_name}"`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logger.error('vuln-scan revoke authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to revoke scanner authorization' });
  } finally {
    db.close();
  }
});

// -- Scan-access log (paginated) ---------------------------------------------
router.get('/access-log', (req, res) => {
  const db = getDb();
  try {
    let limit = parseInt(req.query.limit, 10);
    if (!Number.isInteger(limit) || limit < 1) limit = 50;
    if (limit > 200) limit = 200;
    let offset = parseInt(req.query.offset, 10);
    if (!Number.isInteger(offset) || offset < 0) offset = 0;

    const where = [];
    const args = [];
    if (req.query.outcome) { where.push('outcome = ?'); args.push(req.query.outcome); }
    if (req.query.scanner_type) { where.push('scanner_type = ?'); args.push(req.query.scanner_type); }
    const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';

    const total = db.prepare('SELECT COUNT(*) AS c FROM vuln_scan_access_log' + whereSql).get(...args).c;
    const rows = db
      .prepare('SELECT * FROM vuln_scan_access_log' + whereSql + ' ORDER BY id DESC LIMIT ? OFFSET ?')
      .all(...args, limit, offset);
    res.json({ entries: rows, total, limit, offset });
  } catch (err) {
    logger.error('vuln-scan access-log error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to read scan-access log' });
  } finally {
    db.close();
  }
});

// -- Verify the hash chain ---------------------------------------------------
router.get('/access-log/verify', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare('SELECT id, prev_hash, this_hash, authorization_id, scanner_type, source_ip, outcome, request_path, user_agent, detail, accessed_at FROM vuln_scan_access_log ORDER BY id ASC')
      .all();
    let prevHash = null;
    for (const row of rows) {
      if ((row.prev_hash || null) !== (prevHash || null)) {
        auditLog(req.user.id, 'VULN_SCAN_ACCESS_LOG_VERIFIED', `intact=false brokenAt=${row.id}`, req.ip);
        return res.json({ intact: false, count: rows.length, brokenAt: row.id, reason: 'prev_hash linkage mismatch' });
      }
      const recomputed = crypto.createHash('sha256').update(canonicalAccessEntry(row)).digest('hex');
      if (recomputed !== row.this_hash) {
        auditLog(req.user.id, 'VULN_SCAN_ACCESS_LOG_VERIFIED', `intact=false brokenAt=${row.id}`, req.ip);
        return res.json({ intact: false, count: rows.length, brokenAt: row.id, reason: 'this_hash mismatch' });
      }
      prevHash = row.this_hash;
    }
    auditLog(req.user.id, 'VULN_SCAN_ACCESS_LOG_VERIFIED', `intact=true count=${rows.length}`, req.ip);
    res.json({ intact: true, count: rows.length });
  } catch (err) {
    logger.error('vuln-scan verify chain error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to verify scan-access log' });
  } finally {
    db.close();
  }
});

// ======================== SCAN-ACCESS RECORDER =============================
// Mounted at /api/vuln-scan-access WITHOUT an admin JWT -- a registered scanner
// (or the operator's scan harness) presents its bearer token. Every call is
// logged (authorized or rejected) to the hash-chained access log. Two factors
// (token + source IP) plus the live policy + master-enabled gate.
accessRouter.post('/', (req, res) => {
  const sourceIp = normalizeIp(req.ip || '');
  const userAgent = (req.get && req.get('user-agent')) ? String(req.get('user-agent')).slice(0, 256) : null;
  const body = req.body || {};
  const requestPath = typeof body.request_path === 'string' ? body.request_path.slice(0, 256) : null;

  // Extract bearer token: Authorization: Bearer <token> or X-Scan-Token header.
  let token = null;
  const authz = req.get && req.get('authorization');
  if (authz && /^Bearer\s+/i.test(authz)) token = authz.replace(/^Bearer\s+/i, '').trim();
  if (!token && req.get && req.get('x-scan-token')) token = String(req.get('x-scan-token')).trim();

  const db = getDb();
  try {
    const log = (outcome, fields) => appendAccessLog(db, {
      authorization_id: fields.authorization_id || null,
      scanner_type: fields.scanner_type || null,
      source_ip: sourceIp,
      outcome,
      request_path: requestPath,
      user_agent: userAgent,
      detail: fields.detail || null,
    });

    if (!token || !/^vss-[0-9a-f]{64}$/.test(token)) {
      log('rejected_token', { detail: 'missing or malformed token' });
      return res.status(401).json({ error: 'Scan authorization token required' });
    }

    // Match the authorization by constant-time token-hash comparison across rows.
    const candidates = db.prepare('SELECT * FROM vuln_scan_scanner_authorizations').all();
    let matched = null;
    for (const row of candidates) {
      if (safeEqualHex(hashToken(token, row.token_salt), row.token_hash)) { matched = row; break; }
    }
    if (!matched) {
      log('rejected_unknown', { detail: 'token did not match any authorization' });
      return res.status(401).json({ error: 'Scan authorization token not recognized' });
    }
    if (matched.enabled !== 1) {
      log('rejected_disabled', { authorization_id: matched.id, scanner_type: matched.scanner_type, detail: 'authorization disabled' });
      return res.status(403).json({ error: 'Scan authorization is disabled' });
    }

    // Live policy + master gate: the feature must be enabled and the matched
    // scanner_type must still be permitted by the current policy.
    const cfg = readConfig(db);
    if (!cfg.enabled) {
      log('rejected_disabled', { authorization_id: matched.id, scanner_type: matched.scanner_type, detail: 'vulnerability scan feature disabled' });
      return res.status(403).json({ error: 'Vulnerability scanning is disabled' });
    }
    if (!cfg.allowedScanners.includes(matched.scanner_type)) {
      log('rejected_disabled', { authorization_id: matched.id, scanner_type: matched.scanner_type, detail: 'scanner_type not permitted by current policy' });
      return res.status(403).json({ error: 'This scanner type is not currently permitted by policy' });
    }

    const cidrs = parseJsonArray(matched.allowed_cidrs);
    if (!ipAllowed(sourceIp, cidrs)) {
      log('rejected_ip', { authorization_id: matched.id, scanner_type: matched.scanner_type, detail: `source ${sourceIp} not in allow-list` });
      return res.status(403).json({ error: 'Source IP not in this authorization\'s allow-list' });
    }

    // Authorized.
    log('authorized', { authorization_id: matched.id, scanner_type: matched.scanner_type });
    db.prepare("UPDATE vuln_scan_scanner_authorizations SET last_scan_at = datetime('now'), last_scan_source_ip = ? WHERE id = ?")
      .run(sourceIp, matched.id);
    res.json({ ok: true, authorized: true, scanner_type: matched.scanner_type });
  } catch (err) {
    logger.error('vuln-scan access recorder error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to record scan access' });
  } finally {
    db.close();
  }
});

router.accessRouter = accessRouter;
module.exports = router;
