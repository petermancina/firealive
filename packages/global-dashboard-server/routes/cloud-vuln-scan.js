// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Cloud Vulnerability Scan: Authorization + Access-Logging
// Integration (GD-server's own duplicated config; mirrors server/routes/cloud-vuln-scan.js)
//
// This is an INTEGRATION (same family as EDR File Inspection and the non-cloud
// Vulnerability Scan tab), NOT a scanner. FireAlive does not run scans and does
// not ingest, parse, or store findings — scan results live in the cloud
// scanner's own application. This route lets an admin AUTHORIZE external
// cloud-posture / IaC scanners (ScoutSuite, Prowler, Pacu, CloudBrute, Checkov)
// to scan the GD-server's cloud deployment, and records EVERY scan access in an
// append-only, hash-chained log so the SOC has a tamper-evident record of when
// FireAlive was scanned. Network-layer blocking remains the operator's firewall
// responsibility; this is the application-layer authorization + audit trail.
//
// TWO routers (mounted separately in server/index.js):
//   module.exports        — admin management router  → /api/cloud-vuln  (ciso/vp JWT)
//     GET    /authorizations            — list (token material never returned)
//     POST   /authorizations            — create; returns the bearer token ONCE
//     PUT    /authorizations/:id         — update (name/cidrs/scope/enabled/notes)
//     DELETE /authorizations/:id         — revoke
//     GET    /access-log                 — paginated scan-access log
//     GET    /access-log/verify          — recompute + verify the hash chain
//   module.exports.accessRouter — scan-access recorder → /api/cloud-vuln-access
//     POST   /                           — gated by per-authorization bearer
//                                          token + source-IP/CIDR allow-list;
//                                          logs authorized/rejected access.
//                                          NOT behind admin JWT (a scanner /
//                                          scan harness presents the token).
//
// Token model mirrors apikeys.js: a high-entropy token is generated, returned
// in plaintext ONCE on creation, and only a salted SHA-256 hash is stored.
// Verification is constant-time. Hash chain mirrors forensic_export_chain:
// this_hash = SHA-256(prev_hash || canonical(entry) || accessed_at).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const accessRouter = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db-init');

// GD-server has no shared audit/logger modules (endpoints write audit_log
// inline and log via console). Local shims keep the handler bodies identical
// to the main-server route.
function audit(db, userId, eventType, detail, ip) {
  try {
    db.prepare('INSERT INTO audit_log (user_id, event_type, detail, ip, severity) VALUES (?, ?, ?, ?, ?)')
      .run(userId || null, eventType, detail || null, ip || null, 'info');
  } catch (_) { /* never let audit failure break the request */ }
}
function logErr(msg, obj) { console.error('[gd-cloud-vuln]', msg, obj && obj.error ? obj.error : ''); }

const VALID_SCANNERS = ['scoutsuite', 'prowler', 'pacu', 'cloudbrute', 'checkov'];
const VALID_COMPONENTS = ['mc', 'ac', 'arc', 'main_server', 'gd_server'];

// ── Helpers ──────────────────────────────────────────────────────────────────

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
// out of scope — operators list explicit IPv6 sources or rely on the firewall).
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

function sanitizeComponents(input) {
  if (!Array.isArray(input)) return null;
  const out = [];
  for (const c of input) {
    if (!VALID_COMPONENTS.includes(c)) return null;
    if (!out.includes(c)) out.push(c);
  }
  return out;
}

function publicAuthorization(row) {
  return {
    id: row.id,
    scanner_type: row.scanner_type,
    display_name: row.display_name,
    allowed_cidrs: parseJsonArray(row.allowed_cidrs),
    scope_components: parseJsonArray(row.scope_components),
    enabled: row.enabled === 1,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_scan_at: row.last_scan_at,
    last_scan_source_ip: row.last_scan_source_ip,
    notes: row.notes,
  };
}

// Canonical serialization of an access-log entry for the hash chain. Fixed
// field order, NUL-separated; any field change breaks the chain.
function canonicalAccessEntry(e) {
  return [
    e.prev_hash || '',
    e.authorization_id || '',
    e.scanner_type || '',
    e.source_ip || '',
    e.component || '',
    e.outcome || '',
    e.request_path || '',
    e.user_agent || '',
    e.detail || '',
    e.accessed_at || '',
  ].join('\u0000');
}

// Append one entry to the hash-chained scan-access log. Reads the prior
// this_hash, computes this_hash = SHA-256(prev_hash || canonical || accessed_at),
// and inserts — all inside a transaction so prev_hash linkage is consistent.
function appendAccessLog(db, fields) {
  const tx = db.transaction((f) => {
    const accessedAt = db.prepare("SELECT datetime('now') AS t").get().t;
    const prevRow = db
      .prepare('SELECT this_hash FROM cloud_vuln_scan_access_log ORDER BY id DESC LIMIT 1')
      .get();
    const prevHash = prevRow ? prevRow.this_hash : null;
    const entry = {
      prev_hash: prevHash,
      authorization_id: f.authorization_id || null,
      scanner_type: f.scanner_type || null,
      source_ip: f.source_ip,
      component: f.component,
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
      'INSERT INTO cloud_vuln_scan_access_log ' +
        '(prev_hash, this_hash, authorization_id, scanner_type, source_ip, component, outcome, request_path, user_agent, detail, accessed_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      entry.prev_hash, thisHash, entry.authorization_id, entry.scanner_type,
      entry.source_ip, entry.component, entry.outcome, entry.request_path,
      entry.user_agent, entry.detail, entry.accessed_at
    );
    return { ...entry, this_hash: thisHash };
  });
  return tx(fields);
}

// ════════════════════════════ ADMIN MANAGEMENT ROUTER ═══════════════════════
// All endpoints below assume an admin JWT (enforced at mount in server/index.js).

// ── List authorizations ──────────────────────────────────────────────────────
router.get('/authorizations', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare('SELECT * FROM cloud_vuln_scanner_authorizations ORDER BY created_at DESC')
      .all();
    res.json({ authorizations: rows.map(publicAuthorization), validScanners: VALID_SCANNERS, validComponents: VALID_COMPONENTS });
  } catch (err) {
    logErr('cloud-vuln list authorizations error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to list scanner authorizations' });
  } finally {
    db.close();
  }
});

// ── Create authorization (returns the bearer token ONCE) ──────────────────────
router.post('/authorizations', (req, res) => {
  const { scanner_type, display_name, allowed_cidrs, scope_components, notes } = req.body || {};
  if (!VALID_SCANNERS.includes(scanner_type)) {
    return res.status(400).json({ error: 'Invalid scanner_type', validScanners: VALID_SCANNERS });
  }
  if (typeof display_name !== 'string' || !display_name.trim() || display_name.length > 128) {
    return res.status(400).json({ error: 'display_name required (1-128 chars)' });
  }
  const cidrs = sanitizeCidrs(allowed_cidrs);
  if (cidrs === null || cidrs.length === 0) {
    return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array of IP / CIDR strings' });
  }
  const scope = sanitizeComponents(scope_components);
  if (scope === null || scope.length === 0) {
    return res.status(400).json({ error: 'scope_components must be a non-empty subset of: ' + VALID_COMPONENTS.join(', ') });
  }
  if (notes != null && (typeof notes !== 'string' || notes.length > 1000)) {
    return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
  }

  const db = getDb();
  try {
    const id = crypto.randomBytes(16).toString('hex');
    const token = `cvs-${crypto.randomBytes(32).toString('hex')}`;
    const salt = crypto.randomBytes(16).toString('hex');
    const tokenHash = hashToken(token, salt);
    db.prepare(
      'INSERT INTO cloud_vuln_scanner_authorizations ' +
        '(id, scanner_type, display_name, allowed_cidrs, scope_components, token_hash, token_salt, enabled, created_by, notes) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)'
    ).run(
      id, scanner_type, display_name.trim(), JSON.stringify(cidrs), JSON.stringify(scope),
      tokenHash, salt, req.user.id, notes != null ? notes : null
    );
    audit(db, req.user.id, 'CLOUD_VULN_AUTH_CREATED', `scanner=${scanner_type} name="${display_name.trim()}" cidrs=${cidrs.length} scope=${scope.join('+')}`, req.ip);
    const row = db.prepare('SELECT * FROM cloud_vuln_scanner_authorizations WHERE id = ?').get(id);
    // token returned ONCE — never retrievable again
    res.status(201).json({ authorization: publicAuthorization(row), token });
  } catch (err) {
    logErr('cloud-vuln create authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to create scanner authorization' });
  } finally {
    db.close();
  }
});

// ── Update authorization ──────────────────────────────────────────────────────
router.put('/authorizations/:id', (req, res) => {
  const { display_name, allowed_cidrs, scope_components, enabled, notes } = req.body || {};
  const db = getDb();
  try {
    const row = db.prepare('SELECT * FROM cloud_vuln_scanner_authorizations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Authorization not found' });

    const next = {
      display_name: row.display_name,
      allowed_cidrs: row.allowed_cidrs,
      scope_components: row.scope_components,
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
      if (cidrs === null || cidrs.length === 0) return res.status(400).json({ error: 'allowed_cidrs must be a non-empty array of IP / CIDR strings' });
      next.allowed_cidrs = JSON.stringify(cidrs);
    }
    if (scope_components !== undefined) {
      const scope = sanitizeComponents(scope_components);
      if (scope === null || scope.length === 0) return res.status(400).json({ error: 'scope_components must be a non-empty subset of: ' + VALID_COMPONENTS.join(', ') });
      next.scope_components = JSON.stringify(scope);
    }
    if (enabled !== undefined) next.enabled = enabled ? 1 : 0;
    if (notes !== undefined) {
      if (notes != null && (typeof notes !== 'string' || notes.length > 1000)) return res.status(400).json({ error: 'notes must be a string up to 1000 chars' });
      next.notes = notes != null ? notes : null;
    }

    db.prepare(
      "UPDATE cloud_vuln_scanner_authorizations SET display_name = ?, allowed_cidrs = ?, scope_components = ?, enabled = ?, notes = ?, updated_at = datetime('now') WHERE id = ?"
    ).run(next.display_name, next.allowed_cidrs, next.scope_components, next.enabled, next.notes, req.params.id);
    audit(db, req.user.id, 'CLOUD_VULN_AUTH_UPDATED', `id=${req.params.id} enabled=${next.enabled}`, req.ip);
    const updated = db.prepare('SELECT * FROM cloud_vuln_scanner_authorizations WHERE id = ?').get(req.params.id);
    res.json({ authorization: publicAuthorization(updated) });
  } catch (err) {
    logErr('cloud-vuln update authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to update scanner authorization' });
  } finally {
    db.close();
  }
});

// ── Revoke authorization ──────────────────────────────────────────────────────
router.delete('/authorizations/:id', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare('SELECT id, scanner_type, display_name FROM cloud_vuln_scanner_authorizations WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Authorization not found' });
    db.prepare('DELETE FROM cloud_vuln_scanner_authorizations WHERE id = ?').run(req.params.id);
    audit(db, req.user.id, 'CLOUD_VULN_AUTH_REVOKED', `id=${req.params.id} scanner=${row.scanner_type} name="${row.display_name}"`, req.ip);
    res.json({ ok: true });
  } catch (err) {
    logErr('cloud-vuln revoke authorization error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to revoke scanner authorization' });
  } finally {
    db.close();
  }
});

// ── Scan-access log (paginated) ───────────────────────────────────────────────
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
    if (req.query.component) { where.push('component = ?'); args.push(req.query.component); }
    const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';

    const total = db.prepare('SELECT COUNT(*) AS c FROM cloud_vuln_scan_access_log' + whereSql).get(...args).c;
    const rows = db
      .prepare('SELECT * FROM cloud_vuln_scan_access_log' + whereSql + ' ORDER BY id DESC LIMIT ? OFFSET ?')
      .all(...args, limit, offset);
    res.json({ entries: rows, total, limit, offset });
  } catch (err) {
    logErr('cloud-vuln access-log error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to read scan-access log' });
  } finally {
    db.close();
  }
});

// ── Verify the hash chain ─────────────────────────────────────────────────────
router.get('/access-log/verify', (req, res) => {
  const db = getDb();
  try {
    const rows = db
      .prepare('SELECT id, prev_hash, this_hash, authorization_id, scanner_type, source_ip, component, outcome, request_path, user_agent, detail, accessed_at FROM cloud_vuln_scan_access_log ORDER BY id ASC')
      .all();
    let prevHash = null;
    for (const row of rows) {
      if ((row.prev_hash || null) !== (prevHash || null)) {
        audit(db, req.user.id, 'CLOUD_VULN_ACCESS_LOG_VERIFIED', `intact=false brokenAt=${row.id}`, req.ip);
        return res.json({ intact: false, count: rows.length, brokenAt: row.id, reason: 'prev_hash linkage mismatch' });
      }
      const recomputed = crypto.createHash('sha256').update(canonicalAccessEntry(row)).digest('hex');
      if (recomputed !== row.this_hash) {
        audit(db, req.user.id, 'CLOUD_VULN_ACCESS_LOG_VERIFIED', `intact=false brokenAt=${row.id}`, req.ip);
        return res.json({ intact: false, count: rows.length, brokenAt: row.id, reason: 'this_hash mismatch' });
      }
      prevHash = row.this_hash;
    }
    audit(db, req.user.id, 'CLOUD_VULN_ACCESS_LOG_VERIFIED', `intact=true count=${rows.length}`, req.ip);
    res.json({ intact: true, count: rows.length });
  } catch (err) {
    logErr('cloud-vuln verify chain error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to verify scan-access log' });
  } finally {
    db.close();
  }
});

// ════════════════════════════ SCAN-ACCESS RECORDER ══════════════════════════
// Mounted at /api/cloud-vuln-access WITHOUT an admin JWT — a registered scanner
// (or the operator's scan harness) presents its bearer token. Every call is
// logged (authorized or rejected) to the hash-chained access log.
accessRouter.post('/', (req, res) => {
  const sourceIp = normalizeIp(req.ip || '');
  const userAgent = (req.get && req.get('user-agent')) ? String(req.get('user-agent')).slice(0, 256) : null;
  const body = req.body || {};
  const component = VALID_COMPONENTS.includes(body.component) ? body.component : 'gd_server';
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
      component,
      outcome,
      request_path: requestPath,
      user_agent: userAgent,
      detail: fields.detail || null,
    });

    if (!token || !/^cvs-[0-9a-f]{64}$/.test(token)) {
      log('rejected_token', { detail: 'missing or malformed token' });
      return res.status(401).json({ error: 'Scan authorization token required' });
    }

    // Find the matching authorization by constant-time token-hash comparison
    // across enabled rows. (Disabled rows are excluded from the match set.)
    const candidates = db.prepare('SELECT * FROM cloud_vuln_scanner_authorizations').all();
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
    const cidrs = parseJsonArray(matched.allowed_cidrs);
    if (!ipAllowed(sourceIp, cidrs)) {
      log('rejected_ip', { authorization_id: matched.id, scanner_type: matched.scanner_type, detail: `source ${sourceIp} not in allow-list` });
      return res.status(403).json({ error: 'Source IP not in this authorization\'s allow-list' });
    }

    // Authorized.
    log('authorized', { authorization_id: matched.id, scanner_type: matched.scanner_type });
    db.prepare("UPDATE cloud_vuln_scanner_authorizations SET last_scan_at = datetime('now'), last_scan_source_ip = ? WHERE id = ?")
      .run(sourceIp, matched.id);
    res.json({ ok: true, authorized: true, scanner_type: matched.scanner_type, component });
  } catch (err) {
    logErr('cloud-vuln access recorder error', { error: err.message, stack: err.stack });
    res.status(500).json({ error: 'Failed to record scan access' });
  } finally {
    db.close();
  }
});

router.accessRouter = accessRouter;
module.exports = router;
