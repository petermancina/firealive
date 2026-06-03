// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — IAM Offboarding Routes
// GET  /api/iam/check-absence   — return analysts whose IAM check is overdue
// POST /api/iam/confirm-status  — confirm analyst as active, OR mark offboarded
// ═══════════════════════════════════════════════════════════════════════════════
//
// These routes support periodic recertification of analyst accounts. The team
// lead receives a list of analysts whose last_iam_check is older than the
// configured interval (or who have never been checked) and either confirms
// each one as still active (resetting the timer) or marks them offboarded.
// Offboarded analysts have active=0 and offboarded_at set; they no longer
// appear in routing or peer-share queues.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const ca = require('../services/ca');
const { encryptConfig, decryptConfig } = require('../services/encryption');
const { runOffboardingDetection } = require('../services/account-review');

// ── List analysts due for IAM recertification ────────────────────────────────
router.get('/check-absence', (req, res) => {
  try {
    const db = getDb();
    // Read configured interval (hours) from team_config; default 168 (1 week)
    const cfgRow = db.prepare("SELECT value FROM team_config WHERE key = 'iam_config'").get();
    const intervalHours = (() => {
      if (!cfgRow) return 168;
      try {
        const cfg = JSON.parse(cfgRow.value);
        const h = Number(cfg.intervalHours);
        return Number.isFinite(h) && h > 0 ? h : 168;
      } catch { return 168; }
    })();
    const cutoff = new Date(Date.now() - intervalHours * 3600000).toISOString();
    const users = db.prepare(`
      SELECT id, pseudonym, last_iam_check
      FROM users
      WHERE role = 'analyst' AND active = 1
    `).all();
    db.close();
    const overdue = users.filter(u => !u.last_iam_check || u.last_iam_check < cutoff);
    auditLog(req.user?.id, 'IAM_CHECK_ABSENCE', `total=${users.length} overdue=${overdue.length}`, req.ip);
    res.json({
      checked: true,
      total: users.length,
      intervalHours,
      needsReview: overdue.map(u => ({ id: u.id, pseudonym: u.pseudonym, lastCheck: u.last_iam_check })),
    });
  } catch (err) {
    logger.error('IAM check-absence error', { error: err.message });
    res.status(500).json({ error: 'Failed to check IAM absence' });
  }
});

// ── Confirm analyst status (active or offboard) ──────────────────────────────
router.post('/confirm-status', (req, res) => {
  const { analystId, action } = req.body || {};
  if (!analystId || typeof analystId !== 'string') {
    return res.status(400).json({ error: 'analystId is required' });
  }
  if (action !== 'active' && action !== 'offboard') {
    return res.status(400).json({ error: 'action must be "active" or "offboard"' });
  }
  try {
    const db = getDb();
    const user = db.prepare("SELECT id, role FROM users WHERE id = ?").get(analystId);
    if (!user) { db.close(); return res.status(404).json({ error: 'Analyst not found' }); }
    if (user.role !== 'analyst') { db.close(); return res.status(400).json({ error: 'User is not an analyst' }); }
    const now = new Date().toISOString();
    if (action === 'offboard') {
      db.prepare("UPDATE users SET active = 0, offboarded_at = ? WHERE id = ?").run(now, analystId);
      auditLog(req.user?.id, 'IAM_OFFBOARD', `analyst=${analystId}`, req.ip);
    } else {
      db.prepare("UPDATE users SET last_iam_check = ? WHERE id = ?").run(now, analystId);
      auditLog(req.user?.id, 'IAM_CONFIRMED_ACTIVE', `analyst=${analystId}`, req.ip);
    }
    db.close();
    res.json({ success: true, analystId, action, at: now });
  } catch (err) {
    logger.error('IAM confirm-status error', { error: err.message });
    res.status(500).json({ error: 'Failed to update analyst status' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — IAM administration (lead/admin, on /api/iam)
//
// Admin-facing controls for the SOC-grade auth stack: built-in CA status, issued-
// certificate inventory + revocation + the revocation list, LDAP/AD directory
// configuration and connectivity test, and a read-only view of the
// auth-enforcement posture (passwordless-only; not operator-configurable).
//
// getDb() opens a fresh better-sqlite3 connection per call, so every route closes
// it in a finally block.
// ═══════════════════════════════════════════════════════════════════════════════

// ── GET /api/iam/ca — built-in CA status ────────────────────────────────────
router.get('/ca', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare(
      'SELECT subject, key_algo, serial_counter, created_at FROM ca_authority WHERE is_active = 1'
    ).get();
    if (!row) return res.json({ initialized: false });
    const caCertPem = ca.getCaCertPem(db);
    return res.json({
      initialized: true,
      subject: row.subject,
      keyAlgo: row.key_algo,
      serial: row.serial_counter,
      createdAt: row.created_at,
      fingerprint: caCertPem ? ca.fingerprint256(caCertPem) : null,
    });
  } catch (err) {
    logger.error('IAM GET /ca failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── GET /api/iam/certs — issued certificate inventory ───────────────────────
router.get('/certs', (req, res) => {
  const db = getDb();
  try {
    const status = req.query && req.query.status;
    const cols = 'serial, subject, user_id, external_id, status, issued_at, expires_at, fingerprint256, revoked_at, revoked_reason';
    let rows;
    if (status && ['active', 'revoked', 'expired'].includes(status)) {
      rows = db.prepare(`SELECT ${cols} FROM issued_certs WHERE status = ? ORDER BY issued_at DESC, rowid DESC`).all(status);
    } else {
      rows = db.prepare(`SELECT ${cols} FROM issued_certs ORDER BY issued_at DESC, rowid DESC`).all();
    }
    return res.json({ certs: rows });
  } catch (err) {
    logger.error('IAM GET /certs failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/iam/certs/revoke — revoke a certificate ───────────────────────
router.post('/certs/revoke', (req, res) => {
  const db = getDb();
  try {
    const { serial, reason } = req.body || {};
    if (!serial) return res.status(400).json({ error: 'serial required' });
    const cert = db.prepare('SELECT status FROM issued_certs WHERE serial = ?').get(serial);
    if (!cert) return res.status(404).json({ error: 'certificate not found' });
    if (cert.status === 'revoked') return res.status(409).json({ error: 'certificate already revoked' });
    ca.revokeCert(db, { serial, reason: reason || 'unspecified' });
    auditLog(req.user.id, 'CERT_REVOKED', `serial=${serial} reason=${reason || 'unspecified'}`, req.ip);
    return res.json({ revoked: true, serial });
  } catch (err) {
    logger.error('IAM revoke failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── GET /api/iam/crl — signed revocation list (no OCSP) ──────────────────────
router.get('/crl', (req, res) => {
  const db = getDb();
  try {
    return res.json(ca.buildRevocationList(db));
  } catch (err) {
    logger.error('IAM CRL failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── GET /api/iam/ldap-config — current LDAP config (bind password masked) ────
router.get('/ldap-config', (req, res) => {
  const db = getDb();
  try {
    const row = db.prepare("SELECT config_encrypted, status FROM integration_config WHERE integration_type = 'iam_ldap'").get();
    if (!row || !row.config_encrypted) return res.json({ configured: false });
    let cfg = {};
    try { cfg = decryptConfig(row.config_encrypted) || {}; } catch (_) { cfg = {}; }
    return res.json({
      configured: true,
      status: row.status,
      server: cfg.server || '',
      port: cfg.port || 636,
      baseDn: cfg.baseDn || '',
      bindDn: cfg.bindDn || '',
      useTLS: cfg.useTLS !== false,
      userFilter: cfg.userFilter || '',
      groupFilter: cfg.groupFilter || '',
      hasBindPassword: !!cfg.bindPassword,
    });
  } catch (err) {
    logger.error('IAM GET /ldap-config failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/iam/ldap-config — save LDAP config (encrypted at rest) ─────────
// The bind password is preserved if not re-supplied, so editing other fields
// does not require re-entering it.
router.post('/ldap-config', (req, res) => {
  const db = getDb();
  try {
    const b = req.body || {};
    if (!b.server || !b.baseDn || !b.bindDn) {
      return res.status(400).json({ error: 'server, baseDn, and bindDn are required' });
    }
    let bindPassword = b.bindPassword;
    if (!bindPassword) {
      const ex = db.prepare("SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap'").get();
      if (ex && ex.config_encrypted) {
        try { bindPassword = (decryptConfig(ex.config_encrypted) || {}).bindPassword; } catch (_) { /* none */ }
      }
    }
    const cfg = {
      server: b.server,
      port: b.port || 636,
      baseDn: b.baseDn,
      bindDn: b.bindDn,
      bindPassword: bindPassword || '',
      useTLS: b.useTLS !== false,
      userFilter: b.userFilter || undefined,
      groupFilter: b.groupFilter || undefined,
      groupMapping: b.groupMapping || undefined,
    };
    const enc = encryptConfig(cfg);
    const existing = db.prepare("SELECT id FROM integration_config WHERE integration_type = 'iam_ldap'").get();
    if (existing) {
      db.prepare("UPDATE integration_config SET config_encrypted = ?, status = 'configured', updated_at = datetime('now') WHERE id = ?").run(enc, existing.id);
    } else {
      db.prepare("INSERT INTO integration_config (integration_type, config_encrypted, status, created_by) VALUES ('iam_ldap', ?, 'configured', ?)").run(enc, req.user.id);
    }
    auditLog(req.user.id, 'IAM_LDAP_CONFIGURED', `server=${b.server}`, req.ip);
    return res.json({ saved: true });
  } catch (err) {
    logger.error('IAM POST /ldap-config failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/iam/ldap-config/test — test bind/connectivity ─────────────────
// Tests the posted config (falling back to the saved bind password if omitted),
// or the saved config when no fields are posted.
router.post('/ldap-config/test', async (req, res) => {
  const db = getDb();
  try {
    const b = req.body || {};
    let cfg;
    if (b.server && b.bindDn) {
      let bindPassword = b.bindPassword;
      if (!bindPassword) {
        const ex = db.prepare("SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap'").get();
        if (ex && ex.config_encrypted) {
          try { bindPassword = (decryptConfig(ex.config_encrypted) || {}).bindPassword; } catch (_) { /* none */ }
        }
      }
      cfg = { server: b.server, port: b.port || 636, baseDn: b.baseDn, bindDn: b.bindDn, bindPassword, useTLS: b.useTLS !== false };
    } else {
      const ex = db.prepare("SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap'").get();
      if (!ex || !ex.config_encrypted) return res.status(400).json({ error: 'no LDAP config to test' });
      cfg = decryptConfig(ex.config_encrypted);
    }
    const { LdapClient } = require('../integrations/ldap');
    const result = await new LdapClient(cfg).testConnection();
    auditLog(req.user.id, 'IAM_LDAP_TESTED', `success=${!!result.success}`, req.ip);
    return res.json(result);
  } catch (err) {
    logger.error('IAM LDAP test failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── GET /api/iam/enforcement — current auth posture (read-only) ─────────────
// Authentication is passwordless-only (mutual-TLS client cert or FIDO2/WebAuthn
// passkey) and is a structural invariant — there is no allow_password mode and
// no operator setter, so this reports the fixed posture for display/audit.
router.get('/enforcement', (req, res) => {
  return res.json({ authEnforcement: 'passwordless', configurable: false });
});


// ── GET /api/iam/offboarding-candidates — list detected candidates ──────────
router.get('/offboarding-candidates', (req, res) => {
  const db = getDb();
  try {
    const status = req.query && req.query.status;
    const base = `
      SELECT oc.id, oc.user_id, u.username, u.role, u.external_id,
             oc.source, oc.detail, oc.detected_at, oc.status, oc.resolved_at
      FROM offboarding_candidates oc
      LEFT JOIN users u ON u.id = oc.user_id
    `;
    let rows;
    if (status && ['pending', 'confirmed_active', 'offboarded'].includes(status)) {
      rows = db.prepare(base + ' WHERE oc.status = ? ORDER BY oc.detected_at DESC, oc.rowid DESC').all(status);
    } else {
      rows = db.prepare(base + ' ORDER BY oc.detected_at DESC, oc.rowid DESC').all();
    }
    return res.json({ candidates: rows });
  } catch (err) {
    logger.error('IAM offboarding list failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

// ── POST /api/iam/offboarding-candidates/scan — run detection on demand ──────
// runOffboardingDetection manages its own DB connection.
router.post('/offboarding-candidates/scan', async (req, res) => {
  try {
    const result = await runOffboardingDetection();
    auditLog(req.user.id, 'OFFBOARDING_SCAN_TRIGGERED', `scanned=${result.scanned} new=${result.newCandidates}`, req.ip);
    return res.json(result);
  } catch (err) {
    logger.error('IAM offboarding scan failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  }
});

// ── POST /api/iam/offboarding-candidates/resolve — confirm-active or offboard ─
// Resolving a still-present user clears their IAM-check watermark. Offboarding
// deactivates the account AND revokes the user's active certificates as
// defense-in-depth — account deactivation already blocks every login path, but
// revocation invalidates the certificates at the PKI/CRL level too.
router.post('/offboarding-candidates/resolve', (req, res) => {
  const db = getDb();
  try {
    const { id, action } = req.body || {};
    if (!id) return res.status(400).json({ error: 'id required' });
    if (action !== 'confirm_active' && action !== 'offboard') {
      return res.status(400).json({ error: "action must be 'confirm_active' or 'offboard'" });
    }
    const cand = db.prepare('SELECT * FROM offboarding_candidates WHERE id = ?').get(id);
    if (!cand) return res.status(404).json({ error: 'candidate not found' });
    if (cand.status !== 'pending') return res.status(409).json({ error: 'candidate already resolved' });

    if (action === 'confirm_active') {
      db.prepare("UPDATE offboarding_candidates SET status = 'confirmed_active', resolved_by = ?, resolved_at = datetime('now') WHERE id = ?").run(req.user.id, id);
      db.prepare("UPDATE users SET last_iam_check = datetime('now') WHERE id = ?").run(cand.user_id);
      auditLog(req.user.id, 'OFFBOARDING_CONFIRMED_ACTIVE', `user=${cand.user_id} candidate=${id}`, req.ip);
      return res.json({ resolved: true, action, candidateId: id });
    }

    // offboard — revoke active certificates, then deactivate the account
    let revoked = 0;
    const certs = db.prepare("SELECT serial FROM issued_certs WHERE user_id = ? AND status = 'active'").all(cand.user_id);
    for (const c of certs) {
      try { ca.revokeCert(db, { serial: c.serial, reason: 'offboarded' }); revoked++; } catch (_) { /* continue revoking the rest */ }
    }
    db.prepare("UPDATE users SET active = 0, offboarded_at = datetime('now') WHERE id = ?").run(cand.user_id);
    db.prepare("UPDATE offboarding_candidates SET status = 'offboarded', resolved_by = ?, resolved_at = datetime('now') WHERE id = ?").run(req.user.id, id);
    auditLog(req.user.id, 'OFFBOARDING_EXECUTED', `user=${cand.user_id} candidate=${id} certs_revoked=${revoked}`, req.ip);
    return res.json({ resolved: true, action, candidateId: id, certsRevoked: revoked });
  } catch (err) {
    logger.error('IAM offboarding resolve failed', { error: err.message });
    return res.status(500).json({ error: 'internal error' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;
