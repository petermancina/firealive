// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance, Monitoring & Forensics Routes
// GET  /api/compliance/report/:framework  — generate compliance report
// GET  /api/compliance/frameworks         — list available frameworks
// GET  /api/monitoring/metrics            — current CPU/mem/db metrics
// GET  /api/monitoring/health-detail      — detailed system health
// GET  /api/retention/config              — get retention policy
// PUT  /api/retention/config              — update retention policy
// POST /api/retention/purge               — manual purge
// GET  /api/audit/export-syslog           — export in syslog RFC 5424 format
// GET  /api/audit/export-forensics        — forensics-tool-compatible export
// POST /api/users/provision               — create user (requires lead MFA approval)
// GET  /api/users/pending                 — list pending user approvals
// POST /api/users/:id/approve             — approve pending user
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');
const { generateComplianceReport, FRAMEWORKS, signLogBatch, toSyslog, getSeverity, SEVERITY_LABELS } = require('../services/compliance');
const { runRetentionPurge, getRetentionConfig, DEFAULT_RETENTION } = require('../services/retention');
const { runtimeMonitor } = require('../services/runtime-monitor');

// ── Compliance Reports ───────────────────────────────────────────────────────
router.get('/compliance/report/:framework', (req, res) => {
  const fw = req.params.framework.toLowerCase();
  if (!FRAMEWORKS[fw]) {
    return res.status(400).json({ error: 'Unknown framework', available: Object.keys(FRAMEWORKS) });
  }

  try {
    const report = generateComplianceReport(fw);
    auditLog(req.user.id, 'COMPLIANCE_REPORT', `framework=${fw} pass=${report.summary.passed}/${report.summary.total}`, req.ip);
    res.json(report);
  } catch (err) {
    logger.error('Compliance report error', { error: err.message });
    res.status(500).json({ error: 'Failed to generate compliance report' });
  }
});

router.get('/compliance/frameworks', (req, res) => {
  res.json({
    frameworks: Object.entries(FRAMEWORKS).map(([id, fw]) => ({
      id, name: fw.name, controlCount: fw.controls.length, note: fw.note || null,
    })),
  });
});

// ── Runtime Metrics ──────────────────────────────────────────────────────────
router.get('/monitoring/metrics', (req, res) => {
  res.json({ metrics: runtimeMonitor.getMetrics(), timestamp: new Date().toISOString() });
});

router.get('/monitoring/health-detail', (req, res) => {
  try {
    const db = getDb();
    const userCount = db.prepare("SELECT COUNT(*) AS c FROM users").get();
    const auditCount = db.prepare("SELECT COUNT(*) AS c FROM audit_log").get();
    const integrations = db.prepare("SELECT integration_type, status FROM integration_config").all();
    const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
    const panicMode = db.prepare("SELECT value FROM team_config WHERE key = 'panic_mode'").get();
    db.close();

    res.json({
      runtime: runtimeMonitor.getMetrics(),
      app: {
        version: '0.0.20',
        fuse: parseInt(fuse?.value, 10),
        panicMode: panicMode?.value === '"active"',
        users: userCount.c,
        auditEvents: auditCount.c,
        integrations: integrations.map(i => ({ type: i.integration_type, status: i.status })),
      },
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    logger.error('Health detail error', { error: err.message });
    res.status(500).json({ error: 'Failed to get health detail' });
  }
});

// ── Retention Config ─────────────────────────────────────────────────────────
router.get('/retention/config', (req, res) => {
  res.json({ config: getRetentionConfig(), defaults: DEFAULT_RETENTION });
});

router.put('/retention/config', (req, res) => {
  const { config } = req.body;
  if (!config || typeof config !== 'object') return res.status(400).json({ error: 'config object required' });

  // Enforce minimums
  const safe = {};
  for (const [key, defaultVal] of Object.entries(DEFAULT_RETENTION)) {
    const val = parseInt(config[key], 10);
    const minimum = key === 'peer_messages_days' ? 0 : key === 'sessions_days' ? 7 : 30;
    safe[key] = isNaN(val) ? defaultVal : Math.max(minimum, val);
  }

  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('retention_config', ?, ?)").run(JSON.stringify(safe), req.user.id);
    db.close();
    auditLog(req.user.id, 'RETENTION_CONFIG_UPDATED', JSON.stringify(safe), req.ip);
    res.json({ ok: true, config: safe });
  } catch (err) {
    logger.error('Update retention config error', { error: err.message });
    res.status(500).json({ error: 'Failed to update retention config' });
  }
});

router.post('/retention/purge', (req, res) => {
  const results = runRetentionPurge();
  res.json({ ok: true, purged: results });
});

// ── Syslog Export ────────────────────────────────────────────────────────────
router.get('/audit/export-syslog', (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const db = getDb();
    let sql = 'SELECT * FROM audit_log WHERE 1=1';
    const params = [];
    if (startDate) { sql += ' AND timestamp >= ?'; params.push(startDate); }
    if (endDate) { sql += ' AND timestamp <= ?'; params.push(endDate); }
    sql += ' ORDER BY timestamp ASC';
    const events = db.prepare(sql).all(...params);
    db.close();

    const syslogLines = events.map(e => toSyslog(e));

    // HMAC sign the batch
    const integrity = signLogBatch(events);

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Disposition', `attachment; filename=firealive-syslog-${new Date().toISOString().slice(0, 10)}.log`);
    res.setHeader('X-Log-HMAC', integrity.hmac || 'unsigned');
    res.setHeader('X-Log-Count', events.length);
    res.send(syslogLines.join('\n'));
  } catch (err) {
    logger.error('Syslog export error', { error: err.message });
    res.status(500).json({ error: 'Failed to export syslog' });
  }
});

// ── Forensics Export ─────────────────────────────────────────────────────────
// Timeline-based format compatible with forensics tools (Sleuth Kit, FTK, EnCase)
// Outputs in MACB timeline format (bodyfile) or structured JSON
router.get('/audit/export-forensics', (req, res) => {
  try {
    const { format = 'timeline', startDate, endDate } = req.query;
    const db = getDb();
    let sql = 'SELECT al.*, u.name AS user_name, u.role AS user_role FROM audit_log al LEFT JOIN users u ON u.id = al.user_id WHERE 1=1';
    const params = [];
    if (startDate) { sql += ' AND al.timestamp >= ?'; params.push(startDate); }
    if (endDate) { sql += ' AND al.timestamp <= ?'; params.push(endDate); }
    sql += ' ORDER BY al.timestamp ASC';
    const events = db.prepare(sql).all(...params);
    db.close();

    if (format === 'timeline') {
      // Sleuth Kit bodyfile / mactime compatible format
      // MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
      const lines = ['# FireAlive Forensics Timeline Export', `# Generated: ${new Date().toISOString()}`, `# Events: ${events.length}`, '#'];
      lines.push('# MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime');
      for (const e of events) {
        const ts = Math.floor(new Date(e.timestamp).getTime() / 1000);
        const hash = crypto.createHash('sha256').update(`${e.id}${e.timestamp}${e.event_type}`).digest('hex');
        const name = `firealive/${e.event_type}/${e.detail?.replace(/[|]/g, '_')?.slice(0, 100) || 'event'}`;
        const severity = getSeverity(e.event_type);
        lines.push(`${hash}|${name}|${e.id}|${SEVERITY_LABELS[severity]}|${e.user_id || '-'}|${e.user_name || '-'}|${(e.detail || '').length}|${ts}|${ts}|${ts}|${ts}`);
      }

      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Content-Disposition', `attachment; filename=firealive-forensics-${new Date().toISOString().slice(0, 10)}.body`);
      return res.send(lines.join('\n'));
    }

    // Structured JSON for general forensics tools
    const forensicsData = {
      exportType: 'firealive_forensics',
      version: '0.0.20',
      exportedAt: new Date().toISOString(),
      eventCount: events.length,
      integrity: signLogBatch(events),
      events: events.map(e => ({
        id: e.id,
        timestamp: e.timestamp,
        epochMs: new Date(e.timestamp).getTime(),
        eventType: e.event_type,
        severity: getSeverity(e.event_type),
        severityLabel: SEVERITY_LABELS[getSeverity(e.event_type)],
        userId: e.user_id,
        userName: e.user_name,
        userRole: e.user_role,
        detail: e.detail,
        ipAddress: e.ip_address,
        cef: e.cef_message,
      })),
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename=firealive-forensics-${new Date().toISOString().slice(0, 10)}.json`);
    res.json(forensicsData);
  } catch (err) {
    logger.error('Forensics export error', { error: err.message });
    res.status(500).json({ error: 'Failed to export forensics data' });
  }
});

// ── User Provisioning with Approval ──────────────────────────────────────────
router.post('/users/provision', (req, res) => {
  const { username, name, role, tier, shift } = req.body;
  if (!username || !name || !role) return res.status(400).json({ error: 'username, name, and role required' });
  if (!['analyst', 'lead', 'admin'].includes(role)) return res.status(400).json({ error: 'Invalid role' });

  try {
    const db = getDb();
    const id = crypto.randomBytes(16).toString('hex');

    // Create as pending — requires lead/admin MFA approval
    db.prepare("INSERT INTO team_config (key, value, updated_by) VALUES (?, ?, ?)").run(
      `pending_user_${id}`,
      JSON.stringify({
        id, username: username.slice(0, 128), name: name.slice(0, 128),
        role, tier: tier || 1, shift: shift || 'day',
        requestedBy: req.user.id, requestedAt: new Date().toISOString(),
        status: 'pending',
      }),
      req.user.id
    );

    db.close();
    auditLog(req.user.id, 'USER_PROVISION_REQUESTED', `username=${username} role=${role}`, req.ip);

    // In production, this triggers a notification to the team lead
    res.status(201).json({ id, status: 'pending_approval', message: 'User creation requires team lead MFA approval.' });
  } catch (err) {
    logger.error('User provision error', { error: err.message });
    res.status(500).json({ error: 'Failed to request user provisioning' });
  }
});

router.get('/users/pending', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can view pending users' });

  try {
    const db = getDb();
    const rows = db.prepare("SELECT value FROM team_config WHERE key LIKE 'pending_user_%'").all();
    db.close();
    const pending = rows.map(r => { try { return JSON.parse(r.value); } catch { return null; } }).filter(p => p && p.status === 'pending');
    res.json({ pending });
  } catch (err) {
    logger.error('List pending users error', { error: err.message });
    res.status(500).json({ error: 'Failed to list pending users' });
  }
});

router.post('/users/:id/approve', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can approve users' });

  const { approved } = req.body;

  try {
    const db = getDb();
    const row = db.prepare("SELECT key, value FROM team_config WHERE key = ?").get(`pending_user_${req.params.id}`);
    if (!row) { db.close(); return res.status(404).json({ error: 'Pending user not found' }); }

    const pending = JSON.parse(row.value);
    if (pending.status !== 'pending') { db.close(); return res.status(400).json({ error: 'Already processed' }); }

    if (approved) {
      // Create the actual user
      const bcrypt = require('bcryptjs');
      const tempPassword = crypto.randomBytes(16).toString('hex');
      const hash = bcrypt.hashSync(tempPassword, 12);

      db.prepare(`
        INSERT INTO users (id, username, password_hash, role, name, tier, shift, auth_method)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'local')
      `).run(pending.id, pending.username, hash, pending.role, pending.name, pending.tier, pending.shift);

      // Initialize routing cap
      const defaultCap = pending.tier === 3 ? 5 : pending.tier === 2 ? 3 : 2;
      db.prepare('INSERT OR IGNORE INTO routing_caps (analyst_id, max_complexity) VALUES (?, ?)').run(pending.id, defaultCap);

      pending.status = 'approved';
      pending.approvedBy = req.user.id;
      pending.approvedAt = new Date().toISOString();
      db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(pending), row.key);
      db.close();

      auditLog(req.user.id, 'USER_APPROVED', `username=${pending.username} role=${pending.role}`, req.ip);
      res.json({ ok: true, userId: pending.id, tempPassword, message: 'User created. Provide temporary password securely — must be changed on first login.' });
    } else {
      pending.status = 'rejected';
      pending.rejectedBy = req.user.id;
      pending.rejectedAt = new Date().toISOString();
      db.prepare("UPDATE team_config SET value = ? WHERE key = ?").run(JSON.stringify(pending), row.key);
      db.close();

      auditLog(req.user.id, 'USER_REJECTED', `username=${pending.username}`, req.ip);
      res.json({ ok: true, status: 'rejected' });
    }
  } catch (err) {
    logger.error('Approve user error', { error: err.message });
    res.status(500).json({ error: 'Failed to process approval' });
  }
});

module.exports = router;
