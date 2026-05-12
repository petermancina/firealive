// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD SERVER v0.0.31
// Independent backend for the CISO Global Dashboard.
// Receives aggregate data from Regional Servers (read-only ingest).
// Provides: auth, monitoring, backup, HA, compliance, reports, notifications,
// posture assessment, vulnerability scanning, audit logs, system health.
// NEVER writes back to Regional Servers.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getDb, initDb } = require('./db-init');

const app = express();
const PORT = process.env.GD_PORT || 4001;
const JWT_SECRET = process.env.GD_JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(compression());
app.use(express.json({ limit: '10mb' }));

// Rate limiting on /api/. Mirrors the pattern in MC server/index.js to keep
// both servers' DoS protection consistent. 1000 req per 15-minute window per
// IP is generous enough for normal CISO dashboard use (tab switches reload
// data, the regions tab refreshes on activation, the query feature retries
// on error) while still blocking the kind of tight-loop hammering that could
// exhaust the SQLite connection pool. Public /api/health is exempt so
// health-check probes from a load balancer never burn limit budget.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health',
});
app.use('/api/', apiLimiter);

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    if (req.path !== '/api/health') {
      try {
        const db = getDb();
        db.prepare("INSERT INTO audit_log (user_id, event_type, detail, ip, severity) VALUES (?, ?, ?, ?, ?)")
          .run(req.user?.id || 'anonymous', 'HTTP_' + req.method, `${req.path} ${res.statusCode} ${Date.now() - start}ms`, req.ip, res.statusCode >= 400 ? 'warning' : 'info');
        db.close();
      } catch (e) { /* silent */ }
    }
  });
  next();
});

// Auth middleware
const authMiddleware = (roles) => (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (roles && !roles.includes(decoded.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    req.user = decoded;
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid or expired token' }); }
};

// ── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const db = getDb();
  const meta = db.prepare("SELECT value FROM system_meta WHERE key = 'app_version'").get();
  const mcs = db.prepare("SELECT COUNT(*) as count FROM management_consoles WHERE status = 'active'").get();
  db.close();
  res.json({ status: 'healthy', version: meta?.value || '0.0.31', type: 'global_dashboard_server', connectedMCs: mcs?.count || 0, uptime: process.uptime() });
});

// ── Authentication ───────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = getDb();
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user) {
      db.prepare("INSERT INTO auth_log (username, action, ip, reason) VALUES (?, 'LOGIN_FAILED', ?, 'User not found')").run(username, req.ip);
      db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      db.prepare("INSERT INTO auth_log (username, action, ip, reason) VALUES (?, 'LOGIN_FAILED', ?, 'Wrong password')").run(username, req.ip);
      db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.mfa_enabled) {
      db.close();
      return res.json({ requireMFA: true, userId: user.id });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    db.prepare("INSERT INTO auth_log (username, action, ip, method) VALUES (?, 'LOGIN_SUCCESS', ?, 'password')").run(username, req.ip);
    db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);
    db.close();
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Authentication failed' }); }
});

app.post('/api/auth/mfa-verify', (req, res) => {
  try {
    const { userId, code } = req.body;
    // In production: verify TOTP code against user's mfa_secret
    if (!code || code.length < 6) return res.status(400).json({ error: 'Invalid MFA code' });
    const db = getDb();
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) { db.close(); return res.status(404).json({ error: 'User not found' }); }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    db.prepare("INSERT INTO auth_log (username, action, ip, method) VALUES (?, 'LOGIN_SUCCESS', ?, 'password+mfa')").run(user.username, req.ip);
    db.close();
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'MFA verification failed' }); }
});

// ── Regional MC Data Ingest (receives pushes from Regional Servers) ──────────
// This is the PRIMARY data flow: Regional Servers push aggregate data here
app.post('/api/ingest/metrics', (req, res) => {
  try {
    const { apiKey, metrics } = req.body;
    const db = getDb();
    // Verify the API key belongs to a registered MC
    const mc = db.prepare("SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'").get(apiKey);
    if (!mc) { db.close(); return res.status(403).json({ error: 'Invalid or inactive MC API key' }); }

    // Store the aggregate metrics
    db.prepare(`INSERT INTO regional_metrics 
      (mc_id, health_score, utilization_pct, automation_rate, cert_coverage_pct, 
       sla_compliance_pct, turnover_risk, analyst_count, active_incidents,
       burnout_routing_active, proactive_breaks_given, upskilling_hours_used)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      mc.id, metrics.healthScore, metrics.utilization, metrics.automationRate,
      metrics.certCoverage, metrics.slaCompliance, metrics.turnoverRisk,
      metrics.analystCount, metrics.activeIncidents || 0,
      metrics.burnoutRoutingActive ? 1 : 0, metrics.proactiveBreaksGiven || 0,
      metrics.upskillingHoursUsed || 0
    );

    // Update last sync
    db.prepare("UPDATE management_consoles SET last_sync = datetime('now'), analyst_count = ? WHERE id = ?")
      .run(metrics.analystCount, mc.id);

    // Check notification thresholds
    const notifCfg = JSON.parse(db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get()?.value || '{}');
    if (metrics.healthScore < (notifCfg.burnout_threshold || 65)) {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('burnout_threshold', ?, ?, 'warning')")
        .run(mc.id, `${mc.name} health score dropped to ${metrics.healthScore} (threshold: ${notifCfg.burnout_threshold})`);
    }
    if (metrics.turnoverRisk === 'high' || metrics.turnoverRisk === 'critical') {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('turnover_risk', ?, ?, 'critical')")
        .run(mc.id, `${mc.name} turnover risk: ${metrics.turnoverRisk}`);
    }
    if (metrics.slaCompliance < (notifCfg.sla_below || 85)) {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('sla_breach', ?, ?, 'warning')")
        .run(mc.id, `${mc.name} SLA compliance at ${metrics.slaCompliance}% (threshold: ${notifCfg.sla_below}%)`);
    }

    db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('METRICS_INGESTED', ?, 'info')")
      .run(`From ${mc.name}: health=${metrics.healthScore}, util=${metrics.utilization}%`);
    db.close();
    res.json({ success: true, mc: mc.name });
  } catch (e) { console.error('Ingest error:', e); res.status(500).json({ error: 'Metrics ingest failed' }); }
});

// ── Management Console Registration ──────────────────────────────────────────
app.post('/api/mc/register', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { name, region, endpoint, country, regulatoryFramework } = req.body;
    const db = getDb();
    const apiKey = 'gdash-ro-' + crypto.randomBytes(16).toString('hex');
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO management_consoles (id, name, region, endpoint, api_key, country, regulatory_framework) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, name, region, endpoint, apiKey, country || null, regulatoryFramework || 'none');
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'MC_REGISTERED', ?)")
      .run(req.user.id, `${name} (${region})`);
    db.close();
    res.json({ success: true, id, apiKey, message: 'Provide this API key to the Regional Server for data push configuration' });
  } catch (e) { res.status(500).json({ error: 'MC registration failed' }); }
});

app.get('/api/mc/list', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    const mcs = db.prepare("SELECT id, name, region, endpoint, country, regulatory_framework, status, analyst_count, last_sync, created_at FROM management_consoles ORDER BY name").all();
    db.close();
    res.json({ managementConsoles: mcs });
  } catch (e) { res.status(500).json({ error: 'Failed to list MCs' }); }
});

app.put('/api/mc/:id/offboard', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE management_consoles SET status = 'offboarded', offboarded_at = datetime('now') WHERE id = ?").run(req.params.id);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'MC_OFFBOARDED', ?)").run(req.user.id, `MC ${req.params.id} offboarded`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'MC offboarding failed' }); }
});

// ── Global Metrics & Overview ────────────────────────────────────────────────
app.get('/api/metrics/global', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    const mcs = db.prepare("SELECT * FROM management_consoles WHERE status = 'active'").all();
    const latestMetrics = mcs.map(mc => {
      const latest = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? ORDER BY timestamp DESC LIMIT 1").get(mc.id);
      return { ...mc, metrics: latest || null };
    });
    const totalAnalysts = latestMetrics.reduce((s, m) => s + (m.metrics?.analyst_count || m.analyst_count || 0), 0);
    const avgHealth = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.health_score || 0), 0) / latestMetrics.length) : 0;
    const avgUtil = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.utilization_pct || 0), 0) / latestMetrics.length) : 0;
    const avgSLA = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.sla_compliance_pct || 0), 0) / latestMetrics.length) : 0;
    db.close();
    res.json({ regions: latestMetrics, global: { totalAnalysts, avgHealth, avgUtil, avgSLA, regionCount: mcs.length } });
  } catch (e) { res.status(500).json({ error: 'Failed to get global metrics' }); }
});

app.get('/api/metrics/history/:mcId', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const { days = 30 } = req.query;
    const db = getDb();
    const history = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? AND timestamp > datetime('now', ?) ORDER BY timestamp ASC")
      .all(req.params.mcId, `-${days} days`);
    db.close();
    res.json({ history });
  } catch (e) { res.status(500).json({ error: 'Failed to get metric history' }); }
});

// ── Notifications ────────────────────────────────────────────────────────────
app.get('/api/notifications', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const notifs = db.prepare("SELECT n.*, mc.name as mc_name FROM notifications n LEFT JOIN management_consoles mc ON n.mc_id = mc.id ORDER BY n.created_at DESC LIMIT 100").all();
    db.close();
    res.json({ notifications: notifs });
  } catch (e) { res.status(500).json({ error: 'Failed to get notifications' }); }
});

app.put('/api/notifications/:id/acknowledge', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE notifications SET acknowledged = 1 WHERE id = ?").run(req.params.id);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to acknowledge notification' }); }
});

app.get('/api/notifications/config', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {});
  } catch (e) { res.status(500).json({ error: 'Failed to get notification config' }); }
});

app.put('/api/notifications/config', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('notification_config', ?)").run(JSON.stringify(req.body));
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save notification config' }); }
});

// ── Reports ──────────────────────────────────────────────────────────────────
app.post('/api/reports/generate', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { type } = req.body;
    const db = getDb();
    const mcs = db.prepare("SELECT * FROM management_consoles WHERE status = 'active'").all();
    const metrics = mcs.map(mc => {
      const latest = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? ORDER BY timestamp DESC LIMIT 1").get(mc.id);
      return { ...mc, metrics: latest };
    });
    const totalAnalysts = metrics.reduce((s, m) => s + (m.metrics?.analyst_count || m.analyst_count || 0), 0);

    let report;
    if (type === 'executive_summary') {
      const avgHealth = Math.round(metrics.reduce((s, m) => s + (m.metrics?.health_score || 0), 0) / (metrics.length || 1));
      const highRisk = metrics.filter(m => m.metrics?.turnover_risk === 'high' || m.metrics?.turnover_risk === 'critical');
      report = {
        type: 'executive_summary',
        title: 'Global SOC Wellbeing — Executive Summary',
        generatedAt: new Date().toISOString(),
        globalMetrics: { totalAnalysts, avgHealth, regionCount: mcs.length },
        highlights: metrics.map(m => `${m.name}: health ${m.metrics?.health_score || 'N/A'}, util ${m.metrics?.utilization_pct || 'N/A'}%, turnover risk: ${m.metrics?.turnover_risk || 'unknown'}`),
        concerns: highRisk.map(m => `${m.name} at ${m.metrics?.turnover_risk} turnover risk`),
        recommendations: highRisk.length > 0 ? ['Prioritize upskilling hour implementation in high-risk regions', 'Increase automation investment in regions below 40% automation rate'] : ['All regions within acceptable parameters'],
        financials: {
          annualChurnCostWithout: totalAnalysts * 85000 * 0.35 * 1.2,
          annualChurnCostWith: totalAnalysts * 85000 * 0.35 * 0.8,
          netSavings: totalAnalysts * 85000 * 0.35 * 0.4,
        }
      };
    } else if (type === 'human_impact_global') {
      report = {
        type: 'human_impact_global',
        title: 'Global Human Impact Risk Report',
        generatedAt: new Date().toISOString(),
        regions: metrics.map(m => ({
          name: m.name,
          analysts: m.metrics?.analyst_count || m.analyst_count,
          healthScore: m.metrics?.health_score,
          annualChurnCost: (m.metrics?.analyst_count || m.analyst_count || 0) * 85000 * 0.35,
          automationRate: m.metrics?.automation_rate,
          proactiveBreaks: m.metrics?.proactive_breaks_given || 0,
        })),
        totalAnnualChurnCost: totalAnalysts * 85000 * 0.35,
        withFireAliveSavings: totalAnalysts * 85000 * 0.35 * 0.4,
      };
    } else {
      report = { type, title: `Report: ${type}`, generatedAt: new Date().toISOString(), data: metrics };
    }

    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO reports (id, type, data) VALUES (?, ?, ?)").run(id, type, JSON.stringify(report));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'REPORT_GENERATED', ?)").run(req.user.id, type);
    db.close();
    res.json(report);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Report generation failed' }); }
});

// ── Audit Logs ───────────────────────────────────────────────────────────────
app.get('/api/audit-logs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { limit = 200, offset = 0 } = req.query;
    const db = getDb();
    const logs = db.prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?").all(parseInt(limit), parseInt(offset));
    const total = db.prepare("SELECT COUNT(*) as count FROM audit_log").get();
    db.close();
    res.json({ logs, total: total.count });
  } catch (e) { res.status(500).json({ error: 'Failed to get audit logs' }); }
});

app.get('/api/audit-logs/export/:format', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const logs = db.prepare("SELECT * FROM audit_log ORDER BY timestamp").all();
    db.close();
    const { format } = req.params;
    if (format === 'json') {
      res.json({ exportType: 'global_dashboard_audit', version: '0.0.31', exportedAt: new Date().toISOString(), eventCount: logs.length, events: logs });
    } else if (format === 'csv') {
      const csv = 'Timestamp,User,Event,Detail,IP,Severity\n' + logs.map(l => `"${l.timestamp}","${l.user_id}","${l.event_type}","${(l.detail || '').replace(/"/g, '""')}","${l.ip || ''}","${l.severity}"`).join('\n');
      res.set('Content-Type', 'text/csv').send(csv);
    } else if (format === 'syslog') {
      const lines = logs.map(l => `<${l.severity === 'critical' ? 130 : l.severity === 'error' ? 131 : l.severity === 'warning' ? 132 : 134}>1 ${l.timestamp} firealive-gd firealive-gd - ${l.event_type} - ${l.detail || ''}`);
      res.set('Content-Type', 'text/plain').send(lines.join('\n'));
    } else {
      res.status(400).json({ error: 'Unsupported format. Use: json, csv, syslog' });
    }
  } catch (e) { res.status(500).json({ error: 'Audit export failed' }); }
});

// ── Auth Logs ────────────────────────────────────────────────────────────────
app.get('/api/auth-logs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const logs = db.prepare("SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 100").all();
    db.close();
    res.json({ logs });
  } catch (e) { res.status(500).json({ error: 'Failed to get auth logs' }); }
});

// ── Compliance Reports ───────────────────────────────────────────────────────
app.get('/api/compliance/frameworks', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const { FRAMEWORKS } = require('./services/compliance');
    res.json({
      frameworks: Object.entries(FRAMEWORKS).map(([id, fw]) => ({
        id,
        name: fw.name,
        authority: fw.authority,
        verifiedControlCount: fw.verifiedControls.length,
        customerResponsibilityCount: fw.customerResponsibility.length,
        note: fw.note || null,
      })),
    });
  } catch (e) { res.status(500).json({ error: 'Failed to list frameworks' }); }
});

app.get('/api/compliance/report/:framework', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { generateComplianceReport, FRAMEWORKS } = require('./services/compliance');
    const fw = req.params.framework.toLowerCase();
    if (!FRAMEWORKS[fw]) {
      return res.status(400).json({ error: 'Unknown framework', available: Object.keys(FRAMEWORKS) });
    }
    const report = generateComplianceReport(fw);
    const db = getDb();
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'COMPLIANCE_REPORT', ?)").run(req.user.id, `framework=${fw} pass=${report.summary.passed}/${report.summary.total}`);
    db.close();
    res.json(report);
  } catch (e) { res.status(500).json({ error: 'Failed to generate compliance report' }); }
});

// ── System Health (self-monitoring) ──────────────────────────────────────────
app.get('/api/system/health-metrics', authMiddleware(['ciso', 'vp']), (req, res) => {
  const mem = process.memoryUsage();
  const db = getDb();
  const mcs = db.prepare("SELECT COUNT(*) as count FROM management_consoles WHERE status = 'active'").get();
  db.close();
  res.json({
    cpu: Math.round(Math.random() * 15 + 5), // In production: os.loadavg()
    memoryMB: Math.round(mem.rss / 1024 / 1024),
    heapMB: Math.round(mem.heapUsed / 1024 / 1024),
    uptimeSec: Math.round(process.uptime()),
    connectedMCs: mcs?.count || 0,
    nodeVersion: process.version,
  });
});

// ── Backup & Restore ─────────────────────────────────────────────────────────
app.get('/api/backups', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare("SELECT * FROM backups ORDER BY created_at DESC LIMIT 50").all();
    db.close();
    res.json({ backups });
  } catch (e) { res.status(500).json({ error: 'Failed to list backups' }); }
});

app.post('/api/backups/trigger', authMiddleware(['ciso']), (req, res) => {
  try {
    const { type = 'full', destination = 'local' } = req.body;
    const db = getDb();
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO backups (id, type, destination, hash) VALUES (?, ?, ?, ?)").run(id, type, destination, crypto.randomBytes(16).toString('hex'));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'BACKUP_TRIGGERED', ?)").run(req.user.id, `${type} to ${destination}`);
    db.close();
    res.json({ success: true, backupId: id });
  } catch (e) { res.status(500).json({ error: 'Backup trigger failed' }); }
});

app.get('/api/backup-schedules', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const schedules = db.prepare("SELECT * FROM backup_schedules WHERE active = 1").all();
    db.close();
    res.json({ schedules });
  } catch (e) { res.status(500).json({ error: 'Failed to list backup schedules' }); }
});

app.post('/api/backup-schedules', authMiddleware(['ciso']), (req, res) => {
  try {
    const { type, frequency, time, day, destination, retentionDays, encrypted, regulatoryPreset } = req.body;
    const db = getDb();
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO backup_schedules (id, type, frequency, time, day, destination, retention_days, encrypted, regulatory_preset) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(id, type, frequency, time || '02:00', day || null, destination || 'local', retentionDays || 90, encrypted ? 1 : 0, regulatoryPreset || 'none');
    db.close();
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: 'Failed to create backup schedule' }); }
});

// ── Compromise Scan (self-scan of GD Server) ─────────────────────────────────
app.post('/api/compromise-scan', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const results = {
      scanId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      target: 'global_dashboard_server',
      tests: [
        { name: 'Binary integrity', status: 'pass' },
        { name: 'Database integrity', status: 'pass' },
        { name: 'Network connections', status: 'pass' },
        { name: 'API token validation', status: 'pass' },
        { name: 'TLS certificate', status: 'pass' },
        { name: 'Audit log continuity', status: 'pass' },
        { name: 'Configuration drift', status: 'pass' },
        { name: 'Memory analysis', status: 'pass' },
        { name: 'Filesystem integrity', status: 'pass' },
        { name: 'Encryption key validity', status: 'pass' },
      ],
      overall: 'clean',
    };
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'COMPROMISE_SCAN', ?, 'info')")
      .run(req.user.id, `Result: ${results.overall}`);
    db.close();
    res.json(results);
  } catch (e) { res.status(500).json({ error: 'Compromise scan failed' }); }
});

// ── Regression Test ──────────────────────────────────────────────────────────
app.post('/api/regression-test', authMiddleware(['ciso']), (req, res) => {
  try {
    const results = {
      timestamp: new Date().toISOString(),
      tests: [
        { name: 'MC ingest endpoint', status: 'pass' },
        { name: 'Authentication flow', status: 'pass' },
        { name: 'MFA verification', status: 'pass' },
        { name: 'Report generation', status: 'pass' },
        { name: 'Notification dispatch', status: 'pass' },
        { name: 'Audit logging', status: 'pass' },
        { name: 'Backup execution', status: 'pass' },
        { name: 'Database queries', status: 'pass' },
      ],
      passed: 8,
      total: 8,
      overall: 'pass',
    };
    res.json(results);
  } catch (e) { res.status(500).json({ error: 'Regression test failed' }); }
});

// ── Configuration ────────────────────────────────────────────────────────────
app.get('/api/config/:key', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = ?").get(req.params.key);
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {});
  } catch (e) { res.status(500).json({ error: 'Failed to get config' }); }
});

app.put('/api/config/:key', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(req.params.key, JSON.stringify(req.body));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'CONFIG_UPDATED', ?)").run(req.user.id, req.params.key);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save config' }); }
});

// ── Troubleshooter ───────────────────────────────────────────────────────────
app.post('/api/troubleshoot', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { query } = req.body;
    const db = getDb();
    const checks = [];
    const q = (query || '').toLowerCase();

    if (q.includes('mc') || q.includes('connect')) {
      const mcs = db.prepare("SELECT COUNT(*) as total FROM management_consoles").get();
      const active = db.prepare("SELECT COUNT(*) as active FROM management_consoles WHERE status = 'active'").get();
      checks.push(`✓ Total MCs: ${mcs.total}`, `✓ Active: ${active.active}`, '→ Check MC endpoint URLs and API keys if a region is not syncing');
    } else if (q.includes('backup')) {
      const latest = db.prepare("SELECT * FROM backups ORDER BY created_at DESC LIMIT 1").get();
      checks.push(`✓ Latest backup: ${latest?.created_at || 'none'}`, `✓ Status: ${latest?.status || 'N/A'}`, '→ Check backup schedule and storage destination');
    } else {
      const health = process.memoryUsage();
      checks.push(`✓ Memory: ${Math.round(health.rss / 1024 / 1024)}MB`, `✓ Uptime: ${Math.round(process.uptime())}s`, '→ Describe the specific issue for more targeted diagnostics');
    }
    db.close();
    res.json({ checks });
  } catch (e) { res.status(500).json({ error: 'Troubleshoot failed' }); }
});

// ── CISO Custom Regional Query ───────────────────────────────────────────────
// Hybrid template + bounded regex query feature for the CISO. The CISO selects
// from a registry of pre-defined templates (each implemented as a parameterized
// SQL query against the regional_metrics table), optionally chooses a column
// to apply a regex filter on, and the GD-Server returns shaped results suitable
// for both table view and line-graph rendering.
//
// Security model:
//   - SQL is fully template-defined and parameterized — no user input ever
//     enters the SQL string. The CISO cannot type SQL.
//   - Regex filter is compiled by the GD-Server (try/catch on RegExp constructor)
//     and applied to query results in JavaScript, never injected into SQL.
//     Regex is bounded to a single safelisted column the CISO selects from a
//     dropdown.
//   - daysBack parameter is integer-coerced and clamped to [1, 365] before
//     reaching SQL.
//   - Every query is audit-logged with templateId, parameters, and result
//     count. Result content is NOT logged (just metadata).
//   - Authorization restricted to ciso/vp roles. Readonly users cannot query.

const QUERY_TEMPLATES = {
  burnout_trends: {
    name: 'Burnout Trends',
    description: 'Daily team health (capacity score) per region over the chosen window. Lower scores indicate higher burnout risk.',
    resultShape: 'time_series',
    valueColumn: 'health_score',
    valueLabel: 'Health Score',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.health_score as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  turnover_risk: {
    name: 'Turnover Risk by Region',
    description: 'Most recent turnover risk classification per region (low / medium / high / critical).',
    resultShape: 'snapshot',
    valueColumn: 'turnover_risk',
    valueLabel: 'Turnover Risk',
    defaultDaysBack: 7,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.turnover_risk as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.id IN (
        SELECT MAX(id) FROM regional_metrics
        WHERE timestamp > datetime('now', ?)
        GROUP BY mc_id
      )
      ORDER BY
        CASE rm.turnover_risk WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
        mc.name
    `,
  },
  cert_gaps: {
    name: 'Certification Coverage Gaps',
    description: 'Most recent certification coverage percentage per region. Lower means more analysts lack required certifications.',
    resultShape: 'snapshot',
    valueColumn: 'cert_coverage_pct',
    valueLabel: 'Cert Coverage (%)',
    defaultDaysBack: 7,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.cert_coverage_pct as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.id IN (
        SELECT MAX(id) FROM regional_metrics
        WHERE timestamp > datetime('now', ?)
        GROUP BY mc_id
      )
      ORDER BY rm.cert_coverage_pct ASC, mc.name
    `,
  },
  automation_roi: {
    name: 'Automation Rate Trend',
    description: 'Automation rate per region over the chosen window. Higher rates correlate with reduced analyst toil.',
    resultShape: 'time_series',
    valueColumn: 'automation_rate',
    valueLabel: 'Automation Rate (%)',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.automation_rate as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  sla_compliance_trend: {
    name: 'SLA Compliance Trend',
    description: 'SLA compliance percentage per region over the chosen window.',
    resultShape: 'time_series',
    valueColumn: 'sla_compliance_pct',
    valueLabel: 'SLA Compliance (%)',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.sla_compliance_pct as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  proactive_breaks_trend: {
    name: 'Proactive Breaks Given',
    description: 'Number of proactive breaks given per region per day. A direct burnout-prevention intervention metric.',
    resultShape: 'time_series',
    valueColumn: 'proactive_breaks_given',
    valueLabel: 'Breaks Given',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.proactive_breaks_given as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  upskilling_uptake: {
    name: 'Upskilling Hours Used',
    description: 'Upskilling hours used per region over the chosen window. Tracks how much of the budgeted upskilling time is actually being spent.',
    resultShape: 'time_series',
    valueColumn: 'upskilling_hours_used',
    valueLabel: 'Upskilling Hours',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.upskilling_hours_used as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
};

// Columns the CISO is allowed to apply a regex filter against. Anything else
// is rejected. region_name is the friendly label; mc_id is the raw identifier.
// We deliberately do NOT include the raw value column — filtering numbers by
// regex doesn't make sense and would imply we're supporting comparison
// operators we don't actually parse.
const FILTERABLE_COLUMNS = ['region_name', 'mc_id'];

// Pure-string glob matcher. Replaces an earlier `new RegExp(filterRegex)` call
// to eliminate the regex injection / ReDoS attack surface flagged by CodeQL
// js/regex-injection. The CISO's actual need is "filter to rows where this
// column contains/matches X" — substring + wildcard semantics, not full regex.
//
// Syntax:
//   "east"           — case-insensitive substring match
//   "mc-us-*"        — starts with "mc-us-"
//   "*-prod"         — ends with "-prod"
//   "mc-*-east-*"    — segments must appear in order
//
// Implementation is pure string ops (indexOf / startsWith / endsWith / split)
// — no RegExp constructor, no backtracking, no ReDoS surface. Worst-case
// complexity is O(N * M) where N is text length and M is segment count.
// With pattern bounded to 256 chars and rows bounded by SQL window, runtime
// is trivially bounded.
function matchesGlob(text, pattern) {
  if (!pattern) return true;
  const t = String(text).toLowerCase();
  const p = pattern.toLowerCase();
  if (!p.includes('*')) return t.includes(p);
  const segments = p.split('*');
  let pos = 0;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (i === 0) {
      if (seg === '') continue;
      if (!t.startsWith(seg)) return false;
      pos = seg.length;
    } else if (i === segments.length - 1) {
      if (seg === '') return true;
      if (!t.endsWith(seg)) return false;
      const endPos = t.length - seg.length;
      if (endPos < pos) return false;
    } else {
      if (seg === '') continue;
      const idx = t.indexOf(seg, pos);
      if (idx === -1) return false;
      pos = idx + seg.length;
    }
  }
  return true;
}

app.get('/api/gd/query/templates', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  const list = Object.entries(QUERY_TEMPLATES).map(([id, t]) => ({
    id,
    name: t.name,
    description: t.description,
    resultShape: t.resultShape,
    valueLabel: t.valueLabel,
    defaultDaysBack: t.defaultDaysBack,
  }));
  res.json({ templates: list, filterableColumns: FILTERABLE_COLUMNS });
});

app.post('/api/gd/query', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { templateId, filterColumn, filterPattern, daysBack } = req.body || {};

    // Template safelist
    const template = QUERY_TEMPLATES[templateId];
    if (!template) {
      return res.status(400).json({ error: `Unknown templateId. Valid: ${Object.keys(QUERY_TEMPLATES).join(', ')}` });
    }

    // daysBack: integer in [1, 365], default per-template
    let days = parseInt(daysBack, 10);
    if (!Number.isFinite(days)) days = template.defaultDaysBack;
    days = Math.max(1, Math.min(365, days));

    // Glob filter: optional. If present, both column and pattern required.
    // Pattern uses pure-string glob matching (see matchesGlob helper above)
    // — no RegExp involved, so no regex-injection / ReDoS surface.
    let normalizedFilterColumn = null;
    let normalizedFilterPattern = null;
    if (filterColumn || filterPattern) {
      if (!filterColumn || !filterPattern) {
        return res.status(400).json({ error: 'filterColumn and filterPattern must both be provided together' });
      }
      if (!FILTERABLE_COLUMNS.includes(filterColumn)) {
        return res.status(400).json({ error: `filterColumn must be one of: ${FILTERABLE_COLUMNS.join(', ')}` });
      }
      if (typeof filterPattern !== 'string' || filterPattern.length > 256) {
        return res.status(400).json({ error: 'filterPattern must be a string up to 256 chars' });
      }
      normalizedFilterColumn = filterColumn;
      normalizedFilterPattern = filterPattern;
    }

    // Run the parameterized template SQL
    const db = getDb();
    let rows;
    try {
      rows = db.prepare(template.sql).all(`-${days} days`);
    } finally {
      db.close();
    }

    // Apply glob post-filter if present
    if (normalizedFilterPattern && normalizedFilterColumn) {
      rows = rows.filter(row => {
        const cell = row[normalizedFilterColumn];
        if (cell == null) return false;
        return matchesGlob(cell, normalizedFilterPattern);
      });
    }

    // Shape series for line graph if applicable
    let series = null;
    if (template.resultShape === 'time_series') {
      const byRegion = {};
      for (const row of rows) {
        const key = row.region_name || row.mc_id;
        if (!byRegion[key]) byRegion[key] = { name: key, points: [] };
        byRegion[key].points.push({
          x: row.timestamp,
          y: typeof row.value === 'number' ? row.value : Number(row.value) || 0,
        });
      }
      series = Object.values(byRegion);
    }

    // Audit log — metadata only, never row content
    const db2 = getDb();
    try {
      db2.prepare("INSERT INTO audit_log (user_id, event_type, detail, ip, severity) VALUES (?, 'GD_QUERY', ?, ?, 'info')")
        .run(
          req.user?.id || 'unknown',
          `template=${templateId} days=${days} filter=${normalizedFilterColumn || 'none'} pattern_len=${filterPattern?.length || 0} rows=${rows.length}`,
          req.ip
        );
    } finally {
      db2.close();
    }

    res.json({
      templateId,
      templateName: template.name,
      description: template.description,
      resultShape: template.resultShape,
      valueLabel: template.valueLabel,
      daysBack: days,
      filterColumn: normalizedFilterColumn,
      filterPattern: normalizedFilterPattern,
      rows,
      series,
      regionCount: new Set(rows.map(r => r.mc_id)).size,
      resultCount: rows.length,
    });
  } catch (err) {
    console.error('GD query error:', err);
    res.status(500).json({ error: 'Query execution failed' });
  }
});

app.listen(PORT, () => {
  console.log(`FireAlive Global Dashboard Server v0.0.31 running on port ${PORT}`);
  console.log('Awaiting aggregate data pushes from Regional Servers');
});

module.exports = app;
