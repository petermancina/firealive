// FireAlive v1.0.0 — Full Feature Routes
const router = require('express').Router();

// Input validation helpers
const validate = {
  string: (v, max=500) => typeof v === 'string' && v.length > 0 && v.length <= max,
  number: (v, min=0, max=100) => typeof v === 'number' && v >= min && v <= max,
  uuid: (v) => typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v),
  signal: (v) => ['cognitive_load','task_switching','queue_pressure','response_latency','break_compliance','shift_overtime'].includes(v),
  framework: (v) => ['nist_csf','iso_27001','soc2','hipaa','gdpr','dora','ccpa','pipeda','lgpd','pdpa_sg','appi_jp','popia_za','nis2','cps234_au','cyber_essentials','fisma'].includes(v),
};
const crypto = require('crypto');
const { requireAuth, requireRole } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

// AI Burnout Engine
router.post('/signals/record', requireAuth, (req, res) => {
  const { AiBurnoutEngine } = require('../services/ai-burnout-engine');
  const engine = new AiBurnoutEngine(req.app.locals.db);
  const { signal, value } = req.body;
  if (!validate.signal(signal)) return res.status(400).json({ error: 'Invalid signal' });
  if (typeof value !== 'number') return res.status(400).json({ error: 'Value must be a number' });
  engine.recordSignal(req.user.id, signal, value);
  res.json({ recorded: true });
});
router.get('/signals/:analystId', requireAuth, (req, res) => {
  const { AiBurnoutEngine } = require('../services/ai-burnout-engine');
  res.json(new AiBurnoutEngine(req.app.locals.db).getSignals(req.params.analystId));
});
router.get('/impacts/:analystId', requireAuth, (req, res) => {
  const { AiBurnoutEngine } = require('../services/ai-burnout-engine');
  res.json(new AiBurnoutEngine(req.app.locals.db).getImpacts(req.params.analystId));
});
router.get('/training-recommendations/:analystId', requireAuth, (req, res) => {
  const { AiBurnoutEngine } = require('../services/ai-burnout-engine');
  res.json(new AiBurnoutEngine(req.app.locals.db).getTrainingRecommendations(req.params.analystId));
});

// Assessments
router.post('/assessments/create', requireAuth, requireRole('manager'), (req, res) => {
  const { AssessmentService } = require('../services/assessment-service');
  const svc = new AssessmentService(req.app.locals.db);
  const { category, platform, targetAnalyst } = req.body;
  const result = svc.create(category, platform, targetAnalyst, req.user.id);
  auditLog(req.app.locals.db, req.user.id, 'ASSESSMENT_CREATED', `${category} → ${targetAnalyst}`);
  // Send notification to analyst
  const { NotificationService } = require('../services/notification-service');
  new NotificationService(req.app.locals.db).send(targetAnalyst, 'assessment', 'New Assessment', `${category} assessment assigned`, 'skills');
  res.json(result);
});
router.post('/assessments/submit', requireAuth, (req, res) => {
  const { AssessmentService } = require('../services/assessment-service');
  const result = new AssessmentService(req.app.locals.db).submitResults(req.body.assessmentId, req.body.score);
  auditLog(req.app.locals.db, req.user.id, 'ASSESSMENT_SUBMITTED', `Score: ${req.body.score}%`);
  res.json(result);
});
router.get('/assessments/analyst/:id', requireAuth, (req, res) => {
  const { AssessmentService } = require('../services/assessment-service');
  res.json(new AssessmentService(req.app.locals.db).getForAnalyst(req.params.id));
});
router.get('/skills/:analystId', requireAuth, (req, res) => {
  const { AssessmentService } = require('../services/assessment-service');
  res.json(new AssessmentService(req.app.locals.db).getSkills(req.params.analystId));
});

// Backups
router.post('/backup/create', requireAuth, requireRole('manager'), (req, res) => {
  const { BackupService } = require('../services/backup-service');
  const result = new BackupService(req.app.locals.db).createBackup(req.body.type || 'full');
  auditLog(req.app.locals.db, req.user.id, 'BACKUP_CREATED', `Type: ${req.body.type || 'full'}`);
  res.json(result);
});
router.get('/backup/history', requireAuth, (req, res) => {
  const { BackupService } = require('../services/backup-service');
  res.json(new BackupService(req.app.locals.db).getHistory());
});
router.post('/backup/schedule/add', requireAuth, requireRole('manager'), (req, res) => {
  const { BackupService } = require('../services/backup-service');
  const { type, interval, retention, destination } = req.body;
  new BackupService(req.app.locals.db).addSchedule(type, interval, retention, destination);
  auditLog(req.app.locals.db, req.user.id, 'BACKUP_SCHEDULE', `${type} every ${interval}`);
  res.json({ saved: true });
});
router.post('/backup/restore/:id', requireAuth, requireRole('manager'), (req, res) => {
  const { BackupService } = require('../services/backup-service');
  res.json(new BackupService(req.app.locals.db).restore(req.params.id));
});

// Compliance
router.post('/compliance/scan', requireAuth, requireRole('manager'), (req, res) => {
  const { ComplianceScanner } = require('../services/compliance-scanner');
  if (!validate.framework(req.body.framework)) return res.status(400).json({ error: 'Invalid framework' });
  const result = new ComplianceScanner(req.app.locals.db).scan(req.body.framework);
  auditLog(req.app.locals.db, req.user.id, 'COMPLIANCE_SCAN', `Framework: ${req.body.framework}`);
  res.json(result);
});

// Regression
router.post('/regression/run', requireAuth, requireRole('manager'), (req, res) => {
  const { RegressionRunner } = require('../services/regression-runner');
  const result = new RegressionRunner(req.app.locals.db).run();
  auditLog(req.app.locals.db, req.user.id, 'REGRESSION_RUN', `${result.passed}/${result.total} passed`);
  res.json(result);
});

// Integrations
router.post('/integrations/save', requireAuth, requireRole('manager'), (req, res) => {
  const { IntegrationManager } = require('../services/integration-manager');
  const mgr = new IntegrationManager(req.app.locals.db);
  const { type, platform, endpoint, apiKey } = req.body;
  const hash = crypto.createHash('sha256').update(apiKey || '').digest('hex');
  const result = mgr.saveConfig(type, platform, endpoint, hash);
  auditLog(req.app.locals.db, req.user.id, 'INTEGRATION_SAVED', `${type}: ${platform}`);
  res.json(result);
});
router.post('/integrations/test', requireAuth, requireRole('manager'), async (req, res) => {
  const { IntegrationManager } = require('../services/integration-manager');
  const result = await new IntegrationManager(req.app.locals.db).testConnection(req.body.type, req.body.endpoint);
  res.json(result);
});
router.get('/integrations/status', requireAuth, (req, res) => {
  const { IntegrationManager } = require('../services/integration-manager');
  res.json(new IntegrationManager(req.app.locals.db).getAll());
});

// System Health
router.get('/health', requireAuth, (req, res) => {
  const { SystemHealthMonitor } = require('../services/system-health');
  res.json(new SystemHealthMonitor(req.app.locals.db).getMetrics());
});
router.get('/clients/connected', requireAuth, (req, res) => {
  const { SystemHealthMonitor } = require('../services/system-health');
  res.json(new SystemHealthMonitor(req.app.locals.db).getConnectedClients());
});

// Notifications
router.get('/notifications', requireAuth, (req, res) => {
  const { NotificationService } = require('../services/notification-service');
  res.json(new NotificationService(req.app.locals.db).getUnread(req.user.id));
});
router.post('/notifications/:id/read', requireAuth, (req, res) => {
  const { NotificationService } = require('../services/notification-service');
  new NotificationService(req.app.locals.db).markRead(req.params.id);
  res.json({ marked: true });
});

// Config lock
router.post('/config/lock', requireAuth, requireRole('manager'), (req, res) => {
  const { locked } = req.body;
  req.app.locals.db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('config_locked', ?)").run(locked ? 'true' : 'false');
  auditLog(req.app.locals.db, req.user.id, 'CONFIG_LOCK', locked ? 'LOCKED' : 'UNLOCKED');
  res.json({ locked });
});

// SLA
router.post('/sla/save', requireAuth, requireRole('manager'), (req, res) => {
  req.app.locals.db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('sla_targets', ?)").run(JSON.stringify(req.body.targets));
  auditLog(req.app.locals.db, req.user.id, 'SLA_UPDATED', 'SLA targets modified');
  res.json({ saved: true });
});

// Shift handoff
router.post('/handoff/save', requireAuth, requireRole('manager'), (req, res) => {
  const { NotificationService } = require('../services/notification-service');
  const notif = new NotificationService(req.app.locals.db);
  // Notify incoming lead
  notif.send('incoming_lead', 'handoff', 'Shift Handoff', req.body.notes || 'Handoff notes available', 'handoff');
  req.app.locals.db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run(`handoff_${Date.now()}`, JSON.stringify({ notes: req.body.notes, from: req.user.id, at: new Date().toISOString() }));
  auditLog(req.app.locals.db, req.user.id, 'HANDOFF', 'Shift handoff saved + notification sent');
  res.json({ saved: true, notified: true });
});

// Config snapshot
router.post('/config/snapshot', requireAuth, requireRole('manager'), (req, res) => {
  const allConfig = req.app.locals.db.prepare("SELECT * FROM config").all();
  const id = crypto.randomUUID();
  req.app.locals.db.prepare("INSERT INTO config (key, value) VALUES (?, ?)").run(`snapshot_${id}`, JSON.stringify({ configs: allConfig, createdAt: new Date().toISOString() }));
  auditLog(req.app.locals.db, req.user.id, 'CONFIG_SNAPSHOT', `Snapshot ${id}`);
  res.json({ id, created: true });
});

// Client heartbeat
router.post('/heartbeat', requireAuth, (req, res) => {
  req.app.locals.db.prepare("UPDATE users SET last_heartbeat = ? WHERE id = ?").run(new Date().toISOString(), req.user.id);
  res.json({ ack: true });
});

// Audit log endpoint (used by all frontend buttons)
router.post('/audit/log', requireAuth, (req, res) => {
  const { event, detail } = req.body;
  auditLog(req.app.locals.db, req.user?.id || 'system', event || 'ACTION', detail || '');
  res.json({ logged: true });
});

// Generic config save (used by various settings)
router.post('/config/save', requireAuth, requireRole('manager'), (req, res) => {
  const { key, value } = req.body;
  if (!key) return res.status(400).json({ error: 'Key required' });
  req.app.locals.db.prepare('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)').run(key, JSON.stringify(value || ''));
  auditLog(req.app.locals.db, req.user.id, 'CONFIG_SAVE', key);
  res.json({ saved: true });
});

module.exports = router;
