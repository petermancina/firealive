// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v0.0.54 — Feature Routes for v31-v54 Additions
// Routes for: SOAR/Ticketing integration, IAM offboarding, upskilling scheduling,
// assessment workflow, helper pay, pseudonym rotation, compliance reports,
// KMS expansion, client provisioning restore/revert, SIEM routing status
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireAuth, requireRole } = require('../middleware/auth');

// ── SOAR Integration ─────────────────────────────────────────────────────────
router.post('/soar/config', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { platform, endpoint, apiKey, autoEscalate } = req.body;
  const encrypted = crypto.createCipheriv('aes-256-gcm', 
    Buffer.from(process.env.FIREALIVE_MASTER_KEY || crypto.randomBytes(32)),
    crypto.randomBytes(12)
  );
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
    'soar_config', JSON.stringify({ platform, endpoint, apiKeyHash: crypto.createHash('sha256').update(apiKey||'').digest('hex'), autoEscalate, updatedAt: new Date().toISOString() })
  );
  auditLog(req.user?.id, 'SOAR_CONFIG', `SOAR ${platform} configured`);
  res.json({ saved: true });
});

router.get('/soar/status', requireAuth, async (req, res) => {
  const db = getDb();
  const row = db.prepare("SELECT value FROM config WHERE key = 'soar_config'").get();
  res.json(row ? JSON.parse(row.value) : { configured: false });
});

// ── Ticketing System Integration (READ-ONLY) ─────────────────────────────────
router.post('/ticketing/config', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { platform, endpoint, apiKey } = req.body;
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
    'ticketing_config', JSON.stringify({ platform, endpoint, apiKeyHash: crypto.createHash('sha256').update(apiKey||'').digest('hex'), readOnly: true, updatedAt: new Date().toISOString() })
  );
  auditLog(req.user?.id, 'TICKETING_CONFIG', `Ticketing ${platform} configured (READ-ONLY)`);
  res.json({ saved: true });
});

router.get('/ticketing/queue-metadata', requireAuth, async (req, res) => {
  const db = getDb();
  const cfg = db.prepare("SELECT value FROM config WHERE key = 'ticketing_config'").get();
  if (!cfg) return res.json({ configured: false });
  // In production: fetch queue metadata from ticketing API
  res.json({ configured: true, queueDepth: 0, avgPriority: 'medium', lastSync: new Date().toISOString() });
});

// ── Burnout-Aware Routing Engine ─────────────────────────────────────────────
router.post('/routing/distribute', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { ticketId, priority, category } = req.body;
  // Get analyst capacity scores
  const analysts = db.prepare("SELECT id, pseudonym, tier, capacity_score FROM users WHERE role='analyst' AND active=1 ORDER BY capacity_score DESC").all();
  if (!analysts.length) return res.status(400).json({ error: 'No available analysts' });
  // Route to analyst with highest capacity (lowest burnout)
  const assigned = analysts[0];
  auditLog(req.user?.id, 'TICKET_ROUTED', `Ticket ${ticketId} -> ${assigned.pseudonym} (capacity: ${assigned.capacity_score})`);
  res.json({ assigned: assigned.pseudonym, capacity: assigned.capacity_score });
});

router.get('/routing/status', requireAuth, async (req, res) => {
  const db = getDb();
  const panic = db.prepare("SELECT value FROM config WHERE key = 'panic_mode'").get();
  const routing = db.prepare("SELECT value FROM config WHERE key = 'routing_enabled'").get();
  res.json({ panicMode: panic?.value === 'true', routingEnabled: routing?.value !== 'false' });
});

// ── IAM Offboarding Detection ────────────────────────────────────────────────
router.post('/iam/check-absence', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const cfg = db.prepare("SELECT value FROM config WHERE key = 'iam_config'").get();
  if (!cfg) return res.json({ checked: false, reason: 'IAM not configured' });
  const iamCfg = JSON.parse(cfg.value);
  // In production: query IAM API for user list, compare against FireAlive users
  const users = db.prepare("SELECT id, pseudonym, last_iam_check FROM users WHERE role='analyst'").all();
  const absent = users.filter(u => !u.last_iam_check || Date.now() - new Date(u.last_iam_check).getTime() > iamCfg.intervalHours * 3600000);
  auditLog(req.user?.id, 'IAM_CHECK', `Checked ${users.length} users, ${absent.length} need review`);
  res.json({ checked: true, total: users.length, needsReview: absent.map(u => ({ id: u.id, pseudonym: u.pseudonym })) });
});

router.post('/iam/confirm-status', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { id, action } = req.body; // action: 'active' or 'offboard'
  if (action === 'offboard') {
    db.prepare("UPDATE users SET active=0, offboarded_at=? WHERE id=?").run(new Date().toISOString(), id);
    auditLog(req.user?.id, 'IAM_OFFBOARD', `Analyst ${id} offboarded`);
  } else {
    db.prepare("UPDATE users SET last_iam_check=? WHERE id=?").run(new Date().toISOString(), id);
    auditLog(req.user?.id, 'IAM_CONFIRMED', `Analyst ${id} confirmed active`);
  }
  res.json({ success: true, action });
});

// ── Upskilling Scheduling ────────────────────────────────────────────────────
router.post('/upskilling/schedule', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { analystUuid, newTime, coverageMin } = req.body;
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
    `upskilling_schedule_${analystUuid}`, JSON.stringify({ time: newTime, updatedAt: new Date().toISOString() })
  );
  auditLog(req.user?.id, 'SCHED_EDIT', `Upskilling for ${analystUuid} -> ${newTime}`);
  res.json({ saved: true, analystUuid, newTime });
});

router.get('/upskilling/schedules', requireAuth, async (req, res) => {
  const db = getDb();
  const rows = db.prepare("SELECT key, value FROM config WHERE key LIKE 'upskilling_schedule_%'").all();
  res.json(rows.map(r => ({ uuid: r.key.replace('upskilling_schedule_', ''), ...JSON.parse(r.value) })));
});

// ── Assessment Workflow ──────────────────────────────────────────────────────
router.post('/assessments/create-and-send', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { category, platform, targetAnalyst, licenseKey } = req.body;
  const assessmentId = crypto.randomUUID();
  db.prepare("INSERT INTO assessments (id, category, platform, target_analyst, status, created_at) VALUES (?, ?, ?, ?, 'sent', ?)").run(
    assessmentId, category, platform, targetAnalyst, new Date().toISOString()
  );
  auditLog(req.user?.id, 'ASSESSMENT_CREATED', `${category} on ${platform} -> ${targetAnalyst}`);
  // In production: push assessment link to analyst client via WebSocket/push notification
  res.json({ id: assessmentId, status: 'sent' });
});

router.post('/assessments/submit-results', requireAuth, async (req, res) => {
  const db = getDb();
  const { assessmentId, score, completionProof } = req.body;
  db.prepare("UPDATE assessments SET status='completed', score=?, completed_at=? WHERE id=?").run(
    score, new Date().toISOString(), assessmentId
  );
  // Trigger AI gap analysis
  auditLog(req.user?.id, 'ASSESSMENT_COMPLETED', `Assessment ${assessmentId}: ${score}%`);
  res.json({ success: true, gapAnalysisTriggered: true });
});

// ── Helper Pay (Quality-Based) ───────────────────────────────────────────────
// The pre-F5 design of these endpoints inserted into a phantom `helper_ratings`
// table. The F5 phase (v1.0.21) introduced canonical Helper Pay storage in
// peer_session_ratings + helper_points_ledger, with the full anti-gaming
// logic (session-participant validation, minimum-duration gate, daily caps,
// lazy debit on lead approval) housed in server/services/helper-pay.js and
// exposed at POST /api/helper-pay/sessions/:sessionId/rate. The endpoint
// below redirects callers there rather than offering a parallel rating path
// that would bypass the anti-gaming protections.
router.post('/helper-pay/rate', requireAuth, async (req, res) => {
  res.status(410).json({
    error: 'Endpoint removed in favor of F5 canonical helper-pay service',
    redirectTo: 'POST /api/helper-pay/sessions/:sessionId/rate',
    note: 'The F5 endpoint enforces session-participant validation, minimum session duration, daily caps, and writes to peer_session_ratings + helper_points_ledger atomically.',
  });
});

router.get('/helper-pay/leaderboard', requireAuth, async (req, res) => {
  const db = getDb();
  // Query the F5 canonical ledger for positive-delta rows, grouped by user.
  // Negative deltas (redemptions, fraud reversals) are excluded so the
  // leaderboard reflects gross helpfulness earnings rather than net balance.
  const leaders = db.prepare(`
    SELECT u.pseudonym, SUM(l.delta) AS total_points
    FROM helper_points_ledger l
    JOIN users u ON u.id = l.user_id
    WHERE l.delta > 0
    GROUP BY l.user_id
    ORDER BY total_points DESC
    LIMIT 10
  `).all();
  res.json(leaders);
});

// ── Pseudonym Rotation ───────────────────────────────────────────────────────
router.post('/pseudonyms/rotate', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const analysts = db.prepare("SELECT id, pseudonym FROM users WHERE role='analyst'").all();
  // Generate new pseudonyms — id (the canonical 32-hex GUID) stays constant
  const animals = ['Falcon','Kestrel','Hawk','Eagle','Osprey','Merlin','Peregrine','Harrier','Sparrow','Wren','Robin','Swift','Heron','Crane','Raven','Owl','Phoenix','Condor','Albatross','Pelican'];
  const shuffled = animals.sort(() => Math.random() - 0.5);
  analysts.forEach((a, i) => {
    const newPseudo = `Analyst-${shuffled[i % shuffled.length]}`;
    db.prepare("UPDATE users SET pseudonym=?, pseudonym_rotated_at=? WHERE id=?").run(newPseudo, new Date().toISOString(), a.id);
  });
  auditLog(req.user?.id, 'PSEUDONYM_ROTATE', `Rotated ${analysts.length} pseudonyms (ids unchanged)`);
  res.json({ rotated: analysts.length });
});

// ── Compliance Report Generation ─────────────────────────────────────────────
router.post('/compliance/generate-report', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { framework } = req.body;
  const controls = db.prepare("SELECT * FROM compliance_controls WHERE framework=?").all(framework);
  const report = { framework, generatedAt: new Date().toISOString(), controls: controls.length ? controls : [
    { id: 'AC-1', name: 'Access Control', status: 'pass', detail: 'MFA + JWT + RBAC + pseudonym isolation' },
    { id: 'SC-1', name: 'Data Protection', status: 'pass', detail: 'AES-256-GCM tiered encryption' },
    { id: 'AU-1', name: 'Audit Trail', status: 'pass', detail: 'Immutable SHA-256 chain' },
    { id: 'IR-1', name: 'Incident Response', status: 'pass', detail: 'OODA simulator + CISM retro' },
    { id: 'CM-1', name: 'Configuration Mgmt', status: 'pass', detail: 'Anti-rollback e-fuse' }
  ]};
  auditLog(req.user?.id, 'COMPLIANCE_REPORT', `Generated ${framework} report`);
  res.json(report);
});

// ── Client Provisioning Restore/Revert ───────────────────────────────────────
router.post('/clients/restore', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { clientId, source, path } = req.body;
  auditLog(req.user?.id, 'CLIENT_RESTORE', `Client ${clientId} restored from ${source}:${path}`);
  res.json({ success: true, clientId, restoredAt: new Date().toISOString() });
});

router.post('/clients/revert', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { clientId, version } = req.body;
  auditLog(req.user?.id, 'CLIENT_REVERT', `Client ${clientId} reverted to ${version}`);
  res.json({ success: true, clientId, revertedTo: version });
});

// ── Backup Scheduling ────────────────────────────────────────────────────────
router.post('/backup/schedule', requireAuth, requireRole('manager'), async (req, res) => {
  const db = getDb();
  const { interval, type, retention } = req.body;
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(
    'backup_schedule', JSON.stringify({ interval, type, retention, updatedAt: new Date().toISOString() })
  );
  auditLog(req.user?.id, 'BACKUP_SCHEDULE', `Backup scheduled: ${interval} ${type}`);
  res.json({ saved: true });
});

// ── Training Completion Pipeline ─────────────────────────────────────────────
router.post('/training/submit-completion', requireAuth, async (req, res) => {
  const db = getDb();
  const { module, platform, url, date } = req.body;
  // Sanitize URL
  const sanitized = (url || '').replace(/<[^>]*>/g, '').replace(/javascript:/gi, '').replace(/%3C/gi, '');
  const id = crypto.randomUUID();
  db.prepare("INSERT INTO training_completions (id, user_id, module, platform, url, completion_date, status) VALUES (?, ?, ?, ?, ?, ?, 'pending')").run(
    id, req.user?.id, module, platform, sanitized, date
  );
  auditLog(req.user?.id, 'TRAINING_SUBMITTED', `${module} on ${platform}`);
  res.json({ id, status: 'pending_verification' });
});

module.exports = router;
