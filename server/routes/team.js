// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Team Routes (Management Console)
// All data is Tier-1: team-level aggregates, no individual burnout indicators
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');

// ── GET /api/team/overview — team health metrics ─────────────────────────────
router.get('/overview', (req, res) => {
  const db = getDb();
  const analysts = db.prepare('SELECT id, name, tier, shift, available FROM users WHERE role = ?').all('analyst');
  const caps = db.prepare('SELECT * FROM routing_caps').all();
  const lqCount = db.prepare('SELECT COUNT(*) as c FROM lighter_queue_requests WHERE status = ?').get('active');
  const autoSys = db.prepare('SELECT * FROM automation_systems').all();
  db.close();

  // Compute team health (Tier-1 aggregate only)
  const dayAnalysts = analysts.filter(a => a.shift === 'day' && a.available);
  const capsMap = Object.fromEntries(caps.map(c => [c.analyst_id, c]));

  res.json({
    analysts: analysts.map(a => ({
      id: a.id, name: a.name, tier: a.tier, shift: a.shift, available: !!a.available,
      maxComplexity: capsMap[a.id]?.max_complexity || 2,
      isOverride: !!capsMap[a.id]?.is_override,
    })),
    automationSystems: autoSys,
    activeLighterQueues: lqCount.c,  // anonymous count only
    dayShiftCount: dayAnalysts.length,
  });
});

// ── GET /api/team/analysts — full analyst list ───────────────────────────────
router.get('/analysts', (req, res) => {
  const db = getDb();
  const analysts = db.prepare(
    'SELECT id, name, tier, shift, available, created_at, last_login FROM users WHERE role = ? ORDER BY shift, tier DESC, name'
  ).all('analyst');
  db.close();
  res.json({ analysts });
});

// ── POST /api/team/provision — provision new analyst ─────────────────────────
router.post('/provision', (req, res) => {
  const { name, username, tier, shift, hostname, ip } = req.body;
  if (!name || !username || !tier || !shift) {
    return res.status(400).json({ error: 'name, username, tier, and shift are required' });
  }

  const bcrypt = require('bcryptjs');
  const crypto = require('crypto');
  const db = getDb();

  // Check for duplicate username
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    db.close();
    return res.status(409).json({ error: 'Username already exists' });
  }

  const tempPassword = crypto.randomBytes(12).toString('base64url');
  const id = crypto.randomBytes(16).toString('hex');
  const activationId = 'SCR-' + crypto.randomBytes(6).toString('hex').toUpperCase();

  db.prepare(
    'INSERT INTO users (id, username, password_hash, role, name, tier, shift) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, username, bcrypt.hashSync(tempPassword, 10), 'analyst', name, tier, shift);

  db.prepare(
    'INSERT INTO routing_caps (analyst_id, max_complexity) VALUES (?, ?)'
  ).run(id, tier === 3 ? 5 : tier === 2 ? 3 : 2);

  db.close();

  auditLog(req.user.id, 'ANALYST_PROVISIONED', `${name} · L${tier} · ${shift} · ${activationId}`, req.ip);

  res.status(201).json({
    id, name, username, tier, shift, activationId, tempPassword,
    message: 'Analyst provisioned. Provide the temporary password securely — it must be changed on first login.',
  });
});

// ── PUT /api/team/routing/:analystId — update routing cap ────────────────────
router.put('/routing/:analystId', (req, res) => {
  const { maxComplexity, isOverride, overrideReason } = req.body;
  const { analystId } = req.params;

  const db = getDb();
  db.prepare(
    'UPDATE routing_caps SET max_complexity = ?, is_override = ?, override_reason = ?, override_by = ?, updated_at = datetime("now") WHERE analyst_id = ?'
  ).run(maxComplexity, isOverride ? 1 : 0, overrideReason || null, req.user.id, analystId);
  db.close();

  auditLog(req.user.id, 'ROUTING_CAP_UPDATED', `analyst=${analystId} cap=${maxComplexity}`, req.ip);
  res.json({ ok: true });
});

module.exports = router;
