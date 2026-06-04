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

  const crypto = require('crypto');
  const db = getDb();

  // Check for duplicate username
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) {
    db.close();
    return res.status(409).json({ error: 'Username already exists' });
  }

  const id = crypto.randomBytes(16).toString('hex');
  const activationId = 'SCR-' + crypto.randomBytes(6).toString('hex').toUpperCase();

  // Passwordless-first: no password is set. The analyst enrolls a passkey by
  // redeeming the enrollment token minted below.
  db.prepare(
    'INSERT INTO users (id, username, role, name, tier, shift) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, username, 'analyst', name, tier, shift);

  db.prepare(
    'INSERT INTO routing_caps (analyst_id, max_complexity) VALUES (?, ?)'
  ).run(id, tier === 3 ? 5 : tier === 2 ? 3 : 2);

  // Mint a single-use enrollment token (SHA-256 hash at rest; plaintext shown
  // once). The analyst redeems it to enroll their first passkey. Expiry is
  // stored in SQLite datetime format so it compares correctly at redemption.
  const enrollmentToken = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(enrollmentToken).digest('hex');
  db.prepare(
    "INSERT INTO enrollment_tokens (user_id, token_hash, expires_at, created_by, scope) VALUES (?, ?, datetime('now', '+7 days'), ?, 'first-credential')"
  ).run(id, tokenHash, req.user.id);

  db.close();

  auditLog(req.user.id, 'ANALYST_PROVISIONED', `${name} · L${tier} · ${shift} · ${activationId}`, req.ip);

  res.status(201).json({
    id, name, username, tier, shift, activationId,
    enrollmentToken,
    enrollmentExpiresInDays: 7,
    enrollEndpoint: '/api/auth/enroll/passkey/options',
    message: 'Analyst provisioned. Provide the enrollment token securely — the analyst redeems it once to enroll their first passkey. It expires in 7 days and can be used only once.',
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
