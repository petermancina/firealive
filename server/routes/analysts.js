// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Analyst Routes (Analyst Client)
// All data is Tier-3: private, encrypted, never visible to management
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { encryptTier3, decryptTier3 } = require('../services/encryption');
const { auditLog } = require('../middleware/audit');

// ── GET /api/analysts/signals — my signals (Tier-3 encrypted) ────────────────
router.get('/signals', (req, res) => {
  const db = getDb();
  const rows = db.prepare(
    'SELECT signals_encrypted, risk_tier, recorded_at FROM analyst_signals WHERE analyst_id = ? ORDER BY recorded_at DESC LIMIT 30'
  ).all(req.user.id);
  db.close();

  const signals = rows.map(r => ({
    ...decryptTier3(r.signals_encrypted),
    riskTier: r.risk_tier,
    recordedAt: r.recorded_at,
  }));

  res.json({ signals });
});

// ── POST /api/analysts/signals — record signals from client sensors ──────────
router.post('/signals', (req, res) => {
  const { investigationTime, dismissRate, ticketQuality, escalationRate } = req.body;
  const db = getDb();

  const data = { investigationTime, dismissRate, ticketQuality, escalationRate };
  const encrypted = encryptTier3(data);

  // Compute risk tier from signals (Tier-1 aggregate)
  // This is the ONLY thing management can see — the tier label, not the values
  let riskTier = 'stable';
  if (investigationTime > 30 || dismissRate > 25 || ticketQuality < 60 || escalationRate > 20) {
    riskTier = 'elevated';
  } else if (investigationTime > 25 || dismissRate > 18 || ticketQuality < 70 || escalationRate > 15) {
    riskTier = 'watch';
  }

  db.prepare(
    'INSERT INTO analyst_signals (analyst_id, signals_encrypted, risk_tier) VALUES (?, ?, ?)'
  ).run(req.user.id, encrypted, riskTier);

  db.close();
  res.json({ riskTier });
});

// ── POST /api/analysts/lighter-queue — request lighter queue (anonymous) ─────
router.post('/lighter-queue', (req, res) => {
  const { duration, maxComplexity, reason } = req.body;
  const db = getDb();
  const crypto = require('crypto');

  // Encrypt analyst ID so management can never see who requested
  const analystEncrypted = encryptTier3(req.user.id);

  // Calculate expiry
  const durationMap = { '1_shift': 8, '24hr': 24, '72hr': 72, '1_week': 168 };
  const hours = durationMap[duration] || 8;
  const expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();

  db.prepare(
    'INSERT INTO lighter_queue_requests (duration, max_complexity, analyst_id_encrypted, expires_at) VALUES (?, ?, ?, ?)'
  ).run(duration, maxComplexity || 2, analystEncrypted, expiresAt);

  // Also update routing cap (this IS visible but is attributed to "anonymous request")
  db.prepare(
    'UPDATE routing_caps SET max_complexity = MIN(max_complexity, ?), updated_at = datetime("now") WHERE analyst_id = ?'
  ).run(maxComplexity || 2, req.user.id);

  db.close();

  // Audit log does NOT include analyst identity
  auditLog(null, 'LIGHTER_QUEUE_REQUEST', `duration=${duration} cap=${maxComplexity}`, req.ip);
  res.json({ ok: true, expiresAt });
});

// ── GET /api/analysts/consent-log — my consent trail ─────────────────────────
router.get('/consent-log', (req, res) => {
  const db = getDb();
  const entries = db.prepare(
    'SELECT action, detail, created_at FROM analyst_consent_log WHERE analyst_id = ? ORDER BY created_at DESC LIMIT 100'
  ).all(req.user.id);
  db.close();
  res.json({ entries });
});

// ── POST /api/analysts/consent — log consent event ───────────────────────────
router.post('/consent', (req, res) => {
  const { action, detail } = req.body;
  const db = getDb();
  db.prepare(
    'INSERT INTO analyst_consent_log (analyst_id, action, detail) VALUES (?, ?, ?)'
  ).run(req.user.id, action, detail || 'Anonymous — no name/signals transmitted');
  db.close();
  res.json({ ok: true });
});

module.exports = router;
