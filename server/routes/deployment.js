// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Deployment Mode (D9)
//
// Reports and, on first run, provisions the deployment mode (bare-metal vs
// virtualized). Mounted at /api/deployment behind authMiddleware lead/admin.
// The mode is hardware-sealed by services/deployment-mode; this surface only
// reads it and offers a one-time provisioning path for operators who did not
// set FIREALIVE_DEPLOYMENT_MODE at boot. Provisioning is admin + MFA step-up
// and provisioning-only: setMode refuses to change an already-sealed mode, and
// the seal is anchor-bound, so this endpoint cannot flip a configured
// deployment to unlock the relaxed virtualization allowances.
//
// Endpoints:
//   GET  /            current deployment-mode summary
//   POST /provision   seal the mode on a not-yet-configured deployment
// ═══════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { mfaStepUp } = require('../middleware/mfa-stepup');
const deploymentMode = require('../services/deployment-mode');

// GET / ────────────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const db = getDb();
  try {
    return res.json(deploymentMode.summary(db));
  } catch (err) {
    logger.error('deployment mode read failed', { error: err.message });
    return res.status(500).json({ error: 'could not read deployment mode' });
  } finally {
    db.close();
  }
});

// POST /provision ──────────────────────────────────────────────────────────
router.post('/provision', mfaStepUp(), (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin role required' });
  }
  const mode = req.body && req.body.mode;
  const db = getDb();
  try {
    const result = deploymentMode.setMode(db, mode);
    auditLog(req.user.id, 'DEPLOYMENT_MODE_PROVISIONED', 'deployment mode sealed as ' + result.mode, req.ip);
    return res.json(Object.assign({ ok: true }, deploymentMode.summary(db)));
  } catch (err) {
    if (err.code === 'INVALID_MODE') return res.status(400).json({ error: err.message });
    if (err.code === 'MODE_ALREADY_SET') return res.status(409).json({ error: err.message });
    if (err.code === 'ANCHOR_REQUIRED') return res.status(503).json({ error: err.message });
    logger.error('deployment mode provisioning failed', { error: err.message });
    return res.status(500).json({ error: 'could not provision deployment mode' });
  } finally {
    db.close();
  }
});

module.exports = router;
