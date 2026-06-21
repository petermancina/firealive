// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Deployment Mode (D9)
//
// Reports and, on first run, provisions the deployment mode (bare-metal,
// virtualized, or cloud). Mounted at /api/deployment behind authMiddleware
// lead/admin.
// The mode is hardware-sealed by services/deployment-mode; this surface only
// reads it and offers a one-time provisioning path for operators who did not
// set FIREALIVE_DEPLOYMENT_MODE at boot. Provisioning is admin + MFA step-up
// and provisioning-only: setMode refuses to change an already-sealed mode, and
// the seal is anchor-bound, so this endpoint cannot flip a configured
// deployment to unlock the relaxed virtualization allowances.
//
// Cloud Mode provisioning additionally requires, fail-closed and before the
// seal, a verified confidential VM (services/cloud-attestation) and a non-spot,
// non-autoscaled instance (services/cloud-metadata). It records the selected
// platform, stable hostname, and dedicated-tenancy requirement, pins the launch
// measurement (TOFU), and persists the provision-time TCB floor via
// services/cloud-mode.
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
const cloudAttestation = require('../services/cloud-attestation');
const cloudMetadata = require('../services/cloud-metadata');
const cloudMode = require('../services/cloud-mode');

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
router.post('/provision', mfaStepUp(), async (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'admin role required' });
  }
  const mode = req.body && req.body.mode;
  const db = getDb();
  try {
    // Cloud Mode requires a verified confidential VM on a single stable
    // instance. Both are checked fail-closed BEFORE anything is sealed. The
    // cloud config is written before the seal so that a late seal failure
    // leaves only inert config, never a sealed-but-unconfigured cloud mode.
    if (mode === deploymentMode.CLOUD) {
      if (deploymentMode.isConfigured(db)) {
        return res.status(409).json({ error: 'deployment mode is already provisioned' });
      }
      const attestation = cloudAttestation.verifyAttestation();
      if (!attestation.verified) {
        return res.status(412).json({ error: 'cloud mode requires a confidential VM: ' + attestation.reason });
      }
      const meta = await cloudMetadata.readCloudMetadata();
      if (meta.spot === true) {
        return res.status(412).json({ error: 'cloud mode refuses spot or preemptible instances; use a standard on-demand instance' });
      }
      if (meta.autoscaled === true) {
        return res.status(412).json({ error: 'cloud mode refuses autoscaled or scale-set instances; deploy a single stable instance' });
      }
      const platform = req.body && req.body.platform;
      const stableHostname = req.body && req.body.stableHostname;
      const requireDedicatedTenancy = !!(req.body && req.body.requireDedicatedTenancy === true);
      cloudMode.setCloudConfig(db, { platform: platform, stableHostname: stableHostname, requireDedicatedTenancy: requireDedicatedTenancy });
      // TOFU-pin the launch measurement and persist the TCB floor at the
      // provision-time platform TCB, so a later boot cannot present a different
      // launch measurement or a rolled-back firmware TCB.
      if (attestation.measurement) cloudMode.pinMeasurement(db, attestation.measurement);
      const provisionFloor = attestation.tcb || attestation.tcbSvn || null;
      if (provisionFloor && cloudMode.TCB_TECHS.indexOf(attestation.tech) !== -1) {
        cloudMode.setTcbFloor(db, { tech: attestation.tech, floor: provisionFloor });
      }
      const result = deploymentMode.setMode(db, mode);
      cloudMode.recordAttestation(db, { tech: attestation.tech, tcb: attestation.tcb || attestation.tcbSvn || null, measurement: attestation.measurement || null, verified: attestation.verified, platformValidationPending: attestation.platformValidationPending });
      auditLog(req.user.id, 'DEPLOYMENT_MODE_PROVISIONED',
        'deployment mode sealed as ' + result.mode + ' on ' + platform + ' (cc ' + attestation.tech + ')', req.ip);
      return res.json(Object.assign({ ok: true, cloud: cloudMode.getCloudConfig(db) }, deploymentMode.summary(db)));
    }

    const result = deploymentMode.setMode(db, mode);
    auditLog(req.user.id, 'DEPLOYMENT_MODE_PROVISIONED', 'deployment mode sealed as ' + result.mode, req.ip);
    return res.json(Object.assign({ ok: true }, deploymentMode.summary(db)));
  } catch (err) {
    if (err.code === 'INVALID_MODE') return res.status(400).json({ error: err.message });
    if (err.code === 'INVALID_PLATFORM' || err.code === 'INVALID_HOSTNAME') return res.status(400).json({ error: err.message });
    if (err.code === 'MODE_ALREADY_SET') return res.status(409).json({ error: err.message });
    if (err.code === 'ANCHOR_REQUIRED') return res.status(503).json({ error: err.message });
    logger.error('deployment mode provisioning failed', { error: err.message });
    return res.status(500).json({ error: 'could not provision deployment mode' });
  } finally {
    db.close();
  }
});

module.exports = router;
