// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — VM Attestation (D11, B5i)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// Mode-gated pre-auth gate for easily-copied substrates. On a virtualized or
// cloud substrate -- virtualized mode, cloud mode, or an SDN deployment sealed
// on either -- an instance flagged as quarantined (a clone, fork, or rollback
// detected by observers) is high-risk -- VMs and cloud images are trivially
// snapshotted and copied -- so we refuse the ENTIRE surface here, before auth,
// rather than only privileged actions. A cloud substrate additionally refuses
// the surface when the confidential VM was not verified at boot. In bare-metal,
// an SDN deployment on bare metal, or unconfigured mode this is a pass-through:
// the existing quarantine guard still covers privileged actions, and the
// machine-bound hardware anchor is the primary defense.
//
// Mount globally, before the auth middleware. Reads the deployment mode and the
// boot confidential-computing result from the startup snapshot on app.locals
// (cheap, no anchor or TPM access) and the instance status via the shared
// quarantine helper.
// ═══════════════════════════════════════════════════════════════════════════

const { logger } = require('../services/logger');
const { readInstanceStatus } = require('./quarantine-guard');

function vmAttestation() {
  return function (req, res, next) {
    let mode;
    try {
      mode = (req.app && req.app.locals && req.app.locals.deploymentMode) || {};
    } catch (_e) {
      mode = {};
    }
    // The deployment-mode summary on app.locals carries the substrate-effective
    // gate: easilyCopied is true for a virtualized or cloud substrate (cloud
    // mode, virtualized mode, or an SDN deployment sealed on either). B5i2.
    const easilyCopied = mode.easilyCopied === true;
    // Bare-metal, SDN on bare metal, or unconfigured: no-op. The narrower
    // quarantine guard and the machine-bound anchor still apply.
    if (!easilyCopied) {
      return next();
    }
    const modeLabel = mode.substrateCloud ? 'cloud' : (mode.substrateVirtualized ? 'virtualized' : (mode.mode || 'unknown'));
    const ccRequired = mode.ccRequired === true;
    let status;
    try {
      status = readInstanceStatus();
    } catch (err) {
      // Attestation is required on an easily-copied substrate; fail closed on a
      // read fault. This is per-request -- a transient fault makes the client
      // retry, it does not silently lower the bar.
      logger.error('VM attestation status read failed; failing closed', { error: err.message });
      return res.status(503).json({ error: 'attestation unavailable' });
    }
    if (status === 'quarantined') {
      logger.warn('VM attestation refused: ' + modeLabel + ' instance is quarantined');
      return res.status(503).json({ error: 'This ' + modeLabel + ' deployment is quarantined (possible clone, fork, or rollback). Access is suspended until the instance identity is re-established.' });
    }
    // A confidential VM verified at boot is additionally required on a cloud
    // substrate (cloud mode or SDN+cloud). The boot wiring records the result on
    // app.locals; a missing or unverified result refuses the surface.
    // This is a cheap app.locals read -- the authoritative boot gate already
    // fails closed when confidential computing is not verified.
    if (ccRequired) {
      let cc;
      try {
        cc = (req.app && req.app.locals && req.app.locals.cloudAttestation) || null;
      } catch (_e) {
        cc = null;
      }
      if (!cc || cc.verified !== true) {
        logger.warn('VM attestation refused: ' + modeLabel + ' instance confidential computing not verified');
        return res.status(503).json({ error: 'This ' + modeLabel + ' deployment is not running on a verified confidential VM. Access is suspended.' });
      }
    }
    return next();
  };
}

module.exports = { vmAttestation };
