// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — VM Attestation (D11, B5i)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// Mode-gated pre-auth gate for easily-copied substrates. In VIRTUALIZED or
// CLOUD mode -- and in SDN mode when the instance is cloud-resident -- an
// instance flagged as quarantined (a clone, fork, or rollback detected by
// observers) is high-risk -- VMs and cloud images are trivially snapshotted and
// copied -- so we refuse the ENTIRE surface here, before auth, rather than only
// privileged actions. CLOUD mode, and cloud-resident SDN, additionally refuse
// the surface when the confidential VM was not verified at boot. In bare-metal,
// onsite SDN, or unconfigured mode this is a pass-through: the existing
// quarantine guard still covers privileged actions, and the machine-bound
// hardware anchor is the primary defense.
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
    // Cloud-resident sdn shares cloud's easily-copied substrate, so it is gated
    // here too (D-B5i-2). The boot wiring records this on app.locals.
    let sdnCloudResident;
    try {
      sdnCloudResident = !!(req.app && req.app.locals && req.app.locals.sdnCloudResident);
    } catch (_e) {
      sdnCloudResident = false;
    }
    const easilyCopied = mode.virtualized || mode.cloud || (mode.sdn && sdnCloudResident);
    // Bare-metal, onsite sdn, or unconfigured: no-op. The narrower quarantine
    // guard and the machine-bound anchor still apply.
    if (!easilyCopied) {
      return next();
    }
    const modeLabel = mode.cloud ? 'cloud' : (mode.virtualized ? 'virtualized' : 'sdn');
    const ccRequired = mode.cloud || (mode.sdn && sdnCloudResident);
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
    // A confidential VM verified at boot is additionally required for cloud and
    // for cloud-resident sdn (cloud-attestation). The boot wiring records the
    // result on app.locals; a missing or unverified result refuses the surface.
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
