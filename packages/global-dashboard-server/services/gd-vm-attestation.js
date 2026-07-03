// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- VM Attestation (D11, B6c)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// Mode-gated pre-auth gate for easily-copied substrates. On a virtualized or
// cloud substrate -- virtualized mode, cloud mode, or an SDN/SASE deployment
// sealed on either -- a GD instance flagged as quarantined (a clone, fork, or
// rollback recorded on gd_instance_identity by the anti-cloning path) is
// high-risk: VMs and cloud images are trivially snapshotted and copied, so we
// refuse the ENTIRE surface here, before auth, rather than only privileged
// actions. A cloud substrate additionally refuses the surface when the
// confidential VM was not verified at boot. In bare-metal, an SDN/SASE
// deployment on bare metal, or unconfigured mode this is a pass-through: the
// fail-closed boot anchor (a clone on different hardware halts at startup) and
// the machine-bound hardware root are the primary defense, and the PoP
// clock-integrity gate covers snapshot-rollback of time-windowed operations.
//
// This is the GD-server twin of the Regional Server's vm-attestation gate.
// Mount globally at /api/, before the GD auth middleware. Reads the deployment
// mode and the boot confidential-computing result from the startup snapshot on
// app.locals (cheap, no anchor or TPM access) and the GD instance status via a
// short-lived DB read, exactly as the Regional Server reads its instance status.
// -----------------------------------------------------------------------------

const { getDb } = require('../db-init');

// Cheap per-request read of the GD instance quarantine status. The B5e GD anchor
// records status 'active' or 'quarantined' on gd_instance_identity; the
// anti-cloning path flips it to 'quarantined'. Mirrors the Regional Server's
// readInstanceStatus. Opens a short-lived connection and ALWAYS closes it in a
// finally (connection hygiene: getDb returns a new handle per call).
function readGdInstanceStatus() {
  const db = getDb();
  try {
    const row = db.prepare("SELECT status FROM gd_instance_identity ORDER BY id LIMIT 1").get();
    return row ? row.status : null;
  } finally {
    db.close();
  }
}

function gdVmAttestation() {
  return function (req, res, next) {
    let mode;
    try {
      mode = (req.app && req.app.locals && req.app.locals.gdDeploymentMode) || {};
    } catch (_e) {
      mode = {};
    }
    // The deployment-mode summary on app.locals carries the substrate-effective
    // gate: easilyCopied is true for a virtualized or cloud substrate (cloud
    // mode, virtualized mode, or an SDN/SASE deployment sealed on either).
    const easilyCopied = mode.easilyCopied === true;
    // Bare-metal, SDN/SASE on bare metal, or unconfigured: no-op. The fail-closed
    // boot anchor and the machine-bound hardware root still apply.
    if (!easilyCopied) {
      return next();
    }
    const modeLabel = mode.substrateCloud ? 'cloud' : (mode.substrateVirtualized ? 'virtualized' : (mode.mode || 'unknown'));
    const ccRequired = mode.ccRequired === true;
    let status;
    try {
      status = readGdInstanceStatus();
    } catch (err) {
      // Attestation is required on an easily-copied substrate; fail closed on a
      // read fault. Per-request, so a transient fault makes the client retry --
      // it does not silently lower the bar.
      console.error('[gd-vm-attestation] instance status read failed; failing closed: ' + err.message);
      return res.status(503).json({ error: 'attestation unavailable' });
    }
    if (status === 'quarantined') {
      console.warn('[gd-vm-attestation] refused: ' + modeLabel + ' GD instance is quarantined');
      return res.status(503).json({ error: 'This ' + modeLabel + ' Global Dashboard deployment is quarantined (possible clone, fork, or rollback). Access is suspended until the instance identity is re-established.' });
    }
    // A confidential VM verified at boot is additionally required on a cloud
    // substrate (cloud mode or SDN/SASE + cloud). The Cloud Mode boot wiring
    // records the result on app.locals.gdCloudAttestation; a missing or
    // unverified result refuses the surface. This is a cheap app.locals read --
    // the authoritative boot gate already fails closed when confidential
    // computing is not verified. Until the Cloud Mode PR lands, a sealed cloud
    // mode has no attestation result and this fails closed, which is the safe
    // direction.
    if (ccRequired) {
      let cc;
      try {
        cc = (req.app && req.app.locals && req.app.locals.gdCloudAttestation) || null;
      } catch (_e) {
        cc = null;
      }
      if (!cc || cc.verified !== true) {
        console.warn('[gd-vm-attestation] refused: ' + modeLabel + ' GD confidential computing not verified');
        return res.status(503).json({ error: 'This ' + modeLabel + ' Global Dashboard deployment is not running on a verified confidential VM. Access is suspended.' });
      }
    }
    return next();
  };
}

module.exports = { gdVmAttestation };
