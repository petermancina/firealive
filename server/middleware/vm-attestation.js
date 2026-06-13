// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — VM Attestation (D11)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// Mode-gated pre-auth gate for the virtualization split. In VIRTUALIZED mode a
// virtualized instance flagged as quarantined (a clone, fork, or rollback
// detected by observers) is high-risk -- VMs are trivially snapshotted and
// copied -- so we refuse the ENTIRE surface here, before auth, rather than only
// privileged actions. In bare-metal or unconfigured mode this is a
// pass-through: the existing quarantine guard still covers privileged actions,
// and the machine-bound hardware anchor is the primary defense.
//
// Mount globally, before the auth middleware. Reads the deployment mode from
// the startup snapshot on app.locals (cheap, no anchor or TPM access) and the
// instance status via the shared quarantine helper.
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
    // Bare-metal or unconfigured: no-op. The narrower quarantine guard and the
    // machine-bound anchor still apply.
    if (!mode.virtualized) {
      return next();
    }
    let status;
    try {
      status = readInstanceStatus();
    } catch (err) {
      // Attestation is required in virtualized mode; fail closed on a read
      // fault. This is per-request -- a transient fault makes the client retry,
      // it does not silently lower the bar.
      logger.error('VM attestation status read failed; failing closed', { error: err.message });
      return res.status(503).json({ error: 'attestation unavailable' });
    }
    if (status === 'quarantined') {
      logger.warn('VM attestation refused: virtualized instance is quarantined');
      return res.status(503).json({ error: 'This virtualized deployment is quarantined (possible clone, fork, or rollback). Access is suspended until the instance identity is re-established.' });
    }
    return next();
  };
}

module.exports = { vmAttestation };
