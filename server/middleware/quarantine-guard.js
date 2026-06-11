// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Quarantine Guard Middleware (Anti-Cloning)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Express middleware (B5e, decision D5). Refuses privileged actions when this
// deployment instance identity has been quarantined -- the status set when the
// AC ratchet, the GD collision check, or the boot-time fuse high-water detects
// a clone, fork, or rollback. A quarantined deployment is one we no longer
// trust to mint long-lived material or approve sensitive operations, so the
// guard is applied (after auth) to the privileged routes that matter.
//
// USAGE
//
//   const { quarantineGuard } = require('../middleware/quarantine-guard');
//   const { authMiddleware } = require('../middleware/auth');
//
//   router.post('/sensitive',
//     authMiddleware(['admin']),
//     quarantineGuard(),
//     handler);
//
// FAIL-OPEN ON A CHECK ERROR: the guard reads instance_identity.status; if that
// read itself fails it allows the request through (logged) rather than bricking
// every privileged path on a transient DB error -- the action own DB use will
// surface real problems, and the boot halt plus the loud quarantine alert are
// the primary controls. It fails CLOSED only on a definitive quarantined status.

const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const QUARANTINED = 'quarantined';

// Read this deployment instance status ('active' | 'quarantined'), or null if
// no identity row exists yet (pre-establishment boots are not blocked).
function readInstanceStatus() {
  const db = getDb();
  try {
    const row = db.prepare("SELECT status FROM instance_identity ORDER BY id LIMIT 1").get();
    return row ? row.status : null;
  } finally {
    db.close();
  }
}

function quarantineGuard() {
  return (req, res, next) => {
    let status;
    try {
      status = readInstanceStatus();
    } catch (err) {
      logger.warn('Quarantine guard status check failed; allowing request', { error: err.message });
      return next();
    }
    if (status === QUARANTINED) {
      logger.error('Privileged action refused: instance is quarantined', {
        path: req.path,
        userId: req.user && req.user.id ? req.user.id : null,
      });
      return res.status(403).json({
        error: 'This deployment is quarantined because a possible clone, fork, or rollback was detected. Privileged actions are disabled until the instance identity is re-established.',
        code: 'INSTANCE_QUARANTINED',
      });
    }
    return next();
  };
}

module.exports = { quarantineGuard, readInstanceStatus };
