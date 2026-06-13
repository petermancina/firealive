// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE — Migration Identity Re-establishment (FA-MIG1) (D14 / 5b)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The section 5b rule: a migration import must NOT carry the source
// deployment's instance identity, because verbatim identity restore is
// indistinguishable from cloning. After the source's data has been restored,
// the restored database still holds the source's instance-level identity;
// this module wipes it and mints a FRESH identity on the target.
//
// Instance-level identity is exactly five tables:
//   - enrollment_tokens ........ outstanding enrollment (now invalid)
//   - issued_certs ............. certificates issued under the old CA
//   - ac_device_signing_keys ... analyst-client device keys (must re-enroll)
//   - ca_authority ............. the deployment CA
//   - instance_identity ........ the hardware-rooted anchor
//
// No other table references these by foreign key, so clearing them cannot
// cascade into analyst or operational data. Everything else is PRESERVED:
// per-analyst burnout keys and recovery wraps (user-bound, so they survive an
// identity reset and stay recoverable via the offline recovery code); the
// audit, forensic, and legal-hold chains; team and system config and sealed
// history; and training / helper-pay records.
//
// Re-minting reuses the same provisioning the suite runs at first boot:
// instance-anchor establish (a fresh hardware-rooted anchor) and ca initCa +
// issueServerCert (a fresh CA and server certificate). Analyst clients re-bind
// to the new identity afterward through the authenticated teardown /
// reprovision ceremony.
//
// This runs against the already-restored database (the data restore swaps the
// database file and requires a restart, so identity is re-established after
// that, against the restored database). It is the post-restore step of the
// migration apply, not the apply in full.
// ─────────────────────────────────────────────────────────────────────────────

const { logger } = require('./logger');
const anchorSvc = require('./instance-anchor');
const caSvc = require('./ca');

// Order is cosmetic: no foreign key references any of these tables, so the
// wipe cannot cascade. Children-before-parents is kept for readability.
const IDENTITY_TABLES = [
  'enrollment_tokens',
  'issued_certs',
  'ac_device_signing_keys',
  'ca_authority',
  'instance_identity',
];

// What this module deliberately leaves untouched. Surfaced in the report so
// an operator can see, at apply time, exactly what is preserved.
const PRESERVED = [
  'per-analyst burnout keys and recovery wraps',
  'audit, forensic, and legal-hold chains',
  'team and system config and sealed history',
  'training and helper-pay records',
];

// ─────────────────────────────────────────────────────────────────────────────
// clearSourceIdentity(db)
//
// Transactionally delete every row from the five instance-identity tables.
// Returns a per-table count of rows removed. Does not touch any other table.
// ─────────────────────────────────────────────────────────────────────────────
function clearSourceIdentity(db) {
  const cleared = {};
  const tx = db.transaction(() => {
    for (const table of IDENTITY_TABLES) {
      const info = db.prepare('DELETE FROM ' + table).run();
      cleared[table] = info.changes;
    }
  });
  tx();
  return cleared;
}

// ─────────────────────────────────────────────────────────────────────────────
// reestablishIdentityFresh(db, options)
//
// options:
//   commonName  server certificate common name (default 'localhost')
//   hostnames   server certificate SAN hostnames (default [])
//
// Wipes the restored source identity, then mints a fresh anchor, CA, and
// server certificate. Returns a report describing what was cleared, the new
// anchor fingerprint, and what was preserved. Throws if re-minting fails
// (for example, no hardware root of trust); the caller treats that as
// fail-closed, consistent with the boot path.
// ─────────────────────────────────────────────────────────────────────────────
function reestablishIdentityFresh(db, options) {
  options = options || {};

  const cleared = clearSourceIdentity(db);
  logger.info('migration-identity: cleared source instance identity', { cleared });

  // instance_identity is now empty, so establish mints a fresh anchor rather
  // than returning an existing one.
  const identity = anchorSvc.establish({ db, logger });

  // Fresh CA and server certificate (initCa is a no-op only when an active CA
  // already exists; the wipe above guarantees it does not).
  caSvc.initCa(db);
  caSvc.issueServerCert(db, {
    commonName: options.commonName || 'localhost',
    hostnames: options.hostnames || [],
  });

  const report = {
    cleared,
    newInstanceId: identity ? identity.instanceId : null,
    newAnchorFingerprint: identity ? identity.fingerprint : null,
    caReprovisioned: true,
    preserved: PRESERVED.slice(),
  };
  logger.info('migration-identity: re-established instance identity fresh', {
    newInstanceId: report.newInstanceId,
    newAnchorFingerprint: report.newAnchorFingerprint,
  });
  return report;
}

module.exports = {
  IDENTITY_TABLES,
  PRESERVED,
  clearSourceIdentity,
  reestablishIdentityFresh,
};
