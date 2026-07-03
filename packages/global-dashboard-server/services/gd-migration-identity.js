// -----------------------------------------------------------------------------
// FIREALIVE Global Dashboard -- Migration Identity Re-establishment (FA-GDMIG1)
// (D14 / 5b)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// -----------------------------------------------------------------------------
//
// The section 5b rule: a migration import must NOT carry the source GD
// deployment's instance identity, because a verbatim identity restore is
// indistinguishable from cloning. After the source's data has been restored, the
// restored database still holds the source GD's instance-level identity; this
// module wipes it and mints a FRESH identity on the target GD.
//
// GD instance-level identity is exactly four tables:
//   - gd_device_signing_keys ... GD device-bound PoP keys (must re-enroll)
//   - issued_certs ............. certificates issued under the old GD CA
//   - ca_authority ............. the GD deployment CA
//   - gd_instance_identity ..... the hardware-rooted GD anchor
//
// (The GD has no enrollment_tokens or ac_device_signing_keys -- it registers
// Management Consoles, it does not enroll Analyst Clients.) No other table
// references these by foreign key, so clearing them cannot cascade into the GD's
// aggregate or operational data. Everything else is PRESERVED: the registered
// Management-Console bindings and their aggregate data; the GD audit and
// forensic chains; GD config and sealed history; and the compliance reports and
// regional rollups.
//
// Re-minting reuses the same provisioning the GD runs at first boot:
// gd-instance-anchor establish (a fresh hardware-rooted GD anchor) and gd-ca
// initCa + issueServerCert (a fresh GD CA and server certificate). Registered
// Management Consoles re-pin to the new GD identity afterward through the
// authenticated re-pin ceremony (a clone cannot reproduce the new fingerprint).
//
// This runs against the already-restored database (the data restore swaps the
// database file and requires a restart, so identity is re-established after
// that, against the restored database). It is the post-restore step of the
// migration apply, not the apply in full. Each trust realm re-mints its own
// identity; the GD never becomes a write-path into the Regional Server.
// -----------------------------------------------------------------------------

const anchorSvc = require('./gd-instance-anchor');
const caSvc = require('./gd-ca');

const logger = {
  info: (m, meta) => console.log('[gd-migration-identity] ' + m, meta !== undefined ? meta : ''),
  warn: (m, meta) => console.warn('[gd-migration-identity] ' + m, meta !== undefined ? meta : ''),
  error: (m, meta) => console.error('[gd-migration-identity] ' + m, meta !== undefined ? meta : ''),
};

// Order is cosmetic: no foreign key references any of these tables, so the wipe
// cannot cascade. Children-before-parents is kept for readability.
const IDENTITY_TABLES = [
  'gd_device_signing_keys',
  'issued_certs',
  'ca_authority',
  'gd_instance_identity',
];

// What this module deliberately leaves untouched. Surfaced in the report so an
// operator can see, at apply time, exactly what is preserved.
const PRESERVED = [
  'registered Management-Console bindings and aggregate data',
  'the GD audit and forensic chains',
  'GD config and sealed history',
  'compliance reports and regional rollups',
];

// -----------------------------------------------------------------------------
// clearSourceIdentity(db)
//
// Transactionally delete every row from the four GD instance-identity tables.
// Returns a per-table count of rows removed. Does not touch any other table.
// -----------------------------------------------------------------------------
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

// -----------------------------------------------------------------------------
// reestablishIdentityFresh(db, options)
//
// options:
//   commonName  server certificate common name (default 'localhost')
//   hostnames   server certificate SAN hostnames (default [])
//
// Wipes the restored source GD identity, then mints a fresh anchor, CA, and
// server certificate. Returns a report describing what was cleared, the new
// anchor fingerprint, and what was preserved. Throws if re-minting fails (for
// example, no hardware root of trust); the caller treats that as fail-closed,
// consistent with the GD boot path.
// -----------------------------------------------------------------------------
function reestablishIdentityFresh(db, options) {
  options = options || {};

  const cleared = clearSourceIdentity(db);
  logger.info('cleared source GD instance identity', { cleared });

  // gd_instance_identity is now empty, so establish mints a fresh anchor rather
  // than returning an existing one.
  const identity = anchorSvc.establish({ db: db, logger: logger });

  // Fresh GD CA and server certificate (initCa is a no-op only when an active CA
  // already exists; the wipe above guarantees it does not).
  caSvc.initCa(db);
  caSvc.issueServerCert(db, {
    commonName: options.commonName || 'localhost',
    hostnames: options.hostnames || [],
  });

  const report = {
    cleared: cleared,
    newInstanceId: identity ? identity.instanceId : null,
    newAnchorFingerprint: identity ? identity.fingerprint : null,
    caReprovisioned: true,
    preserved: PRESERVED.slice(),
  };
  logger.info('re-established GD instance identity fresh', {
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
