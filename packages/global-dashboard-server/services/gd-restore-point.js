// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Pre-upgrade restore points (Global Dashboard)  (B6k)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// WHY THIS EXISTS
//
// FireAlive never installs an update. the Regional Server's update-check detects a
// newer release and notifies; the operator downloads and runs
// the installer themselves, entirely outside the product (and both are opt-in,
// so an air-gapped deployment never reaches for the network at all).
//
// That leaves one gap. An operator who upgrades and finds the new build broken
// has to get back to the previous one, and going back means putting the
// PREVIOUS binary in front of a database it can accept. The anti-rollback fuse
// makes that specific: services/gd-fuse-high-water.js records the highest fuse
// this node has ever run, in node_state INSIDE the database, and the boot gate
// halts a build below it. So a rollback needs a database whose recorded mark is
// the OLD one -- which only a backup taken BEFORE the upgrade contains.
//
// This module takes that backup, at the old fuse and the old schema, while the
// old build is still the running one. It is the only moment such an artifact
// can be produced.
//
// WHAT THIS IS NOT
//
// It is not a new backup engine. A restore point IS a full-suite backup --
// same v2 pipeline, same Ed25519 manifest signature, same AES-256-GCM archive,
// same hardware-sealed KEK wrapping the DEK, same /verify path. This module
// composes services/gd-backup-full-suite.js and adds exactly two things: it writes
// the bundle to a store OUTSIDE the data root, and it records why the bundle
// was taken.
//
// WHERE IT GOES, AND WHY THAT IS THE WHOLE POINT
//
// lib/gd-data-root.restorePointsDir() is a SIBLING of the data root, not a child.
// Rolling back means replacing the contents of the data root; a restore point
// stored inside it would be destroyed by the operation it exists to serve --
// the same defect P1-1 removed, where backups inside the application bundle
// died with the update they were meant to survive.
//
// Nothing here is pushed anywhere. No storage-destination adapter, no
// credentials, no egress. An air-gapped deployment keeps its restore points on
// its own disk, and a second copy is an operator carrying the bundle to
// removable media.
//
// AUTHORITY
//
// The row this module writes is a CONVENIENCE for the console. The offline
// rollback tool does not trust it: the tool's whole job is to replace the
// database the row lives in, and in the case that matters most -- an upgrade
// that will not boot -- the deployment may never get far enough to read it.
// The tool trusts the bundle's signed manifest (source_db.fuse_counter_at_creation)
// and the hardware-sealed KEK that wraps its DEK, both of which travel with the
// bundle and neither of which a copied disk can forge.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const path = require('path');

const dataRoot = require('../lib/gd-data-root');
const pkg = require('../package.json');
const { performFullSuiteBackup } = require('./gd-backup-full-suite');
const { appendGdAuditEntry } = require('./gd-audit-chain');

// The backup type recorded on the underlying backups row. Deliberately
// 'on-demand' and not 'snapshot': backups.type carries a CHECK constraint whose
// 'snapshot' value already means PRE-RESTORE, and reusing it would conflate two
// different operations in one column. An operator did ask for this backup, so
// 'on-demand' is the honest value; the pre-upgrade meaning lives on the
// restore_points row.
const BACKUP_TYPE = 'on-demand';

function nowIso() { return new Date().toISOString(); }

// The fuse the RUNNING binary is on. db/init.js writes system_meta.fuse_counter
// from lib/version at every boot, so this is the build's own fuse rather than
// anything a peer replicated. Falls back to the version module if the row is
// somehow absent, because a restore point without a recorded fuse cannot be
// used for a rollback and it is better to fail here than to write one.
function sourceFuseCounter(db) {
  const row = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  const fromDb = row ? parseInt(row.value, 10) : NaN;
  if (Number.isInteger(fromDb) && fromDb >= 0) return fromDb;
  if (Number.isInteger(pkg.fuseCounter) && pkg.fuseCounter >= 0) return pkg.fuseCounter;
  const e = new Error('restore-point: no fuse counter is recorded; a restore point without one cannot authorize a rollback');
  e.code = 'NO_FUSE';
  throw e;
}

/**
 * Create a pre-upgrade restore point.
 *
 * Fail-closed and loud: every failure throws. A restore point that silently did
 * not happen is worse than none at all, because the operator upgrades believing
 * they have a way back.
 *
 * @param {object} db      an open database handle (the row is written here)
 * @param {object} opts
 * @param {string} opts.userId  the operator taking it (required)
 * @param {string} [opts.note]  free text shown in the console listing
 * @param {string} [opts.ip]    request IP, for the audit entry
 * @returns {Promise<object>} the stored restore_points row
 */
async function createRestorePoint(db, opts) {
  if (!opts || typeof opts !== 'object') {
    const e = new Error('restore-point: opts required'); e.code = 'INVALID_INPUT'; throw e;
  }
  if (typeof opts.userId !== 'string' || opts.userId === '') {
    const e = new Error('restore-point: userId required'); e.code = 'INVALID_INPUT'; throw e;
  }

  const fuse = sourceFuseCounter(db);
  const store = dataRoot.restorePointsDir();

  // ensureDir refuses a group- or world-accessible directory rather than
  // widening it, so this also proves the store is 0700 before anything is
  // written into it. performFullSuiteBackup calls the same function; doing it
  // here means the refusal names this operation rather than surfacing from
  // inside the backup engine.
  dataRoot.ensureDir(store);

  let backup;
  try {
    // GD divergences from the Regional Server twin, all read from the code:
    //   - the db handle is the FIRST argument (the MC's engine calls getDb itself)
    //   - the output-directory option is `backupsDir` (plural), not `backupDir`
    //   - the trigger option is `triggerType`, not `type`
    backup = await performFullSuiteBackup(db, { triggerType: BACKUP_TYPE, backupsDir: store });
  } catch (err) {
    const e = new Error('restore-point: the full-suite backup failed, so NO restore point exists: ' + err.message);
    e.code = 'BACKUP_FAILED';
    e.cause = err;
    throw e;
  }

  // The GD engine returns backup_dir directly; the Regional Server twin has to
  // derive it from the manifest path.
  const bundleDir = backup.backup_dir || path.dirname(backup.manifest_path);
  const createdAt = nowIso();
  const id = require('crypto').randomBytes(16).toString('hex');

  db.prepare(
    'INSERT INTO restore_points '
    + '(id, backup_id, purpose, bundle_dir, manifest_path, source_fuse_counter, source_version, created_at, created_by_user_id, note) '
    + "VALUES (?, ?, 'pre-upgrade', ?, ?, ?, ?, ?, ?, ?)",
  ).run(
    id, backup.id, bundleDir, backup.manifest_path,
    fuse, pkg.version, createdAt, opts.userId,
    (typeof opts.note === 'string' && opts.note !== '') ? opts.note : null,
  );

  try {
    appendGdAuditEntry(db, {
      userId: opts.userId,
      eventType: 'RESTORE_POINT_CREATED',
      detail: 'restore_point=' + id + ' backup=' + backup.id + ' fuse=' + fuse
        + ' version=' + pkg.version + ' dir=' + bundleDir,
      ip: opts.ip,
    });
  } catch (auditErr) {
    // The bundle exists and the row is written; refusing to report that because
    // a chain append failed would be perverse, and the same degraded-mode
    // reasoning the restore routes already apply. Surface it, do not hide it.
    // eslint-disable-next-line no-console
    console.error('[restore-point] audit append failed (the restore point IS created):', auditErr.message);
  }

  return get(db, id);
}

function get(db, id) {
  return db.prepare('SELECT * FROM restore_points WHERE id = ?').get(id);
}

// Newest first. Includes a liveness flag per row so the console can show an
// operator that a bundle they are relying on has gone missing from disk --
// silence here would be the worst possible failure mode.
function list(db, limit) {
  const n = Number.isInteger(limit) && limit > 0 && limit <= 200 ? limit : 50;
  const rows = db.prepare(
    'SELECT * FROM restore_points ORDER BY created_at DESC LIMIT ?',
  ).all(n);
  return rows.map((r) => Object.assign({}, r, {
    bundle_present: fs.existsSync(r.manifest_path),
  }));
}

module.exports = {
  BACKUP_TYPE,
  createRestorePoint,
  get,
  list,
  sourceFuseCounter,
};
