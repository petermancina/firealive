// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Offline rollback apply  (B6k)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════
//
// WHAT THIS IS
//
// The one operation in FireAlive that puts a build BELOW the recorded
// anti-rollback high-water back in front of its data. It exists because the
// alternative is worse: an operator whose upgrade broke production, with a
// signed pre-upgrade backup in hand, and no way to use it.
//
// It is deliberately not an API. There is no route, no flag, no config option.
// It runs from a CLI, with the server stopped, on the host, and it CONSUMES an
// authorization it cannot create.
//
// WHY THIS IS A CONTROL AND NOT A BACK DOOR
//
// Everything that makes a rollback possible is granted by the RUNNING server,
// by an authenticated admin, through a two-person gate, before this tool is
// ever invoked:
//
//   services/key-op-authorization.js mintKoa refuses without an APPROVED
//   two-person gate, signs the canonical payload with the hardware anchor (a
//   copied disk cannot sign, so it cannot mint), and writes a single-use row.
//   verifyKoa checks that signature offline against instance_identity
//   .anchor_public alone -- no hardware, no server, no network.
//
// This tool only verifies and consumes. The gates it adds on top:
//
//   1. THE SERVER MUST BE STOPPED. Not politeness -- correctness.
//      db-restore-swap renames the restored bytes over the live database, and
//      its contract requires the caller to close its handle first "so the
//      rename does not write to an unlinked ghost inode." This process cannot
//      close a handle held by the server, so it refuses while one is alive.
//   2. THE AUTHORIZATION MUST BE FOR THIS RESTORE POINT. op='rollback' and
//      key_op_ref bound to the restore point being applied.
//   3. EXACTLY ONE VERSION BACK. The bundle's signed fuse must equal the
//      current mark minus one. This bounds downgrade depth to a single step AND
//      makes an outstanding authorization SELF-INVALIDATING: upgrade again and
//      the equality breaks, with nobody having to revoke anything.
//   4. THE BUNDLE MUST BE THIS DEPLOYMENT'S. Its manifest signature must verify
//      against a signing key this database knows, and its KEK-wrapped DEK must
//      unwrap under this host's hardware-sealed KEK -- enforced inside
//      db-restore-swap, which refuses a foreign-KEK bundle BEFORE the swap.
//   5. MALWARE SCAN, FAIL-CLOSED. Inherited from db-restore-swap: no scanner,
//      a detected threat, or an inconclusive scan all abort.
//
// WHAT IT DELIBERATELY DOES NOT DO
//
// It does NOT apply the B6j-4 post-restore ratchet. That ratchet exists to stop
// a restore from lowering the anti-rollback mark, and it is why the ordinary
// restore path cannot be used for a rollback: it would compute
// max(current, restored) and push the mark straight back up. Omitting it here
// IS the operation. Nothing about B6j-4 is weakened -- the ratchet still runs on
// every route-driven restore; this one path, behind five gates and a stopped
// server, is the sanctioned exception.
//
// It DOES force-lock the restored configuration, reusing B6j-4's D6 doctrine: a
// node that comes back from a restore comes back frozen, and requires a hardware
// unlock before any configuration change.
//
// WHERE CONSUMPTION IS RECORDED, AND WHY IT MATTERS
//
// In the RESTORED database, not the live one. A rollback authorization minted
// AFTER the upgrade exists only in the database this operation replaces, so
// consuming it in place would be erased by the very operation it authorizes --
// leaving the token replayable. Writing the consumed row into the restored
// database closes that window, and the pre-restore snapshot db-restore-swap
// takes preserves the evidence either way.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const fs = require('fs');
const path = require('path');

const dataRoot = require('../lib/data-root');
const pidfile = require('./pidfile');
const koaSvc = require('./key-op-authorization');
const signingKeysSvc = require('./backup-signing-keys');
const manifestSvc = require('./backup-manifest');
const dbRestoreSwap = require('./db-restore-swap');
const { readHighWater } = require('./fuse-high-water');

const CODES = {
  SERVER_RUNNING: 'SERVER_RUNNING',
  NO_KOA: 'NO_KOA',
  KOA_INVALID: 'KOA_INVALID',
  KOA_WRONG_OP: 'KOA_WRONG_OP',
  KOA_WRONG_TARGET: 'KOA_WRONG_TARGET',
  NO_RESTORE_POINT: 'NO_RESTORE_POINT',
  BUNDLE_MISSING: 'BUNDLE_MISSING',
  MANIFEST_INVALID: 'MANIFEST_INVALID',
  SIGNATURE_INVALID: 'SIGNATURE_INVALID',
  FUSE_NOT_ONE_BACK: 'FUSE_NOT_ONE_BACK',
  CONSUME_FAILED: 'CONSUME_FAILED',
};

class RollbackError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'RollbackError';
    this.code = code;
    this.detail = detail || null;
  }
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/**
 * Apply a rollback. The caller must NOT hold an open database handle.
 *
 * @param {object} opts
 * @param {function} opts.openDb   () => db   MUST open a FRESH handle on each
 *   call. This function closes every handle it opens -- once before the swap
 *   (the rename cannot proceed while a handle is held) and once after, against
 *   the restored file. getDb() satisfies this: it opens a new connection per
 *   call, which is why no process restart is needed for connection correctness.
 *   A cached-handle implementation would hand back a closed database after the
 *   swap and fail with ERR_INVALID_STATE.
 * @param {string} opts.koaId      the rollback authorization to consume
 * @param {string} [opts.restorePointId]  which restore point (else the KOA's key_op_ref)
 * @param {boolean} [opts.dryRun]  run every gate, then stop before the swap
 * @returns {Promise<object>} a result describing what was verified and done
 */
async function applyRollback(opts) {
  if (!opts || typeof opts.openDb !== 'function') {
    throw new RollbackError('INVALID_INPUT', 'rollback-apply: openDb required');
  }
  if (typeof opts.koaId !== 'string' || opts.koaId === '') {
    throw new RollbackError('INVALID_INPUT', 'rollback-apply: koaId required');
  }

  // ── GATE 1: the server must be stopped ────────────────────────────────────
  const held = pidfile.read();
  if (held && held.alive) {
    throw new RollbackError(CODES.SERVER_RUNNING,
      'the FireAlive server is running (pid ' + held.pid + '). Stop it before rolling back: '
      + 'the restore renames a database over the live file, and a running server would keep '
      + 'writing to an unlinked copy, silently discarding every write from that point on.',
      { pid: held.pid, pidfile: held.path });
  }

  let db = opts.openDb();
  let verified;
  try {
    // ── GATE 2: the authorization ─────────────────────────────────────────
    const koa = koaSvc.getKoa(db, opts.koaId);
    if (!koa) {
      throw new RollbackError(CODES.NO_KOA,
        'no authorization with id ' + opts.koaId + '. A rollback must be authorized from the '
        + 'running server first (an approved two-person gate, then a minted rollback KOA); this '
        + 'tool can consume one but never create one.');
    }
    if (koa.op !== 'rollback') {
      throw new RollbackError(CODES.KOA_WRONG_OP,
        "authorization " + opts.koaId + " is for op='" + koa.op + "', not 'rollback'");
    }
    const anchorPem = koaSvc.anchorPublicPem(db);
    const v = koaSvc.verifyKoa(koa, anchorPem);
    if (!v.valid) {
      throw new RollbackError(CODES.KOA_INVALID,
        'authorization ' + opts.koaId + ' is not usable: ' + v.reason);
    }

    // ── The restore point this authorization names ────────────────────────
    const rpId = (typeof opts.restorePointId === 'string' && opts.restorePointId)
      ? opts.restorePointId : koa.key_op_ref;
    if (koa.key_op_ref !== rpId) {
      throw new RollbackError(CODES.KOA_WRONG_TARGET,
        'authorization ' + opts.koaId + ' is bound to restore point ' + koa.key_op_ref
        + ', not ' + rpId + '. One authorization authorizes exactly one restore point.');
    }
    const rp = db.prepare('SELECT * FROM restore_points WHERE id = ?').get(rpId);
    if (!rp) {
      throw new RollbackError(CODES.NO_RESTORE_POINT, 'no restore point with id ' + rpId);
    }
    if (rp.consumed_at) {
      throw new RollbackError(CODES.NO_RESTORE_POINT,
        'restore point ' + rpId + ' was already applied at ' + rp.consumed_at);
    }

    // ── The bundle on disk ────────────────────────────────────────────────
    const bundleDir = rp.bundle_dir;
    const files = {
      manifest: path.join(bundleDir, manifestSvc.MANIFEST_FILENAME),
      signature: path.join(bundleDir, manifestSvc.SIGNATURE_FILENAME),
      archive: path.join(bundleDir, manifestSvc.ARCHIVE_FILENAME),
      wrappedKey: path.join(bundleDir, manifestSvc.WRAPPED_KEY_FILENAME),
    };
    for (const [k, f] of Object.entries(files)) {
      if (!fs.existsSync(f)) {
        throw new RollbackError(CODES.BUNDLE_MISSING,
          'restore point ' + rpId + ' is incomplete: ' + k + ' is missing at ' + f
          + '. The store is outside the data root precisely so this survives; if it is gone, '
          + 'this restore point cannot be applied.');
      }
    }

    // ── GATE 4a: the manifest signature must verify against a key THIS
    //    database knows. A bundle from another deployment fails here; a
    //    tampered manifest fails here.
    const manifestBytes = fs.readFileSync(files.manifest);
    let manifest;
    try {
      manifest = JSON.parse(manifestBytes.toString('utf8'));
    } catch (e) {
      throw new RollbackError(CODES.MANIFEST_INVALID, 'manifest is not valid JSON: ' + e.message);
    }
    const signature = fs.readFileSync(files.signature);
    const fp = manifest.signing_key_fingerprint
      || (manifest.signing_key && manifest.signing_key.fingerprint);
    if (!fp) {
      throw new RollbackError(CODES.MANIFEST_INVALID,
        'manifest carries no signing-key fingerprint; it cannot be attributed to this deployment');
    }
    if (!signingKeysSvc.verifyManifestByFingerprint(db, manifestBytes, signature, fp)) {
      throw new RollbackError(CODES.SIGNATURE_INVALID,
        'the manifest signature does not verify against any signing key this deployment knows '
        + '(fingerprint ' + String(fp).slice(0, 16) + '...). Refusing to restore an unattributable bundle.');
    }

    // ── GATE 3: exactly one version back ──────────────────────────────────
    const bundleFuse = manifest.source_db && manifest.source_db.fuse_counter_at_creation;
    if (!Number.isInteger(bundleFuse)) {
      throw new RollbackError(CODES.MANIFEST_INVALID,
        'the manifest records no fuse counter; the one-version-back rule cannot be checked');
    }
    const currentMark = readHighWater(db);
    if (!Number.isInteger(currentMark)) {
      throw new RollbackError(CODES.FUSE_NOT_ONE_BACK,
        'this database records no anti-rollback high-water; refusing to roll back blind');
    }
    if (bundleFuse !== currentMark - 1) {
      throw new RollbackError(CODES.FUSE_NOT_ONE_BACK,
        'this restore point is at fuse ' + bundleFuse + ' and the recorded mark is ' + currentMark
        + '. A rollback may go back exactly ONE version (' + (currentMark - 1) + '). '
        + (bundleFuse < currentMark - 1
          ? 'This deployment has been upgraded again since the restore point was taken, which '
            + 'voids the authorization: roll back one step at a time, each with its own restore point.'
          : 'The restore point is not older than the running build.'),
        { bundleFuse: bundleFuse, currentMark: currentMark });
    }

    verified = {
      koaId: koa.id,
      restorePointId: rpId,
      bundleDir: bundleDir,
      bundleFuse: bundleFuse,
      currentMark: currentMark,
      signingKeyFingerprint: fp,
      files: files,
      manifest: manifest,
    };
  } finally {
    // The swap renames over this database; the handle must be closed first.
    try { db.close(); } catch (_e) { /* already closed */ }
    db = null;
  }

  if (opts.dryRun) {
    return Object.assign({ applied: false, dryRun: true }, verified);
  }

  // ── GATES 4b + 5, and the swap itself ─────────────────────────────────────
  // db-restore-swap enforces the KEK match (a foreign-KEK bundle is refused
  // BEFORE the swap) and the mandatory fail-closed malware scan, then snapshots
  // the current database and atomically renames the restored bytes into place.
  const swap = await dbRestoreSwap.restoreDatabaseFromArchive({
    archiveBytes: fs.readFileSync(verified.files.archive),
    wrappedKeyBytes: fs.readFileSync(verified.files.wrappedKey),
    scheme: verified.manifest.key_wrapping && verified.manifest.key_wrapping.scheme,
    kekReference: verified.manifest.key_wrapping && verified.manifest.key_wrapping.kek_reference,
    manifest: verified.manifest,
    label: 'rollback',
  });

  // ── Post-swap posture, on the RESTORED database ───────────────────────────
  const restored = opts.openDb();
  let forceLocked = false;
  try {
    // D6: a node that comes back from a restore comes back frozen. Same doctrine
    // as B6j-4; only the ratchet is deliberately absent.
    const hasLock = restored.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='config_lock_state'",
    ).get();
    if (hasLock) {
      restored.prepare(
        'INSERT INTO config_lock_state (id, lock_active, locked_at, auto_relock_at, idle_minutes) '
        + 'VALUES (1, 1, ?, NULL, 15) '
        + 'ON CONFLICT(id) DO UPDATE SET lock_active = 1, locked_at = excluded.locked_at, '
        + 'auto_relock_at = NULL, locked_by_user_id = NULL',
      ).run(Date.now());
      forceLocked = true;
    }

    // Single-use, recorded where it survives: see the header.
    const consumed = koaSvc.consumeKoa(restored, verified.koaId,
      'rollback to fuse ' + verified.bundleFuse + ' from mark ' + verified.currentMark);
    if (!consumed) {
      // The row may not exist in the restored database at all (a KOA minted
      // after the upgrade). Insert it consumed, so a replay finds it spent.
      try {
        restored.prepare(
          'INSERT OR REPLACE INTO key_op_authorizations '
          + '(id, op, key_op_ref, approval_id, requested_by_user_id, created_at, expires_at, '
          + 'anchor_public_fingerprint, signature, consumed_at, consumed_context) '
          + 'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?',
        ).run(
          verified.koaId, 'rollback', verified.restorePointId, 'carried', 'offline-tool',
          new Date().toISOString(), new Date().toISOString(),
          'carried', 'carried', new Date().toISOString(),
          'consumed by the offline rollback tool; row carried into the restored database',
        );
      } catch (e) {
        throw new RollbackError(CODES.CONSUME_FAILED,
          'the rollback succeeded but the authorization could not be marked consumed in the '
          + 'restored database: ' + e.message + '. Revoke it manually before starting the server.');
      }
    }

    restored.prepare(
      'UPDATE restore_points SET consumed_at = ?, consumed_context = ? WHERE id = ?',
    ).run(new Date().toISOString(), 'applied by the offline rollback tool', verified.restorePointId);
  } finally {
    try { restored.close(); } catch (_e) { /* ignore */ }
  }

  return {
    applied: true,
    koaId: verified.koaId,
    restorePointId: verified.restorePointId,
    bundleDir: verified.bundleDir,
    fuseFrom: verified.currentMark,
    fuseTo: verified.bundleFuse,
    preRestorePath: swap.preRestorePath,
    scan: swap.scan,
    configForceLocked: forceLocked,
    dbPath: dataRoot.dbPath(),
  };
}

module.exports = {
  CODES,
  RollbackError,
  applyRollback,
};
