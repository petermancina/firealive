#!/usr/bin/env node
'use strict';

// FIREALIVE (Global Dashboard) -- offline import rekey CLI (B6h B-6, FA-MIG1)
//
// The cross-KEK import path. The online /import/apply handles only same-KEK imports and refuses a
// foreign-KEK bundle at the restore gate; this tool imports a bundle whose backup was wrapped
// under a DIFFERENT KEK, by recovering the SOURCE KEK from the source deployment's recovery code
// and re-sealing every Tier-1 column to THIS node's own KEK.
//
// Run ON the target node (a hardware root of trust is required to unseal this node's own KEK).
// Point --bundle-dir at an already-unpacked migration bundle directory.
//
//   Usage:  node gd-import-rekey.js --bundle-dir <dir> --koa <koa-id> \
//                                --recovery-code <source-recovery-code> --passphrase <passphrase>
//           (set DB_PATH to the node database if not the default)
//
// The KOA (op='migration-import') must have been requested, approved by a second admin, and minted
// via /api/key-ops on this node first; importRekey verifies it offline against the node's anchor
// public key and consumes it single-use. The source recovery code and passphrase come from the
// SOURCE deployment's operator.
//
// Flow: recover source KEK -> restore the bundle's DB with a raw-KEK DEK unwrap (the same-KEK gate
// is skipped on this authorized path) -> re-seal every Tier-1 column source-KEK -> own-KEK in one
// atomic transaction -> scrub the source KEK.
//
// FORWARD-ONLY (D-R2-7): the imported bundle and any prior backups/exports stay under their source
// KEK. This tool re-seals only the live database. Retain the source recovery code to read them.
//
// Exit codes: 0 import + rekey complete; 1 failed (restore is atomic, rekey is atomic); 2 usage.

const path = require('path');
const fs = require('fs');
const { getDb } = require('../db-init');
const tier1Kek = require('../services/gd-tier1-kek');
const backupManifestSvc = require('../services/gd-backup-manifest');
const dbRestoreSwap = require('../services/gd-db-restore-swap');
const { importRekey } = require('../services/gd-tier1-import-rekey');

const BACKUP_SUBDIR = 'backup';

function parseArgs(argv) {
  const out = { bundleDir: null, koaId: null, recoveryCode: null, passphrase: null };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--bundle-dir' && argv[i + 1]) { out.bundleDir = argv[++i]; }
    else if ((a === '--koa' || a === '--koa-id') && argv[i + 1]) { out.koaId = argv[++i]; }
    else if (a === '--recovery-code' && argv[i + 1]) { out.recoveryCode = argv[++i]; }
    else if (a === '--passphrase' && argv[i + 1]) { out.passphrase = argv[++i]; }
  }
  return out;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (!args.bundleDir || !args.koaId || !args.recoveryCode || !args.passphrase) {
    process.stderr.write('usage: node gd-import-rekey.js --bundle-dir <dir> --koa <koa-id> --recovery-code <code> --passphrase <passphrase>\n');
    return 2;
  }

  const backupDir = path.join(args.bundleDir, BACKUP_SUBDIR);
  let backupManifest;
  let archiveBytes;
  let wrappedKeyBytes;
  try {
    backupManifest = JSON.parse(fs.readFileSync(path.join(backupDir, backupManifestSvc.MANIFEST_FILENAME), 'utf8'));
    archiveBytes = fs.readFileSync(path.join(backupDir, backupManifestSvc.ARCHIVE_FILENAME));
    wrappedKeyBytes = fs.readFileSync(path.join(backupDir, backupManifestSvc.WRAPPED_KEY_FILENAME));
  } catch (err) {
    process.stderr.write('IMPORT-REKEY FAILED: could not read the bundle backup files under ' + backupDir + ': ' + err.message + '\n');
    return 1;
  }
  const wrapping = backupManifest.key_wrapping || {};

  // Recover the SOURCE KEK from the recovery code. Scrubbed in the finally no matter what.
  let sourceKek;
  try {
    sourceKek = tier1Kek.recoverKekFromCode(args.recoveryCode, args.passphrase);
  } catch (err) {
    process.stderr.write('IMPORT-REKEY FAILED: could not recover the source KEK from the recovery code: ' + err.message + '\n');
    return 1;
  }

  try {
    // 1. Restore the imported DB, unwrapping the DEK with the source KEK (gate skipped -- this is
    //    the authorized cross-KEK path). Atomic swap; on failure nothing is left half-applied.
    await dbRestoreSwap.restoreDatabaseFromArchive({
      archiveBytes: archiveBytes,
      wrappedKeyBytes: wrappedKeyBytes,
      scheme: wrapping.scheme,
      kekReference: wrapping.kek_reference,
      rawKek: sourceKek,
      manifest: backupManifest,
      label: 'import-rekey',
    });

    // 2. Re-seal every Tier-1 column of the restored DB source-KEK -> this node own-KEK, under the
    //    migration-import KOA, in one atomic transaction. Fresh handle: the restore swapped the DB.
    const result = importRekey(getDb(), {
      koaId: args.koaId,
      sourceRecoveryCode: args.recoveryCode,
      sourcePassphrase: args.passphrase,
    });

    process.stdout.write('IMPORT-REKEY COMPLETE.\n');
    process.stdout.write('  Restored the imported database and re-sealed ' + result.resealed
      + ' value(s) across ' + result.columns + ' Tier-1 column(s): source KEK -> this node own KEK.\n');
    process.stdout.write('  FORWARD-ONLY: the imported bundle and any prior backups/exports remain under their source KEK -- retain the source recovery code to read them.\n');
    return 0;
  } catch (err) {
    process.stderr.write('IMPORT-REKEY FAILED: ' + err.message + '\n');
    process.stderr.write('The restore and the re-seal are each atomic. If the re-seal did not run, the authorization may still be usable.\n');
    return 1;
  } finally {
    if (Buffer.isBuffer(sourceKek)) sourceKek.fill(0);
  }
}

if (require.main === module) {
  main(process.argv).then(function (code) { process.exit(code); }, function (err) {
    process.stderr.write('IMPORT-REKEY FAILED: ' + (err && err.message ? err.message : String(err)) + '\n');
    process.exit(1);
  });
}

module.exports = { parseArgs, main };
