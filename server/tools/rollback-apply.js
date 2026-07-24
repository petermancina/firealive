#!/usr/bin/env node
'use strict';

// FIREALIVE -- offline rollback CLI (B6k)
//
// Puts the PREVIOUS build back in front of its data, using a pre-upgrade restore
// point taken by that build. This is the only operation that lets a FireAlive
// deployment run below its recorded anti-rollback high-water, and it is
// deliberately not reachable over HTTP: it runs here, on the host, with the
// server stopped.
//
//   Usage:  node rollback-apply.js --koa <koa-id> [--restore-point <id>] [--dry-run]
//
//           --koa            the rollback authorization to consume (required)
//           --restore-point  which restore point to apply; defaults to the one
//                            the authorization is bound to
//           --dry-run        run every gate and report, changing nothing
//
// BEFORE RUNNING THIS
//
//   1. Stop the FireAlive server. This tool refuses while it is alive, because
//      the restore renames a database over the live file and a running server
//      would keep writing to an unlinked copy.
//   2. Have a rollback authorization. It is minted by the RUNNING server behind
//      an approved two-person gate (/api/key-ops), and this tool can consume one
//      but never create one. If the upgraded build no longer starts, the
//      authorization must have been minted BEFORE the upgrade -- that is what
//      the contingency option on a restore point is for.
//
// WHAT IT REFUSES
//
//   a running server; a missing, expired, tampered or already-consumed
//   authorization; an authorization for a different restore point or a different
//   operation; an incomplete or unattributable bundle; a bundle wrapped under a
//   different KEK; a failed or inconclusive malware scan; and anything that is
//   not EXACTLY one version back -- so upgrading again voids an outstanding
//   authorization on its own.
//
// AFTER IT SUCCEEDS
//
//   The database is the pre-upgrade one and its recorded mark is the old fuse,
//   so the previous build starts. Configuration comes back LOCKED and needs a
//   hardware unlock. The database that was replaced is kept as a pre-restore
//   snapshot; the path is printed.
//
// Exit codes: 0 applied (or dry run passed); 1 refused or failed (atomic --
// nothing changed unless the swap itself is reported); 2 usage error.

const { getDb } = require('../db/init');
const { applyRollback } = require('../services/rollback-apply');

function parseArgs(argv) {
  const out = { koaId: null, restorePointId: null, dryRun: false };
  for (let i = 2; i < argv.length; i++) {
    if ((argv[i] === '--koa' || argv[i] === '--koa-id') && argv[i + 1]) { out.koaId = argv[i + 1]; i++; }
    else if (argv[i] === '--restore-point' && argv[i + 1]) { out.restorePointId = argv[i + 1]; i++; }
    else if (argv[i] === '--dry-run') { out.dryRun = true; }
  }
  return out;
}

async function main(argv) {
  const args = parseArgs(argv);
  if (!args.koaId) {
    process.stderr.write('usage: node rollback-apply.js --koa <koa-id> [--restore-point <id>] [--dry-run]\n');
    return 2;
  }

  let result;
  try {
    result = await applyRollback({
      openDb: getDb,
      koaId: args.koaId,
      restorePointId: args.restorePointId,
      dryRun: args.dryRun,
    });
  } catch (e) {
    process.stderr.write('ROLLBACK REFUSED: ' + e.message + '\n');
    if (e.code) process.stderr.write('  code: ' + e.code + '\n');
    process.stderr.write('Nothing was changed.\n');
    return 1;
  }

  if (result.dryRun) {
    process.stdout.write('DRY RUN -- every gate passed. Nothing was changed.\n');
    process.stdout.write('  restore point: ' + result.restorePointId + '\n');
    process.stdout.write('  bundle:        ' + result.bundleDir + '\n');
    process.stdout.write('  would move the anti-rollback mark ' + result.currentMark + ' -> ' + result.bundleFuse + '\n');
    process.stdout.write('Re-run without --dry-run to apply.\n');
    return 0;
  }

  process.stdout.write('ROLLBACK COMPLETE.\n');
  process.stdout.write('  restore point:  ' + result.restorePointId + ' (bundle ' + result.bundleDir + ')\n');
  process.stdout.write('  anti-rollback:  mark ' + result.fuseFrom + ' -> ' + result.fuseTo + '; the previous build will now start.\n');
  process.stdout.write('  database:       ' + result.dbPath + '\n');
  process.stdout.write('  previous db kept at: ' + result.preRestorePath + '\n');
  if (result.configForceLocked) {
    process.stdout.write('  configuration is LOCKED -- unlock with a hardware key before making changes.\n');
  }
  process.stdout.write('  the authorization has been consumed and cannot be replayed.\n');
  process.stdout.write('Start the PREVIOUS version of FireAlive now.\n');
  return 0;
}

main(process.argv).then((code) => process.exit(code)).catch((e) => {
  process.stderr.write('ROLLBACK FAILED (unexpected): ' + (e && e.message) + '\n');
  process.exit(1);
});
