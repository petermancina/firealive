#!/usr/bin/env node
'use strict';

// FIREALIVE (Global Dashboard) -- offline node rekey CLI (B6h B-4)
//
// Run ON the node (a hardware root of trust is required to unseal the adopted shared KEK
// and seal under this node's own KEK). Rebinds the replicated Tier-1 columns from the
// adopted shared KEK to the own KEK -- under a rekey KOA -- then sheds the shared KEK, so
// the node is standalone and may be un-paired.
//
//   Usage:  node gd-rekey-node.js --koa <koa-id>
//           (set DB_PATH to point at the node database if not the default data/firealive.db)
//
// The KOA (op='rekey') must have been requested, approved by a second admin, and minted via
// /api/key-ops on this node first. This tool verifies it offline against the node's anchor
// public key and consumes it single-use.
//
// FORWARD-ONLY: existing backups and forensic exports stay under the OLD KEK. This tool
// never touches them -- retain the old recovery code to read them.
//
// Exit codes: 0 rekey complete; 1 rekey failed (atomic -- nothing changed); 2 usage error.

const { getDb } = require('../db-init');
const tier1Kek = require('../services/gd-tier1-kek');
const { rekeyNode } = require('../services/gd-tier1-rekey');

function parseArgs(argv) {
  let koaId = null;
  for (let i = 2; i < argv.length; i++) {
    if ((argv[i] === '--koa' || argv[i] === '--koa-id') && argv[i + 1]) { koaId = argv[i + 1]; i++; }
  }
  return { koaId: koaId };
}

function main(argv) {
  const args = parseArgs(argv);
  if (!args.koaId) {
    process.stderr.write('usage: node gd-rekey-node.js --koa <koa-id>\n');
    return 2;
  }

  const db = getDb();
  // Load the adopted shared KEK into memory so sharedKek() returns IT (the key the replicated
  // columns are currently sealed under), not the ownKek() fallback. No-op if none was adopted,
  // in which case rekeyNode reports there is nothing to rebind.
  tier1Kek.loadSharedKekOnBoot(db);

  let result;
  try {
    result = rekeyNode(db, { koaId: args.koaId });
  } catch (e) {
    process.stderr.write('REKEY FAILED: ' + e.message + '\n');
    process.stderr.write('The operation is atomic -- nothing was changed. If the authorization was not yet consumed, it is still usable.\n');
    return 1;
  }

  process.stdout.write('REKEY COMPLETE.\n');
  process.stdout.write('  Re-sealed ' + result.resealed + ' value(s) across ' + result.columns + ' replicated column(s): shared KEK -> this node own KEK.\n');
  process.stdout.write('  The shared-KEK wrapper has been shed. This node is standalone and may now be un-paired.\n');
  process.stdout.write('  FORWARD-ONLY: existing backups and forensic exports remain under the OLD KEK -- retain the old recovery code to read them.\n');
  return 0;
}

process.exit(main(process.argv));
