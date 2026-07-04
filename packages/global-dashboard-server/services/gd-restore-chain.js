// ============================================================================
// packages/global-dashboard-server/services/gd-restore-chain.js
//
// GD twin of the Regional Server restore-chain. Verbatim mirror adapted only for
// GD module paths (gd-backup-*) and console logging (the GD has no ./logger).
//
// R3l C65 -- Walker, validator, and replayer for incremental and differential
// backup chains.
//
// Given a leaf backup id, this module:
//
//   1. walkChain(db, leafBackupId)
//      Walks the parent_backup_id linkage backwards from the leaf until
//      it reaches the anchor full backup. Returns the ordered list
//      [anchor, ...intermediates_oldest_to_newest, leaf]. For full and
//      snapshot leaves the chain is just [leaf]. For differential leaves
//      the chain is [anchor, leaf] (differential anchor IS its
//      parent_backup_id). For incremental leaves the chain can be
//      arbitrarily long.
//
//   2. validateChain(db, chain)
//      For each backup in the chain, verifies:
//        - manifest file SHA-256 matches backups.sha256_hash
//        - manifest signature verifies against the recorded signing key
//        - archive.bin SHA-256 matches manifest's files[0].sha256
//        - wrapped-key.bin SHA-256 matches manifest's files[1].sha256
//        - for incremental/differential with page_count > 0:
//            unwrap key, decrypt+decompress archive, parse INCR-v1 bundle,
//            verify each frame's page SHA-256 against the manifest entry
//      Returns a structured report.
//
//   3. replayChain(db, chain, targetDbPath, options)
//      Apply the chain to a target database file:
//        1. Anchor full backup: extract its archive payload to targetDbPath
//        2. Each subsequent link (incremental or differential):
//           unwrap key, decrypt+decompress, parse INCR-v1 bundle, write
//           each frame's raw page bytes into targetDbPath at the
//           appropriate page offset. Truncate targetDbPath when a commit
//           frame's dbSizeAfterCommit indicates a database shrink.
//
// The INCR-v1 bundle format (read here, written by C63 gd-backup-incremental
// and C64 backup-differential) is documented in gd-backup-incremental.js.
//
// This module is read-and-write at the filesystem level (creates and
// modifies the target DB file) but read-only against the management DB
// (it reads the backups table and signing keys but never writes them).
// Higher-level orchestration that decides WHEN to restore (approvals,
// IP allowlists, audit logging) lives in the existing routes/restore.js
// and will be extended to call this module in C66.
// ============================================================================

const fs = require('fs');
const crypto = require('crypto');

const archiveSvc = require('./gd-backup-archive');
const keyWrapSvc = require('./gd-backup-key-wrapping');
const manifestSvc = require('./gd-backup-manifest');
const signingKeysSvc = require('./gd-backup-signing-keys');

// INCR-v1 format constants -- must match gd-backup-incremental.js. Duplicated
// here rather than imported to avoid a runtime require dependency on
// gd-backup-incremental (this module is also used by the restore route which
// may run in a context where gd-backup-incremental hasn't loaded).
const INCR_MAGIC = Buffer.from('INCR', 'ascii');
const INCR_FORMAT_VERSION = 1;
const INCR_HEADER_SIZE = 16;
const INCR_PER_FRAME_OVERHEAD = 44;

const MAX_CHAIN_DEPTH = 1000;  // safety against malformed chains

/**
 * Walk the chain from a leaf backup id back to the anchor full backup.
 * Returns the chain in restore order (anchor first, leaf last).
 *
 * Throws on cycles, missing parents, or chain depth above MAX_CHAIN_DEPTH.
 */
function walkChain(db, leafBackupId) {
  if (!leafBackupId) {
    throw new Error('walkChain: leafBackupId required');
  }
  const select = db.prepare('SELECT * FROM backups WHERE id = ?');

  const leaf = select.get(leafBackupId);
  if (!leaf) {
    throw new Error(`walkChain: backup not found: ${leafBackupId}`);
  }

  const strategy = leaf.backup_strategy || 'full';

  if (strategy === 'full' || strategy === 'snapshot') {
    return [leaf];
  }

  if (strategy === 'differential') {
    // Differential's parent_backup_id IS the anchor full backup.
    if (!leaf.parent_backup_id) {
      throw new Error(`walkChain: differential backup ${leafBackupId} has no parent_backup_id`);
    }
    const anchor = select.get(leaf.parent_backup_id);
    if (!anchor) {
      throw new Error(`walkChain: differential ${leafBackupId} parent ${leaf.parent_backup_id} not found`);
    }
    if ((anchor.backup_strategy || 'full') !== 'full') {
      throw new Error(`walkChain: differential ${leafBackupId} parent ${anchor.id} is not a full backup (strategy=${anchor.backup_strategy})`);
    }
    return [anchor, leaf];
  }

  if (strategy !== 'incremental') {
    throw new Error(`walkChain: unknown backup_strategy '${strategy}' for ${leafBackupId}`);
  }

  // Incremental: walk parent_backup_id backwards.
  const reversed = [leaf];
  const seen = new Set([leaf.id]);
  let current = leaf;
  while ((current.backup_strategy || 'full') === 'incremental') {
    if (reversed.length > MAX_CHAIN_DEPTH) {
      throw new Error(`walkChain: chain depth exceeded MAX_CHAIN_DEPTH=${MAX_CHAIN_DEPTH}`);
    }
    if (!current.parent_backup_id) {
      throw new Error(`walkChain: incremental backup ${current.id} has no parent_backup_id`);
    }
    if (seen.has(current.parent_backup_id)) {
      throw new Error(`walkChain: cycle detected at backup ${current.parent_backup_id}`);
    }
    const parent = select.get(current.parent_backup_id);
    if (!parent) {
      throw new Error(`walkChain: parent ${current.parent_backup_id} of ${current.id} not found`);
    }
    seen.add(parent.id);
    reversed.push(parent);
    current = parent;
  }
  // current is now the anchor (full or snapshot). Verify.
  const anchorStrategy = current.backup_strategy || 'full';
  if (anchorStrategy !== 'full' && anchorStrategy !== 'snapshot') {
    throw new Error(`walkChain: anchor ${current.id} has unexpected strategy '${anchorStrategy}'`);
  }
  // We pushed in reverse order (leaf -> ... -> anchor); reverse for return.
  return reversed.slice().reverse();
}

/**
 * Read a file and compute its SHA-256. Returns { bytes, sha256, sizeBytes }.
 */
function readFileWithHash(filePath) {
  const bytes = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  return { bytes, sha256, sizeBytes: bytes.length };
}

/**
 * Parse an INCR-v1 bundle. Returns:
 *   {
 *     pageSize: number,
 *     frameCount: number,
 *     frames: [
 *       { frameNo, pageNo, dbSizeAfterCommit, sha256, pageBuf },
 *       ...
 *     ]
 *   }
 *
 * Throws on malformed input.
 */
function parseIncrBundle(buf) {
  if (!Buffer.isBuffer(buf)) {
    throw new Error('parseIncrBundle: buf must be Buffer');
  }
  if (buf.length < INCR_HEADER_SIZE) {
    throw new Error(`parseIncrBundle: buffer too short (${buf.length} < ${INCR_HEADER_SIZE})`);
  }
  const magic = buf.subarray(0, 4);
  if (!magic.equals(INCR_MAGIC)) {
    throw new Error(`parseIncrBundle: invalid magic '${magic.toString('ascii')}'; expected 'INCR'`);
  }
  const version = buf.readUInt32BE(4);
  if (version !== INCR_FORMAT_VERSION) {
    throw new Error(`parseIncrBundle: unsupported format version ${version}; this build expects ${INCR_FORMAT_VERSION}`);
  }
  const frameCount = buf.readUInt32BE(8);
  const pageSize = buf.readUInt32BE(12);
  if (pageSize === 0 && frameCount > 0) {
    throw new Error(`parseIncrBundle: pageSize=0 but frameCount=${frameCount}`);
  }
  const expectedLen = INCR_HEADER_SIZE + frameCount * (INCR_PER_FRAME_OVERHEAD + pageSize);
  if (buf.length < expectedLen) {
    throw new Error(`parseIncrBundle: bundle truncated; expected ${expectedLen} bytes, got ${buf.length}`);
  }

  const frames = [];
  let cursor = INCR_HEADER_SIZE;
  for (let i = 0; i < frameCount; i++) {
    const frameNo = buf.readUInt32BE(cursor); cursor += 4;
    const pageNo = buf.readUInt32BE(cursor); cursor += 4;
    const dbSizeAfterCommit = buf.readUInt32BE(cursor); cursor += 4;
    const sha256 = buf.subarray(cursor, cursor + 32).toString('hex'); cursor += 32;
    const pageBuf = Buffer.from(buf.subarray(cursor, cursor + pageSize));  // copy
    cursor += pageSize;
    frames.push({ frameNo, pageNo, dbSizeAfterCommit, sha256, pageBuf });
  }
  return { pageSize, frameCount, frames };
}

/**
 * Verify a single backup's on-disk files match what its DB row + manifest
 * declare. For full backups, this is the standard manifest + archive +
 * wrapped-key + signature verification. For incremental/differential
 * backups, additionally parse and validate the INCR bundle's per-page
 * SHA-256 hashes.
 *
 * Returns:
 *   {
 *     ok: boolean,
 *     backupId,
 *     strategy,
 *     steps: [
 *       { name: 'manifest_sha256',       ok, error? },
 *       { name: 'manifest_signature',    ok, error? },
 *       { name: 'archive_sha256',        ok, error? },
 *       { name: 'wrapped_key_sha256',    ok, error? },
 *       { name: 'incr_bundle_per_page',  ok, error? },   // inc/diff only
 *     ]
 *   }
 *
 * The function does NOT throw on validation failure; the report's ok
 * is false and the failing step describes what went wrong. It DOES
 * throw on truly catastrophic conditions (missing files, unparseable
 * JSON), which the caller should treat as overall validation failure.
 */
async function validateBackup(db, backup) {
  const strategy = backup.backup_strategy || 'full';
  const steps = [];
  let ok = true;
  const fail = (name, err) => {
    steps.push({ name, ok: false, error: typeof err === 'string' ? err : err.message });
    ok = false;
  };
  const pass = (name) => steps.push({ name, ok: true });

  // Step 1: manifest SHA-256
  let manifestBytes;
  let manifest;
  try {
    const mf = readFileWithHash(backup.manifest_path);
    manifestBytes = mf.bytes;
    if (mf.sha256 !== backup.sha256_hash) {
      fail('manifest_sha256', `manifest SHA-256 ${mf.sha256} != backups.sha256_hash ${backup.sha256_hash}`);
    } else {
      pass('manifest_sha256');
    }
    manifest = manifestSvc.parse(manifestBytes);
  } catch (err) {
    fail('manifest_sha256', err);
    return { ok: false, backupId: backup.id, strategy, steps };
  }

  // Step 2: manifest signature
  try {
    const sigBytes = fs.readFileSync(backup.manifest_sig_path);
    const verifyResult = signingKeysSvc.verifyManifest(db, manifestBytes, sigBytes, backup.signing_key_id);
    if (verifyResult && verifyResult.ok) {
      pass('manifest_signature');
    } else {
      fail('manifest_signature', (verifyResult && verifyResult.reason) || 'signature did not verify');
    }
  } catch (err) {
    fail('manifest_signature', err);
  }

  // Step 3 + 4: archive + wrapped-key file hashes
  const archiveFileEntry = manifestSvc.getFileEntry(manifest, 'archive.bin')
    || (manifest.files && manifest.files.find(f => f.name === 'archive.bin'));
  const wrappedKeyFileEntry = manifestSvc.getFileEntry(manifest, 'wrapped-key.bin')
    || (manifest.files && manifest.files.find(f => f.name === 'wrapped-key.bin'));

  let archiveBytes;
  if (archiveFileEntry) {
    try {
      const ar = readFileWithHash(backup.archive_path);
      archiveBytes = ar.bytes;
      if (ar.sha256 !== archiveFileEntry.sha256) {
        fail('archive_sha256', `archive SHA-256 ${ar.sha256} != manifest ${archiveFileEntry.sha256}`);
      } else if (ar.sizeBytes !== archiveFileEntry.size_bytes) {
        fail('archive_sha256', `archive size ${ar.sizeBytes} != manifest ${archiveFileEntry.size_bytes}`);
      } else {
        pass('archive_sha256');
      }
    } catch (err) {
      fail('archive_sha256', err);
    }
  }

  let wrappedKeyBytes;
  if (wrappedKeyFileEntry) {
    try {
      const wk = readFileWithHash(backup.wrapped_key_path);
      wrappedKeyBytes = wk.bytes;
      if (wk.sha256 !== wrappedKeyFileEntry.sha256) {
        fail('wrapped_key_sha256', `wrapped-key SHA-256 ${wk.sha256} != manifest ${wrappedKeyFileEntry.sha256}`);
      } else if (wk.sizeBytes !== wrappedKeyFileEntry.size_bytes) {
        fail('wrapped_key_sha256', `wrapped-key size ${wk.sizeBytes} != manifest ${wrappedKeyFileEntry.size_bytes}`);
      } else {
        pass('wrapped_key_sha256');
      }
    } catch (err) {
      fail('wrapped_key_sha256', err);
    }
  }

  // Step 5: INCR bundle per-page validation (inc/diff with page_count > 0)
  if ((strategy === 'incremental' || strategy === 'differential') && backup.page_count > 0) {
    try {
      if (!archiveBytes || !wrappedKeyBytes) {
        throw new Error('archive or wrapped-key missing; cannot validate frames');
      }
      const scheme = manifest.key_wrapping_scheme || 'env-var';
      const ref = manifest.kek_reference || 'TIER1_ENCRYPTION_KEY';
      const ephemeralKey = await keyWrapSvc.unwrapKey(wrappedKeyBytes, scheme, ref, {});
      const extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
      const bundle = parseIncrBundle(extracted.payload || extracted);
      const manifestFrames = manifest.frames || [];
      // Two checks: (a) every bundle frame's sha256 matches the recomputed
      // hash of its own page bytes; (b) the bundle's frame metadata matches
      // the manifest's frames descriptor when one is present.
      let frameOk = true;
      const frameErrors = [];
      for (const f of bundle.frames) {
        const recomputed = crypto.createHash('sha256').update(f.pageBuf).digest('hex');
        if (recomputed !== f.sha256) {
          frameOk = false;
          frameErrors.push(`frame ${f.frameNo} page sha256 mismatch (declared ${f.sha256}, recomputed ${recomputed})`);
          if (frameErrors.length > 5) { frameErrors.push('... (truncated)'); break; }
        }
      }
      if (frameOk && manifestFrames.length > 0) {
        if (manifestFrames.length !== bundle.frameCount) {
          frameOk = false;
          frameErrors.push(`manifest declares ${manifestFrames.length} frames but bundle has ${bundle.frameCount}`);
        } else {
          for (let i = 0; i < bundle.frames.length; i++) {
            const bf = bundle.frames[i];
            const mf = manifestFrames[i];
            if (mf.sha256 !== bf.sha256 || mf.frame_no !== bf.frameNo || mf.page_no !== bf.pageNo) {
              frameOk = false;
              frameErrors.push(`frame ${bf.frameNo}: manifest mismatch`);
              if (frameErrors.length > 5) break;
            }
          }
        }
      }
      if (frameOk) pass('incr_bundle_per_page');
      else fail('incr_bundle_per_page', frameErrors.join('; '));
    } catch (err) {
      fail('incr_bundle_per_page', err);
    }
  }

  return { ok, backupId: backup.id, strategy, steps };
}

/**
 * Validate every backup in a chain. Returns:
 *   {
 *     ok: boolean,            // true iff every link's ok is true
 *     chainLength,
 *     results: [perBackupResult, ...]
 *   }
 *
 * Stops at the first failed link's level: still records the failure
 * but does not attempt to validate further links (since a broken
 * predecessor invalidates everything downstream).
 */
async function validateChain(db, chain) {
  if (!Array.isArray(chain) || chain.length === 0) {
    throw new Error('validateChain: chain must be non-empty array');
  }
  const results = [];
  let chainOk = true;
  for (const backup of chain) {
    const result = await validateBackup(db, backup);
    results.push(result);
    if (!result.ok) {
      chainOk = false;
      break;
    }
  }
  return {
    ok: chainOk,
    chainLength: chain.length,
    resultsCount: results.length,
    results,
  };
}

/**
 * Apply INCR-v1 frames to a target database file. Each frame's page bytes
 * are written at offset (page_no - 1) * page_size since SQLite pages are
 * 1-indexed. If a frame's dbSizeAfterCommit is nonzero, it marks a commit
 * boundary; the file is truncated to (dbSizeAfterCommit * page_size) so
 * subsequent reads see the post-commit database size.
 */
function applyIncrFramesToFile(targetDbPath, bundle) {
  const fd = fs.openSync(targetDbPath, 'r+');
  try {
    for (const frame of bundle.frames) {
      const offset = (frame.pageNo - 1) * bundle.pageSize;
      fs.writeSync(fd, frame.pageBuf, 0, bundle.pageSize, offset);
      if (frame.dbSizeAfterCommit > 0) {
        // Commit frame: shrink/grow the DB file to the post-commit size.
        const newSize = frame.dbSizeAfterCommit * bundle.pageSize;
        fs.ftruncateSync(fd, newSize);
      }
    }
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Replay a chain onto a target database file. Steps:
 *
 *   1. Validate the chain end-to-end via validateChain (unless
 *      options.skipValidation is true).
 *   2. Anchor (full backup): unwrap key, decrypt+decompress archive,
 *      write payload to targetDbPath.
 *   3. For each subsequent link: unwrap key, decrypt+decompress,
 *      parse INCR bundle, apply frames to targetDbPath via
 *      applyIncrFramesToFile.
 *
 * Returns:
 *   {
 *     ok: boolean,
 *     anchorBackupId,
 *     linksReplayed,            number of inc/diff links applied
 *     framesApplied,            total frame count across all links
 *     validation,               result of validateChain (if not skipped)
 *     error?                    on failure
 *   }
 */
async function replayChain(db, chain, targetDbPath, options = {}) {
  if (!Array.isArray(chain) || chain.length === 0) {
    return { ok: false, error: 'replayChain: chain must be non-empty array' };
  }

  // Pre-validation unless explicitly skipped
  let validation = null;
  if (!options.skipValidation) {
    validation = await validateChain(db, chain);
    if (!validation.ok) {
      return {
        ok: false,
        error: 'chain validation failed; aborting replay',
        validation,
      };
    }
  }

  const anchor = chain[0];
  const anchorStrategy = anchor.backup_strategy || 'full';
  if (anchorStrategy !== 'full' && anchorStrategy !== 'snapshot') {
    return { ok: false, error: `replayChain: anchor must be full or snapshot, got ${anchorStrategy}` };
  }

  // Step 2: write the anchor full backup's DB contents to targetDbPath.
  try {
    const archiveBytes = fs.readFileSync(anchor.archive_path);
    const wrappedKeyBytes = fs.readFileSync(anchor.wrapped_key_path);
    const manifestBytes = fs.readFileSync(anchor.manifest_path);
    const manifest = manifestSvc.parse(manifestBytes);
    const scheme = manifest.key_wrapping_scheme || 'env-var';
    const ref = manifest.kek_reference || 'TIER1_ENCRYPTION_KEY';
    const ephemeralKey = await keyWrapSvc.unwrapKey(wrappedKeyBytes, scheme, ref, {});
    const extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
    // extractArchive returns {name, payload} per backup-archive.js docs.
    const payload = extracted.payload || extracted;
    fs.writeFileSync(targetDbPath, payload);
  } catch (err) {
    console.error('restore-chain: anchor replay failed', { anchorId: anchor.id, error: err.message });
    return { ok: false, error: `anchor replay failed: ${err.message}`, validation };
  }

  // Step 3: apply each incremental/differential link.
  let framesApplied = 0;
  let linksReplayed = 0;
  for (let i = 1; i < chain.length; i++) {
    const link = chain[i];
    const strategy = link.backup_strategy || 'full';
    if (strategy === 'full' || strategy === 'snapshot') {
      // Unexpected -- shouldn't appear past index 0 in a well-formed chain.
      console.warn('restore-chain: unexpected full/snapshot mid-chain; skipping', { id: link.id, strategy });
      continue;
    }
    if (link.page_count === 0) {
      // Empty incremental/differential: no frames to apply.
      linksReplayed += 1;
      continue;
    }
    try {
      const archiveBytes = fs.readFileSync(link.archive_path);
      const wrappedKeyBytes = fs.readFileSync(link.wrapped_key_path);
      const manifestBytes = fs.readFileSync(link.manifest_path);
      const manifest = manifestSvc.parse(manifestBytes);
      const scheme = manifest.key_wrapping_scheme || 'env-var';
      const ref = manifest.kek_reference || 'TIER1_ENCRYPTION_KEY';
      const ephemeralKey = await keyWrapSvc.unwrapKey(wrappedKeyBytes, scheme, ref, {});
      const extracted = await archiveSvc.extractArchive(archiveBytes, ephemeralKey);
      const bundle = parseIncrBundle(extracted.payload || extracted);
      applyIncrFramesToFile(targetDbPath, bundle);
      framesApplied += bundle.frameCount;
      linksReplayed += 1;
    } catch (err) {
      console.error('restore-chain: link replay failed', { id: link.id, strategy, error: err.message });
      return {
        ok: false,
        error: `link ${link.id} (${strategy}) replay failed: ${err.message}`,
        anchorBackupId: anchor.id,
        linksReplayed,
        framesApplied,
        validation,
      };
    }
  }

  return {
    ok: true,
    anchorBackupId: anchor.id,
    leafBackupId: chain[chain.length - 1].id,
    chainLength: chain.length,
    linksReplayed,
    framesApplied,
    validation,
  };
}

module.exports = {
  walkChain,
  validateChain,
  validateBackup,
  replayChain,
  parseIncrBundle,
  applyIncrFramesToFile,
  MAX_CHAIN_DEPTH,
  INCR_MAGIC,
  INCR_FORMAT_VERSION,
  INCR_HEADER_SIZE,
  INCR_PER_FRAME_OVERHEAD,
};
