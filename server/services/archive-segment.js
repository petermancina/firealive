// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Sealed Archive-Segment Primitive (B5q)
//
// The shared gold-standard archival unit used by the two net-new writers
// (audit-log archival and CEF-stream archival). One sealAndPush call turns a
// plaintext payload into a tamper- AND gap-evident, encrypted, pushed segment:
//
//   1. resolve the destination for the category (storage-routing)
//   2. residency write-gate (data-residency evaluateDestination, fail closed)
//   3. chain position: prev_hash = the prior segment's this_hash, sequence + 1
//   4. content_sha256 = SHA-256(plaintext); build the canonical signed manifest
//      (category, sequence, prev_hash, content_sha256, range) and the chain hash
//      this_hash = SHA-256(prev_hash || manifest) -- mirrors the forensic chain
//   5. sign this_hash with the dedicated archive-chain key (archive-chain-keys)
//   6. FA-ENC1-encrypt the payload under the hardware-rooted KEK
//      (export-encryption); the category + chain position are bound into the GCM
//      AAD via the exportId, so a ciphertext cannot be replayed under another
//      category or position
//   7. stage the ciphertext and push it through the destination adapter
//   8. record the segment (append-only) only after the push succeeds, so a
//      failed push leaves the chain unadvanced and the writer simply re-covers
//      the same range next cycle
//
// verifyChain(db, category) re-derives every segment's this_hash from its stored
// columns, checks contiguity (no dropped sequence) and linkage (prev_hash ==
// prior this_hash), and verifies each manifest signature -- proving the series
// is continuous, gap-evident, and unforged.
//
// Encrypt-before-push: only ciphertext ever leaves for a destination. The
// plaintext payload stays in memory; the staged file is already FA-ENC1.
//
// Schema: db/init.js -> storage_archive_segments (append-only triggers) +
// archive_chain_signing_keys.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const exportEncryption = require('./export-encryption');
const archiveChainKeys = require('./archive-chain-keys');
const storageRouting = require('./storage-routing');
const storageDestinations = require('./storage-destinations');
const dataResidency = require('./data-residency');
const base = require('./destination-adapter-base');

// Categories that flow through the sealed-segment chain. (backup / snapshot /
// forensic_export have their own push paths; these two are net-new archives.)
const ARCHIVE_CATEGORIES = ['audit_log', 'cef_archive'];

const DEFAULT_PUSH_TIMEOUT_MS = 5 * 60 * 1000;

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function nowStamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
}

// ── Canonical manifest + chain hash ────────────────────────────────────────

/**
 * buildManifestBytes(fields)
 *
 * The canonical, signed manifest for a segment. Every field is a stored column
 * so verifyChain can reconstruct these exact bytes from the row. Fixed key
 * order; null for absent range/prev. Deliberately excludes push-side metadata
 * (destination, dest_path, bytes) so the integrity claim is about the content
 * and chain position, independent of how the segment was packaged or where it
 * landed.
 */
function buildManifestBytes(fields) {
  return Buffer.from(
    JSON.stringify({
      v: 1,
      category: fields.category,
      sequence: fields.sequence,
      prev_hash: fields.prevHash === undefined ? null : fields.prevHash,
      content_sha256: fields.contentSha256,
      range_start: fields.rangeStart === undefined ? null : fields.rangeStart,
      range_end: fields.rangeEnd === undefined ? null : fields.rangeEnd,
    }),
    'utf-8'
  );
}

// this_hash = SHA-256(prev_hash_bytes || manifest) -- genesis hashes the
// manifest alone. Mirrors the forensic_export_chain link function.
function chainHash(prevHash, manifestBytes) {
  const linkInput = prevHash
    ? Buffer.concat([Buffer.from(prevHash, 'hex'), manifestBytes])
    : manifestBytes;
  return sha256Hex(linkInput);
}

function latestSegment(db, category) {
  return db
    .prepare(
      'SELECT sequence, this_hash FROM storage_archive_segments WHERE category = ? ORDER BY sequence DESC LIMIT 1'
    )
    .get(category);
}

// ── Seal + push ────────────────────────────────────────────────────────────

// Push one already-staged sealed segment to a single destination. Builds the
// adapter context (directory-based: the staged file under sourceDir) and calls
// the destination adapter. Returns the adapter push result or throws.
async function pushSegmentToDestination(dest, ctx) {
  const adapter = base.getAdapter(dest.adapter);
  if (!adapter) {
    throw new Error(`archive-segment: adapter '${dest.adapter}' not loaded in registry`);
  }
  const adapterContext = {
    backupId: ctx.exportId,
    sourceDir: ctx.sourceDir,
    files: [
      { name: ctx.fileName, absolutePath: path.join(ctx.sourceDir, ctx.fileName), sizeBytes: ctx.framed.length, sha256: ctx.fileSha256 },
    ],
    manifestSha256: ctx.thisHash,
    createdAt: nowStamp(),
    // Recorded routing hint; current adapters mirror the source dir name under
    // the destination's configured base path.
    pathPrefix: ctx.pathPrefix,
    destination: {
      id: dest.id,
      name: dest.name,
      adapter: dest.adapter,
      config: dest.config,
      credentials: dest.credentials,
      immutability_mode: dest.immutability_mode,
      retention_days: dest.retention_days,
    },
  };
  return adapter.push(adapterContext, { logger: ctx.logger, timeoutMs: ctx.timeoutMs });
}

/**
 * sealAndPush(db, category, payloadBuf, rangeMeta, options)
 *
 * Seal a plaintext payload into the next chain segment for a category and push
 * it to the configured destination(s) -- a primary plus an optional secondary
 * (failover). The payload is sealed once (one FA-ENC1 artifact, one signed
 * manifest, one chain advance) and the same sealed file is pushed to each
 * destination. Returns one of:
 *   { pushed: false, configured: false, reason }            no route/destination
 *   { pushed: false, blocked: true, reason, residency }     primary residency refused
 *   { pushed: false, reason: 'empty payload', ... }         nothing to archive
 *   { pushed: true, category, sequence, prevHash, thisHash, contentSha256,
 *     destinationRef, destinationPath, secondaryDestinationRef,
 *     secondaryDestinationPath, bytes, immutabilityVerified }
 *                                                            sealed + pushed + recorded
 *
 * Throws only on hard failures (unsupported category, bad input, the primary
 * adapter not loaded, the primary push itself failing) -- the caller logs and
 * retries the same range next cycle, since no segment is recorded unless the
 * primary push succeeds. The secondary push is best-effort: residency-gated and
 * never fatal; when it is skipped or fails, the segment is recorded with the
 * primary copy only.
 *
 * rangeMeta: { rangeStart, rangeEnd } describing the window this segment covers
 * (e.g., the audit_log id or timestamp range). Recorded and signed.
 */
async function sealAndPush(db, category, payloadBuf, rangeMeta = {}, options = {}) {
  const logger = options.logger || console;

  if (!ARCHIVE_CATEGORIES.includes(category)) {
    throw new Error(
      `archive-segment: unsupported category '${category}' (expected ${ARCHIVE_CATEGORIES.join(', ')})`
    );
  }
  if (!Buffer.isBuffer(payloadBuf)) {
    throw new Error('archive-segment: payloadBuf must be a Buffer');
  }
  if (payloadBuf.length === 0) {
    return { pushed: false, configured: true, reason: 'empty payload' };
  }

  // 1. Resolve the destination route (primary + optional secondary).
  const route = storageRouting.getRouteForType(db, category);
  if (!route.configured || !route.destinations || route.destinations.length === 0) {
    return { pushed: false, configured: false, reason: 'no destination configured' };
  }
  const primaryView = route.destinations[0];
  const secondaryView = route.destinations[1] || null;

  // 2. Residency write-gate on the PRIMARY (fail closed). The secondary is
  // gated separately below and, if blocked, simply skipped (best-effort).
  const residency = dataResidency.evaluateDestination(db, category, primaryView.id);
  if (residency.blocked) {
    return {
      pushed: false,
      configured: true,
      blocked: true,
      reason: residency.reason || 'blocked by data residency policy',
      residency,
    };
  }

  // 3. Chain position, content hash, manifest, signature.
  archiveChainKeys.ensureActiveSigningKey(db); // idempotent; boot hook normally did this
  const prev = latestSegment(db, category);
  const prevHash = prev ? prev.this_hash : null;
  const sequence = prev ? prev.sequence + 1 : 1;
  const contentSha256 = sha256Hex(payloadBuf);
  const rangeStart = rangeMeta.rangeStart === undefined ? null : rangeMeta.rangeStart;
  const rangeEnd = rangeMeta.rangeEnd === undefined ? null : rangeMeta.rangeEnd;

  const manifestBytes = buildManifestBytes({
    category,
    sequence,
    prevHash,
    contentSha256,
    rangeStart,
    rangeEnd,
  });
  const thisHash = chainHash(prevHash, manifestBytes);
  const signed = archiveChainKeys.signManifest(db, Buffer.from(thisHash, 'hex'));
  const manifestSignature = JSON.stringify({ sig: signed.signature, fp: signed.fingerprint });

  // 4. FA-ENC1-seal the payload. The exportId binds category + chain position
  // into the GCM AAD (FAENC1|v1|archive|<exportId>).
  const exportId = `${category}-seg-${sequence}-${thisHash.slice(0, 12)}`;
  const sealed = await exportEncryption.sealArtifact(payloadBuf, {
    role: exportEncryption.ROLE_ARCHIVE,
    exportId,
    db,
  });
  const framed = sealed.framed;
  const fileSha256 = sha256Hex(framed);
  const fileName = `${category}-${sequence}.faenc1`;

  // 5. Stage once, then push to the primary (authoritative) and, best-effort,
  // the secondary (failover). The same sealed file is pushed to each.
  const primaryDest = storageDestinations.getDestinationWithCredentials(db, primaryView.id);
  if (!primaryDest) {
    throw new Error(`archive-segment: primary destination '${primaryView.id}' vanished before push`);
  }

  const stagingParent = fs.mkdtempSync(path.join(os.tmpdir(), 'fa-archive-'));
  const segDirName = `${category}-${sequence}`;
  const sourceDir = path.join(stagingParent, segDirName);
  let primaryResult;
  let secondaryRef = null;
  let secondaryPath = null;
  try {
    fs.mkdirSync(sourceDir, { recursive: true });
    fs.writeFileSync(path.join(sourceDir, fileName), framed, { mode: 0o600 });

    const stageCtx = {
      sourceDir,
      fileName,
      framed,
      fileSha256,
      thisHash,
      pathPrefix: route.pathPrefix ? String(route.pathPrefix) : null,
      exportId,
      logger,
      timeoutMs: options.timeoutMs || DEFAULT_PUSH_TIMEOUT_MS,
    };

    // Primary push advances the chain; a failure throws (no segment recorded,
    // the writer re-covers the same range next cycle).
    primaryResult = await pushSegmentToDestination(primaryDest, stageCtx);

    // Secondary push (failover) is best-effort: residency-gated and never fatal.
    if (secondaryView) {
      const secResidency = dataResidency.evaluateDestination(db, category, secondaryView.id);
      if (secResidency.blocked) {
        logger.warn('archive-segment: secondary destination blocked by residency; failover copy skipped', {
          category,
          sequence,
          destinationRef: secondaryView.id,
          reason: secResidency.reason,
        });
      } else {
        try {
          const secondaryDest = storageDestinations.getDestinationWithCredentials(db, secondaryView.id);
          if (!secondaryDest) {
            logger.warn('archive-segment: secondary destination not found; failover copy skipped', {
              category,
              sequence,
              destinationRef: secondaryView.id,
            });
          } else {
            const secondaryResult = await pushSegmentToDestination(secondaryDest, stageCtx);
            secondaryRef = secondaryDest.id;
            secondaryPath = secondaryResult.destinationPath || null;
          }
        } catch (secondaryErr) {
          logger.error('archive-segment: secondary push failed (non-fatal); segment recorded with the primary copy only', {
            category,
            sequence,
            error: secondaryErr.message,
          });
        }
      }
    }
  } finally {
    try {
      fs.rmSync(stagingParent, { recursive: true, force: true });
    } catch (_cleanupErr) {
      /* best-effort: staged file is encrypted; leftover is non-sensitive */
    }
  }

  // 6. Record the segment (append-only) -- only now that the primary push
  // succeeded. Both copies are recorded; the secondary fields are null when no
  // secondary is configured or its push was skipped/failed.
  db.prepare(
    `INSERT INTO storage_archive_segments
       (category, sequence, prev_hash, this_hash, content_sha256, range_start, range_end,
        destination_ref, dest_path, secondary_destination_ref, secondary_dest_path,
        bytes, manifest_signature, pushed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    category,
    sequence,
    prevHash,
    thisHash,
    contentSha256,
    rangeStart,
    rangeEnd,
    primaryDest.id,
    primaryResult.destinationPath || null,
    secondaryRef,
    secondaryPath,
    framed.length,
    manifestSignature,
    nowStamp()
  );

  return {
    pushed: true,
    configured: true,
    category,
    sequence,
    prevHash,
    thisHash,
    contentSha256,
    destinationRef: primaryDest.id,
    destinationPath: primaryResult.destinationPath || null,
    secondaryDestinationRef: secondaryRef,
    secondaryDestinationPath: secondaryPath,
    bytes: framed.length,
    immutabilityVerified: primaryResult.immutabilityVerified || null,
  };
}

// ── Verify ─────────────────────────────────────────────────────────────────

/**
 * verifyChain(db, category)
 *
 * Re-derive and check the whole segment chain for a category. Returns
 *   { ok, category, count, brokenAt, reason }
 * where brokenAt is the offending sequence (or null when intact). Detects a
 * dropped/duplicated segment (sequence gap), a broken link (prev_hash mismatch),
 * altered content/metadata (this_hash mismatch), and a forged or unsigned
 * manifest (signature invalid).
 */
function verifyChain(db, category) {
  if (!ARCHIVE_CATEGORIES.includes(category)) {
    return { ok: false, category, count: 0, brokenAt: null, reason: 'unsupported category' };
  }

  const rows = db
    .prepare(
      `SELECT id, sequence, prev_hash, this_hash, content_sha256, range_start, range_end, manifest_signature
       FROM storage_archive_segments WHERE category = ? ORDER BY sequence ASC`
    )
    .all(category);

  let prevThisHash = null;
  let expectedSeq = 1;
  for (const row of rows) {
    if (row.sequence !== expectedSeq) {
      return { ok: false, category, count: rows.length, brokenAt: row.sequence, reason: 'sequence gap' };
    }
    if ((row.prev_hash || null) !== (prevThisHash || null)) {
      return { ok: false, category, count: rows.length, brokenAt: row.sequence, reason: 'prev_hash mismatch' };
    }

    const manifestBytes = buildManifestBytes({
      category,
      sequence: row.sequence,
      prevHash: row.prev_hash,
      contentSha256: row.content_sha256,
      rangeStart: row.range_start,
      rangeEnd: row.range_end,
    });
    const recomputed = chainHash(row.prev_hash, manifestBytes);
    if (recomputed !== row.this_hash) {
      return { ok: false, category, count: rows.length, brokenAt: row.sequence, reason: 'this_hash mismatch' };
    }

    let sigObj = null;
    try {
      sigObj = JSON.parse(row.manifest_signature);
    } catch (_parseErr) {
      sigObj = null;
    }
    if (
      !sigObj ||
      !archiveChainKeys.verifyManifest(db, Buffer.from(row.this_hash, 'hex'), sigObj.sig, sigObj.fp)
    ) {
      return {
        ok: false,
        category,
        count: rows.length,
        brokenAt: row.sequence,
        reason: 'manifest signature invalid',
      };
    }

    prevThisHash = row.this_hash;
    expectedSeq += 1;
  }

  return { ok: true, category, count: rows.length, brokenAt: null, reason: 'chain intact' };
}

module.exports = {
  ARCHIVE_CATEGORIES,
  sealAndPush,
  verifyChain,
  // exposed for tests
  buildManifestBytes,
  chainHash,
};
