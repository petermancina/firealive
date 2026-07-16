// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Sealed Archive-Segment Primitive (B5q)
//
// The shared gold-standard archival unit used by the two net-new writers
// (audit-log archival and CEF-stream archival). One sealAndPush call turns a
// plaintext payload into a tamper- AND gap-evident, encrypted, pushed segment:
//
//   1. resolve the destination route for the category (storage-routing) -- a
//      primary plus an optional secondary, both written on every run
//   2. residency write-gate on the primary (data-residency, fail closed)
//   3. chain position: prev_hash = the prior segment's this_hash, sequence + 1
//   4. content_sha256 = SHA-256(plaintext); build the canonical signed manifest
//      (category, sequence, prev_hash, content_sha256, range) and the chain hash
//      this_hash = SHA-256(prev_hash || manifest) -- mirrors the forensic chain
//   5. sign this_hash with the dedicated archive-chain key (archive-chain-keys)
//   6. FA-ENC1-encrypt the payload under the hardware-rooted KEK
//      (export-encryption); the category + chain position are bound into the GCM
//      AAD via the exportId, so a ciphertext cannot be replayed under another
//      category or position
//   7. stage the ciphertext in the durable pending dir, then push it to the
//      primary (which advances the chain) and, on every run, the secondary
//   8. record the segment (append-only) only after the primary push succeeds, so
//      a failed primary leaves the chain unadvanced and the writer re-covers the
//      same range next cycle. Every push is recorded in archive_segment_pushes;
//      the secondary copy is retried (MAX_ATTEMPTS, like backups) from the
//      retained artifact until it lands -- so a copy reliably exists in both
//      destinations, not just the primary
//
// verifyChain(db, category) re-derives every segment's this_hash from its stored
// columns, checks contiguity (no dropped sequence) and linkage (prev_hash ==
// prior this_hash), and verifies each manifest signature -- proving the series
// is continuous, gap-evident, and unforged. It is independent of where copies
// landed; push state lives in archive_segment_pushes.
//
// Encrypt-before-push: only ciphertext ever leaves for a destination. The
// plaintext payload stays in memory; the staged file is already FA-ENC1.
//
// Schema: db/init.js -> storage_archive_segments (append-only triggers, artifact
// + chain only) + archive_segment_pushes (mutable per-push tracking) +
// archive_chain_signing_keys.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const exportEncryption = require('./export-encryption');
const archiveChainKeys = require('./archive-chain-keys');
const storageRouting = require('./storage-routing');
const storageDestinations = require('./storage-destinations');
const dataResidency = require('./data-residency');
const base = require('./destination-adapter-base');
const dataRoot = require('../lib/data-root');

// Categories that flow through the sealed-segment chain. (backup / snapshot /
// forensic_export have their own push paths; these two are net-new archives.)
const ARCHIVE_CATEGORIES = ['audit_log', 'cef_archive'];

const DEFAULT_PUSH_TIMEOUT_MS = 5 * 60 * 1000;

// Revision v4: a sealed segment whose secondary copy has not yet landed is
// retained under this directory (one sub-directory per segment) so the retry
// sweep can re-push the same artifact; the sub-directory is removed once the
// secondary push succeeds. Bounded -- only un-replicated-secondary segments are
// held; the steady state, where the secondary lands promptly, retains nothing.
// Mirrors the backups data-dir convention.
function resolvePendingDir() {
  // P1-1: ARCHIVE_PENDING_DIR, else the canonical data root.
  return dataRoot.archivePendingDir();
}

// Secondary re-push retry policy. Mirrors backup-push.js exactly: five attempts
// with an escalating backoff; once exhausted the row stays 'failed' (next_retry_at
// null) and the artifact is retained for a manual re-push.
const MAX_ATTEMPTS = 5;
const RETRY_DELAYS_SEC = [
  5 * 60,        // 5 min  -> attempt 2
  30 * 60,       // 30 min -> attempt 3
  2 * 60 * 60,   // 2 hr   -> attempt 4
  12 * 60 * 60,  // 12 hr  -> attempt 5
];

// next_retry_at after a failed attempt, or null once MAX_ATTEMPTS is reached.
function calculateNextRetryAt(justCompletedAttempt) {
  if (justCompletedAttempt >= MAX_ATTEMPTS) return null;
  const delaySec = RETRY_DELAYS_SEC[justCompletedAttempt - 1];
  if (delaySec === undefined) return null;
  return new Date(Date.now() + delaySec * 1000).toISOString().slice(0, 19).replace('T', ' ');
}

function sha256Hex(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function nowStamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
}

// Best-effort removal of a retained pending sub-directory. The staged file is
// FA-ENC1 ciphertext, so a leftover is non-sensitive.
function removePendingDir(dir, logger) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (cleanupErr) {
    (logger || console).warn('archive-segment: failed to remove pending dir (encrypted; non-sensitive)', {
      dir, error: cleanupErr.message,
    });
  }
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
 * runSecondaryAttempt(db, pushId, options)
 *
 * Make one attempt to push a segment's secondary copy, updating its
 * archive_segment_pushes row. Used both for the initial attempt in sealAndPush
 * and by retryPendingSegmentPushes. Mirrors the backup-push attempt/backoff model
 * (MAX_ATTEMPTS). On success the row is 'succeeded' and the retained pending
 * artifact is removed; on failure the row is 'failed' with next_retry_at (null
 * once attempts are exhausted) and the artifact is retained. The residency gate
 * is re-evaluated on each attempt, so a later policy change lets the copy
 * through. Returns { ok: true } | { ok: false, reason }.
 */
async function runSecondaryAttempt(db, pushId, options = {}) {
  const logger = options.logger || console;

  const row = db.prepare(
    `SELECT p.id, p.segment_id, p.destination_id, p.status, p.attempt_count, p.source_artifact_path,
            s.category, s.sequence, s.this_hash
       FROM archive_segment_pushes p
       JOIN storage_archive_segments s ON s.id = p.segment_id
      WHERE p.id = ?`
  ).get(pushId);
  if (!row) return { ok: false, reason: 'push row not found' };
  if (row.status === 'succeeded') return { ok: true };

  const attemptCount = row.attempt_count + 1;
  const fail = (message) => {
    db.prepare(
      `UPDATE archive_segment_pushes
          SET status = 'failed', attempt_count = ?, error_message = ?, next_retry_at = ?,
              last_attempt_at = datetime('now')
        WHERE id = ?`
    ).run(attemptCount, String(message).slice(0, 1000), calculateNextRetryAt(attemptCount), pushId);
    return { ok: false, reason: message };
  };

  // Residency re-check (a later policy change lets the retry through).
  const secResidency = dataResidency.evaluateDestination(db, row.category, row.destination_id);
  if (secResidency.blocked) {
    logger.warn('archive-segment: secondary destination blocked by residency; second copy deferred', {
      category: row.category, sequence: row.sequence, destinationRef: row.destination_id, reason: secResidency.reason,
    });
    return fail(`blocked by residency: ${secResidency.reason || 'policy'}`);
  }

  const dest = storageDestinations.getDestinationWithCredentials(db, row.destination_id);
  if (!dest) return fail('secondary destination not found');

  if (!row.source_artifact_path || !fs.existsSync(row.source_artifact_path)) {
    logger.error('archive-segment: retained artifact missing; secondary copy cannot be re-pushed', {
      category: row.category, sequence: row.sequence, path: row.source_artifact_path,
    });
    return fail('retained artifact missing');
  }

  // Mark running with the incremented attempt count.
  db.prepare(
    `UPDATE archive_segment_pushes SET status = 'running', attempt_count = ?, last_attempt_at = datetime('now') WHERE id = ?`
  ).run(attemptCount, pushId);

  let framed;
  try {
    framed = fs.readFileSync(row.source_artifact_path);
  } catch (readErr) {
    return fail(`cannot read retained artifact: ${readErr.message}`);
  }

  const sourceDir = path.dirname(row.source_artifact_path);
  let route;
  try {
    route = storageRouting.getRouteForType(db, row.category);
  } catch (_routeErr) {
    route = null;
  }
  const ctx = {
    sourceDir,
    fileName: path.basename(row.source_artifact_path),
    framed,
    fileSha256: sha256Hex(framed),
    thisHash: row.this_hash,
    pathPrefix: route && route.pathPrefix ? String(route.pathPrefix) : null,
    exportId: `${row.category}-seg-${row.sequence}-${row.this_hash.slice(0, 12)}`,
    logger,
    timeoutMs: options.timeoutMs || DEFAULT_PUSH_TIMEOUT_MS,
  };

  let result;
  try {
    result = await pushSegmentToDestination(dest, ctx);
  } catch (pushErr) {
    return fail(pushErr.message);
  }

  db.prepare(
    `UPDATE archive_segment_pushes
        SET status = 'succeeded', pushed_at = datetime('now'), size_pushed_bytes = ?, destination_path = ?,
            error_message = NULL, next_retry_at = NULL, source_artifact_path = NULL
      WHERE id = ?`
  ).run(framed.length, result.destinationPath || null, pushId);
  removePendingDir(sourceDir, logger);
  return { ok: true };
}

/**
 * sealAndPush(db, category, payloadBuf, rangeMeta, options)
 *
 * Seal a plaintext payload into the next chain segment for a category and push
 * it to the configured destinations -- a primary plus an optional secondary,
 * each written on this run. The payload is sealed once (one FA-ENC1 artifact, one
 * signed manifest, one chain advance) and the same sealed file is pushed to each
 * destination. Returns one of:
 *   { pushed: false, configured: false, reason }            no route/destination
 *   { pushed: false, blocked: true, reason, residency }     primary residency refused
 *   { pushed: false, reason: 'empty payload', ... }         nothing to archive
 *   { pushed: true, category, sequence, prevHash, thisHash, contentSha256,
 *     segmentId, primaryDestinationRef, primaryDestinationPath,
 *     secondaryDestinationRef, secondaryReplicated, bytes, immutabilityVerified }
 *                                                            sealed + recorded
 *
 * Throws only on hard failures (unsupported category, bad input, the primary
 * adapter not loaded, the primary push itself failing) -- the caller logs and
 * retries the same range next cycle, since no segment is recorded unless the
 * primary push succeeds. The secondary push is recorded in archive_segment_pushes
 * and retried (from the retained artifact) until it lands; it never makes
 * sealAndPush throw. secondaryReplicated reports whether it landed on this run.
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
  // residency-gated per attempt inside runSecondaryAttempt.
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

  // 5. Stage the sealed file in the durable pending dir (one sub-dir per
  // segment), so the same artifact serves the primary push now and the secondary
  // retry later if needed.
  const primaryDest = storageDestinations.getDestinationWithCredentials(db, primaryView.id);
  if (!primaryDest) {
    throw new Error(`archive-segment: primary destination '${primaryView.id}' vanished before push`);
  }

  const segDirName = `${category}-${sequence}`;
  const sourceDir = path.join(resolvePendingDir(), segDirName);
  const stagedFilePath = path.join(sourceDir, fileName);
  fs.mkdirSync(sourceDir, { recursive: true });
  fs.writeFileSync(stagedFilePath, framed, { mode: 0o600 });

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

  // 6. Primary push advances the chain. A failure throws (no segment recorded);
  // discard the staged artifact and let the writer re-cover the range next cycle.
  let primaryResult;
  try {
    primaryResult = await pushSegmentToDestination(primaryDest, stageCtx);
  } catch (primaryErr) {
    removePendingDir(sourceDir, logger);
    throw primaryErr;
  }

  // 7. Record the segment (append-only) and the primary push row atomically, now
  // that the primary copy exists.
  const segmentId = db.transaction(() => {
    const info = db.prepare(
      `INSERT INTO storage_archive_segments
         (category, sequence, prev_hash, this_hash, content_sha256, range_start, range_end, bytes, manifest_signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(category, sequence, prevHash, thisHash, contentSha256, rangeStart, rangeEnd, framed.length, manifestSignature);
    const sid = info.lastInsertRowid;
    db.prepare(
      `INSERT INTO archive_segment_pushes
         (segment_id, destination_id, role, status, pushed_at, size_pushed_bytes, destination_path, attempt_count, last_attempt_at)
       VALUES (?, ?, 'primary', 'succeeded', datetime('now'), ?, ?, 1, datetime('now'))`
    ).run(sid, primaryDest.id, framed.length, primaryResult.destinationPath || null);
    return sid;
  })();

  // 8. Second copy. With no secondary configured the staged artifact is not
  // needed. Otherwise record a queued secondary row and attempt it now; on
  // failure it is left, with its artifact, for the retry sweep.
  let secondaryReplicated = false;
  if (!secondaryView) {
    removePendingDir(sourceDir, logger);
  } else {
    const secInfo = db.prepare(
      `INSERT INTO archive_segment_pushes
         (segment_id, destination_id, role, status, source_artifact_path)
       VALUES (?, ?, 'secondary', 'queued', ?)`
    ).run(segmentId, secondaryView.id, stagedFilePath);
    const attempt = await runSecondaryAttempt(db, secInfo.lastInsertRowid, { logger, timeoutMs: options.timeoutMs });
    secondaryReplicated = attempt.ok === true;
  }

  return {
    pushed: true,
    configured: true,
    category,
    sequence,
    prevHash,
    thisHash,
    contentSha256,
    segmentId,
    primaryDestinationRef: primaryDest.id,
    primaryDestinationPath: primaryResult.destinationPath || null,
    secondaryDestinationRef: secondaryView ? secondaryView.id : null,
    secondaryReplicated,
    bytes: framed.length,
    immutabilityVerified: primaryResult.immutabilityVerified || null,
  };
}

/**
 * retryPendingSegmentPushes(db, options)
 *
 * The replication sweep. Re-attempts every secondary push that has not yet
 * landed and is due (status 'queued' or 'failed', attempts not exhausted,
 * next_retry_at null or past). Mirrors the backup_pushes retry cadence; intended
 * to be called on a schedule. A row that exhausts MAX_ATTEMPTS stays 'failed'
 * (next_retry_at null) with its artifact retained for a manual re-push, and is
 * not picked up again. Returns { scanned, succeeded, failed }.
 */
async function retryPendingSegmentPushes(db, options = {}) {
  const logger = options.logger || console;
  const limit = options.limit || 100;

  const due = db.prepare(
    `SELECT id FROM archive_segment_pushes
      WHERE role = 'secondary'
        AND status IN ('queued', 'failed')
        AND attempt_count < ?
        AND (next_retry_at IS NULL OR next_retry_at <= datetime('now'))
      ORDER BY id ASC
      LIMIT ?`
  ).all(MAX_ATTEMPTS, limit);

  let succeeded = 0;
  let failed = 0;
  for (const r of due) {
    try {
      const res = await runSecondaryAttempt(db, r.id, { logger, timeoutMs: options.timeoutMs });
      if (res.ok) succeeded += 1;
      else failed += 1;
    } catch (sweepErr) {
      failed += 1;
      logger.error('archive-segment: retry sweep attempt crashed', { pushId: r.id, error: sweepErr.message });
    }
  }
  return { scanned: due.length, succeeded, failed };
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
  retryPendingSegmentPushes,
  verifyChain,
  // exposed for tests
  buildManifestBytes,
  chainHash,
};
