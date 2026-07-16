// =============================================================================
// FIREALIVE GD -- CEF-Archive Spool
//
// Durably archives the CEF stream the GD emits to a SIEM. Unlike the audit
// trail -- whose CEF is already persisted and hash-chained in audit_log
// (gd-audit-chain.js) -- the alert/SIEM push feed (gd-siem-adapter.js) is
// fire-and-forget: it is sent over syslog and not retained anywhere. This spool
// gives that feed a durable, FA-ENC1-encrypted, gap-evident, tamper-evident,
// dual-written archive on the routed cef_archive destination(s), so there is a
// defensible record of exactly what the GD forwarded to the SIEM and when,
// independent of SIEM availability. Twins the Regional B5q cef-archive-spool for
// the GD trust realm.
//
// Two halves:
//   appendLine(line)  -- the SIEM emit path tees each formatted CEF line here
//                        (one line per spool entry). Best-effort; never throws,
//                        so SIEM emission cannot be crashed by a spool error.
//   flush(db)         -- seals the accumulated lines into the cef_archive segment
//                        chain via gd-archive-segment.sealAndPush (encrypt + push
//                        + retry). Called on the archival cadence.
//
// Crash-safe + order-preserving rotation: flush seals a leftover pending file
// from a prior failed flush FIRST, then rotates the active spool into the pending
// slot and seals it. A seal/push that does not succeed (no route, residency, a
// failed push) leaves the pending file in place to retry next flush -- so cef
// segments stay strictly in order and no lines are lost. The active spool is the
// implicit cursor (un-sealed lines live in it); the segment chain itself is the
// record of what has been sealed.
// =============================================================================

const fs = require('fs');
const path = require('path');

const archiveSegment = require('./gd-archive-segment');
const { canonicalSerialize } = require('./audit-export-shared');
const gdDataRoot = require('../lib/gd-data-root');

const CEF_CATEGORY = 'cef_archive';
const SPOOL_FILE = 'cef-current.log';   // active spool; appended by the SIEM tee
const PENDING_FILE = 'cef-pending.log'; // rotated, awaiting seal (single slot)

function resolveSpoolDir() {
  // P1-1: GD_CEF_SPOOL_DIR, else the canonical GD data root.
  return gdDataRoot.cefSpoolDir();
}
function currentPath() {
  return path.join(resolveSpoolDir(), SPOOL_FILE);
}
function pendingPath() {
  return path.join(resolveSpoolDir(), PENDING_FILE);
}
function nowStamp() {
  return new Date().toISOString().replace('T', ' ').replace(/\..+$/, '');
}

/**
 * appendLine(line, options)
 *
 * Durably append one CEF line to the active spool. Best-effort and never throws
 * -- SIEM emission must not be crashable by a spool error, and the line is still
 * streamed to the SIEM by the caller regardless. Carriage returns / newlines in
 * the line are flattened so each spool entry is exactly one line. Returns
 * { spooled: bool, error? }.
 */
function appendLine(line, options = {}) {
  if (line == null) return { spooled: false };
  const logger = options.logger || console;
  try {
    fs.mkdirSync(resolveSpoolDir(), { recursive: true });
    fs.appendFileSync(currentPath(), String(line).replace(/[\r\n]+/g, ' ') + '\n', { mode: 0o600 });
    return { spooled: true };
  } catch (err) {
    logger.error('gd-cef-archive-spool: append failed (non-fatal)', { error: err.message });
    return { spooled: false, error: err.message };
  }
}

// Seal one rotated pending file into a cef_archive segment. Returns the
// sealAndPush result augmented with linesSealed; deletes the file on a successful
// push (or when it holds nothing sealable). Leaves the file in place when the
// push did not happen, so the caller can retry it next flush.
async function sealPendingFile(db, filePath, options) {
  const raw = fs.readFileSync(filePath, 'utf-8');
  // Keep lines with real content (drop blank/whitespace-only noise) without
  // altering a kept line's bytes.
  const lines = raw.split('\n').filter((l) => l.trim().length > 0);
  if (lines.length === 0) {
    fs.rmSync(filePath, { force: true }); // empty rotated file; nothing to seal
    return { pushed: false, reason: 'empty', linesSealed: 0 };
  }

  const sealedAt = nowStamp();
  const payload = canonicalSerialize({
    category: CEF_CATEGORY,
    sealed_at: sealedAt,
    line_count: lines.length,
    lines: lines,
  });

  const result = await archiveSegment.sealAndPush(
    db,
    CEF_CATEGORY,
    payload,
    { rangeStart: sealedAt, rangeEnd: sealedAt },
    { logger: options.logger, timeoutMs: options.timeoutMs }
  );

  if (result.pushed) {
    fs.rmSync(filePath, { force: true }); // sealed + pushed; drop the spool file
  }
  return Object.assign({ linesSealed: lines.length }, result);
}

/**
 * flush(db, options)
 *
 * Seal the spooled CEF lines into the cef_archive chain. Order-preserving and
 * crash-safe (see file header). Returns one of:
 *   { flushed: false, reason: 'nothing to flush' }
 *   { flushed: false, configured: false, reason }             no destination routed
 *   { flushed: <bool>, segments: [...], deferred: true, reason }  seal deferred
 *   { flushed: true, segments: [{ sequence, lines }] }
 *
 * options: { logger, timeoutMs }. Throws only if a filesystem op or sealAndPush
 * throws (a primary seal/push failure) -- the pending file is intact and is
 * retried next flush.
 */
async function flush(db, options = {}) {
  const logger = options.logger || console;
  const dir = resolveSpoolDir();
  const cur = currentPath();
  const pend = pendingPath();

  const segments = [];

  const deferred = (res) => ({
    flushed: segments.length > 0,
    segments: segments,
    deferred: true,
    configured: res.configured !== false,
    reason: res.reason || (res.blocked ? 'blocked by residency' : 'not pushed'),
  });

  // 1. Seal a leftover pending file first (keeps the chain in order).
  if (fs.existsSync(pend)) {
    const res = await sealPendingFile(db, pend, { logger: logger, timeoutMs: options.timeoutMs });
    if (res.pushed) {
      segments.push({ sequence: res.sequence, lines: res.linesSealed });
    } else if (res.reason !== 'empty') {
      return deferred(res); // not pushed: leave it, retry next flush
    }
  }

  // 2. Rotate the active spool (only if it has content) into the pending slot.
  let rotated = false;
  if (fs.existsSync(cur) && fs.statSync(cur).size > 0) {
    fs.mkdirSync(dir, { recursive: true });
    fs.renameSync(cur, pend);
    rotated = true;
  }

  if (!rotated) {
    return segments.length > 0
      ? { flushed: true, segments: segments }
      : { flushed: false, reason: 'nothing to flush' };
  }

  // 3. Seal the just-rotated pending file.
  const res = await sealPendingFile(db, pend, { logger: logger, timeoutMs: options.timeoutMs });
  if (res.pushed) {
    segments.push({ sequence: res.sequence, lines: res.linesSealed });
  } else if (res.reason !== 'empty') {
    return deferred(res);
  }

  return { flushed: segments.length > 0, segments: segments };
}

module.exports = {
  appendLine,
  flush,
  CEF_CATEGORY,
  // exposed for tests
  resolveSpoolDir,
  currentPath,
  pendingPath,
};
