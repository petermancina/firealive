// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Chain Integrity Verifier Service
//
// Scheduled service that periodically walks the entire backup_chain
// to detect tampering. The verifier:
//
//   1. Walks every chain entry, verifying linkage (each prev_hash
//      matches predecessor's this_hash) and per-entry consistency
//      (this_hash recomputes correctly + Ed25519 signature verifies).
//
//   2. Appends a VERIFY entry to the chain recording the result.
//      The VERIFY entry's payload commits the verifier's findings
//      (ok / broken_at_id / reason / entries_verified) into the
//      chain itself, creating a permanent forensic record. Future
//      verifications include this VERIFY entry in their walks --
//      so you can see the history of past verifications by
//      browsing the chain.
//
//   3. On failure, emits a CHAIN_INTEGRITY_FAILURE audit log
//      entry with full breakage details. Chain breakage is a
//      security-critical event; surfacing it in the standard
//      audit log feed (not just buried in the chain) ensures
//      the SOC sees it via existing monitoring.
//
// CALLERS
//
//   server/services/scheduler.js -- cron job (commits 10-11 of this
//   phase). Default schedule: daily at 03:00 (configurable via
//   CHAIN_VERIFY_SCHEDULE env var). Picks a different hour from
//   the scheduled backup at 02:00 so they don't pile up on the
//   same minute.
//
//   server/routes/backup-chain.js -- the GET /verify endpoint
//   (commit 7) does its own walk + VERIFY-entry append inline. It
//   does NOT call this service to keep the route file independent
//   of the scheduler service. The two paths produce equivalent
//   results.
//
// EMPTY-CHAIN BEHAVIOR
//
// On a fresh install with no backups taken yet, the chain has zero
// entries. The verifier skips silently in this case -- no VERIFY
// entry, no audit log -- because appending a VERIFY entry to an
// empty chain would create a chain whose only entry is "I verified
// nothing", which adds noise without adding signal.
//
// BROKEN-CHAIN APPEND BEHAVIOR
//
// If verifyFullChain finds breakage at entry K, the verifier still
// appends a new VERIFY entry at the head. This works because
// appendChainEntry only depends on the CURRENT head (most recent
// by id) -- historical breakage is recorded but does not impede
// new appends. The VERIFY entry's payload commits the breakage
// details so the chain itself becomes a permanent forensic record
// of the discovery time and circumstances.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');
const chainSvc = require('./backup-chain');

const DEFAULT_SCHEDULE = '0 3 * * *';   // daily at 03:00 UTC

/**
 * Get the cron schedule string for the chain verifier. Read from
 * env var CHAIN_VERIFY_SCHEDULE; falls back to '0 3 * * *' (daily
 * at 03:00 UTC). Operators can override via env to run more or less
 * frequently or align with their maintenance window.
 *
 * Returns: cron expression string (5 fields, node-cron syntax)
 */
function getSchedule() {
  return process.env.CHAIN_VERIFY_SCHEDULE || DEFAULT_SCHEDULE;
}

/**
 * runScheduledVerification(options)
 *
 * Run a full chain verification pass. Synchronous (better-sqlite3
 * is sync; verifying a chain of thousands of entries is sub-second
 * for typical SOC backup volumes -- daily backups for 5 years is
 * ~1825 entries plus VERIFY/RESTORE entries; well within sync limits).
 *
 * options:
 *   verifier              optional string identifying the caller;
 *                         recorded in the VERIFY entry's payload.
 *                         Defaults to 'scheduled'.
 *   appendVerifyEntry     bool, default true. Set false to do a
 *                         read-only check that doesn't write to the
 *                         chain. Used by health-check probes.
 *
 * Returns:
 *   {
 *     ok                  boolean overall result
 *     entriesVerified     number of entries walked successfully
 *     brokenAtId          chain id where breakage was detected (if any)
 *     reason              breakage reason ('hash_mismatch',
 *                         'signature_invalid', 'broken_linkage',
 *                         'malformed_payload') or null
 *     detail              human-readable detail
 *     verifyChainEntry    info on the VERIFY entry appended (or null
 *                         if appendVerifyEntry was false or if the
 *                         append itself failed)
 *     verifyChainError    error message if VERIFY entry append failed,
 *                         null otherwise
 *     skippedEmpty        true if the chain was empty and the
 *                         verifier skipped silently
 *   }
 *
 * Does NOT throw on chain breakage -- breakage is a result, not an
 * error. Throws only on infrastructure failure (DB unreachable, etc.).
 */
function runScheduledVerification(options = {}) {
  const verifier = options.verifier || 'scheduled';
  const appendVerifyEntry = options.appendVerifyEntry !== false;
  const startedAt = Date.now();

  let db;
  try {
    db = getDb();
  } catch (err) {
    logger.error('chain-verifier: failed to open DB', { error: err.message });
    throw err;
  }

  try {
    // Empty-chain skip
    const stats = chainSvc.getChainStats(db);
    if (stats.totalEntries === 0) {
      logger.info('chain-verifier: skipping empty chain (no entries to verify)');
      return {
        ok: true,
        entriesVerified: 0,
        brokenAtId: null,
        reason: null,
        detail: 'chain is empty; nothing to verify',
        verifyChainEntry: null,
        verifyChainError: null,
        skippedEmpty: true,
        durationMs: Date.now() - startedAt,
      };
    }

    // Walk the chain
    const result = chainSvc.verifyFullChain(db);

    // Append VERIFY entry (unless suppressed)
    let verifyChainEntry = null;
    let verifyChainError = null;
    if (appendVerifyEntry) {
      try {
        const ce = chainSvc.appendChainEntry(db, {
          eventType: 'VERIFY',
          backupId: null,
          payload: {
            verifier,
            ok: result.ok,
            entries_verified: result.entriesVerified,
            broken_at_id: result.brokenAtId || null,
            reason: result.reason || null,
            detail: result.detail || null,
          },
        });
        verifyChainEntry = {
          id: ce.id,
          this_hash: ce.thisHash,
          created_at: ce.createdAt,
        };
      } catch (chainErr) {
        // Failure to append the VERIFY entry should not lose the
        // verification result -- callers still get the result
        // payload; just chain_entry is null.
        verifyChainError = chainErr.message;
        logger.error(
          'chain-verifier: VERIFY entry append failed (verification result is still reported)',
          { error: chainErr.message },
        );
      }
    }

    // Audit log: success path is informational, failure path is
    // security-critical and uses a distinct event type so SIEM
    // feeds can alert on it.
    if (result.ok) {
      auditLog(
        null, // system actor; no user id
        'CHAIN_INTEGRITY_VERIFIED',
        `verifier=${verifier} entries_verified=${result.entriesVerified}`,
        '127.0.0.1',
      );
      logger.info('chain-verifier: chain integrity verified', {
        verifier,
        entriesVerified: result.entriesVerified,
        durationMs: Date.now() - startedAt,
      });
    } else {
      auditLog(
        null,
        'CHAIN_INTEGRITY_FAILURE',
        `verifier=${verifier} broken_at_id=${result.brokenAtId} reason=${result.reason} entries_verified=${result.entriesVerified}`,
        '127.0.0.1',
      );
      logger.error(
        'chain-verifier: CHAIN INTEGRITY FAILURE detected. The cryptographic chain of custody for backups has been tampered with or has become inconsistent. This is a security-critical event. Investigate immediately.',
        {
          verifier,
          brokenAtId: result.brokenAtId,
          reason: result.reason,
          detail: result.detail,
          entriesVerified: result.entriesVerified,
          durationMs: Date.now() - startedAt,
        },
      );
    }

    return {
      ok: result.ok,
      entriesVerified: result.entriesVerified,
      brokenAtId: result.brokenAtId || null,
      reason: result.reason || null,
      detail: result.detail || null,
      verifyChainEntry,
      verifyChainError,
      skippedEmpty: false,
      durationMs: Date.now() - startedAt,
    };
  } finally {
    try { db.close(); } catch { /* swallow */ }
  }
}

module.exports = {
  // public API
  runScheduledVerification,
  getSchedule,

  // constants
  DEFAULT_SCHEDULE,
};
