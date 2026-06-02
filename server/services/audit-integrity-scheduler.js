// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Audit Log Integrity Scheduler (B5a)
//
// Runs the Log Integrity check on a cadence. One cycle:
//   1. Verify the audit_log hash chain incrementally from the latest signed
//      checkpoint forward (O(new rows)). The full authoritative walk lives on
//      GET /api/audit/integrity ("Verify Now"); this is the always-on watch.
//   2. If intact, write a fresh Ed25519-signed checkpoint that notarizes the
//      current chain head. If broken, raise a critical AUDIT_CHAIN_BREAK alert
//      through the B3 alert router (audit + SIEM + SOAR + notification + email
//      + webhook per the matrix) and do NOT checkpoint a broken chain.
//   3. Run the gap check (detectMissingLogs): deletions show up as id gaps and
//      offline windows as time gaps. The two checks are complementary — the
//      hash chain catches in-place content edits and full rewrites; the gap
//      check catches missing rows.
//
// Config (team_config.audit_integrity_config, all optional):
//   { enabled: true, interval_minutes: 60, gap_threshold_minutes: 30 }
// enabled is honored every cycle; interval_minutes is read at boot (restart to
// change the cadence), matching the other schedulers.
// ═══════════════════════════════════════════════════════════════════════════

'use strict';

const { logger } = require('./logger');

const DEFAULT_INTERVAL_MS = 3600000; // 60 minutes
const DEFAULT_GAP_THRESHOLD_MIN = 30;
const CONFIG_KEY = 'audit_integrity_config';

function _loadConfig(db) {
  try {
    const row = db.prepare('SELECT value FROM team_config WHERE key = ?').get(CONFIG_KEY);
    return row ? JSON.parse(row.value) : {};
  } catch (_e) {
    return {};
  }
}

// One Log-Integrity cycle. Returns a small status object (used by tests and the
// manual evaluate path).
function runIntegrityCycle(db, deps = {}) {
  const config = _loadConfig(db);
  if (config && config.enabled === false) return { skipped: 'disabled' };

  const auditChain = deps.auditChain || require('./audit-chain');
  const routeAlert = deps.routeAlert || require('./alert-router').routeAlert;

  const out = { chain: null, checkpointId: null, gapFindings: null };

  // 1. Chain integrity (incremental from the latest signed checkpoint).
  let result;
  try {
    result = auditChain.verifyIncremental(db);
  } catch (e) {
    logger.warn('audit integrity verify error', { error: e.message });
    return { error: e.message };
  }
  out.chain = result.intact ? 'intact' : 'broken';

  if (result.intact) {
    try {
      const cp = auditChain.createCheckpoint(db);
      out.checkpointId = cp ? cp.id : null;
    } catch (e) {
      logger.warn('audit checkpoint failed', { error: e.message });
    }
  } else {
    try {
      const msg = `Audit log integrity check failed: ${result.reason || 'unknown'} at id ${result.brokenAt}`;
      Promise.resolve(
        routeAlert(db, {
          type: 'AUDIT_CHAIN_BREAK',
          severity: 'critical',
          message: msg,
          timestamp: new Date().toISOString(),
        })
      ).catch(() => {});
    } catch (e) {
      logger.warn('audit chain break alert failed', { error: e.message });
    }
    logger.warn('Audit log hash chain BROKEN', { reason: result.reason, brokenAt: result.brokenAt });
  }

  // 2. Gap check (deletions / time gaps). detectMissingLogs opens its own
  //    connection and routes its own alert.
  try {
    const { detectMissingLogs } = require('./soar-alerting');
    const thresholdMinutes = (config && config.gap_threshold_minutes) || DEFAULT_GAP_THRESHOLD_MIN;
    out.gapFindings = detectMissingLogs(thresholdMinutes) || null;
  } catch (e) {
    logger.warn('audit gap check failed', { error: e.message });
  }

  return out;
}

// Start the periodic scheduler. No-op cycles when disabled via config.
function startAuditIntegrityScheduler(getDb, deps = {}) {
  let intervalMs = deps.intervalMs;
  if (!intervalMs) {
    try {
      const db = getDb();
      try {
        const cfg = _loadConfig(db);
        intervalMs = cfg && cfg.interval_minutes ? cfg.interval_minutes * 60000 : DEFAULT_INTERVAL_MS;
      } finally {
        db.close();
      }
    } catch (_e) {
      intervalMs = DEFAULT_INTERVAL_MS;
    }
  }

  const handle = setInterval(() => {
    let db;
    try {
      db = getDb();
      runIntegrityCycle(db, deps);
    } catch (e) {
      logger.warn('audit integrity cycle error', { error: e.message });
    } finally {
      if (db) {
        try { db.close(); } catch (_e) { /* already closed */ }
      }
    }
  }, intervalMs);
  if (handle && typeof handle.unref === 'function') handle.unref();
  return handle;
}

module.exports = { startAuditIntegrityScheduler, runIntegrityCycle, CONFIG_KEY };
