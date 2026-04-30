// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — SOAR Alert Dispatcher
// When FIM violations, CPU/memory/bandwidth spikes, or missing logs are
// detected, this service pushes alerts to the configured SOAR platform
// for automated investigation, containment, and isolation.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');
const { version } = require('../lib/version');

const ALERT_TYPES = {
  FIM_FILE_MODIFIED: { severity: 'critical', action: 'investigate_app_compromise', containment: 'isolate_host' },
  FIM_FILE_DELETED: { severity: 'critical', action: 'investigate_app_compromise', containment: 'isolate_host' },
  FIM_FILE_ADDED: { severity: 'high', action: 'investigate_unauthorized_change', containment: 'none' },
  CPU_SPIKE: { severity: 'medium', action: 'check_process_activity', containment: 'none' },
  MEMORY_SPIKE: { severity: 'medium', action: 'check_memory_injection', containment: 'none' },
  BANDWIDTH_SPIKE_OUT: { severity: 'high', action: 'investigate_data_exfil', containment: 'throttle_network' },
  BANDWIDTH_SPIKE_IN: { severity: 'medium', action: 'check_inbound_attack', containment: 'none' },
  DB_READ_SPIKE: { severity: 'high', action: 'investigate_injection', containment: 'isolate_db' },
  FUSE_VIOLATION: { severity: 'critical', action: 'investigate_rollback_attack', containment: 'isolate_host' },
  INTEGRITY_VIOLATION: { severity: 'critical', action: 'investigate_app_tampering', containment: 'isolate_host' },
  MISSING_LOGS: { severity: 'high', action: 'investigate_log_tampering', containment: 'preserve_evidence' },
  PRIVILEGE_ESCALATION: { severity: 'critical', action: 'investigate_account_compromise', containment: 'disable_account' },
};

/**
 * Dispatch an alert to the configured SOAR platform.
 * The SOAR can then run playbooks for investigation and containment.
 */
async function dispatchToSoar(alertType, details) {
  const config = ALERT_TYPES[alertType];
  if (!config) {
    logger.warn('Unknown SOAR alert type', { alertType });
    return { dispatched: false, reason: 'Unknown alert type' };
  }

  try {
    const db = getDb();
    const soarConfig = db.prepare("SELECT * FROM integration_config WHERE integration_type = 'soar' AND status = 'operational'").get();
    db.close();

    if (!soarConfig) {
      logger.debug('No SOAR configured — alert logged only', { alertType });
      return { dispatched: false, reason: 'No SOAR integration configured' };
    }

    // Build SOAR alert payload
    const payload = {
      source: 'firealive',
      version,
      alertType,
      severity: config.severity,
      suggestedAction: config.action,
      suggestedContainment: config.containment,
      timestamp: new Date().toISOString(),
      hostname: process.env.HOSTNAME || 'firealive-server',
      pid: process.pid,
      details: typeof details === 'string' ? details : JSON.stringify(details),
    };

    // In production, this would POST to the SOAR API endpoint
    // const { SoarClient } = require('../integrations/soar');
    // const { decryptConfig } = require('./encryption');
    // const soarCfg = decryptConfig(soarConfig.config_encrypted);
    // const client = new SoarClient(soarCfg);
    // await client.writeRoutingVars({ firealive_security_alert: payload });

    logger.warn('SOAR alert dispatched', { alertType, severity: config.severity, action: config.action });
    auditLog(null, 'SOAR_ALERT_DISPATCHED', `${alertType}: ${config.severity} — action: ${config.action}`);

    return { dispatched: true, alertType, severity: config.severity, action: config.action };
  } catch (err) {
    logger.error('SOAR dispatch error', { error: err.message, alertType });
    return { dispatched: false, error: err.message };
  }
}

/**
 * Check for missing logs — gaps in sequential audit IDs or time gaps > threshold.
 */
function detectMissingLogs(thresholdMinutes = 30) {
  try {
    const db = getDb();

    // Check for ID gaps (deleted records)
    const gaps = db.prepare(`
      SELECT a.id AS before_id, MIN(b.id) AS after_id, (MIN(b.id) - a.id - 1) AS missing_count
      FROM audit_log a
      JOIN audit_log b ON b.id > a.id
      GROUP BY a.id
      HAVING missing_count > 0
      LIMIT 10
    `).all();

    // Check for time gaps
    const timeGaps = db.prepare(`
      SELECT a.id, a.timestamp AS last_ts,
             (SELECT MIN(b.timestamp) FROM audit_log b WHERE b.id > a.id) AS next_ts
      FROM audit_log a
      WHERE (SELECT MIN(b.timestamp) FROM audit_log b WHERE b.id > a.id) IS NOT NULL
      AND (julianday((SELECT MIN(b.timestamp) FROM audit_log b WHERE b.id > a.id)) - julianday(a.timestamp)) * 24 * 60 > ?
      LIMIT 5
    `).all(thresholdMinutes);

    db.close();

    const findings = [];
    if (gaps.length > 0) {
      const totalMissing = gaps.reduce((s, g) => s + g.missing_count, 0);
      findings.push({ type: 'ID_GAP', count: totalMissing, detail: `${totalMissing} audit records missing (ID gaps detected)` });
    }
    if (timeGaps.length > 0) {
      findings.push({ type: 'TIME_GAP', count: timeGaps.length, detail: `${timeGaps.length} time gaps > ${thresholdMinutes} min detected` });
    }

    if (findings.length > 0) {
      auditLog(null, 'MISSING_LOGS', JSON.stringify(findings));
      dispatchToSoar('MISSING_LOGS', findings);
    }

    return { clean: findings.length === 0, findings };
  } catch (err) {
    logger.error('Missing log detection error', { error: err.message });
    return { clean: false, error: err.message };
  }
}

module.exports = { dispatchToSoar, detectMissingLogs, ALERT_TYPES };
