// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Data Retention Service
// Configurable retention periods per data type. Scheduled purge job.
// Defaults: signals 90 days, audit 365 days, SLA 180 days,
//           messages 0 (deleted on session close), backups per config.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

const DEFAULT_RETENTION = {
  audit_log_days: 365,
  sla_measurements_days: 180,
  peer_messages_days: 0,      // deleted on session close, purge stragglers
  reports_days: 365,
  backups_days: 35,
  assessment_results_days: 730, // 2 years
  consent_log_days: 365,
  sessions_days: 30,
  // AI burnout-message caches (N1b). Freshness is governed by each row's
  // expires_at (a short window); this 7-day purge is a physical backstop
  // that removes orphaned rows — departed analysts, conditions that stopped
  // firing, or rows left behind if the precompute scheduler stops running.
  team_intervention_prompts_days: 7,
};

function getRetentionConfig() {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'retention_config'").get();
    db.close();
    return row ? { ...DEFAULT_RETENTION, ...JSON.parse(row.value) } : DEFAULT_RETENTION;
  } catch {
    return DEFAULT_RETENTION;
  }
}

function runRetentionPurge() {
  const config = getRetentionConfig();
  const db = getDb();
  const results = {};

  try {
    const purge = (table, dateCol, days, label) => {
      if (days <= 0 && label !== 'peer_messages') return;
      const cutoff = new Date(Date.now() - (days || 1) * 86400000).toISOString();
      // SECURITY: Whitelist table/column names to prevent SQL injection
      // Whitelist of (table, date_column) pairs that the retention
      // purge is allowed to operate on. Every table targeted by a
      // purge() call below MUST be in this map with its correct
      // date column, or the purge will throw 'Invalid table' and
      // abort the entire purge cycle.
      const SAFE_TABLES = {
        'audit_log': 'timestamp',
        'sla_measurements': 'measured_at',
        'peer_messages': 'created_at',
        'reports': 'generated_at',
        'analyst_consent_log': 'created_at',
        'sessions': 'expires_at',
        'notifications': 'created_at',
        'peer_sessions': 'created_at',
        'team_intervention_prompts': 'generated_at',
      };
      if (!SAFE_TABLES[table] || SAFE_TABLES[table] !== dateCol) throw new Error('Invalid table');
      const r = db.prepare(`DELETE FROM ${table} WHERE ${dateCol} < ?`).run(cutoff);
      results[label] = r.changes;
    };

    purge('audit_log', 'timestamp', config.audit_log_days, 'audit');
    purge('sla_measurements', 'measured_at', config.sla_measurements_days, 'sla');
    purge('peer_messages', 'created_at', Math.max(config.peer_messages_days, 1), 'messages');
    purge('reports', 'generated_at', config.reports_days, 'reports');
    purge('analyst_consent_log', 'created_at', config.consent_log_days, 'consent');
    purge('sessions', 'expires_at', config.sessions_days, 'sessions');
    purge('team_intervention_prompts', 'generated_at', config.team_intervention_prompts_days, 'ai_team_prompts');

    const totalPurged = Object.values(results).reduce((s, v) => s + v, 0);
    if (totalPurged > 0) {
      auditLog(null, 'RETENTION_PURGE', `Purged ${totalPurged} records: ${JSON.stringify(results)}`);
      logger.info('Retention purge complete', results);
    }
  } catch (err) {
    logger.error('Retention purge error', { error: err.message });
  } finally {
    db.close();
  }

  return results;
}

module.exports = { runRetentionPurge, getRetentionConfig, DEFAULT_RETENTION };
