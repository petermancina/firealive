// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Recertification Service
// Periodic prompts for team leads to review:
//   - User accounts (still needed? correct role/tier?)
//   - Analyst skill assessments (outdated?)
//   - Integration configs (new systems? decommissioned ones?)
//   - Configuration settings (still appropriate?)
//   - Log/backup destinations (still valid?)
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

const DEFAULT_RECERT_INTERVAL_DAYS = 90; // quarterly

function getRecertConfig() {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'recert_config'").get();
    db.close();
    return row ? JSON.parse(row.value) : { intervalDays: DEFAULT_RECERT_INTERVAL_DAYS, lastCompleted: null, enabled: true };
  } catch { return { intervalDays: DEFAULT_RECERT_INTERVAL_DAYS, lastCompleted: null, enabled: true }; }
}

function checkRecertDue() {
  const config = getRecertConfig();
  if (!config.enabled) return { due: false, reason: 'Recertification disabled' };

  const lastDate = config.lastCompleted ? new Date(config.lastCompleted) : new Date(0);
  const daysSince = Math.floor((Date.now() - lastDate.getTime()) / 86400000);
  const due = daysSince >= config.intervalDays;

  if (due) {
    auditLog(null, 'RECERT_DUE', `${daysSince} days since last recertification (interval: ${config.intervalDays}d)`);
  }

  return { due, daysSince, intervalDays: config.intervalDays, lastCompleted: config.lastCompleted };
}

function generateRecertReport() {
  const db = getDb();
  const report = { generatedAt: new Date().toISOString(), sections: {} };

  try {
    // 1. Account review
    const users = db.prepare('SELECT id, username, name, role, tier, shift, last_login, created_at, auth_method FROM users ORDER BY role, name').all();
    const staleDate = new Date(Date.now() - 90 * 86400000).toISOString();
    report.sections.accounts = {
      total: users.length,
      stale: users.filter(u => !u.last_login || u.last_login < staleDate).length,
      byRole: {},
      users: users.map(u => ({
        id: u.id, name: u.name, role: u.role, tier: u.tier,
        lastLogin: u.last_login || 'never',
        stale: !u.last_login || u.last_login < staleDate,
        authMethod: u.auth_method,
      })),
    };
    for (const u of users) report.sections.accounts.byRole[u.role] = (report.sections.accounts.byRole[u.role] || 0) + 1;

    // 2. Integration review
    const integrations = db.prepare('SELECT integration_type, status, last_test_at, updated_at FROM integration_config ORDER BY integration_type').all();
    const staleIntDate = new Date(Date.now() - 30 * 86400000).toISOString();
    report.sections.integrations = {
      total: integrations.length,
      operational: integrations.filter(i => i.status === 'operational').length,
      untested: integrations.filter(i => !i.last_test_at || i.last_test_at < staleIntDate).length,
      items: integrations,
    };

    // 3. Assessment staleness
    const assessments = db.prepare('SELECT id, name, tier, created_at, status FROM assessments WHERE status = ? ORDER BY created_at', ).all('active');
    const staleAssessDate = new Date(Date.now() - 180 * 86400000).toISOString();
    report.sections.assessments = {
      total: assessments.length,
      stale: assessments.filter(a => a.created_at < staleAssessDate).length,
      items: assessments.map(a => ({ ...a, stale: a.created_at < staleAssessDate })),
    };

    // 4. Configuration summary
    const configKeys = db.prepare("SELECT COUNT(*) AS c FROM team_config WHERE key NOT LIKE 'peer_%' AND key NOT LIKE 'ooda_%' AND key NOT LIKE 'cert%' AND key NOT LIKE 'pending_%' AND key NOT LIKE 'lockout_%' AND key NOT LIKE 'reset_%'").get();
    report.sections.configuration = { totalSettings: configKeys.c };

    // 5. Backup health
    const recentBackup = db.prepare("SELECT created_at, status FROM backups ORDER BY created_at DESC LIMIT 1").get();
    report.sections.backups = {
      lastBackup: recentBackup?.created_at || 'never',
      lastStatus: recentBackup?.status || 'none',
    };

  } catch (err) {
    logger.error('Recert report error', { error: err.message });
    report.error = err.message;
  } finally {
    db.close();
  }

  return report;
}

function completeRecert(userId) {
  try {
    const db = getDb();
    const config = getRecertConfig();
    config.lastCompleted = new Date().toISOString();
    config.lastCompletedBy = userId;
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('recert_config', ?, ?)").run(JSON.stringify(config), userId);
    db.close();
    auditLog(userId, 'RECERT_COMPLETED', 'Recertification review completed');
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

module.exports = { checkRecertDue, generateRecertReport, completeRecert, getRecertConfig };
