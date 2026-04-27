// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Automated Account Review
// Scheduled job that detects:
//   - Stale accounts (no login in 90+ days)
//   - Orphaned accounts (not in LDAP/SSO sync)
//   - Privilege escalation patterns
//   - Duplicate accounts (same name or external_id)
//   - Suspicious usage patterns
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { auditLog } = require('../middleware/audit');

const STALE_THRESHOLD_DAYS = 90;
const SUSPICIOUS_API_CALLS_PER_HOUR = 500;

/**
 * Run full account review. Returns findings array.
 */
function runAccountReview() {
  const findings = [];
  const db = getDb();

  try {
    // 1. Stale accounts — no login in 90+ days
    const staleDate = new Date(Date.now() - STALE_THRESHOLD_DAYS * 86400000).toISOString();
    const stale = db.prepare(`
      SELECT id, username, name, role, last_login, created_at
      FROM users
      WHERE (last_login IS NULL OR last_login < ?) AND created_at < ?
    `).all(staleDate, staleDate);

    for (const u of stale) {
      findings.push({
        type: 'STALE_ACCOUNT',
        severity: 'medium',
        userId: u.id,
        username: u.username,
        detail: `No login since ${u.last_login || 'never'}. Account created ${u.created_at}.`,
        recommendation: 'Review account — disable if no longer active.',
      });
    }

    // 2. Orphaned local accounts — created locally but LDAP is configured
    const ldapConfig = db.prepare("SELECT id FROM integration_config WHERE integration_type = 'iam_ldap' AND status = 'operational'").get();
    if (ldapConfig) {
      const localAccounts = db.prepare(`
        SELECT id, username, name, role, created_at
        FROM users
        WHERE auth_method = 'local' AND role != 'developer'
      `).all();

      for (const u of localAccounts) {
        findings.push({
          type: 'ORPHANED_LOCAL_ACCOUNT',
          severity: 'high',
          userId: u.id,
          username: u.username,
          detail: `Local account exists while LDAP is operational. Account not provisioned via directory sync.`,
          recommendation: 'Investigate — could be a backdoor account. Migrate to LDAP or remove.',
        });
      }
    }

    // 3. Duplicate accounts
    const dupes = db.prepare(`
      SELECT name, COUNT(*) AS count, GROUP_CONCAT(id) AS ids
      FROM users
      GROUP BY LOWER(name)
      HAVING count > 1
    `).all();

    for (const d of dupes) {
      findings.push({
        type: 'DUPLICATE_ACCOUNT',
        severity: 'high',
        detail: `${d.count} accounts with name "${d.name}": ${d.ids}`,
        recommendation: 'Review for fake/cloned accounts.',
      });
    }

    // 4. Privilege escalation — analyst accounts that made admin-level API calls
    const recentDate = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const escalations = db.prepare(`
      SELECT al.user_id, u.name, u.role, al.event_type, COUNT(*) AS count
      FROM audit_log al
      JOIN users u ON u.id = al.user_id
      WHERE al.timestamp > ?
        AND u.role = 'analyst'
        AND (al.event_type LIKE 'APIKEY%' OR al.event_type LIKE 'INTEGRATION%'
             OR al.event_type LIKE 'BACKUP%' OR al.event_type LIKE 'NOTIFICATION_CONFIG%'
             OR al.event_type LIKE 'USER_%')
      GROUP BY al.user_id, al.event_type
    `).all(recentDate);

    for (const e of escalations) {
      findings.push({
        type: 'PRIVILEGE_ESCALATION',
        severity: 'critical',
        userId: e.user_id,
        username: e.name,
        detail: `Analyst "${e.name}" performed ${e.count} admin-level action(s): ${e.event_type}`,
        recommendation: 'IMMEDIATE: Investigate account compromise. Disable if unauthorized.',
      });
    }

    // 5. Excessive API activity (potential automated abuse)
    const highActivity = db.prepare(`
      SELECT user_id, COUNT(*) AS count,
             (SELECT name FROM users WHERE id = audit_log.user_id) AS name
      FROM audit_log
      WHERE timestamp > datetime('now', '-1 hour')
      GROUP BY user_id
      HAVING count > ?
    `).all(SUSPICIOUS_API_CALLS_PER_HOUR);

    for (const h of highActivity) {
      findings.push({
        type: 'EXCESSIVE_ACTIVITY',
        severity: 'high',
        userId: h.user_id,
        username: h.name,
        detail: `${h.count} API calls in the last hour (threshold: ${SUSPICIOUS_API_CALLS_PER_HOUR})`,
        recommendation: 'Review for automated abuse or compromised credentials.',
      });
    }

    // 6. Accounts with no role assignment
    const noRole = db.prepare("SELECT id, username, name FROM users WHERE role IS NULL OR role = ''").all();
    for (const u of noRole) {
      findings.push({
        type: 'NO_ROLE',
        severity: 'medium',
        userId: u.id,
        username: u.username,
        detail: `Account "${u.name}" has no role assigned.`,
        recommendation: 'Assign role or remove account.',
      });
    }

  } catch (err) {
    logger.error('Account review error', { error: err.message });
    findings.push({ type: 'REVIEW_ERROR', severity: 'high', detail: err.message });
  } finally {
    db.close();
  }

  // Log findings
  if (findings.length > 0) {
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    auditLog(null, 'ACCOUNT_REVIEW', `${findings.length} findings (${critical} critical, ${high} high)`);
    logger.warn('Account review completed with findings', { count: findings.length, critical, high });
  } else {
    auditLog(null, 'ACCOUNT_REVIEW', 'No findings — all accounts clean');
    logger.info('Account review completed — no findings');
  }

  return findings;
}

module.exports = { runAccountReview, STALE_THRESHOLD_DAYS };
