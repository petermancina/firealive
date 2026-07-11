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
const { LdapClient } = require('../integrations/ldap');
const { openTier1 } = require('./tier1-seal');

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
      // Exclude the 'legacy-anonymous' system sentinel: a deliberate local,
      // inactive placeholder account (FK author-of-record for anonymized
      // messages), identified by its stable id rather than by role.
      const localAccounts = db.prepare(`
        SELECT id, username, name, role, created_at
        FROM users
        WHERE auth_method = 'local' AND id != 'legacy-anonymous'
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

// ═══════════════════════════════════════════════════════════════════════════════
// B5b — Offboarding detection (surface-only)
//
// Flags users who appear to have departed — absent from the directory (a real
// LDAPS presence check, FAIL-SAFE: a directory error is treated as UNKNOWN,
// never as absent), whose certificate access has been revoked or has expired,
// or who have gone stale — into offboarding_candidates (status 'pending'). It
// NEVER deactivates an account; a human resolves each candidate via the
// management surface. The partial-unique index on offboarding_candidates keeps
// at most one open (pending) candidate per user, so re-runs do not duplicate.
// ═══════════════════════════════════════════════════════════════════════════════

const OFFBOARD_STALE_DAYS = 90;

// Decide the single highest-priority offboarding source for a user, or null.
// Priority: ldap_absent > cert_revoked > cert_expired > stale.
async function classifyOffboardingSource(db, ldap, u, staleCutoff) {
  // 1. Directory absence (fail-safe). Only when we have a directory client and
  //    a directory identity to look up.
  if (ldap && (u.username || u.external_id)) {
    try {
      const result = await ldap.userExists(u.username || u.external_id);
      // found:false WITHOUT an error is a definitive directory miss. found:false
      // WITH an error means the directory was unreachable/erroring → treat as
      // UNKNOWN and do not flag.
      if (result && result.found === false && !result.error) {
        return { source: 'ldap_absent', detail: `Not present in directory (looked up ${u.username || u.external_id}).` };
      }
    } catch (_) {
      // unreachable → unknown → no flag (fail-safe)
    }
  }

  // 2/3. Certificate state — only meaningful for users who have ever held a
  //      certificate. A status of 'active' with a past expires_at is treated as
  //      expired (nothing flips the stored status on expiry).
  const certs = db.prepare(`
    SELECT
      SUM(CASE WHEN status = 'active' AND expires_at > datetime('now') THEN 1 ELSE 0 END) AS valid,
      SUM(CASE WHEN status = 'revoked' THEN 1 ELSE 0 END) AS revoked,
      SUM(CASE WHEN status = 'expired' OR (status = 'active' AND expires_at <= datetime('now')) THEN 1 ELSE 0 END) AS expired,
      COUNT(*) AS total
    FROM issued_certs WHERE user_id = ?
  `).get(u.id);
  if (certs && certs.total > 0 && (certs.valid || 0) === 0) {
    if ((certs.revoked || 0) > 0) {
      return { source: 'cert_revoked', detail: `All ${certs.total} issued certificate(s) revoked; none active.` };
    }
    if ((certs.expired || 0) > 0) {
      return { source: 'cert_expired', detail: `All ${certs.total} issued certificate(s) expired; none active.` };
    }
  }

  // 4. Stale — an established account with no recent login or directory check.
  //    A freshly-created account (created after the cutoff) is never flagged
  //    stale just because it has not logged in yet.
  const lastSeen = u.last_login || u.last_iam_check || null;
  if (u.created_at && u.created_at < staleCutoff && (!lastSeen || lastSeen < staleCutoff)) {
    return { source: 'stale', detail: `No activity since ${lastSeen || 'never'} (threshold ${OFFBOARD_STALE_DAYS}d).` };
  }

  return null;
}

// Run offboarding detection across the human SOC roles. Surface-only: inserts
// pending candidates, never deactivates. Returns a summary.
async function runOffboardingDetection() {
  const db = getDb();
  const detected = [];
  try {
    // Directory client — only if LDAP is configured + reachable enough to have
    // a saved config. (userExists is itself fail-safe per directory error.)
    let ldap = null;
    try {
      const row = db.prepare(
        "SELECT config_encrypted FROM integration_config WHERE integration_type = 'iam_ldap' AND status IN ('configured','operational')"
      ).get();
      if (row && row.config_encrypted) {
        const cfg = openTier1('integration_config.config_encrypted', row.config_encrypted);
        if (cfg && cfg.server) ldap = new LdapClient(cfg);
      }
    } catch (e) {
      logger.warn('Offboarding detection: LDAP config unavailable; directory checks skipped', { error: e.message });
    }

    const staleCutoff = new Date(Date.now() - OFFBOARD_STALE_DAYS * 86400000).toISOString();
    const users = db.prepare(
      "SELECT id, username, external_id, last_login, last_iam_check, created_at FROM users WHERE active = 1 AND role IN ('analyst','lead','admin')"
    ).all();

    for (const u of users) {
      let src = null;
      try {
        src = await classifyOffboardingSource(db, ldap, u, staleCutoff);
      } catch (e) {
        logger.warn('Offboarding classify failed for a user; skipping', { error: e.message });
        continue;
      }
      if (!src) continue;
      const r = db.prepare(`
        INSERT OR IGNORE INTO offboarding_candidates (user_id, source, detail, status)
        VALUES (?, ?, ?, 'pending')
      `).run(u.id, src.source, src.detail);
      if (r.changes > 0) detected.push({ userId: u.id, source: src.source, detail: src.detail });
    }

    auditLog(null, 'OFFBOARDING_DETECTION', `scanned=${users.length} new_candidates=${detected.length}`, null);
    logger.info('Offboarding detection complete', { scanned: users.length, newCandidates: detected.length });
    return { scanned: users.length, newCandidates: detected.length, detected };
  } catch (err) {
    logger.error('Offboarding detection error', { error: err.message });
    return { scanned: 0, newCandidates: 0, detected: [], error: err.message };
  } finally {
    db.close();
  }
}

module.exports = { runAccountReview, STALE_THRESHOLD_DAYS, runOffboardingDetection, classifyOffboardingSource, OFFBOARD_STALE_DAYS };
