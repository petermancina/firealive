// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduler Service
// Handles: scheduled reports, backup automation, signal aggregation,
// lighter queue expiry, SLA measurement, OODA scheduled-mode replenishment
// ═══════════════════════════════════════════════════════════════════════════════

const cron = require('node-cron');
const { logger } = require('./logger');
const { versionLabel } = require('../lib/version');
const notifications = require('./notifications');

const schedulerService = {
  jobs: [],

  start() {
    // ── Expire lighter queue requests ────────────────────────────────────
    this.jobs.push(cron.schedule('*/5 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const db = getDb();
        const expired = db.prepare(
          'UPDATE lighter_queue_requests SET status = ? WHERE status = ? AND expires_at < datetime("now")'
        ).run('expired', 'active');
        if (expired.changes > 0) {
          logger.info(`Expired ${expired.changes} lighter queue request(s)`);
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: lighter queue expiry failed', { error: err.message });
      }
    }));

    // ── Scheduled report generation ──────────────────────────────────────
    this.jobs.push(cron.schedule('0 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const db = getDb();
        const config = db.prepare('SELECT * FROM report_config WHERE id = ?').get('default');
        if (!config) { db.close(); return; }

        const now = new Date();
        const dayNames = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday'];
        const currentDay = dayNames[now.getDay()];
        const currentHour = now.getHours().toString().padStart(2, '0') + ':00';

        if (config.schedule === 'daily' && currentHour === config.time_of_day) {
          generateReport(db, config, 'scheduled');
        } else if (config.schedule === 'weekly' && currentDay === config.day_of_week && currentHour === config.time_of_day) {
          generateReport(db, config, 'scheduled');
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: report generation failed', { error: err.message });
      }
    }));

    // ── Automated backup ─────────────────────────────────────────────────
    const backupSchedule = process.env.BACKUP_SCHEDULE || '0 2 * * *';
    this.jobs.push(cron.schedule(backupSchedule, () => {
      try {
        logger.info('Starting scheduled backup');
        // Backup logic will be in backup route/service
        const { performBackup } = require('./backup');
        performBackup('daily-auto');
      } catch (err) {
        logger.error('Scheduler: backup failed', { error: err.message });
      }
    }));

    // ── R3d-2: scheduled chain integrity verification ──────────────────────
    //
    // Walks the entire backup_chain checking linkage + per-entry hash
    // recomputation + Ed25519 signature verification. Appends a VERIFY
    // entry to the chain recording the result. Emits a
    // CHAIN_INTEGRITY_FAILURE audit event on detected tampering --
    // distinct from informational CHAIN_INTEGRITY_VERIFIED so SIEM
    // feeds can alert on integrity failures independently.
    //
    // Default schedule is one hour after the default backup time
    // (03:00 UTC vs 02:00 UTC) so they don't pile up on the same
    // minute. Operators can override via CHAIN_VERIFY_SCHEDULE env
    // var; chain-verifier.js getSchedule() handles the fallback.
    //
    // Empty-chain skip: on fresh installs with no backups taken yet,
    // the verifier returns immediately without writing a VERIFY entry
    // or audit log. Reason: nothing to verify; entries here would be
    // noise.
    //
    // Broken-chain appends still succeed: appendChainEntry depends on
    // the CURRENT head only, not historical integrity, so even on a
    // tampered chain the VERIFY entry recording the discovery lands
    // correctly at the head.
    const chainVerifierSchedule = (() => {
      try {
        return require('./chain-verifier').getSchedule();
      } catch {
        return '0 3 * * *';
      }
    })();
    this.jobs.push(cron.schedule(chainVerifierSchedule, () => {
      try {
        const { runScheduledVerification } = require('./chain-verifier');
        runScheduledVerification({ verifier: 'scheduled' });
      } catch (err) {
        logger.error('Scheduler: chain verification failed', { error: err.message });
      }
    }));

    // ── R3d-3: scheduled retry of due push failures ──────────────────────
    //
    // Picks up failed pushes whose next_retry_at has passed and runs
    // them via backupPush.retryAllDuePushes. Operates on the schedule
    // from BACKUP_PUSH_RETRY_SCHEDULE env var; defaults to hourly at
    // minute 15 ('15 * * * *') -- offset from the chain verifier
    // (03:00) and the other top-of-hour jobs (IAM recert at 09:00,
    // OODA replenishment at :00) to avoid contention.
    //
    // The exponential backoff schedule in backup-push.js spaces
    // retries at 5min, 30min, 2hr, 12hr after each failure. Hourly
    // scheduler ticks mean a 5min-due retry waits at most 60min
    // before being picked up. Operators wanting faster retries can
    // manually trigger via POST /api/backup-push/retry-all-due
    // (commit 11 of this phase) without waiting for the next tick.
    //
    // Per-tick error handling matches the rest of the scheduler:
    // exceptions logged at error level, scheduler keeps running.
    // Pushes that throw inside the orchestrator are caught and
    // surfaced via backup_pushes.error_message; this layer only
    // sees catastrophic failures (DB unreachable, etc.).
    const pushRetrySchedule = process.env.BACKUP_PUSH_RETRY_SCHEDULE || '15 * * * *';
    this.jobs.push(cron.schedule(pushRetrySchedule, async () => {
      try {
        const { getDb } = require('../db/init');
        const backupPush = require('./backup-push');
        const db = getDb();
        try {
          const result = await backupPush.retryAllDuePushes(db, { logger });
          if (result.retried > 0) {
            const succeeded = result.results.filter(r => r.ok && !r.skipped).length;
            const failed = result.results.filter(r => !r.ok && !r.skipped).length;
            const skipped = result.results.filter(r => r.skipped).length;
            logger.info('Scheduler: backup push retry sweep complete', {
              retried: result.retried,
              succeeded,
              failed,
              skipped,
            });
          }
        } finally {
          try { db.close(); } catch { /* swallow */ }
        }
      } catch (err) {
        logger.error('Scheduler: backup push retry sweep failed', { error: err.message });
      }
    }));

    // ── Email notification pipeline ──────────────────────────────────────
    const emailIntervalSec = parseInt(process.env.NOTIFICATIONS_EMAIL_INTERVAL_SEC || '60', 10);
    const emailCronExpr = emailIntervalSec >= 60
      ? `*/${Math.floor(emailIntervalSec / 60)} * * * *`
      : '* * * * *';
    this.jobs.push(cron.schedule(emailCronExpr, async () => {
      try {
        const { processQueue } = require('./notifications-email');
        const stats = await processQueue();
        if (stats.processed > 0 || stats.skipped > 0) {
          logger.info('Notifications email pipeline cycle', stats);
        }
      } catch (err) {
        logger.error('Scheduler: notifications email pipeline failed', { error: err.message });
      }    
    }));

    // ── IAM recertification daily check ──────────────────────────────────
    // Runs once daily at 09:00 local time. If recertification is due (per
    // the configured interval, default 90 days), notifies every lead and
    // admin so they can run the recert workflow.
    this.jobs.push(cron.schedule('0 9 * * *', () => {
      try {
        const { checkRecertDue } = require('./recertification');
        const status = checkRecertDue();
        if (!status.due) return;

        const eligible = notifications.getEligibleRecipients('iam_recert_due', {
          roles: ['lead', 'admin'],
          activeOnly: true,
        });

        let notifiedCount = 0;
        for (const recipientId of eligible) {
          try {
            notifications.notify({
              recipientId,
              eventType: 'iam_recert_due',
              title: 'IAM recertification is due',
              body: `${status.daysSince} days have passed since the last recertification (interval: ${status.intervalDays} days). Open the Recertification tab to review user accounts, integrations, assessments, and configuration settings.`,
              linkTab: 'recertification',
              linkParams: { focus: 'review' },
            });
            notifiedCount++;
          } catch (notifyErr) {
            logger.warn('IAM recert: notify recipient failed (non-fatal)', { recipientId, error: notifyErr.message });
          }
        }
        logger.info(`IAM recert daily job: notified ${notifiedCount} lead/admin recipient(s)`);
      } catch (err) {
        logger.error('Scheduler: IAM recert daily job failed', { error: err.message });
      }
    }));

    // ── OODA scheduled-mode replenishment (Phase F4c) ────────────────────
    //
    // Runs hourly at :00. For each ir_policy with replenishment_config.mode
    // === 'scheduled', checks whether the current hour and day-of-week
    // match the policy's scheduled_hour and scheduled_days values. If so,
    // and no queued/running job exists for that policy, enqueues a
    // replenishment job using the policy's batch_size.
    //
    // Schedule format (in replenishment_config JSON):
    //
    //   { "mode": "scheduled",
    //     "scheduled_hour": 0-23,           required; hour-of-day to fire
    //     "scheduled_days": ["mon","tue"],  optional; if omitted, fires
    //                                        every day. Strings are 3-letter
    //                                        lowercase: sun, mon, tue, wed,
    //                                        thu, fri, sat
    //     "batch_size": 1-20                target_count_per_difficulty
    //                                        for the enqueued job (defaults
    //                                        to 5 if missing or invalid)
    //   }
    //
    // Skip-if-already-pending guard: prevents pile-up if a previous
    // scheduled run's job hasn't completed by the next firing.
    //
    // Defense in depth: malformed replenishment_config JSON is silently
    // skipped (try/catch around JSON.parse), invalid scheduled_hour values
    // are silently skipped, missing or invalid batch_size falls back to 5.
    // Per-policy enqueue errors are logged but don't stop the loop —
    // other policies still get their scheduled refills even if one fails.
    this.jobs.push(cron.schedule('0 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const oodaJobs = require('./ooda-generation-jobs');
        const db = getDb();

        const now = new Date();
        const currentHour = now.getHours();
        const dayNames = ['sun','mon','tue','wed','thu','fri','sat'];
        const currentDay = dayNames[now.getDay()];

        const policies = db.prepare(`
          SELECT id, title, replenishment_config FROM ir_policies
          WHERE deleted_at IS NULL
        `).all();

        let enqueued = 0;
        let skippedAlreadyQueued = 0;
        let skippedNotMatched = 0;

        for (const policy of policies) {
          let cfg;
          try {
            cfg = JSON.parse(policy.replenishment_config || '{}');
          } catch (parseErr) {
            // Malformed config — skip silently. The policy still works
            // for analyst plays; just no scheduled replenishment.
            continue;
          }

          if (cfg.mode !== 'scheduled') continue;

          const scheduledHour = parseInt(cfg.scheduled_hour, 10);
          if (!Number.isInteger(scheduledHour) || scheduledHour < 0 || scheduledHour > 23) {
            // Invalid hour — skip until config is corrected
            continue;
          }
          if (scheduledHour !== currentHour) {
            skippedNotMatched++;
            continue;
          }

          // scheduled_days is optional; null/missing means "every day"
          if (Array.isArray(cfg.scheduled_days) && cfg.scheduled_days.length > 0) {
            if (!cfg.scheduled_days.includes(currentDay)) {
              skippedNotMatched++;
              continue;
            }
          }

          // Skip if a job is already queued or running for this policy.
          // Prevents pile-up when previous scheduled runs haven't
          // completed by the next firing.
          const existing = db.prepare(`
            SELECT id FROM ooda_generation_jobs
            WHERE policy_id = ? AND status IN ('queued', 'running')
            LIMIT 1
          `).get(policy.id);
          if (existing) {
            skippedAlreadyQueued++;
            continue;
          }

          // Resolve batch_size with a sensible fallback if config is missing
          // or out of range
          const rawBatchSize = parseInt(cfg.batch_size, 10);
          const batchSize = (Number.isInteger(rawBatchSize)
                              && rawBatchSize >= 1
                              && rawBatchSize <= 20)
                              ? rawBatchSize : 5;

          try {
            const jobId = oodaJobs.enqueueJob({
              policy_id: policy.id,
              mode: 'scheduled',
              target_count_per_difficulty: batchSize,
              enqueued_by: null,  // system action; no user attribution
            });
            enqueued++;
            logger.info(`Scheduled replenishment enqueued`, {
              policy_id: policy.id,
              policy_title: policy.title,
              job_id: jobId,
              batch_size: batchSize,
            });
          } catch (enqueueErr) {
            logger.error('Scheduled replenishment: enqueue failed', {
              policy_id: policy.id,
              policy_title: policy.title,
              error: enqueueErr.message,
            });
          }
        }

        db.close();

        if (enqueued > 0 || skippedAlreadyQueued > 0) {
          logger.info(`Scheduled replenishment cycle complete`, {
            enqueued,
            skipped_already_queued: skippedAlreadyQueued,
            skipped_not_matched: skippedNotMatched,
            policies_examined: policies.length,
          });
        }
      } catch (err) {
        logger.error('Scheduler: scheduled replenishment failed', { error: err.message });
      }
    }));

    logger.info(`Scheduler started with ${this.jobs.length} jobs (email pipeline interval: ${emailIntervalSec}s)`);
  },

  stop() {
    this.jobs.forEach(j => j.stop());
    this.jobs = [];
    logger.info('Scheduler stopped');
  }
};

function generateReport(db, config, type) {
  const crypto = require('crypto');
  const sections = JSON.parse(config.sections || '{}');
  const analysts = db.prepare('SELECT * FROM users WHERE role = ?').all('analyst');

  const report = {
    generated: new Date().toISOString(),
    platform: `FireAlive ${versionLabel}`,
    type,
    depersonalized: true,
    sections: {},
  };

  if (sections.teamHealth) {
    report.sections.teamHealth = {
      totalAnalysts: analysts.length,
      byShift: { day: analysts.filter(a => a.shift === 'day').length, swing: analysts.filter(a => a.shift === 'swing').length, night: analysts.filter(a => a.shift === 'night').length },
    };
  }
  if (sections.tierBreakdown) {
    report.sections.tierBreakdown = {
      l1: analysts.filter(a => a.tier === 1).length,
      l2: analysts.filter(a => a.tier === 2).length,
      l3: analysts.filter(a => a.tier === 3).length,
    };
  }

  const content = JSON.stringify(report, null, 2);
  db.prepare('INSERT INTO reports (type, format, content, sections_count) VALUES (?, ?, ?, ?)')
    .run(type, config.format, Buffer.from(content), Object.keys(report.sections).length);

  logger.info(`Report generated: ${type}, ${Object.keys(report.sections).length} sections`);
}

module.exports = { schedulerService };
