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

    // ── Ephemeral chat retention sweep (U3) ──────────────────────────────
    // Enforces the "retained five minutes after the conversation closes, then
    // permanently deleted" claim for BOTH peer chat and lead chat. Runs every
    // minute so a closed conversation's transport ciphertext is gone within
    // five to six minutes of close. Session/thread records persist (they are
    // reusable pairing anchors), and any flagged content lives independently in
    // the abuse evidence vault, so this sweep never destroys material a reviewer
    // still needs.
    this.jobs.push(cron.schedule('* * * * *', () => {
      try {
        this.sweepEphemeralChatRetention();
      } catch (err) {
        logger.error('Scheduler: ephemeral chat retention sweep failed', { error: err.message });
      }
    }));

    // ── Expire peer board threads (U2) ───────────────────────────────────
    // A board thread is removed once every post in it — the root and all
    // replies — is past its 7-day window; deleting the root cascades the
    // replies via the thread_root_id foreign key. A thread is never swept
    // while any post in it is pending or held under abuse review
    // (removed_pending_review = 1): the evidence vault keeps an independent
    // copy of flagged content, so this sweep can never destroy material a
    // lead still needs. Daily is ample for a 7-day window.
    this.jobs.push(cron.schedule('30 3 * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const db = getDb();
        const swept = db.prepare(`
          DELETE FROM peer_board_messages
          WHERE id IN (
            SELECT root.id FROM peer_board_messages root
            WHERE root.parent_id IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM peer_board_messages m
                WHERE (m.id = root.id OR m.thread_root_id = root.id)
                  AND m.removed_pending_review = 1
              )
              AND NOT EXISTS (
                SELECT 1 FROM peer_board_messages m
                WHERE (m.id = root.id OR m.thread_root_id = root.id)
                  AND m.expires_at >= datetime('now')
              )
          )
        `).run();
        if (swept.changes > 0) {
          logger.info(`Expired ${swept.changes} peer board thread(s)`);
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: peer board expiry failed', { error: err.message });
      }
    }));

    // ── R3d-4 part 2: expire stale restore-approval rows ─────────────────
    //
    // Sweeps three classes of expiry per services/restore-approvals.js:
    //   (1) strict-mode pending past expires_at (= created_at + window)
    //   (2) delayed-self-approval pending past hard expiry
    //       (= created_at + 2 * window)
    //   (3) approved past consumption deadline
    //       (= approved_at + window)
    //
    // Hourly is plenty -- defense-in-depth checks inside approve(),
    // findUsableForBackup(), and consumeApproval() enforce expiry
    // independently at the point of use, so the sweeper exists only
    // to clean up the queue UI's view of stale rows. A bug in the
    // sweeper does NOT create a security gap; the row is still
    // unusable at restore time.
    this.jobs.push(cron.schedule('0 * * * *', () => {
      try {
        const { getDb } = require('../db/init');
        const approvalsSvc = require('./restore-approvals');
        const { auditLog } = require('../middleware/audit');
        const db = getDb();
        const result = approvalsSvc.expirePending(db);
        const total =
          result.strict_pending_expired_ids.length +
          result.delayed_self_hard_expired_ids.length +
          result.approved_consumption_expired_ids.length;
        if (total > 0) {
          logger.info('Restore-approval sweeper marked rows expired', {
            strict_pending: result.strict_pending_expired_ids.length,
            delayed_self_hard: result.delayed_self_hard_expired_ids.length,
            approved_consumption: result.approved_consumption_expired_ids.length,
          });
          // One audit event per non-empty class with the IDs in detail.
          // Splitting by class lets SIEM rules alert on unusual ratios
          // (e.g. high consumption-deadline expiry could indicate a
          // workflow problem where admins approve but never consume).
          if (result.strict_pending_expired_ids.length > 0) {
            auditLog(
              null,
              'RESTORE_APPROVAL_EXPIRED_STRICT_PENDING',
              `count=${result.strict_pending_expired_ids.length} ` +
                `ids=${result.strict_pending_expired_ids.join(',')}`,
              null,
            );
          }
          if (result.delayed_self_hard_expired_ids.length > 0) {
            auditLog(
              null,
              'RESTORE_APPROVAL_EXPIRED_DELAYED_SELF_HARD',
              `count=${result.delayed_self_hard_expired_ids.length} ` +
                `ids=${result.delayed_self_hard_expired_ids.join(',')}`,
              null,
            );
          }
          if (result.approved_consumption_expired_ids.length > 0) {
            auditLog(
              null,
              'RESTORE_APPROVAL_EXPIRED_CONSUMPTION_DEADLINE',
              `count=${result.approved_consumption_expired_ids.length} ` +
                `ids=${result.approved_consumption_expired_ids.join(',')}`,
              null,
            );
          }
        }
        db.close();
      } catch (err) {
        logger.error('Scheduler: restore-approval expiry sweep failed', {
          error: err.message,
        });
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

    // ── R3i: DB-driven multi-schedule backup registration ────────────────
    //
    // Replaces the single hardcoded BACKUP_SCHEDULE env-var cron job with
    // a per-schedule registration pattern: every row in backup_schedules
    // with active=1 gets its own cron.schedule() registered. The job
    // handler loads the schedule fresh by id at fire time (defends against
    // mid-flight edits), runs performBackup, and records last_status /
    // last_run / last_error / next_run back to the row.
    //
    // Legacy env-var fallback: when no active schedules exist in the DB
    // AND process.env.BACKUP_SCHEDULE is set, a single legacy job runs
    // off the env var. Matches the C11 migration behavior — existing
    // installs that have not yet had their team_config.backup_config
    // singleton migrated continue to back up.
    //
    // Reload-on-mutation: a 60-second poll computes a checksum of the
    // active backup_schedules rows. When the checksum changes (any
    // create / update / delete), reloadBackupJobs() tears down the
    // current backup cron jobs and re-registers from the fresh DB
    // state. The poll cadence trades 60-second responsiveness against
    // simpler cross-module decoupling — the backup-schedules service
    // does not need to call into scheduler directly. Admin-grade
    // schedule mutations are infrequent enough that the lag is
    // operator-acceptable.
    this._registerBackupJobs();
    this.jobs.push(cron.schedule('* * * * *', () => {
      this._maybeReloadBackupJobs();
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
        const { processQueue } = require('./notifications-pipeline');
        const stats = await processQueue();
        if (stats.processed > 0 || stats.skipped > 0) {
          logger.info('Notifications email pipeline cycle', stats);
        }
      } catch (err) {
        logger.error('Scheduler: notifications email pipeline failed', { error: err.message });
      }    
    }));

    // ── SMS notification pipeline (N1a C10) ──────────────────────────────
    // Sibling cron to the email pipeline above. Polls notifications WHERE
    // sms_delivery_status='queued' and dispatches via the team's configured
    // SMS provider (Twilio or AWS SNS — N1a C8 module notifications-sms.js).
    // Interval is configurable via NOTIFICATIONS_SMS_INTERVAL_SEC env (default
    // 60s); shorter intervals supported but cron min granularity is 1 minute
    // when interval >= 60s, otherwise every-minute. Desktop dispatch does NOT
    // get a cron job here — desktop is purely push-based via sendDesktopToUser
    // synchronously from notifications.js enqueueDesktop() (N1a C24).
    //
    // Analyst anonymity: notifications-sms.js performs per-row defense-in-
    // depth role checking (N1a C7) and skips analyst-role rows that somehow
    // reached the SMS queue. If sms_provider is not configured in
    // notification_config, the pipeline returns immediately with skipped
    // count and logs the queue depth — no error spam.
    const smsIntervalSec = parseInt(process.env.NOTIFICATIONS_SMS_INTERVAL_SEC || '60', 10);
    const smsCronExpr = smsIntervalSec >= 60
      ? `*/${Math.floor(smsIntervalSec / 60)} * * * *`
      : '* * * * *';
    this.jobs.push(cron.schedule(smsCronExpr, async () => {
      try {
        const { processSmsQueue } = require('./notifications-sms');
        const stats = await processSmsQueue();
        if (stats.processed > 0 || stats.skipped > 0) {
          logger.info('Notifications SMS pipeline cycle', stats);
        }
      } catch (err) {
        logger.error('Scheduler: notifications SMS pipeline failed', { error: err.message });
      }
    }));

    // ── AI burnout: team intervention prompt precompute (N1b C9) ───
    // Computes server-side team health, determines which team conditions are
    // active, and generates an AI
    // intervention prompt for each active condition. Tier-1 aggregate only --
    // team health and the prompts derive from team-level data and never refer
    // to an individual analyst. Runs every AI_BURNOUT_TEAM_INTERVAL_SEC
    // (default 300s), non-overlapping and bounded. Only missing/expired prompts
    // are regenerated; on generator failure the row is DELETED so the Actions
    // tab shows the detected condition with an AI-unavailable notice rather
    // than stale guidance. Inactive conditions are simply not served by the
    // read endpoint (which recomputes active conditions live) and age out via
    // retention.
    const aitIntervalSec = parseInt(process.env.AI_BURNOUT_TEAM_INTERVAL_SEC || '300', 10);
    const aitCron = aitIntervalSec >= 60 ? `*/${Math.floor(aitIntervalSec / 60)} * * * *` : '* * * * *';
    const aitMaxPerCycle = parseInt(process.env.AI_BURNOUT_TEAM_MAX_PER_CYCLE || '5', 10);
    const aitFreshnessSec = aitIntervalSec * 2;
    let aitRunning = false;
    this.jobs.push(cron.schedule(aitCron, async () => {
      if (aitRunning) return; // internal LLM is serial -- never overlap cycles
      aitRunning = true;
      const { getDb } = require('../db/init');
      const db = getDb();
      try {
        const { computeTeamHealth } = require('./team-health');
        const teamConditions = require('./team-conditions');
        const { generateTeamPrompt } = require('./burnout-message-generator');
        const th = computeTeamHealth(db);
        const active = teamConditions.getActive(th);
        let budget = aitMaxPerCycle;
        for (const cond of active) {
          if (budget <= 0) break;
          const fresh = db.prepare(
            "SELECT 1 FROM team_intervention_prompts WHERE prompt_key=? AND expires_at > datetime('now')"
          ).get(cond.key);
          if (fresh) continue; // still fresh -- no regeneration needed
          budget -= 1;
          const res = await generateTeamPrompt(
            { key: cond.key, severity: cond.severity, label: cond.label },
            th
          );
          if (res.ok) {
            db.prepare(
              'INSERT INTO team_intervention_prompts (prompt_key, severity, label, content, model_name, kb_refs, generated_at, expires_at) ' +
              "VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now', '+' || ? || ' seconds')) " +
              'ON CONFLICT(prompt_key) DO UPDATE SET severity=excluded.severity, label=excluded.label, content=excluded.content, ' +
              'model_name=excluded.model_name, kb_refs=excluded.kb_refs, generated_at=excluded.generated_at, expires_at=excluded.expires_at'
            ).run(
              cond.key, cond.severity, cond.label,
              JSON.stringify(res.content), res.model_name,
              JSON.stringify(res.kb_refs || []), aitFreshnessSec
            );
          } else {
            db.prepare('DELETE FROM team_intervention_prompts WHERE prompt_key=?').run(cond.key);
            if (res.reason && res.reason !== 'AI_NOT_CONFIGURED' && res.reason !== 'AI_INTERNAL_UNAVAILABLE') {
              logger.warn('AI team prompt unavailable', { condition: cond.key, reason: res.reason });
            }
          }
        }
      } catch (err) {
        logger.error('Scheduler: AI team prompt precompute failed', { error: err.message });
      } finally {
        db.close();
        aitRunning = false;
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
    for (const job of this.backupJobs.values()) {
      job.stop();
    }
    this.backupJobs.clear();
    this._lastBackupSignature = null;
    this.jobs = [];
    logger.info('Scheduler stopped');
  },

  // ── U3: shared ephemeral-chat retention sweep ──────────────────────────
  //
  // Peer chat and lead chat both promise "retained five minutes after the
  // conversation closes, then permanently deleted." This deletes only the
  // transport ciphertext rows, and only for conversations closed at least five
  // minutes ago; the session/thread records persist as reusable pairing anchors
  // and any flagged content is sealed independently in the abuse evidence vault.
  //
  // Lead chat keys on lead_chat_threads.closed_at (a SQLite timestamp) and the
  // thread set stays small (one reused row per analyst/lead pairing), so a plain
  // subquery is fine. Peer sessions live as team_config JSON (peer_session_<id>)
  // with an ISO-8601 closedAt, and accumulate per conversation, so the peer side
  // is anchored on messages that still exist: it inspects only sessions with
  // surviving ciphertext, point-looks-up each session's record, and also purges
  // any orphaned rows whose session record is already gone.
  sweepEphemeralChatRetention() {
    const { getDb } = require('../db/init');
    const db = getDb();
    try {
      const leadDeleted = db.prepare(`
        DELETE FROM lead_messages
        WHERE thread_id IN (
          SELECT id FROM lead_chat_threads
          WHERE status = 'closed' AND closed_at IS NOT NULL
            AND closed_at <= datetime('now', '-5 minutes')
        )
      `).run().changes;

      const cutoff = Date.now() - 5 * 60 * 1000;
      const sessionIds = db.prepare('SELECT DISTINCT session_id FROM peer_messages').all().map(r => r.session_id);
      const getSession = db.prepare('SELECT value FROM team_config WHERE key = ?');
      const expired = [];
      for (const sid of sessionIds) {
        const row = getSession.get(`peer_session_${sid}`);
        if (!row) { expired.push(sid); continue; } // orphaned ciphertext: session record gone
        let s;
        try { s = JSON.parse(row.value); } catch { continue; }
        if (s && s.status === 'closed' && s.closedAt) {
          const t = Date.parse(s.closedAt);
          if (!Number.isNaN(t) && t <= cutoff) expired.push(sid);
        }
      }
      let peerDeleted = 0;
      if (expired.length) {
        const placeholders = expired.map(() => '?').join(',');
        peerDeleted = db.prepare(
          `DELETE FROM peer_messages WHERE session_id IN (${placeholders})`
        ).run(...expired).changes;
      }

      if (leadDeleted > 0 || peerDeleted > 0) {
        logger.info('Scheduler: ephemeral chat retention sweep', {
          leadMessagesDeleted: leadDeleted,
          peerMessagesDeleted: peerDeleted,
        });
      }
    } finally {
      db.close();
    }
  },

  // ── R3i: backup job lifecycle ──────────────────────────────────────────
  //
  // backupJobs is a Map keyed by schedule id (or the sentinel
  // '__legacy_env__' when running off process.env.BACKUP_SCHEDULE).
  // Values are node-cron Job instances. Tracking these separately
  // from this.jobs lets reloadBackupJobs() tear down only the
  // backup-related crons without touching the unrelated jobs
  // (lighter expiry, restore-approval sweeps, GD push, etc.).
  backupJobs: new Map(),
  _lastBackupSignature: null,

  _registerBackupJobs() {
    // Stop any currently-registered backup jobs.
    for (const job of this.backupJobs.values()) {
      try { job.stop(); } catch (_) { /* idempotent */ }
    }
    this.backupJobs.clear();

    const { getDb } = require('../db/init');
    let db = null;
    try {
      db = getDb();
      const schedules = db.prepare(
        'SELECT * FROM backup_schedules WHERE active = 1'
      ).all();

      if (schedules.length === 0) {
        // Legacy env-var fallback.
        const envSchedule = process.env.BACKUP_SCHEDULE;
        if (envSchedule) {
          this._registerLegacyEnvBackupJob(envSchedule);
          logger.info(`Scheduler: no DB schedules — registered legacy env-var backup job (${envSchedule})`);
        } else {
          logger.info('Scheduler: no DB schedules and no BACKUP_SCHEDULE env var — backup cron is idle');
        }
      } else {
        let registered = 0;
        let skipped = 0;
        for (const schedule of schedules) {
          if (this._registerBackupJob(schedule)) {
            registered += 1;
          } else {
            skipped += 1;
          }
        }
        logger.info(`Scheduler: registered ${registered} backup schedule(s)${skipped > 0 ? ` (skipped ${skipped} unschedulable)` : ''}`);
      }

      // Update the signature so the next poll does not see this state
      // as a change.
      this._lastBackupSignature = this._computeBackupSignature(db);
    } catch (err) {
      logger.error('Scheduler: backup jobs registration failed', { error: err.message });
    } finally {
      if (db) { try { db.close(); } catch (_) { /* idempotent */ } }
    }
  },

  _registerBackupJob(schedule) {
    const cronExpr = this._scheduleToCronExpression(schedule);
    if (!cronExpr) {
      logger.warn('Scheduler: skipping unschedulable backup', {
        scheduleId: schedule.id,
        name: schedule.name,
        frequency: schedule.frequency,
        interval: schedule.interval,
      });
      return false;
    }
    try {
      const job = cron.schedule(cronExpr, () => {
        this._runBackupJob(schedule.id);
      });
      this.backupJobs.set(schedule.id, job);
      return true;
    } catch (registerErr) {
      logger.error('Scheduler: cron.schedule registration failed', {
        scheduleId: schedule.id,
        cronExpr,
        error: registerErr.message,
      });
      return false;
    }
  },

  _registerLegacyEnvBackupJob(cronExpr) {
    try {
      const job = cron.schedule(cronExpr, () => {
        try {
          logger.info('Starting legacy env-var scheduled backup');
          const { performBackup } = require('./backup');
          performBackup('daily-auto');
        } catch (err) {
          logger.error('Scheduler: legacy backup failed', { error: err.message });
        }
      });
      this.backupJobs.set('__legacy_env__', job);
    } catch (registerErr) {
      logger.error('Scheduler: legacy env-var backup registration failed', {
        cronExpr,
        error: registerErr.message,
      });
    }
  },

  _runBackupJob(scheduleId) {
    const { getDb } = require('../db/init');
    const backupSchedules = require('./backup-schedules');
    let db = null;
    try {
      db = getDb();
      const schedule = db.prepare(
        'SELECT * FROM backup_schedules WHERE id = ?'
      ).get(scheduleId);
      if (!schedule || schedule.active === 0) {
        logger.warn('Scheduler: backup fire for missing/inactive schedule', { scheduleId });
        return;
      }

      // Compute the NEXT fire time (after this one) and write it back.
      // The current invocation IS the previous next_run; from now we
      // look forward for the subsequent one.
      const next = backupSchedules.nextFireTime({
        active: schedule.active,
        frequency: schedule.frequency,
        interval: schedule.interval,
        time: schedule.time,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
      });

      db.prepare(
        'UPDATE backup_schedules SET last_status = ?, next_run = ? WHERE id = ?'
      ).run('running', next, scheduleId);

      // ── R3l C56: dispatch by (backup_kind, backup_strategy) tuple ──
      //
      // Pre-R3l, this layer unconditionally called performBackup (DB-only)
      // regardless of the operator's intent. backup_full_suite.js
      // existed and was complete but never invoked from the scheduler —
      // every scheduled run silently produced a DB-only backup even
      // though FEATURE-GUIDE line 605 documents full-suite as the
      // operator-intended default.
      //
      // C53/C54/C55 added schema columns making intent explicit:
      // backup_schedules.backup_kind and backup_schedules.backup_strategy.
      // C56 here makes the dispatch honor that intent.
      //
      // Dispatch table (kind, strategy) -> target function:
      //   (full-suite, full)        -> performFullSuiteBackup
      //   (single-db,  full)        -> performBackup
      //   (any,        incremental) -> performIncrementalBackup     (C63)
      //   (any,        differential)-> performDifferentialBackup    (C64)
      //   (full-suite, snapshot)    -> performFullSuiteBackup with type='snapshot'
      //   (single-db,  snapshot)    -> performBackup with type='snapshot'
      //
      // The legacy schedule.type column ('daily-auto'/'on-demand'/'snapshot')
      // is still passed as the underlying TYPE parameter to whichever
      // function is dispatched. kind+strategy are the dispatch axes;
      // type is the parameter the dispatched function takes.
      //
      // tryLoad guard for incremental/differential: those modules
      // don't ship until C63/C64. A schedule with strategy='incremental'
      // on a pre-C63 deploy will fail loud with a clear error pointing
      // to the missing module rather than silently falling back.
      //
      // Defensive null-coercion on kind/strategy: post-C53/C55 the
      // schema enforces NOT NULL DEFAULT 'full-suite'/'full' on these
      // columns so NULL shouldn't be reachable, but coercion is cheap
      // and survives any schema-skew edge case during in-place upgrades.
      const kind = schedule.backup_kind || 'full-suite';
      const strategy = schedule.backup_strategy || 'full';
      const legacyType = schedule.type === 'snapshot' ? 'snapshot' : 'daily-auto';
      const backupType = strategy === 'snapshot' ? 'snapshot' : legacyType;
      const startedAt = new Date().toISOString();

      const tryLoad = (moduleId) => {
        try {
          return require(moduleId);
        } catch (loadErr) {
          if (loadErr && loadErr.code === 'MODULE_NOT_FOUND') return null;
          throw loadErr;
        }
      };

      let backupPromise;
      let dispatchTarget;

      if (strategy === 'incremental') {
        const incModule = tryLoad('./backup-incremental');
        if (!incModule || typeof incModule.performIncrementalBackup !== 'function') {
          throw new Error(
            `Scheduler: schedule '${schedule.name}' requests strategy='incremental' ` +
            `but backup-incremental.js is not available on this deploy (added in R3l C63)`
          );
        }
        dispatchTarget = 'performIncrementalBackup';
        backupPromise = Promise.resolve(
          incModule.performIncrementalBackup({ type: backupType, scheduleId, backupKind: kind })
        );
      } else if (strategy === 'differential') {
        const diffModule = tryLoad('./backup-differential');
        if (!diffModule || typeof diffModule.performDifferentialBackup !== 'function') {
          throw new Error(
            `Scheduler: schedule '${schedule.name}' requests strategy='differential' ` +
            `but backup-differential.js is not available on this deploy (added in R3l C64)`
          );
        }
        dispatchTarget = 'performDifferentialBackup';
        backupPromise = Promise.resolve(
          diffModule.performDifferentialBackup({ type: backupType, scheduleId, backupKind: kind })
        );
      } else if (kind === 'full-suite') {
        // strategy='full' or 'snapshot' both go through the full-suite
        // path; the type parameter chooses the flavor inside that function.
        const { performFullSuiteBackup } = require('./backup-full-suite');
        dispatchTarget = 'performFullSuiteBackup';
        backupPromise = Promise.resolve(performFullSuiteBackup({ type: backupType }));
      } else {
        // kind='single-db'; strategy='full' or 'snapshot'
        const { performBackup } = require('./backup');
        dispatchTarget = 'performBackup';
        backupPromise = Promise.resolve(performBackup(backupType, { scheduleId }));
      }

      logger.info('Scheduler: starting scheduled backup', {
        scheduleId,
        name: schedule.name,
        kind,
        strategy,
        type: backupType,
        dispatchTarget,
      });

      backupPromise.then(() => {
        try {
          const successDb = getDb();
          successDb.prepare(
            'UPDATE backup_schedules SET last_status = ?, last_run = ?, last_error = NULL WHERE id = ?'
          ).run('success', startedAt, scheduleId);
          successDb.close();
          logger.info('Scheduler: scheduled backup complete', {
            scheduleId,
            name: schedule.name,
          });
        } catch (recordSuccessErr) {
          logger.error('Scheduler: failed to record backup success', {
            scheduleId,
            error: recordSuccessErr.message,
          });
        }
      }).catch((jobErr) => {
        try {
          const failDb = getDb();
          failDb.prepare(
            'UPDATE backup_schedules SET last_status = ?, last_error = ? WHERE id = ?'
          ).run('failed', String(jobErr.message || jobErr), scheduleId);
          failDb.close();
        } catch (recordFailErr) {
          logger.error('Scheduler: failed to record backup failure', {
            scheduleId,
            error: recordFailErr.message,
          });
        }
        logger.error('Scheduler: scheduled backup failed', {
          scheduleId,
          name: schedule.name,
          error: jobErr.message,
        });
      });
    } catch (err) {
      logger.error('Scheduler: backup job runner threw', {
        scheduleId,
        error: err.message,
      });
    } finally {
      if (db) { try { db.close(); } catch (_) { /* idempotent */ } }
    }
  },

  // Cron expression builder. node-cron format: m h dom mon dow.
  // Limitation: monthly schedules where day_of_month exceeds the
  // current month's last day (e.g. 31 in February) will simply not
  // fire that month under raw cron rules. The nextFireTime helper
  // in backup-schedules clamps to the last day for UI prediction
  // purposes, but the cron registration itself uses raw rules.
  // A future cleanup phase can implement the clamp at fire time
  // by registering a daily cron + checking the date inside the
  // handler.
  _scheduleToCronExpression(schedule) {
    if (!schedule) return null;
    const frequency = schedule.frequency
      || this._legacyIntervalToFrequency(schedule.interval);
    if (!frequency) return null;

    const time = schedule.time || '02:00';
    const timeMatch = /^(\d{1,2}):(\d{2})$/.exec(time);
    if (!timeMatch && frequency !== 'hourly') return null;
    const h = timeMatch ? parseInt(timeMatch[1], 10) : 0;
    const m = timeMatch ? parseInt(timeMatch[2], 10) : 0;
    if (frequency !== 'hourly' && (h < 0 || h > 23 || m < 0 || m > 59)) return null;

    if (frequency === 'hourly') return '0 * * * *';
    if (frequency === 'daily') return `${m} ${h} * * *`;
    if (frequency === 'weekly') {
      const dow = schedule.day_of_week;
      if (typeof dow !== 'number' || dow < 0 || dow > 6) return null;
      return `${m} ${h} * * ${dow}`;
    }
    if (frequency === 'monthly') {
      const dom = schedule.day_of_month;
      if (typeof dom !== 'number' || dom < 1 || dom > 31) return null;
      return `${m} ${h} ${dom} * *`;
    }
    return null;
  },

  _legacyIntervalToFrequency(interval) {
    if (!interval || typeof interval !== 'string') return null;
    const lower = interval.toLowerCase();
    if (lower.includes('hour')) return 'hourly';
    if (lower.includes('week')) return 'weekly';
    if (lower.includes('month')) return 'monthly';
    if (lower.includes('day') || lower === 'daily') return 'daily';
    return null;
  },

  _computeBackupSignature(db) {
    // Concatenate the scheduling-relevant fields of every active
    // schedule. Any change to frequency / time / day / activeness
    // shifts the signature and triggers a reload on next poll.
    const rows = db.prepare(`
      SELECT id, COALESCE(frequency, interval, '') AS f,
             COALESCE(time, '') AS t,
             COALESCE(day_of_week, -1) AS dow,
             COALESCE(day_of_month, -1) AS dom,
             active
      FROM backup_schedules
      ORDER BY id
    `).all();
    return rows.map(r =>
      `${r.id}:${r.f}:${r.t}:${r.dow}:${r.dom}:${r.active}`
    ).join('|');
  },

  _maybeReloadBackupJobs() {
    const { getDb } = require('../db/init');
    let db = null;
    try {
      db = getDb();
      const sig = this._computeBackupSignature(db);
      if (sig !== this._lastBackupSignature) {
        logger.info('Scheduler: backup schedule signature changed; reloading jobs');
        // _registerBackupJobs opens its own DB connection; close ours
        // first so we don't hold two simultaneously.
        try { db.close(); } catch (_) { /* idempotent */ }
        db = null;
        this._registerBackupJobs();
      } else if (db) {
        try { db.close(); } catch (_) { /* idempotent */ }
        db = null;
      }
    } catch (err) {
      logger.error('Scheduler: poll-and-reload failed', { error: err.message });
      if (db) { try { db.close(); } catch (_) { /* idempotent */ } }
    }
  },

  // Public hook: callers (the backup-schedules service or admin
  // route handlers) can trigger an immediate reload after a known
  // mutation. The 60-second poll guarantees eventual consistency
  // even without this hook, but explicit callers avoid the lag.
  reloadBackupJobs() {
    logger.info('Scheduler: reloadBackupJobs called');
    this._registerBackupJobs();
  },
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
