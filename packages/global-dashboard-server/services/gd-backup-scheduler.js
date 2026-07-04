// packages/global-dashboard-server/services/gd-backup-scheduler.js
//
// GD backup scheduler -- a twin of the Regional Server scheduler's backup-job
// section, replacing the GD's former inline setInterval scheduler. Every active
// backup_schedules row with a schedulable cadence gets its own node-cron job;
// the handler loads the schedule fresh at fire time, gates interval schedules on
// next_run, dispatches by (backup_kind, backup_strategy) to the GD backup
// writers with the correct 'scheduled' trigger, and records last_status /
// last_run / last_error / next_run back to the row. A per-minute poll reloads
// the jobs when the active-schedule signature changes (create / update / delete)
// and drives the per-minute ticks that interval schedules ride on.
//
// HA note: the Regional scheduler fronts every fire with mayRunWriteJob() (the
// sole-writer lease). The GD runs single-instance today, so mayRunWriteJob()
// here is an always-allow placeholder. The sole-writer lease is a later GD
// phase -- this is a deliberate no-op, not a weakened guard.

const cron = require('node-cron');
const { getDb } = require('../db-init');
const gdBackupSchedules = require('./gd-backup-schedules');

const gdBackupScheduler = {
  backupJobs: new Map(),
  reloadJob: null,
  _lastBackupSignature: '',

  start() {
    this._registerBackupJobs();
    this.reloadJob = cron.schedule('* * * * *', () => {
      if (!this.mayRunWriteJob()) return;
      this._maybeReloadBackupJobs();
    });
  },

  stop() {
    for (const job of this.backupJobs.values()) {
      try { job.stop(); } catch (_e) { /* idempotent */ }
    }
    this.backupJobs.clear();
    if (this.reloadJob) {
      try { this.reloadJob.stop(); } catch (_e) { /* idempotent */ }
      this.reloadJob = null;
    }
  },

  // Always-allow placeholder; see the HA note at the top of this file.
  mayRunWriteJob() {
    return true;
  },

  _registerBackupJobs() {
    for (const job of this.backupJobs.values()) {
      try { job.stop(); } catch (_e) { /* idempotent */ }
    }
    this.backupJobs.clear();

    let db = null;
    try {
      db = getDb();
      const schedules = db.prepare(
        'SELECT * FROM backup_schedules WHERE active = 1'
      ).all();

      if (schedules.length === 0) {
        const envSchedule = process.env.GD_BACKUP_SCHEDULE;
        if (envSchedule) {
          this._registerLegacyEnvBackupJob(envSchedule);
          console.log('GD scheduler: no DB schedules -- registered legacy env-var backup job (' + envSchedule + ')');
        } else {
          console.log('GD scheduler: no DB schedules and no GD_BACKUP_SCHEDULE env var -- backup cron is idle');
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
        console.log('GD scheduler: registered ' + registered + ' backup schedule(s)' + (skipped > 0 ? ' (skipped ' + skipped + ' unschedulable)' : ''));
      }

      this._lastBackupSignature = this._computeBackupSignature(db);
    } catch (err) {
      console.error('GD scheduler: backup jobs registration failed:', err.message);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },

  _registerBackupJob(schedule) {
    const cronExpr = this._scheduleToCronExpression(schedule);
    if (!cronExpr) {
      console.warn('GD scheduler: skipping unschedulable backup (scheduleId ' + schedule.id + ', name ' + schedule.name + ')');
      return false;
    }
    try {
      const job = cron.schedule(cronExpr, () => {
        if (!this.mayRunWriteJob()) return;
        this._runBackupJob(schedule.id);
      });
      this.backupJobs.set(schedule.id, job);
      return true;
    } catch (registerErr) {
      console.error('GD scheduler: cron.schedule registration failed (scheduleId ' + schedule.id + ', cronExpr ' + cronExpr + '):', registerErr.message);
      return false;
    }
  },

  _registerLegacyEnvBackupJob(cronExpr) {
    try {
      const job = cron.schedule(cronExpr, () => {
        if (!this.mayRunWriteJob()) return;
        let db = null;
        try {
          console.log('GD scheduler: starting legacy env-var scheduled backup');
          db = getDb();
          const { performV2Backup } = require('./gd-backup-v2');
          Promise.resolve(performV2Backup(db, { triggerType: 'scheduled' }))
            .catch((err) => console.error('GD scheduler: legacy backup failed:', err.message))
            .finally(() => { if (db) { try { db.close(); } catch (_e) { /* idempotent */ } } });
        } catch (err) {
          console.error('GD scheduler: legacy backup failed:', err.message);
          if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
        }
      });
      this.backupJobs.set('__legacy_env__', job);
    } catch (registerErr) {
      console.error('GD scheduler: legacy env-var backup registration failed (cronExpr ' + cronExpr + '):', registerErr.message);
    }
  },

  async _runBackupJob(scheduleId) {
    let db = null;
    try {
      db = getDb();
      const schedule = db.prepare(
        'SELECT * FROM backup_schedules WHERE id = ?'
      ).get(scheduleId);
      if (!schedule || schedule.active === 0) {
        console.warn('GD scheduler: backup fire for missing/inactive schedule (scheduleId ' + scheduleId + ')');
        return;
      }

      // Interval schedules ride a per-minute cron; gate each tick on next_run so
      // they fire only once the interval has elapsed. A null next_run (interval
      // never computed -- e.g. malformed interval_minutes) is treated as not-due
      // so a bad row can never cause a per-minute backup storm. Non-interval
      // schedules fire on a precise cron and always proceed.
      const fireFrequency = schedule.frequency
        || this._legacyIntervalToFrequency(schedule.interval);
      if (fireFrequency === 'interval') {
        if (!schedule.next_run || new Date() < new Date(schedule.next_run)) {
          return;
        }
      }

      // Compute the NEXT fire time (after this one) and write it back.
      const next = gdBackupSchedules.nextFireTime({
        active: schedule.active,
        frequency: schedule.frequency,
        interval: schedule.interval,
        interval_minutes: schedule.interval_minutes,
        created_at: schedule.created_at,
        time: schedule.time,
        day_of_week: schedule.day_of_week,
        day_of_month: schedule.day_of_month,
      });
      db.prepare(
        'UPDATE backup_schedules SET last_status = ?, next_run = ? WHERE id = ?'
      ).run('running', next, scheduleId);

      // Dispatch by (backup_kind, backup_strategy). The GD writers take
      // (db, options) and read options.triggerType for the recorded trigger.
      //   (any,        incremental) -> gd-backup-incremental.performIncrementalBackup
      //   (any,        differential)-> gd-backup-differential.performDifferentialBackup
      //   (any,        snapshot)    -> gd-backup-v2.performSnapshotBackup
      //   (full-suite, full)        -> gd-backup-full-suite.performFullSuiteBackup
      //   (single-db,  full)        -> gd-backup-v2.performV2Backup
      // type carries the trigger ('scheduled' unless the schedule itself is a
      // snapshot type); kind+strategy are the dispatch axes.
      const kind = schedule.backup_kind || 'full-suite';
      const strategy = schedule.backup_strategy || 'full';
      const legacyType = schedule.type === 'snapshot' ? 'snapshot' : 'scheduled';
      const backupType = strategy === 'snapshot' ? 'snapshot' : legacyType;
      const startedAt = new Date().toISOString();
      const opts = {
        triggerType: backupType,
        scheduleId,
        backupKind: kind,
        maxChainDepth: schedule.max_chain_depth != null ? schedule.max_chain_depth : undefined,
      };

      try {
        let dispatchTarget;
        if (strategy === 'incremental') {
          dispatchTarget = 'performIncrementalBackup';
          const r = await require('./gd-backup-incremental').performIncrementalBackup(db, opts);
          if (r && r.ok === false) throw new Error(r.error || 'incremental backup failed');
        } else if (strategy === 'differential') {
          dispatchTarget = 'performDifferentialBackup';
          const r = await require('./gd-backup-differential').performDifferentialBackup(db, opts);
          if (r && r.ok === false) throw new Error(r.error || 'differential backup failed');
        } else if (backupType === 'snapshot') {
          dispatchTarget = 'performSnapshotBackup';
          await Promise.resolve(require('./gd-backup-v2').performSnapshotBackup(db, opts));
        } else if (kind === 'full-suite') {
          dispatchTarget = 'performFullSuiteBackup';
          await Promise.resolve(require('./gd-backup-full-suite').performFullSuiteBackup(db, opts));
        } else {
          dispatchTarget = 'performV2Backup';
          await Promise.resolve(require('./gd-backup-v2').performV2Backup(db, opts));
        }
        db.prepare(
          'UPDATE backup_schedules SET last_status = ?, last_run = ?, last_error = NULL WHERE id = ?'
        ).run('success', startedAt, scheduleId);
        console.log('GD scheduler: scheduled backup complete (scheduleId ' + scheduleId + ', name ' + schedule.name + ', ' + dispatchTarget + ')');
      } catch (jobErr) {
        db.prepare(
          'UPDATE backup_schedules SET last_status = ?, last_error = ? WHERE id = ?'
        ).run('failed', String(jobErr.message || jobErr).slice(0, 500), scheduleId);
        console.error('GD scheduler: scheduled backup failed (scheduleId ' + scheduleId + '):', jobErr.message);
      }
    } catch (err) {
      console.error('GD scheduler: backup job runner threw (scheduleId ' + scheduleId + '):', err.message);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },

  _scheduleToCronExpression(schedule) {
    if (!schedule) return null;
    const frequency = schedule.frequency
      || this._legacyIntervalToFrequency(schedule.interval);
    if (!frequency) return null;

    // Interval schedules fire on a per-minute cron; _runBackupJob gates each
    // tick on next_run. An arbitrary cadence cannot be a single cron expression;
    // interval_minutes bounds are enforced by gd-backup-schedules at create/
    // update, with a defensive positive-integer check here.
    if (frequency === 'interval') {
      const im = schedule.interval_minutes;
      if (typeof im !== 'number' || !Number.isInteger(im) || im <= 0) return null;
      return '* * * * *';
    }

    const time = schedule.time || '02:00';
    const timeMatch = /^(\d{1,2}):(\d{2})$/.exec(time);
    if (!timeMatch && frequency !== 'hourly') return null;
    const h = timeMatch ? parseInt(timeMatch[1], 10) : 0;
    const m = timeMatch ? parseInt(timeMatch[2], 10) : 0;
    if (frequency !== 'hourly' && (h < 0 || h > 23 || m < 0 || m > 59)) return null;

    if (frequency === 'hourly') return '0 * * * *';
    if (frequency === 'daily') return m + ' ' + h + ' * * *';
    if (frequency === 'weekly') {
      const dow = schedule.day_of_week;
      if (typeof dow !== 'number' || dow < 0 || dow > 6) return null;
      return m + ' ' + h + ' * * ' + dow;
    }
    if (frequency === 'monthly') {
      const dom = schedule.day_of_month;
      if (typeof dom !== 'number' || dom < 1 || dom > 31) return null;
      return m + ' ' + h + ' ' + dom + ' * *';
    }
    return null;
  },

  _legacyIntervalToFrequency(interval) {
    if (!interval || typeof interval !== 'string') return null;
    const lower = interval.toLowerCase();
    if (lower === 'interval') return 'interval';
    if (lower.includes('hour')) return 'hourly';
    if (lower.includes('week')) return 'weekly';
    if (lower.includes('month')) return 'monthly';
    if (lower.includes('day') || lower === 'daily') return 'daily';
    return null;
  },

  _computeBackupSignature(db) {
    // Concatenate the scheduling-relevant fields of every active schedule. Any
    // change to frequency / time / day / interval_minutes / activeness shifts
    // the signature and triggers a reload on the next poll.
    const rows = db.prepare(
      'SELECT id, COALESCE(frequency, interval, \'\') AS f, '
      + 'COALESCE(time, \'\') AS t, '
      + 'COALESCE(day_of_week, -1) AS dow, '
      + 'COALESCE(day_of_month, -1) AS dom, '
      + 'COALESCE(interval_minutes, -1) AS im, '
      + 'active FROM backup_schedules ORDER BY id'
    ).all();
    return rows.map((r) =>
      r.id + ':' + r.f + ':' + r.t + ':' + r.dow + ':' + r.dom + ':' + r.im + ':' + r.active
    ).join('|');
  },

  _maybeReloadBackupJobs() {
    let db = null;
    try {
      db = getDb();
      const sig = this._computeBackupSignature(db);
      if (sig !== this._lastBackupSignature) {
        console.log('GD scheduler: backup schedule signature changed; reloading jobs');
        // _registerBackupJobs opens its own connection; close ours first.
        try { db.close(); } catch (_e) { /* idempotent */ }
        db = null;
        this._registerBackupJobs();
      } else if (db) {
        try { db.close(); } catch (_e) { /* idempotent */ }
        db = null;
      }
    } catch (err) {
      console.error('GD scheduler: poll-and-reload failed:', err.message);
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },
};

module.exports = { gdBackupScheduler };
