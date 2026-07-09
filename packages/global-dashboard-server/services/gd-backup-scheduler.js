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
// This is the GD's general scheduler: the backup jobs above plus the B6d HA
// cadence. mayRunWriteJob() is now the real sole-writer gate (gd-ha-lease via
// haWriteAuthority) -- it fails OPEN for a standalone (unpaired) node so single-
// instance deployments are unaffected, and suppresses autonomous write work only
// on a positively-confirmed paired passive (or an active that has lost its lease).
// The HA ticks (heartbeat, replication shipping, lag) run on setInterval at
// config-driven periods in haTimers, re-registerable via reloadHaJobs() on a live
// /ha/config change. The failure-detection tick and the heartbeat's self-fence /
// role-reconcile reactions land with gd-ha-failover (PR-3).

const cron = require('node-cron');
const { getDb } = require('../db-init');
const gdBackupSchedules = require('./gd-backup-schedules');

const gdBackupScheduler = {
  backupJobs: new Map(),
  jobs: [],
  reloadJob: null,
  _lastBackupSignature: '',
  haTimers: [],
  _haHeartbeatBusy: false,
  _haShipBusy: false,

  start() {
    this._registerBackupJobs();
    this._registerHaJobs();
    this._registerMaintenanceJobs();
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
    try { this.haTimers.forEach((t) => clearInterval(t)); } catch (_e) { /* idempotent */ }
    this.haTimers = [];
    for (const job of this.jobs) {
      try { job.stop(); } catch (_e) { /* idempotent */ }
    }
    this.jobs = [];
  },

  // Returns null (a no-op signal) unless HA is enabled in config AND a peer is
  // paired; otherwise returns { cfg, role }. Any error (HA tables absent on a
  // fresh DB) is treated as "not configured" so the HA jobs stay silent.
  haReplicationContext(db) {
    try {
      const row = db.prepare("SELECT value FROM config WHERE key = 'ha_config'").get();
      if (!row) return null;
      let cfg;
      try { cfg = JSON.parse(row.value) || {}; } catch (parseErr) { return null; }
      if (!cfg.enabled) return null;
      const peer = db.prepare("SELECT status FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
      if (!peer) return null;
      const node = db.prepare("SELECT role FROM gd_ha_node WHERE id = 'self'").get() || { role: 'standalone' };
      return { cfg: cfg, role: node.role };
    } catch (ctxErr) {
      return null;
    }
  },

  // Single source of truth for "may this node write?", shared with the data layer
  // (gd-ha-lease.assertWriteAuthority/iAmActive). Suppress autonomous scheduler
  // work ONLY when positively confirmed a paired passive; fail OPEN on every other
  // case (standalone, HA tables absent, probe error) so single-instance
  // deployments are never affected. A paired active is allowed only while it still
  // holds a valid current-epoch lease.
  haWriteAuthority(db) {
    const ctx = this.haReplicationContext(db);
    if (!ctx) return true;
    if (ctx.role === 'passive') return false;
    if (ctx.role === 'active') {
      try { return require('./gd-ha-lease').iAmActive(db); } catch (leaseErr) { return true; }
    }
    return true;
  },

  // Self-contained write-authority probe for the cron callbacks: opens a short-
  // lived connection, asks haWriteAuthority, closes it. A passive (or an active
  // that has lost its lease) returns false and the calling job skips. Fails OPEN
  // on any error: a probe failure must never freeze a single-instance node's jobs.
  mayRunWriteJob() {
    try {
      const db = getDb();
      try {
        return this.haWriteAuthority(db);
      } finally {
        db.close();
      }
    } catch (probeErr) {
      return true;
    }
  },

  // -- B6d: maintenance jobs (non-backup, non-HA periodic work) ---------------
  //
  // Integration-health probes the configured KMS / storage / MC-trust integrations
  // and caches the result. It ran on a bare setInterval in index.js; it now lives
  // here, fronted by mayRunWriteJob() like every other periodic write job. This is
  // required for HA correctness: cacheResults writes the `config` table, which IS
  // replicated, so a confirmed paired passive running the probe would overwrite a
  // replicated row the active owns -- diverging the pair, and on promotion making
  // the standby's locally-cached value canonical. A passive instead receives the
  // active's cached results by replication. mayRunWriteJob() fails OPEN, so a
  // standalone GD probes exactly as before. Skipping the job on a passive also
  // avoids doubling the outbound probe load on the external integrations.
  _registerMaintenanceJobs() {
    try {
      // Cadences are env-overridable and staggered off the top of the hour,
      // mirroring the MC scheduler (its push-retry runs at :15, archive-seal at
      // :35) so the sweeps never pile up on each other.
      const retrySchedule = process.env.GD_STORAGE_RETRY_SCHEDULE || '15 * * * *';
      const sealSchedule = process.env.GD_ARCHIVAL_SEAL_SCHEDULE || '35 * * * *';
      const retentionSchedule = process.env.GD_BACKUP_RETENTION_SCHEDULE || '30 3 * * *';

      this.jobs.push(cron.schedule('*/15 * * * *', () => {
        if (!this.mayRunWriteJob()) return;
        this._runIntegrationHealth();
      }));
      this.jobs.push(cron.schedule(retrySchedule, () => {
        if (!this.mayRunWriteJob()) return;
        this._runStorageRetrySweep();
      }));
      this.jobs.push(cron.schedule(sealSchedule, () => {
        if (!this.mayRunWriteJob()) return;
        this._runArchivalSeal();
      }));
      this.jobs.push(cron.schedule(retentionSchedule, () => {
        if (!this.mayRunWriteJob()) return;
        this._runBackupRetention();
      }));
      console.log('GD scheduler: maintenance jobs registered (integration-health every 15m, storage-retry '
        + retrySchedule + ', archival-seal ' + sealSchedule + ', backup-retention ' + retentionSchedule + ')');
    } catch (registerErr) {
      console.error('GD scheduler: maintenance job registration failed:', registerErr.message);
    }
  },

  // Retry-sweep: re-attempt due pushes across every push table. Writes the
  // replicated *_pushes / segment tables AND performs outbound cloud uploads, so a
  // passive must never run it -- two nodes sweeping would double-upload the same
  // segments and race the push-state rows.
  _runStorageRetrySweep() {
    let db = null;
    try { db = getDb(); } catch (e) { console.error('GD scheduler: storage retry-sweep getDb failed:', e.message); return; }
    const backupV2 = require('./gd-backup-v2');
    const archiveSegment = require('./gd-archive-segment');
    const storagePush = require('./gd-storage-push');
    const { rebuildForensicExportContext } = require('./forensic-export');
    Promise.resolve()
      .then(() => backupV2.retryDueV2BackupPushes(db))
      .then(() => archiveSegment.retryPendingSegmentPushes(db))
      .then(() => storagePush.retryDuePushes(db, { pushTable: 'forensic_export_pushes', rebuildContext: rebuildForensicExportContext }))
      .catch((e) => console.error('GD scheduler: storage retry-sweep error:', e && e.message ? e.message : e))
      .finally(() => { try { db.close(); } catch (_e) { /* idempotent */ } });
  },

  // Archival-seal: archive new audit rows and flush the CEF spool into sealed,
  // pushed segments. The passive's own audit_log rows are node-local and persist;
  // sealing resumes when it promotes, so nothing is lost by skipping this.
  _runArchivalSeal() {
    let db = null;
    try { db = getDb(); } catch (e) { console.error('GD scheduler: archival-seal getDb failed:', e.message); return; }
    const auditArchive = require('./gd-audit-archive');
    const cefSpool = require('./gd-cef-archive-spool');
    Promise.resolve()
      .then(() => auditArchive.archiveNewAuditEntries(db))
      .then(() => cefSpool.flush(db))
      .catch((e) => console.error('GD scheduler: archival-seal error:', e && e.message ? e.message : e))
      .finally(() => { try { db.close(); } catch (_e) { /* idempotent */ } });
  },

  // Retention: delete backup artifacts older than the retention window (mtime).
  // Synchronous. The sharpest reason this set is gated -- a passive running it
  // would delete artifacts the active still owns and diverge the backups table.
  _runBackupRetention() {
    let db = null;
    try {
      db = getDb();
      require('./gd-backup-v2').cleanOldBackups(db);
    } catch (e) {
      console.error('GD scheduler: backup retention error:', e && e.message ? e.message : e);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },

  _runIntegrationHealth() {
    let db = null;
    try {
      db = getDb();
      const gdIntegrationHealth = require('./gd-integration-health');
      Promise.resolve(gdIntegrationHealth.runAndCache(db))
        .catch((err) => console.error('GD scheduler: integration-health probe failed:', err && err.message ? err.message : err))
        .finally(() => { if (db) { try { db.close(); } catch (_e) { /* idempotent */ } } });
    } catch (err) {
      console.error('GD scheduler: integration-health job threw:', err && err.message ? err.message : err);
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
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

  // ── B6d HA cadence (heartbeat / replication ship / lag) ──────────────────
  // setInterval ticks at config-driven periods, tracked in haTimers so
  // reloadHaJobs() can re-register on a live /ha/config change. Each tick self-
  // gates by role via haReplicationContext and no-ops unless HA is enabled AND
  // paired. The passive failure-detection tick and the heartbeat's failover
  // reactions (adopt-higher-epoch role reconcile, isolation self-fence) land with
  // gd-ha-failover in PR-3.

  _haIntervals() {
    let cfg = {};
    let db = null;
    try {
      db = getDb();
      const row = db.prepare("SELECT value FROM config WHERE key = 'ha_config'").get();
      if (row) { try { cfg = JSON.parse(row.value) || {}; } catch (parseErr) { cfg = {}; } }
    } catch (readErr) {
      cfg = {};
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
    const clamp = (v, dflt) => {
      const n = Number(v);
      if (!Number.isFinite(n) || n < 1) return dflt;
      return Math.min(Math.floor(n), 3600);
    };
    return { heartbeatSec: clamp(cfg.heartbeatIntervalSec, 5), syncSec: clamp(cfg.syncIntervalSec, 5), lagSec: 15 };
  },

  _registerHaJobs() {
    const iv = this._haIntervals();
    this.haTimers.push(setInterval(() => { this._haHeartbeatTick(); }, iv.heartbeatSec * 1000));
    this.haTimers.push(setInterval(() => { this._haDetectTick(); }, iv.heartbeatSec * 1000));
    this.haTimers.push(setInterval(() => { this._haShipTick(); }, iv.syncSec * 1000));
    this.haTimers.push(setInterval(() => { this._haLagTick(); }, iv.lagSec * 1000));
    console.log('GD scheduler: HA jobs registered (heartbeat/detect ' + iv.heartbeatSec + 's, ship ' + iv.syncSec + 's, lag ' + iv.lagSec + 's)');
  },

  // Re-register the HA ticks with the current config intervals. Called from PUT
  // /ha/config so an interval change takes effect live, no restart.
  reloadHaJobs() {
    try { this.haTimers.forEach((t) => clearInterval(t)); } catch (clearErr) { /* ignore */ }
    this.haTimers = [];
    this._registerHaJobs();
  },

  // Active only: renew this node's lease (keeping the write-authority window
  // fresh), then deliver the heartbeat to the passive over the peer link,
  // recording peer contact on success. (PR-3 adds here: adopt a higher epoch from
  // the reply + reconcile role, and run the isolation self-fence.)
  async _haHeartbeatTick() {
    if (this._haHeartbeatBusy) return;
    this._haHeartbeatBusy = true;
    let db = null;
    try {
      db = getDb();
      const ctx = this.haReplicationContext(db);
      if (ctx && ctx.role === 'active') {
        const haLease = require('./gd-ha-lease');
        const haPeerLink = require('./gd-ha-peer-link');
        const haLiveness = require('./gd-ha-liveness');
        const ttl = (ctx.cfg.leaseTtlSec && ctx.cfg.leaseTtlSec > 0) ? ctx.cfg.leaseTtlSec : 30;
        haLease.renewLease(db, ttl);
        const localEpoch = haLease.currentEpoch(db);
        const lease = haLease.getLease(db) || {};
        try {
          const reply = await haPeerLink.sendToPeer(db, '/api/ha/peer/heartbeat', { epoch: localEpoch, leaseExpiresAt: lease.lease_expires_at || null }, {});
          haLiveness.recordPeerContact();
          // If the peer reports a higher epoch it has promoted -- this node is a
          // superseded active and must step down (the stale-epoch fence).
          const peerEpoch = reply && reply.epoch;
          if (peerEpoch && localEpoch && peerEpoch > localEpoch) {
            haLease.recordPeerHeartbeat(db, peerEpoch, null);
            require('./gd-ha-failover').reconcileRole(db);
          }
        } catch (sendErr) {
          // Passive unreachable this tick; not fatal (it runs its own detector).
        }
        // Isolation self-fence, gated by a grace window since this node took the
        // lease so a freshly promoted active is not demoted on stale liveness
        // before traffic/peer contact resumes. Age is computed in SQL (UTC-safe)
        // from term_started_at; checkSelfFence then demotes only when BOTH the
        // client and peer signals are present and stale.
        try {
          const graceSec = (ctx.cfg.selfFenceTimeoutSec && ctx.cfg.selfFenceTimeoutSec > 0) ? ctx.cfg.selfFenceTimeoutSec : 60;
          const ageRow = db.prepare("SELECT CAST((julianday('now') - julianday(term_started_at)) * 86400 AS REAL) AS age FROM gd_ha_lease WHERE id = 'current'").get();
          const ageSec = (ageRow && Number.isFinite(ageRow.age)) ? ageRow.age : null;
          if (ageSec !== null && ageSec > graceSec) {
            require('./gd-ha-failover').checkSelfFence(db, haLiveness.snapshot());
          }
        } catch (fenceErr) {
          // Self-fence is a safety net; never let it disrupt the heartbeat.
        }
      }
    } catch (err) {
      console.error('GD scheduler: HA heartbeat failed:', err && err.message ? err.message : err);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
      this._haHeartbeatBusy = false;
    }
  },

  // Passive only: when the active's delivered heartbeat has gone stale past the
  // configured miss-count, evaluatePromotion claims the next epoch, installs the
  // sealed promotion material, and flips this node to active.
  _haDetectTick() {
    let db = null;
    try {
      db = getDb();
      const ctx = this.haReplicationContext(db);
      if (ctx && ctx.role === 'passive') {
        require('./gd-ha-failover').evaluatePromotion(db, {});
      }
    } catch (err) {
      console.error('GD scheduler: HA failure detection failed:', err && err.message ? err.message : err);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },

  // Active only: ship pending journal rows to the paired passive; a no-op when
  // nothing is pending.
  async _haShipTick() {
    if (this._haShipBusy) return;
    this._haShipBusy = true;
    let db = null;
    try {
      db = getDb();
      const ctx = this.haReplicationContext(db);
      if (ctx && ctx.role === 'active') {
        const haReplication = require('./gd-ha-replication');
        const haPeerLink = require('./gd-ha-peer-link');
        await haReplication.shipOnce(db, haPeerLink.peerSender(db, '/api/ha/peer/replicate'));
      }
    } catch (err) {
      console.error('GD scheduler: HA replication shipping failed:', err && err.message ? err.message : err);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
      this._haShipBusy = false;
    }
  },

  // Refreshes gd_ha_replication_state.lag_seconds so GET /ha/status reports real
  // lag. No-op unless HA is enabled AND paired.
  _haLagTick() {
    let db = null;
    try {
      db = getDb();
      const ctx = this.haReplicationContext(db);
      if (ctx) {
        require('./gd-ha-replication').computeLag(db);
      }
    } catch (err) {
      console.error('GD scheduler: HA lag update failed:', err && err.message ? err.message : err);
    } finally {
      if (db) { try { db.close(); } catch (_e) { /* idempotent */ } }
    }
  },
};

module.exports = { gdBackupScheduler };
