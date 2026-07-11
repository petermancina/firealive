// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — HR Scheduling Sync Service
//
// Recurring service that pulls per-analyst weekly availability from the
// configured HR platform (UKG/Kronos, Workday, ADP, BambooHR, or Manual)
// and upserts the results into the canonical analyst_availability table.
// The upskilling auto-assigner (separate component) reads
// analyst_availability to find gaps where it can schedule upskilling
// blocks.
//
// One-way data flow per tick: HR platform -> MC. Push-back of upskilling
// assignments to the HR platform calendar (where the platform supports
// it — Workday and UKG) is a separate code path triggered by the
// auto-assigner when it creates an assignment, not by this recurring
// service. This service is the pull.
//
// Configuration is stored in scheduling_platform_config (singleton row).
// credentials_encrypted is a Tier-1 (AES-256-GCM) base64 blob holding a
// JSON object whose shape varies per platform; see each adapter's
// doc-block for the platform-specific credentials shape.
//
// Sync lifecycle per tick:
//   1. Read scheduling_platform_config; if disabled or missing platform,
//      skip
//   2. Decrypt credentials, JSON-parse to platform-specific shape
//   3. require() the adapter for config.platform
//   4. Call adapter.pullAvailability({ db, log, config }) with retry-and-backoff
//   5. Upsert each returned analyst row into analyst_availability via
//      ON CONFLICT (user_id, week_start) DO UPDATE
//   6. Update last_sync_at, last_sync_status, last_sync_error,
//      last_sync_duration_ms, consecutive_failures
//   7. Audit log success/failure
//
// Circuit breaker: after 20 consecutive failures the service auto-disables
// the sync (sets enabled=0) and emits a critical audit event. The admin
// must re-enable manually via PUT /api/scheduling/config after fixing
// whatever broke. This matches the gd-push.js circuit breaker.
//
// Anonymity: the adapter resolves HR-system-employee-email to users.id
// internally and only ever returns rows keyed by users.id. This service
// never sees email addresses; it just upserts UUID-keyed rows. Email is
// the silent join key inside the adapter, and this service is downstream
// of that translation. (See ANONYMITY MODEL note in db/init.js for the
// full contract.)
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { openTier1 } = require('./tier1-seal');
const { auditLog } = require('../middleware/audit');

const CIRCUIT_BREAKER_THRESHOLD = 20;

// Adapter dispatch table. Keys MUST match scheduling_platform_config.platform
// CHECK constraint values exactly. require()d at module load so a missing
// adapter file fails fast at boot, not on first tick.
const ADAPTERS = {
  ukg_kronos: require('./scheduling-platforms/ukg-kronos'),
  workday:    require('./scheduling-platforms/workday'),
  adp:        require('./scheduling-platforms/adp'),
  bamboohr:   require('./scheduling-platforms/bamboohr'),
  manual:     require('./scheduling-platforms/manual'),
};

class SchedulingSyncService {
  constructor() {
    this.timerId = null;
    this.shuttingDown = false;
    this.inFlight = false;  // guards against overlapping ticks if a sync
                            // somehow runs longer than the configured
                            // interval (unlikely but observed in early
                            // GD push tests under load)
  }

  // ── Public lifecycle ──────────────────────────────────────────────────────
  start() {
    if (this.timerId) return;
    this.shuttingDown = false;
    this._scheduleNext(0);  // first tick immediately so a freshly-configured
                            // sync doesn't wait the full interval before
                            // running
    logger.info('Scheduling sync service started');
  }

  stop() {
    this.shuttingDown = true;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    logger.info('Scheduling sync service stopped');
  }

  /**
   * Trigger an immediate sync, bypassing the recurring schedule. Used by
   * the POST /api/scheduling/sync route handler when a lead clicks
   * "Sync Now" in the MC. Returns synchronously after rescheduling — the
   * actual sync runs asynchronously, and the lead's UI polls
   * GET /api/scheduling/config for last_sync_at to see when it completes.
   *
   * If a tick is already in flight, this method is a no-op (the in-flight
   * guard in _tick will short-circuit a redundant trigger). If the
   * service is shutting down, this method is a no-op (start() must run
   * first).
   *
   * @returns {{ok: boolean, alreadyRunning: boolean, error?: string}}
   */
  triggerSync() {
    if (this.shuttingDown) {
      return { ok: false, alreadyRunning: false, error: 'Sync service is not running. Service must be started before triggering a sync.' };
    }
    if (this.inFlight) {
      // A tick is already running. The current run will record its result
      // when it completes; no need to queue a second one.
      return { ok: true, alreadyRunning: true };
    }
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    this._scheduleNext(0);
    logger.info('Scheduling sync triggered manually');
    return { ok: true, alreadyRunning: false };
  }

  // ── Scheduling ────────────────────────────────────────────────────────────
  _scheduleNext(delayMs) {
    if (this.shuttingDown) return;
    this.timerId = setTimeout(() => this._tick(), delayMs);
  }

  async _tick() {
    if (this.shuttingDown) return;
    if (this.inFlight) {
      logger.warn('Scheduling sync tick skipped — previous tick still running');
      this._scheduleNext(60_000);  // re-check in 1 min
      return;
    }

    let intervalMinutes = 60;  // fallback if config unreadable
    this.inFlight = true;

    try {
      const config = this._readConfig();
      intervalMinutes = (config && config.sync_interval_minutes) || 60;
      if (config && config.enabled === 1 && config.platform && config.credentials_encrypted) {
        await this._performSync(config);
      }
    } catch (err) {
      logger.error('Scheduling sync tick error', { error: err.message });
    } finally {
      this.inFlight = false;
      // Always schedule the next tick, even after errors
      this._scheduleNext(intervalMinutes * 60 * 1000);
    }
  }

  _readConfig() {
    const db = getDb();
    try {
      return db.prepare('SELECT * FROM scheduling_platform_config WHERE id = 1').get();
    } finally {
      db.close();
    }
  }

  // ── Sync attempt ──────────────────────────────────────────────────────────
  async _performSync(config) {
    const startedAt = Date.now();
    let attempt = 0;
    let lastError = null;

    while (attempt <= config.retry_max) {
      attempt++;
      try {
        const credentials = this._decryptCredentials(config.credentials_encrypted);
        const adapter = ADAPTERS[config.platform];
        if (!adapter) {
          // Defensive — should be impossible given ADAPTERS is keyed off the
          // same enum the CHECK constraint enforces.
          throw new Error(`Unknown scheduling platform: ${config.platform}`);
        }

        const adapterCtx = {
          db: getDb(),
          log: this._buildAdapterLogger(config.platform),
          config: {
            endpoint_url: config.endpoint_url,
            credentials,
          },
        };

        let result;
        try {
          result = await adapter.pullAvailability(adapterCtx);
        } finally {
          // The adapter received a borrowed db handle; close it on this side
          // so we don't leak handles per-tick.
          try { adapterCtx.db.close(); } catch { /* best-effort */ }
        }

        const upserted = this._upsertAvailability(config.platform, result);
        const durationMs = Date.now() - startedAt;
        this._recordSuccess(durationMs, upserted);
        return;
      } catch (err) {
        lastError = err;
        if (attempt <= config.retry_max) {
          const backoffMs = config.retry_backoff_seconds * 1000 * attempt;
          await new Promise((r) => setTimeout(r, backoffMs));
        }
      }
    }

    // All retries exhausted
    const durationMs = Date.now() - startedAt;
    this._recordFailure(lastError && lastError.message || 'unknown error', durationMs);
  }

  /**
   * Decrypt the Tier-1 credentials_encrypted blob and JSON-parse the
   * plaintext into the platform-specific credential shape.
   */
  _decryptCredentials(encryptedBase64) {
    if (!encryptedBase64) {
      throw new Error('credentials_encrypted is empty; configure platform credentials first');
    }
    return openTier1('scheduling_platform_config.credentials_encrypted', encryptedBase64);
  }

  /**
   * Build a structured-log shim that the adapter calls with
   *   log(level, msg, meta)
   * and which routes to the canonical logger plus tags every line with
   * the current platform.
   */
  _buildAdapterLogger(platform) {
    return (level, msg, meta = {}) => {
      const fn = logger[level] || logger.info;
      fn.call(logger, msg, { platform, ...meta });
    };
  }

  /**
   * Upsert each returned analyst row into analyst_availability via
   * ON CONFLICT (user_id, week_start) DO UPDATE. Returns the number of
   * rows successfully written (for the success log line).
   */
  _upsertAvailability(platform, result) {
    const list = (result && Array.isArray(result.analysts)) ? result.analysts : [];
    if (list.length === 0) return 0;

    const db = getDb();
    let written = 0;
    try {
      const stmt = db.prepare(`
        INSERT INTO analyst_availability (user_id, week_start, slots_json, source_platform, last_synced_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'))
        ON CONFLICT (user_id, week_start) DO UPDATE SET
          slots_json = excluded.slots_json,
          source_platform = excluded.source_platform,
          last_synced_at = datetime('now'),
          updated_at = datetime('now')
      `);
      const txn = db.transaction((rows) => {
        for (const row of rows) {
          if (!row || !row.userId || !row.weekStart) continue;
          let slotsJson;
          try {
            slotsJson = JSON.stringify(row.slots || {});
          } catch {
            slotsJson = '{}';
          }
          stmt.run(row.userId, row.weekStart, slotsJson, platform);
          written++;
        }
      });
      txn(list);
    } catch (err) {
      // Wrap so the caller treats the upsert failure as a sync failure
      // and the circuit breaker counts it.
      throw new Error(`analyst_availability upsert failed: ${err.message}`);
    } finally {
      db.close();
    }
    return written;
  }

  // ── Status persistence ────────────────────────────────────────────────────
  _recordSuccess(durationMs, upsertedCount) {
    const db = getDb();
    try {
      db.prepare(
        `UPDATE scheduling_platform_config
         SET last_sync_at = datetime('now'),
             last_sync_status = 'success',
             last_sync_error = NULL,
             last_sync_duration_ms = ?,
             consecutive_failures = 0,
             updated_at = datetime('now')
         WHERE id = 1`
      ).run(durationMs);
      auditLog(null, 'SCHEDULING_SYNC_SUCCESS', `duration=${durationMs}ms upserted=${upsertedCount}`);
    } catch (err) {
      logger.error('Scheduling sync success recording failed', { error: err.message });
    } finally {
      db.close();
    }
  }

  _recordFailure(errorMessage, durationMs) {
    const db = getDb();
    try {
      const truncated = (errorMessage || '').slice(0, 1000);
      db.prepare(
        `UPDATE scheduling_platform_config
         SET last_sync_at = datetime('now'),
             last_sync_status = 'failure',
             last_sync_error = ?,
             last_sync_duration_ms = ?,
             consecutive_failures = consecutive_failures + 1,
             updated_at = datetime('now')
         WHERE id = 1`
      ).run(truncated, durationMs);

      const row = db.prepare('SELECT consecutive_failures FROM scheduling_platform_config WHERE id = 1').get();
      const consecutive = (row && row.consecutive_failures) || 0;
      auditLog(null, 'SCHEDULING_SYNC_FAILURE', `error=${truncated.slice(0, 200)} consecutive=${consecutive}`);

      // Circuit breaker — auto-disable after the threshold so a misconfigured
      // or unreachable HR platform doesn't generate unbounded failure logs
      // and unbounded outbound retry traffic. The admin must re-enable
      // manually via PUT /api/scheduling/config after diagnosing.
      if (consecutive >= CIRCUIT_BREAKER_THRESHOLD) {
        db.prepare(
          `UPDATE scheduling_platform_config SET enabled = 0, updated_at = datetime('now') WHERE id = 1`
        ).run();
        auditLog(null, 'SCHEDULING_SYNC_CIRCUIT_BREAKER',
          `Auto-disabled after ${consecutive} consecutive failures. Admin must re-enable via PUT /api/scheduling/config.`);
        logger.error('Scheduling sync circuit breaker tripped — auto-disabled', { consecutiveFailures: consecutive });
      }
    } catch (err) {
      logger.error('Scheduling sync failure recording failed', { error: err.message });
    } finally {
      db.close();
    }
  }
}

// Singleton — there's one HR scheduling sync per Regional MC.
const schedulingSyncService = new SchedulingSyncService();

module.exports = { schedulingSyncService };
