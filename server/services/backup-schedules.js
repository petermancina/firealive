// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Schedules Service
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Multi-schedule backup with regulatory framework presets. Operators
// configure as many independent backup schedules as they need; each
// schedule fires on its own cadence and may optionally be tied to a
// regulatory framework preset (HIPAA, SOX, PCI-DSS, GDPR, NIST CSF,
// ISO 27001, SOC 2) that enforces compliance-grade floors on
// retention and encryption.
//
// Architectural relationship to existing backup infrastructure:
//
//   - This service owns the SCHEDULE definitions (when to back up,
//     under what compliance framework). It does NOT execute the
//     backups themselves — the scheduler service tickles backup
//     execution via the existing R3d backup pipeline (encrypted
//     manifests, signing keys, chain integrity).
//
//   - The legacy v1.0.0 BackupService class in backup-service.js
//     coexists. Its addSchedule method becomes a thin delegate to
//     this service in C10; until then the v100 stub route
//     (POST /api/v1/backup/schedule/add) continues to write
//     directly to backup_schedules with the legacy column shape
//     (interval/retention as free-form strings, the eight R3i
//     columns left NULL).
//
//   - The backup_schedules table itself was promoted into init.js
//     migration discipline in C2; this service operates against
//     the canonical schema and never CREATEs or ALTERs tables.
//
// Floor enforcement model (hybrid):
//
//   Picking a regulatory preset on schedule create/update applies
//   the preset's MINIMUM compliance values to the schedule. The
//   operator may go HIGHER but NOT lower. The auditor's question
//   is "what's your retention?" not "what preset did you pick?",
//   so the floor needs teeth — preserved at the service layer
//   via applyPresetFloor() throwing RETENTION_BELOW_FLOOR or
//   ENCRYPTION_REQUIRED when a violation is attempted.
//
//   The 'None' preset (regulatory_preset_id=NULL) skips floor
//   enforcement. Operators retain full flexibility for custom or
//   non-compliance-driven schedules.
//
// Overlap detection model:
//
//   Two schedules whose fire times come within OVERLAP_WINDOW_MIN
//   minutes of each other are considered overlapping. detectOverlap
//   computes the first OVERLAP_LOOKAHEAD fire times for the
//   proposed schedule and checks them against the first
//   OVERLAP_LOOKAHEAD fire times of every OTHER active schedule.
//   The route handler surfaces overlaps as a 409 SCHEDULE_OVERLAP
//   with the conflicting schedule + fire-time pairs; the UI lets
//   the operator confirm queuing the second schedule behind the
//   first.
//
//   The window is ±5 minutes because backup operations can have
//   variable execution duration (DB size, destination latency)
//   and starting two backups at the same moment risks I/O
//   contention on the source DB or destination. A 5-minute
//   safety margin keeps the queueing logic simple and predictable.
//
// Public API:
//
//   list()                                       -> Schedule[]
//   get(id)                                      -> Schedule | null
//   create(data)                                 -> Schedule
//   update(id, data)                             -> Schedule | null
//   deleteSchedule(id)                           -> { deleted: boolean }
//   getPresets()                                 -> Preset[]
//   applyPresetFloor(db, data, presetId)         -> data (in-place, throws on violation)
//   detectOverlap(db, data, excludeId)           -> { overlaps: Overlap[] }
//   nextFireTime(schedule, fromTime=new Date())  -> ISO string | null
//
//   Error codes raised by this service (route handler translates
//   to HTTP status):
//
//     RETENTION_BELOW_FLOOR    400  preset.min_retention_days violated
//     ENCRYPTION_REQUIRED      400  preset.required_encryption='AES-256' but encrypted=0
//     PRESET_NOT_FOUND         400  regulatory_preset_id references missing preset
//     SCHEDULE_NOT_FOUND       404  id does not match any row
//     INVALID_FREQUENCY        400  frequency outside {hourly,daily,weekly,monthly,interval}
//     INVALID_INTERVAL_MINUTES 400  interval_minutes outside [15,1440] for an interval schedule
//     INVALID_TIME             400  time not in 'HH:MM' format
//     INVALID_DAY_OF_WEEK      400  day_of_week not in 0..6
//     INVALID_DAY_OF_MONTH     400  day_of_month not in 1..31
//
//   SCHEDULE_OVERLAP is NOT thrown by the service — the route
//   handler calls detectOverlap() and returns 409 itself when
//   the returned overlaps list is non-empty AND the request did
//   not include force_queue=true.

const { getDb } = require('../db/init');

// ── Tunable constants ────────────────────────────────────────────────

const OVERLAP_WINDOW_MIN = 5;        // minutes between fire times to consider overlap
const OVERLAP_LOOKAHEAD = 10;        // number of future fires to compute per schedule for overlap check
const VALID_FREQUENCIES = ['hourly', 'daily', 'weekly', 'monthly', 'interval'];

// Arbitrary sub-daily cadence bounds for frequency='interval'. Floor 15 min:
// below it backup overhead + overlap risk dominate, and sub-15-min RPO is the
// continuous-data-protection paradigm, not scheduled backups. Ceiling 1440 min
// (= daily); longer cadence uses the daily/weekly/monthly frequencies.
const MIN_INTERVAL_MINUTES = 15;
const MAX_INTERVAL_MINUTES = 1440;

// R3l C57: per-schedule kind + strategy enums, mirror of the schema CHECK
// constraints landed by R3l C53 and R3l C55. Kept in sync with init.js
// (Workstream 3 schema layer). Exported so route layers and tests can
// reference the canonical sets without re-declaring them.
const VALID_BACKUP_KINDS = ['single-db', 'full-suite'];
const VALID_BACKUP_STRATEGIES = ['full', 'incremental', 'differential', 'snapshot'];

// ── Error helper ─────────────────────────────────────────────────────

function makeError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// ── nextFireTime ─────────────────────────────────────────────────────
//
// Pure function: given a schedule record and an optional reference
// time, returns the next ISO timestamp at which the schedule should
// fire. Returns null when the schedule is inactive (active=0) — the
// scheduler treats null next_run as "do not register this schedule".
//
// Frequency semantics:
//
//   hourly        Fires at the top of every hour. The time field is
//                 ignored for hourly schedules; next fire is the next
//                 hour boundary at or after fromTime.
//
//   interval      Fires every interval_minutes on a stable grid anchored
//                 at created_at (a scheduler outage skips missed fires and
//                 resumes on the grid rather than bursting catch-up runs).
//                 The time / day fields are ignored. interval_minutes is
//                 bounded [15, 1440]; the sub-daily cadence for RPO policies
//                 under 24h. Below 15 min is the CDP paradigm, out of scope.
//
//   daily         Fires once a day at the configured time. If today's
//                 time is still in the future, fires today; else
//                 fires tomorrow.
//
//   weekly        Fires once a week on day_of_week at the configured
//                 time. Computes the next occurrence at or after
//                 fromTime.
//
//   monthly       Fires once a month on day_of_month at the configured
//                 time. If day_of_month > days-in-current-month
//                 (e.g. day_of_month=31 in February), fires on the
//                 last day of that month. Next occurrence at or
//                 after fromTime.
//
// Edge cases:
//
//   - active=0 schedules return null (no scheduling).
//   - Missing required fields for a frequency return null with no
//     throw (caller handles validation upstream).
//   - All times are computed in UTC. The route handler stores time
//     fields as the operator entered them (UTC by convention); the
//     scheduler also runs in UTC. Cross-timezone deployments
//     should configure their schedules with explicit UTC times.

function nextFireTime(schedule, fromTime = new Date()) {
  if (!schedule || schedule.active === 0) return null;

  const frequency = schedule.frequency || _legacyIntervalToFrequency(schedule.interval);
  if (!VALID_FREQUENCIES.includes(frequency)) return null;

  const from = new Date(fromTime);

  if (frequency === 'hourly') {
    // Next hour boundary at or after fromTime.
    const next = new Date(from);
    next.setUTCMinutes(0, 0, 0);
    if (next <= from) next.setUTCHours(next.getUTCHours() + 1);
    return next.toISOString();
  }

  if (frequency === 'interval') {
    // Fires every interval_minutes on a stable grid anchored at the schedule's
    // created_at (like hourly's hour-boundary grid). Anchoring at created_at
    // rather than last_run means a scheduler outage skips missed fires and
    // resumes on the grid, instead of bursting a run of catch-up backups. The
    // time / day_of_week / day_of_month fields are ignored for interval
    // schedules. interval_minutes is bounded [MIN, MAX]; out-of-range or
    // non-integer returns null (no scheduling), matching upstream validation.
    const im = schedule.interval_minutes;
    if (typeof im !== 'number' || !Number.isInteger(im)
        || im < MIN_INTERVAL_MINUTES || im > MAX_INTERVAL_MINUTES) {
      return null;
    }
    const anchor = schedule.created_at ? new Date(schedule.created_at) : from;
    if (Number.isNaN(anchor.getTime())) return null;
    const intervalMs = im * 60 * 1000;
    const elapsed = from.getTime() - anchor.getTime();
    const k = Math.max(1, Math.floor(elapsed / intervalMs) + 1);
    return new Date(anchor.getTime() + k * intervalMs).toISOString();
  }

  const time = schedule.time || '02:00';
  const timeMatch = /^(\d{1,2}):(\d{2})$/.exec(time);
  if (!timeMatch) return null;
  const hours = parseInt(timeMatch[1], 10);
  const minutes = parseInt(timeMatch[2], 10);
  if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return null;

  if (frequency === 'daily') {
    const next = new Date(from);
    next.setUTCHours(hours, minutes, 0, 0);
    if (next <= from) next.setUTCDate(next.getUTCDate() + 1);
    return next.toISOString();
  }

  if (frequency === 'weekly') {
    const dow = schedule.day_of_week;
    if (typeof dow !== 'number' || dow < 0 || dow > 6) return null;
    const next = new Date(from);
    next.setUTCHours(hours, minutes, 0, 0);
    const currentDow = next.getUTCDay();
    let daysAhead = (dow - currentDow + 7) % 7;
    if (daysAhead === 0 && next <= from) daysAhead = 7;
    next.setUTCDate(next.getUTCDate() + daysAhead);
    return next.toISOString();
  }

  if (frequency === 'monthly') {
    const dom = schedule.day_of_month;
    if (typeof dom !== 'number' || dom < 1 || dom > 31) return null;
    const next = new Date(from);
    next.setUTCHours(hours, minutes, 0, 0);
    // Set day; clamp to last day of month if dom > daysInMonth.
    const daysInMonth = new Date(Date.UTC(
      next.getUTCFullYear(),
      next.getUTCMonth() + 1,
      0,
    )).getUTCDate();
    const effectiveDom = Math.min(dom, daysInMonth);
    next.setUTCDate(effectiveDom);
    if (next <= from) {
      // Advance to next month and clamp again.
      next.setUTCMonth(next.getUTCMonth() + 1, 1);
      const nextDaysInMonth = new Date(Date.UTC(
        next.getUTCFullYear(),
        next.getUTCMonth() + 1,
        0,
      )).getUTCDate();
      next.setUTCDate(Math.min(dom, nextDaysInMonth));
      next.setUTCHours(hours, minutes, 0, 0);
    }
    return next.toISOString();
  }

  return null;
}

// Legacy interval strings from v100 callers (e.g. 'Every 4hr', 'Daily',
// 'Weekly'). Crude mapping for backwards compatibility. Modern callers
// supply frequency directly.
function _legacyIntervalToFrequency(interval) {
  if (!interval || typeof interval !== 'string') return null;
  const lower = interval.toLowerCase();
  if (lower === 'interval') return 'interval';
  if (lower.includes('hour')) return 'hourly';
  if (lower.includes('week')) return 'weekly';
  if (lower.includes('month')) return 'monthly';
  if (lower.includes('day') || lower === 'daily') return 'daily';
  return null;
}

// ── applyPresetFloor ─────────────────────────────────────────────────
//
// Validates a schedule's retention_days and encrypted fields against
// the preset's floor. Throws on violation; otherwise returns the
// (unchanged) data.
//
// Note: this function does NOT pre-fill recommended fields (frequency,
// destination_type). Those are pre-filled by the UI on preset
// selection, not enforced by the service. The service only enforces
// the floor.

function applyPresetFloor(db, data, presetId) {
  if (presetId == null) return data;

  const preset = db.prepare(
    'SELECT * FROM regulatory_presets WHERE id = ?',
  ).get(presetId);
  if (!preset) {
    throw makeError('PRESET_NOT_FOUND',
      `Regulatory preset '${presetId}' does not exist`);
  }

  const retentionDays = _parseRetentionDays(data.retention_days, data.retention);
  if (retentionDays == null || retentionDays < preset.min_retention_days) {
    throw makeError('RETENTION_BELOW_FLOOR',
      `Preset '${preset.name}' requires retention of at least ${preset.min_retention_days} days; got ${retentionDays}`);
  }

  if (preset.required_encryption === 'AES-256' && data.encrypted !== 1) {
    throw makeError('ENCRYPTION_REQUIRED',
      `Preset '${preset.name}' requires AES-256 encryption (encrypted must be 1)`);
  }

  return data;
}

// Accept either retention_days (modern INTEGER) or retention (legacy
// free-form string like '30 days'). Returns the integer day count or
// null when neither parseable nor present.
function _parseRetentionDays(retentionDays, retentionString) {
  if (typeof retentionDays === 'number' && Number.isInteger(retentionDays)) {
    return retentionDays;
  }
  if (typeof retentionString === 'string') {
    const match = /^(\d+)\s*day/i.exec(retentionString);
    if (match) return parseInt(match[1], 10);
  }
  return null;
}

// ── detectOverlap ────────────────────────────────────────────────────
//
// For the proposed schedule data, compute the first OVERLAP_LOOKAHEAD
// fire times. Then for each OTHER active schedule, compute its first
// OVERLAP_LOOKAHEAD fire times. Any pair (proposed, other) within
// OVERLAP_WINDOW_MIN minutes is an overlap.
//
// excludeId: when updating an existing schedule, pass its id here so
// the schedule does not detect overlap with itself.
//
// Returns { overlaps: [{ scheduleId, fireTime, conflictingFireTime }] }.

function detectOverlap(db, data, excludeId = null) {
  const proposedFires = _computeFireSeries(data);
  if (proposedFires.length === 0) return { overlaps: [] };

  const otherSchedules = db.prepare(
    'SELECT * FROM backup_schedules WHERE active = 1 AND id != ?',
  ).all(excludeId == null ? -1 : excludeId);

  const windowMs = OVERLAP_WINDOW_MIN * 60 * 1000;
  const overlaps = [];

  for (const other of otherSchedules) {
    const otherFires = _computeFireSeries(other);
    for (const proposed of proposedFires) {
      for (const otherFire of otherFires) {
        const diff = Math.abs(new Date(proposed) - new Date(otherFire));
        if (diff <= windowMs) {
          overlaps.push({
            scheduleId: other.id,
            scheduleName: other.name || `Schedule #${other.id}`,
            fireTime: proposed,
            conflictingFireTime: otherFire,
          });
        }
      }
    }
  }

  return { overlaps };
}

// Compute the next OVERLAP_LOOKAHEAD fire times for a schedule.
// Iterates nextFireTime() from each fire time forward.
function _computeFireSeries(schedule) {
  const fires = [];
  let cursor = new Date();
  for (let i = 0; i < OVERLAP_LOOKAHEAD; i += 1) {
    const next = nextFireTime(schedule, cursor);
    if (!next) break;
    fires.push(next);
    // Advance cursor 1 ms past the fire so the next iteration finds
    // the SUBSEQUENT fire, not the same one.
    cursor = new Date(new Date(next).getTime() + 1);
  }
  return fires;
}

// ── Public CRUD ──────────────────────────────────────────────────────

function list() {
  const db = getDb();
  const rows = db.prepare(`
    SELECT
      s.*,
      p.name AS preset_name,
      p.min_retention_days AS preset_min_retention_days,
      p.required_encryption AS preset_required_encryption,
      p.framework_citation AS preset_framework_citation
    FROM backup_schedules s
    LEFT JOIN regulatory_presets p ON s.regulatory_preset_id = p.id
    ORDER BY s.created_at DESC, s.id DESC
  `).all();
  return rows;
}

function get(id) {
  const db = getDb();
  const row = db.prepare(`
    SELECT
      s.*,
      p.name AS preset_name,
      p.min_retention_days AS preset_min_retention_days,
      p.required_encryption AS preset_required_encryption,
      p.framework_citation AS preset_framework_citation
    FROM backup_schedules s
    LEFT JOIN regulatory_presets p ON s.regulatory_preset_id = p.id
    WHERE s.id = ?
  `).get(id);
  return row || null;
}

function create(data) {
  const db = getDb();
  _validateScheduleFields(data);

  if (data.regulatory_preset_id != null) {
    applyPresetFloor(db, data, data.regulatory_preset_id);
  }

  const now = new Date().toISOString();
  const result = db.prepare(`
    INSERT INTO backup_schedules
      (type, interval, retention, destination, encrypted, active,
       last_run, created_at, name, regulatory_preset_id,
       time, day_of_week, day_of_month, next_run, last_status, last_error,
       backup_kind, backup_strategy, destination_filter, max_chain_depth,
       interval_minutes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    data.type || 'full',
    data.frequency || data.interval || null,
    _stringifyRetention(data.retention_days, data.retention),
    data.destination || null,
    data.encrypted === undefined ? 1 : (data.encrypted ? 1 : 0),
    data.active === undefined ? 1 : (data.active ? 1 : 0),
    null,
    now,
    data.name || null,
    data.regulatory_preset_id || null,
    data.time || null,
    data.day_of_week == null ? null : data.day_of_week,
    data.day_of_month == null ? null : data.day_of_month,
    null,
    null,
    null,
    // R3l C57: explicit defaults match the schema's NOT NULL DEFAULT
    // declarations from R3l C53 + R3l C55. Passing NULL here would
    // violate NOT NULL; passing the same string the schema would
    // default to keeps INSERT and ALTER-with-DEFAULT in sync.
    data.backup_kind || 'full-suite',
    data.backup_strategy || 'full',
    data.destination_filter ? JSON.stringify(data.destination_filter) : null,
    // R3l C74: max_chain_depth NULL = use system_meta global default.
    // The C73 schema migration added this column as nullable INTEGER
    // (no default), so INSERT with NULL is valid and means "fall through".
    data.max_chain_depth == null ? null : data.max_chain_depth,
    // interval_minutes: the sub-daily cadence for frequency='interval'
    // (nullable INTEGER; NULL for non-interval schedules).
    data.interval_minutes == null ? null : data.interval_minutes,
  );

  const id = result.lastInsertRowid;
  const row = get(id);
  if (row) {
    const next = nextFireTime(_rowToSchedule(row));
    if (next) {
      db.prepare('UPDATE backup_schedules SET next_run = ? WHERE id = ?').run(next, id);
      row.next_run = next;
    }
  }
  return row;
}

function update(id, data) {
  const db = getDb();
  const existing = get(id);
  if (!existing) return null;

  _validateScheduleFields(data);

  if (data.regulatory_preset_id != null) {
    applyPresetFloor(db, data, data.regulatory_preset_id);
  }

  db.prepare(`
    UPDATE backup_schedules
    SET type = COALESCE(?, type),
        interval = COALESCE(?, interval),
        retention = COALESCE(?, retention),
        destination = COALESCE(?, destination),
        encrypted = COALESCE(?, encrypted),
        active = COALESCE(?, active),
        name = COALESCE(?, name),
        regulatory_preset_id = COALESCE(?, regulatory_preset_id),
        time = COALESCE(?, time),
        day_of_week = COALESCE(?, day_of_week),
        day_of_month = COALESCE(?, day_of_month),
        backup_kind = COALESCE(?, backup_kind),
        backup_strategy = COALESCE(?, backup_strategy),
        destination_filter = COALESCE(?, destination_filter),
        max_chain_depth = COALESCE(?, max_chain_depth),
        interval_minutes = COALESCE(?, interval_minutes)
    WHERE id = ?
  `).run(
    data.type || null,
    data.frequency || data.interval || null,
    _stringifyRetention(data.retention_days, data.retention),
    data.destination || null,
    data.encrypted === undefined ? null : (data.encrypted ? 1 : 0),
    data.active === undefined ? null : (data.active ? 1 : 0),
    data.name || null,
    data.regulatory_preset_id || null,
    data.time || null,
    data.day_of_week == null ? null : data.day_of_week,
    data.day_of_month == null ? null : data.day_of_month,
    // R3l C57: COALESCE preserves existing values when these are NULL.
    // To clear destination_filter back to NULL after setting it,
    // operators currently must DELETE and re-create the schedule;
    // explicit-clear support is out of scope for this commit.
    data.backup_kind || null,
    data.backup_strategy || null,
    data.destination_filter ? JSON.stringify(data.destination_filter) : null,
    // R3l C74: same COALESCE pattern. To clear back to NULL (revert
    // schedule from override to global default), the same DELETE+re-
    // create workflow applies. PUT with max_chain_depth=null is
    // semantically "leave unchanged", not "clear override".
    data.max_chain_depth == null ? null : data.max_chain_depth,
    data.interval_minutes == null ? null : data.interval_minutes,
    id,
  );

  const updated = get(id);
  if (updated) {
    const next = nextFireTime(_rowToSchedule(updated));
    db.prepare('UPDATE backup_schedules SET next_run = ? WHERE id = ?').run(next, id);
    updated.next_run = next;
  }
  return updated;
}

function deleteSchedule(id) {
  const db = getDb();
  const result = db.prepare('DELETE FROM backup_schedules WHERE id = ?').run(id);
  return { deleted: result.changes > 0 };
}

function getPresets() {
  const db = getDb();
  return db.prepare(
    'SELECT * FROM regulatory_presets ORDER BY name',
  ).all();
}

// ── Internal helpers ─────────────────────────────────────────────────

// Normalize a DB row into the schedule shape that nextFireTime expects.
// The row may have legacy interval and modern frequency; nextFireTime
// falls back to _legacyIntervalToFrequency when frequency is null.
function _rowToSchedule(row) {
  return {
    active: row.active,
    frequency: row.frequency,
    interval: row.interval,
    interval_minutes: row.interval_minutes,
    created_at: row.created_at,
    time: row.time,
    day_of_week: row.day_of_week,
    day_of_month: row.day_of_month,
  };
}

// Convert retention_days (INTEGER) into the legacy retention TEXT
// column shape (e.g. '30 days') for backwards-compatible storage.
// Pre-existing rows with retention TEXT are preserved verbatim;
// new rows always get the canonical 'N days' form.
function _stringifyRetention(retentionDays, retentionString) {
  if (typeof retentionDays === 'number' && Number.isInteger(retentionDays)) {
    return `${retentionDays} days`;
  }
  if (typeof retentionString === 'string') return retentionString;
  return null;
}

// Validate the optional schedule fields. Frequency-driven schedules
// (daily/weekly/monthly) require time; weekly requires day_of_week;
// monthly requires day_of_month. Hourly does not require time.
function _validateScheduleFields(data) {
  if (data.frequency !== undefined && data.frequency !== null) {
    if (!VALID_FREQUENCIES.includes(data.frequency)) {
      throw makeError('INVALID_FREQUENCY',
        `frequency must be one of: ${VALID_FREQUENCIES.join(', ')}`);
    }
  }
  // Interval schedules carry the sub-daily cadence in interval_minutes, bounded
  // [MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES]. Validated whenever the request
  // declares an interval schedule (via the modern frequency field or the legacy
  // interval column value) so a 400 is returned rather than a schedule that
  // never fires (nextFireTime returns null for an out-of-range interval).
  if (data.frequency === 'interval' || data.interval === 'interval') {
    const im = data.interval_minutes;
    if (!Number.isInteger(im) || im < MIN_INTERVAL_MINUTES || im > MAX_INTERVAL_MINUTES) {
      throw makeError('INVALID_INTERVAL_MINUTES',
        `interval_minutes must be an integer in ${MIN_INTERVAL_MINUTES}..${MAX_INTERVAL_MINUTES} for an interval schedule`);
    }
  }
  if (data.time !== undefined && data.time !== null) {
    if (!/^\d{1,2}:\d{2}$/.test(data.time)) {
      throw makeError('INVALID_TIME', 'time must be in HH:MM 24-hour format');
    }
    const [h, m] = data.time.split(':').map(n => parseInt(n, 10));
    if (h < 0 || h > 23 || m < 0 || m > 59) {
      throw makeError('INVALID_TIME', 'time must be a valid HH:MM 24-hour value');
    }
  }
  if (data.day_of_week !== undefined && data.day_of_week !== null) {
    if (!Number.isInteger(data.day_of_week) || data.day_of_week < 0 || data.day_of_week > 6) {
      throw makeError('INVALID_DAY_OF_WEEK',
        'day_of_week must be an integer in 0..6 (Sunday=0)');
    }
  }
  if (data.day_of_month !== undefined && data.day_of_month !== null) {
    if (!Number.isInteger(data.day_of_month) || data.day_of_month < 1 || data.day_of_month > 31) {
      throw makeError('INVALID_DAY_OF_MONTH',
        'day_of_month must be an integer in 1..31');
    }
  }
  // R3l C57: backup_kind / backup_strategy / destination_filter validation.
  // Each is optional on the request (POST defaults to 'full-suite'/'full'/
  // null; PUT leaves unchanged when absent). Validation here mirrors the
  // SQLite CHECK constraints from C53/C55 so a 400 is returned with a
  // helpful message rather than letting the request reach the DB and fail
  // with SQLITE_CONSTRAINT_CHECK.
  if (data.backup_kind !== undefined && data.backup_kind !== null) {
    if (!VALID_BACKUP_KINDS.includes(data.backup_kind)) {
      throw makeError('INVALID_BACKUP_KIND',
        `backup_kind must be one of: ${VALID_BACKUP_KINDS.join(', ')}`);
    }
  }
  if (data.backup_strategy !== undefined && data.backup_strategy !== null) {
    if (!VALID_BACKUP_STRATEGIES.includes(data.backup_strategy)) {
      throw makeError('INVALID_BACKUP_STRATEGY',
        `backup_strategy must be one of: ${VALID_BACKUP_STRATEGIES.join(', ')}`);
    }
  }
  if (data.destination_filter !== undefined && data.destination_filter !== null) {
    if (!Array.isArray(data.destination_filter)) {
      throw makeError('INVALID_DESTINATION_FILTER',
        'destination_filter must be an array of tag strings (or null for no filter)');
    }
    if (!data.destination_filter.every(t => typeof t === 'string')) {
      throw makeError('INVALID_DESTINATION_FILTER',
        'destination_filter entries must all be strings');
    }
  }
  // R3l C74: max_chain_depth validation. Per-schedule override for the
  // depth limit enforced by backup-incremental.js (C73). Must be a
  // positive integer, or null to fall back to the system_meta global
  // default ('100' as seeded by the C73 migration). The hard cap from
  // C65 restore-chain.js (MAX_CHAIN_DEPTH=1000) is the upper bound on
  // any per-schedule value since the chain walker won't follow chains
  // longer than that regardless of what the schedule says.
  if (data.max_chain_depth !== undefined && data.max_chain_depth !== null) {
    if (!Number.isInteger(data.max_chain_depth) || data.max_chain_depth <= 0) {
      throw makeError('INVALID_MAX_CHAIN_DEPTH',
        'max_chain_depth must be a positive integer (or null to use the global default)');
    }
    if (data.max_chain_depth > 1000) {
      throw makeError('INVALID_MAX_CHAIN_DEPTH',
        'max_chain_depth must be at most 1000 (the hard cap enforced by restore-chain.js)');
    }
  }
}

// ── Module exports ───────────────────────────────────────────────────

module.exports = {
  list,
  get,
  create,
  update,
  delete: deleteSchedule,
  deleteSchedule,
  getPresets,
  applyPresetFloor,
  detectOverlap,
  nextFireTime,
  // Tunable constants exported for visibility and tests.
  OVERLAP_WINDOW_MIN,
  OVERLAP_LOOKAHEAD,
  VALID_FREQUENCIES,
  // R3l C57: kind + strategy enum constants exported for route layers,
  // tests, and any future API contract documentation generators.
  VALID_BACKUP_KINDS,
  VALID_BACKUP_STRATEGIES,
};
