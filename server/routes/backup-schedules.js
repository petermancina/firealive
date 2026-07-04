// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Schedules Routes
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// HTTP surface for the multi-schedule backup subsystem. Mounted at
// /api/backup-schedules in server/index.js with authMiddleware(['admin'])
// and configLockGate() — matching the established posture for
// backup-destinations, backup-push, and gd-config (all of which are
// admin-only platform-config surfaces gated by the config lock).
//
// The route file itself does NOT apply auth or the config-lock gate;
// both are applied at mount time in index.js. Inside the file, the
// only role-vs-action checks needed are within-admin distinctions
// that don't exist here — every endpoint is uniformly admin-grade.
//
// ENDPOINT INVENTORY
//
//   GET    /api/backup-schedules
//     List all schedules with preset metadata JOINed in. Returns
//     a flat array of schedule rows; each row carries
//     preset_name, preset_min_retention_days,
//     preset_required_encryption, preset_framework_citation
//     when regulatory_preset_id is non-null, NULL fields
//     otherwise. Sorted created_at DESC, id DESC.
//
//   POST   /api/backup-schedules
//     Create a new schedule. Body fields:
//       name, type, frequency, time, day_of_week, day_of_month,
//       destination, retention_days, encrypted,
//       regulatory_preset_id, active, force_queue
//     Detects overlap with existing active schedules before
//     INSERT. Returns 409 SCHEDULE_OVERLAP with the conflicting
//     schedule + fire-time pairs unless force_queue=true on the
//     request body. Validates preset floor; returns 400
//     RETENTION_BELOW_FLOOR or ENCRYPTION_REQUIRED on violation.
//     Returns 201 with the created schedule on success.
//
//   PUT    /api/backup-schedules/:id
//     Update an existing schedule. Same body fields as POST.
//     Overlap detection excludes the same row (excludeId=:id).
//     Returns 404 SCHEDULE_NOT_FOUND if id does not exist.
//     Returns 200 with the updated schedule on success.
//
//   DELETE /api/backup-schedules/:id
//     Remove a schedule. Returns 404 SCHEDULE_NOT_FOUND if id
//     does not exist. Returns 200 { deleted: true } on success.
//     ON DELETE SET NULL on the regulatory_preset_id FK means
//     preset removal does not cascade-delete schedules; schedule
//     deletion is operator-initiated only.
//
//   GET    /api/backup-schedules/presets
//     List all regulatory_presets rows. Returns name, description,
//     min_retention_days, required_encryption, recommended_*,
//     framework_citation for each preset. Sorted by name. The UI
//     pre-fills new-schedule form fields from these recommended
//     values when the operator picks a preset.
//
// AUDIT EVENTS WRITTEN
//
//   BACKUP_SCHEDULE_CREATED                 successful POST
//   BACKUP_SCHEDULE_UPDATED                 successful PUT
//   BACKUP_SCHEDULE_DELETED                 successful DELETE
//   BACKUP_SCHEDULE_RETENTION_FLOOR_VIOLATION
//                                           400 from RETENTION_BELOW_FLOOR
//   BACKUP_SCHEDULE_ENCRYPTION_REQUIRED     400 from ENCRYPTION_REQUIRED
//   BACKUP_SCHEDULE_OVERLAP_QUEUED          POST/PUT with force_queue=true
//                                           after overlap detected
//
// All audit_log rows include the operator's user_id, the schedule
// name and id (when known), and structured detail JSON for forensic
// reconstruction. The auditMiddleware writes a generic API-action
// row on every call; these explicit event_type rows are queryable
// for compliance and incident review.
//
// CONFIG LOCK INTERACTION
//
// configLockGate() is applied at mount time in index.js. When the
// platform config lock is engaged (config_lock_state.lock_active=1),
// all mutation endpoints (POST/PUT/DELETE) return 423 Locked. The
// list and presets read endpoints (GET) are also gated for consistency
// with the broader backup-destinations / backup-push pattern; an
// operator wanting to inspect schedules during a locked window
// unlocks via POST /api/config/lock first.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const router = express.Router();
const backupSchedules = require('../services/backup-schedules');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');

// ── Helper: write an explicit audit_log row ──────────────────────────
//
// The auditMiddleware writes a generic API-action row on every call.
// This helper writes an additional row with a queryable event_type
// and structured detail JSON, matching the pattern shipped in
// helper-pay routes (LEADERBOARD_OPT_IN_FLIPPED,
// LEADERBOARD_SOCKPUPPET_CONFIRMED, etc.).
//
// Failures are logged and swallowed — the canonical operation
// has already committed (or already failed); audit-log write
// failure must not change the response semantics.
function writeAuditEvent(req, eventType, detail) {
  try {
    auditLog(
      req.user ? req.user.id : null,
      eventType,
      JSON.stringify(detail || {}),
      req.ip || null,
    );
  } catch (auditErr) {
    logger.warn('backup-schedules audit-log write failed', {
      eventType,
      error: auditErr.message,
    });
  }
}

// ── GET /api/backup-schedules ────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const schedules = backupSchedules.list();
    res.json({ schedules });
  } catch (err) {
    logger.error('GET /api/backup-schedules failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// ── GET /api/backup-schedules/presets ────────────────────────────────
//
// Declared BEFORE the /:id paths so Express does not match 'presets'
// as an :id parameter. (Not strictly required since no GET /:id
// endpoint exists, but explicit ordering prevents future drift.)
router.get('/presets', (req, res) => {
  try {
    const presets = backupSchedules.getPresets();
    res.json({ presets });
  } catch (err) {
    logger.error('GET /api/backup-schedules/presets failed', { error: err.message });
    res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// ── POST /api/backup-schedules ───────────────────────────────────────
//
// Two-phase write:
//   1. Detect overlap with other active schedules. If overlaps
//      and !force_queue → 409 SCHEDULE_OVERLAP.
//   2. Service.create() validates fields + applies preset floor +
//      INSERTs the row + computes next_run.
//
// The two phases are NOT atomic — there is a small window between
// overlap check and INSERT during which another operator could
// create a conflicting schedule. The window is operator-tolerable
// because: (a) backup schedule creation is an admin-grade action,
// not a high-throughput surface; (b) the scheduler tick is the
// authoritative serializer at execution time (overlap_window
// applies at fire time, not just at create time); (c) detectOverlap
// rerun on the next mutation would surface the post-hoc conflict
// for operator review.
router.post('/', (req, res) => {
  const db = getDb();
  const body = req.body || {};

  try {
    const { overlaps } = backupSchedules.detectOverlap(db, body, null);
    if (overlaps.length > 0 && body.force_queue !== true) {
      return res.status(409).json({
        error: 'SCHEDULE_OVERLAP',
        message: `Schedule overlaps with ${overlaps.length} existing fire time(s) within ${backupSchedules.OVERLAP_WINDOW_MIN} minutes. Retry with force_queue=true to confirm.`,
        overlaps,
      });
    }
    if (overlaps.length > 0 && body.force_queue === true) {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_OVERLAP_QUEUED', {
        proposedName: body.name || null,
        overlapCount: overlaps.length,
        overlaps,
      });
    }

    const schedule = backupSchedules.create(body);
    writeAuditEvent(req, 'BACKUP_SCHEDULE_CREATED', {
      scheduleId: schedule.id,
      name: schedule.name,
      preset: schedule.regulatory_preset_id,
      frequency: body.frequency || schedule.interval,
      time: schedule.time,
      destination: schedule.destination,
      encrypted: schedule.encrypted,
      retentionDays: body.retention_days,
      // R3l C57: kind + strategy + destination subset visibility
      backupKind: schedule.backup_kind,
      backupStrategy: schedule.backup_strategy,
      destinationFilter: schedule.destination_filter
        ? JSON.parse(schedule.destination_filter)
        : null,
      // R3l C74: per-schedule chain-depth override visibility.
      // null in audit means "this schedule inherits the global default".
      maxChainDepth: schedule.max_chain_depth == null ? null : schedule.max_chain_depth,
      // B6c post-3: interval cadence visibility (minutes; null = non-interval).
      intervalMinutes: schedule.interval_minutes == null ? null : schedule.interval_minutes,
    });
    return res.status(201).json({ schedule });
  } catch (err) {
    if (err.code === 'RETENTION_BELOW_FLOOR') {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_RETENTION_FLOOR_VIOLATION', {
        attemptedName: body.name || null,
        attemptedPreset: body.regulatory_preset_id || null,
        attemptedRetentionDays: body.retention_days || null,
      });
      return res.status(400).json({ error: err.code, message: err.message });
    }
    if (err.code === 'ENCRYPTION_REQUIRED') {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_ENCRYPTION_REQUIRED', {
        attemptedName: body.name || null,
        attemptedPreset: body.regulatory_preset_id || null,
      });
      return res.status(400).json({ error: err.code, message: err.message });
    }
    if (err.code === 'PRESET_NOT_FOUND'
      || err.code === 'INVALID_FREQUENCY'
      || err.code === 'INVALID_TIME'
      || err.code === 'INVALID_DAY_OF_WEEK'
      || err.code === 'INVALID_DAY_OF_MONTH'
      || err.code === 'INVALID_BACKUP_KIND'
      || err.code === 'INVALID_BACKUP_STRATEGY'
      || err.code === 'INVALID_DESTINATION_FILTER'
      || err.code === 'INVALID_MAX_CHAIN_DEPTH'
      || err.code === 'INVALID_INTERVAL_MINUTES') {
      return res.status(400).json({ error: err.code, message: err.message });
    }
    logger.error('POST /api/backup-schedules failed', { error: err.message });
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// ── PUT /api/backup-schedules/:id ────────────────────────────────────
router.put('/:id', (req, res) => {
  const db = getDb();
  const id = parseInt(req.params.id, 10);
  const body = req.body || {};

  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'INVALID_ID',
      message: 'id must be an integer' });
  }

  try {
    // Overlap detection excludes the same row being updated so the
    // schedule does not conflict with itself.
    const { overlaps } = backupSchedules.detectOverlap(db, body, id);
    if (overlaps.length > 0 && body.force_queue !== true) {
      return res.status(409).json({
        error: 'SCHEDULE_OVERLAP',
        message: `Schedule overlaps with ${overlaps.length} existing fire time(s) within ${backupSchedules.OVERLAP_WINDOW_MIN} minutes. Retry with force_queue=true to confirm.`,
        overlaps,
      });
    }
    if (overlaps.length > 0 && body.force_queue === true) {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_OVERLAP_QUEUED', {
        scheduleId: id,
        proposedName: body.name || null,
        overlapCount: overlaps.length,
        overlaps,
      });
    }

    const schedule = backupSchedules.update(id, body);
    if (!schedule) {
      return res.status(404).json({ error: 'SCHEDULE_NOT_FOUND',
        message: `Schedule #${id} does not exist` });
    }
    writeAuditEvent(req, 'BACKUP_SCHEDULE_UPDATED', {
      scheduleId: schedule.id,
      name: schedule.name,
      preset: schedule.regulatory_preset_id,
      changedFields: Object.keys(body).filter(k => k !== 'force_queue'),
      intervalMinutes: schedule.interval_minutes == null ? null : schedule.interval_minutes,
    });
    return res.json({ schedule });
  } catch (err) {
    if (err.code === 'RETENTION_BELOW_FLOOR') {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_RETENTION_FLOOR_VIOLATION', {
        scheduleId: id,
        attemptedPreset: body.regulatory_preset_id || null,
        attemptedRetentionDays: body.retention_days || null,
      });
      return res.status(400).json({ error: err.code, message: err.message });
    }
    if (err.code === 'ENCRYPTION_REQUIRED') {
      writeAuditEvent(req, 'BACKUP_SCHEDULE_ENCRYPTION_REQUIRED', {
        scheduleId: id,
        attemptedPreset: body.regulatory_preset_id || null,
      });
      return res.status(400).json({ error: err.code, message: err.message });
    }
    if (err.code === 'PRESET_NOT_FOUND'
      || err.code === 'INVALID_FREQUENCY'
      || err.code === 'INVALID_TIME'
      || err.code === 'INVALID_DAY_OF_WEEK'
      || err.code === 'INVALID_DAY_OF_MONTH'
      || err.code === 'INVALID_BACKUP_KIND'
      || err.code === 'INVALID_BACKUP_STRATEGY'
      || err.code === 'INVALID_DESTINATION_FILTER'
      || err.code === 'INVALID_MAX_CHAIN_DEPTH'
      || err.code === 'INVALID_INTERVAL_MINUTES') {
      return res.status(400).json({ error: err.code, message: err.message });
    }
    logger.error('PUT /api/backup-schedules/:id failed', {
      scheduleId: id,
      error: err.message,
    });
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

// ── DELETE /api/backup-schedules/:id ─────────────────────────────────
router.delete('/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) {
    return res.status(400).json({ error: 'INVALID_ID',
      message: 'id must be an integer' });
  }

  // Capture name before delete so the audit-log row carries it.
  let scheduleName = null;
  let presetId = null;
  try {
    const existing = backupSchedules.get(id);
    if (existing) {
      scheduleName = existing.name;
      presetId = existing.regulatory_preset_id;
    }
  } catch (lookupErr) {
    logger.warn('DELETE /api/backup-schedules/:id pre-delete lookup failed', {
      scheduleId: id,
      error: lookupErr.message,
    });
  }

  try {
    const result = backupSchedules.deleteSchedule(id);
    if (!result.deleted) {
      return res.status(404).json({ error: 'SCHEDULE_NOT_FOUND',
        message: `Schedule #${id} does not exist` });
    }
    writeAuditEvent(req, 'BACKUP_SCHEDULE_DELETED', {
      scheduleId: id,
      name: scheduleName,
      preset: presetId,
    });
    return res.json({ deleted: true, id });
  } catch (err) {
    logger.error('DELETE /api/backup-schedules/:id failed', {
      scheduleId: id,
      error: err.message,
    });
    return res.status(500).json({ error: 'INTERNAL_ERROR', message: err.message });
  }
});

module.exports = router;
