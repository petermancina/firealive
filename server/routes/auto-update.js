// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Automated Update-Detection Admin Routes (B5r)
//
// Admin API for detect-and-notify update checking. Backs the management console
// Updates tab and the update-available banner. FireAlive never downloads,
// routes, or installs an update -- it checks THIS repo's GitHub Releases (via
// services/update-check) and surfaces the result.
//
//   GET    /api/auto-update/config      the schedule config (safe defaults when
//                                       unset; opt-in -- disabled by default)
//   PUT    /api/auto-update/config      set the schedule config (validated +
//                                       audited; a config-write -- gated by the
//                                       config-lock chokepoint, registered in
//                                       config-write-routes.js)
//   POST   /api/auto-update/check-now   run a check immediately (manual), record
//                                       it, and return the outcome (lightly
//                                       rate-limited so the button cannot hammer
//                                       GitHub)
//   GET    /api/auto-update/status      lean state for the banner + last-check
//                                       display
//
// Mounting (index.js) applies admin auth + the config-write chokepoint, so these
// handlers assume an authenticated admin and read req.user.id for the audit
// actor. The schedule config is the team_config key auto_update_schedule_config;
// each check is recorded in auto_update_check_log. The HA-gated scheduled check
// and the once-per-version channel notification live in services/scheduler.js
// (commit 6); a manual check here records notified=0 and never fires a channel
// notice (the admin sees the result directly), leaving the once-per-version
// notify decision to the scheduler.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const router = express.Router();

const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { requireObjectBody } = require('../middleware/body-validation');
const { logger } = require('../services/logger');
const { version } = require('../lib/version');
const updateCheck = require('../services/update-check');

const APP_VERSION = version;

// Opt-in: disabled by default, so air-gapped / offline-first deployments stay
// dark unless an operator turns the check on.
const DEFAULTS = {
  enabled: false,
  frequency: 'weekly',   // 'daily' | 'weekly' | 'monthly'
  dayOfWeek: 1,          // 0-6 (Sunday=0), used when frequency='weekly'
  dayOfMonth: 1,         // 1-28, used when frequency='monthly'
  timeUtc: '03:00',      // HH:MM, the cadence window in UTC
  notifyLead: false,     // also notify the team lead via their configured channels
};

const FREQUENCIES = ['daily', 'weekly', 'monthly'];

// A manual "check now" may run at most once a minute per process, so a stuck or
// rapidly-clicked button cannot hammer the public GitHub endpoint.
let lastManualCheckMs = 0;
const MANUAL_CHECK_MIN_INTERVAL_MS = 60 * 1000;

function actorOf(req) {
  return req.user && req.user.id ? req.user.id : 'system';
}

function isAllDigits(str) {
  if (typeof str !== 'string' || str.length === 0) return false;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    if (c < 48 || c > 57) return false;
  }
  return true;
}

function isInt(n) {
  return typeof n === 'number' && Number.isInteger(n);
}

// Validate an 'HH:MM' 24-hour UTC time, regex-free.
function isValidTimeUtc(s) {
  if (typeof s !== 'string') return false;
  const parts = s.split(':');
  if (parts.length !== 2) return false;
  if (!isAllDigits(parts[0]) || !isAllDigits(parts[1])) return false;
  if (parts[0].length < 1 || parts[0].length > 2) return false;
  if (parts[1].length !== 2) return false;
  const hh = Number(parts[0]);
  const mm = Number(parts[1]);
  return hh >= 0 && hh <= 23 && mm >= 0 && mm <= 59;
}

// Validate + normalize an incoming schedule config. Returns { ok, config } or
// { ok:false, error }.
function validateConfig(body) {
  const out = Object.assign({}, DEFAULTS);

  if (typeof body.enabled !== 'boolean') {
    return { ok: false, error: 'enabled must be a boolean' };
  }
  out.enabled = body.enabled;

  if (typeof body.frequency !== 'string' || FREQUENCIES.indexOf(body.frequency) === -1) {
    return { ok: false, error: "frequency must be one of 'daily', 'weekly', 'monthly'" };
  }
  out.frequency = body.frequency;

  if (body.dayOfWeek !== undefined && body.dayOfWeek !== null) {
    if (!isInt(body.dayOfWeek) || body.dayOfWeek < 0 || body.dayOfWeek > 6) {
      return { ok: false, error: 'dayOfWeek must be an integer 0-6 (Sunday=0)' };
    }
    out.dayOfWeek = body.dayOfWeek;
  }

  if (body.dayOfMonth !== undefined && body.dayOfMonth !== null) {
    if (!isInt(body.dayOfMonth) || body.dayOfMonth < 1 || body.dayOfMonth > 28) {
      return { ok: false, error: 'dayOfMonth must be an integer 1-28' };
    }
    out.dayOfMonth = body.dayOfMonth;
  }

  if (!isValidTimeUtc(body.timeUtc)) {
    return { ok: false, error: "timeUtc must be 'HH:MM' (24-hour UTC)" };
  }
  const tp = String(body.timeUtc).split(':');
  out.timeUtc = (tp[0].length === 1 ? '0' + tp[0] : tp[0]) + ':' + tp[1];

  if (typeof body.notifyLead !== 'boolean') {
    return { ok: false, error: 'notifyLead must be a boolean' };
  }
  out.notifyLead = body.notifyLead;

  return { ok: true, config: out };
}

// Read the stored config merged over defaults (so a partial or absent row still
// yields a complete, safe config).
function readConfig(db) {
  const row = db.prepare("SELECT value FROM team_config WHERE key = 'auto_update_schedule_config'").get();
  if (!row) return Object.assign({}, DEFAULTS);
  try {
    const parsed = JSON.parse(row.value);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return Object.assign({}, DEFAULTS, parsed);
    }
  } catch (e) {
    /* fall through to defaults on a corrupt value */
  }
  return Object.assign({}, DEFAULTS);
}

// ── GET /config ──────────────────────────────────────────────────────────────
router.get('/config', (req, res) => {
  const db = getDb();
  try {
    return res.json({ config: readConfig(db) });
  } catch (e) {
    logger.error('auto-update: get config failed', { error: e.message });
    return res.status(500).json({ error: 'Failed to read update schedule config' });
  } finally {
    try { db.close(); } catch (e) { /* ignore */ }
  }
});

// ── PUT /config (config-write -- gated by the chokepoint at the mount) ────────
router.put('/config', requireObjectBody, (req, res) => {
  const v = validateConfig(req.body);
  if (!v.ok) return res.status(400).json({ error: v.error });
  const cfg = v.config;

  const db = getDb();
  try {
    db.prepare(
      "INSERT INTO team_config (key, value, updated_by) VALUES ('auto_update_schedule_config', ?, ?) " +
      "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')"
    ).run(JSON.stringify(cfg), actorOf(req));
  } catch (e) {
    logger.error('auto-update: put config failed', { error: e.message });
    try { db.close(); } catch (e2) { /* ignore */ }
    return res.status(500).json({ error: 'Failed to save update schedule config' });
  }
  try { db.close(); } catch (e) { /* ignore */ }

  auditLog(
    actorOf(req),
    'AUTO_UPDATE_CONFIG_SET',
    `enabled=${cfg.enabled}, frequency=${cfg.frequency}, timeUtc=${cfg.timeUtc}, notifyLead=${cfg.notifyLead}`,
    req.ip
  );
  return res.json({ ok: true, config: cfg });
});

// ── POST /check-now (manual; rate-limited; records notified=0) ────────────────
router.post('/check-now', async (req, res) => {
  const now = Date.now();
  const sinceMs = now - lastManualCheckMs;
  if (sinceMs < MANUAL_CHECK_MIN_INTERVAL_MS) {
    const retryAfterSec = Math.ceil((MANUAL_CHECK_MIN_INTERVAL_MS - sinceMs) / 1000);
    return res.status(429).json({
      error: 'A manual update check ran recently. Please wait a moment before checking again.',
      retryAfterSec,
    });
  }
  lastManualCheckMs = now;

  let r;
  try {
    r = await updateCheck.checkForUpdate({ currentVersion: APP_VERSION });
  } catch (e) {
    // checkForUpdate is written never to reject; guard anyway and fail safe.
    logger.error('auto-update: manual check threw', { error: e.message });
    r = { result: 'source_unreachable', latestVersion: null, releaseUrl: null, releaseName: null, checkedAt: new Date().toISOString() };
  }

  const db = getDb();
  try {
    db.prepare(
      "INSERT INTO auto_update_check_log (current_version, result, latest_version, release_url, notified, trigger_kind) " +
      "VALUES (?, ?, ?, ?, 0, 'manual')"
    ).run(APP_VERSION, r.result, r.latestVersion, r.releaseUrl);
  } catch (e) {
    logger.error('auto-update: failed to record manual check', { error: e.message });
  } finally {
    try { db.close(); } catch (e) { /* ignore */ }
  }

  auditLog(
    actorOf(req),
    'UPDATE_CHECK_RAN',
    `trigger=manual result=${r.result}${r.latestVersion ? ' latest=' + r.latestVersion : ''}`,
    req.ip
  );

  return res.json({
    result: r.result,
    currentVersion: APP_VERSION,
    latestVersion: r.latestVersion,
    releaseUrl: r.releaseUrl,
    releaseName: r.releaseName,
    checkedAt: r.checkedAt,
  });
});

// ── GET /status (lean -- banner + last-check display) ─────────────────────────
router.get('/status', (req, res) => {
  const db = getDb();
  try {
    const cfg = readConfig(db);
    const lastRow = db.prepare(
      "SELECT checked_at, result FROM auto_update_check_log ORDER BY id DESC LIMIT 1"
    ).get();
    // The most recent DETERMINATE verdict (available/none). A 'source_unreachable'
    // never overrides a standing 'available' (the update did not vanish because a
    // later check could not reach GitHub).
    const lastDet = db.prepare(
      "SELECT result, latest_version, release_url FROM auto_update_check_log WHERE result IN ('available', 'none') ORDER BY id DESC LIMIT 1"
    ).get();

    let updateAvailable = false;
    let latestVersion = null;
    let releaseUrl = null;
    // Re-check strictly-newer against the live running version so the banner
    // auto-clears once the operator has updated, even before the next check runs.
    if (lastDet && lastDet.result === 'available' && lastDet.latest_version &&
        updateCheck.isStrictlyNewer(lastDet.latest_version, APP_VERSION)) {
      updateAvailable = true;
      latestVersion = lastDet.latest_version;
      releaseUrl = lastDet.release_url || null;
    }

    return res.json({
      currentVersion: APP_VERSION,
      enabled: cfg.enabled,
      updateAvailable,
      latestVersion,
      releaseUrl,
      lastCheckedAt: lastRow ? lastRow.checked_at : null,
      lastResult: lastRow ? lastRow.result : null,
    });
  } catch (e) {
    logger.error('auto-update: status failed', { error: e.message });
    return res.status(500).json({ error: 'Failed to read update status' });
  } finally {
    try { db.close(); } catch (e) { /* ignore */ }
  }
});

module.exports = router;
