// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — HR Scheduling Platform Configuration Routes
//
// GET  /api/scheduling/config     — read current platform config (creds masked)
// PUT  /api/scheduling/config     — update platform config (creds encrypted)
// POST /api/scheduling/test       — test saved config (configure-then-test)
// POST /api/scheduling/sync       — trigger an immediate sync (202 Accepted)
// POST /api/scheduling/save-all   — bulk save per-analyst availability (manual override)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Lead/admin-only endpoints for managing this MC's HR scheduling platform
// integration. Authorization is enforced at the mount level
// (authMiddleware(['admin', 'lead'])) in server/index.js. The route handlers
// themselves don't re-check role.
//
// The configuration is stored as a single-row (id=1) record in the
// scheduling_platform_config table. The credentials_encrypted field is
// transit-only — accepted from the lead via PUT as a structured
// per-platform JSON object, encrypted (Tier-1 AES-256-GCM), stored as
// base64 text, and never returned in GET responses. GET returns
// credentials_set: true/false instead.
//
// Configure-then-test pattern: POST /test reads the SAVED config from the
// DB (set previously via PUT) and uses it to call the adapter. The
// request body is ignored. This prevents SSRF via the test endpoint —
// the URL passed to fetch always comes from a row whose hostname was
// validated against HR_ALLOWED_HOSTS at write time, defense in depth
// re-validated at test time.
//
// Per-platform credential shapes (the route validates these on PUT):
//
//   ukg_kronos: {tenantUrl, clientId, clientSecret, username, password,
//                apiKey?}
//   workday:    {tenantUrl, clientId, clientSecret, refreshToken}
//   adp:        {clientId, clientSecret?, certPem, certKeyPem}
//   bamboohr:   {subdomain, apiKey}
//   manual:     null (no credentials)
//
// ANONYMITY: This route operates exclusively on user_id (UUID) and never
// touches users.email or any direct-identity field. The /save-all
// endpoint accepts schedules keyed by userId; it does NOT accept email
// or username and does not surface those fields in responses. The lead's
// MC view should display pseudonyms (or usernames where role-appropriate),
// translating to user_id internally for these calls. See ANONYMITY MODEL
// note in db/init.js for the full contract.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { sealTier1, openTier1 } = require('../services/tier1-seal');
const { validateAllowedHost } = require('../services/hr-allow-list');
const { schedulingSyncService } = require('../services/scheduling-sync');

const ADAPTERS = {
  ukg_kronos: require('../services/scheduling-platforms/ukg-kronos'),
  workday:    require('../services/scheduling-platforms/workday'),
  adp:        require('../services/scheduling-platforms/adp'),
  bamboohr:   require('../services/scheduling-platforms/bamboohr'),
  manual:     require('../services/scheduling-platforms/manual'),
};

const VALID_PLATFORMS = Object.keys(ADAPTERS);
const VALID_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
const TIME_REGEX = /^\d{2}:\d{2}$/;
const ISO_DATE_REGEX = /^\d{4}-\d{2}-\d{2}$/;
const REQUEST_TIMEOUT_MS = 30000;

// ── Helpers ───────────────────────────────────────────────────────────────

function readConfigRow(db) {
  return db.prepare('SELECT * FROM scheduling_platform_config WHERE id = 1').get();
}

function sanitizeForResponse(row) {
  if (!row) return null;
  return {
    enabled: row.enabled === 1,
    platform: row.platform || null,
    endpoint_url: row.endpoint_url || '',
    credentials_set: !!row.credentials_encrypted,
    sync_interval_minutes: row.sync_interval_minutes,
    retry_max: row.retry_max,
    retry_backoff_seconds: row.retry_backoff_seconds,
    last_sync_at: row.last_sync_at,
    last_sync_status: row.last_sync_status,
    last_sync_error: row.last_sync_error,
    last_sync_duration_ms: row.last_sync_duration_ms,
    consecutive_failures: row.consecutive_failures,
    updated_at: row.updated_at,
  };
}

/**
 * Validate the endpoint_url string and check the hostname against
 * HR_ALLOWED_HOSTS. Manual mode has no endpoint URL so this returns
 * ok with value=null when platform is 'manual' or url is empty/null.
 */
function validateEndpointUrl(value, platform) {
  if (platform === 'manual') {
    return { ok: true, value: null };
  }
  if (typeof value !== 'string') {
    return { ok: false, error: 'endpoint_url must be a string' };
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return { ok: false, error: 'endpoint_url is required for non-manual platforms' };
  }
  if (trimmed.length > 2048) {
    return { ok: false, error: 'endpoint_url too long (max 2048)' };
  }
  let parsed;
  try { parsed = new URL(trimmed); }
  catch { return { ok: false, error: 'endpoint_url must be a valid absolute URL' }; }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'endpoint_url must use http:// or https://' };
  }
  const allowed = validateAllowedHost(parsed.hostname);
  if (!allowed.ok) return { ok: false, error: allowed.error };
  return { ok: true, value: parsed.toString() };
}

/**
 * Validate per-platform credential shape. Returns
 * {ok: true, value: object} on success or {ok: false, error: string}.
 * Manual mode returns ok with value=null (no credentials needed).
 *
 * The shape rules are deliberately strict — extra fields are stripped,
 * missing required fields error out. This prevents the lead from
 * accidentally storing fields that don't reach the adapter.
 */
function validateCredentials(platform, creds) {
  if (platform === 'manual') {
    return { ok: true, value: null };
  }
  if (creds === null || creds === undefined) {
    return { ok: false, error: 'credentials object is required for non-manual platforms' };
  }
  if (typeof creds !== 'object' || Array.isArray(creds)) {
    return { ok: false, error: 'credentials must be a JSON object' };
  }

  const required = {
    ukg_kronos: ['tenantUrl', 'clientId', 'clientSecret', 'username', 'password'],
    workday:    ['tenantUrl', 'clientId', 'clientSecret', 'refreshToken'],
    adp:        ['clientId', 'certPem', 'certKeyPem'],
    bamboohr:   ['subdomain', 'apiKey'],
  };
  const optional = {
    ukg_kronos: ['apiKey'],
    workday:    [],
    adp:        ['clientSecret'],
    bamboohr:   [],
  };

  const reqList = required[platform];
  if (!reqList) {
    return { ok: false, error: `Unknown platform: ${platform}` };
  }
  const missing = reqList.filter(k => typeof creds[k] !== 'string' || creds[k].trim() === '');
  if (missing.length > 0) {
    return { ok: false, error: `${platform} credentials missing required fields: ${missing.join(', ')}` };
  }

  // Build the sanitized credentials object — required keys plus any
  // optional keys that were provided. Extra/unrecognized keys are
  // silently dropped.
  const out = {};
  for (const k of reqList) out[k] = creds[k].trim();
  for (const k of (optional[platform] || [])) {
    if (typeof creds[k] === 'string' && creds[k].trim()) out[k] = creds[k].trim();
  }

  // Per-platform sanity checks beyond field presence.
  if (platform === 'workday' || platform === 'ukg_kronos') {
    if (!/^https?:\/\//.test(out.tenantUrl)) {
      return { ok: false, error: 'tenantUrl must be a full http(s):// URL' };
    }
    let parsed;
    try { parsed = new URL(out.tenantUrl); }
    catch { return { ok: false, error: 'tenantUrl is not a valid URL' }; }
    const allowed = validateAllowedHost(parsed.hostname);
    if (!allowed.ok) return { ok: false, error: `tenantUrl rejected: ${allowed.error}` };
  }
  if (platform === 'adp') {
    if (!/-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----/.test(out.certPem)) {
      return { ok: false, error: 'certPem does not look like a PEM-encoded certificate' };
    }
    if (!/-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----/.test(out.certKeyPem)) {
      return { ok: false, error: 'certKeyPem does not look like a PEM-encoded private key' };
    }
  }

  return { ok: true, value: out };
}

/**
 * Validate a slots map: an object whose keys are day-of-week names and
 * whose values are arrays of {start, end} intervals. Times are HH:MM
 * 24-hour. Empty array per day = unavailable that day. Missing day key
 * also = unavailable that day.
 */
function validateSlotsObject(slots) {
  if (slots === null || slots === undefined) return { ok: true, value: {} };
  if (typeof slots !== 'object' || Array.isArray(slots)) {
    return { ok: false, error: 'slots must be an object keyed by day-of-week' };
  }
  const out = {};
  for (const [day, intervals] of Object.entries(slots)) {
    if (!VALID_DAYS.includes(day)) {
      return { ok: false, error: `slots key '${day}' is not a valid day-of-week` };
    }
    if (!Array.isArray(intervals)) {
      return { ok: false, error: `slots.${day} must be an array of intervals` };
    }
    out[day] = [];
    for (const interval of intervals) {
      if (!interval || typeof interval !== 'object') {
        return { ok: false, error: `slots.${day} contains a non-object entry` };
      }
      if (!TIME_REGEX.test(interval.start) || !TIME_REGEX.test(interval.end)) {
        return { ok: false, error: `slots.${day} entries require start and end as HH:MM strings` };
      }
      if (interval.start >= interval.end) {
        return { ok: false, error: `slots.${day} interval start must be before end (${interval.start}-${interval.end})` };
      }
      out[day].push({ start: interval.start, end: interval.end });
    }
  }
  return { ok: true, value: out };
}

// ── GET /api/scheduling/config ────────────────────────────────────────────
router.get('/config', (req, res) => {
  const db = getDb();
  try {
    const row = readConfigRow(db);
    res.json(sanitizeForResponse(row) || { enabled: false, credentials_set: false });
  } catch (err) {
    logger.error('Scheduling config read error', { error: err.message });
    res.status(500).json({ error: 'Failed to read scheduling platform configuration' });
  } finally {
    db.close();
  }
});

// ── PUT /api/scheduling/config ────────────────────────────────────────────
// Body fields, all optional except where noted:
//   enabled                  — boolean
//   platform                 — one of: ukg_kronos, workday, adp, bamboohr, manual
//   endpoint_url             — required for non-manual when enabling
//   credentials              — per-platform JSON object (encrypted at rest)
//   clear_credentials        — boolean; if true, clears stored credentials
//   sync_interval_minutes    — 5-1440
//   retry_max                — 0-10
//   retry_backoff_seconds    — 1-3600
//   reset_failure_counter    — boolean; resets consecutive_failures=0
router.put('/config', (req, res) => {
  const body = req.body || {};
  const db = getDb();
  try {
    let current = readConfigRow(db);
    if (!current) {
      db.prepare('INSERT OR IGNORE INTO scheduling_platform_config (id, enabled, sync_interval_minutes) VALUES (1, 0, 60)').run();
      current = readConfigRow(db);
    }

    // Determine the effective platform after this PUT (used for
    // validating endpoint_url and credentials in their respective shapes).
    const effectivePlatform = body.platform !== undefined ? body.platform : current.platform;
    if (body.platform !== undefined && !VALID_PLATFORMS.includes(body.platform)) {
      db.close();
      return res.status(400).json({ error: `platform must be one of: ${VALID_PLATFORMS.join(', ')}` });
    }

    const updates = [];
    const params = [];

    if (body.enabled !== undefined) {
      updates.push('enabled = ?');
      params.push(body.enabled === true || body.enabled === 1 ? 1 : 0);
    }
    if (body.platform !== undefined) {
      updates.push('platform = ?');
      params.push(body.platform);
    }
    if (body.endpoint_url !== undefined) {
      if (body.endpoint_url === '' || body.endpoint_url === null) {
        // Allow clearing only if also disabling or using manual platform
        const willBeEnabled = body.enabled !== undefined
          ? (body.enabled === true || body.enabled === 1)
          : current.enabled === 1;
        const willBeManual = effectivePlatform === 'manual';
        if (willBeEnabled && !willBeManual) {
          db.close();
          return res.status(400).json({ error: 'Cannot clear endpoint_url while enabled=true on a non-manual platform' });
        }
        updates.push('endpoint_url = ?');
        params.push(null);
      } else {
        const v = validateEndpointUrl(body.endpoint_url, effectivePlatform || 'manual');
        if (!v.ok) { db.close(); return res.status(400).json({ error: v.error }); }
        updates.push('endpoint_url = ?');
        params.push(v.value);
      }
    }

    // credentials — encrypt before storing; clear_credentials takes precedence
    if (body.clear_credentials === true) {
      updates.push('credentials_encrypted = ?');
      params.push(null);
    } else if (body.credentials !== undefined) {
      if (!effectivePlatform) {
        db.close();
        return res.status(400).json({ error: 'platform must be set before configuring credentials' });
      }
      const v = validateCredentials(effectivePlatform, body.credentials);
      if (!v.ok) { db.close(); return res.status(400).json({ error: v.error }); }
      if (v.value === null) {
        // Manual mode — store NULL credentials
        updates.push('credentials_encrypted = ?');
        params.push(null);
      } else {
        let encrypted;
        try {
          encrypted = sealTier1('scheduling_platform_config.credentials_encrypted', v.value);
        } catch (err) {
          logger.error('Scheduling config credentials encryption error', { error: err.message });
          db.close();
          return res.status(500).json({ error: 'Failed to encrypt credentials — check TIER1_ENCRYPTION_KEY env var' });
        }
        updates.push('credentials_encrypted = ?');
        params.push(encrypted);
      }
    }

    // numeric bounds
    if (body.sync_interval_minutes !== undefined) {
      const n = parseInt(body.sync_interval_minutes, 10);
      if (!Number.isFinite(n) || n < 5 || n > 1440) {
        db.close();
        return res.status(400).json({ error: 'sync_interval_minutes must be 5-1440' });
      }
      updates.push('sync_interval_minutes = ?');
      params.push(n);
    }
    if (body.retry_max !== undefined) {
      const n = parseInt(body.retry_max, 10);
      if (!Number.isFinite(n) || n < 0 || n > 10) {
        db.close();
        return res.status(400).json({ error: 'retry_max must be 0-10' });
      }
      updates.push('retry_max = ?');
      params.push(n);
    }
    if (body.retry_backoff_seconds !== undefined) {
      const n = parseInt(body.retry_backoff_seconds, 10);
      if (!Number.isFinite(n) || n < 1 || n > 3600) {
        db.close();
        return res.status(400).json({ error: 'retry_backoff_seconds must be 1-3600' });
      }
      updates.push('retry_backoff_seconds = ?');
      params.push(n);
    }

    if (body.reset_failure_counter === true) {
      updates.push('consecutive_failures = ?');
      params.push(0);
      updates.push('last_sync_status = ?');
      params.push(null);
      updates.push('last_sync_error = ?');
      params.push(null);
    }

    // Cross-field validation: enabling requires platform + endpoint (unless manual) + credentials (unless manual)
    const willBeEnabled = body.enabled !== undefined
      ? (body.enabled === true || body.enabled === 1)
      : current.enabled === 1;
    if (willBeEnabled) {
      const finalPlatform = body.platform !== undefined ? body.platform : current.platform;
      if (!finalPlatform) {
        db.close();
        return res.status(400).json({ error: 'Cannot enable without platform set' });
      }
      const finalEndpoint = body.endpoint_url !== undefined ? body.endpoint_url : current.endpoint_url;
      if (finalPlatform !== 'manual' && !finalEndpoint) {
        db.close();
        return res.status(400).json({ error: `Cannot enable ${finalPlatform} without endpoint_url` });
      }
      const finalCredsPresent = body.clear_credentials === true
        ? false
        : (body.credentials !== undefined ? true : !!current.credentials_encrypted);
      if (finalPlatform !== 'manual' && !finalCredsPresent) {
        db.close();
        return res.status(400).json({ error: `Cannot enable ${finalPlatform} without credentials set` });
      }
    }

    if (updates.length === 0) {
      db.close();
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push("updated_at = datetime('now')");
    db.prepare(`UPDATE scheduling_platform_config SET ${updates.join(', ')} WHERE id = 1`).run(...params);

    auditLog(req.user?.id, 'SCHEDULING_CONFIG_UPDATED',
      `fields=${Object.keys(body).filter(k => body[k] !== undefined).join(',')}`,
      req.ip);

    const updated = readConfigRow(db);
    res.json(sanitizeForResponse(updated));
  } catch (err) {
    logger.error('Scheduling config update error', { error: err.message });
    res.status(500).json({ error: 'Failed to update scheduling platform configuration' });
  } finally {
    db.close();
  }
});

// ── POST /api/scheduling/test ─────────────────────────────────────────────
// Runs adapter.pullAvailability against the SAVED configuration as a
// connectivity check. Body is ignored (configure-then-test). Result is
// not written to analyst_availability — that only happens in /sync.
router.post('/test', async (req, res) => {
  const db = getDb();
  let row;
  try {
    row = readConfigRow(db);
  } finally {
    db.close();
  }

  if (!row || !row.platform) {
    return res.status(400).json({ error: 'No platform configured. Set one via PUT /api/scheduling/config first.' });
  }
  const platform = row.platform;
  if (platform === 'manual') {
    auditLog(req.user?.id, 'SCHEDULING_TEST_SUCCESS', 'platform=manual (no external system to test)', req.ip);
    return res.json({ ok: true, platform: 'manual', note: 'Manual mode has no external system to test' });
  }
  if (!row.endpoint_url) {
    return res.status(400).json({ error: 'No endpoint_url configured. Set one via PUT /api/scheduling/config first.' });
  }
  if (!row.credentials_encrypted) {
    return res.status(400).json({ error: 'No credentials configured. Set them via PUT /api/scheduling/config first.' });
  }

  // Defense in depth: re-validate the stored URL hostname at test time.
  let parsedUrl;
  try { parsedUrl = new URL(row.endpoint_url); }
  catch (err) { return res.status(400).json({ error: 'Stored endpoint_url is invalid: ' + err.message }); }
  const allowed = validateAllowedHost(parsedUrl.hostname);
  if (!allowed.ok) {
    auditLog(req.user?.id, 'SCHEDULING_TEST_BLOCKED',
      `Allow-list rejected stored URL hostname ${parsedUrl.hostname}`, req.ip);
    return res.status(400).json({ error: allowed.error });
  }

  // Decrypt credentials.
  let credentials;
  try {
    credentials = openTier1('scheduling_platform_config.credentials_encrypted', row.credentials_encrypted);
  } catch (err) {
    logger.error('Scheduling test credentials decryption error', { error: err.message });
    return res.status(500).json({ error: 'Failed to decrypt stored credentials — check TIER1_ENCRYPTION_KEY env var' });
  }

  const adapter = ADAPTERS[platform];
  if (!adapter) {
    return res.status(500).json({ error: `Adapter for platform '${platform}' not loaded — server bug` });
  }

  const adapterDb = getDb();
  const adapterCtx = {
    db: adapterDb,
    log: (level, msg, meta = {}) => {
      const fn = logger[level] || logger.info;
      fn.call(logger, msg, { platform, test: true, ...meta });
    },
    config: { endpoint_url: row.endpoint_url, credentials },
  };
  const startedAt = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    // The adapter's pullAvailability is naturally idempotent for reads.
    // We don't write the result anywhere; we just measure success and
    // surface the analyst count to the lead.
    const result = await adapter.pullAvailability(adapterCtx);
    const durationMs = Date.now() - startedAt;
    const analystsReturned = (result && Array.isArray(result.analysts)) ? result.analysts.length : 0;
    auditLog(req.user?.id, 'SCHEDULING_TEST_SUCCESS',
      `platform=${platform} duration=${durationMs}ms analystsReturned=${analystsReturned}`, req.ip);
    return res.json({ ok: true, platform, durationMs, analystsReturned });
  } catch (err) {
    const durationMs = Date.now() - startedAt;
    const isAbort = err.name === 'AbortError';
    auditLog(req.user?.id, 'SCHEDULING_TEST_FAILURE',
      `platform=${platform} error=${isAbort ? 'timeout' : err.message} duration=${durationMs}ms`, req.ip);
    return res.status(200).json({
      ok: false,
      platform,
      durationMs,
      error: isAbort ? `Test timed out after ${REQUEST_TIMEOUT_MS}ms` : err.message,
    });
  } finally {
    clearTimeout(timer);
    try { adapterDb.close(); } catch { /* best-effort */ }
  }
});

// ── POST /api/scheduling/sync ─────────────────────────────────────────────
// Triggers an immediate sync via schedulingSyncService.triggerSync().
// Returns 202 Accepted; the actual sync runs asynchronously and the UI
// polls GET /api/scheduling/config for last_sync_at to see completion.
router.post('/sync', (req, res) => {
  const db = getDb();
  let row;
  try {
    row = readConfigRow(db);
  } finally {
    db.close();
  }
  if (!row || row.enabled !== 1) {
    return res.status(400).json({ error: 'Sync is not enabled. Enable via PUT /api/scheduling/config first.' });
  }
  const result = schedulingSyncService.triggerSync();
  if (!result.ok) {
    auditLog(req.user?.id, 'SCHEDULING_SYNC_TRIGGER_REJECTED', result.error || 'unknown', req.ip);
    return res.status(503).json({ error: result.error });
  }
  auditLog(req.user?.id, 'SCHEDULING_SYNC_TRIGGERED',
    result.alreadyRunning ? 'already-running' : 'queued-immediate', req.ip);
  return res.status(202).json({
    ok: true,
    alreadyRunning: result.alreadyRunning,
    note: result.alreadyRunning
      ? 'A sync is already in progress; result will appear on completion.'
      : 'Sync queued to run immediately. Poll GET /api/scheduling/config for last_sync_at to see completion.',
  });
});

// ── POST /api/scheduling/save-all ─────────────────────────────────────────
// Bulk save per-analyst availability. Used by the lead's "Save All" button
// in the MC Per-Analyst Scheduling card (manual mode + manual override of
// platform-synced rows). Body shape:
//
//   { schedules: [{ userId, weekStart, slots }, ...] }
//
// Each entry is validated and upserted into analyst_availability with
// source_platform='manual'. The sync service's automated rows for the
// same (userId, weekStart) will be replaced — manual override takes
// effect immediately.
//
// ANONYMITY: schedules entries reference userId (UUID), not email or
// username. The MC frontend translates pseudonym/username display to
// userId at request build time.
router.post('/save-all', (req, res) => {
  const body = req.body || {};
  if (!Array.isArray(body.schedules)) {
    return res.status(400).json({ error: 'schedules must be an array' });
  }
  if (body.schedules.length === 0) {
    return res.status(400).json({ error: 'schedules is empty — nothing to save' });
  }
  if (body.schedules.length > 1000) {
    return res.status(400).json({ error: 'schedules too large (max 1000 per request)' });
  }

  // Validate every entry up front so a partial save can't happen.
  const prepared = [];
  for (let i = 0; i < body.schedules.length; i++) {
    const e = body.schedules[i];
    if (!e || typeof e !== 'object') {
      return res.status(400).json({ error: `schedules[${i}] is not an object` });
    }
    if (typeof e.userId !== 'string' || !e.userId.trim()) {
      return res.status(400).json({ error: `schedules[${i}].userId is required` });
    }
    if (typeof e.weekStart !== 'string' || !ISO_DATE_REGEX.test(e.weekStart)) {
      return res.status(400).json({ error: `schedules[${i}].weekStart must be YYYY-MM-DD` });
    }
    // weekStart should be a Monday — verify
    const d = new Date(`${e.weekStart}T00:00:00Z`);
    if (isNaN(d.getTime())) {
      return res.status(400).json({ error: `schedules[${i}].weekStart is not a valid date` });
    }
    if (d.getUTCDay() !== 1) {
      return res.status(400).json({ error: `schedules[${i}].weekStart must be a Monday (got day-of-week ${d.getUTCDay()})` });
    }
    const v = validateSlotsObject(e.slots);
    if (!v.ok) {
      return res.status(400).json({ error: `schedules[${i}].${v.error}` });
    }
    prepared.push({ userId: e.userId.trim(), weekStart: e.weekStart, slotsJson: JSON.stringify(v.value) });
  }

  const db = getDb();
  let writtenCount = 0;
  let unknownUserCount = 0;
  try {
    // Verify each userId exists in users (FK enforces it but we want a
    // clean error message instead of a SQLITE_CONSTRAINT_FOREIGNKEY).
    const userExistsStmt = db.prepare('SELECT 1 FROM users WHERE id = ? LIMIT 1');
    const upsertStmt = db.prepare(`
      INSERT INTO analyst_availability (user_id, week_start, slots_json, source_platform, last_synced_at, created_at, updated_at)
      VALUES (?, ?, ?, 'manual', datetime('now'), datetime('now'), datetime('now'))
      ON CONFLICT (user_id, week_start) DO UPDATE SET
        slots_json = excluded.slots_json,
        source_platform = 'manual',
        last_synced_at = datetime('now'),
        updated_at = datetime('now')
    `);
    const txn = db.transaction((rows) => {
      for (const row of rows) {
        const exists = userExistsStmt.get(row.userId);
        if (!exists) { unknownUserCount++; continue; }
        upsertStmt.run(row.userId, row.weekStart, row.slotsJson);
        writtenCount++;
      }
    });
    txn(prepared);

    auditLog(req.user?.id, 'SCHEDULING_SAVE_ALL',
      `written=${writtenCount} unknownUsers=${unknownUserCount} requested=${prepared.length}`, req.ip);

    return res.json({
      ok: true,
      written: writtenCount,
      unknownUsers: unknownUserCount,
      requested: prepared.length,
    });
  } catch (err) {
    logger.error('Scheduling save-all error', { error: err.message });
    return res.status(500).json({ error: 'Failed to save schedules' });
  } finally {
    db.close();
  }
});

module.exports = router;
