// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GD Push Configuration Routes
// GET  /api/gd-config       — read current GD push configuration
// PUT  /api/gd-config       — update GD push configuration
// POST /api/gd-config/test  — test the configured connection (dry-run)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Admin-only endpoints for managing this Regional MC's connection to its
// Global Dashboard Server. The configuration is stored as a single-row
// (id=1) record in the gd_push_config table. The api_key field is
// transit-only — it is accepted from the admin via PUT, encrypted
// (Tier-1 AES-256-GCM), stored as base64 text, and never returned in GET
// responses. GET returns api_key_set: true/false instead, so the admin UI
// can show whether a key is configured without ever exposing the plaintext.
//
// Authorization is enforced at the mount level (admin-only) in
// server/index.js. The route handlers themselves don't re-check role.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { encrypt, decrypt } = require('../services/encryption');

const REQUEST_TIMEOUT_MS = 15000;  // shorter timeout for interactive test calls

// ── Helpers ───────────────────────────────────────────────────────────────
function readConfigRow(db) {
  return db.prepare('SELECT * FROM gd_push_config WHERE id = 1').get();
}

function sanitizeForResponse(row) {
  // Omit api_key_encrypted from GET responses; surface a boolean instead so
  // the admin UI can render "API key: configured" or "not set" without ever
  // touching the encrypted blob.
  if (!row) return null;
  return {
    enabled: row.enabled === 1,
    endpoint_url: row.endpoint_url || '',
    api_key_set: !!row.api_key_encrypted,
    push_interval_minutes: row.push_interval_minutes,
    retry_max: row.retry_max,
    retry_backoff_seconds: row.retry_backoff_seconds,
    last_push_at: row.last_push_at,
    last_push_status: row.last_push_status,
    last_push_error: row.last_push_error,
    last_push_duration_ms: row.last_push_duration_ms,
    consecutive_failures: row.consecutive_failures,
    updated_at: row.updated_at,
  };
}

function validateEndpointUrl(value) {
  if (typeof value !== 'string') return { ok: false, error: 'endpoint_url must be a string' };
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, error: 'endpoint_url is required when enabled=true' };
  if (trimmed.length > 2048) return { ok: false, error: 'endpoint_url too long (max 2048)' };
  let parsed;
  try { parsed = new URL(trimmed); }
  catch { return { ok: false, error: 'endpoint_url must be a valid absolute URL' }; }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { ok: false, error: 'endpoint_url must use http:// or https://' };
  }
  return { ok: true, value: parsed.toString() };
}

function validateApiKey(value) {
  if (typeof value !== 'string') return { ok: false, error: 'api_key must be a string' };
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, error: 'api_key is required when setting it' };
  if (trimmed.length < 16) return { ok: false, error: 'api_key looks too short to be valid (min 16)' };
  if (trimmed.length > 512) return { ok: false, error: 'api_key too long (max 512)' };
  return { ok: true, value: trimmed };
}

// ── GET /api/gd-config ────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const db = getDb();
  try {
    const row = readConfigRow(db);
    res.json(sanitizeForResponse(row) || { enabled: false, api_key_set: false });
  } catch (err) {
    logger.error('GD config read error', { error: err.message });
    res.status(500).json({ error: 'Failed to read GD push configuration' });
  } finally {
    db.close();
  }
});

// ── PUT /api/gd-config ────────────────────────────────────────────────────
// Request body fields, all optional except where noted:
//   enabled                  — boolean
//   endpoint_url             — required if enabled=true and not already set
//   api_key                  — plaintext API key from POST /api/mc/register on
//                              the GD-Server. If present, it is encrypted at
//                              rest. Omit to leave the existing key in place.
//   clear_api_key            — boolean; if true, clears the stored key (overrides api_key)
//   push_interval_minutes    — 1-1440
//   retry_max                — 0-10
//   retry_backoff_seconds    — 1-3600
//   reset_failure_counter    — boolean; if true, sets consecutive_failures=0.
//                              Used after the circuit breaker has tripped.
router.put('/', (req, res) => {
  const body = req.body || {};
  const db = getDb();

  try {
    const existing = readConfigRow(db);
    if (!existing) {
      // The schema's INSERT OR IGNORE seed should have run on init, but if for
      // some reason the row is missing (manual DB tampering, partial migration
      // on a very old deploy), recreate it now.
      db.prepare('INSERT OR IGNORE INTO gd_push_config (id, enabled, push_interval_minutes) VALUES (1, 0, 15)').run();
    }
    const current = readConfigRow(db);

    // ── Build the patch ──
    const updates = [];
    const params = [];

    // enabled
    if (body.enabled !== undefined) {
      const v = body.enabled === true || body.enabled === 1 ? 1 : 0;
      updates.push('enabled = ?');
      params.push(v);
    }

    // endpoint_url
    if (body.endpoint_url !== undefined) {
      if (body.endpoint_url === '' || body.endpoint_url === null) {
        // Allow clearing endpoint only if also disabling
        const targetEnabled = body.enabled !== undefined
          ? (body.enabled === true || body.enabled === 1)
          : current.enabled === 1;
        if (targetEnabled) {
          db.close();
          return res.status(400).json({ error: 'Cannot clear endpoint_url while enabled=true' });
        }
        updates.push('endpoint_url = ?');
        params.push(null);
      } else {
        const v = validateEndpointUrl(body.endpoint_url);
        if (!v.ok) { db.close(); return res.status(400).json({ error: v.error }); }
        updates.push('endpoint_url = ?');
        params.push(v.value);
      }
    }

    // api_key — encrypt before storing; clear_api_key takes precedence
    if (body.clear_api_key === true) {
      updates.push('api_key_encrypted = ?');
      params.push(null);
    } else if (body.api_key !== undefined) {
      const v = validateApiKey(body.api_key);
      if (!v.ok) { db.close(); return res.status(400).json({ error: v.error }); }
      let encrypted;
      try {
        encrypted = encrypt(v.value, 'TIER1_ENCRYPTION_KEY').toString('base64');
      } catch (err) {
        logger.error('GD config api_key encryption error', { error: err.message });
        db.close();
        return res.status(500).json({ error: 'Failed to encrypt api_key — check TIER1_ENCRYPTION_KEY env var' });
      }
      updates.push('api_key_encrypted = ?');
      params.push(encrypted);
    }

    // numeric fields with bounds
    if (body.push_interval_minutes !== undefined) {
      const n = parseInt(body.push_interval_minutes, 10);
      if (!Number.isFinite(n) || n < 1 || n > 1440) {
        db.close();
        return res.status(400).json({ error: 'push_interval_minutes must be 1-1440' });
      }
      updates.push('push_interval_minutes = ?');
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

    // reset_failure_counter — used after circuit-breaker auto-disable
    if (body.reset_failure_counter === true) {
      updates.push('consecutive_failures = ?');
      params.push(0);
      updates.push('last_push_status = ?');
      params.push(null);
      updates.push('last_push_error = ?');
      params.push(null);
    }

    // ── Cross-field validation: enabling requires endpoint+key to be set ──
    // Determine the post-update state
    const willBeEnabled = body.enabled !== undefined
      ? (body.enabled === true || body.enabled === 1)
      : current.enabled === 1;
    if (willBeEnabled) {
      const finalEndpoint = body.endpoint_url !== undefined
        ? (body.endpoint_url || null)
        : current.endpoint_url;
      const finalKeyPresent = body.clear_api_key === true
        ? false
        : (body.api_key !== undefined ? true : !!current.api_key_encrypted);
      if (!finalEndpoint) {
        db.close();
        return res.status(400).json({ error: 'Cannot enable without endpoint_url' });
      }
      if (!finalKeyPresent) {
        db.close();
        return res.status(400).json({ error: 'Cannot enable without api_key set' });
      }
    }

    if (updates.length === 0) {
      db.close();
      return res.status(400).json({ error: 'No fields to update' });
    }

    updates.push("updated_at = datetime('now')");
    const sql = `UPDATE gd_push_config SET ${updates.join(', ')} WHERE id = 1`;
    db.prepare(sql).run(...params);

    auditLog(req.user?.id, 'GD_CONFIG_UPDATED',
      `fields=${Object.keys(body).filter(k => body[k] !== undefined).join(',')}`,
      req.ip);

    const updated = readConfigRow(db);
    res.json(sanitizeForResponse(updated));
  } catch (err) {
    logger.error('GD config update error', { error: err.message });
    res.status(500).json({ error: 'Failed to update GD push configuration' });
  } finally {
    db.close();
  }
});

// ── POST /api/gd-config/test ──────────────────────────────────────────────
// Sends a single dry-run ping to the GD-Server using the currently-stored
// configuration. If body contains endpoint_url and/or api_key, those override
// stored values for the test only (the stored config is NOT modified). This
// lets the admin verify a new endpoint+key pair before saving them.
router.post('/test', async (req, res) => {
  const body = req.body || {};
  const db = getDb();
  let row;
  try {
    row = readConfigRow(db);
  } finally {
    db.close();
  }

  // Resolve effective endpoint
  let endpointUrl = row?.endpoint_url || null;
  if (body.endpoint_url !== undefined) {
    const v = validateEndpointUrl(body.endpoint_url);
    if (!v.ok) return res.status(400).json({ error: v.error });
    endpointUrl = v.value;
  }
  if (!endpointUrl) return res.status(400).json({ error: 'No endpoint_url to test (none configured and none provided in request)' });

  // Resolve effective API key
  let apiKey = null;
  if (body.api_key !== undefined) {
    const v = validateApiKey(body.api_key);
    if (!v.ok) return res.status(400).json({ error: v.error });
    apiKey = v.value;
  } else if (row?.api_key_encrypted) {
    try {
      const buffer = Buffer.from(row.api_key_encrypted, 'base64');
      apiKey = decrypt(buffer, 'TIER1_ENCRYPTION_KEY');
    } catch (err) {
      logger.error('GD config test decryption error', { error: err.message });
      return res.status(500).json({ error: 'Failed to decrypt stored api_key — check TIER1_ENCRYPTION_KEY env var' });
    }
  }
  if (!apiKey) return res.status(400).json({ error: 'No api_key to test (none configured and none provided in request)' });

  // Send a minimal dry-run payload. The GD-Server's /api/ingest/metrics
  // accepts whatever metrics shape we send; for a connectivity test we use
  // a sentinel payload that won't affect normal operations on the GD side
  // (the GD-Server will record an INGEST event and store one row of test
  // values in regional_metrics — operationally inert).
  const url = endpointUrl.replace(/\/+$/, '') + '/api/ingest/metrics';
  const testBody = {
    apiKey,
    metrics: {
      healthScore: 0,
      utilization: 0,
      automationRate: 0,
      certCoverage: 0,
      slaCompliance: 0,
      turnoverRisk: 'low',
      analystCount: 0,
      activeIncidents: 0,
      burnoutRoutingActive: false,
      proactiveBreaksGiven: 0,
      upskillingHoursUsed: 0,
    },
  };

  const startedAt = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(testBody),
      signal: controller.signal,
    });
    const durationMs = Date.now() - startedAt;
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      auditLog(req.user?.id, 'GD_CONFIG_TEST_FAILURE',
        `status=${response.status} duration=${durationMs}ms`, req.ip);
      return res.status(200).json({
        ok: false,
        status: response.status,
        durationMs,
        error: text.slice(0, 500) || `HTTP ${response.status}`,
      });
    }
    const responseBody = await response.json().catch(() => ({}));
    auditLog(req.user?.id, 'GD_CONFIG_TEST_SUCCESS', `duration=${durationMs}ms`, req.ip);
    return res.json({ ok: true, status: response.status, durationMs, response: responseBody });
  } catch (err) {
    const durationMs = Date.now() - startedAt;
    const isAbort = err.name === 'AbortError';
    auditLog(req.user?.id, 'GD_CONFIG_TEST_FAILURE',
      `error=${isAbort ? 'timeout' : err.message} duration=${durationMs}ms`, req.ip);
    return res.status(200).json({
      ok: false,
      durationMs,
      error: isAbort ? `Request timed out after ${REQUEST_TIMEOUT_MS}ms` : err.message,
    });
  } finally {
    clearTimeout(timeout);
  }
});

module.exports = router;
