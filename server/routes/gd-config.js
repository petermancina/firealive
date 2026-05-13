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
const dns = require('dns').promises;
const net = require('net');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { auditLog } = require('../middleware/audit');
const { encrypt, decrypt } = require('../services/encryption');
const { validateAllowedHost } = require('../services/gd-allow-list');

const REQUEST_TIMEOUT_MS = 15000;  // shorter timeout for interactive test calls

// ── Helpers ───────────────────────────────────────────────────────────────
function readConfigRow(db) {
  return db.prepare('SELECT * FROM gd_push_config WHERE id = 1').get();
}

// ── SSRF protection ───────────────────────────────────────────────────────
// The POST /test handler accepts a destination URL from the admin and makes
// an outbound HTTP request to it. Without these guards an admin could be
// tricked (or maliciously configured) into pointing the test at sensitive
// internal-only addresses — most notably the cloud metadata service at
// 169.254.169.254 which on AWS/Azure/GCP exposes IAM credentials and
// instance metadata via unauthenticated GET. CodeQL js/request-forgery
// (alert #334) flagged this correctly.
//
// We deliberately do NOT block RFC 1918 ranges (10/8, 172.16/12, 192.168/16)
// because legitimate corporate GD-Server deployments commonly live on
// internal corporate networks. Blocking them would make the feature
// unusable for the typical customer. What we block is the smaller set of
// addresses where "I want to ping 169.254.169.254" or "I want to ping
// localhost:6379" is almost certainly an attempt to exfiltrate or pivot.
//
// We resolve the hostname via DNS lookup so this works even if the URL
// uses a hostname that resolves to a dangerous IP (DNS rebinding aside —
// see TOCTOU note in handler). For URLs that already use a literal IP
// the hostname check applies directly without a DNS round trip.

function isDangerousIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  // 0.0.0.0/8 — "this network" (RFC 1122)
  if (a === 0) return true;
  // 127.0.0.0/8 — loopback (RFC 1122)
  if (a === 127) return true;
  // 169.254.0.0/16 — link-local; includes AWS/Azure/GCP cloud metadata at
  // 169.254.169.254 which serves IAM credentials over unauthenticated HTTP
  if (a === 169 && b === 254) return true;
  return false;
}

function isDangerousIPv6(ip) {
  const lower = ip.toLowerCase();
  // Loopback ::1
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  // Unspecified ::
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return true;
  // Link-local fe80::/10 (covers fe80:: through febf::)
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
  // IPv4-mapped IPv6 ::ffff:127.0.0.1 — extract the embedded IPv4 and
  // recurse so e.g. ::ffff:169.254.169.254 is also caught
  const v4mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4mapped) return isDangerousIPv4(v4mapped[1]);
  return false;
}

async function validateHostnameSafety(hostname) {
  // If the URL host is already a literal IP, check it directly without DNS.
  if (net.isIP(hostname)) {
    if (net.isIPv4(hostname) && isDangerousIPv4(hostname)) {
      return { ok: false, error: `Refusing to send to ${hostname} — loopback, "this network", or link-local addresses (including cloud metadata services) are not allowed for security reasons.` };
    }
    if (net.isIPv6(hostname) && isDangerousIPv6(hostname)) {
      return { ok: false, error: `Refusing to send to ${hostname} — loopback or link-local addresses are not allowed for security reasons.` };
    }
    return { ok: true };
  }
  // Otherwise resolve via DNS and check every returned address.
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    for (const { address, family } of addresses) {
      if (family === 4 && isDangerousIPv4(address)) {
        return { ok: false, error: `Refusing to send to ${hostname} (resolves to ${address}) — loopback, "this network", or link-local addresses (including cloud metadata services) are not allowed for security reasons.` };
      }
      if (family === 6 && isDangerousIPv6(address)) {
        return { ok: false, error: `Refusing to send to ${hostname} (resolves to ${address}) — loopback or link-local addresses are not allowed for security reasons.` };
      }
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: `Could not resolve ${hostname}: ${err.message}` };
  }
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
    // R3g PR3 Phase 5 (C24): expose mc_id so the operator UI can show
    // "GD knows this MC as: <mc_id>" and surface configuration errors
    // visibly. Not sensitive — mc_id is a public identifier on the GD
    // side (visible to any CISO browsing the management consoles list).
    mc_id: row.mc_id || '',
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
  // Allow-list check. Hostnames must be in GD_ALLOWED_HOSTS env var. This
  // is the primary SSRF defense and breaks the user-input -> fetch
  // dataflow that triggered CodeQL js/request-forgery (alert #334).
  // The check runs at write time (PUT /api/gd-config) so a bad URL never
  // reaches the database in the first place.
  const allowed = validateAllowedHost(parsed.hostname);
  if (!allowed.ok) return { ok: false, error: allowed.error };
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

// R3g PR3 Phase 5 (C24): mc_id is the identifier the GD assigned to this MC
// at /api/mc/register time. Used to construct the path-bound URL
// /api/mc/<mc_id>/signing-key when the MC submits a key (the GD's C18
// endpoint requires both api_key in the body AND :id in the path to match
// a single MC, so the MC has to know its own GD-side id).
//
// The current GD generates these as crypto.randomBytes(4).toString('hex')
// (8 lowercase hex chars), but operators running modified GDs or custom
// deployments may use UUIDs or other formats. The validator is permissive
// enough to accept the default 8-hex shape PLUS UUIDs PLUS other reasonable
// ASCII-safe identifiers; rejects clear garbage (whitespace, control
// characters, oversize input).
//
// Length cap 128 is generous — UUIDs are 36, GD-generated ids are 8;
// anything longer is almost certainly a misconfiguration.
function validateMcId(value) {
  if (typeof value !== 'string') return { ok: false, error: 'mc_id must be a string' };
  const trimmed = value.trim();
  if (!trimmed) return { ok: false, error: 'mc_id cannot be empty' };
  if (trimmed.length > 128) return { ok: false, error: 'mc_id too long (max 128)' };
  // ASCII-safe: alphanumerics, hyphens, underscores. Covers hex,
  // UUIDs (with hyphens), and most identifier conventions.
  if (!/^[A-Za-z0-9_-]+$/.test(trimmed)) {
    return { ok: false, error: 'mc_id must contain only letters, digits, hyphens, and underscores' };
  }
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
//                              Setting api_key requires a paired mc_id (either
//                              in this same PUT or already stored).
//   mc_id                    — the GD-side identifier for this MC, returned
//                              by /api/mc/register alongside the api_key.
//                              ASCII-safe (letters, digits, hyphens,
//                              underscores), max 128 chars. R3g PR3 Phase 5.
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

    // mc_id — R3g PR3 Phase 5 (C24). The GD-side identifier the MC submits
    // its signing key under. Validated independently here; the cross-field
    // rule that an api_key change requires a paired mc_id is enforced below.
    if (body.mc_id !== undefined) {
      if (body.mc_id === '' || body.mc_id === null) {
        // Allow clearing only if no api_key is set on the post-update state.
        // If api_key remains set without mc_id, the MC can't construct the
        // path-bound submission URL and the trust handshake is unworkable.
        const willKeyBeSet = body.clear_api_key === true
          ? false
          : (body.api_key !== undefined ? true : !!current.api_key_encrypted);
        if (willKeyBeSet) {
          db.close();
          return res.status(400).json({ error: 'Cannot clear mc_id while api_key is set; clear api_key first or set a new mc_id' });
        }
        updates.push('mc_id = ?');
        params.push(null);
      } else {
        const v = validateMcId(body.mc_id);
        if (!v.ok) { db.close(); return res.status(400).json({ error: v.error }); }
        updates.push('mc_id = ?');
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

    // ── Cross-field: setting api_key requires a paired mc_id (R3g PR3 Phase 5)
    //
    // Without mc_id, the MC cannot construct the path-bound URL
    // /api/mc/<mc_id>/signing-key required by the GD's C18 endpoint to
    // submit a public key. Accepting an api_key change without mc_id would
    // leave the MC in a state where it has credentials but cannot do
    // anything with them — the next handshake attempt would fail with a
    // routing error.
    //
    // The mc_id can come from either:
    //   - This same PUT body (body.mc_id is a non-empty string), OR
    //   - The currently-stored row (current.mc_id is non-empty)
    //
    // Reject only when api_key is being set AND no mc_id is available
    // through either source.
    const apiKeyBeingSet = body.api_key !== undefined && body.clear_api_key !== true;
    if (apiKeyBeingSet) {
      const finalMcId = body.mc_id !== undefined
        ? (body.mc_id || null)
        : current.mc_id;
      if (!finalMcId) {
        db.close();
        return res.status(400).json({
          error: 'mc_id is required when setting api_key — provide it alongside the api_key from /api/mc/register, or set mc_id first'
        });
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
// Sends a single dry-run ping to the GD-Server using the CURRENTLY-STORED
// configuration. The endpoint_url and api_key are read from the database
// (set previously via PUT /api/gd-config) — the request body is ignored.
//
// This deliberately does NOT accept a URL or key override in the body.
// Earlier versions did, which let an admin "test before save" but also
// exposed a CodeQL js/request-forgery (alert #334) — user-input flowing
// directly into fetch(url). The current pattern is configure-then-test:
//
//   1. Admin PUTs the URL+key (with enabled=false) — the URL's hostname
//      is checked against GD_ALLOWED_HOSTS at write time
//   2. Admin POSTs to /test with no body — server reads the stored row
//      and tests
//   3. If test passes, admin PUTs again with enabled=true to activate
//      the recurring push
//
// Saving with enabled=false is harmless (the push service skips disabled
// rows), so there's no risk in saving an unverified URL+key — the
// allow-list at write time guarantees the URL points at a pre-approved
// destination, and the API key is encrypted at rest (Tier-1 AES-256-GCM).
router.post('/test', async (req, res) => {
  const db = getDb();
  let row;
  try {
    row = readConfigRow(db);
  } finally {
    db.close();
  }

  // Resolve endpoint and key from stored config only — no body override.
  const endpointUrl = row?.endpoint_url || null;
  if (!endpointUrl) {
    return res.status(400).json({ error: 'No endpoint_url configured. Set one via PUT /api/gd-config first.' });
  }

  if (!row?.api_key_encrypted) {
    return res.status(400).json({ error: 'No api_key configured. Set one via PUT /api/gd-config first.' });
  }
  let apiKey;
  try {
    const buffer = Buffer.from(row.api_key_encrypted, 'base64');
    apiKey = decrypt(buffer, 'TIER1_ENCRYPTION_KEY');
  } catch (err) {
    logger.error('GD config test decryption error', { error: err.message });
    return res.status(500).json({ error: 'Failed to decrypt stored api_key — check TIER1_ENCRYPTION_KEY env var' });
  }

  // Send a minimal dry-run payload. The GD-Server's /api/ingest/metrics
  // accepts whatever metrics shape we send; for a connectivity test we use
  // a sentinel payload that won't affect normal operations on the GD side
  // (the GD-Server will record an INGEST event and store one row of test
  // values in regional_metrics — operationally inert).
  const url = endpointUrl.replace(/\/+$/, '') + '/api/ingest/metrics';

  // Defense in depth — re-validate the stored URL's hostname against the
  // allow-list at fetch time. The allow-list was already checked at PUT
  // time (when the URL was stored), but checking again here protects
  // against three scenarios:
  //   1. The DB row was tampered with out-of-band
  //   2. GD_ALLOWED_HOSTS env var was tightened since the URL was stored
  //   3. A code path elsewhere wrote to gd_push_config without going
  //      through validateEndpointUrl
  let parsedUrl;
  try { parsedUrl = new URL(url); }
  catch (err) { return res.status(400).json({ error: 'Stored test URL is invalid: ' + err.message }); }
  const allowed = validateAllowedHost(parsedUrl.hostname);
  if (!allowed.ok) {
    auditLog(req.user?.id, 'GD_CONFIG_TEST_BLOCKED', `Allow-list rejected stored URL hostname ${parsedUrl.hostname}`);
    return res.status(400).json({ error: allowed.error });
  }

  // Additional belt-and-suspenders DNS check rejecting loopback / "this
  // network" / link-local addresses (including cloud metadata services
  // like AWS 169.254.169.254). The allow-list above already requires the
  // hostname be pre-approved, but even an admin who legitimately
  // pre-approved a hostname might not realize it resolves to an internal
  // address. There's a small TOCTOU window between this check and the
  // socket connect; DNS rebinding could theoretically exploit it. For a
  // single admin-triggered test inside a corporate network this is an
  // acceptable tradeoff.
  const safety = await validateHostnameSafety(parsedUrl.hostname);
  if (!safety.ok) {
    auditLog(req.user?.id, 'GD_CONFIG_TEST_BLOCKED', `Blocked unsafe destination ${parsedUrl.hostname}`);
    return res.status(400).json({ error: safety.error });
  }

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
      // Refuse to follow redirects. Otherwise an admin who pre-approved
      // a hostname that points at a server they don't fully control could
      // be redirected to an internal service (302 to 169.254.169.254 or
      // similar) — bypassing both the allow-list and the dangerous-IP
      // block since redirects use a fresh URL not subject to either.
      redirect: 'error',
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
