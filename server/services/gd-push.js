// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Global Dashboard Push Service
// Pushes aggregate region-level metrics from this Regional MC to the configured
// Global Dashboard Server (GD-Server). One-way data flow — the GD-Server is
// read-only ingest from the MC's perspective and never writes back.
//
// The GD-Server runs as a separate backend process (typically on port 4001)
// operated by the customer's CISO/VP. The CISO obtains an API key by calling
// POST /api/mc/register on the GD-Server, then provides the key plus the
// GD-Server endpoint URL to this MC's admin who fills it into the MC's Global
// Dashboard Push settings (PUT /api/gd-config). This service then begins
// pushing on the configured cadence.
//
// Configuration is stored in the gd_push_config singleton row in the canonical
// MC schema. The api_key_encrypted column holds the API key as a base64-encoded
// AES-256-GCM Tier-1 encrypted blob, decrypted only when this service is about
// to make an outbound HTTP call.
//
// Push lifecycle per attempt:
//   1. Read gd_push_config; if disabled or missing endpoint/key, skip
//   2. Decrypt API key
//   3. Call MetricsCollector for current snapshot
//   4. Map snapshot to GD-Server ingest body shape
//   5. POST to <endpoint_url>/api/ingest/metrics with retry-and-backoff
//   6. Update last_push_at, last_push_status, last_push_error,
//      last_push_duration_ms, consecutive_failures
//   7. Audit log success/failure
//
// Circuit breaker: after 20 consecutive failures the service auto-disables
// the push (sets enabled=0) and emits a critical audit event. The admin must
// re-enable manually via PUT /api/gd-config after fixing whatever broke.
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { decrypt } = require('./encryption');
const { MetricsCollector } = require('./metrics-collector');
const { auditLog } = require('../middleware/audit');
const { validateAllowedHost } = require('./gd-allow-list');

const CIRCUIT_BREAKER_THRESHOLD = 20;
const REQUEST_TIMEOUT_MS = 30000;

class GdPushService {
  constructor() {
    this.timerId = null;
    this.shuttingDown = false;
  }

  // ── Public lifecycle ──────────────────────────────────────────────────────
  start() {
    if (this.timerId) return;
    this.shuttingDown = false;
    this._scheduleNext(0);  // first tick immediately so a freshly-configured
                            // push doesn't wait the full interval before
                            // sending its first sample
    logger.info('GD push service started');
  }

  stop() {
    this.shuttingDown = true;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    logger.info('GD push service stopped');
  }

  // ── Scheduling ────────────────────────────────────────────────────────────
  _scheduleNext(delayMs) {
    if (this.shuttingDown) return;
    this.timerId = setTimeout(() => this._tick(), delayMs);
  }

  async _tick() {
    if (this.shuttingDown) return;
    let intervalMinutes = 15;  // fallback if config unreadable
    try {
      const config = this._readConfig();
      intervalMinutes = config?.push_interval_minutes || 15;
      if (config && config.enabled === 1 && config.endpoint_url && config.api_key_encrypted) {
        await this._performPush(config);
      }
    } catch (err) {
      logger.error('GD push tick error', { error: err.message });
    } finally {
      // Always schedule the next tick, even after errors
      this._scheduleNext(intervalMinutes * 60 * 1000);
    }
  }

  _readConfig() {
    const db = getDb();
    try {
      return db.prepare('SELECT * FROM gd_push_config WHERE id = 1').get();
    } finally {
      db.close();
    }
  }

  // ── Push attempt ──────────────────────────────────────────────────────────
  async _performPush(config) {
    const startedAt = Date.now();
    let attempt = 0;
    let lastError = null;

    while (attempt <= config.retry_max) {
      attempt++;
      try {
        const apiKey = this._decryptKey(config.api_key_encrypted);
        const body = this._buildIngestBody(apiKey);
        await this._postToGd(config.endpoint_url, body);
        const durationMs = Date.now() - startedAt;
        this._recordSuccess(durationMs);
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
    this._recordFailure(lastError?.message || 'unknown error', durationMs);
  }

  _decryptKey(encryptedBase64) {
    const buffer = Buffer.from(encryptedBase64, 'base64');
    return decrypt(buffer, 'TIER1_ENCRYPTION_KEY');
  }

  // Map MetricsCollector output to the GD-Server /api/ingest/metrics body shape.
  // The GD-Server expects:
  //   { apiKey, metrics: { healthScore, utilization, automationRate, certCoverage,
  //                        slaCompliance, turnoverRisk, analystCount, activeIncidents,
  //                        burnoutRoutingActive, proactiveBreaksGiven,
  //                        upskillingHoursUsed } }
  _buildIngestBody(apiKey) {
    const db = getDb();
    let snapshot;
    try {
      snapshot = new MetricsCollector(db).collect();
    } finally {
      db.close();
    }

    // Map the canonical snapshot fields. Fields the canonical MC does not yet
    // track are derived as best as possible or sent as null; the GD-Server's
    // regional_metrics columns accept NULL on missing fields. As features get
    // built canonically (real SLA tracking, automation rate accounting, etc.),
    // the GD push automatically picks up the new fields with no code change
    // here other than extending the mapping below.
    const metrics = {
      healthScore: this._scoreToHundred(snapshot.team_health?.avgCapacity),
      utilization: this._safeUtilization(db),
      automationRate: this._safeAutomationRate(db),
      certCoverage: this._safeCertCoverage(db),
      slaCompliance: this._safeSlaCompliance(db),
      turnoverRisk: this._deriveTurnoverRisk(snapshot.team_health?.avgCapacity),
      analystCount: snapshot.team_health?.analysts || 0,
      activeIncidents: this._safeActiveIncidents(db),
      burnoutRoutingActive: snapshot.routing?.enabled !== false,
      proactiveBreaksGiven: this._safeProactiveBreaks(db),
      upskillingHoursUsed: snapshot.upskilling?.scheduledAnalysts || 0,
    };

    return { apiKey, metrics };
  }

  // ── Field helpers ────────────────────────────────────────────────────────
  // Each helper is defensive: it opens its own DB scope when needed and never
  // throws — on any error it returns a safe default so the push doesn't fail
  // because one auxiliary metric couldn't be computed.

  _scoreToHundred(avgCapacity) {
    // capacity_score is the canonical 0-100 wellbeing measure; treat it
    // directly as the GD-side healthScore. If null/missing, default 0.
    const n = parseInt(avgCapacity, 10);
    return Number.isFinite(n) ? Math.max(0, Math.min(100, n)) : 0;
  }

  _safeUtilization(db) {
    try {
      // % of analysts currently with available=0 (working a ticket / on a call).
      // Approximation until per-ticket workload tracking exists.
      const total = db.prepare("SELECT COUNT(*) as n FROM users WHERE role='analyst' AND active=1").get();
      const working = db.prepare("SELECT COUNT(*) as n FROM users WHERE role='analyst' AND active=1 AND available=0").get();
      if (!total?.n) return 0;
      return Math.round((working.n / total.n) * 100);
    } catch { return null; }
  }

  _safeAutomationRate(db) {
    try {
      const cfg = db.prepare("SELECT value FROM config WHERE key='automation_rate'").get();
      if (!cfg) return null;
      const n = parseInt(cfg.value, 10);
      return Number.isFinite(n) ? n : null;
    } catch { return null; }
  }

  _safeCertCoverage(db) {
    try {
      const cfg = db.prepare("SELECT value FROM config WHERE key='cert_coverage_pct'").get();
      if (!cfg) return null;
      const n = parseInt(cfg.value, 10);
      return Number.isFinite(n) ? n : null;
    } catch { return null; }
  }

  _safeSlaCompliance(db) {
    try {
      const row = db.prepare("SELECT AVG(compliance_pct) as avg FROM sla_measurements WHERE timestamp > datetime('now', '-24 hours')").get();
      const n = parseInt(row?.avg, 10);
      return Number.isFinite(n) ? n : null;
    } catch { return null; }
  }

  _deriveTurnoverRisk(avgCapacity) {
    // Maps wellbeing score to the GD-Server's CHECK constraint values.
    // Thresholds match the notification thresholds elsewhere (burnout_threshold
    // default 65 in the GD-Server's notification config).
    const n = parseInt(avgCapacity, 10);
    if (!Number.isFinite(n)) return 'low';
    if (n < 40) return 'critical';
    if (n < 55) return 'high';
    if (n < 70) return 'medium';
    return 'low';
  }

  _safeActiveIncidents(db) {
    try {
      const row = db.prepare("SELECT COUNT(*) as n FROM ooda_actions WHERE status='in_progress'").get();
      return row?.n || 0;
    } catch { return 0; }
  }

  _safeProactiveBreaks(db) {
    try {
      const row = db.prepare("SELECT COUNT(*) as n FROM audit_log WHERE event_type='PROACTIVE_BREAK_GIVEN' AND timestamp > datetime('now', '-24 hours')").get();
      return row?.n || 0;
    } catch { return 0; }
  }

  // ── HTTP ──────────────────────────────────────────────────────────────────
  async _postToGd(endpointUrl, body) {
    // endpointUrl is the GD-Server base URL (e.g. https://gd.corp:4001).
    // The ingest path is fixed by the GD-Server contract.
    const url = endpointUrl.replace(/\/+$/, '') + '/api/ingest/metrics';

    // Defense in depth — re-validate the stored URL's hostname against the
    // GD_ALLOWED_HOSTS allow-list at every push, NOT just at write-time
    // (gd-config.js validateEndpointUrl already gated PUT). Reasons:
    //   1. The DB row could have been tampered with out of band
    //   2. GD_ALLOWED_HOSTS env var could have been tightened since the
    //      URL was stored, and we want the new restriction to take effect
    //      on the next push
    //   3. If gd_push_config gets seeded via an external migration or
    //      direct SQL, this check still applies
    // If the allow-list rejects, throw — the caller treats this as a
    // push failure, audit-logs it, and applies the normal backoff.
    let parsedUrl;
    try { parsedUrl = new URL(url); }
    catch (err) { throw new Error('GD push URL is invalid: ' + err.message); }
    const allowed = validateAllowedHost(parsedUrl.hostname);
    if (!allowed.ok) {
      throw new Error('GD push allow-list rejected hostname: ' + allowed.error);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
        // Refuse to follow redirects. Belt-and-suspenders against an
        // SSRF-via-redirect attack where a pre-approved hostname returns
        // a 302 to an internal service like 169.254.169.254. The
        // redirect would use a fresh URL not subject to the allow-list.
        redirect: 'error',
      });
      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`GD ingest returned HTTP ${response.status}: ${text.slice(0, 200)}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  // ── Status persistence ────────────────────────────────────────────────────
  _recordSuccess(durationMs) {
    const db = getDb();
    try {
      db.prepare(
        `UPDATE gd_push_config
         SET last_push_at = datetime('now'),
             last_push_status = 'success',
             last_push_error = NULL,
             last_push_duration_ms = ?,
             consecutive_failures = 0,
             updated_at = datetime('now')
         WHERE id = 1`
      ).run(durationMs);
      auditLog(null, 'GD_PUSH_SUCCESS', `duration=${durationMs}ms`);
    } catch (err) {
      logger.error('GD push success recording failed', { error: err.message });
    } finally {
      db.close();
    }
  }

  _recordFailure(errorMessage, durationMs) {
    const db = getDb();
    try {
      const truncated = (errorMessage || '').slice(0, 1000);
      db.prepare(
        `UPDATE gd_push_config
         SET last_push_at = datetime('now'),
             last_push_status = 'failure',
             last_push_error = ?,
             last_push_duration_ms = ?,
             consecutive_failures = consecutive_failures + 1,
             updated_at = datetime('now')
         WHERE id = 1`
      ).run(truncated, durationMs);

      const row = db.prepare('SELECT consecutive_failures FROM gd_push_config WHERE id = 1').get();
      auditLog(null, 'GD_PUSH_FAILURE', `error=${truncated.slice(0, 200)} consecutive=${row?.consecutive_failures || 0}`);

      // Circuit breaker — auto-disable after the threshold so a misconfigured
      // or unreachable GD-Server doesn't generate an unbounded failure log
      // and unbounded outbound retry traffic. The admin must re-enable
      // manually after diagnosing.
      if ((row?.consecutive_failures || 0) >= CIRCUIT_BREAKER_THRESHOLD) {
        db.prepare(
          `UPDATE gd_push_config SET enabled = 0, updated_at = datetime('now') WHERE id = 1`
        ).run();
        auditLog(null, 'GD_PUSH_CIRCUIT_BREAKER',
          `Auto-disabled after ${row.consecutive_failures} consecutive failures. Admin must re-enable via PUT /api/gd-config.`);
        logger.error('GD push circuit breaker tripped — auto-disabled', { consecutiveFailures: row.consecutive_failures });
      }
    } catch (err) {
      logger.error('GD push failure recording failed', { error: err.message });
    } finally {
      db.close();
    }
  }
}

// Singleton instance — there's one push pipeline per Regional MC.
const gdPushService = new GdPushService();

module.exports = { gdPushService };
