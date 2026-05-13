// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Global Dashboard Push Service
//
// Pushes aggregate region-level metrics from this Regional MC to the configured
// Global Dashboard Server (GD-Server). One-way data flow — the GD-Server is
// read-only ingest from the MC's perspective and never writes back.
//
// The GD-Server runs as a separate backend process (typically on port 4001)
// operated by the customer's CISO/VP. The CISO obtains an API key by calling
// POST /api/mc/register on the GD-Server, then provides the key plus the
// GD-Server endpoint URL to this MC's admin who fills it into the MC's Global
// Dashboard Push settings (PUT /api/gd-config). The PUT handler (C27)
// auto-fires the initial handshake; this service polls for status on
// subsequent ticks and signs outbound pushes with the approved key.
//
// R3g PR3 PHASE 5 (C28) — TICK SEMANTICS
//
// Every tick has two phases bridged by the gd_push_signing_keys table:
//
//   PHASE A — Handshake status poll
//     If handshake_status='pending_approval' and pending_signing_key_id is
//     set, POST to <endpoint_url>/api/mc/me/signing-key-status (C21) with
//     { apiKey, keyId: pending_signing_key_id } to learn the CISO's
//     decision. Three outcomes:
//
//       'pending_approval'  No-op. The next tick will poll again.
//
//       'approved'         Commit the staged keypair via
//                          signingKeysSvc.commitStagedKeypair. The local
//                          row becomes is_active=1; any prior active key
//                          gets demoted with rotated_out_at=now (still
//                          inside the GD's grace window per C22). Advance
//                          gd_push_config.handshake_status='approved',
//                          clear pending_signing_key_id, update
//                          last_handshake_at.
//
//       'rejected'         Rollback the staged keypair via
//                          signingKeysSvc.rollbackStagedKeypair (deletes
//                          the local row). Advance handshake_status=
//                          'rejected' so the operator can re-PUT
//                          gd-config (with corrected api_key, typically)
//                          to retry. The C27 PUT handler treats
//                          'rejected' as eligible for re-firing.
//
//   PHASE B — Signed metrics push
//     If a current active signing key exists, build the ingest body, sign
//     with the active key via gd-push-signer.signPushPayload, and POST to
//     <endpoint_url>/api/ingest/metrics with the X-FA-* headers. The GD's
//     verifier (C22) accepts signatures from the active key OR from a
//     recently-rotated-out approved key still inside the grace window.
//
//     If NO active signing key exists (handshake hasn't completed yet on
//     this MC), the push is skipped with an info log — NOT a failure.
//     consecutive_failures is not incremented for this case.
//
// Configuration is stored in the gd_push_config singleton row in the canonical
// MC schema. The api_key_encrypted column holds the API key as a base64-encoded
// AES-256-GCM Tier-1 encrypted blob, decrypted only when this service is about
// to make an outbound HTTP call.
//
// Push lifecycle per tick:
//   1. Read gd_push_config; if disabled or missing endpoint/key, skip
//   2. If pending handshake: poll GD status, commit/rollback/no-op
//   3. If active signing key exists:
//      a. Decrypt API key
//      b. Call MetricsCollector for current snapshot
//      c. Map snapshot to GD-Server ingest body shape
//      d. Sign payload with active key (timestamp re-generated per attempt)
//      e. POST signed bytes + headers to /api/ingest/metrics with
//         retry-and-backoff
//      f. Update last_push_at, last_push_status, last_push_error,
//         last_push_duration_ms, consecutive_failures
//      g. Audit log success/failure
//   4. If no active key: log skip; do NOT touch last_push_* fields
//
// Circuit breaker: after 20 consecutive failures the service auto-disables
// the push (sets enabled=0) and emits a critical audit event. The admin must
// re-enable manually via PUT /api/gd-config after fixing whatever broke.
// The circuit breaker counts only PUSH failures (signed-POST errors), NOT
// handshake-poll failures (those are silent retry-on-next-tick).
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { decrypt } = require('./encryption');
const { MetricsCollector } = require('./metrics-collector');
const { auditLog } = require('../middleware/audit');
const { validateAllowedHost } = require('./gd-allow-list');
// R3g PR3 Phase 5 (C28): handshake polling and signed-push integration
const signingKeysSvc = require('./gd-push-signing-keys');
const { signPushPayload } = require('./gd-push-signer');

const CIRCUIT_BREAKER_THRESHOLD = 20;
const REQUEST_TIMEOUT_MS = 30000;
const STATUS_POLL_TIMEOUT_MS = 15000;  // shorter than push — status poll is cheap

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
        // R3g PR3 Phase 5 (C28): poll handshake status BEFORE pushing.
        // If the CISO approved since last tick, this is what commits the
        // staged keypair locally so the subsequent push can sign with it.
        // Polling failure is non-fatal and silent — next tick retries.
        await this._pollHandshakeStatus(config);
        // Re-read config after polling — handshake_status / pending_signing_
        // key_id may have advanced. _performPush needs the latest state to
        // decide whether to skip-on-no-active-key.
        const refreshedConfig = this._readConfig() || config;
        await this._performPush(refreshedConfig);
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

  // ── Phase 5 (C28): Handshake status polling ───────────────────────────────
  //
  // When a signing key submission is pending CISO approval on the GD side,
  // this method polls the GD's /api/mc/me/signing-key-status endpoint (C21)
  // to find out whether the CISO has approved, rejected, or is still
  // deciding. On approved/rejected we mutate local state to match (commit
  // or rollback the staged keypair; advance handshake_status; clear
  // pending_signing_key_id). On 'pending_approval' or any error, no local
  // change — the next tick will poll again.
  //
  // INVARIANTS:
  //   - Polling failures are silent (logger.warn, no audit). Recovery is
  //     by retry on the next tick; flooding audit on every flaky network
  //     call is noise.
  //   - The commit/rollback paths AUDIT the state transition because that's
  //     a real local-state change with security implications (a new key
  //     becoming active, or a rejected key being deleted).
  //   - This method never throws — all errors caught + logged. The caller
  //     (_tick) treats it as best-effort.
  //   - 429 rate-limit responses are honored quietly (the GD's rate-limit
  //     is per (mcId, keyId) and a well-behaved client polling once per
  //     tick will never exhaust it; a 429 here means clock skew or a
  //     misconfigured tick interval — log info, retry next tick).
  async _pollHandshakeStatus(config) {
    if (config.handshake_status !== 'pending_approval') return;
    if (!config.pending_signing_key_id) {
      logger.warn('GD push: handshake_status=pending_approval but pending_signing_key_id is NULL — inconsistent state; skipping poll');
      return;
    }
    if (!config.mc_id) {
      // Without mc_id the MC can't even resolve itself on the GD; the
      // status endpoint uses apiKey not mc_id, but having pending_approval
      // without mc_id is a config inconsistency that should be visible.
      logger.warn('GD push: handshake_status=pending_approval but mc_id is NULL — operator must set mc_id via PUT /api/gd-config');
      return;
    }

    // ── Build + validate status URL ──
    const statusUrl = config.endpoint_url.replace(/\/+$/, '') + '/api/mc/me/signing-key-status';
    let parsedUrl;
    try { parsedUrl = new URL(statusUrl); }
    catch (err) {
      logger.warn('GD push: status poll URL invalid', { error: err.message });
      return;
    }
    const allowed = validateAllowedHost(parsedUrl.hostname);
    if (!allowed.ok) {
      logger.warn('GD push: status poll allow-list rejected', { hostname: parsedUrl.hostname, error: allowed.error });
      return;
    }

    // ── POST status request ──
    let apiKey;
    try {
      apiKey = this._decryptKey(config.api_key_encrypted);
    } catch (err) {
      logger.error('GD push: status poll api_key decrypt failed', { error: err.message });
      return;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), STATUS_POLL_TIMEOUT_MS);
    let resp;
    let body;
    try {
      try {
        resp = await fetch(statusUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apiKey, keyId: config.pending_signing_key_id }),
          signal: controller.signal,
          redirect: 'error',
        });
        const text = await resp.text();
        try { body = JSON.parse(text); }
        catch { body = { error: text.slice(0, 200) }; }
      } finally {
        clearTimeout(timeout);
      }
    } catch (netErr) {
      logger.warn('GD push: status poll network failure', { error: netErr.message });
      return;
    }

    if (resp.status === 429) {
      logger.info('GD push: status poll rate-limited; retry next tick',
        { retryAfter: body?.retryAfterSeconds });
      return;
    }
    if (!resp.ok) {
      logger.warn('GD push: status poll failed',
        { status: resp.status, code: body?.code, error: body?.error });
      return;
    }
    if (!body || (body.status !== 'pending_approval' && body.status !== 'approved' && body.status !== 'rejected')) {
      logger.warn('GD push: status poll returned unexpected body', { body });
      return;
    }

    if (body.status === 'pending_approval') {
      // No change — keep waiting. logger.debug would be more appropriate
      // but the codebase uses info as the lowest level for routine ops.
      return;
    }

    if (body.status === 'approved') {
      // Commit the staged keypair locally. From this point forward,
      // outbound pushes sign with the new key (Phase B of this tick).
      const db = getDb();
      try {
        let commitResult;
        try {
          commitResult = signingKeysSvc.commitStagedKeypair(db, config.pending_signing_key_id);
        } catch (commitErr) {
          // Local row gone (manual cleanup?) or already committed (race
          // with manual intervention). Update handshake_status anyway so
          // we don't keep polling for a row that's not there.
          logger.warn('GD push: GD reported approved but local commit failed',
            { error: commitErr.message, stagedId: config.pending_signing_key_id });
          db.prepare(`
            UPDATE gd_push_config
            SET handshake_status = 'approved',
                pending_signing_key_id = NULL,
                last_handshake_at = datetime('now'),
                updated_at = datetime('now')
            WHERE id = 1
          `).run();
          auditLog(null, 'GD_PUSH_HANDSHAKE_APPROVED_NO_COMMIT',
            `stagedId=${config.pending_signing_key_id} error=${commitErr.message.slice(0, 200)}`);
          return;
        }
        db.prepare(`
          UPDATE gd_push_config
          SET handshake_status = 'approved',
              pending_signing_key_id = NULL,
              last_handshake_at = datetime('now'),
              updated_at = datetime('now')
          WHERE id = 1
        `).run();
        auditLog(null, 'GD_PUSH_HANDSHAKE_APPROVED',
          `stagedId=${config.pending_signing_key_id} newFingerprint=${commitResult.newPublicKeyFingerprint} priorFingerprint=${commitResult.priorPublicKeyFingerprint || 'none'}`);
        logger.info('GD push: handshake approved by CISO, staged key committed', {
          newId: commitResult.newId,
          newFingerprint: commitResult.newPublicKeyFingerprint,
          priorFingerprint: commitResult.priorPublicKeyFingerprint,
        });
      } catch (dbErr) {
        logger.error('GD push: approval bookkeeping failed', { error: dbErr.message });
      } finally {
        db.close();
      }
      return;
    }

    // body.status === 'rejected'
    {
      const db = getDb();
      try {
        let rollbackResult;
        try {
          rollbackResult = signingKeysSvc.rollbackStagedKeypair(db, config.pending_signing_key_id);
        } catch (rbErr) {
          logger.warn('GD push: GD reported rejected but rollback threw',
            { error: rbErr.message, stagedId: config.pending_signing_key_id });
          rollbackResult = { deleted: false, fingerprint: null };
        }
        db.prepare(`
          UPDATE gd_push_config
          SET handshake_status = 'rejected',
              pending_signing_key_id = NULL,
              last_handshake_at = datetime('now'),
              updated_at = datetime('now')
          WHERE id = 1
        `).run();
        auditLog(null, 'GD_PUSH_HANDSHAKE_REJECTED',
          `stagedId=${config.pending_signing_key_id} fingerprint=${rollbackResult.fingerprint || 'unknown'} rolledBack=${rollbackResult.deleted}`);
        logger.info('GD push: handshake rejected by CISO, staged key rolled back', {
          stagedId: config.pending_signing_key_id,
          fingerprint: rollbackResult.fingerprint,
        });
      } catch (dbErr) {
        logger.error('GD push: rejection bookkeeping failed', { error: dbErr.message });
      } finally {
        db.close();
      }
    }
  }

  // ── Push attempt ──────────────────────────────────────────────────────────
  async _performPush(config) {
    // Phase 5 (C28): if no active signing key exists, the handshake hasn't
    // completed yet on this MC. Skip the push cleanly — this is NOT a
    // failure (no last_push_* update, no consecutive_failures increment,
    // no circuit-breaker progress). Pre-Phase-5 deployments that had an
    // is_active=1 key auto-created on first run see no behavior change
    // here; the new gated path only triggers when stage/commit hasn't
    // yet completed for this configuration.
    const dbCheck = getDb();
    let activeFingerprint;
    try {
      activeFingerprint = signingKeysSvc.getActiveFingerprint(dbCheck);
    } finally {
      dbCheck.close();
    }
    if (!activeFingerprint) {
      // Quiet info log on every tick would be noisy if handshake stays
      // pending for hours. Log only when state worth reporting:
      //   - 'none'                 first install, operator hasn't saved
      //                            config yet (shouldn't happen here —
      //                            _tick gates on enabled+endpoint+key)
      //   - 'pending_approval'     waiting for CISO; expected
      //   - 'rejected'             CISO rejected; operator action needed
      //   - 'approved'             paradox — claim of approval but no
      //                            active key means commit failed earlier;
      //                            this needs operator attention
      if (config.handshake_status === 'approved') {
        logger.warn('GD push: handshake_status=approved but no active signing key — re-run handshake via PUT /api/gd-config or POST /api/gd-signing-key/rotate');
      } else {
        logger.info('GD push: no active signing key (handshake not yet completed); skipping push',
          { handshake_status: config.handshake_status });
      }
      return;
    }

    const startedAt = Date.now();
    let attempt = 0;
    let lastError = null;

    while (attempt <= config.retry_max) {
      attempt++;
      try {
        const apiKey = this._decryptKey(config.api_key_encrypted);
        const bodyObj = this._buildIngestBody(apiKey);
        // Sign fresh on every attempt — the GD's verifier (C22) enforces a
        // 5-minute timestamp skew window; retries spanning more than that
        // need a fresh timestamp + signature. The signer reads the active
        // key from the DB each call, so a key rotation during a retry
        // sequence picks up the new key on the next attempt automatically.
        const dbSign = getDb();
        let signed;
        try {
          signed = signPushPayload(dbSign, bodyObj);
        } finally {
          dbSign.close();
        }
        await this._postToGd(config.endpoint_url, signed);
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
  //
  // signed: object from signPushPayload(db, bodyObj) with shape
  //   { fingerprint, timestamp, signature, bodyBytes }
  //
  // We POST `signed.bodyBytes` verbatim — NOT JSON.stringify(bodyObj). The
  // bytes were generated under a specific canonicalization that the
  // signature commits to; any re-serialization would produce different
  // bytes (key order, whitespace) and the GD verifier (C22) would reject.
  async _postToGd(endpointUrl, signed) {
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
        headers: {
          'Content-Type': 'application/json',
          // R3g PR3 Phase 5: signed-push contract from C8/C10/C22
          'X-FA-Key-Fingerprint': signed.fingerprint,
          'X-FA-Timestamp': signed.timestamp,
          'X-FA-Signature': signed.signature,
        },
        body: signed.bodyBytes,
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
