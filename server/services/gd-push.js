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
// The circuit breaker counts only METRICS push failures (signed POST to
// /api/ingest/metrics), NOT handshake-poll failures and NOT compliance-
// push failures. Compliance is a separate cadence with its own audit
// trail; missing one day's compliance push is recoverable without
// disabling the whole pipeline.
//
// R3g PR3 PHASE 6 (C32) — COMPLIANCE PUSH TICK (SEPARATE SCHEDULE)
//
// In addition to the metrics tick above, the service runs a SECOND
// independent tick on the compliance_push_cadence_hours cadence (default
// 24h, seeded in C6, range 1-720). Each compliance tick:
//
//   1. Reads gd_push_config; if disabled or no active signing key, skip
//   2. Iterates over all FRAMEWORKS keys exposed by the compliance
//      module (currently 16: hipaa, soc2, nist_csf, gdpr, dora,
//      iso_27001, fisma, cyber_essentials, nis2, cps234_au, ccpa,
//      lgpd, pipeda, pdpa_sg, appi_jp, popia_za)
//   3. For each framework:
//      a. Call generateComplianceReport(framework) to produce the full
//         report (mc-local — uses the MC's own DB, NOT shipped over
//         the wire)
//      b. Distill to the summary shape stored in
//         mc_compliance_reports.summary_json:
//           { passed, total, perCategoryCounts, topFailingControls[3],
//             generatedAt, digestHash }
//      c. Sign with active key (same signer as metrics path)
//      d. POST to /api/ingest/compliance-reports (C30/C31)
//      e. Audit log per-framework success or failure
//   4. Continue to next framework even if one fails; partial-success
//      is better than all-or-nothing for a long-cadence push
//
// Compliance push DOES NOT update gd_push_config.last_push_*. Those
// fields are operationally tied to the metrics tick. Compliance
// success/failure is captured purely in audit log entries
// (GD_COMPLIANCE_PUSH_SUCCESS / GD_COMPLIANCE_PUSH_FAILURE) per
// framework. A future schema additon may add last_compliance_push_*
// fields if operator UI demands them; for v1.0.33 the audit log is
// sufficient.
//
// The two ticks share start() / stop() lifecycle and the same active
// signing key. A handshake polled by the metrics tick that lands an
// approved key in mid-tick will be observable by the compliance
// tick on its next firing (and vice versa, though the metrics tick
// fires far more frequently).
// ═══════════════════════════════════════════════════════════════════════════════

const { getDb } = require('../db/init');
const { logger } = require('./logger');
const { openTier1 } = require('./tier1-seal');
const { MetricsCollector } = require('./metrics-collector');
const { auditLog } = require('../middleware/audit');
const { validateAllowedHost } = require('./gd-allow-list');
// R3g PR3 Phase 5 (C28): handshake polling and signed-push integration
const signingKeysSvc = require('./gd-push-signing-keys');
const { signPushPayload } = require('./gd-push-signer');
// R3g PR3 Phase 6 (C32): compliance summary generation
const { generateComplianceReport, FRAMEWORKS } = require('./compliance');

// R3h: helper-pay service supplies the leaderboard payload for the
// MC→GD leaderboard push pipeline added in C9b. Only opted-in analysts
// are returned by getLeaderboard; the opt-in invariant propagates from
// the MC's users.leaderboard_opt_in column through this push to the
// GD's regional_leaderboard table per privacy invariant I3.
const helperPay = require('./helper-pay');

const CIRCUIT_BREAKER_THRESHOLD = 20;
const REQUEST_TIMEOUT_MS = 30000;
const STATUS_POLL_TIMEOUT_MS = 15000;  // shorter than push — status poll is cheap
const DEFAULT_COMPLIANCE_CADENCE_HOURS = 24;
const MAX_COMPLIANCE_CADENCE_HOURS = 720;  // 30-day ceiling from gd_push_config CHECK

// R3h: leaderboard tick cadence + payload size discipline.
//   Cadence 15 min default matches the build plan v1 and the leaderboard's
//   natural rate of change (rating events occur in low-minute frequency
//   during active hours, leaderboard re-orders on each rating). The 24-hour
//   ceiling matches the gd_push_config CHECK.
//   Limit 50 entries gives the GD enough roster depth to render its own
//   top-N (the GD Helper Recognition tab in C11 displays top 10 or top 20
//   depending on view) while keeping the signed payload well under the
//   GD's ingest body size limits.
const DEFAULT_LEADERBOARD_CADENCE_MINUTES = 15;
const MAX_LEADERBOARD_CADENCE_MINUTES = 1440;  // 24h ceiling from gd_push_config CHECK
const LEADERBOARD_PUSH_LIMIT = 50;

class GdPushService {
  constructor() {
    this.timerId = null;
    // R3g PR3 Phase 6 (C32): separate timer for compliance pushes
    this.complianceTimerId = null;
    // R3h (C9b): separate timer for leaderboard pushes
    this.leaderboardTimerId = null;
    this.shuttingDown = false;
  }

  // ── Public lifecycle ──────────────────────────────────────────────────────
  start() {
    if (this.timerId || this.complianceTimerId || this.leaderboardTimerId) return;
    this.shuttingDown = false;
    this._scheduleNext(0);  // metrics tick: first fire immediately so a
                            // freshly-configured push doesn't wait the
                            // full interval before sending its first sample
    this._scheduleNextCompliance(0);  // compliance tick: first fire
                                      // immediately for the same reason —
                                      // operator gets feedback within the
                                      // first cadence rather than a day later
    this._scheduleNextLeaderboard(0);  // R3h: leaderboard tick — same
                                       // immediate-first-fire rationale.
                                       // The 15-min default cadence is
                                       // tight enough that operators see
                                       // first push within the GD's HTTP
                                       // request window of the start.
    logger.info('GD push service started (metrics + compliance + leaderboard ticks)');
  }

  stop() {
    this.shuttingDown = true;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    if (this.complianceTimerId) {
      clearTimeout(this.complianceTimerId);
      this.complianceTimerId = null;
    }
    if (this.leaderboardTimerId) {
      clearTimeout(this.leaderboardTimerId);
      this.leaderboardTimerId = null;
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
        await this._postToGd(config.endpoint_url, '/api/ingest/metrics', signed);
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
    return openTier1('gd_push_config.api_key_encrypted', encryptedBase64);
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
    let instanceFingerprint = null;
    try {
      snapshot = new MetricsCollector(db).collect();
      // B5e: read this deployment's instance fingerprint while the DB is open
      // so the GD can bind it per-MC and detect a clone (the same fingerprint
      // under two mc_ids). Defensive: any failure sends null (the GD treats an
      // absent fingerprint as not-yet-reporting).
      try {
        const idRow = db.prepare("SELECT fingerprint FROM instance_identity ORDER BY id LIMIT 1").get();
        instanceFingerprint = idRow ? idRow.fingerprint : null;
      } catch (idErr) {
        instanceFingerprint = null;
      }
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

    return { apiKey, instanceFingerprint, metrics };
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
  // path: the ingest path on the GD (e.g. '/api/ingest/metrics' or
  //   '/api/ingest/compliance-reports'). Generalized from the original
  //   metrics-only signature in C32 so the compliance tick can reuse the
  //   same allow-list + redirect-defense + AbortController machinery.
  //
  // signed: object from signPushPayload(db, bodyObj) with shape
  //   { fingerprint, timestamp, signature, bodyBytes }
  //
  // We POST `signed.bodyBytes` verbatim — NOT JSON.stringify(bodyObj). The
  // bytes were generated under a specific canonicalization that the
  // signature commits to; any re-serialization would produce different
  // bytes (key order, whitespace) and the GD verifier (C22) would reject.
  async _postToGd(endpointUrl, path, signed) {
    // endpointUrl is the GD-Server base URL (e.g. https://gd.corp:4001).
    const url = endpointUrl.replace(/\/+$/, '') + path;

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

  // ── HTTP — signed fetch that returns the response without throwing ────────
  //
  // R3g PR3 Phase 7 (C36): introduced for the mailbox poll + full-report
  // fulfillment paths that need to inspect the response status (poll
  // reads response body; full-report path distinguishes 202 from 409
  // NOT_PENDING). Same URL building + allow-list + AbortController +
  // X-FA-* headers as _postToGd; differs only in NOT throwing on a
  // non-ok response status.
  //
  // Returns: { ok, status, bodyText }   on HTTP response
  // Throws:                              on network error or timeout
  async _signedFetchToGd(endpointUrl, path, signed) {
    const url = endpointUrl.replace(/\/+$/, '') + path;
    try { new URL(url); } catch (_) { throw new Error('Invalid GD endpoint URL'); }
    const allowCheck = validateAllowedHost(url);
    if (!allowCheck.ok) {
      throw new Error('GD endpoint hostname blocked by allow-list: ' + allowCheck.reason);
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-FA-Key-Fingerprint': signed.fingerprint,
          'X-FA-Timestamp': signed.timestamp,
          'X-FA-Signature': signed.signature,
        },
        body: signed.bodyBytes,
        signal: controller.signal,
        redirect: 'error',
      });
      const bodyText = await response.text().catch(() => '');
      return { ok: response.ok, status: response.status, bodyText };
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

  // ──────────────────────────────────────────────────────────────────────────
  // R3g PR3 Phase 6 (C32): Compliance tick (separate cadence from metrics)
  // ──────────────────────────────────────────────────────────────────────────

  _scheduleNextCompliance(delayMs) {
    if (this.shuttingDown) return;
    this.complianceTimerId = setTimeout(() => this._complianceTick(), delayMs);
  }

  async _complianceTick() {
    if (this.shuttingDown) return;
    let cadenceHours = DEFAULT_COMPLIANCE_CADENCE_HOURS;
    try {
      const config = this._readConfig();
      // Read cadence with the same defensive coercion pattern as the metrics
      // tick's interval read: invalid values fall back to the default.
      const raw = config?.compliance_push_cadence_hours;
      if (Number.isInteger(raw) && raw >= 1 && raw <= MAX_COMPLIANCE_CADENCE_HOURS) {
        cadenceHours = raw;
      }
      if (config && config.enabled === 1 && config.endpoint_url && config.api_key_encrypted) {
        await this._performCompliancePush(config);
      }
    } catch (err) {
      logger.error('GD compliance tick error', { error: err.message });
    } finally {
      // Always schedule the next compliance tick, even after errors
      this._scheduleNextCompliance(cadenceHours * 60 * 60 * 1000);
    }
  }

  async _performCompliancePush(config) {
    // Active-key check — same gate as the metrics tick. No active key
    // means handshake hasn't completed; skip cleanly with an info log
    // and try again on the next cadence.
    const dbCheck = getDb();
    let activeFingerprint;
    try {
      activeFingerprint = signingKeysSvc.getActiveFingerprint(dbCheck);
    } finally {
      dbCheck.close();
    }
    if (!activeFingerprint) {
      logger.info('GD compliance push: no active signing key; skipping tick',
        { handshake_status: config.handshake_status });
      return;
    }

    // Decrypt api_key once for the whole tick — all framework POSTs share
    // the same credential. Never logged, never put in audit detail.
    let apiKey;
    try {
      apiKey = this._decryptKey(config.api_key_encrypted);
    } catch (err) {
      logger.error('GD compliance push: api_key decrypt failed', { error: err.message });
      return;
    }

    // ── R3g PR3 Phase 7 (C36): Drain the CISO mailbox FIRST ──
    //
    // Before the daily per-framework summary push, poll the GD for
    // any CISO-initiated full-report requests pending fulfillment.
    // Processing the mailbox first ensures pending requests get
    // fulfilled within the same tick that discovers them, rather
    // than waiting another full cadence. Most ticks find an empty
    // mailbox (steady state), so this adds one cheap signed POST in
    // the common case.
    //
    // Mailbox failures DO NOT abort the summary push that follows.
    // The poll is best-effort: a network blip or transient GD error
    // shouldn't cost the MC its daily compliance summary delivery.
    // Each method internally handles its own audit + recovery.
    try {
      await this._processPendingRequests(config, apiKey);
    } catch (err) {
      logger.error('GD compliance push: mailbox processing unhandled error',
        { error: err.message });
    }

    // Iterate every framework the compliance module exposes. Each one
    // gets its own per-framework push with its own retry sequence; a
    // failure in one framework doesn't block subsequent ones. This
    // partial-success behavior is the right trade for a long-cadence
    // push: losing one framework's daily summary is recoverable
    // (next tick retries), but losing all 16 because of one bad
    // framework would be unrecoverable for 24h.
    const frameworkKeys = Object.keys(FRAMEWORKS);
    let successCount = 0;
    let failureCount = 0;
    for (const framework of frameworkKeys) {
      try {
        const ok = await this._pushOneComplianceFramework(config, apiKey, framework);
        if (ok) successCount++;
        else failureCount++;
      } catch (err) {
        // _pushOneComplianceFramework catches its own errors and returns
        // false; this catch handles unexpected escape (e.g. signing key
        // disappeared mid-tick, fully unhandled exception in summary
        // builder).
        failureCount++;
        logger.error('GD compliance push: unexpected error in framework push',
          { framework, error: err.message });
        auditLog(null, 'GD_COMPLIANCE_PUSH_FAILURE',
          `framework=${framework} reason=unhandled_exception error=${err.message.slice(0, 200)}`);
      }
    }

    logger.info('GD compliance tick complete',
      { total: frameworkKeys.length, succeeded: successCount, failed: failureCount });
  }

  // Returns true on success, false on failure. Never throws under normal
  // operation — failures are audit-logged and returned as false.
  async _pushOneComplianceFramework(config, apiKey, framework) {
    // 1. Generate the full compliance report locally (uses the MC's own DB)
    let fullReport;
    try {
      fullReport = generateComplianceReport(framework);
    } catch (genErr) {
      auditLog(null, 'GD_COMPLIANCE_PUSH_FAILURE',
        `framework=${framework} stage=generate reason=${genErr.message.slice(0, 200)}`);
      logger.warn('GD compliance push: report generation failed',
        { framework, error: genErr.message });
      return false;
    }
    if (!fullReport) {
      // generateComplianceReport returns null for unknown framework keys.
      // Shouldn't happen since we iterate Object.keys(FRAMEWORKS), but
      // defend against a future refactor that filters FRAMEWORKS.
      auditLog(null, 'GD_COMPLIANCE_PUSH_FAILURE',
        `framework=${framework} stage=generate reason=unknown_framework`);
      return false;
    }

    // 2. Distill the full report to the summary shape stored in
    //    mc_compliance_reports.summary_json
    const summary = this._buildComplianceSummary(framework, fullReport);

    // 3. Build the body and sign + post with retry
    const bodyObj = { apiKey, framework, summary };
    const retryMax = Number.isInteger(config.retry_max) ? config.retry_max : 3;
    const backoffSeconds = Number.isInteger(config.retry_backoff_seconds)
      ? config.retry_backoff_seconds : 30;

    let attempt = 0;
    let lastError = null;
    while (attempt <= retryMax) {
      attempt++;
      try {
        // Sign on every attempt — same rationale as the metrics tick: the
        // GD's 5-minute timestamp skew window means we need a fresh
        // timestamp if backoff push us past it.
        const dbSign = getDb();
        let signed;
        try {
          signed = signPushPayload(dbSign, bodyObj);
        } finally {
          dbSign.close();
        }
        await this._postToGd(config.endpoint_url, '/api/ingest/compliance-reports', signed);
        auditLog(null, 'GD_COMPLIANCE_PUSH_SUCCESS',
          `framework=${framework} attempt=${attempt} fingerprint=${signed.fingerprint} digestHash=${summary.digestHash}`);
        return true;
      } catch (err) {
        lastError = err;
        if (attempt <= retryMax) {
          const backoffMs = backoffSeconds * 1000 * attempt;
          await new Promise((r) => setTimeout(r, backoffMs));
        }
      }
    }

    auditLog(null, 'GD_COMPLIANCE_PUSH_FAILURE',
      `framework=${framework} attempts=${attempt} reason=${(lastError?.message || 'unknown').slice(0, 200)}`);
    logger.warn('GD compliance push: framework failed after retries',
      { framework, attempts: attempt, error: lastError?.message });
    return false;
  }

  // Distill the full generateComplianceReport output to the summary shape
  // stored in mc_compliance_reports.summary_json:
  //   { passed, total, perCategoryCounts, topFailingControls[3],
  //     generatedAt, digestHash }
  //
  // Size discipline: the C30 endpoint caps stringified summary at 64 KB.
  // topFailingControls is capped at 3 entries with truncated detail to
  // stay well under that ceiling even with many failing controls.
  _buildComplianceSummary(framework, fullReport) {
    const verifiedSummary = fullReport.summary?.verified || {};
    const customerSummary = fullReport.summary?.customerResponsibility || {};

    // Top failing controls: prioritize 'fail' status > 'warning' status,
    // take the first 3, truncate detail strings to 200 chars each.
    const failures = (fullReport.verifiedControls || [])
      .filter(c => c.status === 'fail');
    const warnings = (fullReport.verifiedControls || [])
      .filter(c => c.status === 'warning');
    const prioritized = [...failures, ...warnings].slice(0, 3);
    const topFailingControls = prioritized.map(c => ({
      controlId: c.controlId,
      controlName: c.controlName,
      status: c.status,
      detail: typeof c.detail === 'string' ? c.detail.slice(0, 200) : null,
    }));

    // digestHash: SHA-256 over a canonical subset of the summary so the GD
    // can deduplicate / detect tampering. Compute before adding
    // generatedAt + digestHash itself to avoid circularity.
    const crypto = require('crypto');
    const canonical = JSON.stringify({
      framework,
      verified: verifiedSummary,
      customer: customerSummary,
      topFailingControls,
    });
    const digestHash = crypto.createHash('sha256').update(canonical).digest('hex');

    return {
      // Aggregate fields the GD cross_region_rollup expects (C31)
      passed: verifiedSummary.passed || 0,
      total: verifiedSummary.total || 0,
      // Per-category breakdown — split between verified status counts
      // and customer-responsibility category counts (which carry the
      // organizational/procedural/physical/training/documentation
      // taxonomy)
      perCategoryCounts: {
        verified: {
          passed: verifiedSummary.passed || 0,
          warnings: verifiedSummary.warnings || 0,
          failed: verifiedSummary.failed || 0,
        },
        customerResponsibility: {
          total: customerSummary.total || 0,
          byCategory: customerSummary.byCategory || {},
        },
      },
      topFailingControls,
      generatedAt: fullReport.generatedAt,
      digestHash,
    };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // R3g PR3 Phase 7 (C36): Mailbox poll + full-report fulfillment
  // ──────────────────────────────────────────────────────────────────────────
  //
  // _processPendingRequests polls the GD for pending CISO-initiated
  // full-report requests and fulfills each one. Called at the top of
  // _performCompliancePush before the per-framework summary loop.
  //
  // Flow:
  //   1. Build poll body { apiKey }, sign, POST to
  //      /api/mc/me/pending-requests (C34)
  //   2. Parse response { requests: [{ id, framework, requested_at }] }
  //   3. For each request, call _pushOneFullReport (which generates +
  //      signs + posts the full report to
  //      /api/ingest/compliance-reports?full=true (C35))
  //   4. Per-request failures are isolated — one bad request doesn't
  //      block others
  //   5. Audit per-request success/failure
  //
  // Poll-level failures (network, auth, malformed response) audit and
  // return cleanly. The caller continues to the summary loop.
  async _processPendingRequests(config, apiKey) {
    // ── Sign + POST the poll ──
    const pollBody = { apiKey };
    let pollResult;
    try {
      const dbSign = getDb();
      let signed;
      try {
        signed = signPushPayload(dbSign, pollBody);
      } finally {
        dbSign.close();
      }
      pollResult = await this._signedFetchToGd(
        config.endpoint_url,
        '/api/mc/me/pending-requests',
        signed,
      );
    } catch (err) {
      // Network error, allow-list rejection, or other pre-HTTP issue
      auditLog(null, 'COMPLIANCE_MAILBOX_POLL_FAILURE',
        `stage=network reason=${err.message.slice(0, 200)}`);
      logger.warn('GD compliance: mailbox poll failed', { error: err.message });
      return;
    }

    if (!pollResult.ok) {
      auditLog(null, 'COMPLIANCE_MAILBOX_POLL_FAILURE',
        `stage=http status=${pollResult.status} body=${pollResult.bodyText.slice(0, 200)}`);
      logger.warn('GD compliance: mailbox poll returned non-ok',
        { status: pollResult.status });
      return;
    }

    // ── Parse response ──
    let parsed;
    try {
      parsed = JSON.parse(pollResult.bodyText);
    } catch (err) {
      auditLog(null, 'COMPLIANCE_MAILBOX_POLL_FAILURE',
        `stage=parse reason=invalid_json bodyPrefix=${pollResult.bodyText.slice(0, 100)}`);
      logger.warn('GD compliance: mailbox poll body not JSON',
        { error: err.message });
      return;
    }
    const requests = Array.isArray(parsed?.requests) ? parsed.requests : null;
    if (!requests) {
      auditLog(null, 'COMPLIANCE_MAILBOX_POLL_FAILURE',
        `stage=parse reason=missing_requests_array`);
      logger.warn('GD compliance: mailbox poll response missing requests array');
      return;
    }

    if (requests.length === 0) {
      // Steady state — no audit (would generate 365 entries/year per MC
      // with no signal value). The summary loop continues.
      return;
    }

    logger.info('GD compliance: processing pending mailbox requests',
      { count: requests.length });

    // ── Fulfill each request ──
    let fulfilled = 0;
    let failed = 0;
    for (const request of requests) {
      // Defensive: skip malformed entries (missing id or framework).
      // C34's contract guarantees these fields, but a future GD bug or
      // version skew shouldn't crash the loop.
      if (!request || typeof request.id !== 'number' || typeof request.framework !== 'string') {
        failed++;
        auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_FAILURE',
          `stage=parse reason=malformed_request_entry entry=${JSON.stringify(request).slice(0, 100)}`);
        continue;
      }
      try {
        const ok = await this._pushOneFullReport(config, apiKey, request);
        if (ok) fulfilled++;
        else failed++;
      } catch (err) {
        // _pushOneFullReport catches its own errors and returns
        // false; this is defensive against unhandled escape.
        failed++;
        logger.error('GD compliance: full-report push unexpected error',
          { requestId: request.id, framework: request.framework, error: err.message });
        auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_FAILURE',
          `requestId=${request.id} framework=${request.framework} reason=unhandled_exception error=${err.message.slice(0, 200)}`);
      }
    }

    logger.info('GD compliance: mailbox processing complete',
      { total: requests.length, fulfilled, failed });
  }

  // Returns true on success (HTTP 202 OR HTTP 409 NOT_PENDING which is
  // the GD's idempotent signal that this request was already fulfilled
  // by a previous attempt whose response was lost in transit). Returns
  // false on terminal failure. Never throws under normal operation.
  async _pushOneFullReport(config, apiKey, request) {
    const requestId = request.id;
    const framework = request.framework;

    // ── Generate the full compliance report locally ──
    let fullReport;
    try {
      fullReport = generateComplianceReport(framework);
    } catch (genErr) {
      auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_FAILURE',
        `requestId=${requestId} framework=${framework} stage=generate reason=${genErr.message.slice(0, 200)}`);
      logger.warn('GD compliance: full-report generation failed',
        { requestId, framework, error: genErr.message });
      return false;
    }
    if (!fullReport) {
      // generateComplianceReport returns null for unknown framework keys.
      // The CISO requested a framework this MC doesn't have. The request
      // stays pending on the GD; a future "mark request failed" endpoint
      // could surface this state explicitly. For now, log + skip.
      auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_FAILURE',
        `requestId=${requestId} framework=${framework} stage=generate reason=unknown_framework_at_mc`);
      logger.warn('GD compliance: full-report request for unknown framework',
        { requestId, framework });
      return false;
    }

    // ── Build body + sign + POST with retry ──
    const bodyObj = { apiKey, requestId, framework, report: fullReport };
    const retryMax = Number.isInteger(config.retry_max) ? config.retry_max : 3;
    const backoffSeconds = Number.isInteger(config.retry_backoff_seconds)
      ? config.retry_backoff_seconds : 30;

    let attempt = 0;
    let lastError = null;
    while (attempt <= retryMax) {
      attempt++;
      try {
        // Sign fresh on each attempt — same timestamp-skew rationale
        // as the summary push.
        const dbSign = getDb();
        let signed;
        try {
          signed = signPushPayload(dbSign, bodyObj);
        } finally {
          dbSign.close();
        }
        const result = await this._signedFetchToGd(
          config.endpoint_url,
          '/api/ingest/compliance-reports?full=true',
          signed,
        );

        if (result.ok) {
          auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_SUCCESS',
            `requestId=${requestId} framework=${framework} attempt=${attempt} fingerprint=${signed.fingerprint}`);
          return true;
        }
        if (result.status === 409) {
          // GD says "request is no longer pending." This means a
          // previous attempt (this tick or a prior tick) succeeded but
          // the response was lost; the GD already has the fulfillment
          // recorded. Treat as success and audit explicitly so an
          // operator can correlate.
          auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_SUCCESS',
            `requestId=${requestId} framework=${framework} attempt=${attempt} fingerprint=${signed.fingerprint} note=already_fulfilled_on_gd`);
          return true;
        }
        // Other non-ok status — throw to trigger retry path
        lastError = new Error(`GD returned HTTP ${result.status}: ${result.bodyText.slice(0, 200)}`);
        lastError.status = result.status;
      } catch (err) {
        lastError = err;
      }
      if (attempt <= retryMax) {
        const backoffMs = backoffSeconds * 1000 * attempt;
        await new Promise((r) => setTimeout(r, backoffMs));
      }
    }

    auditLog(null, 'COMPLIANCE_FULL_REPORT_PUSH_FAILURE',
      `requestId=${requestId} framework=${framework} attempts=${attempt} reason=${(lastError?.message || 'unknown').slice(0, 200)}`);
    logger.warn('GD compliance: full-report push failed after retries',
      { requestId, framework, attempts: attempt, error: lastError?.message });
    return false;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // R3h (C9b): Leaderboard tick — separate cadence from metrics + compliance
  // ──────────────────────────────────────────────────────────────────────────
  //
  // Pushes the top-50 opted-in helpers' leaderboard summary to the GD on a
  // configurable cadence (default 15 min, gd_push_config.leaderboard_push_
  // cadence_minutes). The push is signed by the same Ed25519 contract as
  // the metrics and compliance pushes; the GD verifies and writes to its
  // regional_leaderboard table (lands in C10).
  //
  // PRIVACY INVARIANT I3 (OPT-IN PROPAGATION)
  //
  // helperPay.getLeaderboard(LEADERBOARD_PUSH_LIMIT) filters at the SQL
  // layer to leaderboard_opt_in = 1. The MC never sends an analyst's name
  // or score to the GD without that analyst having explicitly opted in
  // via their AC. The opt-in invariant therefore propagates from the
  // MC's users column through this push to the GD's regional_leaderboard
  // table — the GD has no path to see opted-out analysts.
  //
  // PRIVACY INVARIANT I4 (PSEUDONYM PREFERENCE)
  //
  // The payload's entry shape strips real names and forwards only
  // pseudonyms when the analyst has one. analyst_pseudonym is the
  // ONLY identifier crossing the wire — never name, never user_id,
  // never email. The GD's regional_leaderboard.analyst_pseudonym
  // column is sized for pseudonym strings, not user identifiers.
  //
  // PAYLOAD SHAPE
  //
  //   { apiKey, leaderboard: {
  //       pushed_at: ISO timestamp,
  //       entries: [
  //         { analyst_pseudonym, points, sessions_count, avg_rating }
  //       ]
  //     }
  //   }
  //
  // The pushed_at timestamp lets the GD detect stale-vs-fresh pushes
  // (a push older than the latest stored push for this MC can be
  // ignored if it arrives out of order).

  _scheduleNextLeaderboard(delayMs) {
    if (this.shuttingDown) return;
    this.leaderboardTimerId = setTimeout(() => this._leaderboardTick(), delayMs);
  }

  async _leaderboardTick() {
    if (this.shuttingDown) return;
    let cadenceMinutes = DEFAULT_LEADERBOARD_CADENCE_MINUTES;
    try {
      const config = this._readConfig();
      // Read cadence with defensive coercion: invalid values fall back
      // to the default. Same pattern as the metrics and compliance ticks.
      const raw = config?.leaderboard_push_cadence_minutes;
      if (Number.isInteger(raw) && raw >= 1 && raw <= MAX_LEADERBOARD_CADENCE_MINUTES) {
        cadenceMinutes = raw;
      }
      if (config && config.enabled === 1 && config.endpoint_url && config.api_key_encrypted) {
        await this._performLeaderboardPush(config);
      }
    } catch (err) {
      logger.error('GD leaderboard tick error', { error: err.message });
    } finally {
      // Always schedule the next leaderboard tick, even after errors.
      this._scheduleNextLeaderboard(cadenceMinutes * 60 * 1000);
    }
  }

  async _performLeaderboardPush(config) {
    // Active-key check — same gate as the metrics and compliance ticks.
    // No active signing key means the handshake hasn't completed; skip
    // cleanly with an info log and let the next tick retry.
    const dbCheck = getDb();
    let activeFingerprint;
    try {
      activeFingerprint = signingKeysSvc.getActiveFingerprint(dbCheck);
    } finally {
      dbCheck.close();
    }
    if (!activeFingerprint) {
      logger.info('GD leaderboard push: no active signing key; skipping tick',
        { handshake_status: config.handshake_status });
      return;
    }

    // Decrypt the api_key once for this tick. Never logged, never put
    // in audit detail.
    let apiKey;
    try {
      apiKey = this._decryptKey(config.api_key_encrypted);
    } catch (err) {
      logger.error('GD leaderboard push: api_key decrypt failed', { error: err.message });
      return;
    }

    // Build the payload. helperPay.getLeaderboard filters to opt-in,
    // active, role='analyst', balance > 0 at the SQL layer (privacy
    // invariant I1 + I3). Per privacy invariant I4, we forward only
    // analyst_pseudonym across the wire — never real names.
    let entries;
    try {
      const rows = helperPay.getLeaderboard(LEADERBOARD_PUSH_LIMIT);
      entries = rows
        .filter(r => r.pseudonym)  // Skip rows without a pseudonym (team
                                   // not configured for pseudonyms); the
                                   // GD-side surface requires a stable
                                   // identifier, and forwarding a real
                                   // name would violate I4. Operators
                                   // who want GD-side leaderboard
                                   // visibility must enable team
                                   // pseudonyms first.
        .map(r => ({
          analyst_pseudonym: r.pseudonym,
          points: r.points,
          sessions_count: r.sessions_count,
          avg_rating: r.avg_rating,
        }));
    } catch (err) {
      logger.error('GD leaderboard push: build failed', { error: err.message });
      return;
    }

    // Even when entries is empty (no opted-in analysts on this MC), we
    // still send the push — the GD needs to know "this MC has no
    // leaderboard right now" so it can clear stale entries from a
    // previous push. The ingest handler in C10 atomically replaces
    // this MC's rows in regional_leaderboard with the new entries.

    const bodyObj = {
      apiKey,
      leaderboard: {
        pushed_at: new Date().toISOString(),
        entries,
      },
    };
    const retryMax = Number.isInteger(config.retry_max) ? config.retry_max : 3;
    const backoffSeconds = Number.isInteger(config.retry_backoff_seconds)
      ? config.retry_backoff_seconds : 30;

    let attempt = 0;
    let lastError = null;
    while (attempt <= retryMax) {
      attempt++;
      try {
        // Sign on every attempt — same rationale as the metrics and
        // compliance ticks: GD's 5-minute timestamp skew window means
        // we need a fresh timestamp if backoff pushes us past it.
        const dbSign = getDb();
        let signed;
        try {
          signed = signPushPayload(dbSign, bodyObj);
        } finally {
          dbSign.close();
        }
        await this._postToGd(config.endpoint_url, '/api/ingest/leaderboard', signed);
        auditLog(null, 'GD_LEADERBOARD_PUSH_SUCCESS',
          `attempt=${attempt} entries=${entries.length} fingerprint=${signed.fingerprint}`);
        return true;
      } catch (err) {
        lastError = err;
        if (attempt <= retryMax) {
          const backoffMs = backoffSeconds * 1000 * attempt;
          await new Promise((r) => setTimeout(r, backoffMs));
        }
      }
    }

    auditLog(null, 'GD_LEADERBOARD_PUSH_FAILURE',
      `attempts=${attempt} reason=${(lastError?.message || 'unknown').slice(0, 200)}`);
    logger.warn('GD leaderboard push: failed after retries',
      { attempts: attempt, error: lastError?.message });
    return false;
  }
}

// Singleton instance — there's one push pipeline per Regional MC.
const gdPushService = new GdPushService();

module.exports = { gdPushService };
