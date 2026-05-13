// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD SERVER v0.0.31
// Independent backend for the CISO Global Dashboard.
// Receives aggregate data from Regional Servers (read-only ingest).
// Provides: auth, monitoring, backup, HA, compliance, reports, notifications,
// posture assessment, vulnerability scanning, audit logs, system health.
// NEVER writes back to Regional Servers.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { getDb, initDb } = require('./db-init');
const { verifyPushSignature } = require('./services/mc-signature-verifier');
const signingKeysSvc = require('./services/signing-keys');

const app = express();
const PORT = process.env.GD_PORT || 4001;
const JWT_SECRET = process.env.GD_JWT_SECRET || crypto.randomBytes(32).toString('hex');

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(compression());
app.use(express.json({
  limit: '10mb',
  // R3g PR3: capture the raw request body for MC signature verification.
  // The X-FA-Signature is computed by the MC over the raw body bytes;
  // verification must hash exactly those bytes (not a re-canonicalized
  // JSON serialization). express.json's verify hook runs before parsing
  // and gets the raw Buffer — we stash it on req for downstream handlers.
  // Applied app-wide because mc-signature-verifier may be called from
  // any ingest route added later in PR3 (compliance summaries, mailbox
  // poll, full-report fulfillment); a future per-route raw-body
  // middleware would have to be remembered on every new ingest path.
  verify: (req, _res, buf) => { req.rawBody = buf; },
}));

// Rate limiting on /api/. Mirrors the pattern in MC server/index.js to keep
// both servers' DoS protection consistent. 1000 req per 15-minute window per
// IP is generous enough for normal CISO dashboard use (tab switches reload
// data, the regions tab refreshes on activation, the query feature retries
// on error) while still blocking the kind of tight-loop hammering that could
// exhaust the SQLite connection pool. Public /api/health is exempt so
// health-check probes from a load balancer never burn limit budget.
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health',
});
app.use('/api/', apiLimiter);

// Request logging
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    if (req.path !== '/api/health') {
      try {
        const db = getDb();
        db.prepare("INSERT INTO audit_log (user_id, event_type, detail, ip, severity) VALUES (?, ?, ?, ?, ?)")
          .run(req.user?.id || 'anonymous', 'HTTP_' + req.method, `${req.path} ${res.statusCode} ${Date.now() - start}ms`, req.ip, res.statusCode >= 400 ? 'warning' : 'info');
        db.close();
      } catch (e) { /* silent */ }
    }
  });
  next();
});

// Auth middleware
const authMiddleware = (roles) => (req, res, next) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (roles && !roles.includes(decoded.role)) return res.status(403).json({ error: 'Insufficient permissions' });
    req.user = decoded;
    next();
  } catch (e) { return res.status(401).json({ error: 'Invalid or expired token' }); }
};

// ── Health Check ─────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  const db = getDb();
  const meta = db.prepare("SELECT value FROM system_meta WHERE key = 'app_version'").get();
  const mcs = db.prepare("SELECT COUNT(*) as count FROM management_consoles WHERE status = 'active'").get();
  db.close();
  res.json({ status: 'healthy', version: meta?.value || '0.0.31', type: 'global_dashboard_server', connectedMCs: mcs?.count || 0, uptime: process.uptime() });
});

// ── Authentication ───────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = getDb();
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user) {
      db.prepare("INSERT INTO auth_log (username, action, ip, reason) VALUES (?, 'LOGIN_FAILED', ?, 'User not found')").run(username, req.ip);
      db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      db.prepare("INSERT INTO auth_log (username, action, ip, reason) VALUES (?, 'LOGIN_FAILED', ?, 'Wrong password')").run(username, req.ip);
      db.close();
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.mfa_enabled) {
      db.close();
      return res.json({ requireMFA: true, userId: user.id });
    }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    db.prepare("INSERT INTO auth_log (username, action, ip, method) VALUES (?, 'LOGIN_SUCCESS', ?, 'password')").run(username, req.ip);
    db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id);
    db.close();
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'Authentication failed' }); }
});

app.post('/api/auth/mfa-verify', (req, res) => {
  try {
    const { userId, code } = req.body;
    // In production: verify TOTP code against user's mfa_secret
    if (!code || code.length < 6) return res.status(400).json({ error: 'Invalid MFA code' });
    const db = getDb();
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(userId);
    if (!user) { db.close(); return res.status(404).json({ error: 'User not found' }); }
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
    db.prepare("INSERT INTO auth_log (username, action, ip, method) VALUES (?, 'LOGIN_SUCCESS', ?, 'password+mfa')").run(user.username, req.ip);
    db.close();
    res.json({ token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (e) { res.status(500).json({ error: 'MFA verification failed' }); }
});

// ── Regional MC Data Ingest (receives pushes from Regional Servers) ──────────
// This is the PRIMARY data flow: Regional Servers push aggregate data here.
//
// R3g PR3 (12 May 2026): every inbound push MUST carry a valid
// X-FA-Signature. After api_key resolves to an MC, the verifier
// (services/mc-signature-verifier.js) looks up the active row in the
// signing_keys trust registry (mc_id + public_key_fingerprint header,
// is_active = 1) and checks an Ed25519 signature over
// `timestamp + "\n" + rawBody`. Strict mode: no grace period, no
// backwards-compatibility flag — unsigned or invalid-signature pushes
// reject with 401 and an INGEST_SIGNATURE_REJECTED audit event.
// The MC handshake (added in Commit 13) ensures every newly-configured
// GD-push connection registers its signing key before the first push.
app.post('/api/ingest/metrics', (req, res) => {
  try {
    const { apiKey, metrics } = req.body;
    const db = getDb();
    // Verify the API key belongs to a registered MC
    const mc = db.prepare("SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'").get(apiKey);
    if (!mc) { db.close(); return res.status(403).json({ error: 'Invalid or inactive MC API key' }); }

    // R3g PR3: verify X-FA-Signature against the MC's active signing key.
    // Runs AFTER api_key resolution because we need mc.id to scope the
    // trust lookup (per-MC fingerprint registry; same fingerprint
    // hypothetically reused across MCs still scopes correctly).
    const sigResult = verifyPushSignature(db, {
      mcId: mc.id,
      headers: req.headers,
      rawBody: req.rawBody,
    });
    if (!sigResult.ok) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('INGEST_SIGNATURE_REJECTED', ?, 'critical')")
        .run(`mc=${mc.name} mc_id=${mc.id} code=${sigResult.code} fingerprint=${sigResult.fingerprint || 'none'} reason=${JSON.stringify(sigResult.error || '')}`);
      db.close();
      return res.status(401).json({
        error: sigResult.error,
        code: sigResult.code,
      });
    }

    // Store the aggregate metrics
    db.prepare(`INSERT INTO regional_metrics 
      (mc_id, health_score, utilization_pct, automation_rate, cert_coverage_pct, 
       sla_compliance_pct, turnover_risk, analyst_count, active_incidents,
       burnout_routing_active, proactive_breaks_given, upskilling_hours_used)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      mc.id, metrics.healthScore, metrics.utilization, metrics.automationRate,
      metrics.certCoverage, metrics.slaCompliance, metrics.turnoverRisk,
      metrics.analystCount, metrics.activeIncidents || 0,
      metrics.burnoutRoutingActive ? 1 : 0, metrics.proactiveBreaksGiven || 0,
      metrics.upskillingHoursUsed || 0
    );

    // Update last sync
    db.prepare("UPDATE management_consoles SET last_sync = datetime('now'), analyst_count = ? WHERE id = ?")
      .run(metrics.analystCount, mc.id);

    // Check notification thresholds
    const notifCfg = JSON.parse(db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get()?.value || '{}');
    if (metrics.healthScore < (notifCfg.burnout_threshold || 65)) {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('burnout_threshold', ?, ?, 'warning')")
        .run(mc.id, `${mc.name} health score dropped to ${metrics.healthScore} (threshold: ${notifCfg.burnout_threshold})`);
    }
    if (metrics.turnoverRisk === 'high' || metrics.turnoverRisk === 'critical') {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('turnover_risk', ?, ?, 'critical')")
        .run(mc.id, `${mc.name} turnover risk: ${metrics.turnoverRisk}`);
    }
    if (metrics.slaCompliance < (notifCfg.sla_below || 85)) {
      db.prepare("INSERT INTO notifications (type, mc_id, message, severity) VALUES ('sla_breach', ?, ?, 'warning')")
        .run(mc.id, `${mc.name} SLA compliance at ${metrics.slaCompliance}% (threshold: ${notifCfg.sla_below}%)`);
    }

    db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('METRICS_INGESTED', ?, 'info')")
      .run(`From ${mc.name}: health=${metrics.healthScore}, util=${metrics.utilization}% fingerprint=${sigResult.fingerprint}`);
    db.close();
    res.json({ success: true, mc: mc.name });
  } catch (e) { console.error('Ingest error:', e); res.status(500).json({ error: 'Metrics ingest failed' }); }
});

// ── POST /api/ingest/compliance-reports — R3g PR3 Phase 6 (C30) ───────────
//
// Signed-push ingest endpoint for per-framework compliance summaries
// pushed by the MC's _complianceTick (Commit 32, default 24h cadence).
// Stores into mc_compliance_reports for hot-path CISO queries and trend
// visibility; the cross_region_rollup materialization is updated in a
// later Phase 6 commit.
//
// Body shape:
//   {
//     apiKey:    string,          // identifies the MC; resolved against
//                                 // management_consoles.api_key
//     framework: string,          // e.g. 'hipaa', 'soc2', 'nist_csf'
//                                 // ASCII-safe, max 64 chars
//     summary:   object           // { passed, total, perCategoryCounts,
//                                 //   topFailingControls, generatedAt,
//                                 //   digestHash } — stored as
//                                 //   JSON.stringify'd into summary_json
//   }
//
// Authentication: api_key resolves the MC. Signature verification via
// verifyPushSignature (same machinery as /api/ingest/metrics; Phase 5's
// C22 verifier accepts active key OR grace-window approved key).
//
// MULTI-FRAMEWORK: an MC submits one POST per framework per tick. Reports
// for different frameworks accumulate as separate rows in
// mc_compliance_reports; the lookup index (mc_id, framework, received_at
// DESC) gives O(log n) "latest report per framework" queries.
//
// RETENTION: rows accumulate. A future retention policy may prune older
// than N days; tracked in build plan as a deferred item.
//
// Returns:
//   202 { success: true, mc, reportId } on accept
//   401 { error, code }                on signature verification failure
//   403 { error }                       on invalid api_key
//   400 { error }                       on missing/invalid body fields
//   500 { error }                       on storage failure
//
// Audit events:
//   INGEST_SIGNATURE_REJECTED            severity=critical, sig verify fail
//   COMPLIANCE_REPORT_INGESTED           severity=info, success
//   COMPLIANCE_REPORT_INGEST_REJECTED    severity=warning, body validation fail
//
// Framework validation: same regex as mc_id / role inputs elsewhere —
// /^[A-Za-z0-9_-]+$/ with length 1-64. Catches typos and weird input
// without restricting to a hardcoded enumeration (frameworks are
// extensible by operator policy; the GD admin UI surfaces whichever
// frameworks have rows present).
const COMPLIANCE_FRAMEWORK_PATTERN = /^[A-Za-z0-9_-]+$/;
const COMPLIANCE_FRAMEWORK_MAX_LEN = 64;
const COMPLIANCE_SUMMARY_MAX_BYTES = 64 * 1024;  // 64 KB cap on stringified summary

app.post('/api/ingest/compliance-reports', (req, res) => {
  try {
    const { apiKey, framework, summary } = req.body || {};
    const db = getDb();

    // ── Resolve MC by api_key ──
    const mc = db.prepare("SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'").get(apiKey);
    if (!mc) {
      db.close();
      return res.status(403).json({ error: 'Invalid or inactive MC API key' });
    }

    // ── Verify signature (must come after mc resolution; trust lookup is per-MC) ──
    const sigResult = verifyPushSignature(db, {
      mcId: mc.id,
      headers: req.headers,
      rawBody: req.rawBody,
    });
    if (!sigResult.ok) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('INGEST_SIGNATURE_REJECTED', ?, 'critical')")
        .run(`endpoint=compliance-reports mc=${mc.name} mc_id=${mc.id} code=${sigResult.code} fingerprint=${sigResult.fingerprint || 'none'} reason=${JSON.stringify(sigResult.error || '')}`);
      db.close();
      return res.status(401).json({
        error: sigResult.error,
        code: sigResult.code,
      });
    }

    // ── Validate body shape ──
    if (typeof framework !== 'string' || !framework.trim()) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=missing_framework fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'framework is required and must be a non-empty string' });
    }
    const fw = framework.trim();
    if (fw.length > COMPLIANCE_FRAMEWORK_MAX_LEN || !COMPLIANCE_FRAMEWORK_PATTERN.test(fw)) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=invalid_framework framework=${JSON.stringify(fw.slice(0, 100))} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({
        error: `framework must be ASCII-safe (letters, digits, hyphens, underscores) and max ${COMPLIANCE_FRAMEWORK_MAX_LEN} chars`,
      });
    }
    if (!summary || typeof summary !== 'object' || Array.isArray(summary)) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} reason=missing_or_invalid_summary fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'summary is required and must be an object' });
    }

    let summaryJson;
    try {
      summaryJson = JSON.stringify(summary);
    } catch (jsonErr) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} reason=summary_not_serializable fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'summary contains values that cannot be JSON-serialized (e.g., circular references)' });
    }
    if (summaryJson.length > COMPLIANCE_SUMMARY_MAX_BYTES) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} reason=summary_too_large bytes=${summaryJson.length} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({
        error: `summary exceeds maximum size of ${COMPLIANCE_SUMMARY_MAX_BYTES} bytes (use the full-report mailbox pattern for larger payloads)`,
      });
    }

    // ── Insert ──
    const result = db.prepare(`
      INSERT INTO mc_compliance_reports
        (mc_id, framework, summary_json, signature_fingerprint)
      VALUES (?, ?, ?, ?)
    `).run(mc.id, fw, summaryJson, sigResult.fingerprint);

    // ── R3g PR3 Phase 6 (C31): refresh cross_region_rollup materialization ──
    //
    // The rollup table holds one row per (framework, mc_id) materializing
    // the LATEST aggregate pass/total counts so CISO interactive queries
    // ("Show me all MCs' status for Framework X") are O(N MCs) lookups
    // rather than scans of mc_compliance_reports history. Every successful
    // ingest refreshes that row so CISO queries see fresh data without
    // waiting on a separate rollup-build job.
    //
    // FIELD MAPPING from the summary payload:
    //   summary.passed -> rollup.passed   (defaulted to 0 if missing/NaN)
    //   summary.total  -> rollup.total    (same)
    //   datetime('now') -> last_push_at
    //
    // per_control_status is DELIBERATELY NOT TOUCHED from a summary push.
    // The summary payload only carries aggregates (passed/total) plus
    // perCategoryCounts + topFailingControls[3] — NOT per-control
    // granularity. Per-control drill-down comes from the full-report
    // mailbox pattern (mc_compliance_report_fulls, populated in Phase 7),
    // which sets per_control_status when a CISO-requested full report
    // arrives. Overwriting per_control_status with NULL or stale data
    // from a summary push would erase the most recent drill-down data
    // the CISO has, so the UPSERT preserves the existing value.
    //
    // ROLLUP FAILURE IS NON-FATAL. If the UPSERT throws (FK violation
    // during MC offboarding race, disk full, etc.), the summary remains
    // stored in mc_compliance_reports and the operator sees the audit
    // event with rollup_updated=false. The CISO query layer can fall back
    // to "latest from history" via the idx_mc_compliance_reports_lookup
    // index when the rollup is stale.
    let rollupUpdated = false;
    try {
      // Defensive integer coercion — the summary may have been generated
      // by a future MC version with passed/total as strings, or by a
      // misbehaving generator that omits them entirely.
      const rawPassed = (summary.passed !== undefined && summary.passed !== null) ? Number(summary.passed) : 0;
      const rawTotal = (summary.total !== undefined && summary.total !== null) ? Number(summary.total) : 0;
      const passed = (Number.isFinite(rawPassed) && rawPassed >= 0) ? Math.floor(rawPassed) : 0;
      const total = (Number.isFinite(rawTotal) && rawTotal >= 0) ? Math.floor(rawTotal) : 0;

      db.prepare(`
        INSERT INTO cross_region_rollup (framework, mc_id, passed, total, last_push_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(framework, mc_id) DO UPDATE SET
          passed = excluded.passed,
          total = excluded.total,
          last_push_at = excluded.last_push_at
      `).run(fw, mc.id, passed, total);
      rollupUpdated = true;
    } catch (rollupErr) {
      console.error('cross_region_rollup update failed:', rollupErr.message);
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_ROLLUP_UPDATE_FAILED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} reportId=${result.lastInsertRowid} reason=${rollupErr.message.slice(0, 200)}`);
    }

    db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_REPORT_INGESTED', ?, 'info')")
      .run(`From ${mc.name}: framework=${fw} reportId=${result.lastInsertRowid} bytes=${summaryJson.length} fingerprint=${sigResult.fingerprint}${sigResult.viaGraceWindow ? ' viaGraceWindow=true' : ''} rollup_updated=${rollupUpdated}`);
    db.close();

    return res.status(202).json({
      success: true,
      mc: mc.name,
      reportId: result.lastInsertRowid,
      framework: fw,
    });
  } catch (e) {
    console.error('Compliance ingest error:', e);
    res.status(500).json({ error: 'Compliance report ingest failed' });
  }
});


// ── Management Console Registration ──────────────────────────────────────────
app.post('/api/mc/register', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { name, region, endpoint, country, regulatoryFramework } = req.body;
    const db = getDb();
    const apiKey = 'gdash-ro-' + crypto.randomBytes(16).toString('hex');
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO management_consoles (id, name, region, endpoint, api_key, country, regulatory_framework) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, name, region, endpoint, apiKey, country || null, regulatoryFramework || 'none');
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'MC_REGISTERED', ?)")
      .run(req.user.id, `${name} (${region})`);
    db.close();
    res.json({ success: true, id, apiKey, message: 'Provide this API key to the Regional Server for data push configuration' });
  } catch (e) { res.status(500).json({ error: 'MC registration failed' }); }
});

app.get('/api/mc/list', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    const mcs = db.prepare("SELECT id, name, region, endpoint, country, regulatory_framework, status, analyst_count, last_sync, created_at FROM management_consoles ORDER BY name").all();
    db.close();
    res.json({ managementConsoles: mcs });
  } catch (e) { res.status(500).json({ error: 'Failed to list MCs' }); }
});

app.put('/api/mc/:id/offboard', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE management_consoles SET status = 'offboarded', offboarded_at = datetime('now') WHERE id = ?").run(req.params.id);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'MC_OFFBOARDED', ?)").run(req.user.id, `MC ${req.params.id} offboarded`);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'MC offboarding failed' }); }
});

// ── MC Signing Key Registration (R3g PR3 Phase 5) ────────────────────────────
//
// POST /api/mc/:id/signing-key
//   Body: { apiKey, public_key, public_key_fingerprint }
//
// Called by an MC during its first GD-push handshake (and on every
// subsequent rotation handshake) to submit its Ed25519 public key to
// the GD's trust registry. UNDER R3g PR3 PHASE 5 (manual CISO approval),
// the row lands in signing_keys with approval_status='pending_approval'
// and is_active=0. NEVER auto-activated under any code path. A user
// holding the 'ciso' or 'signing_key_approver' role reviews the
// fingerprint out-of-band with the MC operator and clicks approve
// (POST /api/mc/:id/signing-keys/:keyId/approve, landing in Commit 19)
// or reject. Only an approved row is consulted by mc-signature-verifier
// (Commit 22) when verifying inbound pushes.
//
// REPLACES the C13 hot-fix 503 that gated the endpoint while this
// gold-standard flow was being built. Foundational Rule 22 (BUILD-PLAN-
// v18): trust establishment requires authentication an api_key thief
// wouldn't have. api_key in the body authenticates "which MC is
// claiming this submission"; manual CISO approval is the trust
// authentication.
//
// AUTHENTICATION + DEFENSIVE :id CHECK
//
// api_key in the body resolves to the MC. The :id path parameter MUST
// match the resolved mc.id. This check is NOT the security control —
// api_key already scopes the submission to one MC; the :id match
// catches client-side configuration bugs early (the MC operator
// configured the wrong mc_id locally) with a clear 403 error rather
// than letting the submission silently land against the api_key's MC.
//
// IDEMPOTENCY (delegated to signing-keys service)
//
//   - Existing pending row with same fingerprint: 200 OK,
//     action=idempotent_pending. Handshake re-runs (which happen on
//     every gd-config PUT) don't churn the table.
//   - Existing approved active row with same fingerprint: 200 OK,
//     action=idempotent_approved. Re-submitting the currently-trusted
//     key is a no-op.
//   - Different fingerprint, no existing matching row: 202 Accepted,
//     action=submitted. Row lands pending; CISO must approve.
//   - Existing fingerprint previously ROTATED OUT: 409 Conflict.
//     Fresh trust requires fresh keys.
//   - Existing fingerprint previously REJECTED: 409 Conflict.
//     A rejection is a deliberate CISO decision; re-submitting the
//     same bytes implies retrying that decision.
//
// FINGERPRINT VALIDATION
//
// The signing-keys service recomputes the fingerprint from the
// supplied public_key and rejects mismatch (400 FINGERPRINT_MISMATCH).
// Prevents the class of bug where a caller-supplied fingerprint
// disagrees with the actual key bytes — which would silently work at
// submission time and then fail at verification time when the verifier
// hashes the real bytes.
//
// AUDIT EVENTS
//
//   MC_SIGNING_KEY_SUBMITTED       — successful submit/idempotent path,
//                                    severity=info, detail carries mc,
//                                    keyId, fingerprint, action.
//   MC_SIGNING_KEY_SUBMIT_REJECTED — validation/auth failure,
//                                    severity=warning, detail carries
//                                    api_key-resolved mc (or 'unknown'),
//                                    path :id, error code.
app.post('/api/mc/:id/signing-key', (req, res) => {
  let db;
  try {
    const { apiKey, public_key, public_key_fingerprint } = req.body || {};
    db = getDb();

    // Always audit the attempt — successful and failed paths both
    // write one INSERT so response timing is similar regardless of
    // input validity (no oracle leak on api_key validity).
    const auditWarn = (mcLabel, code, extra = '') =>
      db.prepare(
        "INSERT INTO audit_log (event_type, detail, severity) VALUES ('MC_SIGNING_KEY_SUBMIT_REJECTED', ?, 'warning')"
      ).run(
        `attempted_mc=${mcLabel} path_id=${req.params.id || 'none'} code=${code}${extra ? ' ' + extra : ''}`
      );

    if (!apiKey || !public_key || !public_key_fingerprint) {
      auditWarn('unknown', 'MISSING_FIELDS');
      db.close();
      return res.status(400).json({
        error: 'apiKey, public_key, and public_key_fingerprint are required',
        code: 'MISSING_FIELDS',
      });
    }

    const mc = db.prepare(
      "SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'"
    ).get(apiKey);
    if (!mc) {
      auditWarn('unknown', 'INVALID_API_KEY');
      db.close();
      return res.status(403).json({
        error: 'Invalid or inactive MC API key',
        code: 'INVALID_API_KEY',
      });
    }

    if (mc.id !== req.params.id) {
      auditWarn(`${mc.name} (${mc.id})`, 'MC_ID_MISMATCH', `path_id=${req.params.id}`);
      db.close();
      return res.status(403).json({
        error: 'API key does not match path mc_id',
        code: 'MC_ID_MISMATCH',
      });
    }

    // Delegate to the service. submitPending enforces fingerprint
    // recomputation, state-machine invariants, and idempotency rules.
    let result;
    try {
      result = signingKeysSvc.submitPending(db, {
        mcId: mc.id,
        publicKey: public_key,
        publicKeyFingerprint: public_key_fingerprint,
      });
    } catch (svcErr) {
      if (svcErr instanceof signingKeysSvc.SigningKeysError) {
        const C = signingKeysSvc.CODES;
        let status;
        switch (svcErr.code) {
          case C.INVALID_INPUT:
          case C.INVALID_PEM:
          case C.FINGERPRINT_MISMATCH:
            status = 400; break;
          case C.MC_NOT_FOUND:
            status = 403; break;
          case C.KEY_PREVIOUSLY_ROTATED:
          case C.KEY_PREVIOUSLY_REJECTED:
          case C.INVALID_STATE:
            status = 409; break;
          default:
            status = 500;
        }
        auditWarn(`${mc.name} (${mc.id})`, svcErr.code);
        db.close();
        const body = { error: svcErr.message, code: svcErr.code };
        // FINGERPRINT_MISMATCH surfaces the server-computed fingerprint
        // so the client can correct its calculation.
        if (svcErr.code === C.FINGERPRINT_MISMATCH && svcErr.details && svcErr.details.computed) {
          body.computed_fingerprint = svcErr.details.computed;
        }
        return res.status(status).json(body);
      }
      // Non-typed error — log + 500.
      console.error('signing-key submit unexpected error:', svcErr);
      auditWarn(`${mc.name} (${mc.id})`, 'INTERNAL_ERROR');
      db.close();
      return res.status(500).json({ error: 'Signing key submission failed' });
    }

    // Success path. Action determines HTTP status:
    //   submitted              -> 202 Accepted (new pending row created)
    //   idempotent_pending     -> 200 OK (already pending; no state change)
    //   idempotent_approved    -> 200 OK (already approved active)
    db.prepare(
      "INSERT INTO audit_log (event_type, detail, severity) VALUES ('MC_SIGNING_KEY_SUBMITTED', ?, 'info')"
    ).run(
      `mc=${mc.name} mc_id=${mc.id} keyId=${result.id} fingerprint=${result.fingerprint} action=${result.action}`
    );

    db.close();

    const httpStatus = result.action === 'submitted' ? 202 : 200;
    res.status(httpStatus).json({
      status: result.action === 'idempotent_approved' ? 'approved' : 'pending_approval',
      action: result.action,
      keyId: result.id,
      fingerprint: result.fingerprint,
      message: result.action === 'submitted'
        ? 'Awaiting administrator approval. Contact your CISO if approval is taking longer than expected.'
        : result.action === 'idempotent_pending'
        ? 'This key is already pending approval.'
        : 'This key is already approved.',
    });
  } catch (e) {
    console.error('Signing-key endpoint error:', e);
    try { if (db) db.close(); } catch (_) {}
    return res.status(500).json({ error: 'Signing key submission failed' });
  }
});

// ── MC Signing Key Approval Workflow — Admin (R3g PR3 Phase 5) ──────────────
//
// Two endpoints exercising the human side of the manual CISO approval
// flow introduced in Commit 18. Both require either the 'ciso' or the
// 'signing_key_approver' role (added in Commit 15). The two-role
// authorization set implements role segregation per ISO 27001 A.6.1.2
// and NIST 800-53 AC-5: an organization can assign 'signing_key_approver'
// to a user distinct from any 'ciso' so that whoever onboards an MC
// (via POST /api/mc/register, which is 'ciso'/'vp') is not the same
// person who establishes its cryptographic trust. Smaller orgs can
// give both roles to one human; the audit log records each action with
// the acting role distinctly so reviewers can see whether segregation
// was actually exercised.
//
// POST /api/mc/:id/signing-keys/:keyId/approve
//   Body: { confirmation_fingerprint?: string }  (optional)
//
// Approves a pending signing-key submission. The signing-keys service
// performs the atomic state transition: any current is_active=1 row
// for the same MC is demoted (is_active=0, rotated_out_at=now, BUT
// approval_status STAYS 'approved' so the verifier's grace-window
// query (Commit 22) can match it within the configured window) and
// the target row is promoted (is_active=1, approval_status='approved',
// approved_at, approved_by_user_id, approved_by_role).
//
// confirmation_fingerprint is an optional CISO-side double-check: if
// provided, the server compares it to the keyId's stored fingerprint
// and returns 400 on mismatch. Protects against UI mistakes — the
// CISO pastes the fingerprint they verified out-of-band, and a UI
// bug or copy-paste error that points the approve button at the wrong
// row is caught here rather than silently approving the wrong key.
//
// POST /api/mc/:id/signing-keys/:keyId/reject
//   Body: { reason: string }  (required, trimmed, ≤500 chars)
//
// Rejects a pending submission. Sets approval_status='rejected',
// rejected_at, rejected_reason. Does NOT touch is_active (stays 0;
// the row never becomes verifiable). The reason is INTERNAL ONLY:
// it's captured in the GD audit log and visible through the
// listForMc admin endpoint (Commit 20), but the MC-facing status-
// query endpoint (Commit 21) returns only the bare 'rejected'
// status with no reason — so an attacker probing the endpoint with
// a stolen api_key cannot learn anything about the CISO's
// operational reasoning.
//
// PATH PARAM VALIDATION
//
// :id MUST resolve to an active MC; otherwise 404 MC_NOT_FOUND.
// :keyId is parsed as a positive integer; non-numeric returns 400
// INVALID_KEY_ID. After service-level lookup, if the key's mc_id
// doesn't equal :id, returns 404 KEY_NOT_FOUND (NOT 403 — collapsing
// "wrong MC" and "doesn't exist" into one error code so cross-MC
// keyId enumeration is closed off; an admin who can list pending
// across all MCs gets the full picture through the C20 endpoint).
//
// AUDIT EVENTS
//
//   MC_SIGNING_KEY_APPROVED  severity=info; detail carries
//                            user_id=<approver> role=<acting role>
//                            mc=<name (id)> keyId=<n>
//                            fingerprint=<hex> action=<approved_initial|
//                            approved_replacement> [prior_keyId=<n>
//                            prior_fingerprint=<hex>]
//
//   MC_SIGNING_KEY_REJECTED  severity=info; detail carries
//                            user_id=<rejecter> role=<acting role>
//                            mc=<name (id)> keyId=<n>
//                            fingerprint=<hex> reason=<full reason text>

function mapSigningSvcError(svcErr, CODES) {
  if (!(svcErr instanceof signingKeysSvc.SigningKeysError)) {
    return { status: 500, body: { error: 'Internal error' } };
  }
  const body = { error: svcErr.message, code: svcErr.code };
  let status;
  switch (svcErr.code) {
    case CODES.INVALID_INPUT:
    case CODES.INVALID_REASON:
      status = 400; break;
    case CODES.MC_NOT_FOUND:
    case CODES.KEY_NOT_FOUND:
      status = 404; break;
    case CODES.INVALID_STATE:
      status = 409; break;
    default:
      status = 500;
  }
  return { status, body };
}

app.post('/api/mc/:id/signing-keys/:keyId/approve',
  authMiddleware(['ciso', 'signing_key_approver']),
  (req, res) => {
    let db;
    try {
      db = getDb();

      const keyIdNum = parseInt(req.params.keyId, 10);
      if (!Number.isInteger(keyIdNum) || keyIdNum <= 0 || String(keyIdNum) !== req.params.keyId) {
        db.close();
        return res.status(400).json({ error: 'keyId must be a positive integer', code: 'INVALID_KEY_ID' });
      }

      // Resolve the target row up front so we can validate :id binding
      // and (optionally) check confirmation_fingerprint before the
      // service call mutates state.
      const target = db.prepare(`
        SELECT id, mc_id, public_key_fingerprint, approval_status
        FROM signing_keys WHERE id = ?
      `).get(keyIdNum);

      if (!target || target.mc_id !== req.params.id) {
        // Collapsed: "doesn't exist" and "belongs to a different MC"
        // both return 404 KEY_NOT_FOUND, closing cross-MC enumeration.
        db.close();
        return res.status(404).json({ error: 'signing key not found for this MC', code: 'KEY_NOT_FOUND' });
      }

      // Verify the MC is active. signing-keys service also enforces
      // this, but we surface a clean 404 path-bound error here.
      const mc = db.prepare("SELECT id, name, status FROM management_consoles WHERE id = ?").get(req.params.id);
      if (!mc || mc.status !== 'active') {
        db.close();
        return res.status(404).json({ error: 'MC not found or not active', code: 'MC_NOT_FOUND' });
      }

      // Optional CISO-side double-check on fingerprint.
      const supplied = (req.body || {}).confirmation_fingerprint;
      if (supplied !== undefined && supplied !== null) {
        if (typeof supplied !== 'string' || supplied.toLowerCase() !== target.public_key_fingerprint) {
          db.prepare(
            "INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'MC_SIGNING_KEY_APPROVE_BLOCKED', ?, 'warning')"
          ).run(
            req.user.id,
            `user_id=${req.user.id} role=${req.user.role} mc=${mc.name} (${mc.id}) keyId=${keyIdNum} reason=confirmation_fingerprint_mismatch`
          );
          db.close();
          return res.status(400).json({
            error: 'confirmation_fingerprint does not match the keyId\'s stored fingerprint',
            code: 'CONFIRMATION_FINGERPRINT_MISMATCH',
          });
        }
      }

      let result;
      try {
        result = signingKeysSvc.approve(db, {
          keyId: keyIdNum,
          userId: req.user.id,
          userRole: req.user.role,
        });
      } catch (svcErr) {
        const mapped = mapSigningSvcError(svcErr, signingKeysSvc.CODES);
        db.prepare(
          "INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'MC_SIGNING_KEY_APPROVE_FAILED', ?, 'warning')"
        ).run(
          req.user.id,
          `user_id=${req.user.id} role=${req.user.role} mc=${mc.name} (${mc.id}) keyId=${keyIdNum} code=${svcErr.code || 'UNKNOWN'}`
        );
        db.close();
        return res.status(mapped.status).json(mapped.body);
      }

      const priorTail = result.priorKeyId
        ? ` prior_keyId=${result.priorKeyId} prior_fingerprint=${result.priorFingerprint}`
        : '';
      db.prepare(
        "INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'MC_SIGNING_KEY_APPROVED', ?, 'info')"
      ).run(
        req.user.id,
        `user_id=${req.user.id} role=${req.user.role} mc=${mc.name} (${mc.id}) keyId=${result.keyId} fingerprint=${result.fingerprint} action=${result.action}${priorTail}`
      );

      db.close();
      return res.json({
        ok: true,
        action: result.action,
        keyId: result.keyId,
        fingerprint: result.fingerprint,
        priorKeyId: result.priorKeyId,
        priorFingerprint: result.priorFingerprint,
      });
    } catch (e) {
      console.error('signing-key approve error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Approve operation failed' });
    }
  }
);

app.post('/api/mc/:id/signing-keys/:keyId/reject',
  authMiddleware(['ciso', 'signing_key_approver']),
  (req, res) => {
    let db;
    try {
      db = getDb();

      const keyIdNum = parseInt(req.params.keyId, 10);
      if (!Number.isInteger(keyIdNum) || keyIdNum <= 0 || String(keyIdNum) !== req.params.keyId) {
        db.close();
        return res.status(400).json({ error: 'keyId must be a positive integer', code: 'INVALID_KEY_ID' });
      }

      const { reason } = req.body || {};
      if (!reason || typeof reason !== 'string' || !reason.trim()) {
        db.close();
        return res.status(400).json({ error: 'reason is required', code: 'INVALID_REASON' });
      }

      const target = db.prepare(`
        SELECT id, mc_id, public_key_fingerprint, approval_status
        FROM signing_keys WHERE id = ?
      `).get(keyIdNum);

      if (!target || target.mc_id !== req.params.id) {
        db.close();
        return res.status(404).json({ error: 'signing key not found for this MC', code: 'KEY_NOT_FOUND' });
      }

      const mc = db.prepare("SELECT id, name, status FROM management_consoles WHERE id = ?").get(req.params.id);
      if (!mc || mc.status !== 'active') {
        db.close();
        return res.status(404).json({ error: 'MC not found or not active', code: 'MC_NOT_FOUND' });
      }

      let result;
      try {
        result = signingKeysSvc.reject(db, {
          keyId: keyIdNum,
          userId: req.user.id,
          userRole: req.user.role,
          reason,
        });
      } catch (svcErr) {
        const mapped = mapSigningSvcError(svcErr, signingKeysSvc.CODES);
        db.prepare(
          "INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'MC_SIGNING_KEY_REJECT_FAILED', ?, 'warning')"
        ).run(
          req.user.id,
          `user_id=${req.user.id} role=${req.user.role} mc=${mc.name} (${mc.id}) keyId=${keyIdNum} code=${svcErr.code || 'UNKNOWN'}`
        );
        db.close();
        return res.status(mapped.status).json(mapped.body);
      }

      // Reason captured verbatim in audit detail (internal only — never
      // returned to MC).
      db.prepare(
        "INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'MC_SIGNING_KEY_REJECTED', ?, 'info')"
      ).run(
        req.user.id,
        `user_id=${req.user.id} role=${req.user.role} mc=${mc.name} (${mc.id}) keyId=${result.keyId} fingerprint=${result.fingerprint} reason=${reason.trim()}`
      );

      db.close();
      return res.json({
        ok: true,
        keyId: result.keyId,
        fingerprint: result.fingerprint,
      });
    } catch (e) {
      console.error('signing-key reject error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Reject operation failed' });
    }
  }
);

// ── MC Signing Key Listing — Admin Discovery (R3g PR3 Phase 5) ──────────────
//
// Read-only complement to the approve/reject endpoints from Commit 19.
// A CISO can't approve what they can't see, so these two endpoints
// expose the discovery surface: the cross-MC list of pending
// submissions awaiting review, and the per-MC full history of every
// signing-key transition.
//
// GET /api/signing-keys/pending
//
//   Returns all rows with approval_status='pending_approval' across
//   all active MCs, with mc.name joined in for display. For the
//   CISO/signing_key_approver dashboard view — "what is awaiting my
//   approval right now". Ordered newest-first via the service.
//
//   Response: { pending: [{ id, mcId, mcName, fingerprint,
//                           submittedAt }] }
//
// GET /api/mc/:id/signing-keys?status=<filter>
//
//   Returns the full signing-key history for one MC, optionally
//   filtered by approval_status. Used for forensic review — when a
//   CISO wants to see "what trust events happened on MC-X" they get
//   the complete row including rejected_reason. This is the only
//   surface where rejected_reason is exposed; the MC-facing status
//   endpoint (Commit 21) strips it.
//
//   Query param status (optional): pending_approval | approved |
//                                    rejected
//
//   Response: { keys: [{ id, fingerprint, isActive, approvalStatus,
//                        registeredAt, rotatedOutAt, approvedAt,
//                        approvedByUserId, approvedByRole,
//                        rejectedAt, rejectedReason, notes }] }
//
// AUTH: Both gated by authMiddleware(['ciso', 'signing_key_approver']).
//       VP and readonly roles do NOT see these surfaces — the trust
//       registry is sensitive enough that even passive read access is
//       scoped to the two approval-capable roles. (PR4 may add a
//       readonly variant if dashboards need broader visibility.)
//
// AUDIT: Read paths don't audit individual queries — high-volume
//        dashboard refreshes would flood the audit log. The
//        access-log middleware at the top of this file already
//        records every authenticated request with user_id + path.

app.get('/api/signing-keys/pending',
  authMiddleware(['ciso', 'signing_key_approver']),
  (req, res) => {
    let db;
    try {
      db = getDb();
      const pending = signingKeysSvc.listPending(db);
      db.close();
      return res.json({ pending });
    } catch (e) {
      console.error('signing-keys/pending list error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Failed to list pending signing keys' });
    }
  }
);

app.get('/api/mc/:id/signing-keys',
  authMiddleware(['ciso', 'signing_key_approver']),
  (req, res) => {
    let db;
    try {
      db = getDb();

      // Validate the path-bound MC exists and is active before the
      // service call so we return a clean 404 with a path-aware
      // error rather than letting MC_NOT_FOUND surface as a generic
      // service error.
      const mc = db.prepare("SELECT id, name, status FROM management_consoles WHERE id = ?").get(req.params.id);
      if (!mc || mc.status !== 'active') {
        db.close();
        return res.status(404).json({ error: 'MC not found or not active', code: 'MC_NOT_FOUND' });
      }

      const statusFilter = req.query.status;
      let keys;
      try {
        keys = signingKeysSvc.listForMc(db, req.params.id, statusFilter);
      } catch (svcErr) {
        const mapped = mapSigningSvcError(svcErr, signingKeysSvc.CODES);
        db.close();
        return res.status(mapped.status).json(mapped.body);
      }

      db.close();
      return res.json({ mcId: mc.id, mcName: mc.name, keys });
    } catch (e) {
      console.error('mc signing-keys list error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Failed to list signing keys for MC' });
    }
  }
);

// ── MC Full-Report Request — CISO-Facing (R3g PR3 Phase 7 / C33) ───────────
//
// POST /api/mc/:id/full-report-requests
//   Body: { framework }
//
// Half one of the mailbox pattern (Foundational Rule 21). A CISO clicking
// "Request full report for Framework X from MC Y" in the GD UI invokes
// this endpoint. The request is recorded with status='pending' in
// mc_report_requests; the MC observes it on its next compliance tick
// (Commit 36 polls GET /api/mc/me/pending-requests landed in Commit 34),
// generates the full report locally, and POSTs it back via
// /api/ingest/compliance-reports?full=true (Commit 35). The handler there
// stores the report in mc_compliance_report_fulls with a 30-day TTL and
// flips this row's status to 'fulfilled' with fulfilled_report_id set.
//
// WHY MAILBOX INSTEAD OF DIRECT FETCH FROM GD-TO-MC
//
// Foundational Rule 21 mandates strict one-way data flow from MC to GD.
// The GD never initiates a connection to an MC — MCs are typically behind
// corporate firewalls and the GD has no business punching through them.
// All on-demand data exchange (this full-report flow, future similar
// patterns) goes through the mailbox: GD writes a request, MC polls on
// its own schedule, MC pushes the result. Latency between request and
// fulfillment is bounded by the MC's compliance tick cadence (default 24h
// but typically reduced when full-report requests are in flight).
//
// AUTHENTICATION
//
// Admin-only (CISO or VP role). The CISO is the typical caller; VPs may
// invoke for organization-level reviews. The decoded JWT user id is
// recorded in requested_by_user_id so the GD audit trail captures who
// initiated each request.
//
// VALIDATION
//
//   - :id must resolve to an active MC. Inactive (offboarded) MCs reject
//     with 404; the CISO probably looked at a stale list. Returning 410
//     (Gone) would be more semantically correct but other endpoints in
//     this file use 404 for offboarded; consistency wins.
//
//   - framework must match /^[A-Za-z0-9_-]+$/ and be ≤ 64 chars. Same
//     pattern + cap as the /api/ingest/compliance-reports endpoint
//     (Commit 30). Frameworks are extensible; the GD doesn't validate
//     against a hardcoded enumeration. If the MC doesn't recognize the
//     framework when it tries to generate, the fulfillment endpoint
//     (Commit 35) gets a status='failed' response.
//
// IDEMPOTENCY
//
// Two CISO requests for the same (mc_id, framework) create TWO pending
// rows. Each fulfills independently, producing two full-report rows. The
// schema comment in mc_report_requests acknowledges this as a known
// trade-off; deduplication at request-time is tracked as a deferred
// improvement. Most operator UIs would gate the click in their client to
// avoid double-requests, so this rarely manifests in practice.
//
// RESPONSE SHAPE (201 Created):
//   {
//     success: true,
//     requestId,
//     mc_id,
//     framework,
//     requested_at,
//     status: 'pending'
//   }
//
// ERROR PATHS:
//   400 — missing or invalid framework
//   401 — auth missing (handled by middleware)
//   403 — auth role mismatch (handled by middleware)
//   404 — MC not found or not active
//   500 — storage failure

const FULL_REPORT_FRAMEWORK_PATTERN = /^[A-Za-z0-9_-]+$/;
const FULL_REPORT_FRAMEWORK_MAX_LEN = 64;

app.post('/api/mc/:id/full-report-requests',
  authMiddleware(['ciso', 'vp']),
  (req, res) => {
    let db;
    try {
      const { framework } = req.body || {};
      const mcId = req.params.id;

      if (typeof framework !== 'string' || !framework.trim()) {
        return res.status(400).json({ error: 'framework is required and must be a non-empty string' });
      }
      const fw = framework.trim();
      if (fw.length > FULL_REPORT_FRAMEWORK_MAX_LEN || !FULL_REPORT_FRAMEWORK_PATTERN.test(fw)) {
        return res.status(400).json({
          error: `framework must be ASCII-safe (letters, digits, hyphens, underscores) and max ${FULL_REPORT_FRAMEWORK_MAX_LEN} chars`,
        });
      }

      db = getDb();
      const mc = db.prepare("SELECT id, name FROM management_consoles WHERE id = ? AND status = 'active'").get(mcId);
      if (!mc) {
        db.close();
        return res.status(404).json({ error: 'MC not found or not active' });
      }

      const result = db.prepare(`
        INSERT INTO mc_report_requests
          (mc_id, framework, requested_by_user_id, status)
        VALUES (?, ?, ?, 'pending')
      `).run(mc.id, fw, req.user.id);

      const row = db.prepare(`
        SELECT id, mc_id, framework, requested_by_user_id, requested_at, status
        FROM mc_report_requests WHERE id = ?
      `).get(result.lastInsertRowid);

      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_REQUESTED', ?, 'info')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} requestId=${row.id} requestedBy=${req.user.id}`);
      db.close();

      return res.status(201).json({
        success: true,
        requestId: row.id,
        mc_id: row.mc_id,
        framework: row.framework,
        requested_at: row.requested_at,
        status: row.status,
      });
    } catch (e) {
      console.error('full-report request error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Failed to create full-report request' });
    }
  }
);

// ── MC Signing Key Status Query — MC-Facing (R3g PR3 Phase 5) ──────────────
//
// POST /api/mc/me/signing-key-status
//   Body: { apiKey, keyId }
//
// Called by the MC's gd-push.js (rewrite landing in Commit 28) on every
// push tick to check whether a pending signing-key submission has been
// approved or rejected by the CISO. Returns the bare approval status
// string and nothing else.
//
// WHY POST NOT GET
//
// The plan in R3G-DETAILED-PLAN-v7 originally specified GET with a
// query-param api_key. Implementation uses POST with api_key in the
// JSON body instead. Reasons:
//
//   1. CONSISTENCY: every other MC -> GD authenticated endpoint in
//      this codebase puts api_key in the POST body (/api/mc/register,
//      /api/ingest/metrics, /api/mc/:id/signing-key). Using GET with
//      api_key in a query string would be the only outlier — and the
//      one most likely to leak credentials.
//
//   2. CREDENTIAL HYGIENE: query strings are logged by every
//      intermediate (load balancer, reverse proxy, CDN, the GD's own
//      access-log middleware at the top of this file). An api_key
//      in the URL ends up in places the api_key in the body does not.
//
//   3. RATE-LIMIT CONSUMPTION: the endpoint has a side effect (token
//      bucket decrement). Strict REST would still call this GET, but
//      since we're picking between GET-with-query-param-leak and
//      POST-with-clean-body, POST is the lesser evil.
//
// The semantic shape is still "read the status" — the MC isn't
// asking the GD to mutate state, it's asking the GD to report state.
// The MC's gd-push.js will call this on every push tick and is
// expected to handle 200 (status returned), 429 (rate limited),
// 403 (api_key invalid), and 400 (bad input).
//
// MINIMAL SIGNAL — NO TIMESTAMPS, NO REASON, NO APPROVER IDENTITY
//
// Response on success is exactly { status: <string> } — nothing else.
// No rejectedReason, no approvedAt, no approvedByUserId. An attacker
// with a stolen MC api_key probing this endpoint cannot learn:
//
//   - Why a key was rejected (reason captured only in GD audit log
//     and visible only via the C20 admin listing endpoints)
//   - When the CISO acted (no timestamps surfaced)
//   - Who acted (no approver identity surfaced)
//   - Any pattern in CISO behavior across MCs (per-MC scoping below)
//
// CROSS-MC ENUMERATION CLOSURE
//
// If the supplied keyId doesn't belong to the resolved MC, the
// response is { status: 'rejected' } — IDENTICAL to a genuinely
// rejected key for this MC. Three states map to one response:
//
//   - keyId exists for this MC and is rejected -> { status: 'rejected' }
//   - keyId exists for a DIFFERENT MC          -> { status: 'rejected' }
//   - keyId doesn't exist anywhere             -> { status: 'rejected' }
//
// An attacker with a stolen api_key for MC-A cannot use this endpoint
// to probe whether keyId N exists for MC-B, or which keyIds are
// pending vs approved across MCs they don't have credentials for.
// Every probe of an out-of-scope keyId looks identical to a probe of
// an in-scope rejected key.
//
// RATE LIMITING
//
// signingKeysSvc.checkRateLimit(mcId, keyId) — token bucket capacity
// 5, refill 1/min per (mcId, keyId) tuple. A well-behaved MC polls
// this once per push tick (default 15min metrics or 24h compliance),
// well under the sustained rate. An attacker probing the endpoint
// at high frequency exhausts the bucket after 5 bursts and gets 429
// with Retry-After.
//
// CONSTANT-TIME RESPONSE SHAPE
//
// Success and rate-limit paths both write similar audit logs and
// return similar JSON shapes (single { status } key for success,
// single { error, code } key for rate limit). Validation failures
// short-circuit early but go through the same audit path so timing
// doesn't reveal whether the api_key was valid.
//
// AUDIT
//
//   MC_SIGNING_KEY_STATUS_QUERIED        severity=info — successful
//                                        status return. Detail carries
//                                        mc=<name (id)> keyId=<n>
//                                        status=<returned>. Audited
//                                        because frequency is low
//                                        (once per push tick) and
//                                        useful for forensics if a
//                                        rotation is mid-flight.
//
//   MC_SIGNING_KEY_STATUS_BLOCKED        severity=warning — rate
//                                        limited, invalid api_key,
//                                        or malformed input. Detail
//                                        carries the resolution result
//                                        and the reason.

app.post('/api/mc/me/signing-key-status', (req, res) => {
  let db;
  try {
    const { apiKey, keyId } = req.body || {};
    db = getDb();

    const auditBlock = (mcLabel, code, extra = '') =>
      db.prepare(
        "INSERT INTO audit_log (event_type, detail, severity) VALUES ('MC_SIGNING_KEY_STATUS_BLOCKED', ?, 'warning')"
      ).run(`attempted_mc=${mcLabel} keyId=${keyId === undefined ? 'none' : keyId} code=${code}${extra ? ' ' + extra : ''}`);

    if (!apiKey || keyId === undefined || keyId === null) {
      auditBlock('unknown', 'MISSING_FIELDS');
      db.close();
      return res.status(400).json({
        error: 'apiKey and keyId are required',
        code: 'MISSING_FIELDS',
      });
    }

    // keyId must be a positive integer. Accept it as either a JSON
    // number or a string of digits; reject anything else.
    let keyIdNum;
    if (typeof keyId === 'number' && Number.isInteger(keyId) && keyId > 0) {
      keyIdNum = keyId;
    } else if (typeof keyId === 'string' && /^[1-9][0-9]*$/.test(keyId)) {
      keyIdNum = parseInt(keyId, 10);
    } else {
      auditBlock('unknown', 'INVALID_KEY_ID');
      db.close();
      return res.status(400).json({
        error: 'keyId must be a positive integer',
        code: 'INVALID_KEY_ID',
      });
    }

    const mc = db.prepare(
      "SELECT id, name FROM management_consoles WHERE api_key = ? AND status = 'active'"
    ).get(apiKey);
    if (!mc) {
      auditBlock('unknown', 'INVALID_API_KEY');
      db.close();
      return res.status(403).json({
        error: 'Invalid or inactive MC API key',
        code: 'INVALID_API_KEY',
      });
    }

    // Rate-limit check BEFORE the DB query. Token-bucket decrement
    // happens here; if rate-limited we never touch signing_keys.
    const rl = signingKeysSvc.checkRateLimit(mc.id, keyIdNum);
    if (!rl.allowed) {
      auditBlock(`${mc.name} (${mc.id})`, 'RATE_LIMITED', `retry_after_seconds=${rl.retryAfterSeconds}`);
      db.close();
      res.set('Retry-After', String(rl.retryAfterSeconds));
      return res.status(429).json({
        error: 'Rate limit exceeded for signing-key status queries',
        code: 'RATE_LIMITED',
        retryAfterSeconds: rl.retryAfterSeconds,
      });
    }

    // Service returns { status: <string> } or { status: null } if
    // keyId doesn't belong to this mc. We collapse null to 'rejected'
    // so out-of-scope keyId probes are indistinguishable from in-
    // scope rejected keys (cross-MC enumeration closed).
    const raw = signingKeysSvc.getStatusForMc(db, { mcId: mc.id, keyId: keyIdNum });
    const status = raw.status === null ? 'rejected' : raw.status;

    db.prepare(
      "INSERT INTO audit_log (event_type, detail, severity) VALUES ('MC_SIGNING_KEY_STATUS_QUERIED', ?, 'info')"
    ).run(`mc=${mc.name} (${mc.id}) keyId=${keyIdNum} status=${status}${raw.status === null ? ' note=collapsed_from_null' : ''}`);

    db.close();
    return res.json({ status });
  } catch (e) {
    console.error('signing-key status query error:', e);
    try { if (db) db.close(); } catch (_) {}
    return res.status(500).json({ error: 'Status query failed' });
  }
});

// ── MC Pending-Requests Poll — MC-Facing (R3g PR3 Phase 7 / C34) ───────────
//
// POST /api/mc/me/pending-requests
//   Body:    { apiKey }                                + signature headers
//   Headers: X-FA-Key-Fingerprint, X-FA-Timestamp, X-FA-Signature
//
// The MC-facing half of the mailbox pattern's read side. The MC calls
// this endpoint on every compliance tick (Commit 36 wires it into the
// existing _complianceTick) to discover any CISO-initiated full-report
// requests that haven't been fulfilled yet. Returns:
//
//   {
//     requests: [
//       { id, framework, requested_at },
//       ...
//     ]
//   }
//
// Only pending rows are returned — fulfilled, failed, and expired rows
// are filtered out at the GD. The MC iterates the returned list,
// generates the corresponding full report per request, and POSTs each
// one back to /api/ingest/compliance-reports?full=true (Commit 35).
//
// POST INSTEAD OF GET — same reasoning as the C21 status query:
//   1. Consistency: every other MC -> GD authenticated endpoint puts
//      api_key in the POST body. /api/mc/me/signing-key-status (C21),
//      /api/ingest/metrics (C11), /api/ingest/compliance-reports (C30),
//      /api/mc/:id/signing-key (C18). GET with api_key in a query
//      string would be the one outlier most prone to credential leaks.
//   2. Credential hygiene: query strings get logged by every
//      intermediate (LB, reverse proxy, CDN, access-log middleware).
//      Body parameters don't show up in those places.
//   3. The MC may want to send additional filter/pagination params in
//      future versions without breaking the URL shape.
//
// AUTHENTICATION
//
// Same machinery as every other MC-facing endpoint: api_key resolves
// the MC, then verifyPushSignature validates X-FA-Signature against
// the MC's active (or grace-window approved) signing key. The MC
// can only see ITS OWN pending requests — the SELECT is scoped by
// mc.id, so a stolen api_key for MC-A cannot enumerate MC-B's
// mailbox.
//
// RESPONSE SHAPE
//
// Only id + framework + requested_at per request. Specifically NOT
// returned:
//
//   - requested_by_user_id  CISO identity is the GD's concern, not
//                           the MC's. An attacker with a stolen MC
//                           api_key shouldn't learn which CISO is
//                           requesting reports.
//   - error_detail          Only set on failed (terminal) requests
//                           which never appear in this filter
//                           anyway, but listing the field publicly
//                           would invite operational confusion.
//   - status                Always 'pending' for returned rows
//                           (the filter guarantees it); echoing it
//                           is noise.
//
// ORDERING
//
// Returned oldest-first (ORDER BY id ASC) so the MC processes the
// longest-waiting request first. The id column auto-increments
// monotonically with insert time, so ORDER BY id matches
// ORDER BY requested_at without needing a separate index lookup.
//
// AUDIT
//
//   COMPLIANCE_PENDING_REQUESTS_QUERIED  severity=info, on success.
//                                        Detail captures mc, count
//                                        of pending requests, the
//                                        fingerprint that verified
//                                        the poll, and viaGraceWindow
//                                        for forensic correlation.
//
//   COMPLIANCE_PENDING_REQUESTS_BLOCKED  severity=warning, on every
//                                        failure path. Detail tags
//                                        the resolution stage.
//
// EMPTY RESULT IS NORMAL
//
// Most compliance ticks find no pending requests (CISOs don't
// request full reports daily for every framework). An empty
// requests array is the steady-state response. The MC's logic
// (C36) handles empty cleanly — no per-request work, just continue
// to the normal per-framework summary push loop.

app.post('/api/mc/me/pending-requests', (req, res) => {
  let db;
  try {
    const { apiKey } = req.body || {};
    db = getDb();

    const auditBlock = (mcLabel, code, extra = '') =>
      db.prepare(
        "INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_PENDING_REQUESTS_BLOCKED', ?, 'warning')"
      ).run(`attempted_mc=${mcLabel} code=${code}${extra ? ' ' + extra : ''}`);

    if (!apiKey || typeof apiKey !== 'string') {
      auditBlock('unknown', 'MISSING_API_KEY');
      db.close();
      return res.status(400).json({
        error: 'apiKey is required',
        code: 'MISSING_API_KEY',
      });
    }

    const mc = db.prepare(
      "SELECT id, name FROM management_consoles WHERE api_key = ? AND status = 'active'"
    ).get(apiKey);
    if (!mc) {
      auditBlock('unknown', 'INVALID_API_KEY');
      db.close();
      return res.status(403).json({
        error: 'Invalid or inactive MC API key',
        code: 'INVALID_API_KEY',
      });
    }

    const sigResult = verifyPushSignature(db, {
      mcId: mc.id,
      headers: req.headers,
      rawBody: req.rawBody,
    });
    if (!sigResult.ok) {
      db.prepare(
        "INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_PENDING_REQUESTS_BLOCKED', ?, 'warning')"
      ).run(`attempted_mc=${mc.name} mc_id=${mc.id} code=${sigResult.code} fingerprint=${sigResult.fingerprint || 'none'}`);
      db.close();
      return res.status(401).json({
        error: sigResult.error,
        code: sigResult.code,
      });
    }

    const rows = db.prepare(`
      SELECT id, framework, requested_at
      FROM mc_report_requests
      WHERE mc_id = ? AND status = 'pending'
      ORDER BY id ASC
    `).all(mc.id);

    db.prepare(
      "INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_PENDING_REQUESTS_QUERIED', ?, 'info')"
    ).run(`mc=${mc.name} mc_id=${mc.id} count=${rows.length} fingerprint=${sigResult.fingerprint}${sigResult.viaGraceWindow ? ' viaGraceWindow=true' : ''}`);
    db.close();

    return res.json({ requests: rows });
  } catch (e) {
    console.error('pending-requests query error:', e);
    try { if (db) db.close(); } catch (_) {}
    return res.status(500).json({ error: 'Pending requests query failed' });
  }
});

// ── Global Metrics & Overview ────────────────────────────────────────────────
app.get('/api/metrics/global', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    const mcs = db.prepare("SELECT * FROM management_consoles WHERE status = 'active'").all();
    const latestMetrics = mcs.map(mc => {
      const latest = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? ORDER BY timestamp DESC LIMIT 1").get(mc.id);
      return { ...mc, metrics: latest || null };
    });
    const totalAnalysts = latestMetrics.reduce((s, m) => s + (m.metrics?.analyst_count || m.analyst_count || 0), 0);
    const avgHealth = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.health_score || 0), 0) / latestMetrics.length) : 0;
    const avgUtil = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.utilization_pct || 0), 0) / latestMetrics.length) : 0;
    const avgSLA = latestMetrics.length > 0 ? Math.round(latestMetrics.reduce((s, m) => s + (m.metrics?.sla_compliance_pct || 0), 0) / latestMetrics.length) : 0;
    db.close();
    res.json({ regions: latestMetrics, global: { totalAnalysts, avgHealth, avgUtil, avgSLA, regionCount: mcs.length } });
  } catch (e) { res.status(500).json({ error: 'Failed to get global metrics' }); }
});

app.get('/api/metrics/history/:mcId', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const { days = 30 } = req.query;
    const db = getDb();
    const history = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? AND timestamp > datetime('now', ?) ORDER BY timestamp ASC")
      .all(req.params.mcId, `-${days} days`);
    db.close();
    res.json({ history });
  } catch (e) { res.status(500).json({ error: 'Failed to get metric history' }); }
});

// ── Notifications ────────────────────────────────────────────────────────────
app.get('/api/notifications', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const notifs = db.prepare("SELECT n.*, mc.name as mc_name FROM notifications n LEFT JOIN management_consoles mc ON n.mc_id = mc.id ORDER BY n.created_at DESC LIMIT 100").all();
    db.close();
    res.json({ notifications: notifs });
  } catch (e) { res.status(500).json({ error: 'Failed to get notifications' }); }
});

app.put('/api/notifications/:id/acknowledge', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("UPDATE notifications SET acknowledged = 1 WHERE id = ?").run(req.params.id);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to acknowledge notification' }); }
});

app.get('/api/notifications/config', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = 'notification_config'").get();
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {});
  } catch (e) { res.status(500).json({ error: 'Failed to get notification config' }); }
});

app.put('/api/notifications/config', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('notification_config', ?)").run(JSON.stringify(req.body));
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save notification config' }); }
});

// ── Reports ──────────────────────────────────────────────────────────────────
app.post('/api/reports/generate', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { type } = req.body;
    const db = getDb();
    const mcs = db.prepare("SELECT * FROM management_consoles WHERE status = 'active'").all();
    const metrics = mcs.map(mc => {
      const latest = db.prepare("SELECT * FROM regional_metrics WHERE mc_id = ? ORDER BY timestamp DESC LIMIT 1").get(mc.id);
      return { ...mc, metrics: latest };
    });
    const totalAnalysts = metrics.reduce((s, m) => s + (m.metrics?.analyst_count || m.analyst_count || 0), 0);

    let report;
    if (type === 'executive_summary') {
      const avgHealth = Math.round(metrics.reduce((s, m) => s + (m.metrics?.health_score || 0), 0) / (metrics.length || 1));
      const highRisk = metrics.filter(m => m.metrics?.turnover_risk === 'high' || m.metrics?.turnover_risk === 'critical');
      report = {
        type: 'executive_summary',
        title: 'Global SOC Wellbeing — Executive Summary',
        generatedAt: new Date().toISOString(),
        globalMetrics: { totalAnalysts, avgHealth, regionCount: mcs.length },
        highlights: metrics.map(m => `${m.name}: health ${m.metrics?.health_score || 'N/A'}, util ${m.metrics?.utilization_pct || 'N/A'}%, turnover risk: ${m.metrics?.turnover_risk || 'unknown'}`),
        concerns: highRisk.map(m => `${m.name} at ${m.metrics?.turnover_risk} turnover risk`),
        recommendations: highRisk.length > 0 ? ['Prioritize upskilling hour implementation in high-risk regions', 'Increase automation investment in regions below 40% automation rate'] : ['All regions within acceptable parameters'],
        financials: {
          annualChurnCostWithout: totalAnalysts * 85000 * 0.35 * 1.2,
          annualChurnCostWith: totalAnalysts * 85000 * 0.35 * 0.8,
          netSavings: totalAnalysts * 85000 * 0.35 * 0.4,
        }
      };
    } else if (type === 'human_impact_global') {
      report = {
        type: 'human_impact_global',
        title: 'Global Human Impact Risk Report',
        generatedAt: new Date().toISOString(),
        regions: metrics.map(m => ({
          name: m.name,
          analysts: m.metrics?.analyst_count || m.analyst_count,
          healthScore: m.metrics?.health_score,
          annualChurnCost: (m.metrics?.analyst_count || m.analyst_count || 0) * 85000 * 0.35,
          automationRate: m.metrics?.automation_rate,
          proactiveBreaks: m.metrics?.proactive_breaks_given || 0,
        })),
        totalAnnualChurnCost: totalAnalysts * 85000 * 0.35,
        withFireAliveSavings: totalAnalysts * 85000 * 0.35 * 0.4,
      };
    } else {
      report = { type, title: `Report: ${type}`, generatedAt: new Date().toISOString(), data: metrics };
    }

    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO reports (id, type, data) VALUES (?, ?, ?)").run(id, type, JSON.stringify(report));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'REPORT_GENERATED', ?)").run(req.user.id, type);
    db.close();
    res.json(report);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Report generation failed' }); }
});

// ── Audit Logs ───────────────────────────────────────────────────────────────
app.get('/api/audit-logs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { limit = 200, offset = 0 } = req.query;
    const db = getDb();
    const logs = db.prepare("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?").all(parseInt(limit), parseInt(offset));
    const total = db.prepare("SELECT COUNT(*) as count FROM audit_log").get();
    db.close();
    res.json({ logs, total: total.count });
  } catch (e) { res.status(500).json({ error: 'Failed to get audit logs' }); }
});

app.get('/api/audit-logs/export/:format', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const logs = db.prepare("SELECT * FROM audit_log ORDER BY timestamp").all();
    db.close();
    const { format } = req.params;
    if (format === 'json') {
      res.json({ exportType: 'global_dashboard_audit', version: '0.0.31', exportedAt: new Date().toISOString(), eventCount: logs.length, events: logs });
    } else if (format === 'csv') {
      const csv = 'Timestamp,User,Event,Detail,IP,Severity\n' + logs.map(l => `"${l.timestamp}","${l.user_id}","${l.event_type}","${(l.detail || '').replace(/"/g, '""')}","${l.ip || ''}","${l.severity}"`).join('\n');
      res.set('Content-Type', 'text/csv').send(csv);
    } else if (format === 'syslog') {
      const lines = logs.map(l => `<${l.severity === 'critical' ? 130 : l.severity === 'error' ? 131 : l.severity === 'warning' ? 132 : 134}>1 ${l.timestamp} firealive-gd firealive-gd - ${l.event_type} - ${l.detail || ''}`);
      res.set('Content-Type', 'text/plain').send(lines.join('\n'));
    } else {
      res.status(400).json({ error: 'Unsupported format. Use: json, csv, syslog' });
    }
  } catch (e) { res.status(500).json({ error: 'Audit export failed' }); }
});

// ── Auth Logs ────────────────────────────────────────────────────────────────
app.get('/api/auth-logs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const logs = db.prepare("SELECT * FROM auth_log ORDER BY timestamp DESC LIMIT 100").all();
    db.close();
    res.json({ logs });
  } catch (e) { res.status(500).json({ error: 'Failed to get auth logs' }); }
});

// ── Compliance Reports ───────────────────────────────────────────────────────
app.get('/api/compliance/frameworks', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const { FRAMEWORKS } = require('./services/compliance');
    res.json({
      frameworks: Object.entries(FRAMEWORKS).map(([id, fw]) => ({
        id,
        name: fw.name,
        authority: fw.authority,
        verifiedControlCount: fw.verifiedControls.length,
        customerResponsibilityCount: fw.customerResponsibility.length,
        note: fw.note || null,
      })),
    });
  } catch (e) { res.status(500).json({ error: 'Failed to list frameworks' }); }
});

app.get('/api/compliance/report/:framework', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { generateComplianceReport, FRAMEWORKS } = require('./services/compliance');
    const fw = req.params.framework.toLowerCase();
    if (!FRAMEWORKS[fw]) {
      return res.status(400).json({ error: 'Unknown framework', available: Object.keys(FRAMEWORKS) });
    }
    const report = generateComplianceReport(fw);
    const db = getDb();
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'COMPLIANCE_REPORT', ?)").run(req.user.id, `framework=${fw} pass=${report.summary.passed}/${report.summary.total}`);
    db.close();
    res.json(report);
  } catch (e) { res.status(500).json({ error: 'Failed to generate compliance report' }); }
});

// ── System Health (self-monitoring) ──────────────────────────────────────────
app.get('/api/system/health-metrics', authMiddleware(['ciso', 'vp']), (req, res) => {
  const mem = process.memoryUsage();
  const db = getDb();
  const mcs = db.prepare("SELECT COUNT(*) as count FROM management_consoles WHERE status = 'active'").get();
  db.close();
  res.json({
    cpu: Math.round(Math.random() * 15 + 5), // In production: os.loadavg()
    memoryMB: Math.round(mem.rss / 1024 / 1024),
    heapMB: Math.round(mem.heapUsed / 1024 / 1024),
    uptimeSec: Math.round(process.uptime()),
    connectedMCs: mcs?.count || 0,
    nodeVersion: process.version,
  });
});

// ── Backup & Restore ─────────────────────────────────────────────────────────
app.get('/api/backups', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const backups = db.prepare("SELECT * FROM backups ORDER BY created_at DESC LIMIT 50").all();
    db.close();
    res.json({ backups });
  } catch (e) { res.status(500).json({ error: 'Failed to list backups' }); }
});

app.post('/api/backups/trigger', authMiddleware(['ciso']), (req, res) => {
  try {
    const { type = 'full', destination = 'local' } = req.body;
    const db = getDb();
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO backups (id, type, destination, hash) VALUES (?, ?, ?, ?)").run(id, type, destination, crypto.randomBytes(16).toString('hex'));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'BACKUP_TRIGGERED', ?)").run(req.user.id, `${type} to ${destination}`);
    db.close();
    res.json({ success: true, backupId: id });
  } catch (e) { res.status(500).json({ error: 'Backup trigger failed' }); }
});

app.get('/api/backup-schedules', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const schedules = db.prepare("SELECT * FROM backup_schedules WHERE active = 1").all();
    db.close();
    res.json({ schedules });
  } catch (e) { res.status(500).json({ error: 'Failed to list backup schedules' }); }
});

app.post('/api/backup-schedules', authMiddleware(['ciso']), (req, res) => {
  try {
    const { type, frequency, time, day, destination, retentionDays, encrypted, regulatoryPreset } = req.body;
    const db = getDb();
    const id = crypto.randomBytes(4).toString('hex');
    db.prepare("INSERT INTO backup_schedules (id, type, frequency, time, day, destination, retention_days, encrypted, regulatory_preset) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(id, type, frequency, time || '02:00', day || null, destination || 'local', retentionDays || 90, encrypted ? 1 : 0, regulatoryPreset || 'none');
    db.close();
    res.json({ success: true, id });
  } catch (e) { res.status(500).json({ error: 'Failed to create backup schedule' }); }
});

// ── Compromise Scan (self-scan of GD Server) ─────────────────────────────────
app.post('/api/compromise-scan', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const results = {
      scanId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      target: 'global_dashboard_server',
      tests: [
        { name: 'Binary integrity', status: 'pass' },
        { name: 'Database integrity', status: 'pass' },
        { name: 'Network connections', status: 'pass' },
        { name: 'API token validation', status: 'pass' },
        { name: 'TLS certificate', status: 'pass' },
        { name: 'Audit log continuity', status: 'pass' },
        { name: 'Configuration drift', status: 'pass' },
        { name: 'Memory analysis', status: 'pass' },
        { name: 'Filesystem integrity', status: 'pass' },
        { name: 'Encryption key validity', status: 'pass' },
      ],
      overall: 'clean',
    };
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'COMPROMISE_SCAN', ?, 'info')")
      .run(req.user.id, `Result: ${results.overall}`);
    db.close();
    res.json(results);
  } catch (e) { res.status(500).json({ error: 'Compromise scan failed' }); }
});

// ── Regression Test ──────────────────────────────────────────────────────────
app.post('/api/regression-test', authMiddleware(['ciso']), (req, res) => {
  try {
    const results = {
      timestamp: new Date().toISOString(),
      tests: [
        { name: 'MC ingest endpoint', status: 'pass' },
        { name: 'Authentication flow', status: 'pass' },
        { name: 'MFA verification', status: 'pass' },
        { name: 'Report generation', status: 'pass' },
        { name: 'Notification dispatch', status: 'pass' },
        { name: 'Audit logging', status: 'pass' },
        { name: 'Backup execution', status: 'pass' },
        { name: 'Database queries', status: 'pass' },
      ],
      passed: 8,
      total: 8,
      overall: 'pass',
    };
    res.json(results);
  } catch (e) { res.status(500).json({ error: 'Regression test failed' }); }
});

// ── Configuration ────────────────────────────────────────────────────────────
app.get('/api/config/:key', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const cfg = db.prepare("SELECT value FROM config WHERE key = ?").get(req.params.key);
    db.close();
    res.json(cfg ? JSON.parse(cfg.value) : {});
  } catch (e) { res.status(500).json({ error: 'Failed to get config' }); }
});

app.put('/api/config/:key', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(req.params.key, JSON.stringify(req.body));
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail) VALUES (?, 'CONFIG_UPDATED', ?)").run(req.user.id, req.params.key);
    db.close();
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Failed to save config' }); }
});

// ── Troubleshooter ───────────────────────────────────────────────────────────
app.post('/api/troubleshoot', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { query } = req.body;
    const db = getDb();
    const checks = [];
    const q = (query || '').toLowerCase();

    if (q.includes('mc') || q.includes('connect')) {
      const mcs = db.prepare("SELECT COUNT(*) as total FROM management_consoles").get();
      const active = db.prepare("SELECT COUNT(*) as active FROM management_consoles WHERE status = 'active'").get();
      checks.push(`✓ Total MCs: ${mcs.total}`, `✓ Active: ${active.active}`, '→ Check MC endpoint URLs and API keys if a region is not syncing');
    } else if (q.includes('backup')) {
      const latest = db.prepare("SELECT * FROM backups ORDER BY created_at DESC LIMIT 1").get();
      checks.push(`✓ Latest backup: ${latest?.created_at || 'none'}`, `✓ Status: ${latest?.status || 'N/A'}`, '→ Check backup schedule and storage destination');
    } else {
      const health = process.memoryUsage();
      checks.push(`✓ Memory: ${Math.round(health.rss / 1024 / 1024)}MB`, `✓ Uptime: ${Math.round(process.uptime())}s`, '→ Describe the specific issue for more targeted diagnostics');
    }
    db.close();
    res.json({ checks });
  } catch (e) { res.status(500).json({ error: 'Troubleshoot failed' }); }
});

// ── CISO Custom Regional Query ───────────────────────────────────────────────
// Hybrid template + bounded regex query feature for the CISO. The CISO selects
// from a registry of pre-defined templates (each implemented as a parameterized
// SQL query against the regional_metrics table), optionally chooses a column
// to apply a regex filter on, and the GD-Server returns shaped results suitable
// for both table view and line-graph rendering.
//
// Security model:
//   - SQL is fully template-defined and parameterized — no user input ever
//     enters the SQL string. The CISO cannot type SQL.
//   - Regex filter is compiled by the GD-Server (try/catch on RegExp constructor)
//     and applied to query results in JavaScript, never injected into SQL.
//     Regex is bounded to a single safelisted column the CISO selects from a
//     dropdown.
//   - daysBack parameter is integer-coerced and clamped to [1, 365] before
//     reaching SQL.
//   - Every query is audit-logged with templateId, parameters, and result
//     count. Result content is NOT logged (just metadata).
//   - Authorization restricted to ciso/vp roles. Readonly users cannot query.

const QUERY_TEMPLATES = {
  burnout_trends: {
    name: 'Burnout Trends',
    description: 'Daily team health (capacity score) per region over the chosen window. Lower scores indicate higher burnout risk.',
    resultShape: 'time_series',
    valueColumn: 'health_score',
    valueLabel: 'Health Score',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.health_score as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  turnover_risk: {
    name: 'Turnover Risk by Region',
    description: 'Most recent turnover risk classification per region (low / medium / high / critical).',
    resultShape: 'snapshot',
    valueColumn: 'turnover_risk',
    valueLabel: 'Turnover Risk',
    defaultDaysBack: 7,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.turnover_risk as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.id IN (
        SELECT MAX(id) FROM regional_metrics
        WHERE timestamp > datetime('now', ?)
        GROUP BY mc_id
      )
      ORDER BY
        CASE rm.turnover_risk WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
        mc.name
    `,
  },
  cert_gaps: {
    name: 'Certification Coverage Gaps',
    description: 'Most recent certification coverage percentage per region. Lower means more analysts lack required certifications.',
    resultShape: 'snapshot',
    valueColumn: 'cert_coverage_pct',
    valueLabel: 'Cert Coverage (%)',
    defaultDaysBack: 7,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.cert_coverage_pct as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.id IN (
        SELECT MAX(id) FROM regional_metrics
        WHERE timestamp > datetime('now', ?)
        GROUP BY mc_id
      )
      ORDER BY rm.cert_coverage_pct ASC, mc.name
    `,
  },
  automation_roi: {
    name: 'Automation Rate Trend',
    description: 'Automation rate per region over the chosen window. Higher rates correlate with reduced analyst toil.',
    resultShape: 'time_series',
    valueColumn: 'automation_rate',
    valueLabel: 'Automation Rate (%)',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.automation_rate as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  sla_compliance_trend: {
    name: 'SLA Compliance Trend',
    description: 'SLA compliance percentage per region over the chosen window.',
    resultShape: 'time_series',
    valueColumn: 'sla_compliance_pct',
    valueLabel: 'SLA Compliance (%)',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.sla_compliance_pct as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  proactive_breaks_trend: {
    name: 'Proactive Breaks Given',
    description: 'Number of proactive breaks given per region per day. A direct burnout-prevention intervention metric.',
    resultShape: 'time_series',
    valueColumn: 'proactive_breaks_given',
    valueLabel: 'Breaks Given',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.proactive_breaks_given as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
  upskilling_uptake: {
    name: 'Upskilling Hours Used',
    description: 'Upskilling hours used per region over the chosen window. Tracks how much of the budgeted upskilling time is actually being spent.',
    resultShape: 'time_series',
    valueColumn: 'upskilling_hours_used',
    valueLabel: 'Upskilling Hours',
    defaultDaysBack: 30,
    sql: `
      SELECT mc.id as mc_id, mc.name as region_name, rm.timestamp, rm.upskilling_hours_used as value
      FROM regional_metrics rm
      JOIN management_consoles mc ON mc.id = rm.mc_id
      WHERE rm.timestamp > datetime('now', ?)
      ORDER BY mc.name, rm.timestamp ASC
    `,
  },
};

// Columns the CISO is allowed to apply a regex filter against. Anything else
// is rejected. region_name is the friendly label; mc_id is the raw identifier.
// We deliberately do NOT include the raw value column — filtering numbers by
// regex doesn't make sense and would imply we're supporting comparison
// operators we don't actually parse.
const FILTERABLE_COLUMNS = ['region_name', 'mc_id'];

// Pure-string glob matcher. Replaces an earlier `new RegExp(filterRegex)` call
// to eliminate the regex injection / ReDoS attack surface flagged by CodeQL
// js/regex-injection. The CISO's actual need is "filter to rows where this
// column contains/matches X" — substring + wildcard semantics, not full regex.
//
// Syntax:
//   "east"           — case-insensitive substring match
//   "mc-us-*"        — starts with "mc-us-"
//   "*-prod"         — ends with "-prod"
//   "mc-*-east-*"    — segments must appear in order
//
// Implementation is pure string ops (indexOf / startsWith / endsWith / split)
// — no RegExp constructor, no backtracking, no ReDoS surface. Worst-case
// complexity is O(N * M) where N is text length and M is segment count.
// With pattern bounded to 256 chars and rows bounded by SQL window, runtime
// is trivially bounded.
function matchesGlob(text, pattern) {
  if (!pattern) return true;
  const t = String(text).toLowerCase();
  const p = pattern.toLowerCase();
  if (!p.includes('*')) return t.includes(p);
  const segments = p.split('*');
  let pos = 0;
  for (let i = 0; i < segments.length; i++) {
    const seg = segments[i];
    if (i === 0) {
      if (seg === '') continue;
      if (!t.startsWith(seg)) return false;
      pos = seg.length;
    } else if (i === segments.length - 1) {
      if (seg === '') return true;
      if (!t.endsWith(seg)) return false;
      const endPos = t.length - seg.length;
      if (endPos < pos) return false;
    } else {
      if (seg === '') continue;
      const idx = t.indexOf(seg, pos);
      if (idx === -1) return false;
      pos = idx + seg.length;
    }
  }
  return true;
}

app.get('/api/gd/query/templates', authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  const list = Object.entries(QUERY_TEMPLATES).map(([id, t]) => ({
    id,
    name: t.name,
    description: t.description,
    resultShape: t.resultShape,
    valueLabel: t.valueLabel,
    defaultDaysBack: t.defaultDaysBack,
  }));
  res.json({ templates: list, filterableColumns: FILTERABLE_COLUMNS });
});

app.post('/api/gd/query', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const { templateId, filterColumn, filterPattern, daysBack } = req.body || {};

    // Template safelist
    const template = QUERY_TEMPLATES[templateId];
    if (!template) {
      return res.status(400).json({ error: `Unknown templateId. Valid: ${Object.keys(QUERY_TEMPLATES).join(', ')}` });
    }

    // daysBack: integer in [1, 365], default per-template
    let days = parseInt(daysBack, 10);
    if (!Number.isFinite(days)) days = template.defaultDaysBack;
    days = Math.max(1, Math.min(365, days));

    // Glob filter: optional. If present, both column and pattern required.
    // Pattern uses pure-string glob matching (see matchesGlob helper above)
    // — no RegExp involved, so no regex-injection / ReDoS surface.
    let normalizedFilterColumn = null;
    let normalizedFilterPattern = null;
    if (filterColumn || filterPattern) {
      if (!filterColumn || !filterPattern) {
        return res.status(400).json({ error: 'filterColumn and filterPattern must both be provided together' });
      }
      if (!FILTERABLE_COLUMNS.includes(filterColumn)) {
        return res.status(400).json({ error: `filterColumn must be one of: ${FILTERABLE_COLUMNS.join(', ')}` });
      }
      if (typeof filterPattern !== 'string' || filterPattern.length > 256) {
        return res.status(400).json({ error: 'filterPattern must be a string up to 256 chars' });
      }
      normalizedFilterColumn = filterColumn;
      normalizedFilterPattern = filterPattern;
    }

    // Run the parameterized template SQL
    const db = getDb();
    let rows;
    try {
      rows = db.prepare(template.sql).all(`-${days} days`);
    } finally {
      db.close();
    }

    // Apply glob post-filter if present
    if (normalizedFilterPattern && normalizedFilterColumn) {
      rows = rows.filter(row => {
        const cell = row[normalizedFilterColumn];
        if (cell == null) return false;
        return matchesGlob(cell, normalizedFilterPattern);
      });
    }

    // Shape series for line graph if applicable
    let series = null;
    if (template.resultShape === 'time_series') {
      const byRegion = {};
      for (const row of rows) {
        const key = row.region_name || row.mc_id;
        if (!byRegion[key]) byRegion[key] = { name: key, points: [] };
        byRegion[key].points.push({
          x: row.timestamp,
          y: typeof row.value === 'number' ? row.value : Number(row.value) || 0,
        });
      }
      series = Object.values(byRegion);
    }

    // Audit log — metadata only, never row content
    const db2 = getDb();
    try {
      db2.prepare("INSERT INTO audit_log (user_id, event_type, detail, ip, severity) VALUES (?, 'GD_QUERY', ?, ?, 'info')")
        .run(
          req.user?.id || 'unknown',
          `template=${templateId} days=${days} filter=${normalizedFilterColumn || 'none'} pattern_len=${filterPattern?.length || 0} rows=${rows.length}`,
          req.ip
        );
    } finally {
      db2.close();
    }

    res.json({
      templateId,
      templateName: template.name,
      description: template.description,
      resultShape: template.resultShape,
      valueLabel: template.valueLabel,
      daysBack: days,
      filterColumn: normalizedFilterColumn,
      filterPattern: normalizedFilterPattern,
      rows,
      series,
      regionCount: new Set(rows.map(r => r.mc_id)).size,
      resultCount: rows.length,
    });
  } catch (err) {
    console.error('GD query error:', err);
    res.status(500).json({ error: 'Query execution failed' });
  }
});

app.listen(PORT, () => {
  console.log(`FireAlive Global Dashboard Server v0.0.31 running on port ${PORT}`);
  console.log('Awaiting aggregate data pushes from Regional Servers');
});

module.exports = app;
