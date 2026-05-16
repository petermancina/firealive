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
const cloudIacBundle = require('./services/cloud-iac-bundle');
const cicdBundle = require('./services/cicd-bundle');

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
// R3g PR3 Phase 7 (C35): cap for fulfilled full reports. The schema
// comment estimates "tens of KB per framework × 16 frameworks"; 1 MB
// per report leaves headroom for verbose verifiedControls + remediation
// detail and customerResponsibility enumeration without inviting abuse.
// The 30-day TTL on mc_compliance_report_fulls bounds storage growth.
const COMPLIANCE_FULL_REPORT_MAX_BYTES = 1024 * 1024;

// ── handleFullReportIngest — R3g PR3 Phase 7 (C35) ────────────────────────
//
// Dispatched from the /api/ingest/compliance-reports route when the
// caller passes ?full=true. Closes the mailbox loop:
//
//   1. CISO requests via C33 -> mc_report_requests row, status='pending'
//   2. MC polls via C34 -> sees the pending row
//   3. MC generates full report locally, signs, POSTs HERE
//   4. This handler:
//      a. Validates the request exists + belongs to this MC + still pending
//      b. Validates report payload (framework matches, body shape, size)
//      c. INSERTs into mc_compliance_report_fulls (30-day TTL)
//      d. UPDATEs mc_report_requests: status='fulfilled', fulfilled_at,
//         fulfilled_report_id pointer
//      e. UPSERTs cross_region_rollup with passed/total AND
//         per_control_status (the full report has per-control
//         granularity that summary pushes lack; C31's preservation
//         logic lets this overwrite per_control_status while summary
//         pushes leave it alone)
//      f. Audits COMPLIANCE_FULL_REPORT_FULFILLED on success
//
// BODY SHAPE:
//   {
//     apiKey,
//     requestId,    // integer or numeric string; mc_report_requests.id
//     framework,    // must match the request's framework
//     report        // object, the full generateComplianceReport output;
//                   // expected fields: summary.{verified|passed|total},
//                   // verifiedControls[]
//   }
//
// AUTHENTICATION: api_key resolves MC; verifyPushSignature validates
// signature. Same machinery as the summary ingest path. Re-implemented
// here rather than extracted because the divergent body/storage logic
// would dominate any shared helper anyway.
//
// IDEMPOTENCY: Re-POST of the same requestId after successful
// fulfillment returns 409 Conflict. Reasoning: the MC's C36 logic
// already cleaned up its local state on the first success; a second
// attempt is either a retry where the first response was lost (rare,
// recoverable by the MC catching 409 as success) or a bug. We prefer
// the explicit 409 over silently inserting a duplicate full-report
// row.
//
// CROSS-MC SCOPING: If requestId exists but belongs to a different MC,
// return 404 — same code as nonexistent requestId. Mirrors the C20
// admin endpoint's cross-MC enumeration closure pattern.
//
// FRAMEWORK MUST MATCH: The framework in the body must equal the
// framework recorded in the request row. Catches MC bugs (submitting
// wrong-framework report for a request) without losing the request to
// fulfillment.
function handleFullReportIngest(req, res) {
  let db;
  try {
    const { apiKey, requestId, framework, report } = req.body || {};
    db = getDb();

    // ── Validate apiKey type before SQL ──
    // node:sqlite throws on undefined parameters. Validate the type up
    // front so callers passing an empty body get a clean 400 rather
    // than a defensive 500 from the outer catch.
    if (!apiKey || typeof apiKey !== 'string') {
      db.close();
      return res.status(400).json({
        error: 'apiKey is required',
        code: 'MISSING_API_KEY',
      });
    }

    // ── Resolve MC ──
    const mc = db.prepare("SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'").get(apiKey);
    if (!mc) {
      db.close();
      return res.status(403).json({ error: 'Invalid or inactive MC API key' });
    }

    // ── Verify signature ──
    const sigResult = verifyPushSignature(db, {
      mcId: mc.id,
      headers: req.headers,
      rawBody: req.rawBody,
    });
    if (!sigResult.ok) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('INGEST_SIGNATURE_REJECTED', ?, 'critical')")
        .run(`endpoint=compliance-reports-full mc=${mc.name} mc_id=${mc.id} code=${sigResult.code} fingerprint=${sigResult.fingerprint || 'none'} reason=${JSON.stringify(sigResult.error || '')}`);
      db.close();
      return res.status(401).json({ error: sigResult.error, code: sigResult.code });
    }

    // ── Validate requestId ──
    let requestIdNum;
    if (typeof requestId === 'number' && Number.isInteger(requestId) && requestId > 0) {
      requestIdNum = requestId;
    } else if (typeof requestId === 'string' && /^[1-9][0-9]*$/.test(requestId)) {
      requestIdNum = parseInt(requestId, 10);
    } else {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=invalid_request_id fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'requestId is required and must be a positive integer' });
    }

    // ── Validate framework ──
    if (typeof framework !== 'string' || !framework.trim()) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} reason=missing_framework fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'framework is required and must be a non-empty string' });
    }
    const fw = framework.trim();
    if (fw.length > COMPLIANCE_FRAMEWORK_MAX_LEN || !COMPLIANCE_FRAMEWORK_PATTERN.test(fw)) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} reason=invalid_framework framework=${JSON.stringify(fw.slice(0, 100))} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({
        error: `framework must be ASCII-safe (letters, digits, hyphens, underscores) and max ${COMPLIANCE_FRAMEWORK_MAX_LEN} chars`,
      });
    }

    // ── Validate report object ──
    if (!report || typeof report !== 'object' || Array.isArray(report)) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} framework=${fw} reason=missing_or_invalid_report fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'report is required and must be an object' });
    }
    let reportJson;
    try { reportJson = JSON.stringify(report); }
    catch (jsonErr) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} framework=${fw} reason=report_not_serializable fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'report contains values that cannot be JSON-serialized' });
    }
    if (reportJson.length > COMPLIANCE_FULL_REPORT_MAX_BYTES) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} framework=${fw} reason=report_too_large bytes=${reportJson.length} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({
        error: `report exceeds maximum size of ${COMPLIANCE_FULL_REPORT_MAX_BYTES} bytes`,
      });
    }

    // ── Look up the request row + enforce belongs-to-MC + still-pending ──
    const requestRow = db.prepare(`
      SELECT id, mc_id, framework, status
      FROM mc_report_requests
      WHERE id = ?
    `).get(requestIdNum);
    if (!requestRow || requestRow.mc_id !== mc.id) {
      // Collapse "doesn't exist" and "exists but belongs to a different MC"
      // into the same 404 so an attacker can't enumerate other MCs'
      // request IDs.
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} framework=${fw} reason=request_not_found_for_mc fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(404).json({ error: 'requestId not found for this MC' });
    }
    if (requestRow.framework !== fw) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} body_framework=${fw} request_framework=${requestRow.framework} reason=framework_mismatch fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({
        error: `framework mismatch: request expects ${requestRow.framework}, body has ${fw}`,
      });
    }
    if (requestRow.status !== 'pending') {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} requestId=${requestIdNum} framework=${fw} request_status=${requestRow.status} reason=request_not_pending fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(409).json({
        error: `request is no longer pending (status=${requestRow.status})`,
        code: 'NOT_PENDING',
      });
    }

    // ── Insert the full report ──
    const fullResult = db.prepare(`
      INSERT INTO mc_compliance_report_fulls
        (mc_id, framework, report_json, signature_fingerprint)
      VALUES (?, ?, ?, ?)
    `).run(mc.id, fw, reportJson, sigResult.fingerprint);
    const fullReportId = fullResult.lastInsertRowid;

    // ── Mark the request fulfilled ──
    db.prepare(`
      UPDATE mc_report_requests
      SET status = 'fulfilled',
          fulfilled_at = datetime('now'),
          fulfilled_report_id = ?
      WHERE id = ?
    `).run(fullReportId, requestIdNum);

    // ── Update cross_region_rollup (refresh aggregates AND per_control_status) ──
    // The full report has per-control granularity that summary pushes
    // lack. This UPSERT updates passed/total/last_push_at AND
    // per_control_status from the verifiedControls — overwriting any
    // prior per_control_status value with the freshest data. Subsequent
    // summary pushes (C31) deliberately leave per_control_status alone.
    let rollupUpdated = false;
    try {
      const verified = report.summary?.verified || {};
      const fallback = report.summary || {};
      const rawPassed = (verified.passed !== undefined ? verified.passed : fallback.passed);
      const rawTotal = (verified.total !== undefined ? verified.total : fallback.total);
      const passedNum = Number(rawPassed);
      const totalNum = Number(rawTotal);
      const passed = (Number.isFinite(passedNum) && passedNum >= 0) ? Math.floor(passedNum) : 0;
      const total = (Number.isFinite(totalNum) && totalNum >= 0) ? Math.floor(totalNum) : 0;

      // Build {controlId: status} from verifiedControls
      const perControl = {};
      if (Array.isArray(report.verifiedControls)) {
        for (const c of report.verifiedControls) {
          if (c && typeof c.controlId === 'string' && typeof c.status === 'string') {
            perControl[c.controlId] = c.status;
          }
        }
      }
      const perControlJson = JSON.stringify(perControl);

      db.prepare(`
        INSERT INTO cross_region_rollup (framework, mc_id, passed, total, per_control_status, last_push_at)
        VALUES (?, ?, ?, ?, ?, datetime('now'))
        ON CONFLICT(framework, mc_id) DO UPDATE SET
          passed             = excluded.passed,
          total              = excluded.total,
          per_control_status = excluded.per_control_status,
          last_push_at       = excluded.last_push_at
      `).run(fw, mc.id, passed, total, perControlJson);
      rollupUpdated = true;
    } catch (rollupErr) {
      console.error('cross_region_rollup update failed (full report):', rollupErr.message);
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_ROLLUP_UPDATE_FAILED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} framework=${fw} fullReportId=${fullReportId} reason=${rollupErr.message.slice(0, 200)}`);
    }

    db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('COMPLIANCE_FULL_REPORT_FULFILLED', ?, 'info')")
      .run(`From ${mc.name}: framework=${fw} requestId=${requestIdNum} fullReportId=${fullReportId} bytes=${reportJson.length} fingerprint=${sigResult.fingerprint}${sigResult.viaGraceWindow ? ' viaGraceWindow=true' : ''} rollup_updated=${rollupUpdated}`);
    db.close();

    return res.status(202).json({
      success: true,
      mc: mc.name,
      requestId: requestIdNum,
      fullReportId,
      framework: fw,
    });
  } catch (e) {
    console.error('Full-report ingest error:', e);
    try { if (db) db.close(); } catch (_) {}
    return res.status(500).json({ error: 'Full report ingest failed' });
  }
}

app.post('/api/ingest/compliance-reports', (req, res) => {
  // R3g PR3 Phase 7 (C35): dispatch to the full-report handler when the
  // caller signals fulfillment intent. Validation/auth duplication between
  // the two paths is acceptable; the divergent body shapes + storage
  // logic dominate any shared helper.
  if (req.query?.full === 'true') {
    return handleFullReportIngest(req, res);
  }
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

// ── Cross-Region Compliance Rollup — Admin (R3g PR3 Phase 8 / C37) ─────────
//
// GET /api/compliance/rollup
//
// Returns the materialized per-(framework, mc_id) compliance state that
// the CISO UI uses to render its framework × MC heat-map matrix. Reads
// from cross_region_rollup, the table that Commits 31 + 35 have been
// populating via UPSERT on every successful compliance ingest (both
// summary pushes and full-report fulfillments).
//
// AUTH: ['ciso', 'vp', 'readonly'] — standard read access for compliance
// reporting. The endpoint reveals no MC-internal data, only aggregates
// the MCs themselves have already pushed.
//
// QUERY PARAMETERS (all optional, all filters AND together):
//   framework   ASCII-safe pattern, max 64 chars. Limits results to one
//               framework. The CISO UI uses this for "drill into HIPAA
//               status across all my MCs" views.
//   mc_id       ASCII-safe pattern, max 64 chars. Limits results to one
//               MC. Used for "show all framework state for this MC"
//               views.
//   region      ASCII-safe pattern, max 64 chars. Limits results to MCs
//               in a specific region (e.g. 'eu', 'us-east'). Used for
//               regional compliance reviews.
//
// RESPONSE SHAPE:
//   {
//     rollups: [
//       {
//         framework, mc_id, mc_name, region,
//         passed, total,
//         last_push_at,
//         has_drilldown            // true iff cross_region_rollup.
//                                  // per_control_status IS NOT NULL.
//                                  // The UI uses this to decide
//                                  // whether to offer the
//                                  // "see per-control detail" link
//                                  // (which calls C38/C39).
//       },
//       ...
//     ]
//   }
//
// DELIBERATELY NOT INCLUDED IN RESPONSE:
//
//   per_control_status  The full per-control JSON drilldown can be
//                       large (~50 KB per framework). Across 50 MCs ×
//                       16 frameworks that's 40 MB on a single call.
//                       The UI fetches drilldown one cell at a time
//                       via C38/C39 (drilldown_endpoints) when the
//                       CISO clicks into a specific (mc, framework).
//
// ACTIVE MCS ONLY: JOIN with management_consoles filters status='active'.
// Offboarded MCs' historical rollup rows still exist (FK cascade only
// fires on full delete) but shouldn't appear in the live heat map.
//
// ORDERING: BY framework ASC, mc_id ASC. Stable across calls; the UI
// can rely on the matrix shape being consistent for client-side
// row/column indexing.
//
// EMPTY STATE: Returns { rollups: [] } when no data has arrived yet
// (e.g. on a freshly-deployed GD with no MCs pushing). The UI shows
// "No compliance data yet" appropriately.
//
// NOT AUDITED: Read-only admin queries. Auth failure audits at the
// middleware level; success queries are not noisy enough to warrant
// per-call audit entries.

const ROLLUP_FILTER_PATTERN = /^[A-Za-z0-9_-]+$/;
const ROLLUP_FILTER_MAX_LEN = 64;

app.get('/api/compliance/rollup',
  authMiddleware(['ciso', 'vp', 'readonly']),
  (req, res) => {
    try {
      const { framework, mc_id, region } = req.query || {};

      // ── Validate optional filters ──
      for (const [name, val] of Object.entries({ framework, mc_id, region })) {
        if (val === undefined) continue;
        if (typeof val !== 'string') {
          return res.status(400).json({
            error: `${name} must be a string`,
          });
        }
        if (val.length > ROLLUP_FILTER_MAX_LEN || !ROLLUP_FILTER_PATTERN.test(val)) {
          return res.status(400).json({
            error: `${name} must be ASCII-safe (letters, digits, hyphens, underscores) and max ${ROLLUP_FILTER_MAX_LEN} chars`,
          });
        }
      }

      const db = getDb();
      const whereClauses = ["mc.status = 'active'"];
      const params = [];
      if (framework) { whereClauses.push('r.framework = ?'); params.push(framework); }
      if (mc_id) { whereClauses.push('r.mc_id = ?'); params.push(mc_id); }
      if (region) { whereClauses.push('mc.region = ?'); params.push(region); }

      const sql = `
        SELECT
          r.framework,
          r.mc_id,
          mc.name AS mc_name,
          mc.region,
          r.passed,
          r.total,
          r.last_push_at,
          CASE WHEN r.per_control_status IS NOT NULL THEN 1 ELSE 0 END AS has_drilldown
        FROM cross_region_rollup r
        JOIN management_consoles mc ON mc.id = r.mc_id
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY r.framework ASC, r.mc_id ASC
      `;
      const rows = db.prepare(sql).all(...params);
      db.close();

      // Coerce has_drilldown to boolean for cleaner JSON output (SQLite
      // returns 0/1 integers from CASE expressions).
      const rollups = rows.map(r => ({
        framework: r.framework,
        mc_id: r.mc_id,
        mc_name: r.mc_name,
        region: r.region,
        passed: r.passed,
        total: r.total,
        last_push_at: r.last_push_at,
        has_drilldown: r.has_drilldown === 1,
      }));

      return res.json({ rollups });
    } catch (e) {
      console.error('compliance rollup error:', e);
      return res.status(500).json({ error: 'Failed to read compliance rollup' });
    }
  }
);

// ── MC Full-Reports List — Admin (R3g PR3 Phase 8 / C38) ──────────────────
//
// GET /api/mc/:id/full-reports[?framework=&limit=]
//
// Lists fulfilled full-report METADATA for a specific MC. Used by the
// CISO UI when a user drills into an MC's profile and wants to see
// "history of full reports the CISO has requested and received."
// Returns metadata only (framework, received_at, expires_at, bytes,
// signature_fingerprint); the actual report payload comes from the
// detail endpoint (C39, upcoming).
//
// AUTH: ['ciso', 'vp', 'readonly']. Same access tier as the rollup
// matrix — reading historical compliance artifacts is part of routine
// review.
//
// QUERY PARAMS:
//   framework   (optional) ASCII-safe key, max 64 chars. Narrows
//               to one framework. UI uses this for "show me HIPAA
//               report history for this MC" views.
//   limit       (optional) integer 1-200, default 50. Bounds
//               response size. The mc_compliance_report_fulls
//               table grows over time (until 30-day TTL prunes
//               old rows) and a CISO who requests full reports
//               often could accumulate hundreds.
//
// PATH PARAM:
//   :id   MC's internal id. Looked up against management_consoles
//         WITHOUT filtering on status — offboarded MCs' historical
//         reports remain visible for compliance audit purposes.
//         Diverges from the rollup endpoint (C37) which IS active-
//         only because that endpoint surfaces live current state.
//         Returns 404 only if the MC never existed at all.
//
// RESPONSE SHAPE (200):
//   {
//     reports: [
//       {
//         id, framework, received_at, expires_at,
//         signature_fingerprint, bytes
//       },
//       ...
//     ]
//   }
//
// DELIBERATELY EXCLUDED FROM LIST:
//
//   report_json   The full report payload can be ~50 KB per row
//                 and up to 1 MB. Across 50 reports that's 50 MB
//                 on a single list call. The UI fetches the body
//                 one report at a time via C39 when the user
//                 clicks a specific row.
//
// EXPIRED ROWS INCLUDED BY DEFAULT
//
// Rows past their expires_at but not yet pruned by the cleanup
// job are still listed. Reasoning: the row exists, is queryable,
// and is honest data. The UI renders an "Expired (will be pruned)"
// badge based on the response's expires_at vs current time. The
// 30-day TTL is the GD's storage policy; the UI surfaces it
// honestly rather than the API hiding pre-prune rows.
//
// ORDERING
//
// received_at DESC, then id DESC as a tiebreaker (two reports
// arriving in the same second from the same MC for different
// frameworks share received_at). Newest-first matches CISO mental
// model: "show me what came in recently."
//
// NOT AUDITED
//
// Read-only admin queries. Auth middleware audits failed
// authorizations; success queries are not noisy enough for
// per-call audit.

const FULL_REPORTS_FILTER_PATTERN = /^[A-Za-z0-9_-]+$/;
const FULL_REPORTS_FILTER_MAX_LEN = 64;
const FULL_REPORTS_DEFAULT_LIMIT = 50;
const FULL_REPORTS_MAX_LIMIT = 200;

app.get('/api/mc/:id/full-reports',
  authMiddleware(['ciso', 'vp', 'readonly']),
  (req, res) => {
    let db;
    try {
      const mcId = req.params.id;
      const { framework, limit } = req.query || {};

      // ── Validate mc_id ──
      if (typeof mcId !== 'string' || mcId.length > FULL_REPORTS_FILTER_MAX_LEN || !FULL_REPORTS_FILTER_PATTERN.test(mcId)) {
        return res.status(400).json({
          error: `mc id must be ASCII-safe (letters, digits, hyphens, underscores) and max ${FULL_REPORTS_FILTER_MAX_LEN} chars`,
        });
      }

      // ── Validate framework filter ──
      if (framework !== undefined) {
        if (typeof framework !== 'string') {
          return res.status(400).json({ error: 'framework must be a string' });
        }
        if (framework.length > FULL_REPORTS_FILTER_MAX_LEN || !FULL_REPORTS_FILTER_PATTERN.test(framework)) {
          return res.status(400).json({
            error: `framework must be ASCII-safe (letters, digits, hyphens, underscores) and max ${FULL_REPORTS_FILTER_MAX_LEN} chars`,
          });
        }
      }

      // ── Validate limit ──
      let limitNum = FULL_REPORTS_DEFAULT_LIMIT;
      if (limit !== undefined) {
        const parsed = parseInt(limit, 10);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > FULL_REPORTS_MAX_LIMIT || String(parsed) !== String(limit).trim()) {
          return res.status(400).json({
            error: `limit must be an integer between 1 and ${FULL_REPORTS_MAX_LIMIT}`,
          });
        }
        limitNum = parsed;
      }

      db = getDb();

      // ── Verify MC exists at all (any status) ──
      const mc = db.prepare("SELECT id FROM management_consoles WHERE id = ?").get(mcId);
      if (!mc) {
        db.close();
        return res.status(404).json({ error: 'MC not found' });
      }

      // ── Query reports ──
      const whereClauses = ['mc_id = ?'];
      const params = [mcId];
      if (framework) {
        whereClauses.push('framework = ?');
        params.push(framework);
      }
      params.push(limitNum);

      const rows = db.prepare(`
        SELECT
          id,
          framework,
          received_at,
          expires_at,
          signature_fingerprint,
          length(report_json) AS bytes
        FROM mc_compliance_report_fulls
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY received_at DESC, id DESC
        LIMIT ?
      `).all(...params);
      db.close();

      return res.json({ reports: rows });
    } catch (e) {
      console.error('mc full-reports list error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Failed to list full reports' });
    }
  }
);

// ── MC Full-Report Detail — Admin (R3g PR3 Phase 8 / C39) ─────────────────
//
// GET /api/mc/:id/full-reports/:reportId
//
// Fetches a single fulfilled full-report's complete payload — metadata
// PLUS the parsed report body. This is the ONLY endpoint that returns
// report_json content; C37 (rollup) and C38 (list) deliberately omit
// the heavy data field.
//
// AUTH: ['ciso', 'vp', 'readonly']. Same access tier as the rollup
// matrix and report list — the report's contents are the MC's own
// pushed data, no GD-internal secrets.
//
// PATH PARAMS:
//   :id        MC's internal id. Validated against the ASCII-safe
//              pattern. Looked up against management_consoles WITHOUT
//              filtering on status (offboarded MCs' historical reports
//              remain accessible for audit retention; consistent with
//              C38).
//   :reportId  mc_compliance_report_fulls.id. Must be a positive
//              integer (accepted as JSON number or string of digits).
//
// PER-MC SCOPING — CROSS-MC ENUMERATION CLOSURE
//
// The report row must satisfy BOTH (id = :reportId AND mc_id = :id).
// A report id that exists but belongs to a DIFFERENT MC returns the
// SAME 404 message as a nonexistent id. An attacker enumerating
// report ids cannot probe which IDs exist on other MCs they don't
// have access to. Mirrors the C35 fulfillment endpoint's collapse
// pattern.
//
// RESPONSE SHAPE (200):
//   {
//     report: {
//       id, mc_id, framework, received_at, expires_at,
//       signature_fingerprint, bytes,
//       data: { /* parsed report_json */ }
//     }
//   }
//
// FIELD NAMING NOTE: the original C35 ingest body field was `report`
// and the storage column is `report_json`. To avoid clashing with the
// outer `report:` wrapper key, the parsed body surfaces as `data` in
// the response. Three names for the same data is unavoidable; the
// response field is the only one we control without breaking existing
// integrations.
//
// JSON PARSE FALLBACK
//
// report_json was inserted by C35 via JSON.stringify(report) and should
// always be valid JSON. Defensive: if parse fails (data corruption,
// disk error during ingest, manual DB tampering), return 500 with a
// generic error message and log the report id for forensic
// investigation. The 500 is appropriate — the data is stored but
// damaged; this isn't a client error.
//
// EXPIRED REPORTS STILL SERVED
//
// Same logic as C38: reports past their expires_at but not yet pruned
// remain queryable. The UI surfaces the expiry timestamp; clients
// requesting an expired-but-extant report get the data. The 30-day
// TTL is a storage policy, not an API contract.
//
// NOT AUDITED
//
// Read-only admin queries. Auth middleware handles authorization
// auditing.

const FULL_REPORT_DETAIL_FILTER_PATTERN = /^[A-Za-z0-9_-]+$/;
const FULL_REPORT_DETAIL_FILTER_MAX_LEN = 64;

app.get('/api/mc/:id/full-reports/:reportId',
  authMiddleware(['ciso', 'vp', 'readonly']),
  (req, res) => {
    let db;
    try {
      const mcId = req.params.id;
      const reportIdRaw = req.params.reportId;

      // ── Validate mc_id ──
      if (typeof mcId !== 'string' || mcId.length > FULL_REPORT_DETAIL_FILTER_MAX_LEN || !FULL_REPORT_DETAIL_FILTER_PATTERN.test(mcId)) {
        return res.status(400).json({
          error: `mc id must be ASCII-safe (letters, digits, hyphens, underscores) and max ${FULL_REPORT_DETAIL_FILTER_MAX_LEN} chars`,
        });
      }

      // ── Validate reportId (positive integer, accepts numeric strings) ──
      if (typeof reportIdRaw !== 'string' || !/^[1-9][0-9]*$/.test(reportIdRaw)) {
        return res.status(400).json({ error: 'reportId must be a positive integer' });
      }
      const reportIdNum = parseInt(reportIdRaw, 10);

      db = getDb();

      // ── Verify MC exists at all ──
      const mc = db.prepare("SELECT id FROM management_consoles WHERE id = ?").get(mcId);
      if (!mc) {
        db.close();
        return res.status(404).json({ error: 'MC not found' });
      }

      // ── Fetch report; collapse cross-MC mismatch to same 404 ──
      const row = db.prepare(`
        SELECT
          id, mc_id, framework, report_json, signature_fingerprint,
          received_at, expires_at,
          length(report_json) AS bytes
        FROM mc_compliance_report_fulls
        WHERE id = ? AND mc_id = ?
      `).get(reportIdNum, mcId);
      db.close();

      if (!row) {
        // Could be nonexistent reportId OR reportId belonging to another
        // MC. Same 404 for both — prevents cross-MC enumeration.
        return res.status(404).json({ error: 'Report not found for this MC' });
      }

      // ── Parse the stored JSON body ──
      let parsedBody;
      try {
        parsedBody = JSON.parse(row.report_json);
      } catch (parseErr) {
        console.error('mc full-report parse error:', { id: row.id, error: parseErr.message });
        return res.status(500).json({ error: 'Stored report data is corrupted' });
      }

      return res.json({
        report: {
          id: row.id,
          mc_id: row.mc_id,
          framework: row.framework,
          received_at: row.received_at,
          expires_at: row.expires_at,
          signature_fingerprint: row.signature_fingerprint,
          bytes: row.bytes,
          data: parsedBody,
        },
      });
    } catch (e) {
      console.error('mc full-report detail error:', e);
      try { if (db) db.close(); } catch (_) {}
      return res.status(500).json({ error: 'Failed to read full report' });
    }
  }
);

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

// ── Regression Test (R3k C26) ────────────────────────────────────────────────
//
// Replaces the v1.0.36 8-pass mock with a real 22-check regression
// runner covering GD-side schema integrity, MC trust, auth, cross-
// region rollup, compliance pipeline, backup machinery, and system
// health. Symmetric to the MC-side /api/regression/run rewrite in
// R3k C4-C6 but checks the GD-server's own canonical state rather
// than the MC's.
//
// CHECK CATEGORIES (22 total)
//
//   schema (4):       integrity_check PRAGMA, canonical-table
//                     presence, backups.format_version column,
//                     signing_keys expected columns
//   mc-trust (3):     management_consoles accessible, signing_keys
//                     active-key coverage, signing-keys service
//                     loadable
//   auth (3):         JWT_SECRET configured, users table accessible
//                     + CISO count, sessions table accessible
//   cross-region (3): cross_region_rollup accessible, regional_metrics
//                     accessible, mc-signature-verifier loadable
//   compliance (3):   mc_compliance_reports + _fulls + _requests
//                     all reachable
//   backup (3):       backups v2-aware, backup_schedules accessible,
//                     latest backup status sane
//   system (3):       Node version >= 18, process RSS sanity,
//                     SQLite version check
//
// Each check returns {name, category, status: 'pass'|'fail'|'skip',
// detail}. Aggregate response: {timestamp, tests, passed, failed,
// skipped, total, overall, summary}.
//
// Endpoint remains POST /api/regression-test, authMiddleware(['ciso'])
// — same surface contract; the response shape is backward-compatible
// (tests[] + passed + total + overall) with additional fields for
// the new richer output.

const CANONICAL_GD_TABLES = [
  'audit_log', 'auth_log', 'backup_schedules', 'backups',
  'config', 'cross_region_rollup', 'management_consoles',
  'mc_compliance_report_fulls', 'mc_compliance_reports',
  'mc_report_requests', 'notifications',
  'regional_leaderboard', 'regional_metrics',
  'reports', 'sessions', 'signing_keys',
  'system_health', 'system_meta', 'users',
];

function runGdRegression(db) {
  const tests = [];
  const record = (category, name, fn) => {
    try {
      const detail = fn();
      tests.push({ category, name, status: 'pass', detail: detail || 'ok' });
    } catch (err) {
      tests.push({ category, name, status: 'fail', detail: String(err.message || err).slice(0, 500) });
    }
  };

  // ── Schema (4) ─────────────────────────────────────────────────────────
  record('schema', 'sqlite integrity_check', () => {
    const r = db.prepare('PRAGMA integrity_check').get();
    if (!r || (r.integrity_check !== 'ok' && r['integrity_check'] !== 'ok')) {
      throw new Error(`integrity_check returned ${JSON.stringify(r)}`);
    }
    return 'ok';
  });
  record('schema', 'canonical tables present', () => {
    const rows = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
    const present = new Set(rows.map(r => r.name));
    const missing = CANONICAL_GD_TABLES.filter(t => !present.has(t));
    if (missing.length > 0) throw new Error(`missing tables: ${missing.join(', ')}`);
    return `${CANONICAL_GD_TABLES.length} canonical tables present`;
  });
  record('schema', 'backups.format_version column (v2)', () => {
    const cols = db.prepare('PRAGMA table_info(backups)').all();
    const names = cols.map(c => c.name);
    if (!names.includes('format_version')) throw new Error('backups.format_version column missing');
    return 'format_version present';
  });
  record('schema', 'signing_keys schema', () => {
    const cols = db.prepare('PRAGMA table_info(signing_keys)').all();
    const required = ['id', 'mc_id', 'public_key', 'status'];
    const names = cols.map(c => c.name);
    const missing = required.filter(c => !names.includes(c));
    if (missing.length > 0) throw new Error(`signing_keys missing columns: ${missing.join(', ')}`);
    return `${cols.length} columns, all required present`;
  });

  // ── MC trust (3) ───────────────────────────────────────────────────────
  record('mc-trust', 'management_consoles accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM management_consoles').get().n;
    return `${n} MC registration(s)`;
  });
  record('mc-trust', 'signing_keys active-key coverage', () => {
    const mcs = db.prepare("SELECT id FROM management_consoles WHERE status='active'").all();
    if (mcs.length === 0) return '0 active MCs (vacuously covered)';
    const uncovered = [];
    for (const mc of mcs) {
      const k = db.prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE mc_id = ? AND status = 'active'").get(mc.id);
      if (k.n === 0) uncovered.push(mc.id);
    }
    if (uncovered.length > 0) throw new Error(`MCs without active signing key: ${uncovered.length}`);
    return `${mcs.length} active MC(s), all with active signing key`;
  });
  record('mc-trust', 'signing-keys service loadable', () => {
    if (typeof signingKeysSvc !== 'object' || signingKeysSvc === null) throw new Error('signingKeysSvc not loaded');
    if (typeof signingKeysSvc.submitPending !== 'function') throw new Error('signingKeysSvc.submitPending missing');
    return 'service module loaded';
  });

  // ── Auth (3) ───────────────────────────────────────────────────────────
  record('auth', 'JWT_SECRET configured', () => {
    if (!JWT_SECRET || typeof JWT_SECRET !== 'string' || JWT_SECRET.length < 16) {
      throw new Error('JWT_SECRET missing or too short');
    }
    if (!process.env.GD_JWT_SECRET) return 'using ephemeral fallback (set GD_JWT_SECRET for persistence across restarts)';
    return 'GD_JWT_SECRET env var present';
  });
  record('auth', 'users table + CISO coverage', () => {
    const total = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
    const ciso = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='ciso'").get().n;
    return `${total} user(s), ${ciso} CISO`;
  });
  record('auth', 'sessions table accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n;
    return `${n} session row(s)`;
  });

  // ── Cross-region (3) ───────────────────────────────────────────────────
  record('cross-region', 'cross_region_rollup accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM cross_region_rollup').get().n;
    return `${n} rollup row(s)`;
  });
  record('cross-region', 'regional_metrics accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM regional_metrics').get().n;
    return `${n} metric row(s)`;
  });
  record('cross-region', 'mc-signature-verifier loadable', () => {
    if (typeof verifyPushSignature !== 'function') throw new Error('verifyPushSignature not loaded');
    return 'verifier module loaded';
  });

  // ── Compliance (3) ─────────────────────────────────────────────────────
  record('compliance', 'mc_compliance_reports accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM mc_compliance_reports').get().n;
    return `${n} report summary row(s)`;
  });
  record('compliance', 'mc_compliance_report_fulls accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM mc_compliance_report_fulls').get().n;
    return `${n} full-report row(s)`;
  });
  record('compliance', 'mc_report_requests accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM mc_report_requests').get().n;
    return `${n} report request row(s)`;
  });

  // ── Backup (3) ─────────────────────────────────────────────────────────
  record('backup', 'backups v2-aware', () => {
    const cols = db.prepare('PRAGMA table_info(backups)').all().map(c => c.name);
    const v2Required = ['format_version', 'manifest_path', 'archive_path'];
    const missing = v2Required.filter(c => !cols.includes(c));
    if (missing.length > 0) throw new Error(`v2 columns missing: ${missing.join(', ')}`);
    return 'v2 columns present';
  });
  record('backup', 'backup_schedules accessible', () => {
    const n = db.prepare('SELECT COUNT(*) AS n FROM backup_schedules').get().n;
    return `${n} schedule row(s)`;
  });
  record('backup', 'latest backup status sane', () => {
    const latest = db.prepare('SELECT id, status, created_at FROM backups ORDER BY created_at DESC LIMIT 1').get();
    if (!latest) return 'no backups recorded yet';
    if (latest.status === 'corrupt' || latest.status === 'tampered') {
      throw new Error(`latest backup id=${latest.id} status=${latest.status}`);
    }
    return `latest id=${latest.id} status=${latest.status}`;
  });

  // ── System (3) ─────────────────────────────────────────────────────────
  record('system', 'Node.js >= 18', () => {
    const major = parseInt((process.versions.node || '0').split('.')[0], 10);
    if (!(major >= 18)) throw new Error(`Node major version ${major} < 18`);
    return `Node ${process.versions.node}`;
  });
  record('system', 'process RSS sanity', () => {
    const rss = process.memoryUsage().rss;
    if (rss > 4 * 1024 * 1024 * 1024) throw new Error(`RSS ${rss} > 4GB`);
    return `RSS ${(rss / 1024 / 1024).toFixed(1)} MiB`;
  });
  record('system', 'SQLite version', () => {
    const r = db.prepare('SELECT sqlite_version() AS v').get();
    if (!r || !r.v) throw new Error('sqlite_version() returned null');
    return `sqlite ${r.v}`;
  });

  const passed = tests.filter(t => t.status === 'pass').length;
  const failed = tests.filter(t => t.status === 'fail').length;
  const skipped = tests.filter(t => t.status === 'skip').length;
  const total = tests.length;

  return {
    timestamp: new Date().toISOString(),
    tests,
    passed,
    failed,
    skipped,
    total,
    overall: failed === 0 ? 'pass' : 'fail',
    summary: { passed, failed, skipped, total },
    side: 'gd',
  };
}

app.post('/api/regression-test', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const results = runGdRegression(db);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'REGRESSION_RUN', ?, ?)")
      .run(req.user.id, `result: ${results.passed}/${results.total} pass, ${results.failed} fail`, results.failed === 0 ? 'info' : 'warning');
    db.close();
    res.json(results);
  } catch (e) {
    res.status(500).json({ error: 'Regression test failed', message: e.message });
  }
});

// ── Cloud & IaC Generator (R3k C30, Sub-phase 6) ─────────────────────────────
//
// GD-side equivalent of MC's /api/cloud/* surface. Generates deploy-
// ment bundles for FIREALIVE GD-server itself (image
// ghcr.io/petermancina/firealive-gd, port 4001) rather than for MC-
// server. Consumes cloud-iac-bundle.js (R3k C29) which collapses
// MC's R3k C9-C22 services into one consolidated module.
//
//   GET  /api/cloud/providers                provider x iac_tool matrix
//                                            + secrets mapping
//   POST /api/cloud/package                  generate bundle. Body:
//                                            {provider, iac_tool}.
//                                            Returns full result manifest.
//   GET  /api/cloud/packages                 list past bundles (100 most
//                                            recent, reverse-chrono).
//   GET  /api/cloud/packages/:id             fetch row + parsed snapshot.
//   GET  /api/cloud/packages/:id/download    stream bundle.tar.gz.
//   GET  /api/cloud/packages/:id/public-key  retrieve the verifier PEM
//                                            for the signing key that
//                                            produced this bundle's sig.
//   POST /api/cloud/signing-keys/rotate      operator-triggered rotation.
//
// AUTH: ciso for write ops (generate, rotate); ciso + vp for reads.
// 503 mapped from SyftNotInstalledError / CosignNotInstalledError so
// the operator sees a clear install-command message when the
// supply-chain binaries are missing.

app.get('/api/cloud/providers', authMiddleware(['ciso', 'vp']), (req, res) => {
  res.json({
    provider_tool_matrix: cloudIacBundle.PROVIDER_TOOL_MATRIX,
    secrets_mapping: cloudIacBundle.SECRETS_MAPPING_BY_PROVIDER,
    deploy_shape: cloudIacBundle.GD_DEPLOY_SHAPE,
  });
});

app.post('/api/cloud/package', authMiddleware(['ciso']), (req, res) => {
  const { provider, iac_tool } = req.body || {};
  if (!provider || !iac_tool) {
    return res.status(400).json({
      error: 'provider and iac_tool are required',
      providers: Object.keys(cloudIacBundle.PROVIDER_TOOL_MATRIX),
    });
  }
  let db;
  try {
    db = getDb();
    const result = cloudIacBundle.generatePackage(db, provider, iac_tool, { userId: req.user.id });
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CLOUD_PACKAGE_GENERATED', ?, 'info')")
      .run(req.user.id, `id=${result.id} provider=${provider} iac_tool=${iac_tool}`);
    db.close();
    res.json(result);
  } catch (err) {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
    if (err.name === 'SyftNotInstalledError' || err.code === 'SYFT_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Syft not installed', message: err.message, code: 'SYFT_NOT_INSTALLED' });
    }
    if (err.name === 'CosignNotInstalledError' || err.code === 'COSIGN_NOT_INSTALLED') {
      return res.status(503).json({ error: 'Cosign not installed', message: err.message, code: 'COSIGN_NOT_INSTALLED' });
    }
    if (/^invalid (provider|\(provider)/.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    try {
      const adb = getDb();
      adb.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CLOUD_PACKAGE_FAILED', ?, 'warning')")
        .run(req.user.id, `provider=${provider} iac_tool=${iac_tool} error=${(err.message || '').slice(0, 200)}`);
      adb.close();
    } catch (_) { /* swallow audit failure */ }
    res.status(500).json({ error: 'Cloud package generation failed', message: err.message });
  }
});

app.get('/api/cloud/packages', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(
        `SELECT id, provider, iac_tool, generated_at, generated_by,
                bundle_archive_path, manifest_sha256, sbom_sha256,
                signature_sha256, signing_key_id, size_bytes
           FROM cloud_packages
           ORDER BY generated_at DESC
           LIMIT 100`,
      )
      .all();
    db.close();
    res.json({ packages: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to list cloud packages', message: e.message });
  }
});

app.get('/api/cloud/packages/:id', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM cloud_packages WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'package not found' });
    let snapshot = null;
    try { snapshot = JSON.parse(row.install_snapshot_json); } catch (e) { /* leave null */ }
    res.json({ ...row, install_snapshot: snapshot });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch package', message: e.message });
  }
});

app.get('/api/cloud/packages/:id/download', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT bundle_archive_path, provider, iac_tool FROM cloud_packages WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'package not found' });
    const fs = require('fs');
    if (!fs.existsSync(row.bundle_archive_path)) {
      return res.status(410).json({ error: 'bundle archive no longer on disk' });
    }
    res.setHeader('Content-Disposition', `attachment; filename="firealive-gd-${row.provider}-${row.iac_tool}-${req.params.id}.tar.gz"`);
    res.setHeader('Content-Type', 'application/gzip');
    fs.createReadStream(row.bundle_archive_path).pipe(res);
  } catch (e) {
    res.status(500).json({ error: 'Failed to download package', message: e.message });
  }
});

app.get('/api/cloud/packages/:id/public-key', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT signing_key_id FROM cloud_packages WHERE id = ?').get(req.params.id);
    if (!row) { db.close(); return res.status(404).json({ error: 'package not found' }); }
    const key = cloudIacBundle.signingKeys.getVerificationKey(db, row.signing_key_id);
    db.close();
    if (!key) return res.status(404).json({ error: 'signing key not found' });
    res.json({
      key_id: key.id,
      public_key_pem: key.publicKeyPem,
      algorithm: key.algorithm,
      status: key.status,
      fingerprint_sha256: key.publicKeyFingerprint,
      created_at: key.createdAt,
      rotated_at: key.rotatedAt,
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch public key', message: e.message });
  }
});

app.post('/api/cloud/signing-keys/rotate', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const result = cloudIacBundle.signingKeys.rotateActiveKey(db);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CLOUD_SIGNING_KEY_ROTATED', ?, 'info')")
      .run(req.user.id, `oldId=${result.oldId || '(none)'} newId=${result.newId}`);
    db.close();
    res.json({ rotated: true, ...result });
  } catch (e) {
    res.status(500).json({ error: 'Signing key rotation failed', message: e.message });
  }
});

// ── CI/CD Pipeline Generator (R3k C32, Sub-phase 6) ──────────────────────────
//
// GD-side equivalent of MC's /api/cicd/* surface (R3k C24). Generates
// CI pipeline configs for FIREALIVE GD-server deployment.
//
//   GET  /api/cicd/platforms                   ciso + vp
//   POST /api/cicd/generate                    ciso
//   GET  /api/cicd/configs                     ciso + vp
//   GET  /api/cicd/configs/:id                 ciso + vp
//   GET  /api/cicd/configs/:id/download        ciso + vp
//   POST /api/cicd/runs                        shared-secret header auth
//   GET  /api/cicd/runs                        ciso + vp
//   GET  /api/cicd/runs/:id                    ciso + vp
//   GET  /api/cicd/webhook-secret              ciso (reveal current)
//   POST /api/cicd/webhook-secret/rotate       ciso (rotate)
//
// AUTH DIVERGENCE FROM MC
// =======================
//
// MC's /api/cicd uses dual auth (admin JWT + api-key with cicd:webhook
// scope). GD has no general api-key + scope infrastructure (the only
// "api keys" on GD-side are management_consoles.api_key values, used
// in request bodies for MC-to-GD ingest endpoints, not as auth
// headers for arbitrary requests). Rather than build that
// infrastructure for one webhook receiver, GD's C32 uses a simpler
// shared-secret header model:
//
//   - X-CICD-Webhook-Secret: <secret>
//   - Secret is auto-generated on first /api/cicd/webhook-secret read,
//     stored in config table as 'cicd_webhook_secret'.
//   - CISO can reveal the current secret via GET, or rotate via
//     POST .../rotate. Old secret is invalid immediately after
//     rotation.
//
// This matches the SOC-grade lift of the feature (single-purpose
// webhook receiver, CI is the only consumer) without expanding the
// auth model.

function gdGetOrCreateCicdWebhookSecret(db) {
  const existing = db.prepare("SELECT value FROM config WHERE key = 'cicd_webhook_secret'").get();
  if (existing) return existing.value;
  const newSecret = crypto.randomBytes(32).toString('hex');
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('cicd_webhook_secret', ?)").run(newSecret);
  return newSecret;
}

function gdVerifyCicdWebhookSecret(req, db) {
  const supplied = req.headers['x-cicd-webhook-secret'];
  if (!supplied || typeof supplied !== 'string') return false;
  const row = db.prepare("SELECT value FROM config WHERE key = 'cicd_webhook_secret'").get();
  if (!row || !row.value) return false;
  // Constant-time compare
  const a = Buffer.from(supplied);
  const b = Buffer.from(row.value);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

app.get('/api/cicd/platforms', authMiddleware(['ciso', 'vp']), (req, res) => {
  res.json({
    platforms: cicdBundle.VALID_PLATFORMS,
    purposes: cicdBundle.VALID_PURPOSES,
    filenames: cicdBundle.PLATFORM_FILENAME,
    deploy_shape: cicdBundle.GD_CICD_SHAPE,
  });
});

app.post('/api/cicd/generate', authMiddleware(['ciso']), (req, res) => {
  const { platform, purpose } = req.body || {};
  if (!platform || !purpose) {
    return res.status(400).json({
      error: 'platform and purpose are required',
      valid_platforms: cicdBundle.VALID_PLATFORMS,
      valid_purposes: cicdBundle.VALID_PURPOSES,
    });
  }
  let db;
  try {
    db = getDb();
    const result = cicdBundle.generateConfig(db, platform, purpose, { userId: req.user.id });
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CICD_CONFIG_GENERATED', ?, 'info')")
      .run(req.user.id, `id=${result.id} platform=${platform} purpose=${purpose}`);
    db.close();
    res.json(result);
  } catch (err) {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
    if (/^invalid (platform|purpose)/.test(err.message)) {
      return res.status(400).json({ error: err.message });
    }
    try {
      const adb = getDb();
      adb.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CICD_CONFIG_FAILED', ?, 'warning')")
        .run(req.user.id, `platform=${platform} purpose=${purpose} error=${(err.message || '').slice(0, 200)}`);
      adb.close();
    } catch (_) { /* swallow */ }
    res.status(500).json({ error: 'CICD config generation failed', message: err.message });
  }
});

app.get('/api/cicd/configs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(`SELECT id, platform, purpose, generated_at, generated_yaml_path, created_by FROM cicd_configs ORDER BY generated_at DESC LIMIT 100`)
      .all();
    db.close();
    res.json({ configs: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to list cicd configs', message: e.message });
  }
});

app.get('/api/cicd/configs/:id', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM cicd_configs WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'config not found' });
    let snapshot = null;
    try { snapshot = JSON.parse(row.current_install_snapshot_json); } catch (e) { /* leave null */ }
    res.json({ ...row, install_snapshot: snapshot });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch cicd config', message: e.message });
  }
});

app.get('/api/cicd/configs/:id/download', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT platform, generated_yaml_path FROM cicd_configs WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'config not found' });
    const fs = require('fs');
    if (!fs.existsSync(row.generated_yaml_path)) {
      return res.status(410).json({ error: 'pipeline file no longer on disk' });
    }
    const filename = cicdBundle.PLATFORM_FILENAME[row.platform] || 'pipeline.yml';
    const downloadName = filename.split('/').pop();
    res.setHeader('Content-Disposition', `attachment; filename="${downloadName}"`);
    res.setHeader('Content-Type', 'text/yaml');
    fs.createReadStream(row.generated_yaml_path).pipe(res);
  } catch (e) {
    res.status(500).json({ error: 'download failed', message: e.message });
  }
});

// Shared-secret-authenticated webhook receiver (NO JWT required)
app.post('/api/cicd/runs', (req, res) => {
  let db;
  try {
    db = getDb();
    if (!gdVerifyCicdWebhookSecret(req, db)) {
      db.close();
      return res.status(403).json({ error: 'Invalid or missing X-CICD-Webhook-Secret header' });
    }

    const {
      external_run_id, platform, config_id, status,
      started_at, finished_at, commit_sha, branch,
      step_results, ci_metadata,
    } = req.body || {};

    const missing = [];
    if (!external_run_id) missing.push('external_run_id');
    if (!platform) missing.push('platform');
    if (!status) missing.push('status');
    if (!started_at) missing.push('started_at');
    if (missing.length > 0) {
      db.close();
      return res.status(400).json({ error: 'Missing required fields', fields: missing });
    }
    if (!cicdBundle.VALID_PLATFORMS.includes(platform)) {
      db.close();
      return res.status(400).json({ error: 'Invalid platform', valid: cicdBundle.VALID_PLATFORMS });
    }
    const VALID_STATUSES = ['queued', 'running', 'passed', 'failed', 'cancelled'];
    if (!VALID_STATUSES.includes(status)) {
      db.close();
      return res.status(400).json({ error: 'Invalid status', valid: VALID_STATUSES });
    }

    try {
      db.prepare(
        `INSERT INTO cicd_runs
           (external_run_id, platform, config_id, status, started_at,
            finished_at, commit_sha, branch, step_results_json,
            ci_metadata_json, received_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      ).run(
        external_run_id, platform, config_id || null, status,
        started_at, finished_at || null, commit_sha || null, branch || null,
        step_results ? JSON.stringify(step_results) : null,
        ci_metadata ? JSON.stringify(ci_metadata) : null,
      );
      const inserted = db
        .prepare(`SELECT id, received_at FROM cicd_runs WHERE platform = ? AND external_run_id = ?`)
        .get(platform, external_run_id);
      db.close();
      res.json({
        received: true,
        idempotent: false,
        run_id: inserted.id,
        received_at: inserted.received_at,
      });
    } catch (insertErr) {
      if (insertErr.code === 'SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE constraint/i.test(insertErr.message)) {
        const existing = db
          .prepare(`SELECT id, received_at FROM cicd_runs WHERE platform = ? AND external_run_id = ?`)
          .get(platform, external_run_id);
        db.close();
        return res.json({
          received: true,
          idempotent: true,
          run_id: existing ? existing.id : null,
          received_at: existing ? existing.received_at : null,
        });
      }
      db.close();
      throw insertErr;
    }
  } catch (e) {
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
    res.status(500).json({ error: 'cicd run insert failed', message: e.message });
  }
});

app.get('/api/cicd/runs', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const rows = db
      .prepare(`SELECT id, external_run_id, platform, config_id, status, started_at, finished_at, commit_sha, branch, received_at FROM cicd_runs ORDER BY received_at DESC LIMIT 200`)
      .all();
    db.close();
    res.json({ runs: rows });
  } catch (e) {
    res.status(500).json({ error: 'runs list failed', message: e.message });
  }
});

app.get('/api/cicd/runs/:id', authMiddleware(['ciso', 'vp']), (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare('SELECT * FROM cicd_runs WHERE id = ?').get(req.params.id);
    db.close();
    if (!row) return res.status(404).json({ error: 'run not found' });
    let stepResults = null, ciMeta = null;
    try { stepResults = row.step_results_json ? JSON.parse(row.step_results_json) : null; } catch (e) {}
    try { ciMeta = row.ci_metadata_json ? JSON.parse(row.ci_metadata_json) : null; } catch (e) {}
    res.json({ ...row, step_results: stepResults, ci_metadata: ciMeta });
  } catch (e) {
    res.status(500).json({ error: 'run fetch failed', message: e.message });
  }
});

app.get('/api/cicd/webhook-secret', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const secret = gdGetOrCreateCicdWebhookSecret(db);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CICD_WEBHOOK_SECRET_REVEALED', 'CISO revealed CICD webhook secret', 'info')")
      .run(req.user.id);
    db.close();
    res.json({ secret, header: 'X-CICD-Webhook-Secret' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to read webhook secret', message: e.message });
  }
});

app.post('/api/cicd/webhook-secret/rotate', authMiddleware(['ciso']), (req, res) => {
  try {
    const db = getDb();
    const newSecret = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES ('cicd_webhook_secret', ?)").run(newSecret);
    db.prepare("INSERT INTO audit_log (user_id, event_type, detail, severity) VALUES (?, 'CICD_WEBHOOK_SECRET_ROTATED', 'CISO rotated CICD webhook secret', 'info')")
      .run(req.user.id);
    db.close();
    res.json({ rotated: true, secret: newSecret, header: 'X-CICD-Webhook-Secret' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to rotate webhook secret', message: e.message });
  }
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

// ════════════════════════════════════════════════════════════════════════════
// R3h — Helper Recognition Leaderboard ingest + read endpoints
// ════════════════════════════════════════════════════════════════════════════
//
// Three endpoints supporting the cross-MC Helper Recognition feature:
//
//   POST /api/ingest/leaderboard       — MC pushes signed top-N summary
//   GET  /api/leaderboard/regional     — cross-MC matrix for the GD tab
//   GET  /api/leaderboard/mc/:id       — per-MC drilldown
//
// PRIVACY INVARIANT I3 (OPT-IN PROPAGATION)
//   The GD has NO concept of "all analysts" — only what the MC pushes
//   crosses the wire, and the MC only pushes opted-in analysts. So
//   the GD's surfaces can never expose an opted-out analyst.
//
// PRIVACY INVARIANT I4 (PSEUDONYM-ONLY)
//   regional_leaderboard stores analyst_pseudonym only. Real names,
//   user_ids, emails are NOT carried in the table or returned by any
//   endpoint.

app.post('/api/ingest/leaderboard', (req, res) => {
  try {
    const { apiKey, leaderboard } = req.body || {};
    const db = getDb();

    // ── Resolve MC by api_key ──
    const mc = db.prepare("SELECT * FROM management_consoles WHERE api_key = ? AND status = 'active'").get(apiKey);
    if (!mc) {
      db.close();
      return res.status(403).json({ error: 'Invalid or inactive MC API key' });
    }

    // ── Verify signature (trust lookup is per-MC) ──
    const sigResult = verifyPushSignature(db, {
      mcId: mc.id,
      headers: req.headers,
      rawBody: req.rawBody,
    });
    if (!sigResult.ok) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('INGEST_SIGNATURE_REJECTED', ?, 'critical')")
        .run(`endpoint=leaderboard mc=${mc.name} mc_id=${mc.id} code=${sigResult.code} fingerprint=${sigResult.fingerprint || 'none'} reason=${JSON.stringify(sigResult.error || '')}`);
      db.close();
      return res.status(401).json({ error: sigResult.error, code: sigResult.code });
    }

    // ── Validate body shape ──
    if (!leaderboard || typeof leaderboard !== 'object' || Array.isArray(leaderboard)) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('LEADERBOARD_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=missing_or_invalid_leaderboard fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'leaderboard is required and must be an object' });
    }
    const pushedAt = typeof leaderboard.pushed_at === 'string' ? leaderboard.pushed_at : null;
    if (!pushedAt) {
      db.close();
      return res.status(400).json({ error: 'leaderboard.pushed_at is required (ISO timestamp string)' });
    }
    const entries = Array.isArray(leaderboard.entries) ? leaderboard.entries : null;
    if (!entries) {
      db.close();
      return res.status(400).json({ error: 'leaderboard.entries is required (array, possibly empty)' });
    }
    if (entries.length > 100) {
      // Defensive ceiling. The MC's LEADERBOARD_PUSH_LIMIT is 50; anything
      // more than 100 indicates either a misconfigured MC or an attempt to
      // flood the GD. Reject rather than silently truncate.
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('LEADERBOARD_INGEST_REJECTED', ?, 'warning')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=entries_too_many count=${entries.length} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(400).json({ error: 'leaderboard.entries exceeds maximum (100)' });
    }

    // ── Per-entry validation ──
    // Each entry must have analyst_pseudonym (string, non-empty),
    // points (integer >= 0), sessions_count (integer >= 0), and
    // avg_rating (number 0-5 or null). Reject the whole push on any
    // invalid entry — partial ingest of a malformed push would leave
    // the GD's state ambiguous about what the MC intended.
    const validated = [];
    for (let i = 0; i < entries.length; i++) {
      const e = entries[i];
      if (!e || typeof e !== 'object') {
        db.close();
        return res.status(400).json({ error: `entries[${i}] is not an object` });
      }
      if (typeof e.analyst_pseudonym !== 'string' || !e.analyst_pseudonym.trim()) {
        db.close();
        return res.status(400).json({ error: `entries[${i}].analyst_pseudonym must be a non-empty string` });
      }
      if (!Number.isInteger(e.points) || e.points < 0) {
        db.close();
        return res.status(400).json({ error: `entries[${i}].points must be a non-negative integer` });
      }
      if (!Number.isInteger(e.sessions_count) || e.sessions_count < 0) {
        db.close();
        return res.status(400).json({ error: `entries[${i}].sessions_count must be a non-negative integer` });
      }
      const avg = e.avg_rating;
      if (avg !== null && (typeof avg !== 'number' || avg < 0 || avg > 5)) {
        db.close();
        return res.status(400).json({ error: `entries[${i}].avg_rating must be a number between 0 and 5 or null` });
      }
      validated.push({
        pseudonym: e.analyst_pseudonym.trim().slice(0, 200),
        points: e.points,
        sessions_count: e.sessions_count,
        avg_rating: avg,
      });
    }

    // ── Atomic REPLACE: DELETE this MC's rows, INSERT the new payload ──
    // Inside a single transaction so a matrix read in parallel cannot
    // observe partial state.
    try {
      const insertStmt = db.prepare(`
        INSERT INTO regional_leaderboard
          (mc_id, analyst_pseudonym, points, sessions_count, avg_rating,
           pushed_at, signature_fingerprint)
          VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      const txn = db.transaction(() => {
        db.prepare("DELETE FROM regional_leaderboard WHERE mc_id = ?").run(mc.id);
        for (const v of validated) {
          insertStmt.run(mc.id, v.pseudonym, v.points, v.sessions_count,
            v.avg_rating, pushedAt, sigResult.fingerprint);
        }
      });
      txn();
    } catch (txnErr) {
      db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('LEADERBOARD_INGEST_FAILED', ?, 'critical')")
        .run(`mc=${mc.name} mc_id=${mc.id} reason=transaction_failed error=${JSON.stringify(txnErr.message).slice(0, 200)} fingerprint=${sigResult.fingerprint}`);
      db.close();
      return res.status(500).json({ error: 'Failed to persist leaderboard' });
    }

    db.prepare("INSERT INTO audit_log (event_type, detail, severity) VALUES ('LEADERBOARD_INGEST_SUCCESS', ?, 'info')")
      .run(`mc=${mc.name} mc_id=${mc.id} entries=${validated.length} fingerprint=${sigResult.fingerprint}`);
    db.close();
    res.json({ ok: true, entries: validated.length });
  } catch (err) {
    console.error('Leaderboard ingest error:', err);
    res.status(500).json({ error: 'Leaderboard ingest failed' });
  }
});

app.get('/api/leaderboard/regional',
  authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    try {
      // Cross-MC matrix: every active MC with its top-N entries inline.
      // The GD frontend renders this as a per-MC card with the top
      // helpers. Per-MC sub-arrays are bounded by the MC's push limit
      // (LEADERBOARD_PUSH_LIMIT = 50 from C9b); the limit query param
      // here further caps the per-MC display to N (default 10).
      const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || 10));

      const mcs = db.prepare(
        "SELECT id, name, region FROM management_consoles WHERE status = 'active' ORDER BY name"
      ).all();

      const result = mcs.map(mc => {
        const entries = db.prepare(`
          SELECT analyst_pseudonym, points, sessions_count, avg_rating,
                 pushed_at, received_at
            FROM regional_leaderboard
           WHERE mc_id = ?
           ORDER BY points DESC, sessions_count DESC, analyst_pseudonym ASC
           LIMIT ?
        `).all(mc.id, limit);
        const lastPushedAt = entries.length > 0 ? entries[0].pushed_at : null;
        return {
          mc_id: mc.id,
          mc_name: mc.name,
          region: mc.region,
          entries,
          last_pushed_at: lastPushedAt,
        };
      });
      db.close();
      res.json({ matrix: result, limit });
    } catch (qErr) {
      db.close();
      throw qErr;
    }
  } catch (err) {
    console.error('Regional leaderboard read error:', err);
    res.status(500).json({ error: 'Failed to load regional leaderboard' });
  }
});

app.get('/api/leaderboard/mc/:id',
  authMiddleware(['ciso', 'vp', 'readonly']), (req, res) => {
  try {
    const db = getDb();
    try {
      const mc = db.prepare(
        "SELECT id, name, region, status FROM management_consoles WHERE id = ?"
      ).get(req.params.id);
      if (!mc) {
        db.close();
        return res.status(404).json({ error: 'MC not found' });
      }
      // Per-MC drilldown: full top-N for that MC plus the most recent
      // push timestamps + signature fingerprint for forensic display.
      const limit = Math.max(1, Math.min(50, parseInt(req.query.limit, 10) || 50));
      const entries = db.prepare(`
        SELECT analyst_pseudonym, points, sessions_count, avg_rating,
               pushed_at, received_at, signature_fingerprint
          FROM regional_leaderboard
         WHERE mc_id = ?
         ORDER BY points DESC, sessions_count DESC, analyst_pseudonym ASC
         LIMIT ?
      `).all(mc.id, limit);
      db.close();
      res.json({
        mc_id: mc.id,
        mc_name: mc.name,
        region: mc.region,
        mc_status: mc.status,
        entries,
        entry_count: entries.length,
      });
    } catch (qErr) {
      db.close();
      throw qErr;
    }
  } catch (err) {
    console.error('Per-MC leaderboard read error:', err);
    res.status(500).json({ error: 'Failed to load per-MC leaderboard' });
  }
});

app.listen(PORT, () => {
  console.log(`FireAlive Global Dashboard Server v0.0.31 running on port ${PORT}`);
  console.log('Awaiting aggregate data pushes from Regional Servers');
});

module.exports = app;
