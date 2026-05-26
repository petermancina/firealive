// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — SOC Analyst Wellbeing Platform — Server
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

require('dotenv').config();

const express = require('express');
const { securityHeaders, sanitizeInput, antiReplay, maxBodySize, enforceMinTls } = require('./middleware/security-hardening');
const { corsPolicy } = require('./middleware/cors-policy');
const { detectSuspiciousInput } = require('./middleware/auth-hardening');
const { aiSecurityMiddleware } = require('./middleware/ai-security');
const { connectionTracker, validateMtls, preventPivot } = require('./middleware/network-security');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const { isIP } = require('net');
const path = require('path');
const { initDb, getDb } = require('./db/init');
const { logger } = require('./services/logger');
const { auditMiddleware } = require('./middleware/audit');
const { authMiddleware } = require('./middleware/auth');
const { configLockGate } = require('./middleware/config-lock');
const { schedulerService } = require('./services/scheduler');
const { networkHardening, antiEnumerationErrors, validatePortBinding } = require('./middleware/network-hardening');
const { bandwidthMonitor } = require('./services/bandwidth-monitor');
const { verifyIntegrity } = require('./services/integrity');
const { runtimeMonitor } = require('./services/runtime-monitor');
const oodaJobs = require('./services/ooda-generation-jobs');
const { gdPushService } = require('./services/gd-push');
const { schedulingSyncService } = require('./services/scheduling-sync');

const app = express();
const PORT = process.env.PORT || 3000;
const { FireAliveWebSocket } = require('./services/websocket-server');
const HOST = process.env.HOST || '0.0.0.0';

// ── Startup Integrity Check ─────────────────────────────────────────────────
if (process.env.SKIP_INTEGRITY_CHECK !== 'true') {
  const integrityResult = verifyIntegrity();
  if (!integrityResult.valid && integrityResult.violations.length > 0) {
    // Log violations but don't halt in dev (no manifest yet)
    if (integrityResult.error) {
      logger.warn('Integrity check skipped', { reason: integrityResult.error });
    } else {
      logger.error('INTEGRITY VIOLATIONS DETECTED', {
        violations: integrityResult.violations.map(v => `${v.type}: ${v.file}`),
      });
      if (process.env.NODE_ENV === 'production') {
        logger.error('HALTING: Source files have been modified. Run integrity --generate after verified deploy.');
        process.exit(1);
      }
    }
  } else if (integrityResult.valid) {
    logger.info('Integrity check passed', { files: integrityResult.expectedFiles });
  }
}

// ── Security Middleware ──────────────────────────────────────────────────────
//
// TRUST_PROXY env var: configures Express's req.ip resolution for deployments
// behind a reverse proxy. Without this, req.ip is the proxy's IP and the
// rate limiter buckets every client together. Must be set BEFORE any
// middleware that reads req.ip (which is most security middleware).
//
//   false (default) — direct internet exposure, no proxy in front
//   "loopback"      — trust 127.0.0.1 / ::1 only (typical local proxy)
//   "1"             — trust exactly one hop (typical single-proxy setup)
//   "2"             — trust exactly two hops (e.g. Cloudflare + NGINX)
//   "uniquelocal"   — trust private + loopback IPs (typical k8s ingress)
//
// Setting this too permissively in a deployment without a real proxy lets
// attackers spoof X-Forwarded-For and bypass IP-based rate limiting.
// See https://expressjs.com/en/guide/behind-proxies.html for full semantics.
if (process.env.TRUST_PROXY) {
  const tp = process.env.TRUST_PROXY;
  // Numeric strings parse to integers; non-numeric pass through as strings.
  app.set('trust proxy', /^\d+$/.test(tp) ? parseInt(tp, 10) : tp);
}

app.use(networkHardening());
app.use(antiEnumerationErrors());
app.use(bandwidthMonitor.middleware());
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // needed for React in dev
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));

app.use(compression());
app.use(express.json({ limit: '5mb' }));

// Rate limiting
//
// Three hardening notes vs the bare-minimum config:
// 1. trust proxy is set above via the TRUST_PROXY env var so req.ip
//    resolves to the actual client IP behind reverse proxies. Without
//    that, every client would bucket under the proxy's IP and the
//    limiter would be effectively disabled.
// 2. keyGenerator does explicit IPv6 /64 aggregation. An IPv6 client
//    can trivially rotate /128 addresses within their assigned /64
//    subnet; aggregating at the /64 boundary prevents that bypass.
//    Inlined (not delegated to the library's internal IPv6 logic) so
//    behavior stays stable across express-rate-limit upgrades.
// 3. validate: true enables the library's startup misconfiguration
//    detector — warns if trust proxy is set inconsistently with the
//    X-Forwarded-For headers seen at runtime, if duplicate header
//    handling collides, etc.
const rateLimitKeyGenerator = (req) => {
  const ip = req.ip;
  if (!ip) return 'unknown';
  if (isIP(ip) === 4) return ip;
  if (isIP(ip) === 6) {
    // IPv4-mapped IPv6 (::ffff:1.2.3.4) — treat as the underlying IPv4
    if (ip.startsWith('::ffff:')) return ip.slice(7);
    // Otherwise aggregate by /64 prefix (first 4 hextets of the address)
    const parts = ip.split(':');
    return parts.slice(0, 4).join(':') + '::/64';
  }
  return ip;
};
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skip: (req) => req.path === '/api/system/health',
  keyGenerator: rateLimitKeyGenerator,
  validate: true,
});
app.use('/api/', apiLimiter);

// Audit logging on all API requests
app.use('/api/', auditMiddleware);

// ── API Routes ───────────────────────────────────────────────────────────────
// Public (no auth)
app.use('/api/auth', require('./routes/auth'));
app.get('/api/system/health', require('./routes/system')); // health check is public

// Authenticated routes
app.use('/api/team', authMiddleware(['lead', 'admin']), require('./routes/team'));
app.use('/api/analysts', authMiddleware(['analyst']), require('./routes/analysts'));
app.use('/api/signals', authMiddleware(['analyst']), require('./routes/signals'));
app.use('/api/impacts', authMiddleware(['analyst']), require('./routes/impacts'));
app.use('/api/training-recommendations', authMiddleware(['analyst']), require('./routes/training-recommendations'));
app.use('/api/routing', authMiddleware(['lead', 'admin']), require('./routes/routing'));
app.use('/api/handoffs', authMiddleware(['lead', 'admin']), require('./routes/handoffs'));
app.use('/api/retro', authMiddleware(['lead', 'admin']), require('./routes/retro'));
app.use('/api/assessments', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/assessments'));
app.use('/api/reports', authMiddleware(['lead', 'admin']), require('./routes/reports'));
app.use('/api/delegations', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/delegations'));
app.use('/api/pseudonyms', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/pseudonyms'));
app.use('/api/integrations', authMiddleware(['admin']), configLockGate(), require('./routes/integrations'));
app.use('/api/v1/malware-scanners', authMiddleware(['admin']), configLockGate(), require('./routes/malware-scanners'));
app.use('/api/apikeys', authMiddleware(['admin']), configLockGate(), require('./routes/apikeys'));
app.use('/api/backup', authMiddleware(['admin']), require('./routes/backup'));
app.use('/api/backup-chain', authMiddleware(['admin']), require('./routes/backup-chain'));
app.use('/api/backup-destinations', authMiddleware(['admin']), configLockGate(), require('./routes/backup-destinations'));
app.use('/api/backup-push', authMiddleware(['admin']), configLockGate(), require('./routes/backup-push'));
app.use('/api/backup-schedules', authMiddleware(['admin']), configLockGate(), require('./routes/backup-schedules'));
app.use('/api/gd-config', authMiddleware(['admin']), configLockGate(), require('./routes/gd-config'));
app.use('/api/gd-signing-key', authMiddleware(['admin']), configLockGate(), require('./routes/gd-signing-key'));
app.use('/api/scheduling', authMiddleware(['admin', 'lead']), configLockGate(), require('./routes/scheduling-platform'));
app.use('/api/audit/event', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/audit-event'));
app.use('/api/audit/mc-event', authMiddleware(['lead', 'admin']), require('./routes/audit-mc-event'));
app.use('/api/audit', authMiddleware(['lead', 'admin']), configLockGate(), require('./routes/audit'));
app.use('/api/metrics', authMiddleware(['lead', 'admin']), require('./routes/metrics'));
app.use('/api/resources', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/resources'));
app.use('/api/sla', authMiddleware(['lead', 'admin']), require('./routes/sla'));
app.use('/api/notifications', authMiddleware(['admin']), require('./routes/notifications'));
app.use('/api/messages', authMiddleware(['analyst']), require('./routes/messages'));
app.use('/api/peers', authMiddleware(['analyst']), require('./routes/peers'));
app.use('/api/e2ee', authMiddleware(['analyst', 'lead']), require('./routes/e2ee-keys'));
app.use('/api/lead-chat', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/lead-chat'));
app.use('/api/leads', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/leads'));
app.use('/api/peer-support', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-support'));
app.use('/api/peer/flags', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-flags'));
app.use('/api/abuse-review-key', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/abuse-review-key'));
app.use('/api/abuse-review', authMiddleware(['abuse_reviewer']), require('./routes/abuse-review'));
app.use('/api/peer-board', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-board'));
app.use('/api/training/completions-review', authMiddleware(['lead', 'admin']), require('./routes/training-completions-review'));
app.use('/api/training', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/training'));
app.use('/api/features', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/features'));
app.use('/api/query', authMiddleware(['lead', 'admin']), require('./routes/query'));
app.use('/api/auth/password', require('./routes/password'));
app.use('/api/restore', authMiddleware(['admin']), require('./routes/restore'));
app.use('/api/restore-approvals', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/restore-approvals'));
app.use('/api/backup-signing-keys', authMiddleware(['admin']), configLockGate(), require('./routes/backup-signing-keys'));
app.use('/api/mfa', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/mfa'));
app.use('/api/config', require('./routes/config-lock'));
app.use('/api/kms-providers', authMiddleware(['admin']), configLockGate(), require('./routes/kms-providers'));
app.use('/api/external-restore', authMiddleware(['admin']), configLockGate(), require('./routes/external-restore'));
app.use('/api/ai-provider', authMiddleware(['lead', 'admin']), configLockGate(), require('./routes/ai-provider'));
app.use('/api/ai-burnout', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ai-burnout'));
app.use('/api/ooda', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ooda'));
app.use('/api/iam', authMiddleware(['lead', 'admin']), configLockGate(), require('./routes/iam'));
app.use('/api/upskilling', authMiddleware(['lead', 'admin']), require('./routes/upskilling'));
app.use('/api/runbook', authMiddleware(['lead', 'admin']), require('./routes/runbook'));
app.use('/api/ttx', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ttx'));
app.use('/api/inbox', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/notifications-inapp'));
app.use('/api/inbox/admin', authMiddleware(['admin']), require('./routes/notifications-admin'));
app.use('/api/users/me/lead-contacts', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/lead-contacts'));
app.use('/api/helper-pay', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/helper-pay'));
app.use('/api/heartbeat', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/heartbeat'));
app.use('/api', authMiddleware(['lead', 'admin']), require('./routes/v021-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v022-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v023-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v024-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v025-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v027-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v030-features'));
app.use('/api', authMiddleware(['lead', 'admin']), require('./routes/compliance-monitoring'));
app.use('/api/system/connected-clients', authMiddleware(['admin']), require('./routes/system-connected-clients'));
app.use('/api/system', authMiddleware(['admin']), require('./routes/system'));
app.use('/api/status', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/status'));
app.use('/api/regression', authMiddleware(['admin']), require('./routes/regression'));
app.use('/api/cicd', authMiddleware(['admin']), require('./routes/cicd'));
app.use('/api/cloud', authMiddleware(['admin']), require('./routes/cloud'));
app.use('/api/forensic-exports', authMiddleware(['admin', 'ciso']), require('./routes/forensic-exports'));
app.use('/api/legal-hold-exports', authMiddleware(['admin', 'ciso']), require('./routes/legal-hold-exports'));

// ── Static Frontend ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));

// SPA fallback — serve index.html for all non-API routes
app.get('*', (req, res) => {
  if (!req.path.startsWith('/api/')) {
    res.sendFile(path.join(__dirname, '../frontend/index.html'));
  }
});

// ── Error Handling ───────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  logger.error('Unhandled error', { error: err.message, stack: err.stack, path: req.path });
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
  });
});

// ── Startup ──────────────────────────────────────────────────────────────────
async function start() {
  try {
    // Initialize database
    initDb();
    logger.info('Database initialized');

    // Start scheduled jobs (report generation, backup, signal aggregation)
    schedulerService.start();
    logger.info('Scheduler started');

    // Start OODA scenario generation jobs worker (Phase F4c).
    // Idempotent: safe to call multiple times. Crash-recovery transitions
    // any orphaned 'running' jobs back to 'queued' so they get picked up.
    // The worker logs its own startup info including configured concurrency,
    // tick interval, and per-job timeout.
    oodaJobs.start();

    // Start bandwidth monitor
    bandwidthMonitor.start();
    bandwidthMonitor.onAlert((alert) => {
      const { auditLog } = require('./middleware/audit');
      auditLog(null, 'BANDWIDTH_ALERT', `${alert.type}: ${alert.message}`);
    });

    // Start runtime monitor (continuous FIM + CPU/memory + DB read anomaly)
    runtimeMonitor.start();
    runtimeMonitor.onAlert((alert) => {
      const { auditLog } = require('./middleware/audit');
      auditLog(null, alert.type, alert.message);
      // Dispatch critical alerts to SOAR
      const { dispatchToSoar } = require('./services/soar-alerting');
      dispatchToSoar(alert.type, alert);
    });

    // Start GD push service (pushes aggregate metrics to configured GD-Server)
    gdPushService.start();

    // Start HR scheduling sync service (pulls per-analyst weekly availability
    // from the configured HR platform — UKG/Workday/ADP/BambooHR/Manual —
    // and upserts into analyst_availability for the upskilling auto-assigner)
    schedulingSyncService.start();

    // Scheduled jobs: account review (03:00), retention purge (04:00),
    // recert check (09:00), log integrity (hourly)
    const { runAccountReview } = require('./services/account-review');
    const { runRetentionPurge } = require('./services/retention');
    const { detectMissingLogs } = require('./services/soar-alerting');
    const { checkRecertDue } = require('./services/recertification');
    setInterval(() => {
      const hour = new Date().getHours();
      if (hour === 3) runAccountReview();
      if (hour === 4) runRetentionPurge();
      if (hour === 9) checkRecertDue();
      detectMissingLogs();
    }, 3600000);

    const server = app.listen(PORT, HOST, () => {
      const pkg = require('../package.json');
      logger.info(`FireAlive v${pkg.version} running on http://${HOST}:${PORT}`);
      validatePortBinding(server, parseInt(PORT, 10));
    });

    // Initialize WebSocket server for real-time features. WebSocket failure
    // is non-fatal — the rest of the server runs without it.
    let wsServer = null;
    try {
      wsServer = new FireAliveWebSocket(server, getDb());
      app.locals.wsServer = wsServer;
      wsServer.startHeartbeatCheck();
      logger.info('WebSocket server started on /ws');
    } catch (e) {
      logger.warn('WebSocket init skipped', { error: e.message });
    }

    // Graceful shutdown handlers. Registered OUTSIDE the WebSocket try
    // block so they fire even if WebSocket init failed — the OODA worker's
    // tick timer would otherwise keep the process alive indefinitely on
    // SIGTERM/SIGINT. Subsystems shut down in dependency-safe order:
    // worker first (stops new jobs from being claimed), WebSocket if it
    // came up (drops live connections), then HTTP server (stops accepting
    // new requests and closes idle keep-alives).
    const gracefulShutdown = (signal) => {
      logger.info(`Received ${signal}, beginning graceful shutdown`);
      try { oodaJobs.shutdown(); } catch (e) { logger.warn('OODA worker shutdown error', { error: e.message }); }
      try { gdPushService.stop(); } catch (e) { logger.warn('GD push service shutdown error', { error: e.message }); }
      try { schedulingSyncService.stop(); } catch (e) { logger.warn('Scheduling sync service shutdown error', { error: e.message }); }
      if (wsServer) { try { wsServer.shutdown(); } catch (e) { logger.warn('WebSocket shutdown error', { error: e.message }); } }
      server.close();
    };
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
  } catch (err) {
    logger.error('Failed to start:', err);
    process.exit(1);
  }
}

start();

module.exports = app;  // for testing
