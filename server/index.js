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
const path = require('path');
const { initDb } = require('./db/init');
const { logger } = require('./services/logger');
const { auditMiddleware } = require('./middleware/audit');
const { authMiddleware } = require('./middleware/auth');
const { schedulerService } = require('./services/scheduler');
const { networkHardening, antiEnumerationErrors, validatePortBinding } = require('./middleware/network-hardening');
const { bandwidthMonitor } = require('./services/bandwidth-monitor');
const { verifyIntegrity } = require('./services/integrity');
const { runtimeMonitor } = require('./services/runtime-monitor');

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
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
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
app.use('/api/routing', authMiddleware(['lead', 'admin']), require('./routes/routing'));
app.use('/api/handoffs', authMiddleware(['lead', 'admin']), require('./routes/handoffs'));
app.use('/api/retro', authMiddleware(['lead', 'admin']), require('./routes/retro'));
app.use('/api/assessments', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/assessments'));
app.use('/api/reports', authMiddleware(['lead', 'admin']), require('./routes/reports'));
app.use('/api/delegations', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/delegations'));
app.use('/api/integrations', authMiddleware(['admin']), require('./routes/integrations'));
app.use('/api/apikeys', authMiddleware(['admin']), require('./routes/apikeys'));
app.use('/api/backup', authMiddleware(['admin']), require('./routes/backup'));
app.use('/api/audit', authMiddleware(['lead', 'admin']), require('./routes/audit'));
app.use('/api/resources', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/resources'));
app.use('/api/sla', authMiddleware(['lead', 'admin']), require('./routes/sla'));
app.use('/api/notifications', authMiddleware(['admin']), require('./routes/notifications'));
app.use('/api/messages', authMiddleware(['analyst']), require('./routes/messages'));
app.use('/api/peers', authMiddleware(['analyst']), require('./routes/peers'));
app.use('/api/peer-support', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-support'));
app.use('/api/peer/flags', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-flags'));
app.use('/api/training', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/training'));
app.use('/api/features', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/features'));
app.use('/api/query', authMiddleware(['lead', 'admin']), require('./routes/query'));
app.use('/api/auth/password', require('./routes/password'));
app.use('/api/restore', authMiddleware(['admin']), require('./routes/restore'));
app.use('/api/ooda', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ooda'));
app.use('/api/iam', authMiddleware(['lead', 'admin']), require('./routes/iam'));
app.use('/api/upskilling', authMiddleware(['lead', 'admin']), require('./routes/upskilling'));
app.use('/api/runbook', authMiddleware(['lead', 'admin']), require('./routes/runbook'));
app.use('/api/ttx', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ttx'));
app.use('/api/inbox', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/notifications-inapp'));
app.use('/api/inbox/admin', authMiddleware(['admin']), require('./routes/notifications-admin'));
app.use('/api', authMiddleware(['lead', 'admin']), require('./routes/v021-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v022-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v023-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v024-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v025-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v027-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/v030-features'));
app.use('/api', authMiddleware(['lead', 'admin']), require('./routes/compliance-monitoring'));
app.use('/api/system', authMiddleware(['admin']), require('./routes/system'));

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

    // Initialize WebSocket server for real-time features
    try {
      const wsServer = new FireAliveWebSocket(server, app.locals?.db);
      wsServer.startHeartbeatCheck();
      logger.info('WebSocket server started on /ws');
      process.on('SIGTERM', () => { wsServer.shutdown(); server.close(); });
      process.on('SIGINT', () => { wsServer.shutdown(); server.close(); });
    } catch (e) {
      logger.warn('WebSocket init skipped', { error: e.message });
    }
  } catch (err) {
    logger.error('Failed to start:', err);
    process.exit(1);
  }
}

start();

module.exports = app;  // for testing
