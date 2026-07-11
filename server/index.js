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
const https = require('https');
const fs = require('fs');
const { initDb, getDb, DB_PATH } = require('./db/init');
const ca = require('./services/ca');
const { logger } = require('./services/logger');
const { auditMiddleware } = require('./middleware/audit');
const { authMiddleware } = require('./middleware/auth');
const { configLockChokepoint } = require('./middleware/config-lock');
const ha = require('./routes/ha');
const { requirePeerCert } = require('./services/ha/ha-peer-link');
const { schedulerService } = require('./services/scheduler');
const { networkHardening, antiEnumerationErrors, validatePortBinding } = require('./middleware/network-hardening');
const { bandwidthMonitor } = require('./services/bandwidth-monitor');
const { verifyIntegrity } = require('./services/integrity');
const { runtimeMonitor } = require('./services/runtime-monitor');
const oodaJobs = require('./services/ooda-generation-jobs');
const { gdPushService } = require('./services/gd-push');
const { schedulingSyncService } = require('./services/scheduling-sync');
const { isAuthorizedScannerIp } = require('./services/cloud-vuln-allowlist');
const { isAuthorizedConsumerIp } = require('./services/threat-hunting-allowlist');
const { isAuthorizedVulnScannerSource } = require('./services/vuln-scan-allowlist');
const geoipService = require('./services/geoip/geoip-service');
const threatHuntingGate = require('./middleware/threat-hunting-auth');

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
      styleSrc: ["'self'", "'unsafe-inline'"],  // self-hosted fonts only — no Google Fonts
      fontSrc: ["'self'"],
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
// Global JSON body parser. /api/ha/peer/* (replication batches and the base64
// pairing baseline) can exceed this limit and is parsed with a larger limit at
// its own mount, after the peer-certificate gate; skip it here so the global
// limit does not reject those bodies first.
const jsonBodyParser = express.json({ limit: '5mb' });
app.use((req, res, next) => {
  if (req.path.startsWith('/api/ha/peer')) return next();
  return jsonBodyParser(req, res, next);
});

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
  skip: (req) => req.path === '/api/system/health' || isAuthorizedScannerIp(req.ip) || isAuthorizedConsumerIp(req.ip) || isAuthorizedVulnScannerSource(req.ip),
  keyGenerator: rateLimitKeyGenerator,
  validate: true,
});
app.use('/api/', apiLimiter);

// Audit logging on all API requests
app.use('/api/', auditMiddleware);
// B5e (D11): mode-gated pre-auth VM attestation. No-op in bare-metal; in
// virtualized mode it refuses the whole API surface when the instance is
// quarantined. Placed after audit logging and before per-route auth.
app.use('/api/', require('./middleware/vm-attestation').vmAttestation());
// B5i (D-B5i-4): mode-gated SDN connection admission. No-op outside sdn mode;
// in sdn mode it refuses the API surface for connections originating outside
// the operator-declared permitted SDN segments. Same pre-auth placement.
app.use('/api/', require('./middleware/sdn-admission').sdnAdmission());
// B5k: mode-gated SASE connector admission. No-op outside sase mode; in sase
// mode it refuses connections whose TCP socket peer is not the operator-declared
// ZTNA connector source (direct-exposure) or that reach an authenticated path
// without a client certificate (passthrough violation). Same pre-auth placement.
app.use('/api/', require('./middleware/sase-admission').saseAdmission());
// B5i (D-B5i-5): mode-gated SDN degraded-posture fail-safe. No-op outside sdn
// mode and while posture is healthy/uncertain; when posture is degraded it
// denies the entire API surface (assume-breach lockdown). After admission so
// the segment perimeter check runs first; same pre-auth placement.
app.use('/api/', require('./middleware/sdn-fail-safe').sdnFailSafe());
// B5k: mode-gated SASE degraded-posture fail-safe. No-op outside sase mode and
// while posture is healthy/uncertain; when the dark-app or passthrough posture
// is degraded it denies the entire API surface (assume-breach lockdown). After
// admission so the connector perimeter check runs first; same pre-auth placement.
app.use('/api/', require('./middleware/sase-fail-safe').saseFailSafe());

// B5o: HA request-layer write guard. On a confirmed passive (HA enabled +
// paired + node role passive) it refuses mutating requests
// (POST/PUT/PATCH/DELETE) with 503, exempting the /ha control plane (the
// active's peer replication/heartbeat/lease and HA admin must reach the
// standby). No-op on standalone and on the active; fails open on any
// uncertainty. Placed pre-auth because the check is on node role, not the user.
app.use('/api/', require('./middleware/ha-write-guard').haWriteGuard());

// B5o: HA liveness. Stamp the last real client API request so the active's
// self-fence (ha-failover.checkSelfFence) can tell whether the SOC is still
// reaching this node. Excludes the peer control plane (/api/ha/peer/*, which is
// peer-to-peer, not a client) and the health endpoint (load-balancer probes).
// Bookkeeping only; never blocks a request.
const haLiveness = require('./services/ha/ha-liveness');
app.use('/api/', (req, res, next) => {
  if (!req.path.startsWith('/api/ha/peer') && req.path !== '/api/system/health') {
    try { haLiveness.recordClientRequest(); } catch (_) { /* never block on liveness bookkeeping */ }
  }
  next();
});

// ── API Routes ───────────────────────────────────────────────────────────────
// Public (no auth)
// ── B5b: public CA certificate distribution ─────────────────────────────────
// Unauthenticated by necessity -- a client must obtain and trust the CA cert
// BEFORE it can present a client certificate or trust the TLS server cert. This
// serves ONLY the public CA certificate, never the key. Desktop apps also
// bundle-trust this CA out-of-band; this endpoint is a convenience/re-fetch
// channel.
app.get('/ca-cert', (req, res) => {
  const db = getDb();
  try {
    const pem = ca.getCaCertPem(db);
    if (!pem) return res.status(503).type('text/plain').send('CA not initialized');
    return res
      .type('application/x-pem-file')
      .set('Content-Disposition', 'attachment; filename="firealive-ca.pem"')
      .send(pem);
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

app.use('/api/auth', require('./routes/auth'));
app.get('/api/system/health', require('./routes/system')); // health check is public

// Authenticated routes
// D25: clients challenge the server to prove control of its hardware instance
// anchor (POST /api/instance/anchor-challenge); a clone cannot sign and is refused.
app.use('/api/instance', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/instance-identity'));
// D24: MC operators register their hardware device key here; destructive
// recovery actions must carry a signature from it (verified downstream).
// /register is the MC keyless bootstrap (an operator registers the hardware
// device key before the session is bound), so it is popExempt; any other route
// under this mount would require a bound, proven session (B5f).
app.use('/api/mc-device-key', (req, res, next) => authMiddleware(['lead', 'admin'], { popExempt: req.path === '/register' })(req, res, next), require('./routes/mc-device-key'));
// D9: report/provision the hardware-sealed deployment mode (bare-metal vs VM).
app.use('/api/deployment', authMiddleware(['lead', 'admin']), require('./routes/deployment'));
app.use('/api/team', authMiddleware(['lead', 'admin']), require('./routes/team'));
app.use('/api/enrollment-reconciliation', authMiddleware(['lead', 'admin']), require('./routes/enrollment-reconciliation'));
app.use('/api/analysts', authMiddleware(['analyst']), require('./routes/analysts'));
app.use('/api/signals', authMiddleware(['analyst']), require('./routes/signals'));
app.use('/api/analyst-keys', authMiddleware(['analyst']), require('./routes/analyst-keys'));
app.use('/api/impacts', authMiddleware(['analyst']), require('./routes/impacts'));
app.use('/api/training-recommendations', authMiddleware(['analyst']), require('./routes/training-recommendations'));
app.use('/api/routing', authMiddleware(['lead', 'admin']), require('./routes/routing'));
app.use('/api/handoffs', authMiddleware(['lead', 'admin']), require('./routes/handoffs'));
app.use('/api/retro', authMiddleware(['lead', 'admin']), require('./routes/retro'));
app.use('/api/assessments', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/assessments'));
app.use('/api/reports', authMiddleware(['lead', 'admin']), require('./routes/reports'));
app.use('/api/delegations', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/delegations'));
app.use('/api/pseudonyms', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/pseudonyms'));
app.use('/api/integrations/ticketing/activity-events', authMiddleware(['admin']), require('./routes/ticketing-activity'));
app.use('/api/integrations', authMiddleware(['admin']), configLockChokepoint(), require('./routes/integrations'));
app.use('/api/sdn', authMiddleware(['admin']), configLockChokepoint(), require('./routes/sdn'));
app.use('/api/v1/malware-scanners', authMiddleware(['admin']), configLockChokepoint(), require('./routes/malware-scanners'));
app.use('/api/apikeys', authMiddleware(['admin']), configLockChokepoint(), require('./routes/apikeys'));
app.use('/api/backup', authMiddleware(['admin']), require('./routes/backup'));
app.use('/api/backup-chain', authMiddleware(['admin']), require('./routes/backup-chain'));
app.use('/api/storage-destinations', authMiddleware(['admin']), configLockChokepoint(), require('./routes/storage-destinations'));
app.use('/api/storage-routing', authMiddleware(['admin']), configLockChokepoint(), require('./routes/storage-routing'));
app.use('/api/backup-push', authMiddleware(['admin']), configLockChokepoint(), require('./routes/backup-push'));
app.use('/api/backup-schedules', authMiddleware(['admin']), configLockChokepoint(), require('./routes/backup-schedules'));
app.use('/api/gd-config', authMiddleware(['admin']), configLockChokepoint(), require('./routes/gd-config'));
app.use('/api/gd-signing-key', authMiddleware(['admin']), configLockChokepoint(), require('./routes/gd-signing-key'));
app.use('/api/scheduling', authMiddleware(['admin', 'lead']), configLockChokepoint(), require('./routes/scheduling-platform'));
app.use('/api/audit/event', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/audit-event'));
app.use('/api/audit/mc-event', authMiddleware(['lead', 'admin']), require('./routes/audit-mc-event'));
app.use('/api/audit', authMiddleware(['lead', 'admin']), configLockChokepoint(), require('./routes/audit'));
app.use('/api/metrics', authMiddleware(['lead', 'admin']), require('./routes/metrics'));
app.use('/api/alert-config', authMiddleware(['admin']), require('./routes/alert-config'));
app.use('/api/integration-health', authMiddleware(['admin']), require('./routes/integration-health'));
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
app.use('/api/abuse-review-keys', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/abuse-review-key').keysRouter);
app.use('/api/lead-abuse-review', authMiddleware(['lead']), require('./routes/lead-abuse-review'));
app.use('/api/peer-board', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/peer-board'));
app.use('/api/training/completions-review', authMiddleware(['lead', 'admin']), require('./routes/training-completions-review'));
app.use('/api/training', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/training'));
app.use('/api/features', authMiddleware(['lead', 'admin', 'analyst']), require('./routes/features'));
app.use('/api/query', authMiddleware(['lead', 'admin']), require('./routes/query'));
app.use('/api/restore', authMiddleware(['admin']), require('./routes/restore'));
app.use('/api/restore-approvals', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/restore-approvals'));
app.use('/api/data-subject', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/data-subject'));
app.use('/api/backup-signing-keys', authMiddleware(['admin']), configLockChokepoint(), require('./routes/backup-signing-keys'));
app.use('/api/config-baseline', authMiddleware(['admin']), configLockChokepoint(), require('./routes/config-baseline'));
app.use('/api/client-recovery', authMiddleware(['admin']), configLockChokepoint(), require('./routes/client-recovery'));
app.use('/api/mfa', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/mfa'));
app.use('/api/config', require('./routes/config-lock'));
app.use('/api/kms-providers', authMiddleware(['admin']), configLockChokepoint(), require('./routes/kms-providers'));
app.use('/api/external-restore', authMiddleware(['admin']), configLockChokepoint(), require('./routes/external-restore'));
app.use('/api/migration', authMiddleware(['admin']), configLockChokepoint(), require('./routes/migration'));
app.use('/api/ai-provider', authMiddleware(['lead', 'admin']), configLockChokepoint(), require('./routes/ai-provider'));
app.use('/api/ai-burnout', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ai-burnout'));
app.use('/api/kb', authMiddleware(['lead', 'admin']), require('./routes/kb'));
app.use('/api/kb-chat', authMiddleware(['lead', 'admin']), require('./routes/kb-chat'));
app.use('/api/troubleshoot', authMiddleware(['admin']), require('./routes/troubleshooter'));
app.use('/api/ooda', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ooda'));
app.use('/api/iam', authMiddleware(['lead', 'admin']), configLockChokepoint(), require('./routes/iam'));
app.use('/api/upskilling', authMiddleware(['lead', 'admin']), require('./routes/upskilling'));
app.use('/api/runbook', authMiddleware(['lead', 'admin']), require('./routes/runbook'));
app.use('/api/ttx', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/ttx'));
app.use('/api/inbox', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/notifications-inapp'));
app.use('/api/inbox/admin', authMiddleware(['admin']), require('./routes/notifications-admin'));
app.use('/api/users/me/lead-contacts', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/lead-contacts'));
app.use('/api/helper-pay', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/helper-pay'));
app.use('/api/heartbeat', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/heartbeat'));
// ── High Availability (B5o) ───────────────────────────────
// Mounted before the catch-all /api routers and the /api/ha config router so
// Express matches these more specific paths first. The peer endpoints use the
// pinned-peer-certificate gate (NOT JWT) and a large body limit for replication
// and the pairing baseline; pair-init is token-authenticated in the handler
// (NOT JWT, NOT pinned, since the pin does not exist until pairing completes);
// config/status/pair use the same JWT + config-lock chokepoint as v024/v025.
app.use('/api/ha/peer', requirePeerCert(getDb), express.json({ limit: '256mb' }), ha.peerRouter);
app.use('/api/ha/pair-init', ha.pairInitRouter);
app.use('/api/ha', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), ha.configRouter);
app.use('/api', authMiddleware(['lead', 'admin']), configLockChokepoint(), require('./routes/v021-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v022-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v023-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v024-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v025-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v027-features'));
app.use('/api', authMiddleware(['lead', 'admin', 'analyst']), configLockChokepoint(), require('./routes/v030-features'));
app.use('/api', authMiddleware(['lead', 'admin']), require('./routes/compliance-monitoring'));
app.use('/api/system/connected-clients', authMiddleware(['admin']), require('./routes/system-connected-clients'));
app.use('/api/system', authMiddleware(['admin']), require('./routes/system'));
// /device-key is the AC keyless bootstrap (an analyst registers the hardware
// device key before the session is bound), so it is popExempt; every other
// compromise route requires a bound, proven session (B5f).
app.use('/api/compromise', (req, res, next) => authMiddleware(['analyst', 'lead', 'admin'], { popExempt: req.path === '/device-key' })(req, res, next), require('./routes/compromise-scan-orchestration'));
app.use('/api/client-ops', authMiddleware(['lead', 'admin']), require('./routes/client-ops'));
app.use('/api/tripwire', authMiddleware(['lead', 'admin']), require('./routes/tripwire'));
app.use('/api/status', authMiddleware(['analyst', 'lead', 'admin']), require('./routes/status'));
app.use('/api/regression', authMiddleware(['admin']), require('./routes/regression'));
app.use('/api/cicd', authMiddleware(['admin']), require('./routes/cicd'));
app.use('/api/cloud', authMiddleware(['admin']), require('./routes/cloud'));
app.use('/api/cloud-vuln', authMiddleware(['admin']), configLockChokepoint(), require('./routes/cloud-vuln-scan'));
app.use('/api/cloud-vuln-access', require('./routes/cloud-vuln-scan').accessRouter);
app.use('/api/vuln-scan', authMiddleware(['admin']), configLockChokepoint(), require('./routes/vuln-scan'));
app.use('/api/vuln-scan-access', require('./routes/vuln-scan').accessRouter);

// B5n: login geo-fencing -- GeoIP database provisioning + policy/management (admin).
app.use('/api/geoip', authMiddleware(['admin']), configLockChokepoint(), require('./routes/geoip-database'));
app.use('/api/geo-fence', authMiddleware(['admin']), configLockChokepoint(), require('./routes/geo-fence'));
// B5n2: data residency -- policy, jurisdiction declarations, transfer register, posture (admin).
app.use('/api/data-residency', authMiddleware(['admin']), configLockChokepoint(), require('./routes/data-residency'));
// B5r: automated update detection -- detect-and-notify schedule config + manual check + status (admin).
app.use('/api/auto-update', authMiddleware(['admin']), configLockChokepoint(), require('./routes/auto-update'));
// Dedicated limiter for the external-facing threat-hunting feed. Automated
// consumers (XDR/ATP/NGAV/MSP) reach these routes over mTLS, and the TAXII
// surface is mounted outside /api so apiLimiter does not cover it. A per-IP
// ceiling bounds a misbehaving or compromised consumer; there is intentionally
// no consumer-IP skip here, since this limiter exists to govern that traffic.
const threatHuntingLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 600,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  keyGenerator: rateLimitKeyGenerator,
  validate: true,
});

app.use('/api/threat-hunting', threatHuntingLimiter, authMiddleware(['admin']), configLockChokepoint(), require('./routes/threat-hunting-admin'));
app.use('/api/threat-hunting-feed', threatHuntingLimiter, threatHuntingGate, require('./routes/threat-hunting-feed'));
app.use('/taxii2', threatHuntingLimiter, threatHuntingGate, require('./routes/threat-hunting-taxii'));
app.use('/api/forensic-exports', authMiddleware(['admin', 'ciso']), require('./routes/forensic-exports'));
app.use('/api', authMiddleware(['analyst', 'lead', 'admin', 'ciso']), require('./routes/report-verification'));

// ── Static Frontend ──────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));

// SPA fallback: serve index.html for all non-API routes.
// Rate-limit this handler: it performs a file-system read (sendFile) and,
// unlike the API routes guarded by apiLimiter, is reachable without auth.
// Keyed by client IP like apiLimiter, with the same trusted-scanner skip.
const staticLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skip: (req) => isAuthorizedScannerIp(req.ip) || isAuthorizedConsumerIp(req.ip),
  keyGenerator: rateLimitKeyGenerator,
  validate: true,
});
app.get('*', staticLimiter, (req, res) => {
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
// ── B5b: built-in CA + HTTPS/WSS material ────────────────────────────────────
// FireAlive serves only over HTTPS, and the WebSocket server rides the same
// listener as WSS. There is no plaintext listener and no dev-HTTP escape hatch;
// if TLS material cannot be established this throws, and start()'s catch exits
// the process (fail-closed) rather than fall back to cleartext.
//
// On first boot the built-in CA self-initializes, mints the one-time break-glass
// recovery credential (logged once, here, for offline capture), and issues the
// localhost TLS server certificate. The server leaf cert+key are persisted under
// the data directory and reused across boots; they are re-issued only if missing,
// expired, or no longer chaining to the active CA (e.g. after a CA reset). The
// server key is a 0600 file because a non-interactive boot must load it without a
// passphrase -- standard TLS practice, and a far lower-value secret than the CA
// key (which stays AES-256-GCM encrypted in the database).
function bootstrapTlsMaterial() {
  const { X509Certificate } = require('crypto');
  const db = getDb();
  try {
    ca.initCa(db);

    const rec = ca.ensureRecoveryCredential(db);
    if (rec.created) {
      logger.warn(
        '\n================================================================\n' +
        ' BREAK-GLASS RECOVERY CREDENTIAL (shown once -- store offline NOW)\n' +
        '   ' + rec.recoveryCredential + '\n' +
        ' This is displayed only at first CA initialization. It re-provisions\n' +
        ' an admin authenticator at the audited recovery endpoint if every\n' +
        ' other credential is lost. Only its hash is stored; it cannot be\n' +
        ' recovered if not captured now.\n' +
        '================================================================'
      );
    }

    const caCertPem = ca.getCaCertPem(db);
    const dataDir = path.dirname(DB_PATH);
    const certPath = path.join(dataDir, 'server-tls.crt');
    const keyPath = path.join(dataDir, 'server-tls.key');

    let certPem = null;
    let keyPem = null;
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      try {
        const c = fs.readFileSync(certPath, 'utf8');
        const k = fs.readFileSync(keyPath, 'utf8');
        const x = new X509Certificate(c);
        const caX = new X509Certificate(caCertPem);
        const now = Date.now();
        const chains = x.verify(caX.publicKey);
        const inWindow = now >= Date.parse(x.validFrom) && now <= Date.parse(x.validTo);
        if (chains && inWindow) {
          certPem = c;
          keyPem = k;
        }
      } catch (_) {
        // unreadable/parse failure -> re-issue below
      }
    }

    if (!certPem) {
      if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
      const issued = ca.issueServerCert(db, { commonName: 'localhost' });
      certPem = issued.certPem;
      keyPem = issued.keyPem;
      fs.writeFileSync(keyPath, keyPem, { mode: 0o600 });
      fs.writeFileSync(certPath, certPem, { mode: 0o644 });
      try { fs.chmodSync(keyPath, 0o600); } catch (_) { /* best effort */ }
      logger.info('Issued new TLS server certificate (localhost)');
    }

    return { key: keyPem, cert: certPem, ca: caCertPem };
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
}

async function start() {
  try {
    // Initialize database
    initDb();
    logger.info('Database initialized');

    // B5q: ensure the archive-chain signing key exists before any scheduled
    // archival runs. The audit-log and CEF archival writers are unattended
    // (scheduler-driven), so the Ed25519 signing identity is established
    // deterministically at boot rather than lazily on first archive. Non-fatal:
    // a failure here is logged and the writers' own resolve path still surfaces
    // the missing key.
    try {
      const archiveChainKeys = require('./services/archive-chain-keys');
      const archiveKeyDb = getDb();
      try {
        const archiveKey = archiveChainKeys.ensureActiveSigningKey(archiveKeyDb);
        logger.info('Archive chain signing key ready', {
          id: archiveKey.id,
          fingerprint: String(archiveKey.fingerprint || '').slice(0, 12),
          newlyCreated: archiveKey.isNewlyCreated,
        });
      } finally {
        archiveKeyDb.close();
      }
    } catch (archiveKeyErr) {
      logger.error('Archive chain signing key init failed (non-fatal)', { error: archiveKeyErr.message });
    }

    // B5n: load the active GeoIP database (login geo-fencing) into memory.
    // Non-fatal: with no provisioned/verifiable database the service stays
    // unloaded and the geo-fence treats an enabled-but-unloaded state as a
    // fail-open misconfiguration rather than blocking logins.
    try {
      const geoDb = getDb();
      try {
        const geoStatus = geoipService.init(geoDb);
        if (geoStatus.loaded) {
          logger.info('GeoIP database loaded', {
            databaseType: geoStatus.database_type,
            sha256: String(geoStatus.sha256 || '').slice(0, 12),
            buildEpoch: geoStatus.build_epoch,
          });
        } else {
          logger.info('GeoIP database not loaded', { reason: geoStatus.error });
        }
      } finally {
        geoDb.close();
      }
    } catch (geoErr) {
      logger.error('GeoIP init failed (non-fatal)', { error: geoErr.message });
    }

    // B5e: establish this deployment's instance identity (anti-cloning) before
    // the CA and other long-lived keys are minted. Verify entropy first, then
    // mint the identity in the platform hardware root of trust. Idempotent --
    // re-boots load the existing identity. Fail-closed (D26): if no hardware
    // root is present, establishment refuses and the server halts (there is no
    // software fallback).
    try {
      const entropy = require('./services/entropy');
      const instanceAnchor = require('./services/instance-anchor');
      const identityDb = getDb();
      try {
        entropy.ensureFirstBootEntropy(identityDb, { logger });
        const identity = instanceAnchor.establish({ db: identityDb, logger: logger });
        logger.info('Instance identity ready', {
          instanceId: identity.instanceId,
          anchorKind: identity.anchorKind,
          status: identity.status,
          fingerprint: identity.fingerprint,
        });
        // B5f (D-B5f-4): print the deployment anchor fingerprint in a prominent
        // operator-facing banner -- the same style as the break-glass banner
        // above -- so the operator can verify it out of band against the value
        // each Analyst Client and the Global Dashboard app display on first
        // contact, and confirm the trust pin only when the two match. A cloned
        // deployment cannot reproduce this fingerprint, so a mismatch at pin
        // time is the signal to refuse. Built without backslash escapes (joined
        // on a newline character) per house style; ASCII-only.
        const anchorFpBar = '================================================================';
        const anchorFpNL = String.fromCharCode(10);
        logger.warn([
          '',
          anchorFpBar,
          ' DEPLOYMENT ANCHOR FINGERPRINT -- verify out of band before pinning',
          '   ' + identity.fingerprint,
          ' Compare this with the fingerprint each Analyst Client and the Global',
          ' Dashboard app show on first connection; confirm the trust pin only',
          ' if they match. A clone cannot reproduce this value.',
          anchorFpBar,
        ].join(anchorFpNL));
      } finally {
        identityDb.close();
      }
    } catch (instanceIdentityErr) {
      logger.error('Instance identity establishment failed; refusing to start (fail-closed, D26)', { error: instanceIdentityErr.message });
      logger.error('FireAlive requires a hardware root of trust: TPM 2.0 on Linux/Windows, or the Secure Enclave on macOS. Provision one and restart; there is no software fallback.');
      process.exit(1);
    }

    // B6h A-7: reload this node's shared KEK (the replicated-domain KEK) if it was
    // adopted at a prior promotion. A promoted node that reboots must re-install the
    // former active's KEK to read the replicated Tier-1 columns; otherwise sharedKek()
    // would fall back to this node's own KEK and mis-read them. FAIL-CLOSED (D16/D26):
    // if the sealed blob is present but cannot be unsealed on this hardware, halt rather
    // than serve replicated data with the wrong key. A node that never adopted a shared
    // KEK has no node_state row, so this is a no-op. Runs after the instance anchor is
    // established (the hardware keystore is ready) and before the server serves.
    try {
      const tier1Kek = require('./services/tier1-kek');
      const kekDb = getDb();
      try {
        const reloaded = tier1Kek.loadSharedKekOnBoot(kekDb);
        if (reloaded) {
          logger.info('Shared Tier-1 KEK reloaded from node_state (this node was promoted); replicated columns are readable');
        }
      } finally {
        kekDb.close();
      }
    } catch (sharedKekReloadErr) {
      logger.error('Shared Tier-1 KEK reload failed; refusing to start (fail-closed, D16)', { error: sharedKekReloadErr.message });
      process.exit(1);
    }

    // B5e: resolve and seal the deployment mode (D9) now that the instance
    // anchor exists. On first run FIREALIVE_DEPLOYMENT_MODE provisions and
    // hardware-seals the mode; thereafter the sealed value is authoritative and
    // a divergent env var is ignored (and logged). Expose a snapshot on
    // app.locals for downstream virtualization gating; the mode is
    // provisioning-only, so a snapshot holds for the process lifetime.
    try {
      const deploymentMode = require('./services/deployment-mode');
      const modeDb = getDb();
      try {
        const envMode = process.env.FIREALIVE_DEPLOYMENT_MODE;
        if (envMode && !deploymentMode.isConfigured(modeDb)) {
          if (deploymentMode.MODES.indexOf(envMode) === -1) {
            logger.warn('Ignoring invalid FIREALIVE_DEPLOYMENT_MODE', { value: envMode, valid: deploymentMode.MODES });
          } else if (envMode === deploymentMode.SDN || envMode === deploymentMode.SASE) {
            // SDN and SASE compose with a host substrate. It is operator-declared
            // via a required, mode-specific env (never auto-picked) and sealed; an
            // absent or weaker-than-detected substrate halts the server
            // (fail-closed), it never silently downgrades.
            const substrateEnv = envMode === deploymentMode.SASE ? 'FIREALIVE_SASE_SUBSTRATE' : 'FIREALIVE_SDN_SUBSTRATE';
            const declared = process.env[substrateEnv];
            if (deploymentMode.SUBSTRATES.indexOf(declared) === -1) {
              logger.error(envMode + ' mode requires ' + substrateEnv + ' to be one of ' + deploymentMode.SUBSTRATES.join(', ') + '; refusing to start (fail-closed)', { value: declared || null });
              process.exit(1);
            }
            const detected = await deploymentMode.detectSubstrate(modeDb);
            const substrateRank = { 'bare-metal': 0, 'virtualized': 1, 'cloud': 2 };
            if (substrateRank[detected] > substrateRank[declared]) {
              logger.error(substrateEnv + ' declares a weaker host substrate than detection proves; refusing to start (anti-downgrade, fail-closed)', { declared: declared, detected: detected });
              process.exit(1);
            }
            deploymentMode.setMode(modeDb, envMode, { substrate: declared });
            logger.info('Deployment mode provisioned and sealed', { mode: envMode, substrate: declared, detected: detected });
          } else {
            deploymentMode.setMode(modeDb, envMode);
            logger.info('Deployment mode provisioned and sealed', { mode: envMode });
          }
        } else if (envMode && deploymentMode.getMode(modeDb) !== envMode) {
          logger.warn('FIREALIVE_DEPLOYMENT_MODE differs from the sealed mode; the sealed mode is authoritative', { env: envMode, sealed: deploymentMode.getMode(modeDb) });
        }
        app.locals.deploymentMode = deploymentMode.summary(modeDb);
        if (app.locals.deploymentMode.networkMode && !app.locals.deploymentMode.substrate) {
          const nm = app.locals.deploymentMode.networkMode;
          logger.warn('This ' + nm + ' deployment has no sealed host substrate and runs on the strict TPM path; re-provision with FIREALIVE_' + nm.toUpperCase() + '_SUBSTRATE to enable substrate-specific protections.');
        }
        logger.info('Deployment mode', app.locals.deploymentMode);
      } finally {
        modeDb.close();
      }
    } catch (deploymentModeErr) {
      logger.warn('Deployment mode resolution failed; defaulting to bare-metal (strict)', { error: deploymentModeErr.message });
      app.locals.deploymentMode = { mode: 'bare-metal', configured: false, recordPresent: false, virtualized: false, hypervisor: null };
    }

    // B5i2: the SDN host substrate is now sealed in the deployment-mode record
    // (operator-declared, anchor-signed), not detected at runtime. sdnCloudResident
    // is a derived alias -- true only for an SDN deployment sealed on a cloud
    // substrate -- kept for the pre-auth attestation gate. The cloud metadata the
    // confidential-VM gate and cert-SAN reconcile need is read and published by
    // the gate below, only for a cloud substrate.
    app.locals.sdnCloudResident = !!(app.locals.deploymentMode && app.locals.deploymentMode.sdn === true && app.locals.deploymentMode.substrateCloud === true);

    // B5h / B5i / B5l2: confidential-VM boot gate (D-B5h-3, D-B5h-4, D-B5i-2).
    // On a confidential-VM substrate -- cloud mode, or an sdn deployment sealed
    // on a cloud substrate -- confidential computing is REQUIRED and fully
    // attested before the server serves any request: verifyAttestation fetches a
    // signed SEV-SNP / TDX report and verifies its vendor certificate chain, the
    // nonce, and the configured TCB floor (fail closed if not verified); the
    // guest CPU cross-tenant side-channel mitigations are checked; spot /
    // autoscaled / ephemeral-fleet instances are refused; single-tenant hardware
    // is required when configured; the launch measurement is pinned on first use
    // and required to match on every boot; the result is stamped and published on
    // app.locals for the pre-auth gate; and periodic re-attestation is scheduled.
    // Any error here halts the server -- it never silently downgrades. An onsite
    // sdn (or bare-metal / virtualized) deployment skips this gate and relies on
    // its TPM hardware root established above.
    if (app.locals.deploymentMode && app.locals.deploymentMode.substrateCloud === true) {
      try {
        const cloudAttestation = require('./services/cloud-attestation');
        const cloudMetadata = require('./services/cloud-metadata');
        const cloudMode = require('./services/cloud-mode');
        const guestMitigations = require('./services/guest-mitigations');

        let cloudConfig = null;
        const cfgDb = getDb();
        try { cloudConfig = cloudMode.getCloudConfig(cfgDb); } finally { cfgDb.close(); }

        const att = cloudAttestation.verifyAttestation({ tcbFloor: cloudConfig ? cloudConfig.tcbFloor : undefined });
        if (!att.verified) {
          logger.error('A confidential-VM substrate (cloud, or cloud-resident sdn) requires confidential computing, but the attestation report did not verify; refusing to start (fail-closed, D-B5h-3 / D-B5i-2)', { reason: att.reason });
          process.exit(1);
        }
        logger.info('Confidential computing attested', { tech: att.tech, platformValidationPending: att.platformValidationPending });

        const mit = guestMitigations.evaluateMitigations();
        if (!mit.ok) {
          logger.error('Guest CPU cross-tenant side-channel mitigations are not satisfied; refusing to start (fail-closed)', { detail: guestMitigations.summarize(mit) });
          process.exit(1);
        }
        logger.info('Guest CPU side-channel mitigations verified', { detail: guestMitigations.summarize(mit) });

        const meta = await cloudMetadata.readCloudMetadata();
        if (meta && (meta.spot === true || meta.autoscaled === true)) {
          logger.error('A confidential-VM substrate refuses spot / autoscaled / ephemeral-fleet instances; run on a dedicated on-demand confidential VM (fail-closed, D-B5h-4)', { spot: meta.spot, autoscaled: meta.autoscaled, provider: meta.provider });
          process.exit(1);
        }
        if (cloudConfig && cloudConfig.requireDedicatedTenancy === true && !cloudMetadata.isDedicatedTenancy(meta)) {
          logger.error('requireDedicatedTenancy is set but the instance is not on single-tenant hardware; refusing to start (fail-closed)', { tenancy: meta ? meta.tenancy : null, provider: meta ? meta.provider : null });
          process.exit(1);
        }

        const recDb = getDb();
        try {
          if (att.measurement) {
            const pin = cloudMode.pinMeasurement(recDb, att.measurement);
            if (!pin.matched) {
              logger.error('The confidential-VM launch measurement does not match the pinned value; refusing to start (fail-closed, measurement TOFU)', { tech: att.tech });
              process.exit(1);
            }
            if (pin.firstPin) logger.info('Confidential-VM launch measurement pinned (trust-on-first-use)', { tech: att.tech });
          }
          cloudMode.recordAttestation(recDb, { tech: att.tech, tcb: att.tcb || att.tcbSvn || null, measurement: att.measurement || null, verified: att.verified, platformValidationPending: att.platformValidationPending });
        } finally {
          recDb.close();
        }

        app.locals.cloudAttestation = { verified: true, tech: att.tech, platformValidationPending: att.platformValidationPending, reason: att.reason, measurement: att.measurement || null };
        app.locals.cloudMetadata = meta || null;
        logger.info('Confidential-VM substrate attested and sealed', { mode: app.locals.deploymentMode.mode, provider: meta ? meta.provider : null, privateIp: meta ? meta.privateIp : null });

        // Periodic re-attestation: re-verify the report, the pinned measurement,
        // and the guest mitigations on an interval. A regression marks the
        // attestation unverified so the pre-auth gate refuses, rather than tearing
        // down a running server on a transient fetch hiccup.
        const REATTEST_INTERVAL_MS = 60 * 60 * 1000;
        const reattestTimer = setInterval(function () {
          try {
            const rdb = getDb();
            try {
              const cfg = cloudMode.getCloudConfig(rdb);
              const re = cloudAttestation.verifyAttestation({ tcbFloor: cfg ? cfg.tcbFloor : undefined });
              let ok = re.verified;
              let reason = re.reason;
              if (ok && re.measurement) {
                const pin = cloudMode.pinMeasurement(rdb, re.measurement);
                if (!pin.matched) { ok = false; reason = 'launch measurement changed since pin'; }
              }
              if (ok) {
                const m2 = guestMitigations.evaluateMitigations();
                if (!m2.ok) { ok = false; reason = 'guest mitigations regressed: ' + guestMitigations.summarize(m2); }
              }
              if (ok) {
                cloudMode.recordAttestation(rdb, { tech: re.tech, tcb: re.tcb || re.tcbSvn || null, measurement: re.measurement || null, verified: true, platformValidationPending: re.platformValidationPending });
                app.locals.cloudAttestation = { verified: true, tech: re.tech, platformValidationPending: re.platformValidationPending, reason: re.reason, measurement: re.measurement || null };
              } else {
                logger.error('Periodic confidential-VM re-attestation failed; marking attestation unverified (pre-auth gate will refuse)', { reason: reason });
                app.locals.cloudAttestation = { verified: false, tech: re.tech || att.tech, reason: reason };
              }
            } finally {
              rdb.close();
            }
          } catch (reErr) {
            logger.error('Periodic confidential-VM re-attestation errored; marking attestation unverified', { error: reErr.message });
            app.locals.cloudAttestation = { verified: false, reason: 're-attestation error: ' + reErr.message };
          }
        }, REATTEST_INTERVAL_MS);
        if (reattestTimer && typeof reattestTimer.unref === 'function') reattestTimer.unref();
      } catch (cloudBootErr) {
        logger.error('Confidential-VM boot gate failed; refusing to start (fail-closed, no downgrade)', { error: cloudBootErr.message });
        process.exit(1);
      }
    }

    // B5e: record this instance's host for vMotion-vs-clone tracking (D10/D11).
    // The anchor is verified above; in virtualized mode the anchor (vTPM)
    // moving to a new host is an authorized relocation we audit, while a
    // bare-metal host change is flagged. Concurrent duplication remains a clone
    // via the observer path; this only tracks sequential relocation.
    try {
      const os = require('os');
      const instanceRegistry = require('./services/instance-registry');
      const { auditLog } = require('./middleware/audit');
      const hostDb = getDb();
      try {
        const mode = app.locals.deploymentMode || {};
        const presence = instanceRegistry.recordHostPresence(hostDb, {
          host: os.hostname(),
          virtualized: mode.substrateVirtualized === true,
          cloud: mode.substrateCloud === true,
          hypervisor: mode.hypervisor || null
        });
        if (presence.migration) {
          logger.warn('Instance relocated to a new host (authorized relocation in virtualized or cloud mode)', { from: presence.previousHost, to: presence.host });
          auditLog(null, 'INSTANCE_MIGRATED', 'authorized relocation from ' + presence.previousHost + ' to ' + presence.host, null);
        } else if (presence.unexpected) {
          logger.error('Instance host changed in bare-metal mode (the anchor should be machine-bound); investigate', { from: presence.previousHost, to: presence.host });
          auditLog(null, 'INSTANCE_HOST_CHANGED', 'unexpected bare-metal host change from ' + presence.previousHost + ' to ' + presence.host, null);
        } else if (presence.firstSeen) {
          logger.info('Instance host recorded', { host: presence.host });
        }
      } finally {
        hostDb.close();
      }
    } catch (hostPresenceErr) {
      logger.warn('Host-presence tracking failed (non-fatal)', { error: hostPresenceErr.message });
    }

    // B5e: anti-rollback high-water gate (decision D7). A running build whose
    // fuse counter is below the highest this deployment has recorded means the
    // binary was downgraded or an older snapshot was restored. Mark the instance
    // quarantined and, in production, halt; otherwise log loudly (matching the
    // source-integrity check). The broader quarantine response is wired later.
    try {
      const fuseHighWater = require('./services/fuse-high-water');
      const hwDb = getDb();
      try {
        const rollbackVerdict = fuseHighWater.checkAndAdvance(hwDb);
        if (rollbackVerdict.rollback) {
          logger.error('ANTI-ROLLBACK VIOLATION: running fuse is below the recorded high-water', {
            currentFuse: rollbackVerdict.currentFuse,
            highWater: rollbackVerdict.highWater,
          });
          try {
            hwDb.prepare(
              "UPDATE instance_identity SET status = 'quarantined', last_attested_at = datetime('now') " +
              "WHERE id = (SELECT id FROM instance_identity ORDER BY id LIMIT 1)"
            ).run();
          } catch (markErr) {
            logger.error('Marking instance quarantined after rollback failed', { error: markErr.message });
          }
          if (process.env.NODE_ENV === 'production') {
            logger.error('HALTING: anti-rollback high-water check failed. Deploy the current or a newer build.');
            process.exit(1);
          }
        } else {
          logger.info('Anti-rollback high-water ok', {
            fuse: rollbackVerdict.currentFuse,
            highWater: rollbackVerdict.highWater,
          });
        }
      } finally {
        hwDb.close();
      }
    } catch (highWaterErr) {
      logger.error('Anti-rollback high-water check failed to run', { error: highWaterErr.message });
    }

    // B5e (Block C, decision D4): start the signed subnet peer-beacon. A clone
    // or fork seen on the local subnet quarantines this instance, which raises
    // the loud alert. Best-effort; a beacon failure must never stop startup. A
    // dedicated long-lived connection backs the background socket (it outlives
    // this block by design, so it is not closed here). The beacon channel is
    // deployment-configured (services/beacon-config.js); when disabled the AC
    // ratchet, anti-rollback high-water, and GD collision detections still run.
    try {
      const beaconConfig = require('./services/beacon-config').getBeaconConfig();
      if (!beaconConfig.enabled) {
        logger.info('Subnet peer-beacon disabled by configuration; AC ratchet, anti-rollback high-water, and GD collision detections remain active');
      } else {
        const peerBeacon = require('./services/peer-beacon');
        const beaconDb = getDb();
        peerBeacon.start(beaconDb, {
          role: 'regional-server',
          port: beaconConfig.port,
          broadcastAddress: beaconConfig.broadcastAddress,
          intervalMs: beaconConfig.intervalMs,
          onDetection: (detection) => {
            try {
              const instanceRegistry = require('./services/instance-registry');
              instanceRegistry.quarantine(beaconDb, {
                reason: 'subnet peer-beacon detected a ' + detection.verdict + (detection.from ? ' from ' + detection.from : ''),
                verdict: detection.verdict,
                observerKind: 'peer-beacon',
                observedFrom: detection.from || null,
              });
              logger.error('Subnet peer-beacon detected a ' + detection.verdict, { from: detection.from, fingerprint: detection.fingerprint });
            } catch (quarErr) {
              logger.error('Quarantine after peer-beacon detection failed', { error: quarErr.message });
            }
          },
        });
        logger.info('Subnet peer-beacon started');
      }
    } catch (beaconErr) {
      logger.warn('Subnet peer-beacon failed to start', { error: beaconErr.message });
    }

    // B5b: built-in CA + HTTPS/WSS material (fail-closed; no plaintext listener).
    const tlsMaterial = bootstrapTlsMaterial();
    logger.info('TLS material ready (built-in CA)');

    // B5h: in cloud mode, reconcile the server certificate SAN against the
    // stable operator hostname (primary) and the instance IP from metadata
    // (secondary), re-issuing under the stable anchor when the address set
    // changed (D-B5h-6). Clients pin the anchor fingerprint, not the leaf, so
    // re-issuing on a cloud stop/start or load-balancer change is safe. Guarded:
    // a reconcile failure keeps the existing cert (still served over the pinned
    // anchor) rather than halting.
    if (app.locals.deploymentMode && app.locals.deploymentMode.substrateCloud === true) {
      try {
        const cloudMode = require('./services/cloud-mode');
        const reconcileDb = getDb();
        try {
          const cloudCfg = cloudMode.getCloudConfig(reconcileDb) || {};
          const meta = app.locals.cloudMetadata || {};
          const reconciled = ca.reconcileServerCert(reconcileDb, {
            stableHostname: cloudCfg.stableHostname || null,
            instanceIp: meta.privateIp || null,
          });
          if (reconciled.reissued) {
            const dataDir = path.dirname(DB_PATH);
            const certPath = path.join(dataDir, 'server-tls.crt');
            const keyPath = path.join(dataDir, 'server-tls.key');
            fs.writeFileSync(keyPath, reconciled.keyPem, { mode: 0o600 });
            fs.writeFileSync(certPath, reconciled.certPem, { mode: 0o644 });
            try { fs.chmodSync(keyPath, 0o600); } catch (_) { /* best effort */ }
            tlsMaterial.key = reconciled.keyPem;
            tlsMaterial.cert = reconciled.certPem;
            tlsMaterial.ca = reconciled.caCertPem;
            logger.info('Reconciled server certificate SAN for cloud address', { san: reconciled.desiredSan });
          } else {
            logger.info('Server certificate SAN already current for cloud address', { san: reconciled.desiredSan });
          }
        } finally {
          reconcileDb.close();
        }
      } catch (reconcileErr) {
        logger.warn('Cloud SAN reconciliation failed; keeping existing certificate (served over the pinned anchor)', { error: reconcileErr.message });
      }
    }

    // B5g: re-seal any legacy plaintext forensic export artifacts
    // at rest (idempotent; rows already sealed are skipped). The DB schema and
    // the Tier-1 KEK are ready by this point. Guarded so a failure logs and does
    // not abort startup; any unsealed rows are retried on the next boot.
    try {
      const { migrateExportsAtRest } = require('./services/export-encryption-migration');
      const exportSealSummary = await migrateExportsAtRest(getDb());
      logger.info('Export at-rest migration complete', exportSealSummary);
    } catch (exportSealErr) {
      logger.warn('Export at-rest migration failed', { error: exportSealErr.message });
    }

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
      const { routeAlert } = require('./services/alert-router');
      const db = getDb();
      routeAlert(db, { ...alert, type: alert.type || 'BANDWIDTH_ALERT' })
        .finally(() => { try { db.close(); } catch (_) {} });
    });

    // Start runtime monitor (continuous FIM + CPU/memory + DB read anomaly)
    // Apply any admin-configured sustained-load thresholds first so the first
    // intervals already honor them; defaults apply if none are stored.
    try {
      const cfgDb = getDb();
      const stored = cfgDb.prepare("SELECT value FROM config WHERE key = 'runtime_monitor_thresholds'").get();
      cfgDb.close();
      if (stored && stored.value) runtimeMonitor.configureThresholds(JSON.parse(stored.value));
    } catch (_) { /* defaults apply */ }
    runtimeMonitor.start();
    runtimeMonitor.onAlert((alert) => {
      // Severity-tiered fan-out: the router always audits, then dispatches to
      // SOAR / SIEM (CEF push) / email / in-app notification / webhook per the
      // configured per-severity routing matrix (B3-C3/C4).
      const { routeAlert } = require('./services/alert-router');
      const db = getDb();
      routeAlert(db, alert)
        .finally(() => { try { db.close(); } catch (_) {} });
    });

    // Start the integration-health periodic scheduler. No-op until an admin
    // enables the master + periodic toggles; honors the configured interval.
    try {
      const ihScheduler = require('./services/integration-health-scheduler');
      ihScheduler.startIntegrationHealthScheduler(getDb);
      // On a new build, run a one-shot smoke probe shortly after boot so config
      // drift from the update surfaces immediately (only when probing is enabled).
      ihScheduler.runUpdateSmokeTest(getDb);
    } catch (e) {
      logger.warn('Integration-health scheduler failed to start', { error: e.message });
    }

    try { require('./services/tripwire-scheduler').startTripwireScheduler(getDb, { getWsServer: () => app.locals.wsServer }); logger.info('Tripwire scheduler started'); } catch (e) { logger.warn('Tripwire scheduler failed to start', { error: e.message }); }
    try { require('./services/audit-integrity-scheduler').startAuditIntegrityScheduler(getDb); logger.info('Audit integrity scheduler started'); } catch (e) { logger.warn('Audit integrity scheduler failed to start', { error: e.message }); }

    // Start the SDN posture probe scheduler. Self-gating: a no-op outside sdn
    // mode. In sdn mode it probes the enabled controller integrations on an
    // interval and drives the posture state machine (and the fail-safe gate).
    try { require('./services/sdn-probe-scheduler').startSdnProbeScheduler(getDb); logger.info('SDN posture probe scheduler started'); } catch (e) { logger.warn('SDN posture probe scheduler failed to start', { error: e.message }); }

    // B5n2: data residency -- reconcile the cross-border transfer register, and
    // validate the declared primary residency against the detected cloud region
    // (Cloud Mode), raising a HIGH alert on a mismatch. Off-cloud / undeclared
    // is a no-op.
    try {
      const dataResidency = require('./services/data-residency');
      const residencyRegions = require('./services/residency-regions');
      const cloudMetadataSvc = require('./services/cloud-metadata');
      const residencyDb = getDb();
      let mismatch = null;
      try {
        dataResidency.reconcileTransfers(residencyDb);
        const cfg = dataResidency.loadResidencyConfig(residencyDb);
        const declared = cfg.primaryResidency.country;
        const meta = app.locals.cloudMetadata || null;
        const region = meta ? cloudMetadataSvc.getRegion(meta) : null;
        let detectedCountry = null;
        if (region) {
          const hit = residencyRegions.regionToCountry(region);
          detectedCountry = hit ? hit.country : null;
        }
        if (cfg.enabled && declared && detectedCountry && detectedCountry !== declared) {
          mismatch = { declared: declared, region: region, country: detectedCountry };
        }
      } finally {
        residencyDb.close();
      }
      if (mismatch) {
        const { routeAlert } = require('./services/alert-router');
        const { auditLog } = require('./middleware/audit');
        const alertDb = getDb();
        routeAlert(alertDb, {
          type: 'RESIDENCY_REGION_MISMATCH',
          severity: 'high',
          source: 'data-residency',
          message: 'declared primary residency ' + mismatch.declared
            + ' does not match detected deployment region ' + mismatch.region
            + ' (' + mismatch.country + ')',
          timestamp: new Date().toISOString(),
        }).finally(function () { try { alertDb.close(); } catch (_) { /* ignore */ } });
        auditLog(null, 'RESIDENCY_REGION_MISMATCH',
          'declared=' + mismatch.declared + ' detected=' + mismatch.region + ' country=' + mismatch.country, null);
        logger.warn('Data residency: declared primary residency does not match detected region', mismatch);
      }
    } catch (e) {
      logger.warn('Data residency boot init failed', { error: e.message });
    }

    // Start GD push service (pushes aggregate metrics to configured GD-Server)
    gdPushService.start();

    // Start HR scheduling sync service (pulls per-analyst weekly availability
    // from the configured HR platform — UKG/Workday/ADP/BambooHR/Manual —
    // and upserts into analyst_availability for the upskilling auto-assigner)
    schedulingSyncService.start();

    // Scheduled jobs: account review (03:00), retention purge + offboarding
    // crypto-erase sweep (04:00), recert check (09:00). Log integrity (chain
    // verify + signed checkpoint + gap check) runs on its own cadence via
    // startAuditIntegrityScheduler below.
    const { runAccountReview } = require('./services/account-review');
    const { runRetentionPurge } = require('./services/retention');
    const { checkRecertDue } = require('./services/recertification');
    const { sweepDueErasures } = require('./services/crypto-erase');
    setInterval(() => {
      const hour = new Date().getHours();
      if (hour === 3) runAccountReview();
      if (hour === 4) runRetentionPurge();
      if (hour === 4) {
        const eraseDb = getDb();
        try {
          sweepDueErasures(eraseDb);
        } catch (e) {
          logger.warn('crypto-erase sweep failed', { error: e.message });
        } finally {
          try { eraseDb.close(); } catch (e) { /* ignore */ }
        }
      }
      if (hour === 9) checkRecertDue();
    }, 3600000);

    const server = https.createServer({
      key: tlsMaterial.key,
      cert: tlsMaterial.cert,
      ca: tlsMaterial.ca,
      // Client certificates are REQUESTED at the TLS handshake but not REQUIRED
      // there (rejectUnauthorized:false): the WebAuthn login and first-credential
      // enrollment paths connect without a client cert and then
      // authenticate at the app layer. Encryption itself is never optional --
      // there is no plaintext listener. mTLS client-cert AUTHENTICATION is
      // enforced in routes/auth.js, which passes the presented peer certificate
      // to ca.verifyClientCert.
      requestCert: true,
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    }, app).listen(PORT, HOST, () => {
      const pkg = require('../package.json');
      logger.info(`FireAlive v${pkg.version} running on https://${HOST}:${PORT}`);
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
