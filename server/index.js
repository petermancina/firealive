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
const { schedulerService } = require('./services/scheduler');
const { networkHardening, antiEnumerationErrors, validatePortBinding } = require('./middleware/network-hardening');
const { bandwidthMonitor } = require('./services/bandwidth-monitor');
const { verifyIntegrity } = require('./services/integrity');
const { runtimeMonitor } = require('./services/runtime-monitor');
const oodaJobs = require('./services/ooda-generation-jobs');
const { gdPushService } = require('./services/gd-push');
const { schedulingSyncService } = require('./services/scheduling-sync');
const { isAuthorizedScannerIp } = require('./services/cloud-vuln-allowlist');

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
  skip: (req) => req.path === '/api/system/health' || isAuthorizedScannerIp(req.ip),
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
app.use('/api/v1/malware-scanners', authMiddleware(['admin']), configLockChokepoint(), require('./routes/malware-scanners'));
app.use('/api/apikeys', authMiddleware(['admin']), configLockChokepoint(), require('./routes/apikeys'));
app.use('/api/backup', authMiddleware(['admin']), require('./routes/backup'));
app.use('/api/backup-chain', authMiddleware(['admin']), require('./routes/backup-chain'));
app.use('/api/backup-destinations', authMiddleware(['admin']), configLockChokepoint(), require('./routes/backup-destinations'));
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
  skip: (req) => isAuthorizedScannerIp(req.ip),
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
          } else {
            deploymentMode.setMode(modeDb, envMode);
            logger.info('Deployment mode provisioned and sealed', { mode: envMode });
          }
        } else if (envMode && deploymentMode.getMode(modeDb) !== envMode) {
          logger.warn('FIREALIVE_DEPLOYMENT_MODE differs from the sealed mode; the sealed mode is authoritative', { env: envMode, sealed: deploymentMode.getMode(modeDb) });
        }
        app.locals.deploymentMode = deploymentMode.summary(modeDb);
        logger.info('Deployment mode', app.locals.deploymentMode);
      } finally {
        modeDb.close();
      }
    } catch (deploymentModeErr) {
      logger.warn('Deployment mode resolution failed; defaulting to bare-metal (strict)', { error: deploymentModeErr.message });
      app.locals.deploymentMode = { mode: 'bare-metal', configured: false, recordPresent: false, virtualized: false, hypervisor: null };
    }

    // B5h: Cloud Mode boot gate (D-B5h-3, D-B5h-4). When the sealed mode is
    // cloud, confidential computing is REQUIRED and attested before the server
    // serves any request: verify a confidential-VM guest is present (fail closed
    // if not), refuse spot / autoscaled / ephemeral-fleet instances, stamp the
    // attestation, and publish the result on app.locals for the pre-auth gate.
    // Any error here halts the server -- cloud mode never silently downgrades.
    if (app.locals.deploymentMode && app.locals.deploymentMode.cloud === true) {
      try {
        const cloudAttestation = require('./services/cloud-attestation');
        const cloudMetadata = require('./services/cloud-metadata');
        const cloudMode = require('./services/cloud-mode');

        const att = cloudAttestation.verifyAttestation();
        if (!att.verified) {
          logger.error('Cloud Mode requires a confidential VM, but confidential computing was not attested; refusing to start (fail-closed, D-B5h-3)', { reason: att.reason });
          process.exit(1);
        }
        logger.info('Confidential computing attested', { tech: att.tech, platformValidationPending: att.platformValidationPending });

        const meta = await cloudMetadata.readCloudMetadata();
        if (meta && (meta.spot === true || meta.autoscaled === true)) {
          logger.error('Cloud Mode refuses spot / autoscaled / ephemeral-fleet instances; run on a dedicated on-demand confidential VM (fail-closed, D-B5h-4)', { spot: meta.spot, autoscaled: meta.autoscaled, provider: meta.provider });
          process.exit(1);
        }

        const attDb = getDb();
        try {
          cloudMode.recordAttestation(attDb, { tech: att.tech });
        } finally {
          attDb.close();
        }

        app.locals.cloudAttestation = { verified: true, tech: att.tech, platformValidationPending: att.platformValidationPending, reason: att.reason };
        app.locals.cloudMetadata = meta || null;
        logger.info('Cloud Mode attested and sealed', { provider: meta ? meta.provider : null, privateIp: meta ? meta.privateIp : null });
      } catch (cloudBootErr) {
        logger.error('Cloud Mode boot gate failed; refusing to start (fail-closed, no downgrade)', { error: cloudBootErr.message });
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
          virtualized: mode.virtualized === true,
          cloud: mode.cloud === true,
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
    if (app.locals.deploymentMode && app.locals.deploymentMode.cloud === true) {
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
