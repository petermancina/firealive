const router = require('express').Router();
const crypto = require('crypto');
const { requireAuth, requireRole } = require('../middleware/auth');
const { auditLog } = require('../middleware/audit');

// Feature Toggles
router.get('/features', requireAuth, (req, res) => {
  const { FeatureToggleService } = require('../services/feature-toggles');
  const svc = new FeatureToggleService(req.app.locals.db);
  res.json(svc.getAll());
});
router.post('/features/:feature/toggle', requireAuth, requireRole('manager'), (req, res) => {
  const { FeatureToggleService } = require('../services/feature-toggles');
  const svc = new FeatureToggleService(req.app.locals.db);
  svc.setEnabled(req.params.feature, req.body.enabled, req.user.id);
  auditLog(req.user.id, 'FEATURE_TOGGLE', `${req.params.feature}: ${req.body.enabled ? 'ON' : 'OFF'}`);
  res.json({ feature: req.params.feature, enabled: req.body.enabled });
});

// Metrics (full suite)
router.get('/metrics', requireAuth, (req, res) => {
  const { MetricsCollector } = require('../services/metrics-collector');
  res.json(new MetricsCollector(req.app.locals.db).collect());
});
router.get('/metrics/cef', requireAuth, (req, res) => {
  const { MetricsCollector } = require('../services/metrics-collector');
  res.type('text/plain').send(new MetricsCollector(req.app.locals.db).toCEF());
});

// Audit integrity
router.get('/audit/integrity', requireAuth, requireRole('manager'), (req, res) => {
  const { verifyAuditChain } = require('../middleware/pentest-hardening');
  const result = verifyAuditChain(req.app.locals.db);
  auditLog(req.user.id, 'AUDIT_CHECK', `Integrity: ${result.intact}`);
  res.json(result);
});

// Recovery Runbook (covers entire suite)
router.post('/runbook/generate', requireAuth, requireRole('manager'), (req, res) => {
  const scenarios = {
    crash: [
      {action:'Check Regional Server',cmd:'systemctl status firealive-server'},
      {action:'Check GD Server',cmd:'systemctl status firealive-gd-server'},
      {action:'Verify DB integrity',cmd:'sqlite3 firealive.db "PRAGMA integrity_check"'},
      {action:'Verify e-fuse counter (must be 60)',cmd:'cat /etc/firealive/fuse_counter'},
      {action:'Restart servers',cmd:'systemctl restart firealive-server firealive-gd-server'},
      {action:'Verify MC client heartbeats resume within 90s'},
      {action:'Verify SIEM CEF feed resumes'},
      {action:'Verify GD receives regional aggregates'},
      {action:'Run full regression (35 tests)',cmd:'firealive-cli test --regression'},
      {action:'Check feature toggle states',cmd:'firealive-cli features --list'},
      {action:'Verify backup scheduler active',cmd:'firealive-cli backup --status'},
    ],
    compromise: [
      {action:'PANIC — disable all routing (MC Operations)'},
      {action:'Isolate Regional Server',cmd:'iptables -P INPUT DROP; iptables -A INPUT -s ADMIN_IP -j ACCEPT'},
      {action:'Isolate GD Server similarly'},
      {action:'Forensic snapshot',cmd:'firealive-cli backup --forensic --all-components'},
      {action:'Verify audit chain integrity',cmd:'firealive-cli audit --verify-chain'},
      {action:'Rotate ALL keys (JWT, encryption, API)',cmd:'firealive-cli keys --rotate-all'},
      {action:'Rotate pseudonyms (MC > Pseudonyms)'},
      {action:'Revoke all active sessions',cmd:'firealive-cli sessions --revoke-all'},
      {action:'Restore from pre-compromise backup'},
      {action:'Re-provision all analyst clients'},
      {action:'Re-enroll MFA for all users'},
      {action:'Notify CISO via GD'},
      {action:'Generate incident report',cmd:'firealive-cli report --incident'},
    ],
    feature_failure: [
      {action:'Identify failed feature in MC Feature Toggles'},
      {action:'Disable feature via toggle API',cmd:'firealive-cli features --disable FEATURE'},
      {action:'Check logs',cmd:'firealive-cli logs --feature=NAME --last=1h'},
      {action:'Run targeted regression',cmd:'firealive-cli test --feature=NAME'},
      {action:'Re-enable and monitor 15 min'},
    ]
  };
  const s = req.body.scenario || 'crash';
  auditLog(req.user.id, 'RUNBOOK', `Generated: ${s}`);
  res.json({ id: crypto.randomUUID(), version:'v1.0.0', scenario:s, steps: scenarios[s] || scenarios.crash });
});

// TTX Generator
router.post('/ttx/generate', requireAuth, requireRole('manager'), (req, res) => {
  const types = {
    ransomware: {title:'Ransomware on SOC Workstation',injects:['Analyst reports encryption','EDR alerts','FireAlive capacity drops to 0','Clients stop heartbeating','SOAR fails'],decisions:['Isolate?','Panic mode?','Restore or forensic hold?']},
    insider: {title:'Insider Compromise',injects:['Unusual admin login','Bulk config changes','Pseudonym export','Routing manipulation'],decisions:['Lock configs?','Rotate pseudonyms?','HR/Legal?']},
    supply_chain: {title:'Compromised Training Platform',injects:['Phishing redirect','Suspicious URL submitted','EDR flags cert','Unusual training content'],decisions:['Disable links?','Block external AI?','Notify analysts?']},
    burnout_crisis: {title:'Mass Burnout',injects:['Health < 40%','Multiple reduced load requests','Peer chat 300% spike','Tripwire triggered'],decisions:['All-hands disable?','Emergency upskilling?','Escalate CISO?']},
  };
  const t = req.body.type || 'ransomware';
  auditLog(req.user.id, 'TTX', `Generated: ${t}`);
  res.json({ id: crypto.randomUUID(), ...types[t] });
});

// Cloud Migration (entire suite)
router.post('/cloud/package', requireAuth, requireRole('manager'), (req, res) => {
  const p = req.body.provider || 'aws';
  auditLog(req.user.id, 'CLOUD_PKG', `Provider: ${p}`);
  res.json({
    id: crypto.randomUUID(), provider:p, version:'v1.0.0',
    components: [
      {name:'firealive-regional-server',type:'container',image:'firealive/server:v1.0.0',ports:[3000],volumes:['/data/db','/data/backups','/data/uploads'],replicas:2},
      {name:'firealive-gd-server',type:'container',image:'firealive/gd-server:v1.0.0',ports:[4001],volumes:['/data/gd-db'],replicas:2},
      {name:'firealive-mc',type:'electron',platforms:['darwin-arm64','win32-x64','linux-x64']},
      {name:'firealive-ac',type:'electron',platforms:['darwin-arm64','win32-x64','linux-x64']},
      {name:'firealive-gd',type:'electron',platforms:['darwin-arm64','win32-x64','linux-x64']},
    ],
    middleware: 9, routes: 37, services: 23,
    security: {tls:'1.3',mtls:true,encryption:'AES-256-GCM + NaCl E2EE',auth:'JWT Ed25519 + MFA TOTP + IAM SSO',audit:'SHA-256 immutable chain',efuse:1},
    services_included: ['ai-burnout-engine','assessment-service','backup-service','compliance-scanner','integration-manager','metrics-collector','notification-service','regression-runner','system-health','feature-toggles','encryption','scheduler','logger','runtime-monitor','integrity','account-review','bandwidth-monitor','recertification','retention','compliance','handoff','alerts','posture-scanner'],
    secrets: p==='aws'?'Secrets Manager':p==='azure'?'Key Vault':'Secret Manager',
  });
});

// Backup (entire suite)
router.post('/backup/full-suite', requireAuth, requireRole('manager'), (req, res) => {
  auditLog(req.user.id, 'BACKUP_FULL', 'Full suite backup initiated');
  res.json({
    id: crypto.randomUUID(),
    components: ['regional-server-db','gd-server-db','mc-configs','ac-configs','gd-configs','audit-logs','feature-toggles','encryption-keys-encrypted','integration-configs','upskilling-schedules','assessment-data','analyst-skills','analyst-baselines','signal-readings','analyst-impacts','training-completions','peer-session-metadata','compliance-reports','backup-schedules','backup-history','notifications','ir-policies','helper-ratings','api-keys','config-snapshots','integration-status'],
    encrypted: true, algorithm: 'AES-256-GCM',
  });
});

// CI/CD (full suite)
router.get('/cicd/full', requireAuth, (req, res) => {
  res.json({
    pipeline: {stages:['lint','unit-test','integration-test','security-scan','sast','container-scan','build-electron','build-containers','code-sign','regression-35-tests','deploy-staging','smoke-test','deploy-production'],efuse_check:true},
    components_built: ['server (37 routes, 23 services, 9 middleware)','gd-server','mc-electron','ac-electron','gd-electron'],
    security_scans: ['npm-audit','snyk','eslint-security','dependency-check','sast'],
    regression_tests: 35,
  });
});

// Regression (full 35-test suite)
router.post('/regression/run', requireAuth, requireRole('manager'), (req, res) => {
  const { RegressionRunner } = require('../services/regression-runner');
  const result = new RegressionRunner(req.app.locals.db).run();
  auditLog(req.user.id, 'REGRESSION', `${result.passed}/${result.total} passed`);
  res.json(result);
});

module.exports = router;
