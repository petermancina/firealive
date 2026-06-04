'use strict';

/**
 * troubleshooter-diagnostics.js  (B5c)
 *
 * Rule-based diagnostic engine for the Management Console Troubleshooter.
 * Internal and read-only. Exports:
 *
 *   runDiagnostics(db, description) -> { topic, findings, baseline }
 *
 * The description is keyword-routed to a topic; each topic runs real checks
 * against current server state (config / team_config / integration_config /
 * audit tables and the relevant per-subsystem tables). An always-run baseline
 * is appended for every topic. Each finding is:
 *
 *   { label, status, detail, fix?, tab? }   status: 'pass' | 'warn' | 'fail'
 *
 * Robustness: every individual check is wrapped so a read error degrades to a
 * single 'warn' finding rather than throwing -- a diagnostic must always return
 * something useful. The description is used only for routing and is never
 * interpolated into a query; all SQL is literal with bound parameters.
 */

let versionInfo = null;
try { versionInfo = require('../lib/version'); } catch (_e) { versionInfo = null; }

// ------------------------------------------------------------------ helpers
function makeFinding(label, status, detail, fix, tab) {
  const o = { label: label, status: status, detail: detail };
  if (fix) { o.fix = fix; }
  if (tab) { o.tab = tab; }
  return o;
}

// Run one check; on any error return a 'warn' finding instead of throwing.
function check(label, tab, fn) {
  try {
    return fn();
  } catch (_e) {
    return makeFinding(label, 'warn',
      'Could not evaluate this check against the current server state.', undefined, tab);
  }
}

function teamConfigValue(db, key) {
  const r = db.prepare('SELECT value FROM team_config WHERE key = ?').get(key);
  return r ? r.value : null;
}
function appConfigValue(db, key) {
  const r = db.prepare('SELECT value FROM config WHERE key = ?').get(key);
  return r ? r.value : null;
}
function sysMetaValue(db, key) {
  const r = db.prepare('SELECT value FROM system_meta WHERE key = ?').get(key);
  return r ? r.value : null;
}
function parseJson(s, fallback) {
  if (s == null) { return fallback; }
  try { return JSON.parse(s); } catch (_e) { return fallback; }
}

// integration_config row + a pass/warn/fail finding for a given integration.
function integrationFinding(db, type, label, tab) {
  const row = db.prepare(
    'SELECT status, last_test_at, last_test_result FROM integration_config ' +
    'WHERE integration_type = ? ORDER BY updated_at DESC LIMIT 1'
  ).get(type) || null;
  if (!row || row.status === 'not_configured') {
    return makeFinding(label, 'warn', 'Not configured.',
      'Configure the integration and run a connection test.', tab);
  }
  if (row.status === 'error') {
    const why = row.last_test_result ? ': ' + String(row.last_test_result).slice(0, 160) : '.';
    return makeFinding(label, 'fail',
      'Configured but the last connection test reported an error' + why,
      'Re-test the connection and verify the endpoint and credentials.', tab);
  }
  if (row.status === 'operational') {
    const when = row.last_test_at ? ' (last tested ' + row.last_test_at + ').' : '.';
    return makeFinding(label, 'pass', 'Operational' + when, undefined, tab);
  }
  const when = row.last_test_at ? ' (last tested ' + row.last_test_at + ').' : ' (not yet tested).';
  return makeFinding(label, 'warn', 'Status: ' + row.status + when,
    'Run a connection test to confirm it is operational.', tab);
}

// ------------------------------------------------------------ topic checks
function checkSoar(db) {
  const out = [];
  out.push(check('SOAR integration', 'soar', function () {
    return integrationFinding(db, 'soar', 'SOAR integration', 'soar');
  }));
  out.push(check('Routing toggle', 'routing', function () {
    const v = teamConfigValue(db, 'routing_enabled');
    const on = v === 'true' || v === '"true"';
    return makeFinding('Burnout-aware routing toggle', on ? 'pass' : 'warn',
      on ? 'Routing is enabled, so SOAR ticket assignments are capacity-aware.'
         : 'Routing is disabled, so SOAR assignments are not re-routed by capacity.',
      on ? undefined : 'Enable routing if you expect capacity-aware assignment.', 'routing');
  }));
  out.push(check('Recent SOAR routing events', 'soar', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM soar_routing_events WHERE received_at > datetime('now','-7 days')"
    ).get().c;
    if (c === 0) {
      return makeFinding('Recent SOAR routing events', 'warn',
        'No SOAR routing events received in the last 7 days.',
        'If the SOAR should be sending ticket events, verify its webhook target and credentials.', 'soar');
    }
    return makeFinding('Recent SOAR routing events', 'pass',
      c + ' routing event(s) received in the last 7 days.', undefined, 'soar');
  }));
  return out;
}

function checkSiem(db) {
  const out = [];
  out.push(check('SIEM integration', 'siem', function () {
    return integrationFinding(db, 'siem', 'SIEM integration', 'siem');
  }));
  out.push(check('SIEM CEF stream activity', 'siem', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM audit_log WHERE cef_message IS NOT NULL AND timestamp > datetime('now','-1 day')"
    ).get().c;
    return makeFinding('SIEM CEF stream activity', c > 0 ? 'pass' : 'warn',
      c > 0 ? c + ' CEF-formatted audit event(s) generated in the last 24h.'
            : 'No CEF-formatted audit events in the last 24h.',
      c > 0 ? undefined : 'Verify the SIEM feed is enabled and the collector endpoint is reachable.', 'siem');
  }));
  return out;
}

function checkPeer(db) {
  const out = [];
  out.push(check('Peer scheduling integration', 'sync_interval', function () {
    const row = db.prepare(
      'SELECT enabled, platform, sync_interval_minutes FROM scheduling_platform_config WHERE id = 1'
    ).get();
    if (!row || row.enabled !== 1) {
      return makeFinding('Peer scheduling integration', 'warn',
        'Workforce scheduling integration is disabled.',
        'Enable and configure it if you expect analyst-availability sync.', 'sync_interval');
    }
    return makeFinding('Peer scheduling integration', 'pass',
      'Enabled (' + (row.platform || 'manual') + ', sync every ' + row.sync_interval_minutes + ' min).',
      undefined, 'sync_interval');
  }));
  out.push(check('Recent peer sessions', 'peersupport', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM peer_sessions WHERE created_at > datetime('now','-7 days')"
    ).get().c;
    return makeFinding('Recent peer support sessions', c > 0 ? 'pass' : 'warn',
      c > 0 ? c + ' peer session(s) in the last 7 days.'
            : 'No peer sessions recorded in the last 7 days.', undefined, 'peersupport');
  }));
  out.push(check('Peer board messages', 'peersupport', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM peer_board_messages').get().c;
    return makeFinding('Peer board messages', 'pass',
      c + ' encrypted board message(s) stored (content is end-to-end encrypted and server-blind).',
      undefined, 'peersupport');
  }));
  return out;
}

function checkRouting(db) {
  const out = [];
  out.push(check('Routing toggle', 'routing', function () {
    const v = teamConfigValue(db, 'routing_enabled');
    const on = v === 'true' || v === '"true"';
    return makeFinding('Burnout-aware routing', on ? 'pass' : 'warn',
      on ? 'Routing is enabled.' : 'Routing is disabled.',
      on ? undefined : 'Enable routing to distribute tickets by capacity.', 'routing');
  }));
  out.push(check('Panic mode', 'routing', function () {
    const active = teamConfigValue(db, 'panic_mode') === '"active"';
    return makeFinding('Panic mode', active ? 'fail' : 'pass',
      active ? 'Panic mode is ACTIVE -- automatic routing is suspended.' : 'Panic mode is not active.',
      active ? 'Lift panic mode from the Routing tab once the situation is resolved.' : undefined, 'routing');
  }));
  out.push(check('Reduced-load overrides', 'routing', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM routing_overrides WHERE active = 1 AND type = 'reduced_load'"
    ).get().c;
    return makeFinding('Active reduced-load overrides', 'pass',
      c + ' analyst(s) currently on a reduced-load override.', undefined, 'routing');
  }));
  out.push(check('Recent routing events', 'routing', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM soar_routing_events WHERE received_at > datetime('now','-7 days')"
    ).get().c;
    return makeFinding('Recent ticket routing events', c > 0 ? 'pass' : 'warn',
      c > 0 ? c + ' routing event(s) in the last 7 days.' : 'No routing events in the last 7 days.',
      undefined, 'routing');
  }));
  return out;
}

function checkBackup(db) {
  const out = [];
  out.push(check('Latest backup', 'backup', function () {
    const b = db.prepare('SELECT type, status, created_at FROM backups ORDER BY created_at DESC LIMIT 1').get();
    if (!b) {
      return makeFinding('Latest backup', 'warn', 'No backups recorded yet.',
        'Run an on-demand backup or configure a schedule.', 'backup');
    }
    if (b.status === 'failed') {
      return makeFinding('Latest backup', 'fail',
        'The most recent backup (' + b.type + ', ' + b.created_at + ') FAILED.',
        'Check the backup destination and credentials, then re-run.', 'backup');
    }
    if (b.status === 'running') {
      return makeFinding('Latest backup', 'warn',
        'The most recent backup (' + b.type + ', ' + b.created_at + ') is still running or did not finalize.',
        undefined, 'backup');
    }
    return makeFinding('Latest backup', 'pass',
      'Most recent backup verified (' + b.type + ', ' + b.created_at + ').', undefined, 'backup');
  }));
  out.push(check('Backup schedules', 'backup_schedules', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1').get().c;
    if (c === 0) {
      return makeFinding('Backup schedules', 'warn', 'No active backup schedules.',
        'Add a schedule so backups run automatically.', 'backup_schedules');
    }
    return makeFinding('Backup schedules', 'pass', c + ' active schedule(s).', undefined, 'backup_schedules');
  }));
  out.push(check('Scheduled backup health', 'backup_schedules', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM backup_schedules WHERE active = 1 AND last_status = 'failed'"
    ).get().c;
    return makeFinding('Scheduled backup health', c > 0 ? 'fail' : 'pass',
      c > 0 ? c + ' active schedule(s) reported a failed last run.'
            : 'No active schedules report a failed last run.',
      c > 0 ? 'Open the failing schedule to see its last error.' : undefined, 'backup_schedules');
  }));
  return out;
}

function checkClient(db) {
  const out = [];
  out.push(check('Provisioned accounts', 'onboard', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
    return makeFinding('Provisioned accounts', 'pass',
      c + ' user account(s) provisioned.', undefined, 'onboard');
  }));
  out.push(check('Registered Analyst Client devices', 'onboard', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM ac_device_signing_keys WHERE active = 1').get().c;
    return makeFinding('Registered Analyst Client devices', c > 0 ? 'pass' : 'warn',
      c > 0 ? c + ' active Analyst Client device key(s) registered.'
            : 'No active Analyst Client device keys registered.',
      c > 0 ? undefined : 'Each Analyst Client registers a device signing key on first run; verify provisioning.',
      'onboard');
  }));
  out.push(check('Recent authentication activity', 'auth_logs', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM auth_log WHERE timestamp > datetime('now','-1 day')"
    ).get().c;
    return makeFinding('Recent authentication activity', 'pass',
      c + ' auth-log event(s) in the last 24h.', undefined, 'auth_logs');
  }));
  return out;
}

function checkAuth(db) {
  const out = [];
  out.push(check('Certificate Authority', 'iam', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM ca_authority WHERE is_active = 1').get().c;
    return makeFinding('Built-in Certificate Authority', c >= 1 ? 'pass' : 'fail',
      c >= 1 ? 'An active CA is initialized.'
             : 'No active CA found -- client-certificate authentication cannot operate.',
      c >= 1 ? undefined : 'The CA bootstraps at startup; check server logs for CA initialization errors.',
      'iam');
  }));
  out.push(check('Passkeys', 'iam', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM webauthn_credentials WHERE is_passwordless = 1').get().c;
    return makeFinding('Passwordless passkeys', c > 0 ? 'pass' : 'warn',
      c > 0 ? c + ' passwordless passkey(s) registered.' : 'No passwordless passkeys registered yet.',
      c > 0 ? undefined : 'Users register passkeys under My Security; the first credential is redeemed via an enrollment token.',
      'iam');
  }));
  out.push(check('Client certificates', 'iam', function () {
    const active = db.prepare("SELECT COUNT(*) AS c FROM issued_certs WHERE status = 'active'").get().c;
    const soon = db.prepare(
      "SELECT COUNT(*) AS c FROM issued_certs WHERE status = 'active' AND expires_at < datetime('now','+14 days')"
    ).get().c;
    if (soon > 0) {
      return makeFinding('Client certificates', 'warn',
        active + ' active client cert(s); ' + soon + ' expiring within 14 days.',
        'Re-enroll the expiring certificates before they lapse.', 'iam');
    }
    return makeFinding('Client certificates', 'pass',
      active + ' active client cert(s); none expiring within 14 days.', undefined, 'iam');
  }));
  out.push(check('Break-glass recovery', 'iam', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM auth_recovery WHERE is_active = 1').get().c;
    return makeFinding('Break-glass recovery credential', c >= 1 ? 'pass' : 'warn',
      c >= 1 ? 'An active break-glass recovery credential is configured.'
             : 'No active break-glass recovery credential.',
      c >= 1 ? undefined : 'Mint a break-glass credential so admin access is recoverable if all passkeys and certs are lost.',
      'iam');
  }));
  out.push(check('Pending enrollments', 'iam', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM enrollment_tokens WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > datetime('now')"
    ).get().c;
    return makeFinding('Pending enrollment tokens', 'pass',
      c + ' unredeemed, unexpired enrollment token(s).', undefined, 'iam');
  }));
  out.push(check('Recent authentication failures', 'auth_logs', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM auth_log WHERE timestamp > datetime('now','-1 day') " +
      "AND (action LIKE '%fail%' OR action LIKE '%deny%' OR action LIKE '%denied%' OR reason IS NOT NULL)"
    ).get().c;
    return makeFinding('Recent authentication failures', c > 0 ? 'warn' : 'pass',
      c > 0 ? c + ' failed or denied auth event(s) in the last 24h.'
            : 'No failed or denied auth events in the last 24h.',
      c > 0 ? 'Review the auth log to find the source of the failures.' : undefined, 'auth_logs');
  }));
  return out;
}

function checkTripwire(db) {
  const out = [];
  out.push(check('Tripwire configuration', 'tripwire', function () {
    const cfg = parseJson(teamConfigValue(db, 'tripwire_config'), null);
    if (!cfg) {
      return makeFinding('Tripwire configuration', 'warn',
        'No tripwire configuration found (defaults apply).', undefined, 'tripwire');
    }
    const enabled = cfg.enabled !== false;
    const thr = cfg.threshold_pct != null ? cfg.threshold_pct + '%' : 'default';
    const win = cfg.window_minutes != null ? cfg.window_minutes + ' min' : 'default';
    return makeFinding('Tripwire configuration', enabled ? 'pass' : 'warn',
      enabled ? 'Enabled (threshold ' + thr + ', window ' + win + ').'
              : 'Reduced-routing tripwire detection is disabled.',
      enabled ? undefined : 'Enable the tripwire to detect synchronized reduced-routing abuse.', 'tripwire');
  }));
  out.push(check('Active tripwire lockout', 'tripwire', function () {
    const ev = db.prepare(
      "SELECT tripped_at, segment, pct_in_reduced FROM tripwire_events " +
      "WHERE lockout_active = 1 AND resolved_at IS NULL ORDER BY tripped_at DESC, rowid DESC LIMIT 1"
    ).get();
    if (ev) {
      const pct = ev.pct_in_reduced != null ? ev.pct_in_reduced + '% in reduced load, ' : '';
      return makeFinding('Active tripwire lockout', 'fail',
        'A lockout is active (segment ' + ev.segment + ', ' + pct + 'tripped ' + ev.tripped_at + ').',
        'Resolve it from the Tripwire tab after a clean compromise scan.', 'tripwire');
    }
    return makeFinding('Active tripwire lockout', 'pass', 'No active lockout.', undefined, 'tripwire');
  }));
  out.push(check('Recent tripwire trips', 'tripwire', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM tripwire_events WHERE tripped_at > datetime('now','-30 days')"
    ).get().c;
    return makeFinding('Recent tripwire trips', c > 0 ? 'warn' : 'pass',
      c > 0 ? c + ' trip(s) in the last 30 days.' : 'No trips in the last 30 days.', undefined, 'tripwire');
  }));
  return out;
}

function checkUpskill(db) {
  const out = [];
  out.push(check('Upskilling configuration', 'upskilling_hr', function () {
    const v = teamConfigValue(db, 'upskilling_config') || teamConfigValue(db, 'upskilling');
    return makeFinding('Upskilling configuration', v ? 'pass' : 'warn',
      v ? 'Upskilling configuration is present.'
        : 'No upskilling configuration found (the feature may be unconfigured).',
      undefined, 'upskilling_hr');
  }));
  out.push(check('Training completions', 'skillmatrix', function () {
    const c = db.prepare('SELECT COUNT(*) AS c FROM training_completions').get().c;
    return makeFinding('Training completions', 'pass',
      c + ' training completion(s) recorded.', undefined, 'skillmatrix');
  }));
  return out;
}

// --------------------------------------------------------------- baseline
function checkBaseline(db) {
  const out = [];
  out.push(check('Database', 'monitoring', function () {
    db.prepare('SELECT 1 AS ok').get();
    const integrity = db.prepare('PRAGMA quick_check').get();
    const val = integrity ? (integrity.quick_check || Object.values(integrity)[0]) : null;
    const ok = val === 'ok';
    return makeFinding('Database', ok ? 'pass' : 'fail',
      ok ? 'Connection and quick integrity check OK.' : 'The quick integrity check did not return OK.',
      ok ? undefined : 'Investigate possible DB corruption; restore from a verified backup if it persists.',
      'monitoring');
  }));
  out.push(check('Recent critical audit events', 'audit', function () {
    const c = db.prepare(
      "SELECT COUNT(*) AS c FROM audit_log WHERE timestamp > datetime('now','-1 day') AND (" +
      "event_type LIKE '%CHAIN_BREAK%' OR event_type LIKE '%TRIPWIRE%' OR event_type LIKE '%COMPROMISE%' OR " +
      "event_type LIKE '%PANIC%' OR event_type LIKE '%CRITICAL%' OR event_type LIKE '%BREAK_GLASS%' OR " +
      "event_type LIKE '%MISSING_LOGS%')"
    ).get().c;
    if (c > 0) {
      return makeFinding('Recent critical audit events', 'fail',
        c + ' high or critical audit event(s) in the last 24h.',
        'Review the audit log for the flagged events.', 'audit');
    }
    return makeFinding('Recent critical audit events', 'pass',
      'No high or critical audit events in the last 24h.', undefined, 'audit');
  }));
  out.push(check('Integration health snapshot', 'monitoring', function () {
    const snap = appConfigValue(db, 'integration_health_last_results');
    if (!snap) {
      return makeFinding('Integration health snapshot', 'warn',
        'No integration-health probe results recorded yet (the layer may be disabled or not yet run).',
        'Enable integration-health probes in System Health to populate this.', 'monitoring');
    }
    return makeFinding('Integration health snapshot', 'pass',
      'Integration-health probe results are present.', undefined, 'monitoring');
  }));
  out.push(check('Panic mode', 'routing', function () {
    const active = teamConfigValue(db, 'panic_mode') === '"active"';
    return makeFinding('Panic mode', active ? 'fail' : 'pass',
      active ? 'Panic mode is ACTIVE -- automatic routing is suspended.' : 'Panic mode is not active.',
      active ? 'Lift panic mode from the Routing tab once resolved.' : undefined, 'routing');
  }));
  out.push(check('Tripwire lockout', 'tripwire', function () {
    const ev = db.prepare(
      "SELECT tripped_at, segment FROM tripwire_events " +
      "WHERE lockout_active = 1 AND resolved_at IS NULL ORDER BY tripped_at DESC, rowid DESC LIMIT 1"
    ).get();
    if (ev) {
      return makeFinding('Tripwire lockout', 'fail',
        'A reduced-routing tripwire lockout is active (segment ' + ev.segment + ', tripped ' + ev.tripped_at + ').',
        'Resolve it from the Tripwire tab after a clean compromise scan.', 'tripwire');
    }
    return makeFinding('Tripwire lockout', 'pass', 'No active tripwire lockout.', undefined, 'tripwire');
  }));
  out.push(check('Version and anti-rollback fuse', 'overview', function () {
    const fuseDb = sysMetaValue(db, 'fuse_counter');
    const v = versionInfo ? versionInfo.version : null;
    const fuseCode = versionInfo ? versionInfo.fuseCounter : null;
    let detail = '';
    if (v) { detail += 'Version v' + v + '. '; }
    if (fuseCode != null) { detail += 'Fuse (code) ' + fuseCode + '. '; }
    if (fuseDb != null) { detail += 'Fuse (db) ' + fuseDb + '.'; }
    if (!detail) { detail = 'Version/fuse metadata is unavailable.'; }
    let status = 'pass';
    let fix;
    if (fuseCode != null && fuseDb != null && String(fuseCode) !== String(fuseDb)) {
      status = 'warn';
      fix = 'Code and DB fuse counters differ -- expected briefly after an upgrade; investigate if it persists.';
    }
    return makeFinding('Version and anti-rollback fuse', status, detail.trim(), fix, 'overview');
  }));
  return out;
}

// ----------------------------------------------------------------- router
function detectTopic(description) {
  const d = String(description || '').toLowerCase();
  function has() {
    for (let i = 0; i < arguments.length; i++) {
      if (d.indexOf(arguments[i]) !== -1) { return true; }
    }
    return false;
  }
  if (has('soar', 'playbook')) { return 'soar'; }
  if (has('siem', 'cef', 'splunk', 'sentinel', 'log forward', 'log-forward')) { return 'siem'; }
  if (has('peer', 'board', 'helper')) { return 'peer'; }
  if (has('rout', 'ticket', 'assign', 'queue', 'panic')) { return 'routing'; }
  if (has('backup', 'restore', 'snapshot')) { return 'backup'; }
  if (has('provision', 'enroll', 'device', 'client', 'onboard', 'sync')) { return 'client'; }
  if (has('auth', 'login', 'log in', 'sign in', 'sign-in', 'cert', 'passkey', 'webauthn', 'credential', 'break-glass', 'break glass')) { return 'auth'; }
  if (has('tripwire', 'reduced load', 'reduced-load', 'lockout')) { return 'tripwire'; }
  if (has('upskill', 'training', 'skill')) { return 'upskill'; }
  return 'general';
}

const TOPIC_CHECKS = {
  soar: checkSoar,
  siem: checkSiem,
  peer: checkPeer,
  routing: checkRouting,
  backup: checkBackup,
  client: checkClient,
  auth: checkAuth,
  tripwire: checkTripwire,
  upskill: checkUpskill
};

function runDiagnostics(db, description) {
  const topic = detectTopic(description);
  let findings = [];
  const fn = TOPIC_CHECKS[topic];
  if (fn) {
    try { findings = fn(db) || []; } catch (_e) { findings = []; }
  }
  let baseline = [];
  try { baseline = checkBaseline(db) || []; } catch (_e) { baseline = []; }
  return { topic: topic, findings: findings, baseline: baseline };
}

module.exports = { runDiagnostics: runDiagnostics, detectTopic: detectTopic };
