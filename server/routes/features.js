// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Feature Toggle System
// Team leads enable or disable individual features from the Management Console.
// Disabling a feature does NOT remove it: the feature greys out and its controls
// deactivate across the Management Console and Analyst Client, with an
// "administratively disabled" note explaining a lead can re-enable it. All
// feature data is preserved while a feature is off — turning it back on restores
// it exactly as it was.
//
// Every feature is classified:
//   - toggle : lead-settable. Only these can be changed through this route.
//   - locked : a security / integrity / safety / compliance capability. Shown in
//              the console as permanently on (with a reason). Never settable —
//              disabling one could lower the SOC's defenses, so the update route
//              rejects any attempt to change it even from a forged request.
//   - core   : structural scaffolding. No switch; not represented here.
//
// GET  /api/features         — effective toggle state + the classified catalog
// PUT  /api/features         — update toggle-class features only (lead/admin)
// GET  /api/features/catalog — the full classified catalog
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Feature Catalog (single source of truth) ─────────────────────────────────
// klass: 'toggle' | 'locked'. Toggles default ON unless noted. Locked entries
// are always on and carry a reason shown in the console.
const FEATURE_CATALOG = [
  // ── Wellbeing ──
  { id: 'peer_chat', name: 'Anonymous Peer Chat', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Encrypted anonymous peer support chat between analysts.' },
  { id: 'peer_board', name: 'Peer Support Board', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Async board for tips and questions, with tiered abuse flagging.' },
  { id: 'peer_scheduling', name: 'Peer Skill-Share Scheduling', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Schedule peer skill-share sessions between analysts.' },
  { id: 'breathing_exercise', name: 'Box Breathing Exercise', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Guided breathing widget in the Analyst Client wellness area.' },
  { id: 'lighter_queue', name: 'Lighter-Queue Requests', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Let analysts anonymously request a temporary lighter ticket load.' },
  { id: 'lead_messaging', name: 'Lead Chat — Pseudonymous, E2EE', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Pseudonymous, end-to-end-encrypted chat between an analyst and their team lead.' },
  { id: 'proactive_interventions', name: 'Proactive Break Interventions', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Research-cited prompts encouraging timely breaks.' },
  { id: 'upskilling_hour', name: 'Upskilling Hour', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Dedicated on-shift hour for development; routing pauses for that analyst.' },
  { id: 'helper_pay', name: 'Helper Pay & Recognition', category: 'wellbeing', klass: 'toggle', default: true,
    desc: 'Points for helping peers, recognition leaderboard, and redemption.' },

  // ── Operations ──
  { id: 'burnout_routing', name: 'Burnout-Aware Routing', category: 'operations', klass: 'toggle', default: true, warnOnDisable: true,
    desc: 'Publish burnout-aware routing variables to the SOAR/ticket system.' },
  { id: 'ooda_simulator', name: 'IR Simulator (OODA)', category: 'operations', klass: 'toggle', default: true,
    desc: 'Train on your org\u2019s real IR policies via OODA-loop scenarios.' },
  { id: 'recovery_runbook', name: 'Recovery Runbook', category: 'operations', klass: 'toggle', default: true,
    desc: 'Guided incident-recovery runbooks for leads.' },

  // ── Development ──
  { id: 'skill_assessments', name: 'Skills & Assessments', category: 'development', klass: 'toggle', default: true,
    desc: 'Skill assessments with gap-driven training recommendations.' },
  { id: 'training_certs', name: 'Training Recommendations & Certs', category: 'development', klass: 'toggle', default: true,
    desc: 'Gap-driven training recommendations and completion tracking.' },
  { id: 'general_certs', name: 'Professional Certifications Registry', category: 'development', klass: 'toggle', default: true,
    desc: 'Register and verify professional certifications.' },

  // ── Integrations ──
  { id: 'calendar_integration', name: 'Calendar & Scheduling Integration', category: 'integrations', klass: 'toggle', default: true,
    desc: 'Sync analyst work schedules to auto-stagger upskilling hours while preserving coverage.' },

  // ── Management ──
  { id: 'ttx_generator', name: 'Tabletop Exercise (TTX) Generator', category: 'management', klass: 'toggle', default: true,
    desc: 'Generate tabletop incident exercises for the team.' },
  { id: 'cicd_pipelines', name: 'CI/CD Pipelines', category: 'management', klass: 'toggle', default: false,
    desc: 'Integrate FireAlive with the org\u2019s CI/CD pipelines.' },

  // ── Locked: Wellbeing ──
  { id: 'signals_display', name: 'Behavioral Signals Display', category: 'wellbeing', klass: 'locked', default: true,
    reason: 'Analyst self-awareness baseline; stays private (Tier-3) and is always available.' },
  { id: 'retro_protocol', name: 'CISM Post-Incident Recovery', category: 'wellbeing', klass: 'locked', default: true,
    reason: 'Incident-recovery safety capability; always available.' },

  // ── Locked: Operations ──
  { id: 'sla_tracking', name: 'SLA Tracking', category: 'operations', klass: 'locked', default: true,
    reason: 'Operational integrity metric; always on.' },
  { id: 'auto_routing_disable', name: 'Auto-Disable Routing', category: 'operations', klass: 'locked', default: true,
    reason: 'Safety automation that protects analysts under overload; cannot be disabled.' },
  { id: 'tripwire', name: 'Tripwire', category: 'operations', klass: 'locked', default: true,
    reason: 'Compromise and insider-threat defense; cannot be disabled.' },

  // ── Locked: Security integrations ──
  { id: 'soar_integration', name: 'SOAR Integration', category: 'security', klass: 'locked', default: true,
    reason: 'Security integration; cannot be disabled.' },
  { id: 'edr_inspection', name: 'EDR Inspection', category: 'security', klass: 'locked', default: true,
    reason: 'Endpoint defense integration; cannot be disabled.' },
  { id: 'threat_hunting', name: 'Threat Hunting', category: 'security', klass: 'locked', default: true,
    reason: 'Detection capability; cannot be disabled.' },
  { id: 'sase', name: 'SASE / ZTNA', category: 'security', klass: 'locked', default: true,
    reason: 'Network security integration; cannot be disabled.' },
  { id: 'vuln_scanning', name: 'Vulnerability Scan', category: 'security', klass: 'locked', default: true,
    reason: 'Authorized-scanner surface; cannot be disabled.' },
  { id: 'cloud_vuln_scan', name: 'Cloud Vulnerability Scan', category: 'security', klass: 'locked', default: true,
    reason: 'Authorized cloud-scanner surface; cannot be disabled.' },
  { id: 'enterprise_kms', name: 'Enterprise KMS', category: 'security', klass: 'locked', default: true,
    reason: 'Key-management integration; cannot be disabled.' },

  // ── Locked: Security ──
  { id: 'pseudonyms', name: 'Analyst Pseudonyms', category: 'security', klass: 'locked', default: true,
    reason: 'Core analyst-anonymity invariant; can never be disabled.' },
  { id: 'auth_logs', name: 'Audit Log', category: 'security', klass: 'locked', default: true,
    reason: 'Tamper-evident audit cannot be switched off.' },
  { id: 'log_integrity', name: 'Log Integrity', category: 'security', klass: 'locked', default: true,
    reason: 'Hash-chain integrity invariant; cannot be disabled.' },
  { id: 'mfa_wizard', name: 'Multi-Factor Authentication', category: 'security', klass: 'locked', default: true,
    reason: 'Authentication control; cannot be disabled.' },
  { id: 'config_padlocks', name: 'Configuration Lock', category: 'security', klass: 'locked', default: true,
    reason: 'Protects configuration changes; cannot be disabled.' },
  { id: 'insider_threat_protocol', name: 'Insider Threat Protocol', category: 'security', klass: 'locked', default: true,
    reason: 'Insider-threat defense; cannot be disabled.' },
  { id: 'compromise_scan', name: 'Client Compromise Self-Scan', category: 'security', klass: 'locked', default: true,
    reason: 'Not optional \u2014 client compromise affects the whole team.' },
  { id: 'post_session_flagging', name: 'Peer Abuse Flagging', category: 'security', klass: 'locked', default: true,
    reason: 'Analysts must always be able to report abuse.' },
  { id: 'concurrent_session_block', name: 'Concurrent Session Block', category: 'security', klass: 'locked', default: true,
    reason: 'Session security; cannot be disabled.' },
  { id: 'inactivity_lock', name: 'Inactivity Lock', category: 'security', klass: 'locked', default: true,
    reason: 'Session security; cannot be disabled.' },
  { id: 'dual_approval', name: 'Dual Approval', category: 'security', klass: 'locked', default: true,
    reason: 'Two-person integrity control; cannot be disabled.' },
  { id: 'auth_log_notifications', name: 'Auth-Log Notifications', category: 'security', klass: 'locked', default: true,
    reason: 'Security alerting; cannot be disabled.' },
  { id: 'posture_assessment', name: 'Posture Assessment', category: 'security', klass: 'locked', default: true,
    reason: 'Client posture defense; cannot be disabled.' },
  { id: 'wifi_policy', name: 'WiFi Policy', category: 'security', klass: 'locked', default: true,
    reason: 'Network policy control; cannot be disabled.' },
  { id: 'geo_fencing', name: 'Geo-Fencing', category: 'security', klass: 'locked', default: true,
    reason: 'Location policy control; cannot be disabled.' },
  { id: 'biometrics', name: 'Biometric Authentication', category: 'security', klass: 'locked', default: true,
    reason: 'Authentication control; cannot be disabled.' },
  { id: 'post_session_rating', name: 'Post-Session Rating', category: 'security', klass: 'locked', default: true,
    reason: 'Quality and safety signal; cannot be disabled.' },

  // ── Locked: Management / Data ──
  { id: 'compliance_reports', name: 'Compliance Reports', category: 'management', klass: 'locked', default: true,
    reason: 'Compliance integrity; always available.' },
  { id: 'backup', name: 'Backup & Storage Routing', category: 'management', klass: 'locked', default: true,
    reason: 'Disaster-recovery requirement; cannot be disabled.' },
  { id: 'backup_schedules', name: 'Backup Schedules', category: 'management', klass: 'locked', default: true,
    reason: 'Disaster-recovery requirement; cannot be disabled.' },
  { id: 'restore', name: 'Restore', category: 'management', klass: 'locked', default: true,
    reason: 'Disaster-recovery capability; cannot be disabled.' },
  { id: 'evidence_preservation', name: 'Evidence Preservation', category: 'management', klass: 'locked', default: true,
    reason: 'Immutable audit trail, eternal abuse-evidence vault, and forensic export; cannot be disabled.' },
  { id: 'analyst_offboarding', name: 'Analyst Offboarding', category: 'management', klass: 'locked', default: true,
    reason: 'Lifecycle and security requirement; cannot be disabled.' },
  { id: 'client_notifications', name: 'Client Notifications', category: 'management', klass: 'locked', default: true,
    reason: 'Critical alerts always deliver; channels remain configurable.' },
];

const TOGGLE_IDS = new Set(FEATURE_CATALOG.filter(f => f.klass === 'toggle').map(f => f.id));

// Effective toggle state = saved value (if present) merged over the default.
function effectiveToggles(saved) {
  const out = {};
  for (const f of FEATURE_CATALOG) {
    if (f.klass !== 'toggle') continue;
    out[f.id] = saved[f.id] !== undefined ? !!saved[f.id] : f.default;
  }
  return out;
}

// ── Get current toggles + catalog ────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'feature_toggles'").get();
    db.close();
    const saved = row ? JSON.parse(row.value) : {};
    res.json({ features: effectiveToggles(saved), catalog: FEATURE_CATALOG });
  } catch (err) {
    logger.error('Get features error', { error: err.message });
    res.status(500).json({ error: 'Failed to get feature toggles' });
  }
});

// ── Update toggles (lead/admin; toggle-class only) ───────────────────────────
router.put('/', (req, res) => {
  if (req.user.role === 'analyst') {
    return res.status(403).json({ error: 'Only leads/admins can change feature toggles' });
  }
  const { features } = req.body || {};
  if (!features || typeof features !== 'object') {
    return res.status(400).json({ error: 'features object required' });
  }

  // Accept only toggle-class ids. Anything else (locked, core, unknown) is
  // rejected — a locked feature cannot be disabled even by a forged request.
  const incoming = {};
  const rejected = [];
  for (const [id, enabled] of Object.entries(features)) {
    if (TOGGLE_IDS.has(id)) incoming[id] = !!enabled;
    else rejected.push(id);
  }

  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'feature_toggles'").get();
    const prevSaved = row ? JSON.parse(row.value) : {};
    const prev = effectiveToggles(prevSaved);

    // Persist only valid toggle ids (drops any stale/unknown keys from storage).
    const merged = { ...prevSaved, ...incoming };
    const clean = {};
    for (const id of TOGGLE_IDS) {
      if (merged[id] !== undefined) clean[id] = !!merged[id];
    }
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('feature_toggles', ?, ?)")
      .run(JSON.stringify(clean), req.user.id);
    db.close();

    const effective = effectiveToggles(clean);
    const changes = [];
    for (const id of Object.keys(incoming)) {
      if (prev[id] !== effective[id]) changes.push(`${id}:${prev[id] ? 'on' : 'off'}->${effective[id] ? 'on' : 'off'}`);
    }
    const detail = (changes.length ? changes.join(', ') : 'no change')
      + (rejected.length ? ` | rejected non-toggle ids: ${rejected.join(', ')}` : '');
    auditLog(req.user.id, 'FEATURES_UPDATED', detail, req.ip);

    // U1: live-propagate the new toggle state to every connected client so the
    // console and analyst clients grey or restore features without a reload.
    // Non-fatal: a broadcast failure must not fail the update.
    try {
      const wsServer = req.app && req.app.locals && req.app.locals.wsServer;
      if (wsServer && typeof wsServer.broadcastFeatureToggles === 'function') {
        wsServer.broadcastFeatureToggles(effective);
      }
    } catch (broadcastErr) {
      logger.error('Feature toggles: broadcast failed (non-fatal)', { error: broadcastErr.message });
    }

    res.json({ ok: true, features: effective, rejected });
  } catch (err) {
    logger.error('Update features error', { error: err.message });
    res.status(500).json({ error: 'Failed to update feature toggles' });
  }
});

// ── Full classified catalog ──────────────────────────────────────────────────
router.get('/catalog', (req, res) => {
  res.json({ catalog: FEATURE_CATALOG });
});

module.exports = router;
