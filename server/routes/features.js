// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Feature Toggle System
// Team leads can enable/disable individual features from the Management Console.
// Disabled features disappear from both Management Console and Analyst Client.
// All feature logic remains available — leads can re-enable at any time.
//
// GET  /api/features         — get current feature toggles
// PUT  /api/features         — update feature toggles (lead/admin)
// GET  /api/features/catalog — list all available features with descriptions
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { logger } = require('../services/logger');

// ── Feature Catalog ──────────────────────────────────────────────────────────
const FEATURE_CATALOG = [
  { id: 'peer_chat', name: 'Anonymous Peer Chat', category: 'wellbeing', default: true,
    desc: 'Encrypted anonymous peer support chat with exclusion lists and mutual identity consent.' },
  { id: 'breathing_exercise', name: 'Box Breathing Exercise', category: 'wellbeing', default: true,
    desc: 'Guided 2-minute breathing exercise in the Analyst Client.' },
  { id: 'lighter_queue', name: 'Lighter Queue Requests', category: 'wellbeing', default: true,
    desc: 'Allow analysts to anonymously request temporary complexity caps.' },
  { id: 'lead_messaging', name: 'Anonymous Lead Messaging', category: 'wellbeing', default: true,
    desc: 'Encrypted anonymous messages from analysts to their team lead.' },
  { id: 'delegation', name: 'Automation Delegation', category: 'operations', default: true,
    desc: 'Allow analysts to propose alert patterns for automation delegation.' },
  { id: 'skill_assessments', name: 'Skills & Assessments', category: 'development', default: true,
    desc: 'Skill assessment system with gap-driven training recommendations.' },
  { id: 'training_certs', name: 'Training Certificates', category: 'development', default: true,
    desc: 'Certificate upload/verification workflow for training completion.' },
  { id: 'retro_protocol', name: 'Post-Incident Recovery Protocol', category: 'wellbeing', default: true,
    desc: 'CISM-informed recovery protocols with lighter queues and follow-up scheduling.' },
  { id: 'burnout_routing', name: 'Burnout-Aware Routing', category: 'operations', default: true,
    desc: 'Ticket routing with burnout awareness via SOAR integration.' },
  { id: 'siem_feed', name: 'SIEM Burnout Dashboard', category: 'integrations', default: true,
    desc: 'Send team health metrics to SIEM for dashboard display.' },
  { id: 'report_engine', name: 'Report Engine', category: 'management', default: true,
    desc: 'Scheduled and on-demand depersonalized team health reports.' },
  { id: 'soar_integration', name: 'SOAR Integration', category: 'integrations', default: true,
    desc: 'Write routing variables to SOAR platforms for burnout-aware ticket distribution.' },
  { id: 'ticket_integration', name: 'Ticketing System Integration', category: 'integrations', default: true,
    desc: 'Read-only integration with ticketing systems for metrics.' },
  { id: 'signals_display', name: 'Analyst Signal Display', category: 'wellbeing', default: true,
    desc: 'Show behavioral drift signals on the Analyst Client home screen.' },
  { id: 'impact_feed', name: 'Impact Verification Feed', category: 'wellbeing', default: true,
    desc: 'Show analysts the verified impact of their actions (delegations, lighter queues).' },
  { id: 'network_map', name: 'Network Connection Map', category: 'management', default: false,
    desc: 'Live visualization of all app connections (clients, integrations, SOAR, SIEM).' },
  { id: 'query_tool', name: 'Data Query Tool', category: 'management', default: false,
    desc: 'Regex-based query tool for burnout data (alternative to SIEM queries).' },
];

// ── Get Current Toggles ──────────────────────────────────────────────────────
router.get('/', (req, res) => {
  try {
    const db = getDb();
    const row = db.prepare("SELECT value FROM team_config WHERE key = 'feature_toggles'").get();
    db.close();

    const saved = row ? JSON.parse(row.value) : {};
    // Merge with defaults
    const toggles = {};
    for (const f of FEATURE_CATALOG) {
      toggles[f.id] = saved[f.id] !== undefined ? saved[f.id] : f.default;
    }

    res.json({ features: toggles });
  } catch (err) {
    logger.error('Get features error', { error: err.message });
    res.status(500).json({ error: 'Failed to get feature toggles' });
  }
});

// ── Update Toggles ───────────────────────────────────────────────────────────
router.put('/', (req, res) => {
  if (req.user.role === 'analyst') return res.status(403).json({ error: 'Only leads/admins can toggle features' });

  const { features } = req.body;
  if (!features || typeof features !== 'object') return res.status(400).json({ error: 'features object required' });

  // Validate only known feature IDs
  const validIds = new Set(FEATURE_CATALOG.map(f => f.id));
  const toggles = {};
  for (const [id, enabled] of Object.entries(features)) {
    if (validIds.has(id)) toggles[id] = !!enabled;
  }

  try {
    const db = getDb();
    db.prepare("INSERT OR REPLACE INTO team_config (key, value, updated_by) VALUES ('feature_toggles', ?, ?)").run(JSON.stringify(toggles), req.user.id);
    db.close();

    const disabled = Object.entries(toggles).filter(([, v]) => !v).map(([k]) => k);
    auditLog(req.user.id, 'FEATURES_UPDATED', `disabled: ${disabled.join(', ') || 'none'}`, req.ip);
    res.json({ ok: true, features: toggles });
  } catch (err) {
    logger.error('Update features error', { error: err.message });
    res.status(500).json({ error: 'Failed to update feature toggles' });
  }
});

// ── Feature Catalog ──────────────────────────────────────────────────────────
router.get('/catalog', (req, res) => {
  res.json({ catalog: FEATURE_CATALOG });
});

module.exports = router;
