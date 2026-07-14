// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE v1.0.0 — Feature Toggle System
// Enables/disables features without removing code. Greyed out UI + disabled inputs.
// ═══════════════════════════════════════════════════════════════════════════════

const FEATURES = {
  burnout_routing: { name: 'Burnout Prevention Routing', default: true, category: 'core' },
  peer_support: { name: 'Peer Support Chat', default: true, category: 'core' },
  upskilling: { name: 'Upskilling Hour', default: true, category: 'core' },
  assessments: { name: 'Skills Assessments', default: true, category: 'core' },
  ir_simulator: { name: 'IR/OODA Simulator', default: true, category: 'training' },
  ai_tutor: { name: 'AI Tutor', default: true, category: 'training' },
  helper_pay: { name: 'Helper Pay', default: false, category: 'optional' },
  pseudonym_rotation: { name: 'Pseudonym Rotation', default: true, category: 'privacy' },
  siem_widget: { name: 'SIEM Widget', default: true, category: 'integration' },
  soar_integration: { name: 'SOAR Integration', default: true, category: 'integration' },
  ticketing_integration: { name: 'Ticketing Integration', default: true, category: 'integration' },
  iam_offboarding: { name: 'IAM Offboarding Detection', default: true, category: 'integration' },
  backup_scheduler: { name: 'Backup Scheduler', default: true, category: 'operations' },
  compliance_reports: { name: 'Compliance Reports', default: true, category: 'compliance' },
  threat_hunting_transparency: { name: 'Threat Hunting Transparency', default: true, category: 'security' },
  edr_integration: { name: 'EDR Integration', default: true, category: 'security' },
  post_incident_wellness: { name: 'Post-Incident Wellness', default: true, category: 'wellness' },
  board: { name: 'Anonymous Board', default: true, category: 'wellness' },
  delegate_to_automation: { name: 'Delegate to Automation', default: true, category: 'core' },
};

class FeatureToggleService {
  constructor(db) { this.db = db; this._initTable(); }
  _initTable() {
    this.db.prepare("CREATE TABLE IF NOT EXISTS feature_toggles (feature TEXT PRIMARY KEY, enabled INTEGER DEFAULT 1, updated_at TEXT, updated_by TEXT)").run();
    for (const [key, feat] of Object.entries(FEATURES)) {
      this.db.prepare("INSERT OR IGNORE INTO feature_toggles (feature, enabled) VALUES (?, ?)").run(key, feat.default ? 1 : 0);
    }
  }
  isEnabled(feature) {
    const row = this.db.prepare("SELECT enabled FROM feature_toggles WHERE feature = ?").get(feature);
    return row ? row.enabled === 1 : FEATURES[feature]?.default ?? false;
  }
  setEnabled(feature, enabled, userId) {
    this.db.prepare("UPDATE feature_toggles SET enabled = ?, updated_at = ?, updated_by = ? WHERE feature = ?").run(enabled ? 1 : 0, new Date().toISOString(), userId, feature);
  }
  getAll() {
    const rows = this.db.prepare("SELECT * FROM feature_toggles").all();
    return rows.map(r => ({ ...r, ...FEATURES[r.feature], enabled: r.enabled === 1 }));
  }
}

module.exports = { FEATURES, FeatureToggleService };
