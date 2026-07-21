// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Metrics Collector
// Collects metrics across all features for monitoring and SIEM output
// ═══════════════════════════════════════════════════════════════════════════════

const { versionLabel, fuseCounter, buildId } = require('../lib/version');

class MetricsCollector {
  constructor(db) { this.db = db; this.metrics = {}; }

  collect() {
    return {
      timestamp: new Date().toISOString(),
      // Core burnout metrics
      team_health: this._getTeamHealth(),
      routing: this._getRoutingMetrics(),
      // Peer support
      peer_sessions: this._getPeerMetrics(),
      // Training & skills
      training: this._getTrainingMetrics(),
      assessments: this._getAssessmentMetrics(),
      // Security
      auth: this._getAuthMetrics(),
      audit_integrity: this._getAuditIntegrity(),
      // Operations
      backup: this._getBackupMetrics(),
      upskilling: this._getUpskillingMetrics(),
      // Integration health
      integrations: this._getIntegrationHealth(),
      // Feature toggle state
      features: this._getFeatureState(),
      // New v1.0.0 services
      notifications: this._getNotificationMetrics(),
      ir_policies: this._getIRPolicyMetrics(),
      // System
      system: { uptime: process.uptime(), memory: process.memoryUsage(), version: versionLabel, fuse: fuseCounter, buildId }
    };
  }

  _getTeamHealth() {
    try {
      const analysts = this.db.prepare("SELECT COUNT(*) as total, AVG(capacity_score) as avg_capacity FROM users WHERE role='analyst' AND active=1").get();
      return { analysts: analysts?.total || 0, avgCapacity: Math.round(analysts?.avg_capacity || 0) };
    } catch { return { analysts: 0, avgCapacity: 0 }; }
  }
  _getRoutingMetrics() {
    try {
      const panic = this.db.prepare("SELECT value FROM config WHERE key='panic_mode'").get();
      const routing = this.db.prepare("SELECT value FROM config WHERE key='routing_enabled'").get();
      return { panicMode: panic?.value === 'true', enabled: routing?.value !== 'false' };
    } catch { return { panicMode: false, enabled: true }; }
  }
  _getPeerMetrics() {
    try {
      const sessions = this.db.prepare("SELECT COUNT(*) as total FROM peer_sessions WHERE created_at > datetime('now', '-24 hours')").get();
      return { last24h: sessions?.total || 0 };
    } catch { return { last24h: 0 }; }
  }
  _getTrainingMetrics() {
    try {
      const completions = this.db.prepare("SELECT COUNT(*) as total FROM training_completions WHERE status='verified'").get();
      return { verified: completions?.total || 0 };
    } catch { return { verified: 0 }; }
  }
  _getAssessmentMetrics() {
    try {
      const a = this.db.prepare("SELECT COUNT(*) as total, AVG(score) as avg FROM assessment_results").get();
      return { completed: a?.total || 0, avgScore: Math.round(a?.avg || 0) };
    } catch { return { completed: 0, avgScore: 0 }; }
  }
  _getAuthMetrics() {
    try {
      const logins = this.db.prepare("SELECT COUNT(*) as total FROM audit_log WHERE event_type='LOGIN' AND timestamp > datetime('now', '-24 hours')").get();
      const failures = this.db.prepare("SELECT COUNT(*) as total FROM audit_log WHERE event_type='LOGIN_FAILED' AND timestamp > datetime('now', '-24 hours')").get();
      return { logins24h: logins?.total || 0, failures24h: failures?.total || 0 };
    } catch { return { logins24h: 0, failures24h: 0 }; }
  }
  _getAuditIntegrity() {
    try {
      const last = this.db.prepare("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").get();
      return { lastHash: last?.hash?.substring(0, 16) || 'none', intact: true };
    } catch { return { intact: false }; }
  }
  _getBackupMetrics() {
    try {
      const last = this.db.prepare("SELECT value FROM config WHERE key='last_backup'").get();
      return last ? JSON.parse(last.value) : { lastBackup: 'never' };
    } catch { return { lastBackup: 'never' }; }
  }
  _getUpskillingMetrics() {
    try {
      const sched = this.db.prepare("SELECT COUNT(*) as total FROM config WHERE key LIKE 'upskilling_schedule_%'").get();
      return { scheduledAnalysts: sched?.total || 0 };
    } catch { return { scheduledAnalysts: 0 }; }
  }
  _getIntegrationHealth() {
    try {
      // Prefer the most recent integration-health probe run when present.
      const cached = {};
      try {
        const row = this.db.prepare("SELECT value FROM config WHERE key='integration_health_last_results'").get();
        if (row && row.value) {
          const parsed = JSON.parse(row.value);
          for (const r of (parsed.results || [])) if (r && r.integration) cached[r.integration] = r.status;
        }
      } catch (_) { /* no cached run */ }
      let masterEnabled = false;
      try {
        const m = this.db.prepare("SELECT value FROM config WHERE key='integration_health_probes_enabled'").get();
        masterEnabled = !!m && (m.value === 'true' || m.value === '1');
      } catch (_) { /* default off */ }

      const keys = ['soar', 'ticketing', 'iam', 'siem', 'kms', 'storage', 'edr'];
      const out = {};
      for (const k of keys) {
        if (cached[k]) { out[k] = cached[k]; continue; } // real probe status (ok/unreachable/auth_failed/...)
        const configured = this._isIntegrationConfigured(k);
        out[k] = !configured ? 'not_configured' : (masterEnabled ? 'configured_not_probed' : 'probes_disabled');
      }
      return out;
    } catch { return {}; }
  }

  _isIntegrationConfigured(key) {
    try {
      if (key === 'soar' || key === 'ticketing' || key === 'siem') {
        return !!this.db.prepare('SELECT 1 FROM config WHERE key = ?').get(`${key}_config`);
      }
      if (key === 'iam') {
        const r = this.db.prepare("SELECT value FROM team_config WHERE key = 'iam_config'").get();
        if (!r || !r.value) return false;
        try { const c = JSON.parse(r.value); return !!(c && c.server && c.bindDn); } catch { return false; }
      }
      if (key === 'kms') { const c = this.db.prepare('SELECT COUNT(*) AS c FROM kms_providers WHERE enabled = 1').get(); return !!(c && c.c > 0); }
      if (key === 'storage') { const c = this.db.prepare('SELECT COUNT(*) AS c FROM storage_destinations WHERE enabled = 1').get(); return !!(c && c.c > 0); }
      if (key === 'edr') { const c = this.db.prepare('SELECT COUNT(*) AS c FROM malware_scanner_integrations').get(); return !!(c && c.c > 0); }
      return false;
    } catch { return false; }
  }
  _getNotificationMetrics() {
    try { const n = this.db.prepare("SELECT COUNT(*) as total, SUM(CASE WHEN read_at IS NULL THEN 1 ELSE 0 END) as unread FROM notifications").get(); return { total: n?.total || 0, unread: n?.unread || 0 }; } catch { return { total: 0, unread: 0 }; }
  }
  _getIRPolicyMetrics() {
    try { const p = this.db.prepare("SELECT COUNT(*) as c FROM ir_policies").get(); return { loaded: p?.c || 0 }; } catch { return { loaded: 0 }; }
  }
  _getFeatureState() {
    try {
      const features = this.db.prepare("SELECT feature, enabled FROM feature_toggles").all();
      return features.reduce((acc, f) => { acc[f.feature] = f.enabled === 1; return acc; }, {});
    } catch { return {}; }
  }

  // Format for SIEM CEF output
  toCEF() {
    const m = this.collect();
    return `CEF:0|FireAlive|SOC-Wellbeing|${m.system.version}|METRICS|Team Health|5|` +
      `teamHealth=${m.team_health.avgCapacity} analysts=${m.team_health.analysts} ` +
      `routingEnabled=${m.routing.enabled} panicMode=${m.routing.panicMode} ` +
      `peerSessions24h=${m.peer_sessions.last24h} ` +
      `trainingVerified=${m.training.verified} assessments=${m.assessments.completed} ` +
      `logins24h=${m.auth.logins24h} authFailures=${m.auth.failures24h} ` +
      `auditIntact=${m.audit_integrity.intact} ` +
      `soar=${m.integrations.soar} ticketing=${m.integrations.ticketing} ` +
      `fuse=${m.system.fuse} uptime=${Math.round(m.system.uptime)} notifications=${m.notifications.unread} irPolicies=${m.ir_policies.loaded}`;
  }
}

module.exports = { MetricsCollector };
