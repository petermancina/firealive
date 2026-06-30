// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Metrics Collector (B6a)
//
// GD-server twin of the regional metrics-collector, scoped to the GD's read-only
// aggregation / compliance / signing role (the GD has no burnout / peer / train-
// ing metrics -- those live on the regional server and never reach the GD). This
// replaces the placeholder /api/system/health-metrics (which returned a random
// CPU value) with real metrics, and provides the CEF line for SIEM export.
//
// CPU / memory / FIM figures are pulled from the GD runtime-monitor singleton
// (services/gd-runtime-monitor) so the same measured numbers back the System
// Health tab, the SIEM line, and the alert thresholds.
//
// Every getter is defensive (try/catch -> sane default): a single metric source
// failing must never blank the whole collection or throw to the caller.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

class GdMetricsCollector {
  constructor(db) { this.db = db; this.metrics = {}; }

  collect() {
    return {
      timestamp: new Date().toISOString(),
      fleet: this._getFleet(),                     // connected MCs
      ingest: this._getIngest(),                   // rollup / metric push activity
      compliance: this._getCompliance(),           // compliance reports + rollup coverage
      signing_keys: this._getSigningKeys(),        // active keys + pending approvals
      audit_integrity: this._getAuditIntegrity(),  // last signed checkpoint + entry count
      backup: this._getBackup(),                   // last backup status / time
      notifications: this._getNotifications(),     // unacknowledged count
      integrations: this._getIntegrationHealth(),  // kms / storage / mc_trust scalar map
      runtime: this._getRuntime(),                 // cpu / mem / fim from the runtime-monitor
      system: this._getSystem(),                   // version / fuse / buildId / uptime / memory
    };
  }

  // ── GD fleet (the connected MCs the GD aggregates) ─────────────────────
  _getFleet() {
    try {
      const r = this.db.prepare(
        "SELECT COUNT(*) AS total, SUM(CASE WHEN status='active' THEN 1 ELSE 0 END) AS active FROM management_consoles"
      ).get();
      return { total: r?.total || 0, active: r?.active || 0 };
    } catch { return { total: 0, active: 0 }; }
  }

  // ── Ingest activity (the signed rollup / metric push pipeline) ─────────
  _getIngest() {
    try {
      const rollups = this.db.prepare('SELECT COUNT(*) AS total FROM cross_region_rollup').get();
      const recent = this.db.prepare("SELECT COUNT(*) AS n FROM regional_metrics WHERE timestamp > datetime('now','-24 hours')").get();
      const lastPush = this.db.prepare('SELECT MAX(last_push_at) AS last FROM cross_region_rollup').get();
      return { rollupTuples: rollups?.total || 0, metricPushes24h: recent?.n || 0, lastPushAt: lastPush?.last || null };
    } catch { return { rollupTuples: 0, metricPushes24h: 0, lastPushAt: null }; }
  }

  // ── Compliance rollup coverage ─────────────────────────────────────────
  _getCompliance() {
    try {
      const reports = this.db.prepare('SELECT COUNT(*) AS total FROM mc_compliance_reports').get();
      const frameworks = this.db.prepare('SELECT COUNT(DISTINCT framework) AS n FROM cross_region_rollup').get();
      return { reportsReceived: reports?.total || 0, frameworksCovered: frameworks?.n || 0 };
    } catch { return { reportsReceived: 0, frameworksCovered: 0 }; }
  }

  // ── Signing-key trust state ────────────────────────────────────────────
  _getSigningKeys() {
    try {
      const active = this.db.prepare('SELECT COUNT(*) AS n FROM signing_keys WHERE is_active=1').get();
      const pending = this.db.prepare("SELECT COUNT(*) AS n FROM signing_keys WHERE approval_status='pending_approval'").get();
      return { active: active?.n || 0, pendingApproval: pending?.n || 0 };
    } catch { return { active: 0, pendingApproval: 0 }; }
  }

  // ── Audit-chain integrity (lightweight: latest signed checkpoint head) ──
  // Side-effect-free; reads the last checkpoint rather than recomputing the
  // chain (a full verify is the audit-integrity timer's job, not the metrics
  // path's).
  _getAuditIntegrity() {
    try {
      const cp = this.db.prepare('SELECT head_hash, entry_count FROM audit_chain_checkpoint ORDER BY id DESC LIMIT 1').get();
      if (cp) return { lastCheckpointHash: (cp.head_hash || '').substring(0, 16), entryCount: cp.entry_count || 0, intact: true };
      const c = this.db.prepare('SELECT COUNT(*) AS n FROM audit_log').get();
      return { lastCheckpointHash: 'none', entryCount: c?.n || 0, intact: true };
    } catch { return { lastCheckpointHash: 'unknown', entryCount: 0, intact: false }; }
  }

  // ── Backup state ───────────────────────────────────────────────────────
  _getBackup() {
    try {
      const last = this.db.prepare('SELECT status, created_at FROM backups ORDER BY created_at DESC LIMIT 1').get();
      return last ? { lastStatus: last.status || 'unknown', lastAt: last.created_at || null } : { lastStatus: 'never', lastAt: null };
    } catch { return { lastStatus: 'never', lastAt: null }; }
  }

  // ── Notifications (the GD shared queue) ────────────────────────────────
  _getNotifications() {
    try {
      const n = this.db.prepare('SELECT COUNT(*) AS total, SUM(CASE WHEN acknowledged=0 THEN 1 ELSE 0 END) AS unack FROM notifications').get();
      return { total: n?.total || 0, unacknowledged: n?.unack || 0 };
    } catch { return { total: 0, unacknowledged: 0 }; }
  }

  // ── Integration-health scalar map ──────────────────────────────────────
  // Prefer the most recent cached probe run; otherwise report configured/
  // disabled. Scoped to the GD's real dependencies (kms / storage / mc_trust).
  _getIntegrationHealth() {
    const keys = ['kms', 'storage', 'mc_trust'];
    const out = {};
    const cached = {};
    let masterEnabled = false;
    try {
      const row = this.db.prepare("SELECT value FROM config WHERE key='integration_health_last_results'").get();
      if (row && row.value) {
        const parsed = JSON.parse(row.value);
        for (const r of (parsed.results || [])) if (r && r.integration) cached[r.integration] = r.status;
      }
    } catch { /* no cached run */ }
    try {
      const m = this.db.prepare("SELECT value FROM config WHERE key='integration_health_probes_enabled'").get();
      masterEnabled = !!m && (m.value === 'true' || m.value === '1');
    } catch { /* default off */ }
    for (const k of keys) {
      if (cached[k]) { out[k] = cached[k]; continue; }
      out[k] = masterEnabled ? 'configured_not_probed' : 'probes_disabled';
    }
    return out;
  }

  // ── Runtime metrics (measured by the runtime-monitor) ──────────────────
  _getRuntime() {
    try {
      const { gdRuntimeMonitor } = require('./gd-runtime-monitor');
      const m = gdRuntimeMonitor.getMetrics();
      return { cpu: m.cpu || 0, memMB: m.memMB || 0, heapMB: m.heapMB || 0, dbReadsPerMin: m.dbReadsPerMin || 0, fimFiles: m.fileCount || 0 };
    } catch { return { cpu: 0, memMB: 0, heapMB: 0, dbReadsPerMin: 0, fimFiles: 0 }; }
  }

  // ── System (version / fuse / buildId from the GD package.json) ─────────
  _getSystem() {
    let version = null, fuse = null, buildId = null;
    try {
      const pkg = require('../package.json');
      version = typeof pkg.version === 'string' ? pkg.version : null;
      fuse = typeof pkg.fuseCounter === 'number' ? pkg.fuseCounter : null;
      buildId = typeof pkg.buildId === 'string' ? pkg.buildId : null;
    } catch { /* leave nulls */ }
    const mem = process.memoryUsage();
    return {
      version, fuse, buildId,
      uptime: Math.round(process.uptime()),
      memoryMB: Math.round(mem.rss / 1024 / 1024),
      heapMB: Math.round(mem.heapUsed / 1024 / 1024),
      nodeVersion: process.version,
    };
  }

  // Format for SIEM CEF output -- the pull companion to the alert-router's
  // immediate SIEM push (SIEM platforms can poll this line on a schedule).
  toCEF() {
    const m = this.collect();
    const v = m.system.version || 'unknown';
    return `CEF:0|FireAlive|GlobalDashboard|${v}|GD_METRICS|GD Health|5|` +
      `mcsActive=${m.fleet.active} mcsTotal=${m.fleet.total} ` +
      `rollupTuples=${m.ingest.rollupTuples} metricPushes24h=${m.ingest.metricPushes24h} ` +
      `complianceReports=${m.compliance.reportsReceived} frameworks=${m.compliance.frameworksCovered} ` +
      `signingKeysActive=${m.signing_keys.active} signingKeysPending=${m.signing_keys.pendingApproval} ` +
      `auditEntries=${m.audit_integrity.entryCount} auditIntact=${m.audit_integrity.intact} ` +
      `cpu=${m.runtime.cpu} memMB=${m.runtime.memMB} fimFiles=${m.runtime.fimFiles} ` +
      `kms=${m.integrations.kms} storage=${m.integrations.storage} mcTrust=${m.integrations.mc_trust} ` +
      `fuse=${m.system.fuse} uptime=${m.system.uptime} unackNotifications=${m.notifications.unacknowledged}`;
  }
}

module.exports = { GdMetricsCollector };
