// FireAlive v1.0.0 — Signal Collector
// Automatically generates burnout signal readings from analyst activity data
// Data sources: ticket velocity from ticketing adapter, session duration,
// break patterns, overtime tracking

class SignalCollector {
  constructor(db) { this.db = db; }

  // Called periodically (every 15 min) to collect signals for active analysts
  async collectAll() {
    const analysts = this.db.prepare("SELECT id, uuid FROM users WHERE role='analyst' AND active=1").all();
    const results = [];
    for (const analyst of analysts) {
      const signals = this._generateSignals(analyst);
      const { AiBurnoutEngine } = require('./ai-burnout-engine');
      const engine = new AiBurnoutEngine(this.db);
      for (const sig of signals) {
        engine.recordSignal(analyst.id, sig.signal, sig.value);
      }
      results.push({ analyst: analyst.uuid, signals: signals.length });
    }
    return { collected: results.length, timestamp: new Date().toISOString() };
  }

  _generateSignals(analyst) {
    const signals = [];
    // Cognitive load: derived from ticket count in last hour
    const ticketCount = this._getTicketCount(analyst.id);
    signals.push({ signal: 'cognitive_load', value: Math.min(100, ticketCount * 8) });
    // Task switching: count of different ticket types handled
    const switchCount = this._getTaskSwitchCount(analyst.id);
    signals.push({ signal: 'task_switching', value: switchCount });
    // Queue pressure: pending tickets assigned
    const queueDepth = this._getQueueDepth(analyst.id);
    signals.push({ signal: 'queue_pressure', value: queueDepth });
    // Response latency: avg time to first action on ticket
    const latency = this._getResponseLatency(analyst.id);
    signals.push({ signal: 'response_latency', value: latency });
    // Break compliance: % of scheduled breaks actually taken
    const breaks = this._getBreakCompliance(analyst.id);
    signals.push({ signal: 'break_compliance', value: breaks });
    // Shift overtime: hours past shift end
    const overtime = this._getOvertime(analyst.id);
    signals.push({ signal: 'shift_overtime', value: overtime });
    return signals;
  }

  _getTicketCount(analystId) {
    try {
      const r = this.db.prepare("SELECT COUNT(*) as c FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-1 hour')").get(analystId);
      return r?.c || 0;
    } catch { return 0; }
  }
  _getTaskSwitchCount(analystId) {
    try {
      const r = this.db.prepare("SELECT COUNT(DISTINCT category) as c FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-1 hour')").get(analystId);
      return r?.c || 0;
    } catch { return 0; }
  }
  _getQueueDepth(analystId) {
    try {
      const r = this.db.prepare("SELECT COUNT(*) as c FROM ticket_assignments WHERE analyst_id=? AND status='open'").get(analystId);
      return r?.c || 0;
    } catch { return 0; }
  }
  _getResponseLatency(analystId) {
    try {
      const r = this.db.prepare("SELECT AVG(response_time_min) as avg FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-1 hour')").get(analystId);
      return Math.round((r?.avg || 3) * 10) / 10;
    } catch { return 3.0; }
  }
  _getBreakCompliance(analystId) {
    try {
      const r = this.db.prepare("SELECT value FROM config WHERE key='break_compliance_' || ?").get(analystId);
      return r ? parseFloat(r.value) : 85;
    } catch { return 85; }
  }
  _getOvertime(analystId) {
    try {
      const r = this.db.prepare("SELECT value FROM config WHERE key='overtime_' || ?").get(analystId);
      return r ? parseFloat(r.value) : 0;
    } catch { return 0; }
  }
}

module.exports = { SignalCollector };
