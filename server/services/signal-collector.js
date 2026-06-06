// FireAlive v1.0.0 — Signal Collector
// Automatically generates burnout signal readings from analyst activity data
// Data sources: ticket velocity from ticketing adapter, session duration,
// break patterns, overtime tracking
//
// B5d1 (analyst-private data architecture): the six collected signals divide
// into two kinds, handled differently.
//   - Behavioral signals (response_latency, break_compliance) are the
//     analyst's own burnout response. They are sealed to the analyst's own
//     public key (analyst_private_data; the server can write but cannot read
//     them back) and a de-identified copy is written for team aggregation.
//     They never appear in server-readable plaintext and never drive a
//     lead-visible control.
//   - Pressure signals (cognitive_load, task_switching, queue_pressure,
//     shift_overtime) are workload/force applied to the analyst by routing.
//     They stay on the operational, lead-visible path so a lead can reduce
//     pressure before burnout; they are NOT sealed or de-identified.
// The routing cap (max_complexity) is derived from the pressure signals only,
// keeping the analyst's private behavioral data out of a visible control. No
// per-analyst burnout score or risk tier is persisted server-side.

const { sealToPublicKey } = require('./analyst-crypto');

// The pressure/behavior split (research-grounded; see the KB: R029 and N004 on
// pressure as imposed demand, R005 and R033 on behavior as the analyst's
// response). Behavioral signals are sealed + de-identified and never enter
// server-readable plaintext; pressure signals stay operational and lead-visible.
const BEHAVIOR_SIGNALS = ['response_latency', 'break_compliance'];
const PRESSURE_SIGNALS = ['cognitive_load', 'task_switching', 'queue_pressure', 'shift_overtime'];

// Fixed operating-range thresholds per signal mapped to a 0/1/2 strain
// contribution. Absolute (no baseline), so the server never needs an analyst's
// history to set a protective cap; on-device baseline and drift remain the
// analyst's private interpretation. Higher contribution = more strain. The
// numbers are tunable operating heuristics, not a calibrated burnout metric.
function signalSeverity(signal, value) {
  switch (signal) {
    case 'cognitive_load':   return value >= 80 ? 2 : value >= 60 ? 1 : 0;
    case 'queue_pressure':   return value >= 12 ? 2 : value >= 8  ? 1 : 0;
    case 'shift_overtime':   return value >= 2  ? 2 : value >= 1  ? 1 : 0;
    case 'response_latency': return value >= 10 ? 2 : value >= 6  ? 1 : 0;
    case 'task_switching':   return value >= 10 ? 2 : value >= 6  ? 1 : 0;
    case 'break_compliance': return value <= 50 ? 2 : value <= 70 ? 1 : 0; // low = strain
    default: return 0;
  }
}

// Map the six current signals to a routing-cap ceiling. The cap is a coarse
// complexity ceiling (1-3), NOT a burnout metric: the analyst's tier is the
// natural ceiling and current strain reduces it by one or two steps. No score
// is stored; only the resulting ceiling, which other mechanisms also set.
function recommendedCap(tierBase, signals) {
  let high = 0;
  let moderate = 0;
  for (const s of signals) {
    const sev = signalSeverity(s.signal, s.value);
    if (sev === 2) high += 1;
    else if (sev === 1) moderate += 1;
  }
  let reduction = 0;
  if (high >= 2) reduction = 2;
  else if (high >= 1 || moderate >= 2) reduction = 1;
  const cap = tierBase - reduction;
  if (cap < 1) return 1;
  if (cap > tierBase) return tierBase;
  return cap;
}

class SignalCollector {
  constructor(db) { this.db = db; }

  // Called periodically (every 15 min) to collect signals for active analysts
  async collectAll() {
    const analysts = this.db
      .prepare("SELECT id, tier, shift FROM users WHERE role='analyst' AND active=1")
      .all();
    const results = [];
    const { AiBurnoutEngine } = require('./ai-burnout-engine');
    const engine = new AiBurnoutEngine(this.db);
    for (const analyst of analysts) {
      const signals = this._generateSignals(analyst);
      const behavior = signals.filter((s) => BEHAVIOR_SIGNALS.includes(s.signal));
      const pressure = signals.filter((s) => PRESSURE_SIGNALS.includes(s.signal));

      // Pressure signals are operational and lead-visible (workload/capacity);
      // they stay on the plaintext operational path. Behavioral signals are
      // deliberately NOT written in the clear here -- they are sealed to the
      // analyst only (below). This plaintext path is retired later in the phase.
      for (const sig of pressure) {
        engine.recordSignal(analyst.id, sig.signal, sig.value);
      }

      // (a) Seal ONLY the behavioral signals (the analyst's burnout response)
      // to the analyst's own public key. The server stores only ciphertext it
      // cannot open. Skipped when the analyst has not yet enrolled a key; that
      // pre-cutover history is resealed at enrollment in a later sub-phase.
      this._sealReading(analyst.id, behavior);

      // (b) De-identified copy of ONLY the behavioral signals, for team
      // aggregation. No identity column exists on this table; small groups are
      // suppressed by k-anonymity downstream. Pressure is aggregated from
      // operational data (team-health), not from this store.
      this._writeDeidentified(analyst, behavior);

      // (c) Routing cap from the PRESSURE signals only. The cap is a visible
      // routing control, so deriving it from workload -- not from the analyst's
      // private behavioral response -- keeps behavioral data out of it.
      this._applyRoutingCap(analyst, pressure);

      results.push({ analyst: analyst.id, signals: signals.length });
    }
    return { collected: results.length, timestamp: new Date().toISOString() };
  }

  // Seal one snapshot (the behavioral signals plus a timestamp) to the
  // analyst's active public key and store it as a private 'reading'. Never
  // blocks the collection run on a single analyst's seal failure.
  _sealReading(analystId, signals) {
    try {
      const key = this.db
        .prepare("SELECT public_key, key_version FROM analyst_keys WHERE analyst_id=? AND status='active'")
        .get(analystId);
      if (!key || !key.public_key) return; // not enrolled yet
      const snapshot = { v: 1, recorded_at: new Date().toISOString(), signals: {} };
      for (const s of signals) snapshot.signals[s.signal] = s.value;
      const sealed = sealToPublicKey(JSON.stringify(snapshot), key.public_key);
      this.db
        .prepare("INSERT INTO analyst_private_data (analyst_id, kind, ciphertext, key_version) VALUES (?, 'reading', ?, ?)")
        .run(analystId, sealed, key.key_version || 1);
    } catch (e) {
      // Sealing is best-effort per analyst; a failure here must not abort the
      // whole collection cycle for the rest of the roster.
    }
  }

  // Write one de-identified row per signal, tagged only by SOC tier and shift.
  // There is deliberately no analyst reference on this table.
  _writeDeidentified(analyst, signals) {
    try {
      const teamTag = analyst.tier != null ? 'tier' + analyst.tier : null;
      const shiftTag = analyst.shift || null;
      const ins = this.db.prepare(
        "INSERT INTO analyst_metrics_deidentified (team_tag, shift_tag, signal, value) VALUES (?, ?, ?, ?)"
      );
      for (const s of signals) ins.run(teamTag, shiftTag, s.signal, s.value);
    } catch (e) {
      // Aggregation copy is best-effort.
    }
  }

  // Derive and apply the routing cap. Protective ratchet-down only: lower the
  // ceiling toward the strain-derived recommendation, never raise it, and never
  // touch a manually overridden row. Raising a ceiling back up is an explicit
  // human or restore action elsewhere, by design.
  _applyRoutingCap(analyst, signals) {
    try {
      const tierBase = analyst.tier >= 1 && analyst.tier <= 3 ? analyst.tier : 2;
      const cap = recommendedCap(tierBase, signals);
      this.db
        .prepare(
          "INSERT INTO routing_caps (analyst_id, max_complexity, updated_at) " +
            "VALUES (?, ?, datetime('now')) " +
            "ON CONFLICT(analyst_id) DO UPDATE SET " +
            "max_complexity = MIN(max_complexity, excluded.max_complexity), " +
            "updated_at = datetime('now') " +
            "WHERE COALESCE(is_override, 0) != 1"
        )
        .run(analyst.id, cap);
    } catch (e) {
      // Cap is advisory; never block collection on it.
    }
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
