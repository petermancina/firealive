// FireAlive v1.0.0 — Signal Collector
// Automatically generates burnout signal readings from analyst activity data
// Data sources: ticket velocity from ticketing adapter, session duration,
// break patterns, overtime tracking
//
// B5d1 (analyst-private data architecture): the collected signals divide into
// two kinds, handled differently.
//   - Behavioral signals (investigationTime, dismissRate, ticketQuality,
//     escalationRate, break_compliance) are the analyst's own burnout
//     response. The first four are computed statistically from the pushed
//     ticket_actions feed over a trailing 7-day window (B5d1-F + PR D);
//     break_compliance is computed at read time from proactive_break_events.
//     They are sealed to the analyst's own public key (analyst_private_data;
//     the server can write but cannot read them back) and a de-identified
//     copy is written for team aggregation. They never appear in
//     server-readable plaintext and never drive a lead-visible control.
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
const BEHAVIOR_SIGNALS = ['investigationTime', 'dismissRate', 'ticketQuality', 'escalationRate', 'break_compliance'];
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
    case 'shift_overtime':   return value >= 8  ? 2 : value >= 4  ? 1 : 0;
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

// Compute the four pressure signals for one analyst from live operational data.
// Shared by the collector (which derives the routing cap from these) and the
// analyst's own My Signals pressure section served by /api/signals/me, so both
// read a single source rather than drifting apart. Pure read; never throws.
function computeAnalystPressure(db, analystId) {
  let ticketCount = 0, switchCount = 0, queueDepth = 0, overtime = 0;
  try {
    const r = db.prepare("SELECT COUNT(*) AS c FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-1 hour')").get(analystId);
    ticketCount = (r && r.c) || 0;
  } catch (_e) {}
  try {
    const r = db.prepare("SELECT COUNT(DISTINCT category) AS c FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-1 hour')").get(analystId);
    switchCount = (r && r.c) || 0;
  } catch (_e) {}
  try {
    const r = db.prepare("SELECT COUNT(*) AS c FROM ticket_assignments WHERE analyst_id=? AND status='open'").get(analystId);
    queueDepth = (r && r.c) || 0;
  } catch (_e) {}
  try {
    const r = db.prepare("SELECT value FROM config WHERE key='overtime_' || ?").get(analystId);
    overtime = r ? (parseFloat(r.value) || 0) : 0;
  } catch (_e) {}
  return {
    cognitive_load: Math.min(100, ticketCount * 8),
    task_switching: switchCount,
    queue_pressure: queueDepth,
    shift_overtime: overtime,
  };
}

class SignalCollector {
  constructor(db) { this.db = db; }

  // Called periodically (every 15 min) to collect signals for active analysts
  async collectAll() {
    // B5d1-F: refresh the per-analyst shift_overtime cache (config['overtime_<id>'])
    // from the roster + after-hours activity before reading signals this cycle, so
    // both the collector below and team-health see a fresh value. Fault-isolated.
    try {
      require('./shift-overtime').computeAndStoreAll(this.db);
    } catch (e) {
      console.error('[signal-collector] shift-overtime compute failed:', e.message);
    }
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

    // ── Pressure signals (operational, lead-visible; drive the routing cap) ──
    // Computed from live operational data by the shared computeAnalystPressure
    // helper, the same source the analyst's My Signals pressure section reads.
    const pressure = computeAnalystPressure(this.db, analyst.id);
    signals.push({ signal: 'cognitive_load', value: pressure.cognitive_load });
    signals.push({ signal: 'task_switching', value: pressure.task_switching });
    signals.push({ signal: 'queue_pressure', value: pressure.queue_pressure });
    signals.push({ signal: 'shift_overtime', value: pressure.shift_overtime });

    // ── Behavioral signals (the analyst's own response; sealed + de-identified, ──
    // never lead-visible). The four ticket-derived signals are computed
    // statistically from the pushed ticket_actions feed over a trailing 7-day
    // window (D11). Each is skipped — not fabricated — when the analyst has no
    // qualifying activity in the window, so absent data never pollutes the
    // on-device baseline. break_compliance is computed at read from break events.
    const investigationTime = this._getInvestigationTime(analyst.id);
    if (investigationTime !== null) signals.push({ signal: 'investigationTime', value: investigationTime });
    const dismissRate = this._getDismissRate(analyst.id);
    if (dismissRate !== null) signals.push({ signal: 'dismissRate', value: dismissRate });
    const ticketQuality = this._getTicketQuality(analyst.id);
    if (ticketQuality !== null) signals.push({ signal: 'ticketQuality', value: ticketQuality });
    const escalationRate = this._getEscalationRate(analyst.id);
    if (escalationRate !== null) signals.push({ signal: 'escalationRate', value: escalationRate });
    const breaks = this._getBreakCompliance(analyst.id);
    if (breaks !== null) signals.push({ signal: 'break_compliance', value: breaks });

    return signals;
  }

  // ── Behavioral signal computations (statistical; sealed + de-identified) ──
  // All four read the pushed ticket_actions feed over a trailing 7-day window
  // and return null when the analyst has no qualifying activity, so the signal
  // is skipped rather than fabricated.

  // investigationTime: average minutes to first action per ticket (absorbs the
  // retired response_latency). Higher = slower triage under load.
  _getInvestigationTime(analystId) {
    try {
      const r = this.db.prepare(
        "SELECT AVG(response_time_min) AS v, COUNT(response_time_min) AS n FROM ticket_actions " +
        "WHERE analyst_id=? AND response_time_min IS NOT NULL AND created_at > datetime('now','-7 days')"
      ).get(analystId);
      if (!r || !r.n) return null;
      return Math.round(r.v * 10) / 10;
    } catch { return null; }
  }

  // dismissRate: share of closures resolved as a dismissal/false-positive,
  // dismiss / (close + dismiss), as a percentage. dismiss is a distinct action
  // type (kept separate from close), so this does not conflate with quality.
  _getDismissRate(analystId) {
    try {
      const r = this.db.prepare(
        "SELECT " +
        "SUM(CASE WHEN action_type='dismiss' THEN 1 ELSE 0 END) AS dismissed, " +
        "SUM(CASE WHEN action_type IN ('close','dismiss') THEN 1 ELSE 0 END) AS closures " +
        "FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-7 days')"
      ).get(analystId);
      const closures = r?.closures || 0;
      if (closures === 0) return null;
      return Math.round(((r.dismissed || 0) / closures) * 1000) / 10;
    } catch { return null; }
  }

  // escalationRate: share of all actions that were escalations, as a percentage.
  _getEscalationRate(analystId) {
    try {
      const r = this.db.prepare(
        "SELECT " +
        "SUM(CASE WHEN action_type='escalate' THEN 1 ELSE 0 END) AS escalated, " +
        "COUNT(*) AS total " +
        "FROM ticket_actions WHERE analyst_id=? AND created_at > datetime('now','-7 days')"
      ).get(analystId);
      const total = r?.total || 0;
      if (total === 0) return null;
      return Math.round(((r.escalated || 0) / total) * 1000) / 10;
    } catch { return null; }
  }

  // ticketQuality: statistical documentation-thoroughness score (0-100, higher
  // is better) over notes the analyst recorded in the window. Combines note
  // length with the presence of distinct IOC/enrichment marker categories
  // (IPv4, file hash, CVE id, enrichment keywords). Purely statistical, no LLM.
  _getTicketQuality(analystId) {
    try {
      const rows = this.db.prepare(
        "SELECT notes FROM ticket_actions WHERE analyst_id=? AND notes IS NOT NULL " +
        "AND TRIM(notes) <> '' AND created_at > datetime('now','-7 days')"
      ).all(analystId);
      if (!rows.length) return null;
      let sum = 0;
      for (const row of rows) {
        const note = String(row.notes);
        const lengthFactor = Math.min(1, note.length / 240);
        let cats = 0;
        if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(note)) cats++;                                                       // IPv4
        if (/\b[a-f0-9]{32,64}\b/i.test(note)) cats++;                                                              // file hash
        if (/\bCVE-\d{4}-\d{4,7}\b/i.test(note)) cats++;                                                            // CVE id
        if (/(enrich|correlat|mitre|att&ck|\bIOC\b|indicator|virustotal|sandbox|threat intel)/i.test(note)) cats++; // enrichment
        const markerFactor = Math.min(1, cats / 2);
        sum += 100 * (0.6 * lengthFactor + 0.4 * markerFactor);
      }
      return Math.round((sum / rows.length) * 10) / 10;
    } catch { return null; }
  }
  _getBreakCompliance(analystId) {
    // Computed at read time from proactive_break_events: taken / decided over a
    // trailing 30-day window, as a percentage. "decided" = breaks with a
    // recorded outcome plus offered breaks left unanswered past a 1-hour grace
    // (implicit expiry, counted as not-taken; no sweep needed). Offered breaks
    // still within grace are pending and excluded. Returns null when the analyst
    // had no decided breaks in the window, so the caller skips the signal.
    try {
      const r = this.db.prepare(
        "SELECT " +
        "SUM(CASE WHEN outcome='taken' THEN 1 ELSE 0 END) AS taken, " +
        "SUM(CASE WHEN outcome IN ('taken','declined','expired') OR offered_at <= datetime('now','-1 hour') THEN 1 ELSE 0 END) AS decided " +
        "FROM proactive_break_events " +
        "WHERE analyst_id=? AND offered_at > datetime('now','-30 days')"
      ).get(analystId);
      const decided = r?.decided || 0;
      if (decided === 0) return null;
      return Math.round(((r.taken || 0) / decided) * 1000) / 10;
    } catch { return null; }
  }
}

module.exports = { SignalCollector, computeAnalystPressure };
