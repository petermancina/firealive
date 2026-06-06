// FireAlive v1.0.42 — Team Health (server-side computeTH replica)
//
// Tier-1 team PRESSURE aggregate. This is the operational, lead-visible side of
// the pressure/behavior split: it summarizes workload applied to the team
// (ticket volume, overtime), never the analysts' private behavioral response.
// It reads only workload inputs — never signal_readings, the sealed
// analyst_private_data, or the de-identified store — and returns ONLY the team
// aggregate { score, status, avgUtil, oc, ext, size }, never any per-analyst
// value. That is what makes it safe to surface to leads and to drive the
// team-intervention conditions: a lead can see team pressure and reduce it
// before burnout without seeing any individual's data.
//
// Reproduces the management console's computeTH formula exactly, but computed
// server-side from canonical operational data instead of the hardcoded demo
// dataset the MC used.
//
// Inputs, all from canonical sources (the collector's pressure inputs):
//   - roster: analysts currently on shift (active + available). The MC demo
//     filtered a hardcoded "day" cohort; the available flag generalizes this
//     without baking in time-of-day shift assumptions.
//   - tk (ticket count, last hour): COUNT(*) from ticket_actions.
//   - wo (overtime hours): config key 'overtime_<analyst_id>'.
//   - util (0-1): the collector's canonical pressure/load metric reused here —
//     cognitive_load = min(100, ticketCount * 8), normalized to 0-1. Reusing
//     the established metric avoids a parallel definition of "load".
//
// The cs/dp/mt/at/ep/sc arithmetic and the status thresholds below are a
// byte-for-byte port of the MC computeTH, so server and client agree on which
// team conditions are active.

// util = min(1, ticketCount * 8 / FULL_LOAD_DIVISOR); 100 mirrors the
// cognitive_load cap, so util >= 0.85 corresponds to ~11+ tickets/hour.
const FULL_LOAD_DIVISOR = 100;

function computeTeamHealth(db) {
  let roster = [];
  try {
    roster = db
      .prepare("SELECT id FROM users WHERE role='analyst' AND active=1 AND available=1")
      .all();
  } catch {
    roster = [];
  }

  // Canonical per-analyst inputs as aggregate lookups; graceful if a table is
  // absent or empty (prototype/fresh DB) — that simply means zero load.
  const ticketByAnalyst = {};
  try {
    const rows = db
      .prepare(
        "SELECT analyst_id AS id, COUNT(*) AS c FROM ticket_actions " +
          "WHERE created_at > datetime('now','-1 hour') GROUP BY analyst_id"
      )
      .all();
    for (const r of rows) ticketByAnalyst[r.id] = r.c;
  } catch {
    /* no ticket_actions data -> zero load */
  }

  const overtimeByAnalyst = {};
  try {
    const rows = db.prepare("SELECT key, value FROM config WHERE key LIKE 'overtime_%'").all();
    for (const r of rows) {
      overtimeByAnalyst[r.key.slice('overtime_'.length)] = parseFloat(r.value) || 0;
    }
  } catch {
    /* no overtime config */
  }

  const sd = roster.map((a) => {
    const tk = ticketByAnalyst[a.id] || 0;
    const wo = overtimeByAnalyst[a.id] || 0;
    const util = Math.min(1, (tk * 8) / FULL_LOAD_DIVISOR);
    return { util, wo, tk };
  });

  // ── computeTH formula (exact MC replica) ───────────────────────────────────
  const n = sd.length || 1;
  const oc = sd.filter((d) => d.util > 0.85).length;
  const ext = sd.filter((d) => d.util > 0.85 && d.wo >= 2).length;
  const au = sd.reduce((s, d) => s + d.util, 0) / (sd.length || 1);
  const cs = Math.max(0, 100 - (oc / n) * 100);
  const dp = ext * 8;
  const mt = Math.max(...sd.map((d) => d.tk), 1);
  const at = sd.reduce((s, d) => s + d.tk, 0) / (sd.length || 1) || 1;
  const ep = Math.max(0, (mt / at - 1.5) * 20);
  const sc = Math.max(0, Math.min(100, Math.round(cs - dp - ep)));

  return {
    score: sc,
    status: sc < 40 ? 'critical' : sc < 60 ? 'stressed' : sc < 75 ? 'watch' : 'healthy',
    avgUtil: Math.round(au * 100),
    oc,
    ext,
    size: n,
  };
}

module.exports = { computeTeamHealth };
