// FireAlive v1.0.42 — Team Intervention Conditions
//
// Deterministic detection predicates for the team-level intervention
// conditions surfaced on the management console Actions tab. Each entry is
// { key, severity, label, cond(th) }: the cond predicate decides whether the
// condition is currently active given the team-health aggregate (th), and the
// label is a factual description of the detected condition.
//
// This module holds NO advice text. When a condition is active, the burnout-
// message generator produces the actual guidance via the LLM, grounded in the
// research KB; when AI is unavailable the Actions tab shows the label only and
// no advice. The predicates mirror, server-side, the ones the MC previously
// evaluated client-side against its computeTH result — plus sustained_overcap,
// added in N1b.
//
// th shape (from team-health.js, the server computeTH replica):
//   { score, status, avgUtil, oc, ext, size }
// status thresholds: score < 40 critical, < 60 stressed, < 75 watch, else
// healthy. ext = analysts in extended over-capacity (util > 85% AND overtime
// >= 2). Conditions are ordered by severity (high first) for the lead's queue.

const TEAM_CONDITIONS = [
  {
    key: 'team_stressed',
    severity: 'high',
    label: 'Team capacity strained',
    cond: (th) => th.status === 'stressed' || th.status === 'critical',
  },
  {
    key: 'sustained_overcap',
    severity: 'high',
    label: 'Sustained over-capacity',
    cond: (th) => th.ext > 0,
  },
  {
    key: 'equity',
    severity: 'medium',
    label: 'Alert distribution may be uneven',
    cond: (th) => th.score < 80,
  },
  {
    key: 'automation',
    severity: 'medium',
    label: 'Automation has spare capacity',
    cond: () => true,
  },
  {
    key: 'one_on_one',
    severity: 'low',
    label: 'Regular 1:1 cadence',
    cond: () => true,
  },
];

// All condition definitions, in display order (high severity first).
function getAll() {
  return TEAM_CONDITIONS;
}

// The subset of conditions whose predicate is currently met for the given
// team-health aggregate. The team-prompt precompute job generates a prompt for
// each of these; the read endpoint recomputes this live so the Actions tab
// always reflects current team state. A malformed th never throws — a
// predicate that errors is simply treated as inactive.
function getActive(th) {
  return TEAM_CONDITIONS.filter((c) => {
    try {
      return !!c.cond(th);
    } catch {
      return false;
    }
  });
}

// Look up a single condition by key (null if unknown).
function getByKey(key) {
  return TEAM_CONDITIONS.find((c) => c.key === key) || null;
}

module.exports = { TEAM_CONDITIONS, getAll, getActive, getByKey };
