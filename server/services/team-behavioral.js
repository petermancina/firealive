// FireAlive v1.0.56 — Team Behavioral Aggregate (de-identified, k-anonymized)
//
// The BEHAVIORAL half of the team view, the counterpart to team-health.js
// (which is the operational PRESSURE half). team-health.js summarizes the
// workload applied to the team; this module summarizes the team's behavioral
// response — but only ever as an all-team aggregate, never a per-analyst value.
//
// It reads ONLY analyst_metrics_deidentified, the de-identified behavioral
// store the collector writes: one row per behavioral signal per analyst per
// collection cycle, tagged by SOC tier and shift but carrying NO analyst
// identity. The collector deliberately leaves that table without an identity
// column and notes that small groups are "suppressed by k-anonymity
// downstream"; this module is that downstream enforcement.
//
// Two protections make the aggregate safe to surface to leads:
//
//   1. k-anonymity. A signal's team mean is published only if at least k
//      distinct analysts contributed to it; otherwise it is suppressed
//      entirely. With fewer than k contributors the "team" number would BE an
//      individual's value. k is system-determined and scales up with the size
//      of the (stable) enrolled analyst population — a larger crowd permits a
//      larger anonymity set — with an absolute floor of 3. It is never lowered
//      by configuration: an operator may only raise it (stricter), never below
//      what the system computes or below 3, so it cannot become a
//      de-anonymization dial.
//
//   2. Smoothing. The aggregate is averaged over a trailing 24-hour window
//      rather than the latest collection cycle. Burnout is a slow, chronic
//      condition, so a multi-shift trend is both more meaningful and far
//      steadier than an instantaneous reading; it also blunts differencing
//      across consecutive reads (each read overlaps heavily and each person's
//      contribution is diluted across many cycles).
//
// Counting contributors without an identity column: within one collection
// cycle the collector writes exactly one row per signal per analyst, so the
// number of rows for a signal in a single cycle equals the number of
// contributing analysts that cycle. Over the 24h window the distinct
// contributors is at least the largest single-cycle count, so we take that
// maximum per-cycle count as a conservative cohort floor and suppress a signal
// unless its best cycle cleared k. The estimate can only under-count the true
// crowd, which can only over-suppress — never under-suppress — so it fails safe
// for privacy.
//
// The aggregate returns factual team means only. It does not classify a mean as
// healthy or unhealthy (the normative bands live on the analyst's device, by
// design) and never exposes per-analyst values or exact contributor counts.

const WINDOW_HOURS = 24;
const MIN_COHORT_FLOOR = 3; // absolute floor; matches tripwire-detector min cohort

// Display metadata for the five behavioral signals. `dir` is the direction in
// which a higher team mean indicates more strain ('up') or less strain
// ('down'); presentation layers use it. The aggregate value itself is the raw
// team mean — interpretation is left to the consumer.
const BEHAVIORAL_META = {
  dismissRate: { label: 'Dismiss rate', dir: 'up' },
  ticketQuality: { label: 'Ticket quality', dir: 'down' },
  investigationTime: { label: 'Investigation time', dir: 'up' },
  escalationRate: { label: 'Escalation rate', dir: 'up' },
  break_compliance: { label: 'Break compliance', dir: 'down' },
};
const BEHAVIORAL_ORDER = [
  'dismissRate',
  'ticketQuality',
  'investigationTime',
  'escalationRate',
  'break_compliance',
];

// System-determined minimum cohort. Scales with the stable enrolled analyst
// population (not the live on-shift roster, which would jitter and invite
// differencing). Coarse buckets: <=10 -> 3, 11-30 -> 5, 31+ -> 10.
function bucketForHeadcount(enrolled) {
  if (enrolled >= 31) return 10;
  if (enrolled >= 11) return 5;
  return MIN_COHORT_FLOOR;
}

// Effective k. Upward-only: an operator may raise the floor via the
// team_aggregate_min_cohort config key but can never push k below the
// system-computed bucket or below the hard floor of 3.
function resolveMinCohort(db) {
  let enrolled = 0;
  try {
    const r = db
      .prepare(
        "SELECT COUNT(*) AS n FROM users WHERE role='analyst' AND active=1 " +
          "AND id IN (SELECT analyst_id FROM analyst_keys WHERE status='active')"
      )
      .get();
    enrolled = (r && r.n) || 0;
  } catch {
    enrolled = 0;
  }
  let override = 0;
  try {
    const r = db.prepare("SELECT value FROM config WHERE key='team_aggregate_min_cohort'").get();
    const parsed = r ? parseInt(r.value, 10) : 0;
    if (Number.isFinite(parsed)) override = parsed;
  } catch {
    override = 0;
  }
  return Math.max(MIN_COHORT_FLOOR, bucketForHeadcount(enrolled), override);
}

// Compute the de-identified, k-anonymized, 24h-smoothed team behavioral
// aggregate. Returns:
//   { k, windowHours, asOf, available, suppressed,
//     signals: [{ signal, label, dir, mean }] }
// asOf is the most recent contributing cycle; suppressed counts signals that
// had data in the window but did not clear k. Never throws — a missing or empty
// store yields an empty, unavailable aggregate.
function computeTeamBehavioral(db) {
  const k = resolveMinCohort(db);
  const base = {
    k,
    windowHours: WINDOW_HOURS,
    asOf: null,
    available: false,
    suppressed: 0,
    signals: [],
  };

  let rows = [];
  try {
    // Per (signal, cycle) headcount and value sum over the trailing window. A
    // collection cycle shares one recorded_at, so grouping by recorded_at gives
    // per-cycle contributor counts.
    rows = db
      .prepare(
        'SELECT signal, recorded_at, COUNT(*) AS c, SUM(value) AS s ' +
          'FROM analyst_metrics_deidentified ' +
          "WHERE recorded_at >= datetime('now','-" +
          WINDOW_HOURS +
          " hours') " +
          'GROUP BY signal, recorded_at'
      )
      .all();
  } catch {
    return base;
  }
  if (!rows.length) return base;

  // Fold per-cycle rows into per-signal totals: window mean = sum(value)/count;
  // cohort = max per-cycle contributor count (a conservative distinct-
  // contributor lower bound).
  const agg = {};
  let asOf = null;
  for (const r of rows) {
    const a = agg[r.signal] || (agg[r.signal] = { count: 0, sum: 0, cohort: 0 });
    a.count += r.c;
    a.sum += r.s;
    if (r.c > a.cohort) a.cohort = r.c;
    if (asOf === null || r.recorded_at > asOf) asOf = r.recorded_at;
  }

  const signals = [];
  let suppressed = 0;
  for (const key of BEHAVIORAL_ORDER) {
    const a = agg[key];
    if (!a || a.count === 0) continue; // no data this window -> omit silently
    if (a.cohort < k) {
      suppressed++; // had data, but the crowd was too small -> suppress
      continue;
    }
    const meta = BEHAVIORAL_META[key];
    signals.push({
      signal: key,
      label: meta.label,
      dir: meta.dir,
      mean: Math.round((a.sum / a.count) * 10) / 10,
    });
  }

  return {
    k,
    windowHours: WINDOW_HOURS,
    asOf,
    available: signals.length > 0,
    suppressed,
    signals,
  };
}

module.exports = { computeTeamBehavioral, WINDOW_HOURS, MIN_COHORT_FLOOR };
