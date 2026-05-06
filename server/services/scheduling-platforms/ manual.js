// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduling Platform Adapter: Manual mode
// ═══════════════════════════════════════════════════════════════════════════════
//
// The "Manual" platform is the no-external-system mode. FireAlive itself
// is the system of record for analyst work schedules — the lead enters
// each analyst's weekly hours directly into the MC's Per-Analyst
// Scheduling card, and no outbound HTTP traffic occurs.
//
// Manual mode exists for three customer scenarios:
//   1. Small teams (<5 analysts) where standing up a Workday/UKG/ADP
//      service account is operationally heavier than the value it adds.
//   2. Self-hosted SOCs that don't run a commercial HRIS.
//   3. Customers who want to evaluate the upskilling-scheduling feature
//      without first integrating with their HR platform.
//
// Adapter contract (shared with the four real-platform adapters):
//
//   pullAvailability({ db, log }) -> Promise<{ analysts: [{userId, weekStart, slots}] }>
//
//     Refresh per-analyst availability from the source of truth. For
//     manual mode the source of truth is the MC's own analyst_availability
//     table (which the lead writes via the Save All button). pullAvailability
//     is therefore a no-op in terms of *changing* anything, but it still
//     returns the current availability so the calling sync routine has a
//     consistent return shape across all platforms.
//
//   pushSchedule({ db, log, assignments }) -> Promise<{ pushed, skipped, errors }>
//
//     Send newly-assigned upskilling events back to the source of truth.
//     For manual mode this is also a no-op — the assignments are already
//     stored in FireAlive's own DB by the auto-assigner, so there's
//     nothing to push externally. Returns counts so the sync log line
//     reads identically to the real-platform adapters.
//
// The other four adapters (ukg-kronos.js, workday.js, adp.js, bamboohr.js)
// implement the same two functions but with real HTTP calls behind a
// hostname check via validateAllowedHost() from ../hr-allow-list.js.
// Manual mode never goes outbound, so it skips the allow-list check —
// there's no hostname to validate.
//
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Manual-mode availability pull. No external system; the MC's own
 * analyst_availability table is the source of truth. Returns the
 * current availability so the calling sync routine can log it and
 * the response shape is consistent with real-platform adapters.
 *
 * @param {object} ctx
 * @param {import('better-sqlite3').Database} ctx.db   — MC database handle
 * @param {(level: string, msg: string, meta?: object) => void} ctx.log
 *   — structured log function provided by the caller (the sync service)
 * @returns {Promise<{analysts: Array<{userId: string, weekStart: string, slots: object}>}>}
 */
async function pullAvailability({ db, log }) {
  log('info', 'manual_adapter.pull_availability.start', { platform: 'manual' });

  // analyst_availability is added in a later commit (server/db/init.js
  // schema migration). Until that ships, this query may return zero rows
  // on a fresh install. The empty-array return shape is intentional —
  // callers must tolerate it.
  let rows = [];
  try {
    rows = db.prepare(`
      SELECT user_id AS userId, week_start AS weekStart, slots_json AS slots
      FROM analyst_availability
      ORDER BY week_start DESC, user_id ASC
    `).all();
  } catch (err) {
    // Table may not exist yet on a build prior to the analyst_availability
    // migration commit. That's fine — manual mode is operational once the
    // table lands; before then it returns an empty list and logs the
    // condition without throwing.
    if (/no such table/i.test(String(err && err.message))) {
      log('warn', 'manual_adapter.pull_availability.table_missing', {
        table: 'analyst_availability',
        note: 'returning empty availability; analyst_availability table not yet migrated',
      });
      rows = [];
    } else {
      throw err;
    }
  }

  const analysts = rows.map(r => {
    let slots;
    try {
      slots = r.slots ? JSON.parse(r.slots) : {};
    } catch {
      slots = {};
    }
    return { userId: r.userId, weekStart: r.weekStart, slots };
  });

  log('info', 'manual_adapter.pull_availability.done', {
    platform: 'manual',
    analystsReturned: analysts.length,
  });

  return { analysts };
}

/**
 * Manual-mode schedule push. No external system to call — the upskilling
 * assignments are already in FireAlive's own DB. Returns success counts
 * so the sync log line reads identically to the real-platform adapters.
 *
 * @param {object} ctx
 * @param {import('better-sqlite3').Database} ctx.db
 * @param {(level: string, msg: string, meta?: object) => void} ctx.log
 * @param {Array<{userId: string, weekStart: string, slot: string, kind: string}>} ctx.assignments
 *   — newly-assigned upskilling events the auto-assigner wants pushed.
 *     Manual mode acknowledges them as already-stored locally.
 * @returns {Promise<{pushed: number, skipped: number, errors: number}>}
 */
async function pushSchedule({ db, log, assignments }) {
  const list = Array.isArray(assignments) ? assignments : [];
  log('info', 'manual_adapter.push_schedule.start', {
    platform: 'manual',
    assignments: list.length,
  });

  // Manual mode has no outbound action. Every assignment is acknowledged
  // because it is already persisted in the MC's own DB by the time the
  // sync routine calls this adapter.
  const result = { pushed: list.length, skipped: 0, errors: 0 };

  log('info', 'manual_adapter.push_schedule.done', {
    platform: 'manual',
    ...result,
  });

  return result;
}

module.exports = { pullAvailability, pushSchedule };
