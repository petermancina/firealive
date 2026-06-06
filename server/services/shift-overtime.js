// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Shift Overtime (Phase B5d1-F)
//
// Computes the per-analyst `shift_overtime` PRESSURE signal and writes it to the
// `config['overtime_<analyst_id>']` cache that the signal collector
// (`_getOvertime`) and `team-health.js` both read. Run as a pre-step at the top
// of the collector's collectAll cycle, so both readers get a fresh value with no
// separate scheduled job.
//
// DEFINITION (KB-grounded; see research-kb N004 "burned-out responders worked
// more than 40 hours per week" + after-hours activity, R017 hours-on-shift, and
// R015/N007 shift-work-is-baseline):
//
//   shift_overtime = max(0, (scheduled_weekly_hours + after_hours_this_week)
//                            - full_time_threshold)
//
//   - scheduled_weekly_hours: the sum of the analyst's current-week roster slot
//     DURATIONS (analyst_availability.slots_json). Duration-based, so it is
//     timezone-free and shift-agnostic (a 4x10 night-shifter sums to 40 -> 0; an
//     extra night -> 10 over).
//   - after_hours_this_week: actual work past the scheduled shift end, SEEN in
//     ticket_actions (not inferred). For each scheduled shift instance this week,
//     the analyst's last activity past the shift end counts as after-hours.
//   - full_time_threshold: config['overtime_full_time_hours'] (default 40). The
//     absolute >40 hr/week marker the literature uses; a part-timer under 40 reads 0.
//
// TIMEZONE. The roster stores LOCAL wall-clock times (no per-row tz); ticket
// activity is stored in UTC. To compare "activity past the scheduled end" we put
// both in UTC: each scheduled shift-end (local) is converted to UTC using
// config['soc_timezone'] (IANA, default 'UTC') -- one timezone per Regional
// Server, which matches the per-region GD/CISO rollup. Activity stays UTC-stored
// and standardized. Per-employee tz from the HR adapters is the documented
// upgrade for a region that spans multiple zones. Conversion uses Node's built-in
// Intl (no library) and is DST-aware via a refine pass.
//
// NIGHT SHIFTS / SPLIT SLOTS. Slot validation enforces start<end per slot, so an
// overnight shift is stored split across two day keys at midnight (e.g. Mon
// 22:00-23:59 + Tue 00:00-06:00). buildShiftInstances merges slots separated by a
// short gap (lunch break, or the midnight boundary) into a single contiguous
// shift instance, so the shift's true end (e.g. Tue 06:00) is used and the
// scheduled AM half is never miscounted as after-hours.
//
// EARLY LEAVERS. The scheduled component is NOT reduced for someone who leaves
// early (the schedule is the commitment; activity-based subtraction is
// unreliable -- non-ticket work like meetings would undercount -- and erring
// toward flagging is the safe direction for a protective signal). The after-hours
// component is inherently activity-based, so it reads 0 for an early departure.
// ═══════════════════════════════════════════════════════════════════════════════

// day-of-week keys indexed to match JS Date.getUTCDay() (0 = Sunday)
const DAY_KEYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

const DEFAULT_FULL_TIME_HOURS = 40;
// Slots within one shift are separated by short gaps (a lunch break, or the
// ~1-minute midnight boundary of a split overnight shift). Distinct shifts on
// different days are separated by many hours. 3 hours cleanly bridges the former
// and separates the latter.
const MERGE_GAP_MINUTES = 180;
// How far past a shift's end activity is still attributed to that shift's tail,
// and the effective per-shift after-hours ceiling. 12 hours is generous for a
// real extension while bounding a stale-timestamp anomaly.
const AFTER_HOURS_WINDOW_HOURS = 12;

// Unix-epoch milliseconds -> Julian Day Number (UTC), to compare against SQLite
// julianday(created_at) which is also UTC-based.
function msToJulian(ms) {
  return ms / 86400000 + 2440587.5;
}

// "HH:MM" -> minutes since local midnight (allows 24:00 = 1440). null if invalid.
function hhmmToMinutes(s) {
  if (typeof s !== 'string') return null;
  const m = s.match(/^(\d{1,2}):(\d{2})$/);
  if (!m) return null;
  const h = parseInt(m[1], 10);
  const mn = parseInt(m[2], 10);
  if (h < 0 || h > 24 || mn < 0 || mn > 59) return null;
  if (h === 24 && mn !== 0) return null;
  return h * 60 + mn;
}

// Sum of slot durations across the week, in hours. Timezone-free.
function weeklyScheduledHours(slots) {
  if (!slots || typeof slots !== 'object') return 0;
  let mins = 0;
  for (const dayName of DAY_KEYS) {
    const daySlots = Array.isArray(slots[dayName]) ? slots[dayName] : [];
    for (const s of daySlots) {
      const sm = hhmmToMinutes(s && s.start);
      const em = hhmmToMinutes(s && s.end);
      if (sm == null || em == null || em <= sm) continue;
      mins += em - sm;
    }
  }
  return mins / 60;
}

// Offset (ms) of timeZone from UTC at the given UTC instant: (wall clock as UTC) - utc.
function tzOffsetMs(utcMs, timeZone) {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone, hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
  const parts = dtf.formatToParts(new Date(utcMs));
  const m = {};
  for (const p of parts) if (p.type !== 'literal') m[p.type] = p.value;
  let hour = parseInt(m.hour, 10);
  if (hour === 24) hour = 0; // some environments emit 24 for midnight
  const asUTC = Date.UTC(+m.year, +m.month - 1, +m.day, hour, +m.minute, +m.second);
  return asUTC - utcMs;
}

// The UTC instant whose wall clock in timeZone is y-mo-d hh:mm. DST-aware (refine).
function localWallClockToUtc(y, mo, d, hh, mm, timeZone) {
  const guessMs = Date.UTC(y, mo - 1, d, hh, mm, 0);
  const offset = tzOffsetMs(guessMs, timeZone);
  let utcMs = guessMs - offset;
  const offset2 = tzOffsetMs(utcMs, timeZone);
  if (offset2 !== offset) utcMs = guessMs - offset2;
  const dt = new Date(utcMs);
  return isNaN(dt.getTime()) ? null : dt;
}

// week-relative absolute minutes -> UTC Date, in timeZone.
function absMinutesToUtc(weekStart, absMin, timeZone) {
  const ws = new Date(weekStart + 'T00:00:00Z');
  if (isNaN(ws.getTime())) return null;
  const dayOffset = Math.floor(absMin / 1440);
  const minuteOfDay = ((absMin % 1440) + 1440) % 1440;
  const d = new Date(ws.getTime() + dayOffset * 86400000);
  const hh = Math.floor(minuteOfDay / 60);
  const mm = minuteOfDay % 60;
  return localWallClockToUtc(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate(), hh, mm, timeZone);
}

// Merge the week's slots into contiguous shift instances; return each instance's
// start/end as UTC Dates.
function buildShiftInstances(slots, weekStart, timeZone) {
  const ws = new Date(weekStart + 'T00:00:00Z');
  if (!slots || typeof slots !== 'object' || isNaN(ws.getTime())) return [];
  const wsDow = ws.getUTCDay();

  const raw = [];
  for (let i = 0; i < DAY_KEYS.length; i++) {
    const daySlots = Array.isArray(slots[DAY_KEYS[i]]) ? slots[DAY_KEYS[i]] : [];
    const offset = (i - wsDow + 7) % 7; // days from weekStart
    for (const s of daySlots) {
      const sm = hhmmToMinutes(s && s.start);
      const em = hhmmToMinutes(s && s.end);
      if (sm == null || em == null || em <= sm) continue;
      raw.push({ startAbs: offset * 1440 + sm, endAbs: offset * 1440 + em });
    }
  }
  raw.sort((a, b) => a.startAbs - b.startAbs);

  const merged = [];
  for (const slot of raw) {
    const last = merged[merged.length - 1];
    if (last && slot.startAbs - last.endAbs <= MERGE_GAP_MINUTES) {
      if (slot.endAbs > last.endAbs) last.endAbs = slot.endAbs;
    } else {
      merged.push({ startAbs: slot.startAbs, endAbs: slot.endAbs });
    }
  }

  const instances = [];
  for (const m of merged) {
    const startUtc = absMinutesToUtc(weekStart, m.startAbs, timeZone);
    const endUtc = absMinutesToUtc(weekStart, m.endAbs, timeZone);
    if (startUtc && endUtc) instances.push({ startUtc, endUtc });
  }
  return instances;
}

// After-hours (hours) for one shift instance: the analyst's last activity past
// the shift end, within the attribution window. 0 if none / left early.
function shiftAfterHours(db, analystId, inst) {
  const startISO = inst.startUtc.toISOString();
  const endPlusWindowISO = new Date(inst.endUtc.getTime() + AFTER_HOURS_WINDOW_HOURS * 3600000).toISOString();
  const row = db.prepare(
    "SELECT MAX(julianday(created_at)) AS lastJ FROM ticket_actions " +
    "WHERE analyst_id = ? AND julianday(created_at) >= julianday(?) AND julianday(created_at) <= julianday(?)"
  ).get(analystId, startISO, endPlusWindowISO);
  if (!row || row.lastJ == null) return 0;
  const endJ = msToJulian(inst.endUtc.getTime());
  const hrs = (row.lastJ - endJ) * 24;
  if (hrs <= 0) return 0;
  return Math.min(hrs, AFTER_HOURS_WINDOW_HOURS);
}

// Overtime hours for one analyst (rounded to 0.1). Uses the most recent roster
// week. Returns 0 when no roster exists.
function computeOvertimeForAnalyst(db, analystId, fullTimeHours, timeZone) {
  const row = db.prepare(
    "SELECT week_start AS weekStart, slots_json AS slotsJson FROM analyst_availability " +
    "WHERE user_id = ? ORDER BY week_start DESC LIMIT 1"
  ).get(analystId);
  if (!row) return 0;
  let slots;
  try { slots = JSON.parse(row.slotsJson); } catch { return 0; }

  const scheduled = weeklyScheduledHours(slots);
  let afterHours = 0;
  for (const inst of buildShiftInstances(slots, row.weekStart, timeZone)) {
    afterHours += shiftAfterHours(db, analystId, inst);
  }
  const overtime = Math.max(0, scheduled + afterHours - fullTimeHours);
  return Math.round(overtime * 10) / 10;
}

// Read config, compute every active analyst's overtime, and write the
// config['overtime_<id>'] cache. Per-analyst faults are isolated.
function computeAndStoreAll(db) {
  let timeZone = 'UTC';
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'soc_timezone'").get();
    if (r && r.value) {
      // Validate the IANA zone; fall back to UTC if invalid.
      // eslint-disable-next-line no-new
      new Intl.DateTimeFormat('en-US', { timeZone: String(r.value) });
      timeZone = String(r.value);
    }
  } catch { timeZone = 'UTC'; }

  let fullTimeHours = DEFAULT_FULL_TIME_HOURS;
  try {
    const r = db.prepare("SELECT value FROM config WHERE key = 'overtime_full_time_hours'").get();
    const n = r ? Number(r.value) : NaN;
    if (Number.isFinite(n) && n > 0) fullTimeHours = n;
  } catch { /* default */ }

  const analysts = db.prepare("SELECT id FROM users WHERE role = 'analyst' AND active = 1").all();
  const write = db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)");
  let written = 0;
  for (const a of analysts) {
    try {
      const overtime = computeOvertimeForAnalyst(db, a.id, fullTimeHours, timeZone);
      write.run('overtime_' + a.id, String(overtime));
      written += 1;
    } catch { /* per-analyst fault isolation */ }
  }
  return { written, timeZone, fullTimeHours };
}

module.exports = {
  computeAndStoreAll,
  computeOvertimeForAnalyst,
  weeklyScheduledHours,
  buildShiftInstances,
  localWallClockToUtc,
  hhmmToMinutes,
};
