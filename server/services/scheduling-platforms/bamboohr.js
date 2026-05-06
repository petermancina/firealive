// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduling Platform Adapter: BambooHR
// ═══════════════════════════════════════════════════════════════════════════════
//
// BambooHR is the simplest of the four real-platform integrations:
//   - Auth is HTTP Basic with the API key as username and any non-empty
//     string as password (BambooHR's documented convention is "x").
//   - Per-tenant subdomain identifies the customer instance.
//   - Base URL pattern is:
//       https://api.bamboohr.com/api/gateway.php/{subdomain}/v1/
//
// This adapter sets the pattern that the other three real-platform
// adapters (workday.js, adp.js, ukg-kronos.js) will follow with their
// own auth schemes:
//   1. Decrypted credentials and endpoint_url arrive via ctx.config.
//   2. Every outbound URL has its hostname validated against
//      HR_ALLOWED_HOSTS via validateAllowedHost() before the fetch.
//   3. fetch() uses { redirect: 'error' } to refuse cross-host redirects
//      (the same SSRF posture established in v1.0.28 for GD push).
//   4. fetch() is wrapped in a 30-second AbortController timeout so a
//      hung HR endpoint can't block the sync indefinitely.
//   5. pullAvailability returns { analysts: [...] } in the shape manual.js
//      established in commit 4. pushSchedule returns
//      { pushed, skipped, errors }.
//
// Credentials shape (Tier-1 encrypted JSON in
// scheduling_platform_config.credentials_encrypted):
//
//   { "subdomain": "acme", "apiKey": "abc123..." }
//
// The route layer (later commit) handles decryption and parses the JSON
// before calling this adapter — the adapter never touches Tier-1
// encryption directly.
//
// userId mapping:
//   BambooHR identifies employees by integer ID. The MC identifies users
//   by uuid. We match on email — BambooHR's "workEmail" field against
//   FireAlive's users.email column. Employees with no MC user are
//   skipped (not an error — could be HR-only staff outside the SOC).
//
// Availability model:
//   Each user gets a weekly availability map:
//     {
//       "monday":    [{"start":"09:00","end":"17:00"}],
//       "tuesday":   [{"start":"09:00","end":"12:00"},{"start":"13:00","end":"17:00"}],
//       ...
//     }
//   Default work week is Mon-Fri 09:00-17:00. Time-off entries from
//   BambooHR's whos_out endpoint subtract from the default. Holidays
//   and approved leave both come through whos_out, so this single
//   query handles both.
//
// pushSchedule for BambooHR:
//   BambooHR does not expose a write target that fits "schedule an
//   analyst for an upskilling block at a specific time." The closest
//   endpoints (training/record, time_off/request) are wrong domains
//   for this use case. So this adapter's pushSchedule is a logging
//   no-op that returns { pushed: 0, skipped: list.length, errors: 0 }
//   with a structured warn line. The MC's own DB remains the system
//   of record for upskilling assignments; analysts see them in their
//   FireAlive AC. (Workday, ADP, and UKG do support a write target
//   and their pushSchedule implementations are real.)
// ═══════════════════════════════════════════════════════════════════════════════

const { validateAllowedHost } = require('../hr-allow-list');

const FETCH_TIMEOUT_MS = 30_000;
const DEFAULT_WORK_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const DEFAULT_DAY_START = '09:00';
const DEFAULT_DAY_END = '17:00';

/**
 * Build the BambooHR Basic Auth header from the API key.
 * BambooHR convention: username = apiKey, password = "x".
 *
 * @param {string} apiKey
 * @returns {string} value for the Authorization header
 */
function buildAuthHeader(apiKey) {
  const token = Buffer.from(`${apiKey}:x`, 'utf8').toString('base64');
  return `Basic ${token}`;
}

/**
 * fetch wrapper with timeout and SSRF guards.
 *
 * @param {string} url
 * @param {object} init
 * @returns {Promise<Response>}
 * @throws on timeout, on disallowed hostname, on non-2xx, or on
 *         redirect attempts (redirect: 'error').
 */
async function safeFetch(url, init) {
  const parsed = new URL(url);
  const guard = validateAllowedHost(parsed.hostname);
  if (!guard.ok) {
    throw new Error(`BambooHR fetch blocked: ${guard.error}`);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...init,
      redirect: 'error',
      signal: ctrl.signal,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`BambooHR ${parsed.pathname} returned ${res.status}: ${body.slice(0, 200)}`);
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Compute Monday-of-week as YYYY-MM-DD for a given Date (UTC).
 * Used to bucket per-user weekly availability rows.
 */
function isoMondayUtc(date) {
  const d = new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
  ));
  // getUTCDay: Sun=0, Mon=1, ..., Sat=6. We want Monday.
  const dow = d.getUTCDay();
  const offsetToMonday = dow === 0 ? -6 : 1 - dow;
  d.setUTCDate(d.getUTCDate() + offsetToMonday);
  return d.toISOString().slice(0, 10);
}

/**
 * Compute YYYY-MM-DD for Sunday at the end of that same week.
 */
function isoSundayUtc(mondayIso) {
  const d = new Date(`${mondayIso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 6);
  return d.toISOString().slice(0, 10);
}

/**
 * Build the default-availability slots map (Mon-Fri, 09:00-17:00).
 */
function defaultSlots() {
  const slots = {};
  for (const day of DEFAULT_WORK_DAYS) {
    slots[day] = [{ start: DEFAULT_DAY_START, end: DEFAULT_DAY_END }];
  }
  return slots;
}

/**
 * Subtract a full-day time-off block from a slots map by clearing the
 * affected day. BambooHR whos_out returns date ranges; we treat each
 * day in the range as a full-day off-block. (Partial-day handling is a
 * later refinement; for v1.0.29 a day-off either zeros the day or it
 * doesn't.)
 */
function applyDayOff(slots, dayOfWeek) {
  if (DEFAULT_WORK_DAYS.includes(dayOfWeek)) {
    slots[dayOfWeek] = [];
  }
}

/**
 * Convert a date (YYYY-MM-DD) to lowercase day-of-week name.
 */
function dayName(iso) {
  const d = new Date(`${iso}T00:00:00Z`);
  return ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'][d.getUTCDay()];
}

/**
 * Pull weekly availability from BambooHR.
 *
 * @param {object} ctx
 * @param {import('better-sqlite3').Database} ctx.db
 * @param {(level: string, msg: string, meta?: object) => void} ctx.log
 * @param {{endpoint_url: string, credentials: {subdomain: string, apiKey: string}}} ctx.config
 * @param {Date} [ctx.weekOf] — optional, defaults to today
 * @returns {Promise<{analysts: Array<{userId: string, weekStart: string, slots: object}>}>}
 */
async function pullAvailability({ db, log, config, weekOf }) {
  const subdomain = config && config.credentials && config.credentials.subdomain;
  const apiKey = config && config.credentials && config.credentials.apiKey;
  if (!subdomain || !apiKey) {
    throw new Error('BambooHR adapter: credentials.subdomain and credentials.apiKey required');
  }

  const base = (config.endpoint_url || `https://api.bamboohr.com/api/gateway.php/${subdomain}/v1`)
    .replace(/\/+$/, '');
  const headers = {
    Authorization: buildAuthHeader(apiKey),
    Accept: 'application/json',
  };

  const weekStart = isoMondayUtc(weekOf instanceof Date ? weekOf : new Date());
  const weekEnd = isoSundayUtc(weekStart);

  log('info', 'bamboohr_adapter.pull_availability.start', {
    platform: 'bamboohr',
    weekStart,
    weekEnd,
  });

  // 1. Pull employee directory (id, workEmail).
  const dirRes = await safeFetch(`${base}/employees/directory`, { headers });
  const dirJson = await dirRes.json();
  const employees = Array.isArray(dirJson && dirJson.employees) ? dirJson.employees : [];

  // 2. Pull who's out for the target week.
  const whosOutRes = await safeFetch(
    `${base}/time_off/whos_out/?start=${weekStart}&end=${weekEnd}`,
    { headers },
  );
  const whosOut = await whosOutRes.json();
  const offBlocks = Array.isArray(whosOut) ? whosOut : [];

  // 3. Map BambooHR employees to MC users by email. Skip employees
  //    not present in the MC users table — could be HR-only staff
  //    outside the SOC and not an error condition.
  const userByEmail = new Map();
  const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
  for (const r of userRows) {
    if (r.email) userByEmail.set(r.email.toLowerCase(), r.id);
  }

  const analysts = [];
  let mappedCount = 0;
  let unmappedCount = 0;
  for (const emp of employees) {
    const email = (emp.workEmail || '').toLowerCase();
    if (!email) { unmappedCount++; continue; }
    const mcUserId = userByEmail.get(email);
    if (!mcUserId) { unmappedCount++; continue; }

    const slots = defaultSlots();
    for (const block of offBlocks) {
      // BambooHR whos_out shape: { type: 'timeOff'|'holiday', employeeId, name, start, end }
      // Per-employee blocks have employeeId; holidays apply to everyone (no employeeId).
      const matchesEmployee = !block.employeeId || String(block.employeeId) === String(emp.id);
      if (!matchesEmployee) continue;
      // Walk every day in the [start, end] inclusive range that falls in this week.
      const start = block.start || block.startDate;
      const end = block.end || block.endDate || start;
      if (!start) continue;
      let cur = new Date(`${start}T00:00:00Z`);
      const stopAt = new Date(`${end}T00:00:00Z`);
      const weekStartD = new Date(`${weekStart}T00:00:00Z`);
      const weekEndD = new Date(`${weekEnd}T00:00:00Z`);
      while (cur <= stopAt) {
        if (cur >= weekStartD && cur <= weekEndD) {
          applyDayOff(slots, dayName(cur.toISOString().slice(0, 10)));
        }
        cur.setUTCDate(cur.getUTCDate() + 1);
      }
    }

    analysts.push({ userId: mcUserId, weekStart, slots });
    mappedCount++;
  }

  log('info', 'bamboohr_adapter.pull_availability.done', {
    platform: 'bamboohr',
    weekStart,
    employeesReturned: employees.length,
    mapped: mappedCount,
    unmapped: unmappedCount,
    offBlocks: offBlocks.length,
  });

  return { analysts };
}

/**
 * BambooHR has no write target that fits "schedule an analyst for an
 * upskilling block at a specific time." This is logged and treated as
 * a no-op; the MC's own DB stays the system of record for upskilling
 * assignments. Workday, ADP, and UKG adapters implement a real push.
 *
 * @param {object} ctx
 * @returns {Promise<{pushed: number, skipped: number, errors: number}>}
 */
async function pushSchedule({ log, assignments }) {
  const list = Array.isArray(assignments) ? assignments : [];
  log('warn', 'bamboohr_adapter.push_schedule.unsupported', {
    platform: 'bamboohr',
    note: 'BambooHR has no write target for upskilling schedule events; assignments remain in FireAlive only',
    skipped: list.length,
  });
  return { pushed: 0, skipped: list.length, errors: 0 };
}

module.exports = { pullAvailability, pushSchedule };
