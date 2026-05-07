// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduling Platform Adapter: Workday
// ═══════════════════════════════════════════════════════════════════════════════
//
// Workday is the second-most-common HR platform in enterprise SOCs (after
// UKG/Kronos). Unlike BambooHR's static API key, Workday uses OAuth 2.0
// with refresh tokens and short-lived access tokens (typically 5-15
// minutes). Workday also has a real write target — calendar events on
// each worker's Workday calendar — so this adapter's pushSchedule
// actually posts events back, where BambooHR's was a no-op.
//
// Tenant URL pattern is per-customer; production looks like
// https://{tenant}.workday.com and the sandbox looks like
// https://wd{N}-impl-services1.workday.com (where N is a small integer
// assigned by Workday). The customer provides the full base URL via
// scheduling_platform_config.endpoint_url; this adapter appends
// well-known path suffixes (e.g., /ccx/oauth2/token,
// /ccx/api/staffing/v6/workers).
//
// Credentials shape (Tier-1 encrypted JSON in
// scheduling_platform_config.credentials_encrypted):
//
//   {
//     "tenantUrl":     "https://acme.workday.com",
//     "clientId":      "...",
//     "clientSecret":  "...",
//     "refreshToken":  "..."
//   }
//
// The route layer decrypts and parses the JSON before calling this
// adapter — the adapter never touches Tier-1 encryption directly.
//
// Note that endpoint_url and credentials.tenantUrl carry overlapping
// information (the base URL for this tenant). Both are stored because
// some Workday deployments route OAuth token requests to a different
// host than data calls. If credentials.tenantUrl is set it wins for
// the token endpoint; endpoint_url is used for data endpoints. This
// matches Workday's documented "OAuth flows" guidance.
//
// Token lifecycle:
//   We refresh the access_token at the start of each adapter call and
//   use it throughout that call. No persistent caching across calls.
//   This is slightly less efficient than a token cache but avoids
//   stale-token bugs when the sync interval is longer than the access
//   token lifetime (which it typically is — sync_interval_minutes
//   defaults to 60, access tokens often expire at 15).
//
// userId mapping:
//   Workday workers have a primaryWorkEmail field. We match against
//   FireAlive's users.email column (case-insensitive). Workers without
//   an MC user are skipped silently — they're HR-only staff outside
//   the SOC, not an error condition.
//
// Availability model:
//   Default Mon-Fri 09:00-17:00, same as the BambooHR adapter. Workday
//   exposes per-worker timeOffEvents with start/end timestamps; we
//   subtract those from the default. Partial-day handling is a later
//   refinement; v1.0.29 treats every off block as a full day.
//
// pushSchedule:
//   Real implementation. POSTs a calendar event per assignment to the
//   worker's Workday calendar via /timeTracking/v1/workers/{id}/calendarEvents.
//   Returns counts of pushed (2xx), skipped (worker not found), and
//   errors (non-2xx response from Workday).
// ═══════════════════════════════════════════════════════════════════════════════

const { validateAllowedHost } = require('../hr-allow-list');

const FETCH_TIMEOUT_MS = 30_000;
const DEFAULT_WORK_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const DEFAULT_DAY_START = '09:00';
const DEFAULT_DAY_END = '17:00';

/**
 * fetch wrapper with timeout and SSRF guards. Identical contract to
 * bamboohr.js's safeFetch — kept locally to each adapter so each one
 * can evolve independently. Future refactor candidate: hoist into a
 * shared scheduling-platforms/_safe-fetch.js module if more than two
 * adapters need divergent timeouts or retry behavior.
 *
 * @param {string} url
 * @param {object} init
 * @returns {Promise<Response>}
 */
async function safeFetch(url, init) {
  const parsed = new URL(url);
  const guard = validateAllowedHost(parsed.hostname);
  if (!guard.ok) {
    throw new Error(`Workday fetch blocked: ${guard.error}`);
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
      throw new Error(`Workday ${parsed.pathname} returned ${res.status}: ${body.slice(0, 200)}`);
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Exchange a refresh_token for a fresh access_token.
 * Workday's OAuth token endpoint is POST {tenantUrl}/ccx/oauth2/token
 * with form-encoded grant_type=refresh_token. Returns { access_token,
 * token_type, expires_in } and Workday usually rotates the refresh
 * token on each refresh — but we don't persist the rotation here
 * because that requires writing back to the credentials_encrypted blob,
 * which is the route layer's responsibility.
 *
 * @param {{tenantUrl: string, clientId: string, clientSecret: string, refreshToken: string}} creds
 * @returns {Promise<string>} access_token
 */
async function refreshAccessToken(creds) {
  const tokenUrl = `${creds.tenantUrl.replace(/\/+$/, '')}/ccx/oauth2/token`;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: creds.refreshToken,
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
  });
  const res = await safeFetch(tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: body.toString(),
  });
  const json = await res.json();
  if (!json || !json.access_token) {
    throw new Error('Workday token endpoint returned no access_token');
  }
  return json.access_token;
}

function isoMondayUtc(date) {
  const d = new Date(Date.UTC(
    date.getUTCFullYear(),
    date.getUTCMonth(),
    date.getUTCDate(),
  ));
  const dow = d.getUTCDay();
  const offsetToMonday = dow === 0 ? -6 : 1 - dow;
  d.setUTCDate(d.getUTCDate() + offsetToMonday);
  return d.toISOString().slice(0, 10);
}

function isoSundayUtc(mondayIso) {
  const d = new Date(`${mondayIso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 6);
  return d.toISOString().slice(0, 10);
}

function defaultSlots() {
  const slots = {};
  for (const day of DEFAULT_WORK_DAYS) {
    slots[day] = [{ start: DEFAULT_DAY_START, end: DEFAULT_DAY_END }];
  }
  return slots;
}

function applyDayOff(slots, dayOfWeek) {
  if (DEFAULT_WORK_DAYS.includes(dayOfWeek)) {
    slots[dayOfWeek] = [];
  }
}

function dayName(iso) {
  const d = new Date(`${iso}T00:00:00Z`);
  return ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'][d.getUTCDay()];
}

/**
 * Pull weekly availability from Workday.
 *
 * @param {object} ctx
 * @param {import('better-sqlite3').Database} ctx.db
 * @param {(level: string, msg: string, meta?: object) => void} ctx.log
 * @param {{endpoint_url: string, credentials: {tenantUrl: string, clientId: string, clientSecret: string, refreshToken: string}}} ctx.config
 * @param {Date} [ctx.weekOf]
 * @returns {Promise<{analysts: Array<{userId: string, weekStart: string, slots: object}>}>}
 */
async function pullAvailability({ db, log, config, weekOf }) {
  const creds = config && config.credentials;
  if (!creds || !creds.tenantUrl || !creds.clientId || !creds.clientSecret || !creds.refreshToken) {
    throw new Error('Workday adapter: credentials require tenantUrl, clientId, clientSecret, refreshToken');
  }

  const dataBase = (config.endpoint_url || creds.tenantUrl).replace(/\/+$/, '');
  const weekStart = isoMondayUtc(weekOf instanceof Date ? weekOf : new Date());
  const weekEnd = isoSundayUtc(weekStart);

  log('info', 'workday_adapter.pull_availability.start', {
    platform: 'workday',
    weekStart,
    weekEnd,
  });

  const accessToken = await refreshAccessToken(creds);
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
  };

  // 1. List workers. Workday's staffing v6 API: GET /ccx/api/staffing/v6/workers
  //    Pagination via offset/limit; we pull up to 200 in one shot for a
  //    typical SOC-sized tenant. Customers with >200 SOC staff can override
  //    in a later refinement.
  const workersRes = await safeFetch(`${dataBase}/ccx/api/staffing/v6/workers?limit=200`, { headers });
  const workersJson = await workersRes.json();
  const workers = Array.isArray(workersJson && workersJson.data) ? workersJson.data : [];

  // 2. Build email-to-MC-user-id map.
  const userByEmail = new Map();
  const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
  for (const r of userRows) {
    if (r.email) userByEmail.set(r.email.toLowerCase(), r.id);
  }

  // 3. For each mapped worker, query their time-off events for the target week.
  const analysts = [];
  let mappedCount = 0;
  let unmappedCount = 0;
  let timeOffFetchErrors = 0;

  for (const w of workers) {
    const email = ((w.primaryWorkEmail || w.workEmail || '') + '').toLowerCase();
    if (!email) { unmappedCount++; continue; }
    const mcUserId = userByEmail.get(email);
    if (!mcUserId) { unmappedCount++; continue; }

    const slots = defaultSlots();

    let timeOffEvents = [];
    try {
      const tofRes = await safeFetch(
        `${dataBase}/ccx/api/timeTracking/v1/workers/${encodeURIComponent(w.id)}/timeOffEvents?fromDate=${weekStart}&toDate=${weekEnd}`,
        { headers },
      );
      const tofJson = await tofRes.json();
      timeOffEvents = Array.isArray(tofJson && tofJson.data) ? tofJson.data : [];
    } catch (err) {
      timeOffFetchErrors++;
      log('warn', 'workday_adapter.pull_availability.time_off_fetch_failed', {
        platform: 'workday',
        workerId: w.id,
        error: String(err && err.message),
      });
      // Continue with default availability rather than dropping the analyst entirely.
    }

    for (const ev of timeOffEvents) {
      const start = (ev.start || ev.startDate || '').slice(0, 10);
      const end = (ev.end || ev.endDate || start).slice(0, 10);
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

  log('info', 'workday_adapter.pull_availability.done', {
    platform: 'workday',
    weekStart,
    workersReturned: workers.length,
    mapped: mappedCount,
    unmapped: unmappedCount,
    timeOffFetchErrors,
  });

  return { analysts };
}

/**
 * Push upskilling assignments to Workday as calendar events.
 *
 * Each assignment becomes a POST to
 *   /ccx/api/timeTracking/v1/workers/{workerId}/calendarEvents
 * with a JSON body describing the event title, start, and end. Workday
 * expects ISO 8601 datetimes; assignments arrive with day + slot
 * (e.g., {weekStart: "2026-05-04", slot: "tuesday-14:00-15:00"}) and
 * are converted here.
 *
 * @param {object} ctx
 * @param {import('better-sqlite3').Database} ctx.db
 * @param {(level: string, msg: string, meta?: object) => void} ctx.log
 * @param {object} ctx.config
 * @param {Array<{userId: string, weekStart: string, slot: string, kind: string}>} ctx.assignments
 * @returns {Promise<{pushed: number, skipped: number, errors: number}>}
 */
async function pushSchedule({ db, log, config, assignments }) {
  const list = Array.isArray(assignments) ? assignments : [];
  log('info', 'workday_adapter.push_schedule.start', {
    platform: 'workday',
    assignments: list.length,
  });

  if (list.length === 0) {
    log('info', 'workday_adapter.push_schedule.done', {
      platform: 'workday', pushed: 0, skipped: 0, errors: 0,
    });
    return { pushed: 0, skipped: 0, errors: 0 };
  }

  const creds = config && config.credentials;
  if (!creds || !creds.tenantUrl || !creds.clientId || !creds.clientSecret || !creds.refreshToken) {
    throw new Error('Workday adapter: credentials require tenantUrl, clientId, clientSecret, refreshToken');
  }
  const dataBase = (config.endpoint_url || creds.tenantUrl).replace(/\/+$/, '');

  const accessToken = await refreshAccessToken(creds);
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };

  // Map MC user IDs → Workday worker IDs by email lookup. Build the
  // map once at the start of the push so we don't re-query per
  // assignment.
  const userById = new Map();
  const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
  for (const r of userRows) {
    if (r.id) userById.set(r.id, (r.email || '').toLowerCase());
  }
  const workersRes = await safeFetch(`${dataBase}/ccx/api/staffing/v6/workers?limit=200`, { headers });
  const workersJson = await workersRes.json();
  const workers = Array.isArray(workersJson && workersJson.data) ? workersJson.data : [];
  const workerByEmail = new Map();
  for (const w of workers) {
    const e = ((w.primaryWorkEmail || w.workEmail || '') + '').toLowerCase();
    if (e) workerByEmail.set(e, w.id);
  }

  let pushed = 0;
  let skipped = 0;
  let errors = 0;

  for (const a of list) {
    const email = userById.get(a.userId);
    const workerId = email ? workerByEmail.get(email) : null;
    if (!workerId) {
      skipped++;
      log('warn', 'workday_adapter.push_schedule.no_worker', {
        platform: 'workday', userId: a.userId,
      });
      continue;
    }

    // Convert {weekStart: "YYYY-MM-DD", slot: "tuesday-14:00-15:00"} to ISO datetimes.
    const slotMatch = /^([a-z]+)-(\d{2}:\d{2})-(\d{2}:\d{2})$/.exec(String(a.slot || ''));
    if (!slotMatch) {
      skipped++;
      log('warn', 'workday_adapter.push_schedule.bad_slot', {
        platform: 'workday', userId: a.userId, slot: a.slot,
      });
      continue;
    }
    const dayIndex = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'].indexOf(slotMatch[1]);
    if (dayIndex < 0) {
      skipped++;
      continue;
    }
    const eventDate = new Date(`${a.weekStart}T00:00:00Z`);
    eventDate.setUTCDate(eventDate.getUTCDate() + dayIndex);
    const dateIso = eventDate.toISOString().slice(0, 10);
    const startIso = `${dateIso}T${slotMatch[2]}:00Z`;
    const endIso = `${dateIso}T${slotMatch[3]}:00Z`;

    const eventBody = {
      title: `FireAlive: ${a.kind || 'upskilling'}`,
      description: 'Scheduled upskilling block — managed by FireAlive',
      start: startIso,
      end: endIso,
      category: 'training',
    };

    try {
      await safeFetch(
        `${dataBase}/ccx/api/timeTracking/v1/workers/${encodeURIComponent(workerId)}/calendarEvents`,
        { method: 'POST', headers, body: JSON.stringify(eventBody) },
      );
      pushed++;
    } catch (err) {
      errors++;
      log('warn', 'workday_adapter.push_schedule.event_post_failed', {
        platform: 'workday', userId: a.userId, workerId, error: String(err && err.message),
      });
    }
  }

  log('info', 'workday_adapter.push_schedule.done', {
    platform: 'workday', pushed, skipped, errors,
  });

  return { pushed, skipped, errors };
}

module.exports = { pullAvailability, pushSchedule };
