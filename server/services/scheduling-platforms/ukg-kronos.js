// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduling Platform Adapter: UKG / Kronos (Workforce Dimensions)
// ═══════════════════════════════════════════════════════════════════════════════
//
// UKG Workforce Dimensions (formerly Kronos Workforce Central / Workforce
// Ready) is the largest enterprise HR/scheduling platform and is the
// fourth and final real-platform adapter for R3c. UKG WFD's REST API
// uses an OAuth-like password grant (client_id + client_secret +
// username + password) plus a per-tenant US-Customer-Api-Key header.
// Access tokens are typically valid for ~1 hour.
//
// UKG WFD has a real schedule write target (scheduled_segments) that
// fits the upskilling-block use case well, so this adapter's
// pushSchedule is a real implementation matching the workday.js
// pattern. Two of the four real-platform adapters (Workday + UKG)
// have real pushSchedule; two (BambooHR + ADP) are no-op due to
// platform-side limitations documented in their respective files.
//
// Tenant URL: https://{tenant}.{region}.workforce.ukg.com
//   e.g., https://acme.us.workforce.ukg.com
//         https://acme.eu.workforce.ukg.com
//
// Credentials shape (Tier-1 encrypted JSON in
// scheduling_platform_config.credentials_encrypted):
//
//   {
//     "tenantUrl":     "https://acme.us.workforce.ukg.com",
//     "clientId":      "...",
//     "clientSecret":  "...",
//     "username":      "service-account@acme.com",
//     "password":      "...",
//     "apiKey":        "..."   // optional; if absent, US-Customer-Api-Key
//                              //   header omitted (some UKG deployments
//                              //   do not require it)
//   }
//
// Note: this is a fuller credential shape than the {tenantUrl, username,
// password} sketched in the scheduling_platform_config doc-block in
// db/init.js commit 3. The simpler shape would not authenticate against
// production UKG WFD; the route layer (later commit) will validate
// against the full shape and the init.js doc-block will be updated for
// accuracy in a docs-only commit alongside the route. The credentials
// blob is opaque to the schema (Tier-1 encrypted), so this is purely a
// contract between the adapter and the route layer — no schema change
// is required.
//
// The route layer decrypts and parses the JSON before calling this
// adapter — the adapter never touches Tier-1 encryption directly.
//
// userId mapping:
//   UKG persons carry a personEmail field (sometimes labeled
//   employeeEmail or workEmail in different UKG editions). We try
//   personEmail, then employeeEmail, then workEmail. Match against
//   FireAlive's users.email column case-insensitively. Persons
//   without an MC user are skipped silently.
//
// Availability model:
//   Default Mon-Fri 09:00-17:00. UKG WFD's
//   /api/v1/commons/schedule endpoint returns scheduled work
//   segments; we use those to identify when each person is
//   on-shift, and time-off requests subtract from the on-shift
//   window. Partial-day handling is a later refinement; v1.0.29
//   treats every full-day off as a full-day off.
//
// pushSchedule:
//   Real implementation. Each assignment becomes a segment
//   posted to /api/v1/scheduling/scheduled_segments with the
//   FireAlive label. Returns counts of pushed (2xx), skipped
//   (person not found), and errors (non-2xx response from UKG).
// ═══════════════════════════════════════════════════════════════════════════════

const { validateAllowedHost } = require('../hr-allow-list');

const FETCH_TIMEOUT_MS = 30_000;
const DEFAULT_WORK_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const DEFAULT_DAY_START = '09:00';
const DEFAULT_DAY_END = '17:00';

/**
 * fetch wrapper with timeout and SSRF guards. Local to this adapter
 * matching the bamboohr.js / workday.js / adp.js pattern.
 *
 * @param {string} url
 * @param {object} init
 * @returns {Promise<Response>}
 */
async function safeFetch(url, init) {
  const parsed = new URL(url);
  const guard = validateAllowedHost(parsed.hostname);
  if (!guard.ok) {
    throw new Error(`UKG fetch blocked: ${guard.error}`);
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
      throw new Error(`UKG ${parsed.pathname} returned ${res.status}: ${body.slice(0, 200)}`);
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Exchange username/password (with client credentials) for an access token.
 * UKG's token endpoint expects form-encoded grant_type=password and
 * the optional US-Customer-Api-Key header.
 *
 * @param {{tenantUrl: string, clientId: string, clientSecret: string, username: string, password: string, apiKey?: string}} creds
 * @returns {Promise<string>} access_token
 */
async function fetchAccessToken(creds) {
  const tokenUrl = `${creds.tenantUrl.replace(/\/+$/, '')}/api/authentication/access_token`;
  const params = new URLSearchParams({
    grant_type: 'password',
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    username: creds.username,
    password: creds.password,
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    Accept: 'application/json',
  };
  if (creds.apiKey) {
    headers['US-Customer-Api-Key'] = creds.apiKey;
  }
  const res = await safeFetch(tokenUrl, {
    method: 'POST',
    headers,
    body: params.toString(),
  });
  const json = await res.json();
  if (!json || !json.access_token) {
    throw new Error('UKG token endpoint returned no access_token');
  }
  return json.access_token;
}

/**
 * Build the standard data-call headers (Bearer + optional API key).
 */
function buildDataHeaders(accessToken, apiKey) {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
  };
  if (apiKey) headers['US-Customer-Api-Key'] = apiKey;
  return headers;
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

function extractPersonEmail(person) {
  return ((person && (person.personEmail || person.employeeEmail || person.workEmail)) || '').toLowerCase();
}

/**
 * Pull weekly availability from UKG WFD.
 *
 * @param {object} ctx
 * @returns {Promise<{analysts: Array<{userId: string, weekStart: string, slots: object}>}>}
 */
async function pullAvailability({ db, log, config, weekOf }) {
  const creds = config && config.credentials;
  if (!creds || !creds.tenantUrl || !creds.clientId || !creds.clientSecret || !creds.username || !creds.password) {
    throw new Error('UKG adapter: credentials require tenantUrl, clientId, clientSecret, username, password');
  }

  const dataBase = (config.endpoint_url || creds.tenantUrl).replace(/\/+$/, '');
  const weekStart = isoMondayUtc(weekOf instanceof Date ? weekOf : new Date());
  const weekEnd = isoSundayUtc(weekStart);

  log('info', 'ukg_adapter.pull_availability.start', {
    platform: 'ukg_kronos',
    weekStart,
    weekEnd,
  });

  const accessToken = await fetchAccessToken(creds);
  const headers = buildDataHeaders(accessToken, creds.apiKey);

  // 1. List persons.
  const personsRes = await safeFetch(
    `${dataBase}/api/commons/persons?limit=200`,
    { headers },
  );
  const personsJson = await personsRes.json();
  const persons = Array.isArray(personsJson && personsJson.persons)
    ? personsJson.persons
    : (Array.isArray(personsJson) ? personsJson : []);

  // 2. Pull time-off for the target week (one tenant-wide call, not
  //    per-person — UKG returns all approved time-off in the window).
  let timeOffRequests = [];
  try {
    const tofRes = await safeFetch(
      `${dataBase}/api/timeoff/timeoff_requests?from=${weekStart}&to=${weekEnd}&statuses=APPROVED`,
      { headers },
    );
    const tofJson = await tofRes.json();
    timeOffRequests = Array.isArray(tofJson && tofJson.timeOffRequests)
      ? tofJson.timeOffRequests
      : (Array.isArray(tofJson) ? tofJson : []);
  } catch (err) {
    log('warn', 'ukg_adapter.pull_availability.timeoff_fetch_failed', {
      platform: 'ukg_kronos',
      error: String(err && err.message),
    });
  }

  // Index time-off by personId for fast per-worker lookup.
  const timeOffByPerson = new Map();
  for (const req of timeOffRequests) {
    const pid = req.personId || req.personRef || req.employeeId;
    if (!pid) continue;
    if (!timeOffByPerson.has(pid)) timeOffByPerson.set(pid, []);
    timeOffByPerson.get(pid).push(req);
  }

  // 3. Build email-to-MC-user-id map.
  const userByEmail = new Map();
  const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
  for (const r of userRows) {
    if (r.email) userByEmail.set(r.email.toLowerCase(), r.id);
  }

  const analysts = [];
  let mappedCount = 0;
  let unmappedCount = 0;

  for (const p of persons) {
    const email = extractPersonEmail(p);
    if (!email) { unmappedCount++; continue; }
    const mcUserId = userByEmail.get(email);
    if (!mcUserId) { unmappedCount++; continue; }

    const personId = p.personId || p.id;
    const slots = defaultSlots();
    const reqs = (personId && timeOffByPerson.get(personId)) || [];

    for (const req of reqs) {
      const start = (req.startDate || req.start || '').slice(0, 10);
      const end = (req.endDate || req.end || start).slice(0, 10);
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

  log('info', 'ukg_adapter.pull_availability.done', {
    platform: 'ukg_kronos',
    weekStart,
    personsReturned: persons.length,
    mapped: mappedCount,
    unmapped: unmappedCount,
    timeOffRequests: timeOffRequests.length,
  });

  return { analysts };
}

/**
 * Push upskilling assignments to UKG as scheduled segments.
 *
 * Each assignment becomes a segment in a single batch POST to
 *   /api/scheduling/scheduled_segments
 * with the FireAlive label. UKG accepts a list in one call so we
 * batch instead of one-call-per-assignment.
 *
 * @param {object} ctx
 * @returns {Promise<{pushed: number, skipped: number, errors: number}>}
 */
async function pushSchedule({ db, log, config, assignments }) {
  const list = Array.isArray(assignments) ? assignments : [];
  log('info', 'ukg_adapter.push_schedule.start', {
    platform: 'ukg_kronos',
    assignments: list.length,
  });

  if (list.length === 0) {
    log('info', 'ukg_adapter.push_schedule.done', {
      platform: 'ukg_kronos', pushed: 0, skipped: 0, errors: 0,
    });
    return { pushed: 0, skipped: 0, errors: 0 };
  }

  const creds = config && config.credentials;
  if (!creds || !creds.tenantUrl || !creds.clientId || !creds.clientSecret || !creds.username || !creds.password) {
    throw new Error('UKG adapter: credentials require tenantUrl, clientId, clientSecret, username, password');
  }
  const dataBase = (config.endpoint_url || creds.tenantUrl).replace(/\/+$/, '');

  const accessToken = await fetchAccessToken(creds);
  const headers = {
    ...buildDataHeaders(accessToken, creds.apiKey),
    'Content-Type': 'application/json',
  };

  // Build MC-user-id → UKG personId map.
  const userById = new Map();
  const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
  for (const r of userRows) {
    if (r.id) userById.set(r.id, (r.email || '').toLowerCase());
  }
  const personsRes = await safeFetch(`${dataBase}/api/commons/persons?limit=200`, { headers });
  const personsJson = await personsRes.json();
  const persons = Array.isArray(personsJson && personsJson.persons)
    ? personsJson.persons
    : (Array.isArray(personsJson) ? personsJson : []);
  const personByEmail = new Map();
  for (const p of persons) {
    const e = extractPersonEmail(p);
    if (e) personByEmail.set(e, p.personId || p.id);
  }

  // Build the batch segments payload. Skip assignments whose user
  // doesn't map to a UKG person, with a counted log line.
  const segments = [];
  let skipped = 0;
  for (const a of list) {
    const email = userById.get(a.userId);
    const personId = email ? personByEmail.get(email) : null;
    if (!personId) {
      skipped++;
      log('warn', 'ukg_adapter.push_schedule.no_person', {
        platform: 'ukg_kronos', userId: a.userId,
      });
      continue;
    }
    const slotMatch = /^([a-z]+)-(\d{2}:\d{2})-(\d{2}:\d{2})$/.exec(String(a.slot || ''));
    if (!slotMatch) {
      skipped++;
      log('warn', 'ukg_adapter.push_schedule.bad_slot', {
        platform: 'ukg_kronos', userId: a.userId, slot: a.slot,
      });
      continue;
    }
    const dayIndex = ['monday','tuesday','wednesday','thursday','friday','saturday','sunday'].indexOf(slotMatch[1]);
    if (dayIndex < 0) { skipped++; continue; }
    const segDate = new Date(`${a.weekStart}T00:00:00Z`);
    segDate.setUTCDate(segDate.getUTCDate() + dayIndex);
    const dateIso = segDate.toISOString().slice(0, 10);
    segments.push({
      personIds: [personId],
      startDate: dateIso,
      startTime: `${slotMatch[2]}:00`,
      endDate: dateIso,
      endTime: `${slotMatch[3]}:00`,
      label: `FireAlive: ${a.kind || 'upskilling'}`,
      segmentType: 'TRAINING',
    });
  }

  if (segments.length === 0) {
    log('info', 'ukg_adapter.push_schedule.done', {
      platform: 'ukg_kronos', pushed: 0, skipped, errors: 0,
    });
    return { pushed: 0, skipped, errors: 0 };
  }

  // POST in one batch.
  let pushed = 0;
  let errors = 0;
  try {
    await safeFetch(
      `${dataBase}/api/scheduling/scheduled_segments`,
      { method: 'POST', headers, body: JSON.stringify({ segments }) },
    );
    pushed = segments.length;
  } catch (err) {
    errors = segments.length;
    log('warn', 'ukg_adapter.push_schedule.batch_failed', {
      platform: 'ukg_kronos',
      segmentCount: segments.length,
      error: String(err && err.message),
    });
  }

  log('info', 'ukg_adapter.push_schedule.done', {
    platform: 'ukg_kronos', pushed, skipped, errors,
  });
  return { pushed, skipped, errors };
}

module.exports = { pullAvailability, pushSchedule };
