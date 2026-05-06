// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Scheduling Platform Adapter: ADP Workforce Now
// ═══════════════════════════════════════════════════════════════════════════════
//
// ADP Workforce Now is the third real-platform adapter and the first to
// require mutual TLS (mTLS). ADP issues each customer a client
// certificate and private key when the API client is provisioned;
// production ADP API access is gated behind that certificate, not just
// a bearer token. This adapter therefore extends the OAuth pattern
// from workday.js with an undici Agent that carries the cert/key
// through every outbound TLS handshake.
//
// Base URL: https://api.adp.com (production) or
// https://accounts.adp.com (token endpoint). Customers may override
// either via scheduling_platform_config.endpoint_url for a private
// API gateway. Token endpoint is always posted to
// {endpoint_url}/auth/oauth/v2/token if endpoint_url is set, else
// the canonical https://accounts.adp.com/auth/oauth/v2/token.
//
// Credentials shape (Tier-1 encrypted JSON in
// scheduling_platform_config.credentials_encrypted):
//
//   {
//     "clientId":     "...",
//     "clientSecret": "...",   // optional; some ADP tenants require it
//     "certPem":      "-----BEGIN CERTIFICATE-----\n...",
//     "certKeyPem":   "-----BEGIN PRIVATE KEY-----\n..."
//   }
//
// The route layer decrypts and parses the JSON before calling this
// adapter. The adapter never touches Tier-1 encryption directly. PEM
// blocks are passed through verbatim — Node's TLS stack accepts them
// as strings.
//
// Token lifecycle: ADP access tokens are typically valid for 1 hour,
// which is comparable to our default sync_interval_minutes of 60. We
// still refresh at the start of each adapter call rather than caching,
// matching the workday.js pattern, because syncs are infrequent
// enough that the extra round-trip is negligible compared to the
// reliability win of a fresh token.
//
// userId mapping:
//   ADP workers carry a businessCommunication.emails[].emailUri field.
//   We match against MC users.email (case-insensitive). Workers
//   without an MC user are skipped silently — HR-only staff outside
//   the SOC, not an error condition.
//
// Availability model:
//   Default Mon-Fri 09:00-17:00 with ADP time-off-requests subtracted.
//   Same partial-day-handling deferral as bamboohr.js and workday.js:
//   v1.0.29 treats every off block as a full day.
//
// pushSchedule for ADP:
//   ADP's API surface for writing schedule events is significantly
//   less mature than Workday's. The closest semantic match for an
//   upskilling block (a non-disruptive scheduled training period) is
//   ADP's scheduling/v1/work-assignments endpoint, but that requires
//   a business meaning ("work assignment") that doesn't fit. Creating
//   an entry through time-off-requests would be semantically wrong
//   (training is not time off) and would also cost the analyst paid
//   leave hours.
//
//   So this adapter's pushSchedule is a logging no-op (matching
//   bamboohr.js's choice). The MC's own DB stays the system of record
//   for upskilling assignments; analysts see them in their AC. If a
//   customer specifically needs ADP-side calendar entries for
//   upskilling, that's a future refinement scoped to a later phase.
// ═══════════════════════════════════════════════════════════════════════════════

const { validateAllowedHost } = require('../hr-allow-list');
const { Agent } = require('undici');

const FETCH_TIMEOUT_MS = 30_000;
const DEFAULT_WORK_DAYS = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday'];
const DEFAULT_DAY_START = '09:00';
const DEFAULT_DAY_END = '17:00';

const DEFAULT_TOKEN_HOST = 'https://accounts.adp.com';
const DEFAULT_DATA_HOST = 'https://api.adp.com';

/**
 * Build an undici Agent that carries the customer's client certificate
 * and private key. ADP's TLS handshake validates this cert against
 * the cert ADP issued at API-client provisioning time.
 *
 * @param {string} certPem    PEM-encoded client certificate
 * @param {string} certKeyPem PEM-encoded private key
 * @returns {Agent}
 */
function buildMtlsAgent(certPem, certKeyPem) {
  return new Agent({
    connect: {
      cert: certPem,
      key: certKeyPem,
      // Honor the system trust store for ADP's server cert. We do not
      // disable cert verification under any circumstances.
      rejectUnauthorized: true,
    },
  });
}

/**
 * fetch wrapper with timeout, SSRF guard, and mTLS dispatcher.
 *
 * @param {string} url
 * @param {object} init
 * @param {Agent} dispatcher
 * @returns {Promise<Response>}
 */
async function safeFetch(url, init, dispatcher) {
  const parsed = new URL(url);
  const guard = validateAllowedHost(parsed.hostname);
  if (!guard.ok) {
    throw new Error(`ADP fetch blocked: ${guard.error}`);
  }
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...init,
      redirect: 'error',
      signal: ctrl.signal,
      dispatcher,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(`ADP ${parsed.pathname} returned ${res.status}: ${body.slice(0, 200)}`);
    }
    return res;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Exchange client credentials (with mTLS) for an access token.
 *
 * @param {{clientId: string, clientSecret?: string}} creds
 * @param {string} tokenBase  base URL for the OAuth token endpoint
 * @param {Agent} dispatcher  mTLS-capable undici Agent
 * @returns {Promise<string>} access_token
 */
async function fetchAccessToken(creds, tokenBase, dispatcher) {
  const tokenUrl = `${tokenBase.replace(/\/+$/, '')}/auth/oauth/v2/token`;
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: creds.clientId,
  });
  if (creds.clientSecret) {
    params.set('client_secret', creds.clientSecret);
  }
  const res = await safeFetch(
    tokenUrl,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body: params.toString(),
    },
    dispatcher,
  );
  const json = await res.json();
  if (!json || !json.access_token) {
    throw new Error('ADP token endpoint returned no access_token');
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
 * Extract the primary work email from an ADP worker record.
 * ADP's worker shape:
 *   businessCommunication: { emails: [{ emailUri, nameCode: { codeValue } }, ...] }
 * We prefer the email tagged "Work" (codeValue === "Work"); if none
 * is tagged, we take the first email in the array.
 */
function extractWorkerEmail(worker) {
  const bc = worker && worker.businessCommunication;
  const emails = bc && Array.isArray(bc.emails) ? bc.emails : [];
  if (emails.length === 0) return '';
  const tagged = emails.find(e => e && e.nameCode && e.nameCode.codeValue === 'Work');
  const chosen = tagged || emails[0];
  return ((chosen && chosen.emailUri) || '').toLowerCase();
}

/**
 * Pull weekly availability from ADP Workforce Now.
 *
 * @param {object} ctx
 * @returns {Promise<{analysts: Array<{userId: string, weekStart: string, slots: object}>}>}
 */
async function pullAvailability({ db, log, config, weekOf }) {
  const creds = config && config.credentials;
  if (!creds || !creds.clientId || !creds.certPem || !creds.certKeyPem) {
    throw new Error('ADP adapter: credentials require clientId, certPem, certKeyPem');
  }

  const dataBase = (config.endpoint_url || DEFAULT_DATA_HOST).replace(/\/+$/, '');
  const tokenBase = (config.endpoint_url ? dataBase : DEFAULT_TOKEN_HOST);

  const weekStart = isoMondayUtc(weekOf instanceof Date ? weekOf : new Date());
  const weekEnd = isoSundayUtc(weekStart);

  log('info', 'adp_adapter.pull_availability.start', {
    platform: 'adp',
    weekStart,
    weekEnd,
  });

  const dispatcher = buildMtlsAgent(creds.certPem, creds.certKeyPem);

  try {
    const accessToken = await fetchAccessToken(creds, tokenBase, dispatcher);
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
    };

    // 1. List workers. ADP HR v2 workers endpoint, with pagination caps
    //    of $top=100 per call; we fetch up to 200 (two pages) for a
    //    typical SOC-sized tenant. Customers with >200 SOC staff can
    //    override in a later refinement.
    const allWorkers = [];
    for (let skip = 0; skip < 200; skip += 100) {
      const wRes = await safeFetch(
        `${dataBase}/hr/v2/workers?$top=100&$skip=${skip}`,
        { headers },
        dispatcher,
      );
      const wJson = await wRes.json();
      const page = Array.isArray(wJson && wJson.workers) ? wJson.workers : [];
      allWorkers.push(...page);
      if (page.length < 100) break;
    }

    // 2. Build email-to-MC-user-id map.
    const userByEmail = new Map();
    const userRows = db.prepare('SELECT id, email FROM users WHERE email IS NOT NULL').all();
    for (const r of userRows) {
      if (r.email) userByEmail.set(r.email.toLowerCase(), r.id);
    }

    // 3. Per mapped worker, fetch time-off requests for the target week.
    const analysts = [];
    let mappedCount = 0;
    let unmappedCount = 0;
    let timeOffFetchErrors = 0;

    for (const w of allWorkers) {
      const email = extractWorkerEmail(w);
      if (!email) { unmappedCount++; continue; }
      const mcUserId = userByEmail.get(email);
      if (!mcUserId) { unmappedCount++; continue; }

      const aoid = w.associateOID || w.workerID || w.id;
      if (!aoid) { unmappedCount++; continue; }

      const slots = defaultSlots();

      let timeOffEvents = [];
      try {
        const tofRes = await safeFetch(
          `${dataBase}/time/v1/workers/${encodeURIComponent(aoid)}/time-off-requests?$filter=startDate ge ${weekStart} and startDate le ${weekEnd}`,
          { headers },
          dispatcher,
        );
        const tofJson = await tofRes.json();
        timeOffEvents = Array.isArray(tofJson && tofJson.timeOffRequests) ? tofJson.timeOffRequests : [];
      } catch (err) {
        timeOffFetchErrors++;
        log('warn', 'adp_adapter.pull_availability.time_off_fetch_failed', {
          platform: 'adp',
          aoid,
          error: String(err && err.message),
        });
      }

      for (const ev of timeOffEvents) {
        const start = (ev.startDate || ev.start || '').slice(0, 10);
        const end = (ev.endDate || ev.end || start).slice(0, 10);
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

    log('info', 'adp_adapter.pull_availability.done', {
      platform: 'adp',
      weekStart,
      workersReturned: allWorkers.length,
      mapped: mappedCount,
      unmapped: unmappedCount,
      timeOffFetchErrors,
    });

    return { analysts };
  } finally {
    // Release the mTLS Agent's underlying sockets. close() resolves
    // once existing connections drain; we don't await here because
    // the function is returning synchronously after the success path.
    dispatcher.close().catch(() => { /* best-effort cleanup */ });
  }
}

/**
 * ADP has no clean write target that fits "schedule an analyst for an
 * upskilling block at a specific time" — see the doc-block at the top
 * of this file for the rationale. Logged no-op; the MC's own DB stays
 * the system of record.
 *
 * @param {object} ctx
 * @returns {Promise<{pushed: number, skipped: number, errors: number}>}
 */
async function pushSchedule({ log, assignments }) {
  const list = Array.isArray(assignments) ? assignments : [];
  log('warn', 'adp_adapter.push_schedule.unsupported', {
    platform: 'adp',
    note: 'ADP has no semantically appropriate write target for upskilling schedule events; assignments remain in FireAlive only',
    skipped: list.length,
  });
  return { pushed: 0, skipped: list.length, errors: 0 };
}

module.exports = { pullAvailability, pushSchedule };
