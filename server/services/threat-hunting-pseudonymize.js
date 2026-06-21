// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Pseudonymizer + Field Projector (B5m)
//
// The privacy floor for the threat-hunting feed. Two guarantees:
//
//   1. Actors are re-pseudonymized. pseudonymizeActor maps an actor id to a
//      stable, irreversible, FEED-SPECIFIC token via HMAC keyed by a per-
//      deployment secret. The same actor maps to the same token (so a hunter can
//      correlate "same actor did X then Y" during an incident), but the token
//      cannot be reversed or correlated to users.pseudonym / user_id on any other
//      surface without the secret. FireAlive stores no real names, so there is
//      nothing more identifying than the pseudonym to begin with.
//
//   2. Projection is fail-closed. projectAllowed reads ONLY the fields named in a
//      per-domain allow-list; every other field on the source row is dropped, so a
//      new column added upstream is never exposed unless explicitly allow-listed.
//      Beneath the allow-list sit two hard rules that win even if an allow-list is
//      wrong: a deny-list of field-name substrings (burnout / wellbeing / Tier-3 /
//      credentials / real-identity) that may never be read or written, and a rule
//      that any identity source field must be pseudonymized or it is dropped.
//
// No burnout score, wellbeing/Tier-3 signal, raw credential, or real identity can
// reach the feed through this module.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const SECRET_KEY = 'threat_hunting_pseudonym_secret';
let cachedSecret = null;

// Field-name substrings that must NEVER reach the feed, on either the source or
// destination name, regardless of the allow-list.
const DENY_SUBSTRINGS = [
  'burnout', 'wellbeing', 'wellness', 'morale', 'stress', 'fatigue',
  'sentiment', 'mood', 'tier3', 'tier_3',
  'password', 'secret', 'token_hash', 'token_salt', 'refresh_token',
  'private_key', 'privatekey', 'recovery',
  'real_name', 'realname', 'full_name', 'fullname', 'email', 'phone', 'ssn',
];

// Source fields that identify an actor: these may be read only to produce a
// pseudonym, never passed through raw.
const IDENTITY_SOURCE_FIELDS = ['user_id', 'analyst_id', 'username', 'user', 'pseudonym'];

function isDeniedField(name) {
  const n = String(name || '').toLowerCase();
  return DENY_SUBSTRINGS.some((d) => n.indexOf(d) !== -1);
}

function isIdentitySource(name) {
  return IDENTITY_SOURCE_FIELDS.indexOf(String(name || '').toLowerCase()) !== -1;
}

// Per-deployment HMAC secret. Created once and stored in the config table;
// race-safe via INSERT OR IGNORE then read-back, and cached in-process.
function getOrCreateSecret(db) {
  if (cachedSecret) return cachedSecret;
  db.prepare('INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)')
    .run(SECRET_KEY, crypto.randomBytes(32).toString('hex'));
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get(SECRET_KEY);
  cachedSecret = row && row.value ? row.value : null;
  return cachedSecret;
}

// Stable, irreversible, feed-specific pseudonym for an actor id.
function pseudonymizeActor(db, userId, namespace) {
  if (userId == null || userId === '') return null;
  const secret = getOrCreateSecret(db);
  if (!secret) return null; // fail closed: no pseudonym rather than a raw id
  const ns = (typeof namespace === 'string' && namespace) ? namespace : 'actor';
  const mac = crypto.createHmac('sha256', secret).update(ns + ':' + String(userId)).digest('hex');
  const prefix = ns === 'actor' ? 'analyst-' : (ns + '-');
  return prefix + mac.slice(0, 16);
}

// Fail-closed projection of one source row through an allow-list. Each spec is
// { from, to?, pseudonym?, transform? }: from is the source field, to the
// output name (defaults to from), pseudonym (true | 'namespace') re-
// pseudonymizes, and transform is an optional value mapper. Only allow-listed
// fields are read; the deny-list and identity rule are enforced regardless.
function projectAllowed(db, record, allowList) {
  const out = {};
  if (!record || typeof record !== 'object' || !Array.isArray(allowList)) return out;
  for (const spec of allowList) {
    if (!spec || typeof spec.from !== 'string') continue;
    const to = (typeof spec.to === 'string' && spec.to) ? spec.to : spec.from;
    if (isDeniedField(spec.from) || isDeniedField(to)) continue;        // hard deny wins
    if (isIdentitySource(spec.from) && !spec.pseudonym) continue;       // identity must be pseudonymized
    if (!Object.prototype.hasOwnProperty.call(record, spec.from)) continue; // fail-closed: missing source omitted
    let val = record[spec.from];
    if (spec.pseudonym) {
      val = pseudonymizeActor(db, val, typeof spec.pseudonym === 'string' ? spec.pseudonym : 'actor');
    } else if (typeof spec.transform === 'function') {
      try { val = spec.transform(val); } catch (_) { continue; }
    }
    out[to] = val;
  }
  return out;
}

module.exports = {
  pseudonymizeActor,
  projectAllowed,
  isDeniedField,
  isIdentitySource,
  DENY_SUBSTRINGS,
  IDENTITY_SOURCE_FIELDS,
  _resetSecretCache: () => { cachedSecret = null; },
};
