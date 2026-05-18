// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Training Library Seed Loader (R3l C3)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Purpose
//   Reads server/db/training-modules-seed.json (shipped in R3l C2) and populates
//   the training_platforms and training_modules tables created in R3l C1.
//
// Idempotency
//   Runs on every boot. Uses INSERT OR REPLACE keyed on the JSON-supplied id, so
//   each boot refreshes the curated rows to match the latest shipped seed. If a
//   future release ships a corrected URL or updated description, that fix takes
//   effect on the next deploy without a manual migration step. Modules that have
//   been REMOVED from the seed remain in the DB as orphans — orphan reaping is a
//   future commit and is deliberately out of scope for C3.
//
// Defense-in-depth URL validation
//   Every URL is re-checked against the same allowlist patterns the C1
//   url_legitimacy CHECK constraint enforces, BEFORE any DB write. This produces
//   better diagnostics than SQLite's opaque "CHECK constraint failed" error and
//   guarantees a single bad URL cannot abort an otherwise-valid batch. If a URL
//   survives this layer but is still rejected by the SQL CHECK, that means the
//   allowlist here has drifted from init.js — the error message says so
//   explicitly so the maintainer knows where to look.
//
// Failure modes
//   Missing seed file → log warning and return (DB is left empty, server still
//   boots, recommendation engine just returns no recommendations).
//   Malformed JSON / missing required arrays → throw (server crashes on boot
//   with a loud error — this is a packaging defect that must be fixed).
//   URL allowlist failure → throw with itemized list of rejected URLs.
//   SQL CHECK constraint failure → throw with explicit drift diagnostic.
//
// Skills array
//   The seed file's `skills` array (the 73-skill taxonomy) is intentionally not
//   persisted in C3. Skills are referenced by string id on training_modules and
//   are also enumerated by the existing assessments system. A dedicated
//   training_skills table is deferred to a future commit if the UI ever needs
//   to render the full taxonomy independently of module presence.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');

const SEED_FILE = path.join(__dirname, 'training-modules-seed.json');

// Allowlist mirrors the C1 url_legitimacy CHECK constraint exactly. Any change
// here MUST be paired with a matching change to init.js or the seed will fail
// validation at the SQL layer with the drift diagnostic below.
const URL_ALLOWLIST_PREFIXES = [
  'https://tryhackme.com/',
  'https://academy.hackthebox.com/',
  'https://app.letsdefend.io/',
  'https://cyberdefenders.org/',
  'https://www.sans.org/cyber-security-courses/',
  'https://www.immersivelabs.com/',
];
const URL_ALLOWLIST_SUBSTRINGS = [
  '/training/internal/',
];

function isUrlAllowed(url) {
  if (typeof url !== 'string' || url.length === 0) return false;
  for (const prefix of URL_ALLOWLIST_PREFIXES) {
    if (url.startsWith(prefix)) return true;
  }
  for (const substring of URL_ALLOWLIST_SUBSTRINGS) {
    if (url.indexOf(substring) !== -1) return true;
  }
  return false;
}

function seedTrainingLibrary(db) {
  if (!fs.existsSync(SEED_FILE)) {
    console.warn('[training-library] seed file not found at', SEED_FILE, '- skipping seed (server will boot with empty training library)');
    return { skipped: true, reason: 'seed file missing', platforms: 0, modules: 0 };
  }

  let seed;
  try {
    const raw = fs.readFileSync(SEED_FILE, 'utf8');
    seed = JSON.parse(raw);
  } catch (err) {
    throw new Error('[training-library] seed file is unreadable or invalid JSON: ' + err.message);
  }

  if (!seed || typeof seed !== 'object') {
    throw new Error('[training-library] seed file did not parse to an object');
  }
  if (!Array.isArray(seed.platforms)) {
    throw new Error('[training-library] seed file missing required platforms array');
  }
  if (!Array.isArray(seed.modules)) {
    throw new Error('[training-library] seed file missing required modules array');
  }

  // Defense-in-depth URL validation before any DB writes.
  const rejected = [];
  for (const m of seed.modules) {
    if (!m || typeof m !== 'object') {
      rejected.push({ id: '<malformed>', title: '<malformed>', url: '<malformed>', reason: 'module is not an object' });
      continue;
    }
    if (!isUrlAllowed(m.url)) {
      rejected.push({ id: m.id, title: m.title, url: m.url, reason: 'URL outside allowlist' });
    }
  }
  if (rejected.length > 0) {
    console.error('[training-library] rejected', rejected.length, 'modules during pre-flight validation:');
    const sample = rejected.slice(0, 5);
    for (const r of sample) {
      console.error('  - id=' + r.id + ' "' + (r.title || '') + '" url=' + (r.url || '') + ' reason=' + r.reason);
    }
    if (rejected.length > sample.length) {
      console.error('  - ... and ' + (rejected.length - sample.length) + ' more (omitted for log brevity)');
    }
    throw new Error('[training-library] ' + rejected.length + ' modules failed URL allowlist validation. Aborting seed without writing to DB.');
  }

  // Bulk insert in a single transaction. INSERT OR REPLACE keyed on id so that
  // a corrected URL or updated description in a future seed release takes effect
  // on the next boot without a separate migration step.
  const insertPlatform = db.prepare(
    'INSERT OR REPLACE INTO training_platforms (id, name, description, domain_pattern, active) VALUES (?, ?, ?, ?, ?)'
  );
  const insertModule = db.prepare(
    'INSERT OR REPLACE INTO training_modules (id, platform_id, skill_id, title, url, difficulty, free_or_paid, estimated_hours, description, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );

  const seedTxn = db.transaction(() => {
    for (const p of seed.platforms) {
      insertPlatform.run(
        p.id,
        p.name,
        p.description || '',
        p.domain_pattern || '',
        (p.active === undefined || p.active) ? 1 : 0
      );
    }
    for (const m of seed.modules) {
      insertModule.run(
        m.id,
        m.platform_id,
        m.skill_id,
        m.title,
        m.url,
        m.difficulty || 'intermediate',
        m.free_or_paid || 'free',
        (typeof m.estimated_hours === 'number') ? m.estimated_hours : 4,
        m.description || '',
        (m.active === undefined || m.active) ? 1 : 0
      );
    }
  });

  try {
    seedTxn();
  } catch (err) {
    // If the C1 CHECK constraint fires here despite our pre-flight validation,
    // it means URL_ALLOWLIST_PREFIXES / URL_ALLOWLIST_SUBSTRINGS in this file
    // has drifted from the url_legitimacy CHECK in init.js. Surface that
    // explicitly so the next maintainer doesn't have to bisect.
    if (err && err.message && err.message.indexOf('url_legitimacy') !== -1) {
      throw new Error(
        '[training-library] SQL CHECK constraint url_legitimacy rejected an insert despite passing the JS pre-flight. ' +
        'This means URL_ALLOWLIST_PREFIXES or URL_ALLOWLIST_SUBSTRINGS in seed-training-library.js has drifted from the url_legitimacy CHECK in init.js. ' +
        'Re-align both lists before redeploying. Original error: ' + err.message
      );
    }
    throw err;
  }

  console.log(
    '[training-library] seeded ' + seed.platforms.length + ' platforms, ' +
    seed.modules.length + ' modules ' +
    '(seed version=' + (seed.version || 'unknown') + ', generated_at=' + (seed.generated_at || 'unknown') + ')'
  );

  return {
    skipped: false,
    platforms: seed.platforms.length,
    modules: seed.modules.length,
    version: seed.version || 'unknown',
    generated_at: seed.generated_at || 'unknown',
  };
}

module.exports = {
  seedTrainingLibrary,
  isUrlAllowed,
  URL_ALLOWLIST_PREFIXES,
  URL_ALLOWLIST_SUBSTRINGS,
  SEED_FILE,
};
