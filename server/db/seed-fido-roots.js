// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — FIDO2 Attestation Trust-Anchor Seed Loader (B5n3)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Purpose
//   Reads server/data/fido-attestation-roots.json (the bundled, provenance-pinned
//   seed of trusted FIDO-certified vendor attestation root CAs) and populates the
//   fido_trusted_roots table. A hardware passkey is accepted at login enrollment
//   only if its attestation chains to one of these roots (or to a root an admin
//   adds later through the IAM admin surface), so this seed is the trust floor for
//   the hardware-credential login gate.
//
// Idempotency
//   Runs on every boot. INSERT ... ON CONFLICT(root_pem) DO NOTHING, keyed on the
//   PEM, so re-running is a no-op for already-present roots and a future release
//   that ships an additional root picks it up on the next deploy. Seeded rows
//   carry seeded=1; admin-added rows carry seeded=0 and are never touched here.
//   The seeder only ever INSERTs - it never deletes - so an admin-added root (or a
//   previously-seeded one) always survives a re-boot.
//
// Defense-in-depth validation
//   Every rootPem is parsed with Node's built-in crypto.X509Certificate and
//   confirmed to be a CA certificate BEFORE any DB write, so a malformed PEM in
//   the committed seed produces a clear boot-log error naming the offending entry
//   rather than a silent failure at the first enrollment attempt. A single bad
//   entry is skipped, not fatal - the valid roots still load. The real
//   attestation-chain check happens at enrollment in webauthn.js; this is a
//   seed-time sanity gate for diagnostics, not the security boundary.
//
// Failure modes (an auth server must stay up; security stays fail-closed)
//   Unlike a content seeder, a broken trust-anchor seed must NOT crash the boot:
//   the database may already hold valid seeded or admin-added roots, and bricking
//   the auth server is a worse outcome than a missing seed. So every failure here
//   is logged loudly and the boot continues:
//     - Missing seed file         -> warn, seed nothing this boot.
//     - Unreadable / invalid JSON  -> error, seed nothing this boot.
//     - Missing roots array        -> error, seed nothing this boot.
//     - A rootPem that is not a parseable CA certificate -> error, skip that one.
//   If the table ends up with zero trusted roots, hardware-key enrollment is
//   refused (fail-closed, secure) until an admin adds a root - it never opens a
//   weaker path.
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SEED_FILE = path.join(__dirname, '..', 'data', 'fido-attestation-roots.json');

// Validate a PEM is a parseable X.509 CA certificate. Returns { ok, reason }.
function validateRootPem(pem) {
  if (typeof pem !== 'string' || pem.indexOf('BEGIN CERTIFICATE') === -1) {
    return { ok: false, reason: 'not a PEM certificate string' };
  }
  let cert;
  try {
    cert = new crypto.X509Certificate(pem);
  } catch (err) {
    return { ok: false, reason: 'unparseable X.509 certificate: ' + err.message };
  }
  if (cert.ca !== true) {
    return { ok: false, reason: 'certificate is not a CA (basicConstraints CA:FALSE)' };
  }
  return { ok: true, reason: '' };
}

function seedFidoRoots(db) {
  if (!fs.existsSync(SEED_FILE)) {
    console.warn('[fido-roots] seed file not found at', SEED_FILE, '- seeding no trusted roots this boot (hardware-key enrollment stays fail-closed until an admin adds a root)');
    return { skipped: true, reason: 'seed file missing', seeded: 0, total: 0 };
  }

  let seed;
  try {
    const raw = fs.readFileSync(SEED_FILE, 'utf8');
    seed = JSON.parse(raw);
  } catch (err) {
    console.error('[fido-roots] seed file is unreadable or invalid JSON:', err.message, '- seeding no trusted roots this boot');
    return { skipped: true, reason: 'unreadable or invalid JSON', seeded: 0, total: 0 };
  }

  if (!seed || typeof seed !== 'object' || !Array.isArray(seed.roots)) {
    console.error('[fido-roots] seed file did not parse to an object with a roots array - seeding no trusted roots this boot');
    return { skipped: true, reason: 'missing roots array', seeded: 0, total: 0 };
  }

  // Defense-in-depth: validate each rootPem parses as a CA certificate before any
  // DB write. Skip (do not abort the batch on) a bad entry, with a loud log.
  const valid = [];
  for (const r of seed.roots) {
    if (!r || typeof r !== 'object') {
      console.error('[fido-roots] skipping a malformed seed entry (not an object)');
      continue;
    }
    const v = validateRootPem(r.rootPem);
    if (!v.ok) {
      console.error('[fido-roots] skipping root vendor=' + (r.vendor || '?') + ' label="' + (r.label || '?') + '": ' + v.reason);
      continue;
    }
    valid.push(r);
  }

  const insertRoot = db.prepare(
    'INSERT INTO fido_trusted_roots (vendor, label, root_pem, seeded) VALUES (?, ?, ?, 1) ON CONFLICT(root_pem) DO NOTHING'
  );

  let inserted = 0;
  const seedTxn = db.transaction(() => {
    for (const r of valid) {
      const info = insertRoot.run(String(r.vendor || ''), String(r.label || ''), String(r.rootPem));
      if (info && typeof info.changes === 'number') {
        inserted += info.changes;
      }
    }
  });
  seedTxn();

  let total = valid.length;
  try {
    const row = db.prepare('SELECT COUNT(*) AS n FROM fido_trusted_roots').get();
    if (row && typeof row.n === 'number') total = row.n;
  } catch (err) {
    // count is informational only - do not let it affect the boot
  }

  const ver = (seed._meta && seed._meta.version) ? seed._meta.version : 'unknown';
  console.log('[fido-roots] processed ' + seed.roots.length + ' seed entries, ' + valid.length + ' valid, ' + inserted + ' newly inserted; ' + total + ' trusted FIDO roots now present (seed version=' + ver + ')');

  if (total === 0) {
    console.warn('[fido-roots] WARNING: zero trusted FIDO roots present - hardware-key enrollment will be refused until an admin adds a root');
  }

  return { skipped: false, seeded: inserted, valid: valid.length, total: total };
}

module.exports = {
  seedFidoRoots,
  validateRootPem,
  SEED_FILE,
};
