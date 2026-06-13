// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Entropy (first-boot verification + key-mint gate)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// First-boot entropy verification and the long-lived-key mint gate (B5e, D6).
//
// THE CLONE / TEMPLATE-DEPLOY ENTROPY RISK
// When two instances boot from the same disk image, they can mint identical
// keys if they share RNG state (the classic cloned-VM duplicate-key problem).
// Node's crypto.randomBytes is backed by a CSPRNG that blocks until the OS RNG
// is seeded (getrandom semantics), so a successful draw means it is initialized;
// JS cannot reseed OpenSSL's pool directly. This module therefore (1) verifies
// the CSPRNG is healthy and fails closed otherwise, (2) offers an instance-unique
// seed that mixes the OS RNG with host-specific sources so clones diverge even
// under shared RNG, and (3) gates long-lived key minting behind an established
// instance identity.

const crypto = require('crypto');
const os = require('os');
const fs = require('fs');

const BOOT_ENTROPY_KEY = 'boot_entropy_commitment';

// A strong, instance-unique 32-byte seed: the OS CSPRNG mixed with host sources
// (network MACs, hostname, machine, total memory, high-resolution time, pid).
// Even if two clones shared OS RNG state, these host/timing inputs differ, so the
// derived seed differs. For consumers that derive secrets from a seed and want
// clone-resistant entropy.
function gatherBootEntropy() {
  const h = crypto.createHash('sha512');
  h.update(crypto.randomBytes(32));
  try {
    const ifaces = os.networkInterfaces();
    const names = Object.keys(ifaces).sort();
    for (let i = 0; i < names.length; i++) {
      const list = ifaces[names[i]] || [];
      for (let j = 0; j < list.length; j++) {
        if (list[j] && list[j].mac) {
          h.update(String(list[j].mac));
        }
      }
    }
  } catch (err) {
    // interface enumeration is best-effort
  }
  h.update(String(os.hostname()));
  h.update(String(os.arch()));
  h.update(String(os.platform()));
  h.update(String(os.totalmem()));
  h.update(String(process.pid));
  h.update(String(process.hrtime.bigint()));
  h.update(String(Date.now()));
  h.update(crypto.randomBytes(32));
  const digest = h.digest();
  return crypto.createHash('sha256').update(digest).digest();
}

// Health-check the CSPRNG. A successful, non-degenerate draw means the generator
// is initialized; callers must not mint long-lived keys when ok is false. On
// Linux the kernel entropy estimate is read best-effort for the log only (modern
// CRNGs report a fixed pool once initialized), and is the gate only when it is
// explicitly zero. Returns { ok, reason, entropyAvail }.
function verifyEntropy() {
  let entropyAvail = null;
  try {
    const raw = fs.readFileSync('/proc/sys/kernel/random/entropy_avail', 'utf8');
    const n = parseInt(raw.trim(), 10);
    if (!Number.isNaN(n)) {
      entropyAvail = n;
    }
  } catch (err) {
    entropyAvail = null;
  }
  try {
    const a = crypto.randomBytes(32);
    const b = crypto.randomBytes(32);
    if (a.equals(b)) {
      return { ok: false, reason: 'CSPRNG produced identical draws', entropyAvail: entropyAvail };
    }
    if (a.equals(Buffer.alloc(32)) || b.equals(Buffer.alloc(32))) {
      return { ok: false, reason: 'CSPRNG produced all-zero output', entropyAvail: entropyAvail };
    }
  } catch (err) {
    return { ok: false, reason: err && err.message ? err.message : String(err), entropyAvail: entropyAvail };
  }
  if (entropyAvail !== null && entropyAvail === 0) {
    return { ok: false, reason: 'kernel entropy pool is empty', entropyAvail: entropyAvail };
  }
  return { ok: true, reason: null, entropyAvail: entropyAvail };
}

// First-boot entropy step, run before instance identity is established. Verifies
// the CSPRNG (throws if unhealthy -- fail closed) and records a one-time,
// non-secret commitment to a freshly gathered boot-entropy seed in system_meta.
// Idempotent: a later boot leaves the existing commitment untouched and re-runs
// only the verification. Returns { verified, fresh, commitment, entropyAvail }.
function ensureFirstBootEntropy(db, options) {
  options = options || {};
  const health = verifyEntropy();
  if (!health.ok) {
    throw new Error('entropy verification failed: ' + (health.reason || 'unknown') +
      ' -- refusing to establish instance identity until the CSPRNG is healthy');
  }
  let fresh = false;
  let commitment = null;
  try {
    const row = db.prepare("SELECT value FROM system_meta WHERE key = ?").get(BOOT_ENTROPY_KEY);
    if (row && row.value) {
      commitment = row.value;
    } else {
      const seed = gatherBootEntropy();
      commitment = crypto.createHash('sha256').update(seed).digest('hex');
      db.prepare("INSERT OR IGNORE INTO system_meta (key, value) VALUES (?, ?)").run(BOOT_ENTROPY_KEY, commitment);
      fresh = true;
    }
  } catch (err) {
    if (options.logger && typeof options.logger.warn === 'function') {
      options.logger.warn('boot-entropy commitment not recorded', { reason: err && err.message ? err.message : String(err) });
    }
  }
  if (options.logger && typeof options.logger.info === 'function') {
    options.logger.info('first-boot entropy verified', { fresh: fresh, entropyAvail: health.entropyAvail });
  }
  return { verified: true, fresh: fresh, commitment: commitment, entropyAvail: health.entropyAvail };
}

// The key-mint gate (decision D6). Long-lived key minting (CA, gd-push, device,
// and the chain-signing families) MUST call this first: it throws unless an
// ACTIVE instance identity exists, so a half-provisioned clone cannot stand up
// its own trust and no long-lived key is minted before identity is established.
// The instance anchor's own keypair is exempt -- it IS the identity being
// established -- and does not call this.
function requireIdentityEstablished(db) {
  let row;
  try {
    row = db.prepare("SELECT status FROM instance_identity ORDER BY id LIMIT 1").get();
  } catch (err) {
    throw new Error('requireIdentityEstablished: instance_identity table unavailable: ' +
      (err && err.message ? err.message : String(err)));
  }
  if (!row) {
    throw new Error('requireIdentityEstablished: no instance identity established -- refusing to mint long-lived keys');
  }
  if (row.status !== 'active') {
    throw new Error('requireIdentityEstablished: instance identity is ' + row.status +
      ' -- refusing to mint long-lived keys');
  }
  return true;
}

module.exports = {
  gatherBootEntropy,
  verifyEntropy,
  ensureFirstBootEntropy,
  requireIdentityEstablished,
};
