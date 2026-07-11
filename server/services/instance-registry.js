// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Instance Registry (clone / fork / rollback classifier)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The server-side detection brain for anti-cloning (B5e, decision D4). The AC
// ratchet sync, the GD-side fingerprint-collision check, and the subnet
// peer-beacon all feed observations here; this module classifies each into a
// verdict, appends it to instance_observations, and (on a bad verdict) tells the
// caller to quarantine. The quarantine response (refuse + loud alert) is wired in
// a later commit and reads currentStatus()/quarantine() from here.
//
// Verdicts (match the instance_observations CHECK constraint):
//   ok       consistent with this instance's own identity and monotonic state
//   clone    this identity was observed coming from another source
//   rollback a trusted observer recorded a higher fuse/ratchet than we present
//            (snapshot or image restore is the usual cause)
//   fork     explicit divergence flagged by an observer (split-brain)

const VERDICT_OK = 'ok';
const VERDICT_FORK = 'fork';
const VERDICT_CLONE = 'clone';
const VERDICT_ROLLBACK = 'rollback';

const OBSERVER_AC = 'ac';
const OBSERVER_GD = 'gd';
const OBSERVER_BEACON = 'peer-beacon';

// Load this instance's own identity and current monotonic state, or null if no
// identity has been established (or the table is absent).
function loadSelf(db) {
  let row;
  try {
    row = db.prepare("SELECT instance_id, fingerprint, ratchet_counter, status FROM instance_identity ORDER BY id LIMIT 1").get();
  } catch (err) {
    return null;
  }
  if (!row) {
    return null;
  }
  let fuseHighWater = null;
  try {
    const m = db.prepare("SELECT value FROM node_state WHERE key = 'fuse_high_water'").get();
    if (m && m.value !== null && m.value !== undefined) {
      fuseHighWater = Number(m.value);
    }
  } catch (err) {
    fuseHighWater = null;
  }
  return {
    instanceId: row.instance_id,
    fingerprint: row.fingerprint,
    ratchetCounter: row.ratchet_counter,
    status: row.status,
    fuseHighWater: fuseHighWater,
  };
}

// Append an observation to the append-only log.
function recordObservation(db, o) {
  o = o || {};
  const detailJson = o.detail !== null && o.detail !== undefined ? JSON.stringify(o.detail) : null;
  db.prepare(
    "INSERT INTO instance_observations " +
    "(observer_kind, observed_instance_fingerprint, observed_from, verdict, detail_json) " +
    "VALUES (?, ?, ?, ?, ?)"
  ).run(o.observerKind || OBSERVER_AC, o.observedFingerprint || null, o.observedFrom || null, o.verdict || VERDICT_OK, detailJson);
}

// Map an observation to a verdict against this instance's own identity and
// monotonic high-water. Pure (no write). The observer supplies the signals it is
// confident about: sameIdentityDifferentSource (the clone signal, from the
// peer-beacon or the GD), forkDetected (explicit divergence), and the highest
// ratchet/fuse it has previously seen from this instance.
function classify(db, obs) {
  obs = obs || {};
  const self = loadSelf(db);
  if (!self) {
    return { verdict: VERDICT_OK, reason: 'no local instance identity' };
  }
  if (obs.sameIdentityDifferentSource === true && obs.observedFingerprint && obs.observedFingerprint === self.fingerprint) {
    return { verdict: VERDICT_CLONE, reason: 'this identity was observed from another source' };
  }
  if (obs.forkDetected === true) {
    return { verdict: VERDICT_FORK, reason: obs.reason || 'divergent state under a shared identity' };
  }
  if (obs.observedFuse !== null && obs.observedFuse !== undefined &&
      self.fuseHighWater !== null && Number(obs.observedFuse) > Number(self.fuseHighWater)) {
    return { verdict: VERDICT_ROLLBACK, reason: 'a trusted observer recorded a higher anti-rollback fuse than this instance presents' };
  }
  if (obs.observedRatchet !== null && obs.observedRatchet !== undefined &&
      Number(obs.observedRatchet) > Number(self.ratchetCounter)) {
    return { verdict: VERDICT_ROLLBACK, reason: 'a trusted observer recorded a higher ratchet than this instance presents' };
  }
  return { verdict: VERDICT_OK, reason: null };
}

// Classify, record, and report whether quarantine is warranted. Callers (the
// observers) pass the raw observation; the quarantine response acts on
// quarantineRecommended.
function evaluateAndRecord(db, obs) {
  obs = obs || {};
  const result = classify(db, obs);
  recordObservation(db, {
    observerKind: obs.observerKind || OBSERVER_AC,
    observedFingerprint: obs.observedFingerprint || null,
    observedFrom: obs.observedFrom || null,
    verdict: result.verdict,
    detail: Object.assign({ reason: result.reason }, obs.detail || {}),
  });
  return {
    verdict: result.verdict,
    reason: result.reason,
    quarantineRecommended: result.verdict !== VERDICT_OK,
  };
}

// Fire a loud, critical alert (audit + notification + email + SOAR + SIEM +
// webhook, plus an urgent client refresh) so a quarantine reaches the team lead
// immediately, not only the audit log. routeAlert is required lazily to avoid a
// load-order cycle, and the call is best-effort -- a failed alert must never
// block the quarantine itself.
function raiseQuarantineAlert(db, opts) {
  opts = opts || {};
  try {
    const { routeAlert } = require('./alert-router');
    const verdict = opts.verdict || VERDICT_CLONE;
    const reason = opts.reason || 'instance quarantined';
    const message = 'Instance quarantined (' + verdict + '): ' + reason + '. Possible clone, fork, or rollback -- privileged actions are now refused and affected analyst clients must re-enroll.';
    Promise.resolve(routeAlert(db, {
      type: 'INSTANCE_QUARANTINED',
      severity: 'critical',
      message: message,
      timestamp: new Date().toISOString(),
    })).catch(() => {});
  } catch (alertErr) {
    // never let an alerting failure block quarantine
  }
}

// Set this instance's status to quarantined and log the triggering observation.
// Idempotent. The mint gate (entropy.requireIdentityEstablished) already refuses
// new long-lived keys once status is not active.
function quarantine(db, opts) {
  opts = opts || {};
  try {
    db.prepare(
      "UPDATE instance_identity SET status = 'quarantined', last_attested_at = datetime('now') " +
      "WHERE id = (SELECT id FROM instance_identity ORDER BY id LIMIT 1)"
    ).run();
  } catch (err) {
    return { status: null, error: err && err.message ? err.message : String(err) };
  }
  recordObservation(db, {
    observerKind: opts.observerKind || OBSERVER_AC,
    observedFingerprint: opts.fingerprint || null,
    observedFrom: opts.observedFrom || null,
    verdict: opts.verdict || VERDICT_CLONE,
    detail: { quarantined: true, reason: opts.reason || 'quarantine requested' },
  });
  raiseQuarantineAlert(db, opts);
  return { status: 'quarantined' };
}

// Current status of this instance ('active' | 'quarantined'), or null.
function currentStatus(db) {
  const self = loadSelf(db);
  return self ? self.status : null;
}

// ──── Host presence / vMotion-vs-clone (D10, D11) ────────────────────────────
// The hardware anchor binds this identity. In VIRTUALIZED or CLOUD mode the
// anchor (a vTPM, including a cloud vTPM) migrates with the VM or cloud
// instance, so the same anchor reappearing on a new host -- a vMotion, or a
// cloud stop/start that returns on a new address -- is an authorized relocation
// that we record and audit. In BARE-METAL the anchor is bound to the physical
// machine, so a host change is unexpected and flagged. This is ORTHOGONAL to the
// clone guard: two CONCURRENT sources under one identity remain a clone (see
// classify, sameIdentityDifferentSource) regardless of mode -- a relocation is
// sequential, a clone is simultaneous, so recording a relocation here never
// relaxes clone detection.
const HOST_KEY = 'instance_host';

function getHomeHost(db) {
  try {
    const row = db.prepare("SELECT value FROM config WHERE key = ?").get(HOST_KEY);
    return row && row.value ? JSON.parse(row.value) : null;
  } catch (_e) {
    return null;
  }
}

function writeHomeHost(db, rec) {
  db.prepare("INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)").run(HOST_KEY, JSON.stringify(rec));
}

// Record the host this instance is running on and classify any change. The
// caller passes virtualized and cloud (from the sealed deployment mode) and a
// best-effort host descriptor and hypervisor hint. Returns:
//   { changed, migration, unexpected, host, previousHost, firstSeen }
// migration  = authorized relocation (host changed in virtualized or cloud mode)
// unexpected = host changed in bare-metal mode (anchor should be machine-bound)
function recordHostPresence(db, opts) {
  opts = opts || {};
  const host = opts.host || 'unknown';
  const virtualized = opts.virtualized === true;
  const cloud = opts.cloud === true;
  // The anchor migrates with the VM (vMotion) or the cloud instance (stop/start),
  // so a host change in either mode is an authorized relocation, not a clone.
  const relocatable = virtualized || cloud;
  const prev = getHomeHost(db);
  const rec = {
    host: host,
    virtualized: virtualized,
    cloud: cloud,
    hypervisor: opts.hypervisor || null,
    since: new Date().toISOString()
  };
  if (!prev || !prev.host) {
    writeHomeHost(db, rec);
    return { changed: false, migration: false, unexpected: false, host: host, previousHost: null, firstSeen: true };
  }
  if (prev.host === host) {
    return { changed: false, migration: false, unexpected: false, host: host, previousHost: host, firstSeen: false };
  }
  writeHomeHost(db, rec);
  return {
    changed: true,
    migration: relocatable,
    unexpected: !relocatable,
    host: host,
    previousHost: prev.host,
    firstSeen: false
  };
}

module.exports = {
  VERDICT_OK,
  VERDICT_FORK,
  VERDICT_CLONE,
  VERDICT_ROLLBACK,
  OBSERVER_AC,
  OBSERVER_GD,
  OBSERVER_BEACON,
  loadSelf,
  recordObservation,
  classify,
  evaluateAndRecord,
  quarantine,
  currentStatus,
  recordHostPresence,
  getHomeHost,
  HOST_KEY,
};
