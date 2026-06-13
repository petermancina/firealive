// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── AC Ratchet (per-device monotonic counter)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// The per-AC monotonic ratchet (B5e, decision D4). Each AC sync advances that
// device's counter, the server echoes the new value, and the AC remembers the
// highest it has seen. If an AC later presents a counter AHEAD of what the server
// holds for it, the server's per-device state regressed -- a snapshot or image
// restore, or a stale fork/clone running behind the real instance. This is the
// always-present detection seam: it needs no GD, only the AC fleet.
//
// This module is the engine. It advances/compares the counter and, on an anomaly,
// records a ROLLBACK observation via the registry and returns a quarantine
// recommendation; the caller (the WebSocket auth handler) acts on it. The matching
// AC-side persistence + the server-behind check live in the next commits.

const registry = require('./instance-registry');

// Read the current per-device ratchet for a user's active device key, or null.
function currentForUser(db, userId) {
  try {
    const row = db.prepare("SELECT ratchet_counter FROM ac_device_signing_keys WHERE user_id = ? AND active = 1 ORDER BY id LIMIT 1").get(userId);
    return row ? Number(row.ratchet_counter || 0) : null;
  } catch (err) {
    return null;
  }
}

// Advance the per-device ratchet on a sync and detect a regressed/forked server.
// params: { userId, presentedCounter, observedFrom }. Returns
// { counter, anomaly, verdict, quarantineRecommended }.
function advanceForUser(db, params) {
  params = params || {};
  const userId = params.userId;
  const presented = (params.presentedCounter !== null && params.presentedCounter !== undefined)
    ? Number(params.presentedCounter)
    : null;
  const observedFrom = params.observedFrom || null;

  let row;
  try {
    row = db.prepare("SELECT id, ratchet_counter FROM ac_device_signing_keys WHERE user_id = ? AND active = 1 ORDER BY id LIMIT 1").get(userId);
  } catch (err) {
    return { counter: null, anomaly: false, verdict: registry.VERDICT_OK, quarantineRecommended: false, error: err && err.message ? err.message : String(err) };
  }
  if (!row) {
    return { counter: null, anomaly: false, verdict: registry.VERDICT_OK, quarantineRecommended: false, reason: 'no active device key' };
  }

  const current = Number(row.ratchet_counter || 0);
  let anomaly = false;
  let verdict = registry.VERDICT_OK;
  if (presented !== null && Number.isFinite(presented) && presented > current) {
    anomaly = true;
    verdict = registry.VERDICT_ROLLBACK;
    registry.recordObservation(db, {
      observerKind: registry.OBSERVER_AC,
      observedFrom: observedFrom,
      verdict: verdict,
      detail: { perDeviceRatchet: true, userId: userId, deviceKeyId: row.id, presented: presented, serverHeld: current },
    });
  }

  const base = (anomaly && Number.isFinite(presented)) ? Math.max(current, presented) : current;
  const next = base + 1;
  try {
    db.prepare("UPDATE ac_device_signing_keys SET ratchet_counter = ?, ratchet_updated_at = datetime('now') WHERE id = ?").run(next, row.id);
  } catch (err) {
    return { counter: current, anomaly: anomaly, verdict: verdict, quarantineRecommended: anomaly, error: err && err.message ? err.message : String(err) };
  }
  return { counter: next, anomaly: anomaly, verdict: verdict, quarantineRecommended: anomaly };
}

module.exports = {
  currentForUser,
  advanceForUser,
};
