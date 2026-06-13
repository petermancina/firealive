// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Instance Collision Detector (B5e)
//
// GD-side anti-cloning collision detector (B5e, decision D4). Every MC binds
// its instance-anchor fingerprint (the MC instance_identity.fingerprint,
// SHA-256 hex of the anchor SPKI DER) to its mc_id. The push ingest path calls
// evaluateBinding() with the mc_id and the fingerprint the MC presented; this
// module compares it against the recorded bindings and flags:
//
//   fingerprint-reused   the same fingerprint is already bound to a DIFFERENT
//                        mc_id -- two deployments share one instance identity,
//                        the signature of a clone.
//   fingerprint-changed  this mc_id presented a fingerprint different from the
//                        one on file -- a re-provision, or a clone that minted
//                        a fresh identity.
//
// Anomalies are appended to mc_instance_collisions (deduped while the state is
// unchanged) and the live binding in mc_instance_bindings is upserted. The
// authenticity of the presented fingerprint is the caller concern (the push
// signature is verified before this runs); this module is pure comparison.

const KIND_REUSED = 'fingerprint-reused';
const KIND_CHANGED = 'fingerprint-changed';

const STATUS_BOUND = 'bound';
const STATUS_COLLISION = 'collision';
const STATUS_REBOUND = 'rebound';

function readBinding(db, mcId) {
  return db.prepare("SELECT mc_id, fingerprint, status FROM mc_instance_bindings WHERE mc_id = ?").get(mcId);
}

// The first OTHER mc_id this fingerprint is already bound to, or null.
function findConflict(db, mcId, fingerprint) {
  const row = db.prepare("SELECT mc_id FROM mc_instance_bindings WHERE fingerprint = ? AND mc_id != ? ORDER BY first_seen_at LIMIT 1").get(fingerprint, mcId);
  return row ? row.mc_id : null;
}

function upsertBinding(db, mcId, fingerprint, status) {
  db.prepare(
    "INSERT INTO mc_instance_bindings (mc_id, fingerprint, status) VALUES (?, ?, ?) " +
    "ON CONFLICT(mc_id) DO UPDATE SET fingerprint = excluded.fingerprint, last_seen_at = datetime('now'), status = excluded.status"
  ).run(mcId, fingerprint, status);
}

function recordCollision(db, args) {
  db.prepare(
    "INSERT INTO mc_instance_collisions (mc_id, fingerprint, conflicting_mc_id, kind, detail) VALUES (?, ?, ?, ?, ?)"
  ).run(args.mcId, args.fingerprint, args.conflictingMcId || null, args.kind, args.detail || null);
}

// Evaluate the fingerprint an MC presented against the recorded bindings,
// record any anomaly, upsert the binding, and return the verdict.
function evaluateBinding(db, args) {
  args = args || {};
  const mcId = args.mcId;
  const fingerprint = args.fingerprint;
  if (typeof mcId !== 'string' || !mcId || typeof fingerprint !== 'string' || !fingerprint) {
    return { ok: false, verdict: 'invalid', error: 'mcId and fingerprint are required' };
  }

  const existing = readBinding(db, mcId);
  const conflictingMcId = findConflict(db, mcId, fingerprint);

  let verdict;
  let kind = null;
  let status;
  let detail = null;
  if (conflictingMcId) {
    verdict = 'collision';
    kind = KIND_REUSED;
    status = STATUS_COLLISION;
    detail = 'fingerprint also bound to mc_id ' + conflictingMcId;
  } else if (existing && existing.fingerprint !== fingerprint) {
    verdict = 'rebind';
    kind = KIND_CHANGED;
    status = STATUS_REBOUND;
    detail = 'instance fingerprint changed from ' + existing.fingerprint + ' to ' + fingerprint;
  } else {
    verdict = 'ok';
    status = STATUS_BOUND;
  }

  // Log the anomaly only when the recorded state is not already this exact
  // (fingerprint, status) -- avoids flooding the log on every steady push.
  const stateChanged = !existing || existing.fingerprint !== fingerprint || existing.status !== status;
  if (kind && stateChanged) {
    recordCollision(db, { mcId: mcId, fingerprint: fingerprint, conflictingMcId: conflictingMcId, kind: kind, detail: detail });
  }

  upsertBinding(db, mcId, fingerprint, status);

  return {
    ok: verdict === 'ok',
    verdict: verdict,
    collision: verdict === 'collision',
    rebind: verdict === 'rebind',
    kind: kind,
    conflictingMcId: conflictingMcId,
    mcId: mcId,
    fingerprint: fingerprint,
  };
}

module.exports = {
  KIND_REUSED,
  KIND_CHANGED,
  STATUS_BOUND,
  STATUS_COLLISION,
  STATUS_REBOUND,
  readBinding,
  findConflict,
  evaluateBinding,
};
