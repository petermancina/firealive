// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Abuse Pattern Detector (U2)
//
// Statistical detection of abuse patterns over peer-flag METADATA. Per the
// AI/ML strategy, peer messages are end-to-end encrypted, so detection keys
// entirely on user UUIDs, flag ids, tiers, and timestamps and NEVER reads
// decrypted content. Three patterns are detected over a rolling window:
//
//   repeat_offender — one analyst is flagged repeatedly (by any flaggers)
//   escalation      — the severity of flags against one analyst rises over time
//   retaliation     — two analysts flag each other (reciprocal flagging)
//
// Each detection is upserted into peer_abuse_patterns: a single live,
// unacknowledged row per (pattern_type, subject, counterpart) is kept and
// refreshed as new flags arrive; once a lead acknowledges a row, a later
// detection opens a fresh one. The tiered identity-reveal policy is applied at
// read time in the review API — this module only ever handles UUIDs.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

const WINDOW_DAYS = 30;
const REPEAT_OFFENDER_MIN = 2; // flags against one subject within the window

function windowStartISO() {
  return new Date(Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000).toISOString();
}

// Severity from the worst tier seen and how many flags are involved. Tier 3
// content (slurs, threats, harassment) is always urgent; tier 2 is at least a
// watch; a tier-1-only pattern is info unless it is also frequent.
function severityFor(maxTier, count) {
  if (maxTier >= 3) return 'urgent';
  if (maxTier === 2) return 'watch';
  return count >= 3 ? 'watch' : 'info';
}

function flagsAgainst(db, subjectId, since) {
  return db.prepare(
    `SELECT id, flagger_user_id, flagged_user_id, tier, created_at
       FROM peer_abuse_flags
      WHERE flagged_user_id = ? AND created_at >= ?
      ORDER BY created_at ASC`
  ).all(subjectId, since);
}

// One analyst flagged repeatedly within the window.
function detectRepeatOffender(db, subjectId, since) {
  const rows = flagsAgainst(db, subjectId, since);
  if (rows.length < REPEAT_OFFENDER_MIN) return null;
  const maxTier = Math.max(...rows.map((r) => r.tier));
  return {
    pattern_type: 'repeat_offender',
    subject_user_id: subjectId,
    counterpart_user_id: null,
    involved_flag_ids: rows.map((r) => r.id),
    flag_count: rows.length,
    max_tier: maxTier,
    window_start: rows[0].created_at,
    window_end: rows[rows.length - 1].created_at,
    severity: severityFor(maxTier, rows.length),
  };
}

// The severity of flags against one analyst rises over the window.
function detectEscalation(db, subjectId, since) {
  const rows = flagsAgainst(db, subjectId, since);
  if (rows.length < 2) return null;
  const firstTier = rows[0].tier;
  const maxTier = Math.max(...rows.map((r) => r.tier));
  if (maxTier <= firstTier) return null; // no upward trend
  return {
    pattern_type: 'escalation',
    subject_user_id: subjectId,
    counterpart_user_id: null,
    involved_flag_ids: rows.map((r) => r.id),
    flag_count: rows.length,
    max_tier: maxTier,
    window_start: rows[0].created_at,
    window_end: rows[rows.length - 1].created_at,
    severity: severityFor(maxTier, rows.length),
  };
}

// Two analysts flag each other within the window. The subject is whoever
// flagged second (the retaliator); the counterpart is the one they retaliated
// against. Reciprocal flagging is at least a watch since it can indicate misuse
// of the flagging system.
function detectRetaliation(db, aId, bId, since) {
  const aFlagsB = db.prepare(
    `SELECT id, tier, created_at FROM peer_abuse_flags
      WHERE flagger_user_id = ? AND flagged_user_id = ? AND created_at >= ?
      ORDER BY created_at ASC`
  ).all(aId, bId, since);
  const bFlagsA = db.prepare(
    `SELECT id, tier, created_at FROM peer_abuse_flags
      WHERE flagger_user_id = ? AND flagged_user_id = ? AND created_at >= ?
      ORDER BY created_at ASC`
  ).all(bId, aId, since);
  if (aFlagsB.length === 0 || bFlagsA.length === 0) return null; // not reciprocal

  let subject, counterpart;
  if (aFlagsB[0].created_at <= bFlagsA[0].created_at) {
    subject = bId; counterpart = aId; // B flagged second -> B retaliated
  } else {
    subject = aId; counterpart = bId;
  }
  const all = [...aFlagsB, ...bFlagsA];
  const maxTier = Math.max(...all.map((r) => r.tier));
  const times = all.map((r) => r.created_at).sort();
  return {
    pattern_type: 'retaliation',
    subject_user_id: subject,
    counterpart_user_id: counterpart,
    involved_flag_ids: all.map((r) => r.id),
    flag_count: all.length,
    max_tier: maxTier,
    window_start: times[0],
    window_end: times[times.length - 1],
    severity: maxTier >= 3 ? 'urgent' : 'watch',
  };
}

// Persist a detection: refresh the live unacknowledged row for this
// (type, subject, counterpart) if one exists, otherwise insert a new one.
function upsertPattern(db, pat) {
  if (!pat) return null;
  const flagIdsJson = JSON.stringify(pat.involved_flag_ids);
  const existing = db.prepare(
    `SELECT id FROM peer_abuse_patterns
      WHERE pattern_type = ? AND subject_user_id = ? AND acknowledged_at IS NULL
        AND ((counterpart_user_id IS NULL AND ? IS NULL) OR counterpart_user_id = ?)`
  ).get(pat.pattern_type, pat.subject_user_id, pat.counterpart_user_id, pat.counterpart_user_id);

  if (existing) {
    db.prepare(
      `UPDATE peer_abuse_patterns
          SET involved_flag_ids = ?, flag_count = ?, max_tier = ?,
              window_start = ?, window_end = ?, severity = ?
        WHERE id = ?`
    ).run(flagIdsJson, pat.flag_count, pat.max_tier, pat.window_start, pat.window_end, pat.severity, existing.id);
    return existing.id;
  }

  const id = crypto.randomBytes(16).toString('hex');
  db.prepare(
    `INSERT INTO peer_abuse_patterns
       (id, pattern_type, subject_user_id, counterpart_user_id, involved_flag_ids,
        flag_count, max_tier, window_start, window_end, severity)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id, pat.pattern_type, pat.subject_user_id, pat.counterpart_user_id, flagIdsJson,
    pat.flag_count, pat.max_tier, pat.window_start, pat.window_end, pat.severity
  );
  return id;
}

// Run all detectors for a newly submitted flag and persist any patterns found.
// Detection is advisory and must never block flag submission, so failures are
// swallowed by the caller's try/catch as well as guarded here.
function runForFlag(db, opts) {
  const flaggerId = opts && opts.flaggerId;
  const flaggedId = opts && opts.flaggedId;
  const since = windowStartISO();
  const ids = [];
  if (flaggedId) {
    const ro = detectRepeatOffender(db, flaggedId, since);
    if (ro) ids.push(upsertPattern(db, ro));
    const es = detectEscalation(db, flaggedId, since);
    if (es) ids.push(upsertPattern(db, es));
  }
  if (flaggerId && flaggedId) {
    const re = detectRetaliation(db, flaggerId, flaggedId, since);
    if (re) ids.push(upsertPattern(db, re));
  }
  return ids.filter(Boolean);
}

module.exports = {
  WINDOW_DAYS,
  severityFor,
  detectRepeatOffender,
  detectEscalation,
  detectRetaliation,
  upsertPattern,
  runForFlag,
};
