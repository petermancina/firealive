// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Helper Pay Service
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════
//
// Recognition system for analysts who help peers via skill-share, mentoring,
// or knowledge-base contributions. Points accrue from peer ratings on real
// sessions and can be redeemed for org-configured rewards (time off, gift
// cards, donations).
//
// The ledger is append-only — every accrual, debit, and reversal is a new
// row, never an UPDATE or DELETE. balance_after is cached at insert so the
// per-user balance read is O(1) on the most recent row.
//
// Anti-gaming protections live here rather than in schema CHECK clauses
// because they require cross-table queries CHECK cannot express:
//
//   - Session-participant validation: the rater must be the session's
//     seeker_id and the rated user must be the session's helper_id.
//     Self-rating and third-party rating are both rejected at write.
//   - Minimum-duration gate: the session's duration_min must be at least
//     MIN_SESSION_DURATION_MIN. Defeats the "open session, immediately
//     close, immediately rate" pattern. Server-visible because
//     peer_sessions stores duration_min in plaintext.
//   - Daily accrual cap per analyst: above DAILY_CAP_POINTS in a single
//     UTC day from rating_received entries, additional ratings still
//     record (the recognition is preserved) but generate a 0-delta
//     ledger entry tagged with notes='daily_cap_reached' for audit.
//   - Yearly per-option redemption cap: max_per_user_per_year on each
//     redemption option blocks a single analyst from draining the budget
//     by repeated redemptions of the same option.
//   - Lazy debit on approval: balance is checked again at approval time,
//     not at request time, so a fraudulent or accidental request cannot
//     freeze a balance.
//
// Note on E2EE constraint. peer_messages stores only ciphertext and
// encrypted sender/recipient blobs, so the service cannot count messages
// by participant to detect "fake session, no real chat" abuse. The
// duration-based gate is the strongest server-visible signal we have.
// Deeper detection (off-line correlation of message timestamps with auth
// activity) lives in the helper_pay_fraud runbook, not in this service.
//
// Public API:
//
//   recordRating(sessionId, ratedByUserId, stars, comment?, helpfulnessTags?,
//                ipAddress?, userAgent?)
//     -> { ratingId, ledgerId | null }
//     The rater must be the session's seeker. The helper is derived from
//     the session record. Returns ledgerId=null when stars yields zero
//     points (1 or 2 stars), and a real ledgerId in every other case
//     including the daily-cap zero-delta entry.
//     R3h-pt2: ipAddress and userAgent are optional. When provided
//     (route handler passes req.ip and req.headers['user-agent']),
//     each is hashed via hashForFingerprint and stored in
//     rater_ip_hash / rater_device_hash for sock-puppet clustering.
//     When omitted (internal callers, tests), the columns store NULL
//     — pre-R3h-pt2 grandfathering pattern preserved.
//
//   getBalance(userId) -> integer
//     Always >= 0 in normal operation. Reads the latest ledger row's
//     balance_after, or 0 if no ledger entries exist yet.
//
//   getLedger(userId, { limit?, before? }) -> [{ id, delta, reason,
//     ref_type, ref_id, balance_after, notes, created_by, created_at }]
//     Default limit 50. before is an ISO datetime cursor for pagination.
//
//   requestRedemption(userId, optionId) -> { redemptionId, status }
//     status is 'requested' for approval-required options, 'approved' for
//     auto-approved options (with the ledger debit written in the same
//     transaction in that case).
//
//   decideRedemption(redemptionId, deciderUserId, approve, note?)
//     -> { redemptionId, status, ledgerId | null }
//     For approve=true: validates the user still has balance, writes the
//     ledger debit, stamps the redemption with ledger_id and approves it.
//     For approve=false: stamps decision_note and denies. Throws
//     REDEMPTION_NOT_PENDING if the redemption is not in 'requested'.
//
//   markFulfilled(redemptionId, fulfillerUserId) -> { redemptionId, status }
//     Stamps fulfilled_at and sets status='fulfilled'. Only valid on
//     approved redemptions. Caller is responsible for the operational
//     act (gift-card delivery, time-off entry); this just records the
//     completion.
//
//   reversePointsForFraud(originalLedgerId, reverserUserId, note)
//     -> { ledgerId }
//     Writes a new ledger entry with the negative of the original delta
//     and reason='reversal_fraud'. Used by incident responders during
//     the helper_pay_fraud runbook scenario. The original entry is left
//     in place; the audit trail is preserved.
//
// Throws structured errors:
//   - 'HELPER_INVALID_RATING' — stars out of range, rater not the seeker,
//     session not found, session too short
//   - 'HELPER_DUPLICATE_RATING' — session already rated by this rater
//   - 'HELPER_OPTION_INACTIVE' — redemption option not active
//   - 'HELPER_INSUFFICIENT_BALANCE' — not enough points (raised on
//     request for auto-approve options, on approval for approval-
//     required options)
//   - 'HELPER_YEARLY_CAP_REACHED' — user has hit max_per_user_per_year
//   - 'REDEMPTION_NOT_PENDING' — decideRedemption called on a redemption
//     not in 'requested' state
//   - 'REDEMPTION_NOT_APPROVED' — markFulfilled called on a redemption
//     not in 'approved' state
//   - 'LEDGER_ENTRY_NOT_FOUND' — reversePointsForFraud called on an
//     id that has no matching ledger row
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { getDb } = require('../db/init');
const { logger } = require('./logger');

// ── Earning rules ───────────────────────────────────────────────────────────
//
// Points awarded per qualifying rating, indexed by stars. 1 and 2 stars
// earn nothing (the recipient was unsatisfied). 3 stars earn a small
// recognition; 4 and 5 stars earn meaningful amounts. Tunable here only.
const POINTS_PER_STARS = {
  1: 0,
  2: 0,
  3: 5,
  4: 10,
  5: 15,
};

// Minimum session duration (in minutes) for a rating to qualify for
// points. Defeats the open-immediately-rate fake-session pattern.
const MIN_SESSION_DURATION_MIN = 3;

// Maximum points an analyst can earn from rating_received entries in a
// single UTC day. Above this, additional ratings still record and the
// peer_session_ratings row is still inserted (the recognition is
// preserved), but the ledger entry is zero-delta with a daily_cap note.
const DAILY_CAP_POINTS = 60;

// ── R3h-pt2: Sock-puppet detection thresholds ───────────────────────────────
//
// A rating is flagged for lead review if its rater_ip_hash OR
// rater_device_hash matches at least SOCKPUPPET_CLUSTER_THRESHOLD other
// ratings against the SAME rated_user_id within the last
// SOCKPUPPET_WINDOW_DAYS days. The thresholds are conservative defaults
// — tight enough to catch a single attacker grinding fake ratings from
// one machine, loose enough not to flag normal small-team behavior
// where 3 analysts genuinely rate the same helper from a shared office
// network. Tunable here; could be made per-team via team_config in a
// later phase.
const SOCKPUPPET_CLUSTER_THRESHOLD = 3;
const SOCKPUPPET_WINDOW_DAYS = 7;

// ── R3h: Leaderboard cache (in-memory, write-through invalidated) ───────────
//
// Leaderboard aggregation is O(n) over helper_points_ledger and the
// per-user ratings subqueries. At v1.0.34's single-SOC scale the query
// is fast, but the MC peersupport tab and the GD push pipeline both
// call it on a recurring basis (peersupport tab on every render, push
// pipeline every 15 min). A 5-minute in-memory cache keyed by limit
// keeps the leaderboard responsive without serving stale data after a
// known-changing event.
//
// Write-through invalidation: bustLeaderboardCache() is called from
// recordRating (new rating affects sessions_count + avg_rating + points),
// reversePointsForFraud (negative-delta ledger entry shifts ranking),
// and setVisibility (opt-in/out changes leaderboard membership). Between
// those events the cache holds steady; after any one, the next read
// recomputes from the DB.
//
// The cache is a Map<number, { data, expiresAt }> keyed by limit so
// getLeaderboard(10) (MC tab default) and getLeaderboard(50) (GD push
// payload) cache independently. bust() clears all keyed entries.

const LEADERBOARD_CACHE_TTL_MS = 5 * 60 * 1000;  // 5 minutes
const leaderboardCache = new Map();

function bustLeaderboardCache() {
  leaderboardCache.clear();
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function newId() {
  return crypto.randomBytes(16).toString('hex');
}

function makeError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

// R3h-pt2: SHA-256 hash truncated to 16 hex chars (64 bits). Used for
// privacy-preserving rater fingerprint clustering. The truncation
// gives ample entropy for sock-puppet detection at v1.0.34's scale
// (false-collision probability is orders of magnitude below the
// detection threshold) while avoiding the bloat of storing full
// 64-char hashes on every rating row.
//
// Returns null on null/empty input rather than hashing the empty
// string. This matters because if every NULL-input rating hashed
// to a stable empty-string-hash value, ALL pre-R3h-pt2 rows would
// cluster together and trigger false sock-puppet flags. Returning
// null lets the C8 detection logic distinguish "no fingerprint
// data" from "fingerprint computed and stored."
function hashForFingerprint(input) {
  if (!input || typeof input !== 'string') return null;
  return crypto.createHash('sha256').update(input).digest('hex').slice(0, 16);
}

// Reads the latest ledger row's balance_after for a user. Returns 0 if
// no entries exist. Caller must pass an open db handle.
function getBalanceInternal(db, userId) {
  const row = db.prepare(
    `SELECT balance_after FROM helper_points_ledger
       WHERE user_id = ?
       ORDER BY created_at DESC, id DESC
       LIMIT 1`
  ).get(userId);
  return row ? row.balance_after : 0;
}

// Inserts a ledger entry. Caller is responsible for transaction context.
// Returns { id, balanceAfter }.
function appendLedger(db, { userId, delta, reason, refType, refId, notes, createdBy }) {
  const id = newId();
  const balanceBefore = getBalanceInternal(db, userId);
  const balanceAfter = balanceBefore + delta;
  db.prepare(
    `INSERT INTO helper_points_ledger
       (id, user_id, delta, reason, ref_type, ref_id, balance_after, notes, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    userId,
    delta,
    reason,
    refType || null,
    refId || null,
    balanceAfter,
    notes || null,
    createdBy || null
  );
  return { id, balanceAfter };
}

// Sum of rating_received deltas earned by a user since UTC midnight.
function pointsEarnedToday(db, userId) {
  const row = db.prepare(
    `SELECT COALESCE(SUM(delta), 0) AS total
       FROM helper_points_ledger
       WHERE user_id = ?
         AND reason = 'rating_received'
         AND created_at >= datetime('now', 'start of day')`
  ).get(userId);
  return row ? row.total : 0;
}

// R3h-pt2: Sock-puppet detection. Called from recordRating after the
// rating row has been inserted. Queries peer_session_ratings for OTHER
// ratings against the SAME rated_user_id within the last
// SOCKPUPPET_WINDOW_DAYS days that share rater_ip_hash OR rater_device_
// hash. If either cluster's size (excluding the just-inserted row) is
// >= SOCKPUPPET_CLUSTER_THRESHOLD - 1, the current row is flagged for
// lead review.
//
// Threshold logic: the build plan calls for "3+ ratings from same hash
// cluster within 7 days against same target." That means INCLUDING the
// just-inserted rating, 3 total in the cluster. Since the query
// excludes the current row (id != currentRatingId), we look for >= 2
// other rows.
//
// Returns null if not flagged; { reason: 'ip_cluster'|'device_cluster'|
// 'both', ipClusterSize, deviceClusterSize } if flagged. Updates the
// peer_session_ratings row to set flagged_sockpuppet=1, flagged_at=now,
// flagged_reason=<reason> when flagged.
//
// Rows with NULL ip_hash and NULL device_hash (pre-R3h-pt2 grandfathered
// rows, or callers that didn't supply fingerprints) are never flagged
// because the hash comparison filters return zero matches against NULL.
//
// Caller must pass an open db handle. Detection runs in the same DB
// session as the rating insert.
function detectSockPuppet(db, currentRatingId, ratedUserId, raterIpHash, raterDeviceHash) {
  const windowClause = `datetime('now', '-${SOCKPUPPET_WINDOW_DAYS} days')`;
  const otherThreshold = SOCKPUPPET_CLUSTER_THRESHOLD - 1;

  let ipClusterSize = 0;
  let deviceClusterSize = 0;

  if (raterIpHash) {
    const ipRow = db.prepare(
      `SELECT COUNT(*) AS n FROM peer_session_ratings
         WHERE rated_user_id = ?
           AND id != ?
           AND rater_ip_hash = ?
           AND created_at >= ${windowClause}`
    ).get(ratedUserId, currentRatingId, raterIpHash);
    ipClusterSize = ipRow ? ipRow.n : 0;
  }

  if (raterDeviceHash) {
    const deviceRow = db.prepare(
      `SELECT COUNT(*) AS n FROM peer_session_ratings
         WHERE rated_user_id = ?
           AND id != ?
           AND rater_device_hash = ?
           AND created_at >= ${windowClause}`
    ).get(ratedUserId, currentRatingId, raterDeviceHash);
    deviceClusterSize = deviceRow ? deviceRow.n : 0;
  }

  const ipExceeds = ipClusterSize >= otherThreshold;
  const deviceExceeds = deviceClusterSize >= otherThreshold;

  if (!ipExceeds && !deviceExceeds) {
    return null;
  }

  const reason = ipExceeds && deviceExceeds
    ? 'both'
    : ipExceeds ? 'ip_cluster' : 'device_cluster';

  db.prepare(
    `UPDATE peer_session_ratings
        SET flagged_sockpuppet = 1,
            flagged_at = datetime('now'),
            flagged_reason = ?
      WHERE id = ?`
  ).run(reason, currentRatingId);

  logger.info('Sock-puppet rating flagged', {
    ratingId: currentRatingId,
    ratedUserId,
    reason,
    ipClusterSize,
    deviceClusterSize,
  });

  return { reason, ipClusterSize, deviceClusterSize };
}

// ── Public API: ratings ─────────────────────────────────────────────────────

function recordRating(sessionId, ratedByUserId, stars, comment, helpfulnessTags, ipAddress, userAgent) {
  if (typeof stars !== 'number' || !Number.isInteger(stars) || stars < 1 || stars > 5) {
    throw makeError('HELPER_INVALID_RATING', 'stars must be an integer between 1 and 5');
  }

  // R3h-pt2: hash the request fingerprint before opening the DB. Null
  // when the caller doesn't supply the inputs (internal callers, tests);
  // matches the grandfathering of pre-R3h-pt2 rows where the columns
  // existed but no one wrote to them.
  const raterIpHash = hashForFingerprint(ipAddress);
  const raterDeviceHash = hashForFingerprint(userAgent);

  const db = getDb();
  try {
    const session = db.prepare(
      `SELECT id, helper_id, seeker_id, duration_min FROM peer_sessions WHERE id = ?`
    ).get(sessionId);
    if (!session) {
      throw makeError('HELPER_INVALID_RATING', 'session not found');
    }
    if (session.seeker_id !== ratedByUserId) {
      throw makeError('HELPER_INVALID_RATING', 'rater must be the session seeker');
    }
    if (!session.helper_id || session.helper_id === ratedByUserId) {
      throw makeError('HELPER_INVALID_RATING', 'session has no distinct helper to rate');
    }
    if ((session.duration_min || 0) < MIN_SESSION_DURATION_MIN) {
      throw makeError('HELPER_INVALID_RATING',
        `session must be at least ${MIN_SESSION_DURATION_MIN} minutes long to be rated for points`);
    }

    const ratedUserId = session.helper_id;
    const ratingId = newId();
    const tagsJson = JSON.stringify(Array.isArray(helpfulnessTags) ? helpfulnessTags : []);

    try {
      db.prepare(
        `INSERT INTO peer_session_ratings
           (id, session_id, rated_by_id, rated_user_id, stars, comment, helpfulness_tags,
            rater_ip_hash, rater_device_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(ratingId, sessionId, ratedByUserId, ratedUserId, stars, comment || null, tagsJson,
        raterIpHash, raterDeviceHash);
    } catch (err) {
      if (err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        throw makeError('HELPER_DUPLICATE_RATING', 'session already rated by this rater');
      }
      throw err;
    }

    // R3h-pt2: run sock-puppet detection against the just-inserted row.
    // If flagged, the row is updated in-place inside detectSockPuppet
    // (flagged_sockpuppet=1 + flagged_at + flagged_reason). The points
    // ledger entry is still written below — the leaderboard query
    // excludes flagged rating contributions until lead review, and the
    // lead's review queue (C8b/c) lets them confirm fraud (triggers
    // reversePointsForFraud) or dismiss (clears flag, leaderboard
    // re-includes naturally).
    detectSockPuppet(db, ratingId, ratedUserId, raterIpHash, raterDeviceHash);

    // Award points (if stars yields any) with daily-cap clamping.
    const earned = POINTS_PER_STARS[stars];
    if (earned <= 0) {
      bustLeaderboardCache();
      return { ratingId, ledgerId: null };
    }
    const earnedToday = pointsEarnedToday(db, ratedUserId);
    const remaining = Math.max(0, DAILY_CAP_POINTS - earnedToday);
    const actualDelta = Math.min(earned, remaining);
    const notes = actualDelta < earned
      ? `daily_cap_${DAILY_CAP_POINTS}_after_${earnedToday}_today`
      : null;
    const { id: ledgerId } = appendLedger(db, {
      userId: ratedUserId,
      delta: actualDelta,
      reason: 'rating_received',
      refType: 'peer_session_rating',
      refId: ratingId,
      notes,
    });
    bustLeaderboardCache();
    return { ratingId, ledgerId };
  } finally {
    db.close();
  }
}

// ── Public API: balance and ledger reads ────────────────────────────────────

function getBalance(userId) {
  const db = getDb();
  try {
    return getBalanceInternal(db, userId);
  } finally {
    db.close();
  }
}

function getLedger(userId, { limit = 50, before } = {}) {
  const db = getDb();
  try {
    const cap = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 200);
    if (before) {
      return db.prepare(
        `SELECT id, delta, reason, ref_type, ref_id, balance_after, notes, created_by, created_at
           FROM helper_points_ledger
           WHERE user_id = ? AND created_at < ?
           ORDER BY created_at DESC, id DESC
           LIMIT ?`
      ).all(userId, before, cap);
    }
    return db.prepare(
      `SELECT id, delta, reason, ref_type, ref_id, balance_after, notes, created_by, created_at
         FROM helper_points_ledger
         WHERE user_id = ?
         ORDER BY created_at DESC, id DESC
         LIMIT ?`
    ).all(userId, cap);
  } finally {
    db.close();
  }
}

// ── Public API: redemption lifecycle ────────────────────────────────────────

function requestRedemption(userId, optionId) {
  const db = getDb();
  try {
    const option = db.prepare(
      `SELECT id, name, cost_points, redemption_type, approval_required,
              active, max_per_user_per_year
         FROM helper_redemption_options WHERE id = ?`
    ).get(optionId);
    if (!option || !option.active) {
      throw makeError('HELPER_OPTION_INACTIVE', 'redemption option is not active');
    }

    // Yearly cap (count approved + fulfilled in last 365 days for this user+option).
    if (option.max_per_user_per_year !== null && option.max_per_user_per_year !== undefined) {
      const usedRow = db.prepare(
        `SELECT COUNT(*) AS used
           FROM helper_redemptions
           WHERE user_id = ? AND option_id = ?
             AND status IN ('approved', 'fulfilled')
             AND requested_at >= datetime('now', '-365 days')`
      ).get(userId, optionId);
      if (usedRow.used >= option.max_per_user_per_year) {
        throw makeError('HELPER_YEARLY_CAP_REACHED',
          `yearly redemption cap (${option.max_per_user_per_year}) reached for this option`);
      }
    }

    const redemptionId = newId();

    if (!option.approval_required) {
      // Auto-approve branch — debit immediately in transaction.
      const balance = getBalanceInternal(db, userId);
      if (balance < option.cost_points) {
        throw makeError('HELPER_INSUFFICIENT_BALANCE',
          `not enough points: balance ${balance}, cost ${option.cost_points}`);
      }
      const txn = db.transaction(() => {
        db.prepare(
          `INSERT INTO helper_redemptions
             (id, user_id, option_id, cost_points, status, decided_at, decided_by)
             VALUES (?, ?, ?, ?, 'approved', datetime('now'), ?)`
        ).run(redemptionId, userId, optionId, option.cost_points, userId);
        const { id: ledgerId } = appendLedger(db, {
          userId,
          delta: -option.cost_points,
          reason: 'redemption',
          refType: 'redemption',
          refId: redemptionId,
        });
        db.prepare(`UPDATE helper_redemptions SET ledger_id = ? WHERE id = ?`)
          .run(ledgerId, redemptionId);
      });
      txn();
      return { redemptionId, status: 'approved' };
    }

    // Approval-required branch — request only, defer balance check to approval.
    db.prepare(
      `INSERT INTO helper_redemptions
         (id, user_id, option_id, cost_points, status)
         VALUES (?, ?, ?, ?, 'requested')`
    ).run(redemptionId, userId, optionId, option.cost_points);
    return { redemptionId, status: 'requested' };
  } finally {
    db.close();
  }
}

function decideRedemption(redemptionId, deciderUserId, approve, note) {
  const db = getDb();
  try {
    const redemption = db.prepare(
      `SELECT id, user_id, option_id, cost_points, status
         FROM helper_redemptions WHERE id = ?`
    ).get(redemptionId);
    if (!redemption) {
      throw makeError('REDEMPTION_NOT_PENDING', 'redemption not found');
    }
    if (redemption.status !== 'requested') {
      throw makeError('REDEMPTION_NOT_PENDING',
        `redemption is in '${redemption.status}', not 'requested'`);
    }

    if (!approve) {
      db.prepare(
        `UPDATE helper_redemptions
            SET status = 'denied', decided_at = datetime('now'),
                decided_by = ?, decision_note = ?
            WHERE id = ?`
      ).run(deciderUserId, note || null, redemptionId);
      return { redemptionId, status: 'denied', ledgerId: null };
    }

    const balance = getBalanceInternal(db, redemption.user_id);
    if (balance < redemption.cost_points) {
      throw makeError('HELPER_INSUFFICIENT_BALANCE',
        `not enough points to approve: balance ${balance}, cost ${redemption.cost_points}`);
    }

    let ledgerId;
    const txn = db.transaction(() => {
      const result = appendLedger(db, {
        userId: redemption.user_id,
        delta: -redemption.cost_points,
        reason: 'redemption',
        refType: 'redemption',
        refId: redemptionId,
        createdBy: deciderUserId,
      });
      ledgerId = result.id;
      db.prepare(
        `UPDATE helper_redemptions
            SET status = 'approved', decided_at = datetime('now'),
                decided_by = ?, decision_note = ?, ledger_id = ?
            WHERE id = ?`
      ).run(deciderUserId, note || null, ledgerId, redemptionId);
    });
    txn();
    return { redemptionId, status: 'approved', ledgerId };
  } finally {
    db.close();
  }
}

function markFulfilled(redemptionId, fulfillerUserId) {
  const db = getDb();
  try {
    const redemption = db.prepare(
      `SELECT status FROM helper_redemptions WHERE id = ?`
    ).get(redemptionId);
    if (!redemption) {
      throw makeError('REDEMPTION_NOT_APPROVED', 'redemption not found');
    }
    if (redemption.status !== 'approved') {
      throw makeError('REDEMPTION_NOT_APPROVED',
        `redemption is in '${redemption.status}', not 'approved'`);
    }
    db.prepare(
      `UPDATE helper_redemptions
          SET status = 'fulfilled', fulfilled_at = datetime('now')
          WHERE id = ?`
    ).run(redemptionId);
    logger.info('Helper Pay redemption fulfilled', { redemptionId, fulfillerUserId });
    return { redemptionId, status: 'fulfilled' };
  } finally {
    db.close();
  }
}

// ── Public API: fraud reversal ──────────────────────────────────────────────

function reversePointsForFraud(originalLedgerId, reverserUserId, note) {
  const db = getDb();
  try {
    const original = db.prepare(
      `SELECT id, user_id, delta, ref_type, ref_id
         FROM helper_points_ledger WHERE id = ?`
    ).get(originalLedgerId);
    if (!original) {
      throw makeError('LEDGER_ENTRY_NOT_FOUND', 'original ledger entry not found');
    }
    const { id } = appendLedger(db, {
      userId: original.user_id,
      delta: -original.delta,
      reason: 'reversal_fraud',
      refType: 'helper_points_ledger',
      refId: original.id,
      notes: note || `reversal of ${original.delta} from ledger ${original.id}`,
      createdBy: reverserUserId,
    });
    logger.info('Helper Pay points reversed for fraud', {
      reverserUserId,
      originalLedgerId,
      reversalLedgerId: id,
      delta: -original.delta,
    });
    bustLeaderboardCache();
    return { ledgerId: id };
  } finally {
    db.close();
  }
}

// ── R3h Public API: leaderboard (opt-in-gated, cached) ──────────────────────
//
// Returns the top N opted-in active analysts sorted by current points
// balance DESC. The lead reviews this list on the MC peersupport tab;
// the GD push pipeline (C9) also calls this function (with a larger
// limit) to build the periodic leaderboard summary payload.
//
// Filters:
//   - leaderboard_opt_in = 1 (privacy invariant I1)
//   - active = 1 (offboarded users hidden)
//   - role = 'analyst' (recognition surface is for analysts; leads and
//     admins reviewing themselves on a leaderboard would be off-purpose)
//   - balance > 0 (zero-scoring entries don't belong on a leaderboard)
//
// Returns: [{ user_id, name, pseudonym, points, sessions_count, avg_rating }]
//
// The query uses a CTE (latest_balance) to derive each user's current
// balance from the most recent ledger row, then joins users and runs
// two correlated subqueries for sessions_count and avg_rating. SQLite's
// query planner handles this efficiently with the existing
// idx_peer_ratings_helper index.

function getLeaderboard(limit = 10) {
  const lim = Math.max(1, Math.min(100, Math.floor(Number(limit) || 10)));
  const now = Date.now();
  const cached = leaderboardCache.get(lim);
  if (cached && cached.expiresAt > now) {
    return cached.data;
  }
  const db = getDb();
  try {
    // R3h-pt2: the leaderboard EXCLUDES contributions from currently-
    // flagged ratings. Three subquery filters cooperate:
    //
    //   adjusted_points: SUMs ledger deltas, but ledger entries that
    //     reference a flagged peer_session_rating are excluded.
    //     Ledger entries from other reason types (redemption, fraud
    //     reversal, admin adjustment) pass through unaffected.
    //
    //   sessions_count subquery: COUNTs DISTINCT session_id where
    //     stars >= 4 AND flagged_sockpuppet = 0.
    //
    //   avg_rating subquery: AVGs stars where flagged_sockpuppet = 0.
    //
    // Net effect: an analyst whose only ratings are flagged sees their
    // points = 0, sessions = 0, avg = null — they fall out of the
    // leaderboard via the points > 0 WHERE filter below.
    //
    // When a lead dismisses a flag (C8b), flagged_sockpuppet flips back
    // to 0 for that row, the cache busts, and the next read includes
    // the row's contribution again. When a lead confirms fraud,
    // reversePointsForFraud writes a negative-delta ledger entry; the
    // original rating stays flagged forever (audit history) so its
    // points contribution stays excluded.
    const rows = db.prepare(`
      WITH adjusted_points AS (
        SELECT lp.user_id, COALESCE(SUM(lp.delta), 0) AS points
          FROM helper_points_ledger lp
          LEFT JOIN peer_session_ratings psr
            ON lp.ref_type = 'peer_session_rating' AND lp.ref_id = psr.id
         WHERE psr.flagged_sockpuppet IS NULL OR psr.flagged_sockpuppet = 0
         GROUP BY lp.user_id
      )
      SELECT
        u.id AS user_id,
        u.name,
        u.pseudonym,
        COALESCE(ap.points, 0) AS points,
        COALESCE((
          SELECT COUNT(DISTINCT session_id)
            FROM peer_session_ratings
           WHERE rated_user_id = u.id
             AND stars >= 4
             AND flagged_sockpuppet = 0
        ), 0) AS sessions_count,
        (
          SELECT ROUND(AVG(stars), 2)
            FROM peer_session_ratings
           WHERE rated_user_id = u.id
             AND flagged_sockpuppet = 0
        ) AS avg_rating
      FROM users u
      LEFT JOIN adjusted_points ap ON ap.user_id = u.id
      WHERE u.leaderboard_opt_in = 1
        AND u.active = 1
        AND u.role = 'analyst'
        AND COALESCE(ap.points, 0) > 0
      ORDER BY points DESC, sessions_count DESC, u.name ASC
      LIMIT ?
    `).all(lim);
    leaderboardCache.set(lim, {
      data: rows,
      expiresAt: now + LEADERBOARD_CACHE_TTL_MS,
    });
    return rows;
  } finally {
    db.close();
  }
}

// ── R3h Public API: team scores (lead operational view, NOT opt-in-gated) ──
//
// Returns ALL active analysts with their current Helper Pay state,
// regardless of leaderboard_opt_in. This is the lead's operational
// view for compensation discussions, payroll reconciliation, and
// periodic team reviews — analogous to how the existing Helper Pay
// admin tab already exposes user-level data (pending redemptions,
// ledger entries) without opt-in gating.
//
// Privacy invariant I5: this surface bypasses opt-in because it's a
// lead-operational surface, not a recognition leaderboard. The opt-in
// flag is included in the response so the lead can see who is and
// isn't on the recognition leaderboard (purely informational; the
// lead cannot toggle it on behalf of an analyst).
//
// Returns: [{ user_id, username, name, pseudonym, role, leaderboard_opt_in,
//   points, sessions_count, avg_rating }]
//
// Not cached: this surface is lead-only, called only when the lead
// opens the peersupport tab full-roster section, low call volume.

function getTeamScores() {
  const db = getDb();
  try {
    return db.prepare(`
      WITH latest_balance AS (
        SELECT user_id, balance_after,
               ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY created_at DESC, id DESC) AS rn
          FROM helper_points_ledger
      )
      SELECT
        u.id AS user_id,
        u.username,
        u.name,
        u.pseudonym,
        u.role,
        u.leaderboard_opt_in,
        COALESCE(lb.balance_after, 0) AS points,
        COALESCE((
          SELECT COUNT(DISTINCT session_id)
            FROM peer_session_ratings
           WHERE rated_user_id = u.id AND stars >= 4
        ), 0) AS sessions_count,
        (
          SELECT ROUND(AVG(stars), 2)
            FROM peer_session_ratings
           WHERE rated_user_id = u.id
        ) AS avg_rating
      FROM users u
      LEFT JOIN latest_balance lb ON lb.user_id = u.id AND lb.rn = 1
      WHERE u.active = 1
        AND u.role = 'analyst'
      ORDER BY points DESC, u.name ASC
    `).all();
  } finally {
    db.close();
  }
}

// ── R3h Public API: visibility (per-analyst opt-in self-control) ────────────
//
// getVisibility(userId) reads the current opt-in state for the AC
// toggle to render its initial UI state on mount.
//
// setVisibility(userId, optIn) writes the new opt-in state. Privacy
// invariant I2: only the analyst can flip their own row. The route
// handler in C3 must pass req.user.id as userId; the service does
// NOT have a notion of "set on behalf of someone else." That mode
// does not exist in the API.
//
// Both functions throw USER_NOT_FOUND if the userId has no row.
// setVisibility busts the leaderboard cache after a successful write
// so the leaderboard reflects the new membership immediately.

function getVisibility(userId) {
  const db = getDb();
  try {
    const row = db.prepare(
      `SELECT leaderboard_opt_in FROM users WHERE id = ?`
    ).get(userId);
    if (!row) {
      throw makeError('USER_NOT_FOUND', 'user not found');
    }
    return { optIn: row.leaderboard_opt_in === 1 };
  } finally {
    db.close();
  }
}

function setVisibility(userId, optIn) {
  const value = optIn ? 1 : 0;
  const db = getDb();
  try {
    const result = db.prepare(
      `UPDATE users SET leaderboard_opt_in = ? WHERE id = ?`
    ).run(value, userId);
    if (result.changes === 0) {
      throw makeError('USER_NOT_FOUND', 'user not found');
    }
    bustLeaderboardCache();
    logger.info('Leaderboard opt-in flipped', { userId, optIn: value });
    return { optIn: value === 1 };
  } finally {
    db.close();
  }
}

// ── R3h-pt2 Public API: sock-puppet review queue ────────────────────────────
//
// getFlaggedRatings() returns rows where flagged_sockpuppet = 1, with
// helper and rater identity (pseudonym preferred for both per privacy
// invariant I4), cluster sizes for context, and the associated ledger
// entry id (needed by decideFlaggedRating to reverse points on confirm).
//
// decideFlaggedRating(ratingId, deciderUserId, confirmFraud, note)
//   confirmFraud = true:  finds the ledger entry tied to this rating
//                         via ref_type='peer_session_rating' AND
//                         ref_id=ratingId, then calls
//                         reversePointsForFraud(ledgerId, deciderUserId,
//                         note). The peer_session_ratings row stays
//                         flagged forever (audit history); the negative
//                         ledger entry permanently cancels the points.
//   confirmFraud = false: UPDATEs the rating row to clear the flag
//                         (flagged_sockpuppet=0, flagged_at=null,
//                         flagged_reason=null). Points stay; leaderboard
//                         re-includes the row on next cache miss.
//
// Both paths bust the leaderboard cache. Both paths log via logger.info.
// The route handler in C8b writes an explicit audit_log event_type
// (LEADERBOARD_SOCKPUPPET_CONFIRMED or LEADERBOARD_SOCKPUPPET_DISMISSED)
// in addition to the auditMiddleware's automatic API-action row.

function getFlaggedRatings() {
  const db = getDb();
  try {
    return db.prepare(`
      SELECT
        psr.id AS rating_id,
        psr.session_id,
        psr.rated_user_id,
        ru.name AS rated_user_name,
        ru.pseudonym AS rated_user_pseudonym,
        psr.rated_by_id,
        bu.name AS rated_by_name,
        bu.pseudonym AS rated_by_pseudonym,
        psr.stars,
        psr.comment,
        psr.created_at,
        psr.flagged_at,
        psr.flagged_reason,
        (SELECT id FROM helper_points_ledger
           WHERE ref_type = 'peer_session_rating' AND ref_id = psr.id
           ORDER BY created_at DESC LIMIT 1) AS ledger_id,
        (SELECT COUNT(*) FROM peer_session_ratings other
           WHERE other.rated_user_id = psr.rated_user_id
             AND other.id != psr.id
             AND other.rater_ip_hash IS NOT NULL
             AND other.rater_ip_hash = psr.rater_ip_hash
             AND other.created_at >= datetime('now', '-${SOCKPUPPET_WINDOW_DAYS} days')
        ) AS ip_cluster_size,
        (SELECT COUNT(*) FROM peer_session_ratings other
           WHERE other.rated_user_id = psr.rated_user_id
             AND other.id != psr.id
             AND other.rater_device_hash IS NOT NULL
             AND other.rater_device_hash = psr.rater_device_hash
             AND other.created_at >= datetime('now', '-${SOCKPUPPET_WINDOW_DAYS} days')
        ) AS device_cluster_size
      FROM peer_session_ratings psr
      JOIN users ru ON ru.id = psr.rated_user_id
      JOIN users bu ON bu.id = psr.rated_by_id
      WHERE psr.flagged_sockpuppet = 1
      ORDER BY psr.flagged_at DESC
    `).all();
  } finally {
    db.close();
  }
}

function decideFlaggedRating(ratingId, deciderUserId, confirmFraud, note) {
  const db = getDb();
  try {
    const rating = db.prepare(
      `SELECT id, flagged_sockpuppet, rated_user_id
         FROM peer_session_ratings WHERE id = ?`
    ).get(ratingId);
    if (!rating) {
      throw makeError('RATING_NOT_FOUND', 'rating not found');
    }
    if (rating.flagged_sockpuppet !== 1) {
      throw makeError('RATING_NOT_FLAGGED', 'rating is not currently flagged');
    }

    if (confirmFraud) {
      // Find the ledger entry tied to this rating, if any. A rating
      // with stars 1-2 has no ledger entry (POINTS_PER_STARS yields 0
      // and recordRating returns early); confirming fraud in that case
      // just leaves the flag set (no points to reverse).
      const ledger = db.prepare(
        `SELECT id FROM helper_points_ledger
           WHERE ref_type = 'peer_session_rating' AND ref_id = ?
           ORDER BY created_at DESC LIMIT 1`
      ).get(ratingId);
      let reversalLedgerId = null;
      if (ledger) {
        // reversePointsForFraud opens its own DB handle; the close()
        // call in our finally below releases this handle separately.
        // Two separate DB handles is fine for SQLite (which serializes
        // anyway), and matches the existing pattern.
        db.close();
        const reversed = reversePointsForFraud(ledger.id, deciderUserId,
          note || `sock-puppet confirmed: rating ${ratingId}`);
        reversalLedgerId = reversed.ledgerId;
        // Re-open is unnecessary; we've nothing more to write in this
        // path. Return immediately.
        logger.info('Sock-puppet rating confirmed as fraud', {
          ratingId, deciderUserId, originalLedgerId: ledger.id,
          reversalLedgerId,
        });
        bustLeaderboardCache();
        return { ratingId, confirmFraud: true, reversalLedgerId };
      }
      // No ledger entry to reverse; just bust cache + log.
      bustLeaderboardCache();
      logger.info('Sock-puppet rating confirmed as fraud (no points to reverse)',
        { ratingId, deciderUserId });
      return { ratingId, confirmFraud: true, reversalLedgerId: null };
    }

    // Dismiss path: clear the flag, points stay, leaderboard re-includes.
    db.prepare(
      `UPDATE peer_session_ratings
          SET flagged_sockpuppet = 0,
              flagged_at = NULL,
              flagged_reason = NULL
        WHERE id = ?`
    ).run(ratingId);
    bustLeaderboardCache();
    logger.info('Sock-puppet rating flag dismissed', {
      ratingId, deciderUserId, note: note || null,
    });
    return { ratingId, confirmFraud: false };
  } finally {
    // db.close() may have already been called in the confirmFraud +
    // ledger path above. Calling close() twice on a better-sqlite3
    // handle is a no-op (the second call sees it already closed) but
    // wrapping defensively keeps the cleanup robust.
    try { db.close(); } catch (_e) { /* already closed */ }
  }
}

module.exports = {
  recordRating,
  getBalance,
  getLedger,
  requestRedemption,
  decideRedemption,
  markFulfilled,
  reversePointsForFraud,
  // R3h additions
  getLeaderboard,
  getTeamScores,
  getVisibility,
  setVisibility,
  bustLeaderboardCache,
  // R3h-pt2 additions
  getFlaggedRatings,
  decideFlaggedRating,
  // Tunable constants exported for visibility and tests.
  POINTS_PER_STARS,
  MIN_SESSION_DURATION_MIN,
  DAILY_CAP_POINTS,
  LEADERBOARD_CACHE_TTL_MS,
  SOCKPUPPET_CLUSTER_THRESHOLD,
  SOCKPUPPET_WINDOW_DAYS,
};
