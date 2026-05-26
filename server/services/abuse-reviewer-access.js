'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — abuse-review access gate (U3 PR E)
//
// canReview() is the single decision point for who may read an abuse case. The
// review API (E4) calls it on EVERY read; no review route may bypass it. It is a
// PURE function — it performs no I/O — so the route is responsible for fetching
// the reviewer, the flag, and the reviewer's assignments and passing them in.
// Keeping it pure makes the access rules exhaustively unit-testable offline.
//
// Hard rules, evaluated in order (first failure wins):
//
//   1. ROLE — the user MUST be an abuse_reviewer. Every other role (analyst,
//      lead, admin, developer) is denied here, and again at the route. Because a
//      user's role is single-valued, requiring abuse_reviewer ALSO guarantees the
//      reviewer is never a team lead — that is how the "no team lead reviews
//      abuse" rule is enforced cryptographically-adjacent at the data layer.
//
//   2. NOT A PARTY — the reviewer must be neither the flagger nor the accused.
//      For a lead_chat case the involved lead is one of those two parties, so
//      this is also what prevents a lead from reviewing a case they are part of.
//
//   3. SCOPE — an assignment must cover the case:
//        - 'all'  -> every case.
//        - 'team' -> assignment.team_id is among the case's team ids
//                    (flag.teamIds, supplied by the route; empty until a team
//                    membership model exists, so team-scoped grants simply do
//                    not match yet — 'all' and 'case' work today).
//        - 'case' -> assignment.flag_id === this flag's id.
//
// Returns { allowed: boolean, reason: string }. `reason` is a stable machine
// code suitable for audit logging; it never carries case content.
// ═══════════════════════════════════════════════════════════════════════════════

const REVIEWER_ROLE = 'abuse_reviewer';

function deny(reason) {
  return { allowed: false, reason };
}

function canReview({ reviewer, flag, assignments } = {}) {
  // (1) role — must be exactly an abuse_reviewer (so never a lead/admin/etc.)
  if (!reviewer || typeof reviewer !== 'object' || !reviewer.id) {
    return deny('no_reviewer');
  }
  if (reviewer.role !== REVIEWER_ROLE) {
    return deny('not_an_abuse_reviewer');
  }
  // A disabled reviewer account may not review (defense in depth; the route's
  // auth should already exclude inactive accounts). Only an explicit 0/false
  // denies — an absent flag is treated as active.
  if (reviewer.active === 0 || reviewer.active === false) {
    return deny('reviewer_inactive');
  }

  if (!flag || typeof flag !== 'object' || !flag.id) {
    return deny('no_case');
  }

  // (2) not a party — neither the flagger nor the accused
  if (reviewer.id === flag.flagger_user_id || reviewer.id === flag.flagged_user_id) {
    return deny('party_to_case');
  }

  // (3) scope — at least one assignment must cover this case
  const list = Array.isArray(assignments) ? assignments : [];
  const teamIds = Array.isArray(flag.teamIds) ? flag.teamIds : [];
  const covered = list.some((a) => {
    if (!a || typeof a !== 'object') return false;
    if (a.scope === 'all') return true;
    if (a.scope === 'case') return !!a.flag_id && a.flag_id === flag.id;
    if (a.scope === 'team') return !!a.team_id && teamIds.includes(a.team_id);
    return false;
  });
  if (!covered) {
    return deny('out_of_scope');
  }

  return { allowed: true, reason: 'ok' };
}

module.exports = { canReview, REVIEWER_ROLE };
