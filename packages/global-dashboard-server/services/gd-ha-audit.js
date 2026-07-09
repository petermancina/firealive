// FIREALIVE GLOBAL DASHBOARD -- HA audit + SIEM funnel (B6d)
//
// One place where an HA lifecycle event is recorded and, when appropriate, delivered.
// The Global Dashboard's equivalent of the Regional Server's middleware/audit.js
// auditLogOn: append the row through the connection the caller is holding, then stream
// the event to the operator's SIEM only when that connection IS the durable chain.
//
// Why a shared module rather than a copy in each HA module: gd-ha-failover,
// gd-ha-pairing, gd-ha-peer-link, and routes/gd-ha.js all emit HA events, and this
// phase has already paid for duplicated logic drifting apart -- two peer-response
// contracts in one subsystem produced a split-brain in the drill meant to prevent one.
// A severity table copied four times would drift the same way.
//
// The gate is isLiveChain(db), not "was a connection injected". In production every
// caller supplies a live handle, so that proxy would suppress real events. A promotion,
// a self-fence, a pairing, or a rejected peer certificate exercised against a hermetic
// clone therefore records where the change happened and emits NOTHING: a drill can
// neither forge a row into the tamper-evident log an auditor reads nor page a SOC with
// an event that never occurred.
//
// The SIEM configuration is read SYNCHRONOUSLY, while the caller's connection is
// certainly open. The dispatch is DATABASE-FREE and deliberately left un-awaited: the
// HA modules are synchronous and their callers close the handle in a finally as soon as
// they return, so an async send that reached for the database would find it closed.
//
// Nothing here may break a promotion, a demotion, a pairing, or a gate decision, so
// every failure is swallowed. ASCII-only; no template literals.

const { appendGdAuditEntry, isLiveChain } = require('./gd-audit-chain');

// Severity drives the SIEM's correlation rules, so these are chosen for what an analyst
// should be paged about rather than for symmetry.
//
// HA_PROMOTION_REFUSED is critical: in cloud mode it means this node could not
// re-attest at the moment it was to take write authority, so the platform is unverified
// AND the pair may be left with no active. HA_PROMOTED, HA_SELF_FENCED, and a
// HA_MANUAL_FAILOVER are high -- an unplanned or operator-driven takeover of the fleet
// aggregation plane is something a SOC correlates against everything else in that
// minute. HA_PAIRED is a warning because it changes the trust topology; HA_PEER_REJECTED
// is a warning because a single one is usually a certificate rotation, while a burst of
// them is what the SIEM should alert on. Routine operator actions are informational.
const HA_EVENT_SEVERITY = {
  HA_PROMOTION_REFUSED: 'critical',
  HA_PROMOTED: 'high',
  HA_SELF_FENCED: 'high',
  HA_MANUAL_FAILOVER: 'high',
  HA_DEMOTED: 'warning',
  HA_PAIRED: 'warning',
  HA_PEER_REJECTED: 'warning',
  HA_PAIR_FAILED: 'warning',
  HA_SEGMENT_REREGISTER_FAILED: 'warning',
  HA_SEGMENT_REREGISTERED: 'info',
  HA_PROMOTION_THROTTLED: 'info',
  HA_PAIR_INITIATED: 'info',
  HA_PAIRING_TOKEN_ISSUED: 'info',
  HA_CONFIG_UPDATED: 'info',
  HA_TEST_STARTED: 'info',
  HA_TEST_COMPLETE: 'info',
};

// An unmapped HA event is a warning, not info: a new event type should be visible in
// the SIEM until someone decides it is routine.
function haEventSeverity(eventType) {
  return HA_EVENT_SEVERITY[eventType] || 'warning';
}

// Stream an already-audited HA event to the operator's SIEM, if this connection is the
// durable chain and a SIEM is configured. Never throws; never touches the connection
// after returning.
function streamHaEvent(db, eventType, detail) {
  try {
    if (!isLiveChain(db)) {
      return { streamed: false, reason: 'not_live_chain' };
    }
    // Required lazily: only a live node with a configured SIEM ever loads the adapter.
    const { loadSiemConfig, pushAlertWithConfig } = require('./gd-siem-push');
    const cfg = loadSiemConfig(db);
    if (!cfg) {
      return { streamed: false, reason: 'not_configured' };
    }
    const alert = {
      type: eventType,
      severity: haEventSeverity(eventType),
      message: detail,
    };
    Promise.resolve(pushAlertWithConfig(cfg, alert)).catch(function () { /* best-effort */ });
    return { streamed: true };
  } catch (streamErr) {
    try { console.error('gd-ha-audit SIEM stream failed:', streamErr && streamErr.message ? streamErr.message : streamErr); } catch (logErr) { /* ignore */ }
    return { streamed: false, reason: 'error' };
  }
}

// Append the audit row through the connection the caller is mutating, then stream.
// The append comes first and is independent: a SIEM that is down, misconfigured, or
// absent never costs the chain its record of what happened.
function auditHaEvent(db, eventType, detail, ip) {
  try {
    appendGdAuditEntry(db, { userId: null, eventType: eventType, detail: detail, ip: ip || null });
  } catch (err) {
    try { console.error('gd-ha-audit append failed:', err && err.message ? err.message : err); } catch (logErr) { /* ignore */ }
  }
  streamHaEvent(db, eventType, detail);
}

module.exports = {
  HA_EVENT_SEVERITY,
  haEventSeverity,
  streamHaEvent,
  auditHaEvent,
};
