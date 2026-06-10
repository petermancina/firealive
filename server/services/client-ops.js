// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Per-Client Fleet Operations dispatch (B5d4)
//
// Orchestrates a fleet operation across analyst clients on the same B4 WebSocket
// dispatch substrate the compromise scan uses. A lead/admin triggers one of the
// six ops; this service resolves the targets, records a run, queues offline
// targets for delivery on reconnect within a TTL, and fans the command out to
// connected ACs. The ops that assert system/security state (refresh_metrics,
// log_integrity, regression, vuln_scan) return an Ed25519 device-signed result;
// config_resync and update_push are command + ack. Result ingestion + signature
// verification + queued-delivery-on-reconnect live in the websocket-server, the
// same place the compromise scan's do.
//
// The server never fabricates a result -- it only dispatches the command and
// stores what the signed clients return. dispatchClientOp on the wsServer lands
// in a later commit; the call is guarded so this service is sound until then
// (offline targets queue; connected targets dispatch once the method exists).
// ═══════════════════════════════════════════════════════════════════════════════

const { logger } = require('./logger');

const QUEUE_TTL_MINUTES = 15;
const MAX_TARGETS = 1000;
const VALID_OPS = new Set([
  'config_resync',
  'refresh_metrics',
  'log_integrity',
  'regression',
  'vuln_scan',
  'update_push',
]);

function badRequest(message, code) {
  const e = new Error(message);
  e.code = code || 'INVALID_INPUT';
  return e;
}

// ── dispatchClientOp(db, { opType, targets, params, initiatedBy, trigger, wsServer }) ──
// targets: 'all' (every active analyst) or an array of analyst user ids.
// Returns { runId, opType, targetCount, dispatched, unreachable: [userId,...] }.
// Throws coded errors (INVALID_OP_TYPE / INVALID_TARGETS / NO_TARGETS) for the
// route to map to HTTP.
function dispatchClientOp(db, opts = {}) {
  const opType = opts.opType;
  const targets = opts.targets;
  const params = opts.params && typeof opts.params === 'object' ? opts.params : null;
  const initiatedBy = opts.initiatedBy || null;
  const trigger = opts.trigger === 'api' ? 'api' : 'manual';
  const wsServer = opts.wsServer || null;

  if (!opType || !VALID_OPS.has(opType)) {
    throw badRequest('op_type must be one of: ' + Array.from(VALID_OPS).join(', '), 'INVALID_OP_TYPE');
  }

  // Resolve targets to active analyst ids.
  let targetIds = [];
  if (targets === 'all') {
    targetIds = db
      .prepare("SELECT id FROM users WHERE role = 'analyst' AND active = 1")
      .all()
      .map((r) => r.id);
  } else if (Array.isArray(targets)) {
    if (targets.length === 0 || targets.length > MAX_TARGETS) {
      throw badRequest('targets must be a non-empty list (max ' + MAX_TARGETS + ') or "all"', 'INVALID_TARGETS');
    }
    const placeholders = targets.map(() => '?').join(',');
    targetIds = db
      .prepare("SELECT id FROM users WHERE id IN (" + placeholders + ") AND role = 'analyst' AND active = 1")
      .all(...targets)
      .map((r) => r.id);
  } else {
    throw badRequest('targets must be "all" or an array of analyst ids', 'INVALID_TARGETS');
  }
  if (targetIds.length === 0) throw badRequest('no valid analyst targets', 'NO_TARGETS');

  // Split connected vs offline against the live WebSocket session map.
  const connected = [];
  const unreachable = [];
  for (const id of targetIds) {
    if (wsServer && wsServer.clients && wsServer.clients.has(id)) connected.push(id);
    else unreachable.push(id);
  }

  const mode = targets === 'all' ? 'all' : 'list';
  const run = db
    .prepare(
      'INSERT INTO client_ops_runs (op_type, trigger, initiated_by, targets_json, target_count, unreachable_count, status) ' +
        "VALUES (?, ?, ?, ?, ?, ?, 'in_progress') RETURNING id"
    )
    .get(opType, trigger, initiatedBy, JSON.stringify({ mode, ids: targetIds }), targetIds.length, unreachable.length);
  const runId = run.id;

  // Queue offline targets for delivery on reconnect within the TTL.
  if (unreachable.length) {
    const expiresAt = new Date(Date.now() + QUEUE_TTL_MINUTES * 60000).toISOString();
    const q = db.prepare('INSERT INTO client_ops_queue (run_id, user_id, expires_at) VALUES (?, ?, ?)');
    const enqueue = db.transaction((ids) => {
      for (const id of ids) q.run(runId, id, expiresAt);
    });
    enqueue(unreachable);
  }

  // Fan out to connected ACs. dispatchClientOp on the wsServer lands in a later
  // commit; guard so this service stays sound until then.
  if (connected.length && wsServer && typeof wsServer.dispatchClientOp === 'function') {
    try {
      wsServer.dispatchClientOp(runId, connected, { opType, params });
    } catch (e) {
      logger.warn('client-op dispatch failed', { runId, opType, error: e.message });
    }
  }

  return { runId, opType, targetCount: targetIds.length, dispatched: connected.length, unreachable };
}

module.exports = { dispatchClientOp, QUEUE_TTL_MINUTES, VALID_OPS };
