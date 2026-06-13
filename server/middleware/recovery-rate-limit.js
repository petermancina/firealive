// ═══════════════════════════════════════════════════════════════════════════
// FIREALIVE — Destructive-Recovery Burst Limiter (D24)
//
// Caps how quickly destructive client recovery can be INITIATED, both per
// operator and across the whole fleet, and raises a critical alert when a
// cap is breached. Dual-control already requires a second operator per
// action; this adds a velocity ceiling so a compromised operator (or a
// compromised pair) cannot drive a rapid mass-eviction without tripping a
// 429 and notifying the SOC. State is in-memory fixed-window counters; the
// window is short, so a restart cannot meaningfully widen the burst budget.
//
// Apply AFTER an auth middleware that sets req.user (per-operator counting).
// ═══════════════════════════════════════════════════════════════════════════

const { routeAlert } = require('../services/alert-router');
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');

const WINDOW_MS = 600000;
const PER_OPERATOR_MAX = 5;
const GLOBAL_MAX = 10;
const GLOBAL_KEY = '__global__';

const counters = new Map();

function hit(key, now, windowMs) {
  let entry = counters.get(key);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowMs };
    counters.set(key, entry);
  }
  entry.count += 1;
  return entry;
}

// Fire-and-forget: alerting must never block or fail the request path. The
// alert router de-dups identical type+severity within its own window.
function fireAlert(type, severity, message) {
  let db;
  try {
    db = getDb();
    const handle = db;
    Promise.resolve(routeAlert(db, { type: type, severity: severity, message: message }))
      .catch((e) => logger.error('recovery burst alert failed', { error: e && e.message }))
      .then(() => { try { handle.close(); } catch (_) { /* ignore */ } });
  } catch (e) {
    logger.error('recovery burst alert dispatch failed', { error: e && e.message });
    if (db) { try { db.close(); } catch (_) { /* ignore */ } }
  }
}

// Factory. label names the action in the alert message. opts may override
// windowMs, perOperatorMax, globalMax.
function recoveryRateLimit(label, opts) {
  const o = opts || {};
  const windowMs = o.windowMs || WINDOW_MS;
  const perOperatorMax = o.perOperatorMax || PER_OPERATOR_MAX;
  const globalMax = o.globalMax || GLOBAL_MAX;
  const name = label || 'recovery';
  return function recoveryBurstGate(req, res, next) {
    const uid = (req.user && req.user.id) || 'unknown';
    const now = Date.now();
    const opEntry = hit('op:' + uid, now, windowMs);
    const globalEntry = hit(GLOBAL_KEY, now, windowMs);
    const retryAfter = Math.ceil((Math.max(opEntry.resetAt, globalEntry.resetAt) - now) / 1000);
    const windowSec = Math.round(windowMs / 1000);
    if (opEntry.count > perOperatorMax) {
      fireAlert('RECOVERY_BURST_OPERATOR', 'critical',
        'operator ' + uid + ' exceeded destructive-recovery rate (' + name + '): ' +
        opEntry.count + ' in ' + windowSec + 's');
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: 'destructive-recovery rate limit exceeded' });
    }
    if (globalEntry.count > globalMax) {
      fireAlert('RECOVERY_BURST_GLOBAL', 'critical',
        'fleet destructive-recovery rate exceeded (' + name + '): ' +
        globalEntry.count + ' in ' + windowSec + 's');
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: 'destructive-recovery rate limit exceeded (fleet)' });
    }
    next();
  };
}

module.exports = { recoveryRateLimit, WINDOW_MS, PER_OPERATOR_MAX, GLOBAL_MAX };
