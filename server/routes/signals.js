// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Signals Routes (Analyst Client, R3l C4)
// Tier-3 private: every query is hard-filtered by req.user.id from the JWT so
// an analyst can only ever read their own data. There is no analyst_id query
// parameter, by design — that would defeat the Tier-3 invariant.
//
// GET /api/signals/me — analyst-self view combining:
//   • current     — latest decrypted snapshot from analyst_signals (current state)
//   • readings    — time-series rows from signal_readings (for trend rendering,
//                   written by services/ai-burnout-engine.js)
//   • sealed_readings — B5d1 per-analyst snapshots sealed to the analyst's own
//                   X25519 public key (analyst_private_data, kind='reading').
//                   Opaque ciphertext; decrypted only on the Analyst Client.
//   • pressure    — the analyst's own operational pressure signals, computed
//                   live (shared with the routing cap); operational/lead-visible,
//                   returned in the clear for the My Signals pressure card.
//   • meta        — pagination + filter echo
//
// This is the new canonical analyst-self endpoint. The pre-existing
// GET /api/analysts/signals returns only the analyst_signals snapshots and will
// be deprecated once the AC frontend is fully wired (C10 wires My Signals).
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { decryptTier3 } = require('../services/encryption');
const { logger } = require('../services/logger');
const { computeAnalystPressure } = require('../services/signal-collector');

const DEFAULT_LOOKBACK_DAYS = 7;
const DEFAULT_LIMIT = 500;
const MAX_LIMIT = 5000;

// Signal names recognized by the burnout engine. Used to validate the optional
// ?signal= filter so analysts cannot trigger arbitrary string queries even
// though the column would accept anything. Kept in lockstep with the keys
// encrypted in analyst_signals by POST /api/analysts/signals.
const ALLOWED_SIGNALS = [
  'investigationTime',
  'dismissRate',
  'ticketQuality',
  'escalationRate',
];

// ── GET /me ──────────────────────────────────────────────────────────────────
router.get('/me', (req, res) => {
  // Tier-3 invariant: analyst id comes from the JWT, never from the request.
  // Defensive failure if the JWT is malformed — fail closed.
  const analystId = req.user && req.user.id;
  if (!analystId) {
    return res.status(401).json({ error: 'JWT missing analyst id' });
  }

  // ── Parse + validate query params ──────────────────────────────────────────
  const now = new Date();
  const defaultSince = new Date(now.getTime() - DEFAULT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000);

  let sinceDate;
  let untilDate;
  try {
    sinceDate = req.query.since ? new Date(req.query.since) : defaultSince;
    untilDate = req.query.until ? new Date(req.query.until) : now;
    if (isNaN(sinceDate.getTime()) || isNaN(untilDate.getTime())) {
      return res.status(400).json({ error: 'invalid since/until timestamp; use ISO 8601 format' });
    }
    if (sinceDate.getTime() > untilDate.getTime()) {
      return res.status(400).json({ error: 'since must be earlier than until' });
    }
  } catch (err) {
    return res.status(400).json({ error: 'invalid since/until timestamp; use ISO 8601 format' });
  }

  const signalFilter = req.query.signal;
  if (signalFilter && !ALLOWED_SIGNALS.includes(signalFilter)) {
    return res.status(400).json({ error: 'invalid signal name', allowed: ALLOWED_SIGNALS });
  }

  let limit = parseInt(req.query.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0) {
    limit = DEFAULT_LIMIT;
  } else if (limit > MAX_LIMIT) {
    limit = MAX_LIMIT;
  }

  const db = getDb();
  try {
    // ── Current snapshot — latest analyst_signals row, decrypted ─────────────
    let current = null;
    const latestRow = db.prepare(
      'SELECT signals_encrypted, risk_tier, recorded_at FROM analyst_signals WHERE analyst_id = ? ORDER BY recorded_at DESC LIMIT 1'
    ).get(analystId);

    if (latestRow) {
      try {
        const decrypted = decryptTier3(latestRow.signals_encrypted);
        current = {
          investigationTime: decrypted && decrypted.investigationTime,
          dismissRate: decrypted && decrypted.dismissRate,
          ticketQuality: decrypted && decrypted.ticketQuality,
          escalationRate: decrypted && decrypted.escalationRate,
          riskTier: latestRow.risk_tier,
          recordedAt: latestRow.recorded_at,
        };
      } catch (decryptErr) {
        // Decryption failure is real (e.g., key rotated without re-encryption,
        // or corrupted row) but should not 500 the whole endpoint — the readings
        // path can still serve historical data. Log and surface a typed error
        // in the current field so the client can render a clear state.
        logger.warn('signals/me decrypt failed', {
          analystId,
          recordedAt: latestRow.recorded_at,
          error: decryptErr.message,
        });
        current = {
          error: 'decryption_failed',
          riskTier: latestRow.risk_tier,
          recordedAt: latestRow.recorded_at,
        };
      }
    }

    // ── Historical readings — signal_readings filtered by analyst + time ─────
    // datetime() is applied on both sides because signal_readings.recorded_at
    // is stored in SQLite's "YYYY-MM-DD HH:MM:SS" format (via datetime('now'))
    // while incoming ISO 8601 strings carry T separators and a Z suffix. The
    // datetime() function normalises both to a comparable canonical form.
    let readingsSql = `
      SELECT signal, value, recorded_at
      FROM signal_readings
      WHERE analyst_id = ?
        AND datetime(recorded_at) >= datetime(?)
        AND datetime(recorded_at) <= datetime(?)
    `;
    const params = [analystId, sinceDate.toISOString(), untilDate.toISOString()];

    if (signalFilter) {
      readingsSql += ' AND signal = ?';
      params.push(signalFilter);
    }

    readingsSql += ' ORDER BY recorded_at DESC LIMIT ?';
    params.push(limit);

    const readings = db.prepare(readingsSql).all(...params);

    // -- Sealed readings -- the analyst's own private snapshots (B5d1) ----------
    // analyst_private_data holds one snapshot per collection cycle, sealed to
    // this analyst's X25519 public key. The server stores and returns only
    // opaque ciphertext and holds no key to open it. The Analyst Client decrypts
    // each blob on-device (burnout key custody) to render its own trend and
    // compute its own baseline and drift. Self-scoped by the same JWT analyst id
    // used above; time-filtered to match the readings window. Snapshots carry
    // all signals at once, so the ?signal= filter does not apply here -- the
    // client filters after decrypting. Served alongside the legacy plaintext
    // readings until the client is migrated to this sealed source.
    const sealedReadings = db.prepare(
      `SELECT id, ciphertext, key_version, recorded_at
       FROM analyst_private_data
       WHERE analyst_id = ?
         AND kind = 'reading'
         AND datetime(recorded_at) >= datetime(?)
         AND datetime(recorded_at) <= datetime(?)
       ORDER BY recorded_at DESC
       LIMIT ?`
    ).all(analystId, sinceDate.toISOString(), untilDate.toISOString(), limit);

    // ── Pressure (operational workload) — computed live, self-scoped ──────────
    // The analyst's own pressure signals, from the same shared helper that feeds
    // the routing cap. No per-analyst pressure is persisted, so this is always
    // current and survives the retirement of the plaintext readings path.
    // Pressure is operational/lead-visible (not part of the sealed behavioral
    // set), so it is returned here in the clear for the My Signals pressure card.
    const pressure = computeAnalystPressure(db, analystId);

    res.json({
      analyst_id: analystId,
      current,
      readings,
      sealed_readings: sealedReadings,
      pressure,
      meta: {
        count: readings.length,
        sealed_count: sealedReadings.length,
        since: sinceDate.toISOString(),
        until: untilDate.toISOString(),
        signal: signalFilter || null,
        limit,
        truncated: readings.length === limit,
      },
    });
  } catch (err) {
    logger.error('signals/me query failed', { analystId, error: err.message });
    res.status(500).json({ error: 'internal error' });
  } finally {
    db.close();
  }
});

module.exports = router;
