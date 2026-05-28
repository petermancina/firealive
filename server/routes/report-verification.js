// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Report Verification Routes
//
// Two authenticated endpoints backing U4 signed exportable reports:
//
//   GET /api/report-signing/key
//     Returns the active report-signing public key (PEM + fingerprint) and the
//     instance label, so an authorized verifier can check report signatures
//     offline (see docs/report-verification.md). Public key only -- the
//     private key is never read here. Gated to admin / ciso / abuse_reviewer.
//
//   GET /api/verify/report/:hash
//     Content-blind verification. Looks a report up by the SHA-256 of its
//     signed material and re-verifies the recorded Ed25519 signature. Returns
//     metadata only -- never content. Per-type authorization:
//       - abuse_flag       -> abuse_reviewer ONLY. Wrong role returns 404
//                             (not 403) so a lead/admin cannot confirm an
//                             accusation exists by probing its hash. This is
//                             the HR/court appeal path: HR asks an independent
//                             reviewer to confirm the accuser's exported report
//                             is genuine; verification is never public.
//       - compliance /
//         report_engine    -> admin or ciso.
//       - helper_pay        -> admin, or the owning analyst (self) identified
//                             by content-blind metadata.owner_user_id (set by
//                             the helper-pay exporter in PR 3).
//
// MOUNT: app.use('/api', authMiddleware([]), require('./routes/report-verification'))
//   authMiddleware([]) requires a valid JWT but allows any role; the
//   per-handler checks below enforce the specifics. Mounted at '/api' (not a
//   sub-prefix) because the two paths live under different bases and the
//   verify path must exactly match the watermark footer's
//   "/api/verify/report/{hash}".
//
// NO AUDIT LOGGING: these are read-only verification endpoints, and an
// abuse_flag verification must never leave an MC-readable trace tying a
// reviewer to a specific accusation (subject_ref = flag_id). The route is
// deliberately silent.
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const { getDb } = require('../db/init');
const { logger } = require('../services/logger');
const { verifyReportByHash, getInstanceLabel } = require('../services/report-signer');

// Reject API-key auth on these endpoints -- verification is a human/JWT action.
function rejectApiKey(req, res) {
  if (req.user && req.user.apiKey) {
    res.status(403).json({ error: 'JWT authentication required on this endpoint' });
    return true;
  }
  return false;
}

// ── GET /api/report-signing/key ──────────────────────────────────────────────
// Active report-signing public key + instance label, for offline verification.
router.get('/report-signing/key', (req, res) => {
  if (rejectApiKey(req, res)) return;
  const role = req.user && req.user.role;
  if (role !== 'admin' && role !== 'ciso' && role !== 'abuse_reviewer') {
    return res.status(403).json({ error: 'admin, ciso, or abuse_reviewer role required' });
  }
  try {
    const db = getDb();
    const keyRow = db.prepare(`
      SELECT public_key, public_key_fingerprint, created_at
      FROM report_signing_keys
      WHERE is_active = 1
      LIMIT 1
    `).get();
    if (!keyRow) {
      return res.status(404).json({ error: 'no active report signing key' });
    }
    res.json({
      instance_label: getInstanceLabel(db),
      active_signing_key: {
        algorithm: 'Ed25519',
        public_key_pem: keyRow.public_key,
        fingerprint: keyRow.public_key_fingerprint,
        created_at: keyRow.created_at,
      },
    });
  } catch (err) {
    logger.error('report-verification: failed to fetch signing key', { error: err.message });
    res.status(500).json({ error: 'failed to fetch signing key' });
  }
});

// ── GET /api/verify/report/:hash ─────────────────────────────────────────────
// Content-blind verification with per-type authorization.
router.get('/verify/report/:hash', (req, res) => {
  if (rejectApiKey(req, res)) return;
  const hash = String(req.params.hash || '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) {
    return res.status(400).json({ error: 'hash must be a 64-char SHA-256 hex string' });
  }
  try {
    const db = getDb();
    const result = verifyReportByHash(db, hash);
    if (!result) {
      return res.status(404).json({ error: 'no report matches that hash' });
    }

    const role = req.user.role;
    const type = result.reportType;

    if (type === 'abuse_flag') {
      // Existence is sensitive. Anyone who is not an independent reviewer gets
      // 404 -- identical to a genuine miss -- so an accusation cannot be
      // confirmed to exist by probing hashes.
      if (role !== 'abuse_reviewer') {
        return res.status(404).json({ error: 'no report matches that hash' });
      }
    } else if (type === 'compliance' || type === 'report_engine') {
      if (role !== 'admin' && role !== 'ciso') {
        return res.status(403).json({ error: 'admin or ciso role required to verify this report' });
      }
    } else if (type === 'helper_pay') {
      const ownerId = result.metadata && result.metadata.owner_user_id;
      const isOwner = ownerId && ownerId === req.user.id;
      if (role !== 'admin' && !isOwner) {
        return res.status(403).json({ error: 'admin or the owning analyst required to verify this report' });
      }
    } else {
      return res.status(403).json({ error: 'unsupported report type' });
    }

    res.json({
      valid: result.valid,
      report_type: result.reportType,
      subject_ref: result.subjectRef,
      key_fingerprint: result.keyFingerprint,
      instance_label: result.instanceLabel,
      signed_at: result.signedAt,
      metadata: result.metadata || null,
    });
  } catch (err) {
    logger.error('report-verification: verify failed', { error: err.message });
    res.status(500).json({ error: 'verification failed' });
  }
});

module.exports = router;
