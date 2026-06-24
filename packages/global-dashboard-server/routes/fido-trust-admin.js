// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — FIDO2 Trust-Anchor Admin Routes (B5n3)
// GET    /api/iam/fido-roots        — list trusted attestation roots
// POST   /api/iam/fido-roots        — add a trusted root from a pasted PEM
// DELETE /api/iam/fido-roots/:id    — remove a root (refuses the last one)
// GET    /api/iam/fido-aaguids      — list the optional AAGUID model allow-list
// POST   /api/iam/fido-aaguids      — add an AAGUID (normalized)
// DELETE /api/iam/fido-aaguids/:id  — remove an AAGUID
// ═══════════════════════════════════════════════════════════════════════════════
//
// These routes let a CISO manage the trust anchors that gate hardware-key login
// enrollment on the Global Dashboard -- the GD twin of the Regional server's
// /api/iam/fido-* routes. They are mounted in index.js behind
// authMiddleware(['ciso']): the GD has no config-lock chokepoint, so trust-anchor
// management is restricted to the CISO role. A hardware passkey is accepted at
// enrollment only if its attestation chains to one of these roots. Bundled roots
// (seeded=1) and admin-added roots (seeded=0) are treated identically as trust
// anchors; removing the LAST root is refused so enrollment can never be left with
// no anchor. An empty AAGUID allow-list means "any model from a trusted vendor".
// ═══════════════════════════════════════════════════════════════════════════════

const router = require('express').Router();
const crypto = require('crypto');
const { getDb } = require('../db-init');
const { appendGdAuditEntry } = require('../services/gd-audit-chain');

function logErr(msg, obj) {
  console.error('[gd-fido-admin]', msg, obj && obj.error ? obj.error : '');
}

router.get('/fido-roots', (req, res) => {
  const db = getDb();
  try {
    const rows = db.prepare(
      'SELECT id, vendor, label, root_pem, seeded, added_by, created_at FROM fido_trusted_roots ORDER BY seeded DESC, vendor, created_at'
    ).all();
    const roots = rows.map((r) => {
      let sha256 = null;
      let subject = null;
      let validTo = null;
      try {
        const cert = new crypto.X509Certificate(r.root_pem);
        sha256 = crypto.createHash('sha256').update(cert.raw).digest('hex');
        subject = cert.subject;
        validTo = cert.validTo;
      } catch (_) {
        // leave nulls for an unparseable stored root
      }
      return {
        id: r.id,
        vendor: r.vendor,
        label: r.label,
        seeded: r.seeded === 1,
        added_by: r.added_by || null,
        created_at: r.created_at,
        sha256: sha256,
        subject: subject,
        valid_to: validTo,
        root_pem: r.root_pem,
      };
    });
    return res.json({ roots: roots, count: roots.length });
  } catch (err) {
    logErr('fido-roots list error', { error: err.message });
    return res.status(500).json({ error: 'Failed to list trusted roots' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.post('/fido-roots', (req, res) => {
  const db = getDb();
  try {
    const { vendor, label, rootPem } = req.body || {};
    if (!vendor || typeof vendor !== 'string') {
      return res.status(400).json({ error: 'vendor is required' });
    }
    if (!label || typeof label !== 'string') {
      return res.status(400).json({ error: 'label is required' });
    }
    if (!rootPem || typeof rootPem !== 'string' || rootPem.indexOf('BEGIN CERTIFICATE') === -1) {
      return res.status(400).json({ error: 'rootPem (a PEM certificate string) is required' });
    }
    let cert;
    try {
      cert = new crypto.X509Certificate(rootPem);
    } catch (_) {
      return res.status(400).json({ error: 'rootPem is not a valid X.509 certificate' });
    }
    if (cert.ca !== true) {
      return res.status(400).json({ error: 'rootPem is not a CA certificate (basicConstraints CA:FALSE)' });
    }
    try {
      db.prepare(
        'INSERT INTO fido_trusted_roots (vendor, label, root_pem, seeded, added_by) VALUES (?, ?, ?, 0, ?)'
      ).run(String(vendor), String(label), String(rootPem), req.user.id);
    } catch (dbErr) {
      if (/UNIQUE|constraint/i.test(dbErr.message)) {
        return res.status(409).json({ error: 'this attestation root is already trusted' });
      }
      throw dbErr;
    }
    const row = db.prepare('SELECT id FROM fido_trusted_roots WHERE root_pem = ?').get(String(rootPem));
    const sha256 = crypto.createHash('sha256').update(cert.raw).digest('hex');
    try {
      appendGdAuditEntry(db, {
        userId: req.user.id,
        eventType: 'FIDO_ROOT_ADDED',
        detail: 'vendor=' + vendor + ' label="' + label + '" sha256=' + sha256,
        ip: req.ip,
        severity: 'warning',
      });
    } catch (_) { /* best-effort */ }
    return res.status(201).json({ added: true, id: row ? row.id : null, vendor: vendor, label: label, sha256: sha256 });
  } catch (err) {
    logErr('fido-roots add error', { error: err.message });
    return res.status(500).json({ error: 'Failed to add trusted root' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.delete('/fido-roots/:id', (req, res) => {
  const db = getDb();
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'root id is required' });
    const row = db.prepare('SELECT id, vendor, label FROM fido_trusted_roots WHERE id = ?').get(id);
    if (!row) {
      return res.status(404).json({ error: 'trusted root not found' });
    }
    const total = db.prepare('SELECT COUNT(*) AS n FROM fido_trusted_roots').get().n;
    if (total <= 1) {
      return res.status(409).json({
        error: 'cannot remove the last trusted attestation root; at least one must remain or hardware-key enrollment would be impossible',
        code: 'LAST_TRUSTED_ROOT',
      });
    }
    db.prepare('DELETE FROM fido_trusted_roots WHERE id = ?').run(id);
    try {
      appendGdAuditEntry(db, {
        userId: req.user.id,
        eventType: 'FIDO_ROOT_REMOVED',
        detail: 'id=' + id + ' vendor=' + row.vendor + ' label="' + row.label + '"',
        ip: req.ip,
        severity: 'warning',
      });
    } catch (_) { /* best-effort */ }
    return res.json({ removed: true, id: id });
  } catch (err) {
    logErr('fido-roots remove error', { error: err.message });
    return res.status(500).json({ error: 'Failed to remove trusted root' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.get('/fido-aaguids', (req, res) => {
  const db = getDb();
  try {
    const rows = db.prepare(
      'SELECT id, aaguid, label, added_by, created_at FROM fido_aaguid_allowlist ORDER BY created_at'
    ).all();
    return res.json({
      aaguids: rows,
      count: rows.length,
      mode: rows.length === 0 ? 'any-trusted-vendor-model' : 'restricted-to-listed-models',
    });
  } catch (err) {
    logErr('fido-aaguids list error', { error: err.message });
    return res.status(500).json({ error: 'Failed to list AAGUID allow-list' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.post('/fido-aaguids', (req, res) => {
  const db = getDb();
  try {
    const { aaguid, label } = req.body || {};
    if (!aaguid || typeof aaguid !== 'string') {
      return res.status(400).json({ error: 'aaguid is required' });
    }
    if (!label || typeof label !== 'string') {
      return res.status(400).json({ error: 'label is required' });
    }
    // Normalize to the canonical lowercase dashed UUID form (the AAGUID string
    // recorded at registration). Accept input with or without dashes.
    const hex = aaguid.replace(/-/g, '').toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(hex)) {
      return res.status(400).json({ error: 'aaguid must be a 128-bit value (32 hex digits, optionally dash-formatted)' });
    }
    const normalized = hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20);
    try {
      db.prepare('INSERT INTO fido_aaguid_allowlist (aaguid, label, added_by) VALUES (?, ?, ?)')
        .run(normalized, String(label), req.user.id);
    } catch (dbErr) {
      if (/UNIQUE|constraint/i.test(dbErr.message)) {
        return res.status(409).json({ error: 'this AAGUID is already on the allow-list' });
      }
      throw dbErr;
    }
    try {
      appendGdAuditEntry(db, {
        userId: req.user.id,
        eventType: 'FIDO_AAGUID_ADDED',
        detail: 'aaguid=' + normalized + ' label="' + label + '"',
        ip: req.ip,
        severity: 'info',
      });
    } catch (_) { /* best-effort */ }
    return res.status(201).json({ added: true, aaguid: normalized, label: label });
  } catch (err) {
    logErr('fido-aaguids add error', { error: err.message });
    return res.status(500).json({ error: 'Failed to add AAGUID' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

router.delete('/fido-aaguids/:id', (req, res) => {
  const db = getDb();
  try {
    const id = req.params.id;
    if (!id) return res.status(400).json({ error: 'aaguid id is required' });
    const row = db.prepare('SELECT id, aaguid FROM fido_aaguid_allowlist WHERE id = ?').get(id);
    if (!row) {
      return res.status(404).json({ error: 'AAGUID not found' });
    }
    db.prepare('DELETE FROM fido_aaguid_allowlist WHERE id = ?').run(id);
    try {
      appendGdAuditEntry(db, {
        userId: req.user.id,
        eventType: 'FIDO_AAGUID_REMOVED',
        detail: 'id=' + id + ' aaguid=' + row.aaguid,
        ip: req.ip,
        severity: 'info',
      });
    } catch (_) { /* best-effort */ }
    return res.json({ removed: true, id: id });
  } catch (err) {
    logErr('fido-aaguids remove error', { error: err.message });
    return res.status(500).json({ error: 'Failed to remove AAGUID' });
  } finally {
    try { db.close(); } catch (_) { /* ignore */ }
  }
});

module.exports = router;
