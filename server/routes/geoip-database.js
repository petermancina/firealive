// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GeoIP Database Admin Route (B5n)
//
// Lets an admin provision the MaxMind GeoLite2-Country database that backs login
// geo-fencing. Mounted (server/index.js) at /api/geoip behind the admin JWT and
// the config-lock chokepoint:
//
//   POST /api/geoip/database   upload + activate a new database
//   GET  /api/geoip/database   active-database status + recent history
//
// The database is uploaded as a RAW application/octet-stream body (a GeoLite2-
// Country file is ~6-9 MB, larger than the 5 MB JSON limit, so it cannot ride in
// a JSON body). The optional expected SHA-256 (the value MaxMind publishes
// alongside the build) travels in the X-Expected-Sha256 header (or ?expectedSha256).
//
// Activation pipeline -- every stage is a fatal gate, fail-closed:
//   1. malware scan   the bytes are inspected by the configured EDR scanner
//                     (IntegrationManager.inspectFile). No scanner configured,
//                     a detection, or a scan error all REFUSE the upload -- the
//                     same hard gate the database-restore path uses.
//   2. format gate    validateMmdb confirms a structurally valid MaxMind DB of
//                     an accepted country/city edition.
//   3. hash           the SHA-256 is computed; if an expected hash was supplied
//                     it must match (operator verifies against MaxMind's published
//                     checksum), so a corrupted or substituted download is caught.
//   4. activate       the file is moved into place atomically, the prior active
//                     row is deactivated, a new active row is inserted, and the
//                     GeoIP service is reloaded so the change takes effect with no
//                     restart.
//
// Every reject is audited GEO_DB_REJECTED with a reason; a successful activation
// is audited GEO_DB_UPDATED. The uploaded file carries no analyst data; the audit
// records the actor (admin), the database metadata, and a hash prefix.
// ═══════════════════════════════════════════════════════════════════════════════

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { getDb } = require('../db/init');
const { auditLog } = require('../middleware/audit');
const { IntegrationManager } = require('../services/integration-manager');
const { validateMmdb } = require('../services/geoip/mmdb-validate');
const geoipService = require('../services/geoip/geoip-service');

const router = express.Router();

const SCAN_FILENAME = 'GeoLite2-Country.mmdb';
const MAX_UPLOAD_BYTES = 128 * 1024 * 1024; // generous; Country is ~9 MB, City ~100 MB

// Upload + activate a new GeoIP database. Raw octet-stream body.
router.post(
  '/database',
  express.raw({ type: 'application/octet-stream', limit: '128mb' }),
  async (req, res) => {
    const userId = req.user && req.user.id ? req.user.id : 'system';
    const body = req.body;

    if (!Buffer.isBuffer(body) || body.length === 0) {
      return res.status(400).json({
        error: 'empty upload; POST the raw .mmdb bytes as application/octet-stream',
        code: 'EMPTY_UPLOAD',
      });
    }
    const buf = body;
    if (buf.length > MAX_UPLOAD_BYTES) {
      return res.status(413).json({ error: 'upload exceeds size limit', code: 'TOO_LARGE' });
    }

    const expected = String(req.get('X-Expected-Sha256') || req.query.expectedSha256 || '')
      .trim()
      .toLowerCase();

    const db = getDb();
    let tmpPath = null;
    try {
      // 1. Malware scan -- fatal gate (mirrors the restore path).
      let scan;
      try {
        const mgr = new IntegrationManager(db);
        scan = await mgr.inspectFile(buf, SCAN_FILENAME, 'application/octet-stream');
      } catch (scanErr) {
        auditLog(userId, 'GEO_DB_REJECTED', 'reason=scan_threw', req.ip);
        return res.status(500).json({ error: 'malware scan failed', code: 'SCAN_FAILED' });
      }
      if (scan.skipped === true) {
        auditLog(userId, 'GEO_DB_REJECTED', 'reason=no_scanner', req.ip);
        return res.status(422).json({
          error: 'a malware scanner must be configured before uploading a GeoIP database (MC > Malware Scanners)',
          code: 'SCANNER_NOT_CONFIGURED',
        });
      }
      if (scan.clean !== true) {
        const threats = Array.isArray(scan.threats) ? scan.threats : [];
        if (threats.length > 0) {
          auditLog(userId, 'GEO_DB_REJECTED', 'reason=malware threats=' + threats.length, req.ip);
          return res.status(422).json({ error: 'upload failed the malware scan', code: 'MALWARE_DETECTED' });
        }
        auditLog(userId, 'GEO_DB_REJECTED', 'reason=scan_failed', req.ip);
        return res.status(500).json({ error: 'malware scan was inconclusive', code: 'SCAN_FAILED' });
      }

      // 2. Format gate.
      fs.mkdirSync(geoipService.geoipDir(), { recursive: true });
      tmpPath = path.join(geoipService.geoipDir(), 'upload-' + crypto.randomBytes(8).toString('hex') + '.mmdb.tmp');
      fs.writeFileSync(tmpPath, buf);

      const v = validateMmdb(tmpPath);
      if (!v.ok) {
        auditLog(userId, 'GEO_DB_REJECTED', 'reason=validate:' + v.code, req.ip);
        return res.status(422).json({
          error: 'not a valid GeoIP database: ' + v.reason,
          code: 'VALIDATION_FAILED',
          detail: v.code,
        });
      }

      // 3. Hash + optional expected-hash compare.
      const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      if (expected && expected !== sha256.toLowerCase()) {
        auditLog(userId, 'GEO_DB_REJECTED', 'reason=hash_mismatch', req.ip);
        return res.status(422).json({
          error: 'SHA-256 does not match the expected value',
          code: 'HASH_MISMATCH',
          expected: expected,
          actual: sha256,
        });
      }

      // 4. Activate: move into place, swap active rows, reload the service.
      const dest = geoipService.activeDbPath();
      fs.renameSync(tmpPath, dest);
      tmpPath = null;

      const m = v.meta;
      const activate = db.transaction(() => {
        db.prepare('UPDATE geoip_database SET active = 0 WHERE active = 1').run();
        db.prepare(
          'INSERT INTO geoip_database (sha256, db_type, build_epoch, node_count, ip_version, record_count, uploaded_by, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)'
        ).run(
          sha256,
          m.database_type,
          m.build_epoch != null ? m.build_epoch : null,
          m.node_count != null ? m.node_count : null,
          m.ip_version != null ? m.ip_version : null,
          null,
          userId
        );
      });
      activate();

      const status = geoipService.reload(db);
      auditLog(
        userId,
        'GEO_DB_UPDATED',
        'type=' + m.database_type + ' sha256=' + sha256.slice(0, 12) + ' build_epoch=' + (m.build_epoch || '?') + ' nodes=' + (m.node_count || '?'),
        req.ip
      );

      return res.json({ success: true, sha256: sha256, status: status });
    } catch (e) {
      return res.status(500).json({ error: 'failed to activate GeoIP database', detail: e.message });
    } finally {
      if (tmpPath) {
        try {
          fs.unlinkSync(tmpPath);
        } catch (_) {
          /* best effort */
        }
      }
      try {
        db.close();
      } catch (_) {
        /* ignore */
      }
    }
  }
);

// Active-database status + recent upload history.
router.get('/database', (req, res) => {
  const db = getDb();
  try {
    const active =
      db
        .prepare(
          'SELECT id, sha256, db_type, build_epoch, node_count, ip_version, record_count, uploaded_by, uploaded_at FROM geoip_database WHERE active = 1 ORDER BY id DESC LIMIT 1'
        )
        .get() || null;
    const history = db
      .prepare(
        'SELECT id, sha256, db_type, build_epoch, uploaded_by, uploaded_at, active FROM geoip_database ORDER BY id DESC LIMIT 10'
      )
      .all();
    const status = geoipService.status();
    return res.json({ service: status, active: active, history: history });
  } catch (e) {
    return res.status(500).json({ error: 'failed to read GeoIP database status' });
  } finally {
    try {
      db.close();
    } catch (_) {
      /* ignore */
    }
  }
});

module.exports = router;
