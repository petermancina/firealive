// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Export Encryption At-Rest Migration (boot-time, idempotent)
//
// Re-seals any legacy plaintext forensic-export artifacts
// left on disk before B5g (or by a crashed prior run). It selects rows whose
// at_rest_scheme is still NULL and that have an archive on record, then seals
// the archive and the manifest sidecar in place IF either is still plaintext
// (detected by the absence of the FA-ENC1 magic), and finally records the
// at-rest posture (at_rest_scheme, at_rest_kek_ref) on the row.
//
// Idempotent: once a row's columns are set it is no longer a candidate, and an
// already-FA-ENC1 file is never re-sealed. Each row runs in its own try/catch,
// so a single failure (for example, a transiently unavailable KEK) is logged
// and the migration continues; the row stays NULL and is retried on next boot.
//
// Invoked once at server startup (see server/index.js). Because it runs before
// the server accepts requests, it cannot race an in-flight export.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const exportEncryption = require('./export-encryption');

const NL = String.fromCharCode(10);

const EXPORT_TABLES = [
  { table: 'forensic_exports', label: 'forensic export' },
];

// Atomically replace a file with new bytes: write a sibling .enc.tmp and rename
// over the target (rename is atomic within a filesystem), so a crash mid-write
// never leaves a partial artifact.
function atomicReplace(targetPath, buf) {
  const tmp = targetPath + '.enc.tmp';
  fs.writeFileSync(tmp, buf);
  fs.renameSync(tmp, targetPath);
}

// Seal one on-disk artifact in place if it exists and is still plaintext.
// Returns the seal result ({ scheme, kekRef }) when it sealed, or null when the
// file was missing or already FA-ENC1-framed.
async function sealIfPlaintext(db, filePath, exportId, role) {
  if (!filePath || !fs.existsSync(filePath)) return null;
  const buf = fs.readFileSync(filePath);
  if (exportEncryption.isFramed(buf)) return null;
  const sealed = await exportEncryption.sealArtifact(buf, { exportId: exportId, role: role, db: db });
  atomicReplace(filePath, sealed.framed);
  return sealed;
}

// Boot-time, idempotent re-encryption of legacy plaintext export artifacts.
// Returns a summary { scanned, sealed, columnsOnly, failed }.
async function migrateExportsAtRest(db) {
  const summary = { scanned: 0, sealed: 0, columnsOnly: 0, failed: 0 };
  if (!db || typeof db.prepare !== 'function') return summary;

  for (let i = 0; i < EXPORT_TABLES.length; i += 1) {
    const spec = EXPORT_TABLES[i];
    let rows;
    try {
      rows = db.prepare(
        'SELECT id, archive_path, manifest_path FROM ' + spec.table +
        ' WHERE at_rest_scheme IS NULL AND archive_path IS NOT NULL'
      ).all();
    } catch (queryErr) {
      // Table or column missing (the C2 schema migration adds the columns):
      // skip this table rather than crash startup.
      process.stderr.write(
        '[export-encryption-migration] cannot scan ' + spec.table + ': ' + queryErr.message + NL
      );
      continue;
    }

    for (let j = 0; j < rows.length; j += 1) {
      const row = rows[j];
      summary.scanned += 1;
      try {
        const sealedArchive = await sealIfPlaintext(db, row.archive_path, row.id, exportEncryption.ROLE_ARCHIVE);
        const sealedManifest = await sealIfPlaintext(db, row.manifest_path, row.id, exportEncryption.ROLE_MANIFEST);
        const sealed = sealedArchive || sealedManifest;
        const scheme = sealed ? sealed.scheme : exportEncryption.DEFAULT_SCHEME;
        const kekRef = sealed ? sealed.kekRef : exportEncryption.DEFAULT_KEK_REFERENCE;
        db.prepare(
          'UPDATE ' + spec.table + ' SET at_rest_scheme = ?, at_rest_kek_ref = ? WHERE id = ?'
        ).run(scheme, kekRef, row.id);
        if (sealed) {
          summary.sealed += 1;
        } else {
          summary.columnsOnly += 1;
        }
      } catch (rowErr) {
        summary.failed += 1;
        process.stderr.write(
          '[export-encryption-migration] failed to seal ' + spec.label + ' ' + row.id + ': ' + rowErr.message + NL
        );
      }
    }
  }

  if (summary.scanned > 0 || summary.failed > 0) {
    console.log(
      'export-encryption migration (B5g): scanned ' + summary.scanned +
      ', sealed ' + summary.sealed +
      ', columns-only ' + summary.columnsOnly +
      ', failed ' + summary.failed
    );
  }
  return summary;
}

module.exports = { migrateExportsAtRest };
