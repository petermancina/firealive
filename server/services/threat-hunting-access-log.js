// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Threat-Hunting Access Log (append-only, hash-chained) (B5m)
//
// Single source of truth for the threat_hunting_access_log hash chain, shared by
// the writer (the feed gate in middleware/threat-hunting-auth.js) and the
// verifier (the admin /access-log/verify endpoint). Keeping the canonical
// serialization in one place guarantees the recomputation matches what was
// written: a field-order change here changes both sides at once and can never
// silently break the chain.
//
// this_hash = SHA-256(canonical(entry)), where canonical pins a fixed field
// order joined by NUL. Every access attempt (authorized or rejected) is logged;
// the table's BEFORE UPDATE / BEFORE DELETE triggers make the log tamper-evident.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// Canonical serialization of an access-log entry. Fixed field order, NUL-
// separated; any field change breaks the chain. result_count is rendered as its
// decimal string (empty when absent) so numbers and nulls canonicalize stably.
function canonicalAccessEntry(e) {
  return [
    e.prev_hash || '',
    e.authorization_id || '',
    e.consumer_type || '',
    e.source_ip || '',
    e.cert_fingerprint || '',
    e.endpoint || '',
    e.format || '',
    e.query_summary || '',
    e.outcome || '',
    (e.result_count == null ? '' : String(e.result_count)),
    e.accessed_at || '',
  ].join('\u0000');
}

// Append one entry to the hash-chained access log. Reads the prior this_hash,
// computes this_hash = SHA-256(canonical(entry)), and inserts -- all inside a
// transaction so the prev_hash linkage is consistent under concurrency.
function appendAccessLog(db, fields) {
  const f = fields || {};
  const tx = db.transaction(() => {
    const accessedAt = db.prepare("SELECT datetime('now') AS t").get().t;
    const prevRow = db
      .prepare('SELECT this_hash FROM threat_hunting_access_log ORDER BY id DESC LIMIT 1')
      .get();
    const prevHash = prevRow ? prevRow.this_hash : null;
    const entry = {
      prev_hash: prevHash,
      authorization_id: f.authorization_id || null,
      consumer_type: f.consumer_type || null,
      source_ip: f.source_ip || '',
      cert_fingerprint: f.cert_fingerprint || null,
      endpoint: f.endpoint || '',
      format: f.format || null,
      query_summary: f.query_summary || null,
      outcome: f.outcome,
      result_count: (f.result_count == null ? null : f.result_count),
      accessed_at: accessedAt,
    };
    const thisHash = crypto
      .createHash('sha256')
      .update(canonicalAccessEntry(entry))
      .digest('hex');
    db.prepare(
      'INSERT INTO threat_hunting_access_log ' +
        '(prev_hash, this_hash, authorization_id, consumer_type, source_ip, cert_fingerprint, endpoint, format, query_summary, outcome, result_count, accessed_at) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      entry.prev_hash, thisHash, entry.authorization_id, entry.consumer_type,
      entry.source_ip, entry.cert_fingerprint, entry.endpoint, entry.format,
      entry.query_summary, entry.outcome, entry.result_count, entry.accessed_at
    );
    return Object.assign({}, entry, { this_hash: thisHash });
  });
  return tx();
}

// Recompute and verify the whole chain in id order. Returns
// { intact, count } on success or { intact:false, count, brokenAt, reason }.
function verifyAccessLogChain(db) {
  const rows = db
    .prepare(
      'SELECT id, prev_hash, this_hash, authorization_id, consumer_type, source_ip, cert_fingerprint, endpoint, format, query_summary, outcome, result_count, accessed_at ' +
        'FROM threat_hunting_access_log ORDER BY id ASC'
    )
    .all();
  let prevHash = null;
  for (const row of rows) {
    if ((row.prev_hash || null) !== (prevHash || null)) {
      return { intact: false, count: rows.length, brokenAt: row.id, reason: 'prev_hash linkage mismatch' };
    }
    const recomputed = crypto
      .createHash('sha256')
      .update(canonicalAccessEntry(row))
      .digest('hex');
    if (recomputed !== row.this_hash) {
      return { intact: false, count: rows.length, brokenAt: row.id, reason: 'this_hash mismatch' };
    }
    prevHash = row.this_hash;
  }
  return { intact: true, count: rows.length };
}

module.exports = { canonicalAccessEntry, appendAccessLog, verifyAccessLogChain };
