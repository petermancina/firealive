// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — MaxMind DB (MMDB) Format Validator (B5n)
//
// The format gate an operator-provided GeoIP database must pass BEFORE it is
// trusted and activated for login geo-fencing. It runs after the malware scan
// and before (and alongside) the SHA-256 hash-verify in the upload route:
//
//   scan (upload-scan / integration-manager)  ->  validateMmdb (here)  ->  hash
//
// Checks:
//   - the file opens as a structurally valid MaxMind DB (metadata marker present,
//     metadata map decodes, record_size in {24,28,32}, node_count > 0, tree fits)
//     -- delegated to the pure-Node reader, which is bounds- and depth-checked;
//   - database_type is one of the accepted country/city editions (allow-list,
//     not a blocklist) -- a City edition is accepted because it still carries the
//     country record the geo-fence reads;
//   - ip_version is 4 or 6 (and the result notes whether the DB can resolve IPv6
//     clients, so the route/UI can warn when only IPv4 is covered).
//
// A short informational self-test resolves a sample public IP to confirm the
// tree + data decode actually work on this file; it is recorded, not a hard gate
// (an unusual-but-valid DB may not carry the sample ranges).
//
// validateMmdb(filePath, opts?) -> { ok, reason, code, meta }
//   meta = { database_type, ip_version, record_size, node_count, build_epoch,
//            file_size, ipv6_capable, sample_country }
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const { open } = require('./mmdb-reader');

// Accepted editions. GeoLite2-Country is the recommended free edition; the paid
// GeoIP2 editions and the City editions are also accepted (City carries country).
const ACCEPTED_DB_TYPES = new Set([
  'GeoLite2-Country',
  'GeoIP2-Country',
  'GeoLite2-City',
  'GeoIP2-City',
]);

const DEFAULTS = {
  minFileBytes: 512,                 // a real MMDB is many KB; reject tiny stubs
  maxFileBytes: 512 * 1024 * 1024,   // generous cap (GeoIP2-City is ~100 MB)
  sampleIps: ['8.8.8.8', '1.1.1.1'], // well-known public addresses for the self-test
};

function rej(code, reason, meta) {
  return { ok: false, reason: reason, code: code, meta: meta || {} };
}

function validateMmdb(filePath, opts) {
  const o = Object.assign({}, DEFAULTS, opts || {});

  let st;
  try {
    st = fs.statSync(filePath);
  } catch (e) {
    return rej('io_error', 'cannot stat file: ' + e.message);
  }
  const fileSize = st.size;
  if (fileSize < o.minFileBytes) {
    return rej('too_small', 'file is smaller than a plausible MMDB (' + fileSize + ' bytes)');
  }
  if (fileSize > o.maxFileBytes) {
    return rej('too_large', 'file exceeds the ' + o.maxFileBytes + '-byte cap (' + fileSize + ' bytes)');
  }

  let buf;
  try {
    buf = fs.readFileSync(filePath);
  } catch (e) {
    return rej('io_error', 'cannot read file: ' + e.message);
  }

  let reader;
  try {
    reader = open(buf);
  } catch (e) {
    return rej('bad_format', 'not a valid MaxMind DB: ' + e.message);
  }

  const m = reader.meta;
  const meta = {
    database_type: m.database_type,
    ip_version: m.ip_version,
    record_size: m.record_size,
    node_count: m.node_count,
    build_epoch: m.build_epoch,
    file_size: fileSize,
    ipv6_capable: m.ip_version === 6,
    sample_country: null,
  };

  if (!ACCEPTED_DB_TYPES.has(m.database_type)) {
    return rej(
      'unsupported_type',
      'database_type "' + String(m.database_type) + '" is not an accepted country/city edition',
      meta
    );
  }
  if (m.ip_version !== 4 && m.ip_version !== 6) {
    return rej('bad_ip_version', 'ip_version ' + String(m.ip_version) + ' is not 4 or 6', meta);
  }

  // Informational self-test: confirm the tree + data decode resolve a well-known
  // public address to a 2-letter ISO code. Recorded in meta, not a hard gate.
  for (const ip of o.sampleIps) {
    const cc = reader.lookupCountry(ip);
    if (typeof cc === 'string' && /^[A-Za-z]{2}$/.test(cc)) {
      meta.sample_country = cc.toUpperCase();
      break;
    }
  }

  return { ok: true, reason: null, code: null, meta: meta };
}

module.exports = { validateMmdb, ACCEPTED_DB_TYPES };
