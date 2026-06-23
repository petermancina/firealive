// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GeoIP Service (active-database loader) (B5n)
//
// Owns the in-memory MaxMind reader used by login geo-fencing. The operator
// uploads a GeoLite2-Country database through the admin route (scan -> validate
// -> hash -> activate); that route writes the file here and records a row in
// geoip_database with active = 1. This service loads the active database once at
// boot (and on reload after a new upload) and answers IP -> country lookups from
// the cached reader -- a per-login lookup never touches the disk or the DB.
//
// Load is integrity-gated and fail-closed: the on-disk file's SHA-256 must match
// the active row's recorded hash before the reader is trusted. Any failure (no
// active row, missing file, hash mismatch, unparsable file) leaves the service
// UNLOADED with a recorded reason. The geo-fence treats "enabled but unloaded"
// as a misconfiguration (fail-open + alert), distinct from "loaded but this IP
// did not resolve" (which blocks under enforcement). This module never decides
// policy; it only loads the database and resolves addresses.
//
//   init(db) / reload(db)  load (or re-load) the active database; return status.
//   resolveCountry(ip)     ISO-3166-1 alpha-2 for ip, or null (unloaded or unmatched).
//   isLoaded()             true once a database is loaded and hash-verified.
//   status()               { loaded, error, sha256, database_type, ip_version,
//                            build_epoch, node_count, loaded_at, path }.
//   geoipDir() / activeDbPath()  on-disk locations (the upload route writes here).
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { open } = require('./mmdb-reader');
const { DB_PATH } = require('../../db/init');

const ACTIVE_DB_FILENAME = 'active.mmdb';

let state = {
  loaded: false,
  reader: null,
  meta: null,
  sha256: null,
  error: null,
  loadedAt: null,
};

// Directory holding the active GeoIP database. Defaults to a "geoip" folder
// beside the SQLite database (operational data the app writes), overridable
// with GEOIP_DIR for deployments that separate data volumes.
function geoipDir() {
  if (process.env.GEOIP_DIR && process.env.GEOIP_DIR.trim()) {
    return path.resolve(process.env.GEOIP_DIR.trim());
  }
  return path.join(path.dirname(DB_PATH), 'geoip');
}

function activeDbPath() {
  return path.join(geoipDir(), ACTIVE_DB_FILENAME);
}

function resetState(error) {
  state = { loaded: false, reader: null, meta: null, sha256: null, error: error || null, loadedAt: null };
}

// Load (or reload) the active database. Synchronous and fail-closed; returns the
// current status object either way. Never throws.
function load(db) {
  let row;
  try {
    row = db
      .prepare(
        'SELECT sha256, db_type, ip_version, build_epoch, node_count FROM geoip_database WHERE active = 1 ORDER BY id DESC LIMIT 1'
      )
      .get();
  } catch (e) {
    resetState('db_query_failed: ' + e.message);
    return status();
  }

  if (!row) {
    resetState('no_active_db');
    return status();
  }

  const filePath = activeDbPath();
  let buf;
  try {
    buf = fs.readFileSync(filePath);
  } catch (e) {
    resetState('file_missing');
    return status();
  }

  const actual = crypto.createHash('sha256').update(buf).digest('hex');
  if (!row.sha256 || actual.toLowerCase() !== String(row.sha256).toLowerCase()) {
    resetState('hash_mismatch');
    return status();
  }

  let reader;
  try {
    reader = open(buf);
  } catch (e) {
    resetState('open_failed: ' + e.message);
    return status();
  }

  state = {
    loaded: true,
    reader: reader,
    meta: reader.meta,
    sha256: actual,
    error: null,
    loadedAt: new Date().toISOString(),
  };
  return status();
}

function init(db) {
  return load(db);
}

function reload(db) {
  return load(db);
}

function isLoaded() {
  return state.loaded === true;
}

// ISO-3166-1 alpha-2 country code for ip, or null. Null means either the
// service is unloaded or the address did not resolve in the database; callers
// distinguish those with isLoaded(). Pure in-memory; never touches disk/DB.
function resolveCountry(ip) {
  if (!state.loaded || !state.reader) return null;
  return state.reader.lookupCountry(ip);
}

function status() {
  const m = state.meta || {};
  return {
    loaded: state.loaded,
    error: state.error,
    sha256: state.sha256,
    database_type: m.database_type || null,
    ip_version: typeof m.ip_version === 'number' ? m.ip_version : null,
    build_epoch: typeof m.build_epoch === 'number' ? m.build_epoch : null,
    node_count: typeof m.node_count === 'number' ? m.node_count : null,
    loaded_at: state.loadedAt,
    path: activeDbPath(),
  };
}

module.exports = {
  init,
  reload,
  resolveCountry,
  isLoaded,
  status,
  geoipDir,
  activeDbPath,
};
