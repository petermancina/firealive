#!/usr/bin/env node
'use strict';

/*
 * derive-tier1-registry.js
 *
 * Derives the Tier-1 column registry for a FireAlive server (Management Console
 * or Global Dashboard) from the shipped source tree, and verifies the
 * derivation. The registry names every column whose ciphertext is sealed under
 * a KEK the server holds -- the columns Part A's domain-aware sealTier1/openTier1
 * chokepoint must cover -- and records, for every other candidate, an explicit
 * reason it is NOT such a column.
 *
 * The derivation has three passes:
 *
 *   1. CANDIDATES -- parse the schema (CREATE TABLE column definitions AND
 *      ALTER TABLE ... ADD COLUMN) and keep every column whose name contains a
 *      ciphertext WORD-PART (encrypted, wrapped, sealed, _sk, credential,
 *      auth_token, api_key, private_key). A word-part rule, not a suffix rule:
 *      it catches sealed_promotion_kek and analyst_key_recovery_wraps.wrapped_sk,
 *      which a *_encrypted suffix rule would miss. Migration shadow tables
 *      (<table>_new, created by SQLite rebuild-migrations) collapse onto their
 *      base table.
 *
 *   2. DOMAIN -- node-local iff the table is excluded from change-data-capture.
 *      The predicate is reconstructed here from ha-cdc's THREE EXPORTED
 *      constants (DEFAULT_EXCLUDE_TABLES / _PREFIXES / _SUFFIXES); it is not
 *      declared in this file. If ha-cdc's exclude set moves, the domain column
 *      moves with it, automatically.
 *
 *   3. CLASS / SHAPE / STORAGE -- read from the crypto call that operates on the
 *      column, on the line of that call. A column read via decryptConfig(row.X)
 *      is Tier-1 json+buffer; decrypt(row.X, 'TIER1_ENCRYPTION_KEY') is Tier-1
 *      utf8+buffer; decryptTier3 / 'TIER3_ENCRYPTION_KEY' is Tier-3. Shape and
 *      storage are taken from that same line -- never a window around it -- so a
 *      distant SHA-256 .toString('hex') can never mislabel a signing key.
 *
 * Candidates that carry NO crypto marker on any line -- a timestamp (sealed_at),
 * a filesystem path (wrapped_key_path), a hash (credential_hash), a boolean flag
 * (backup_schedules.encrypted), a client-sealed envelope the server only stores
 * (the peer_abuse_* vault, analyst_key_recovery_wraps.wrapped_sk), an HKDF-derived
 * seal (wrap_private_sealed, sealed_promotion_kek), or a dead column with no
 * writer -- are classified in MANUAL_CLASSIFICATION, each with file evidence and a
 * reason. MANUAL takes precedence over the automatic pass: it also disambiguates
 * a column NAME shared by two tables of different class (config_encrypted lives
 * in both live integration_config and dead ai_provider_config; content_encrypted
 * in both Tier-3 peer_board_messages and client-sealed peer_abuse_flags).
 *
 * The derivation FAILS (non-zero exit) if any candidate is left unclassified, if
 * a MANUAL entry is stale (its column is no longer a candidate, or its evidence
 * file no longer mentions the column), or if the per-class counts do not match
 * the expected derivation on the shipped tree. That is the coverage guarantee:
 * a new *_encrypted column cannot be added without either a live Tier-1 crypto
 * site (which this script will find and register) or an explicit human decision
 * recorded here.
 *
 * Usage:
 *   node scripts/derive-tier1-registry.js                 # derive mc + gd, print summary, assert
 *   node scripts/derive-tier1-registry.js --emit mc       # print the generated registry module (mc)
 *   node scripts/derive-tier1-registry.js --emit gd       # print the generated registry module (gd)
 *   node scripts/derive-tier1-registry.js --json mc       # full classification as JSON (for the coverage check)
 *   node scripts/derive-tier1-registry.js --json gd
 *
 * A0.2 (server/services/tier1-columns.js) and A0.3
 * (packages/global-dashboard-server/services/gd-tier1-columns.js) are the
 * committed outputs of --emit mc and --emit gd. A0.4
 * (scripts/check-tier1-registry-coverage.js) consumes --json.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

// ---------------------------------------------------------------------------
// Candidate rule (word-part, not suffix).
// ---------------------------------------------------------------------------
const WORD_PARTS = [
  'encrypted', 'wrapped', 'sealed', '_sk',
  'credential', 'auth_token', 'api_key', 'private_key',
];
function isCandidateColumn(col) {
  for (let i = 0; i < WORD_PARTS.length; i++) {
    if (col.indexOf(WORD_PARTS[i]) !== -1) return true;
  }
  return false;
}

// A <table>_new shadow (SQLite rebuild-migration scratch table) is the same
// logical table as <table>.
function baseTable(name) {
  return name.slice(-4) === '_new' ? name.slice(0, -4) : name;
}

// ---------------------------------------------------------------------------
// Per-server layout.
// ---------------------------------------------------------------------------
const SERVERS = {
  mc: {
    label: 'Management Console',
    schema: 'server/db/init.js',
    cdc: 'server/services/ha/ha-cdc.js',
    sourceRoots: ['server/services', 'server/routes', 'server/db'],
    emitPath: 'server/services/tier1-columns.js',
    emitVar: 'TIER1_COLUMNS',
  },
  gd: {
    label: 'Global Dashboard',
    schema: 'packages/global-dashboard-server/db-init.js',
    cdc: 'packages/global-dashboard-server/services/gd-ha-cdc.js', // GD's own gd_ha_* exclude twin
    sourceRoots: ['packages/global-dashboard-server'],
    emitPath: 'packages/global-dashboard-server/services/gd-tier1-columns.js',
    emitVar: 'GD_TIER1_COLUMNS',
  },
};

// ---------------------------------------------------------------------------
// Domain: reconstruct ha-cdc's isExcluded() from its exported constants only.
// ---------------------------------------------------------------------------
function loadExcludePredicate(server) {
  const cdc = require(path.join(ROOT, SERVERS[server].cdc));
  const exTables = cdc.DEFAULT_EXCLUDE_TABLES;
  const exPrefixes = cdc.DEFAULT_EXCLUDE_PREFIXES;
  const exSuffixes = cdc.DEFAULT_EXCLUDE_SUFFIXES;
  if (!Array.isArray(exTables) || !Array.isArray(exPrefixes) || !Array.isArray(exSuffixes)) {
    throw new Error('ha-cdc did not export the three exclude constants; domain cannot be derived');
  }
  // Mirrors ha-cdc.isExcluded() exactly (it is not itself exported).
  return function isExcluded(name) {
    if (exTables.indexOf(name) !== -1) return true;
    for (let i = 0; i < exPrefixes.length; i++) {
      if (name.indexOf(exPrefixes[i]) === 0) return true;
    }
    for (let j = 0; j < exSuffixes.length; j++) {
      const suf = exSuffixes[j];
      if (name.length >= suf.length && name.slice(-suf.length) === suf) return true;
    }
    return false;
  };
}

// ---------------------------------------------------------------------------
// Pass 1: candidates from the schema (CREATE TABLE + ALTER TABLE ADD COLUMN).
// ---------------------------------------------------------------------------
const RE_CREATE = /CREATE TABLE(?:\s+IF NOT EXISTS)?\s+["'`]?([a-zA-Z0-9_]+)["'`]?/;
const RE_COLUMN = /^\s*["'`]?([a-z_][a-z0-9_]*)["'`]?\s+(BLOB|TEXT|INTEGER|REAL|NUMERIC)\b/i;
const RE_ALTER = /ALTER TABLE\s+["'`]?([a-zA-Z0-9_]+)["'`]?\s+ADD COLUMN\s+["'`]?([a-z_][a-z0-9_]*)["'`]?\s*(BLOB|TEXT|INTEGER|REAL|NUMERIC)?/i;

function deriveCandidates(server) {
  const text = fs.readFileSync(path.join(ROOT, SERVERS[server].schema), 'utf8');
  const lines = text.split('\n');
  const byKey = new Map(); // baseTable.column -> { table, column, decl }
  let current = null;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];

    const alter = ln.match(RE_ALTER);
    if (alter) {
      const table = baseTable(alter[1]);
      const col = alter[2];
      const decl = (alter[3] || 'TEXT').toUpperCase();
      if (isCandidateColumn(col)) {
        const key = table + '.' + col;
        if (!byKey.has(key)) byKey.set(key, { table: table, column: col, decl: decl });
      }
      continue;
    }

    const create = ln.match(RE_CREATE);
    if (create) { current = baseTable(create[1]); continue; }

    if (current) {
      const cm = ln.match(RE_COLUMN);
      if (cm) {
        const col = cm[1];
        const decl = cm[2].toUpperCase();
        if (isCandidateColumn(col)) {
          const key = current + '.' + col;
          if (!byKey.has(key)) byKey.set(key, { table: current, column: col, decl: decl });
        }
      }
    }
  }
  return [...byKey.values()];
}

// ---------------------------------------------------------------------------
// Source index (for the automatic crypto-site pass).
// ---------------------------------------------------------------------------
function indexSource(server) {
  const roots = SERVERS[server].sourceRoots;
  const files = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (e) { return; }
    for (const ent of entries) {
      if (ent.name === 'node_modules' || ent.name === '.git' || ent.name.charAt(0) === '.') continue;
      const full = path.join(dir, ent.name);
      if (ent.isDirectory()) { walk(full); continue; }
      if (!ent.isFile()) continue;
      if (!/\.(js|cjs|mjs)$/.test(ent.name)) continue;
      let body;
      try { body = fs.readFileSync(full, 'utf8'); }
      catch (e) { continue; }
      files.push({ rel: path.relative(ROOT, full), lines: body.split('\n') });
    }
  }
  for (const r of roots) walk(path.join(ROOT, r));
  return files;
}

// ---------------------------------------------------------------------------
// Pass 3 (automatic): class/shape/storage from the crypto call operating on the
// column, read off that call's own line.
// ---------------------------------------------------------------------------
function reColUse(col) {
  // The column appears as a bound property or literal on the crypto line:
  //   decryptConfig(row.<col>)        .<col>
  //   decrypt(record['<col>'], ...)   ['<col>'] / "<col>"
  return new RegExp('(?:\\.' + col + '\\b|["\'`]' + col + '["\'`])');
}

function markersOnLine(line) {
  // Returns { tier: 'tier1'|'tier3', named: bool } or null.
  if (/\b(?:decryptConfig|encryptConfig)\s*\(/.test(line)) return { tier: 'tier1', named: true };
  if (/\b(?:decryptTier3|encryptTier3)\s*\(/.test(line)) return { tier: 'tier3', named: true };
  if (/\b(?:en|de)crypt\s*\([^\n]*['"]TIER1_ENCRYPTION_KEY['"]/.test(line)) return { tier: 'tier1', named: false };
  if (/\b(?:en|de)crypt\s*\([^\n]*['"]TIER3_ENCRYPTION_KEY['"]/.test(line)) return { tier: 'tier3', named: false };
  return null;
}

function shapeStorageOnLine(line, named) {
  // encryptConfig/encryptTier3 always JSON-serialize their argument -> json.
  // A bare encrypt(str, KEY) carries a utf8 payload unless the line itself
  // serializes/parses JSON. Storage is buffer unless the line encodes the
  // ciphertext as base64 or hex right there.
  let shape;
  if (named) {
    shape = 'json';
  } else {
    shape = /JSON\.(?:parse|stringify)/.test(line) ? 'json' : 'utf8';
  }
  let storage = 'buffer';
  if (/\.toString\(\s*['"]base64['"]\s*\)/.test(line) || /Buffer\.from\([^\n]*['"]base64['"]/.test(line)) {
    storage = 'base64';
  } else if (/\.toString\(\s*['"]hex['"]\s*\)/.test(line)) {
    storage = 'hex';
  }
  return { shape: shape, storage: storage };
}

function classifyAuto(index, col) {
  const use = reColUse(col);
  // Prefer a named-helper site (decryptConfig/decryptTier3) over a keyed
  // encrypt/decrypt site, and a reader over a writer -- but any strong site
  // settles it. First match by priority wins; evidence is that site.
  let keyed = null;
  for (const f of index) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!use.test(line)) continue;
      const m = markersOnLine(line);
      if (!m) continue;
      const ss = shapeStorageOnLine(line, m.named);
      const hit = {
        class: m.tier, shape: ss.shape, storage: ss.storage,
        evidence: { file: f.rel, line: i + 1 }, source: 'auto',
      };
      if (m.named) return hit;      // strongest: settle immediately
      if (!keyed) keyed = hit;      // remember the first keyed site
    }
  }
  return keyed; // may be null
}

// ---------------------------------------------------------------------------
// MANUAL_CLASSIFICATION -- markerless candidates, with file evidence + reason.
// Authoritative over the automatic pass. `evidence` is the file that justifies
// the class; the column name must still appear in it (staleness guard).
// ---------------------------------------------------------------------------
const MANUAL_CLASSIFICATION = {
  mc: {
    // HKDF-derived seals: sealed with a key DERIVED from the KEK, not the KEK
    // itself. Tier-1-adjacent but their own class; the rekey tool re-seals them
    // by re-derivation, it does not treat them as raw Tier-1 ciphertext.
    'ha_node.wrap_private_sealed':
      { class: 'tier1-derived', shape: 'json', storage: 'buffer', evidence: 'server/services/ha/ha-keys.js', reason: 'HKDF-derived local seal of the pairing wrap private key (ha-keys.sealToHardware)' },
    'ha_node.sealed_promotion_kek':
      { class: 'tier1-derived', shape: 'json', storage: 'buffer', evidence: 'server/services/ha/ha-failover.js', reason: 'promotion-time transport seal of the shared KEK; installed at failover, never the KEK itself' },

    // Client-sealed: the server stores an opaque envelope it cannot open. Sealed
    // on the analyst/flagger device to a recipient set the server is not part of.
    'peer_abuse_flags.content_encrypted':
      { class: 'client-sealed', shape: 'opaque', storage: 'buffer', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed flagger note (multi-recipient Team-Lead envelope); server stores verbatim, decrypts in Management Console only' },
    'peer_abuse_evidence_vault.sealed_content_encrypted':
      { class: 'client-sealed', shape: 'opaque', storage: 'buffer', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed post body envelope; server never holds a key' },
    'peer_abuse_evidence_vault.context_encrypted':
      { class: 'client-sealed', shape: 'opaque', storage: 'buffer', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed thread-context envelope; server never holds a key' },
    'analyst_key_recovery_wraps.wrapped_sk':
      { class: 'client-sealed', shape: 'opaque', storage: 'base64', evidence: 'server/routes/analyst-keys.js', reason: 'client-supplied x25519-sealedbox wrap of the analyst secret key; validated as base64, never decrypted server-side' },

    // Tier-3: analyst-keyed content, not KEK-keyed. Shares the content_encrypted
    // name with the client-sealed peer_abuse_flags column, so it is pinned here.
    'peer_board_messages.content_encrypted':
      { class: 'tier3', shape: 'utf8', storage: 'buffer', evidence: 'server/routes/peer-board.js', reason: 'Tier-3 encryptTier3 of the post body (analyst-tier key), not a KEK column' },

    // Dead columns: defined but never written. Pinned so the shared column name
    // (config_encrypted / api_key_encrypted) does not borrow a live table's
    // Tier-1 crypto site. Dropped in Part B-4.
    'ai_provider_config.config_encrypted':
      { class: 'unused', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'no writer in tree; superseded config path; dropped in B-4' },
    'automation_systems.api_key_encrypted':
      { class: 'unused', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'no writer in tree; dropped in B-4' },
    'external_restore_sources.backup_decryption_key_encrypted':
      { class: 'unused', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'no writer in tree; dropped in B-4' },

    // Not ciphertext: the word-part rule matched a non-secret column.
    'auth_recovery.credential_hash':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'a hash, not a KEK-sealed secret' },
    'backup_schedules.encrypted':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'INTEGER boolean flag (whether the destination is encrypted), not ciphertext' },
    'backups.wrapped_key_path':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'a filesystem path to a wrapped key, not the ciphertext itself' },
    'peer_abuse_evidence_vault.sealed_at':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'a timestamp (datetime), not ciphertext' },
    'webauthn_credentials.credential_id':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'server/db/init.js', reason: 'a WebAuthn credential identifier, not a KEK-sealed secret' },
  },

  gd: {
    'gd_ha_node.wrap_private_sealed':
      { class: 'tier1-derived', shape: 'json', storage: 'buffer', evidence: 'packages/global-dashboard-server/services/gd-ha-keys.js', reason: 'HKDF-derived local seal of the pairing wrap private key' },
    'gd_ha_node.sealed_promotion_kek':
      { class: 'tier1-derived', shape: 'json', storage: 'buffer', evidence: 'packages/global-dashboard-server/services/gd-ha-failover.js', reason: 'promotion-time transport seal of the shared KEK' },

    'external_restore_sources.backup_decryption_key_encrypted':
      { class: 'unused', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'no writer in tree; dropped in B-4' },

    'management_consoles.api_key':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/index.js', reason: 'MC-trust shared-secret bearer token, matched by equality (WHERE api_key = ?); not KEK ciphertext' },
    'auth_recovery.credential_hash':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a hash, not a KEK-sealed secret' },
    'backup_schedules.encrypted':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'INTEGER boolean flag, not ciphertext' },
    'backups.wrapped_key_path':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a filesystem path to a wrapped key, not the ciphertext itself' },
    'webauthn_credentials.credential_id':
      { class: 'not-ciphertext', shape: 'n-a', storage: 'n-a', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a WebAuthn credential identifier, not a KEK-sealed secret' },
  },
};

// ---------------------------------------------------------------------------
// Expected derivation on the shipped tree (the acceptance test). Counts are over
// the meaningful classes; not-ciphertext is reported but not pinned to a number.
// ---------------------------------------------------------------------------
const EXPECTED = {
  mc: { tier1: 19, 'tier1-derived': 2, tier3: 1, 'client-sealed': 4, unused: 3 },
  gd: { tier1: 10, 'tier1-derived': 2, tier3: 0, 'client-sealed': 0, unused: 1 },
};
const NODE_LOCAL_EXPECTED = { mc: 9, gd: 6 };

const ALL_CLASSES = ['tier1', 'tier1-derived', 'tier3', 'client-sealed', 'unused', 'not-ciphertext'];

// ---------------------------------------------------------------------------
// Derive one server: classify every candidate; collect problems.
// ---------------------------------------------------------------------------
function fileMentions(relFile, col) {
  try {
    const body = fs.readFileSync(path.join(ROOT, relFile), 'utf8');
    return body.indexOf(col) !== -1;
  } catch (e) {
    return false;
  }
}

function derive(server) {
  const isExcluded = loadExcludePredicate(server);
  const candidates = deriveCandidates(server);
  const index = indexSource(server);
  const manual = MANUAL_CLASSIFICATION[server] || {};

  const rows = [];
  const unclassified = [];
  const staleManual = [];
  const candidateKeys = new Set(candidates.map(function (c) { return c.table + '.' + c.column; }));

  for (const c of candidates) {
    const key = c.table + '.' + c.column;
    const domain = isExcluded(c.table) ? 'node-local' : 'replicated';
    let cls = null;

    if (Object.prototype.hasOwnProperty.call(manual, key)) {
      const m = manual[key];
      if (!fileMentions(m.evidence, c.column)) {
        staleManual.push({ key: key, reason: 'evidence file no longer mentions the column: ' + m.evidence });
      }
      cls = {
        class: m.class, shape: m.shape, storage: m.storage,
        evidence: { file: m.evidence, line: null }, source: 'manual', reason: m.reason,
      };
    } else {
      const auto = classifyAuto(index, c.column);
      if (auto) {
        cls = auto;
      } else {
        unclassified.push(key);
        cls = { class: 'UNCLASSIFIED', shape: 'n-a', storage: 'n-a', evidence: null, source: 'none' };
      }
    }

    rows.push({
      table: c.table, column: c.column, decl: c.decl, domain: domain,
      class: cls.class, shape: cls.shape, storage: cls.storage,
      source: cls.source, evidence: cls.evidence, reason: cls.reason || null,
    });
  }

  // Stale MANUAL entries whose column is no longer a candidate at all.
  for (const key of Object.keys(manual)) {
    if (!candidateKeys.has(key)) {
      staleManual.push({ key: key, reason: 'column is no longer a schema candidate' });
    }
  }

  const counts = {};
  for (const cl of ALL_CLASSES) counts[cl] = 0;
  let nodeLocalTier1 = 0;
  let replicatedTier1 = 0;
  for (const r of rows) {
    if (Object.prototype.hasOwnProperty.call(counts, r.class)) counts[r.class] += 1;
    if (r.class === 'tier1') {
      if (r.domain === 'node-local') nodeLocalTier1 += 1; else replicatedTier1 += 1;
    }
  }

  return {
    server: server,
    rows: rows.sort(rowSort),
    counts: counts,
    nodeLocalTier1: nodeLocalTier1,
    replicatedTier1: replicatedTier1,
    unclassified: unclassified,
    staleManual: staleManual,
  };
}

function rowSort(a, b) {
  const order = { 'node-local': 0, 'replicated': 1 };
  const da = order[a.domain] == null ? 2 : order[a.domain];
  const db = order[b.domain] == null ? 2 : order[b.domain];
  if (da !== db) return da - db;
  if (a.table !== b.table) return a.table < b.table ? -1 : 1;
  return a.column < b.column ? -1 : (a.column > b.column ? 1 : 0);
}

// ---------------------------------------------------------------------------
// Verify against the expected derivation.
// ---------------------------------------------------------------------------
function verify(d) {
  const problems = [];
  const exp = EXPECTED[d.server];
  for (const cl of Object.keys(exp)) {
    if (d.counts[cl] !== exp[cl]) {
      problems.push(d.server + ': expected ' + exp[cl] + ' ' + cl + ', derived ' + d.counts[cl]);
    }
  }
  if (d.nodeLocalTier1 !== NODE_LOCAL_EXPECTED[d.server]) {
    problems.push(d.server + ': expected ' + NODE_LOCAL_EXPECTED[d.server] + ' node-local tier1, derived ' + d.nodeLocalTier1);
  }
  for (const key of d.unclassified) problems.push(d.server + ': UNCLASSIFIED candidate ' + key);
  for (const s of d.staleManual) problems.push(d.server + ': stale MANUAL entry ' + s.key + ' (' + s.reason + ')');
  return problems;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------
function printSummary(d) {
  console.log('== ' + d.server.toUpperCase() + ' (' + SERVERS[d.server].label + ') ==');
  console.log('   tier1           ' + d.counts.tier1 +
    '  (node-local ' + d.nodeLocalTier1 + ', replicated ' + d.replicatedTier1 + ')');
  console.log('   tier1-derived   ' + d.counts['tier1-derived']);
  console.log('   tier3           ' + d.counts.tier3);
  console.log('   client-sealed   ' + d.counts['client-sealed']);
  console.log('   unused          ' + d.counts.unused);
  console.log('   not-ciphertext  ' + d.counts['not-ciphertext']);
  console.log('   ---- candidates ' + d.rows.length +
    ', unclassified ' + d.unclassified.length + ', stale-manual ' + d.staleManual.length);
  console.log('');
  console.log('   Tier-1 registry (tier1 + tier1-derived):');
  for (const r of d.rows) {
    if (r.class !== 'tier1' && r.class !== 'tier1-derived') continue;
    console.log('     [' + pad(r.domain, 10) + '] ' + pad(r.class, 13) + ' ' +
      pad(r.shape, 6) + ' ' + pad(r.storage, 6) + ' ' + r.table + '.' + r.column);
  }
  console.log('');
}
function pad(s, n) { s = String(s); while (s.length < n) s += ' '; return s; }

function emitModule(d) {
  const S = SERVERS[d.server];
  const registry = d.rows
    .filter(function (r) { return r.class === 'tier1' || r.class === 'tier1-derived'; })
    .map(function (r) {
      return "  { table: '" + r.table + "', column: '" + r.column + "', domain: '" +
        r.domain + "', class: '" + r.class + "', shape: '" + r.shape + "', storage: '" + r.storage + "' },";
    });
  const out = [];
  out.push("'use strict';");
  out.push('');
  out.push('/*');
  out.push(' * ' + path.basename(S.emitPath) + ' -- GENERATED by scripts/derive-tier1-registry.js.');
  out.push(' * DO NOT EDIT BY HAND. Regenerate: node scripts/derive-tier1-registry.js --emit ' + d.server);
  out.push(' *');
  out.push(' * The Tier-1 columns of the ' + S.label + ' schema: those sealed under a KEK');
  out.push(' * this server holds. domain node-local uses the node own KEK; domain replicated');
  out.push(' * uses the shared (active) KEK. class tier1-derived is HKDF-sealed from the KEK.');
  out.push(' */');
  out.push('');
  out.push('const ' + S.emitVar + ' = [');
  for (const line of registry) out.push(line);
  out.push('];');
  out.push('');
  out.push('module.exports = { ' + S.emitVar + ': ' + S.emitVar + ' };');
  out.push('');
  return out.join('\n');
}

function jsonFull(d) {
  return JSON.stringify({
    server: d.server,
    counts: d.counts,
    nodeLocalTier1: d.nodeLocalTier1,
    replicatedTier1: d.replicatedTier1,
    unclassified: d.unclassified,
    staleManual: d.staleManual,
    columns: d.rows,
  }, null, 2);
}

// ---------------------------------------------------------------------------
// CLI.
// ---------------------------------------------------------------------------
function main() {
  const argv = process.argv.slice(2);
  const emitIdx = argv.indexOf('--emit');
  const jsonIdx = argv.indexOf('--json');

  if (emitIdx !== -1) {
    const server = argv[emitIdx + 1];
    if (!SERVERS[server]) { console.error('usage: --emit <mc|gd>'); process.exit(2); }
    const d = derive(server);
    const problems = verify(d);
    if (problems.length) {
      console.error('refusing to emit: derivation does not verify:');
      for (const p of problems) console.error('  - ' + p);
      process.exit(1);
    }
    process.stdout.write(emitModule(d));
    return;
  }

  if (jsonIdx !== -1) {
    const server = argv[jsonIdx + 1];
    if (!SERVERS[server]) { console.error('usage: --json <mc|gd>'); process.exit(2); }
    process.stdout.write(jsonFull(derive(server)));
    return;
  }

  // Default: derive both, print, assert.
  let problems = [];
  for (const server of ['mc', 'gd']) {
    const d = derive(server);
    printSummary(d);
    problems = problems.concat(verify(d));
  }
  if (problems.length) {
    console.error('DERIVATION FAILED:');
    for (const p of problems) console.error('  - ' + p);
    process.exit(1);
  }
  console.log('OK: both servers derive and verify against the expected classification.');
}

if (require.main === module) main();

module.exports = { derive: derive, verify: verify, emitModule: emitModule, EXPECTED: EXPECTED };
