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
 * WHAT IS DERIVED AUTOMATICALLY (from source, every run):
 *
 *   1. CANDIDATES -- schema columns whose name contains a ciphertext WORD-PART
 *      (encrypted, wrapped, sealed, _sk, credential, auth_token, api_key,
 *      private_key). A word-part rule, not a suffix rule: it catches
 *      sealed_promotion_kek and analyst_key_recovery_wraps.wrapped_sk, which a
 *      *_encrypted suffix rule would miss. Both CREATE TABLE and ALTER TABLE ADD
 *      COLUMN are scanned (notification_config.sms_auth_token_encrypted is
 *      ALTER-added). Migration shadow tables (<table>_new) collapse onto <table>.
 *
 *   2. DOMAIN -- node-local iff the table is excluded from change-data-capture.
 *      The predicate is reconstructed from the server's ha-cdc THREE EXPORTED
 *      constants (DEFAULT_EXCLUDE_TABLES / _PREFIXES / _SUFFIXES); GD uses its own
 *      gd-ha-cdc twin. It is not declared here: if the exclude set moves, the
 *      domain column moves with it.
 *
 *   3. CLASS -- from the key tier of the crypto call that operates on the column.
 *      A Tier-1 marker (encryptConfig/decryptConfig, encrypt/decrypt with
 *      'TIER1_ENCRYPTION_KEY', or the encryptTier1/decryptTier1 phantom) is
 *      tier1; a Tier-3 marker is tier3. Markerless candidates are classified in
 *      MANUAL_CLASSIFICATION (below), which takes precedence.
 *
 * WHY SHAPE / STORAGE ARE CITED FACTS, NOT NAME-DERIVED:
 *
 *   The at-rest encoding of a column is not a property of its name. It is
 *   per-table AND per-server, and it hides behind helper indirection
 *   (decryptCredentials, _decryptKey, sealToHardware). The name credentials_
 *   encrypted alone is stored five different ways:
 *
 *     MC storage_destinations   raw iv|tag|ct Buffer, base64-encoded into TEXT
 *     MC kms_providers          raw iv|tag|ct Buffer, HEX-encoded  into TEXT
 *     MC sdn_integrations       raw iv|tag|ct Buffer, in a BLOB       (buffer)
 *     GD storage_destinations   gd-encryption self-describing JSON envelope STRING
 *     GD external_restore       raw ciphertext, base64-encoded into TEXT
 *
 *   MC's encryptConfig returns a raw Buffer(iv|tag|ct); GD's encryptConfig
 *   (gd-encryption) returns a JSON envelope string {v,iv,tag,ciphertext}. A
 *   reader that inferred encoding from a column NAME would stamp one table's
 *   encoding onto every table that shares the name, and would conflate the two
 *   servers' envelope architectures. So shape/storage are recorded per column in
 *   ENCODING as reviewed facts, each carrying a source file and a distinctive
 *   PROOF substring; the script re-reads the cited file every run and fails if
 *   the proof is gone (the encoding changed) -- exactly correction #3's intent
 *   (read the encoding from the crypto site, never a distant window) and #4's
 *   (file evidence, drift-checked). shape and storage still come from the actual
 *   crypto site; the citation records WHICH site is authoritative, because
 *   automatic attribution across shared names and helpers is not reliable.
 *
 *     shape   : json    plaintext is JSON-serialized before sealing
 *               utf8    plaintext is a UTF-8 string
 *               raw     plaintext is opaque bytes (a key)
 *     storage : buffer    ciphertext stored as a raw Buffer (BLOB, or a Buffer
 *                         bound to a TEXT column)
 *               base64    ciphertext base64-encoded into a TEXT column
 *               hex       ciphertext hex-encoded into a TEXT column
 *               envelope  gd-encryption self-describing JSON envelope string
 *
 * The derivation FAILS (non-zero exit) on: an unclassified candidate; a stale
 * MANUAL entry (its column is no longer a candidate, or its evidence file no
 * longer mentions the column); a tier1/tier1-derived/tier3 column with no
 * ENCODING entry; an ENCODING entry whose evidence file or proof is missing; or
 * a per-class count that does not match the expected derivation on the shipped
 * tree. That is the coverage guarantee: a new *_encrypted column cannot land
 * without either a live Tier-1 crypto site the script finds, or an explicit
 * human decision with cited evidence.
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

const SHAPES = ['json', 'utf8', 'raw'];
const STORAGES = ['buffer', 'base64', 'hex', 'envelope'];
const ENCODED_CLASSES = ['tier1', 'tier1-derived', 'tier3']; // must have an ENCODING entry
const ALL_CLASSES = ['tier1', 'tier1-derived', 'tier3', 'client-sealed', 'unused', 'not-ciphertext'];

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
// Source index (for the automatic class pass).
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
// Pass 3 (automatic): CLASS from the key tier of the crypto call on the column.
// ---------------------------------------------------------------------------
function reColUse(col) {
  return new RegExp('(?:\\.' + col + '\\b|["\'`]' + col + '["\'`])');
}
function tierMarkerOnLine(line) {
  // Named Tier-1 helper, the encryptTier1/decryptTier1 phantom, or a TIER1-keyed
  // encrypt/decrypt -> tier1. The Tier-3 equivalents -> tier3.
  if (/\b(?:decryptConfig|encryptConfig|decryptTier1|encryptTier1)\s*\(/.test(line)) return 'tier1';
  if (/\b(?:decryptTier3|encryptTier3)\s*\(/.test(line)) return 'tier3';
  if (/\b(?:en|de)crypt\s*\([^\n]*['"]TIER1_ENCRYPTION_KEY['"]/.test(line)) return 'tier1';
  if (/\b(?:en|de)crypt\s*\([^\n]*['"]TIER3_ENCRYPTION_KEY['"]/.test(line)) return 'tier3';
  return null;
}
function classifyAuto(index, col) {
  const use = reColUse(col);
  for (const f of index) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!use.test(line)) continue;
      const tier = tierMarkerOnLine(line);
      if (tier) return { class: tier, evidence: { file: f.rel, line: i + 1 }, source: 'auto' };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// ENCODING -- per-column shape/storage, each with a source file and a PROOF
// substring that must be present in it. Reviewed facts, drift-checked.
// ---------------------------------------------------------------------------
const ENCODING = {
  mc: {
    // node-local signing keys: encryptConfig returns a raw iv|tag|ct Buffer,
    // read back via decryptConfig(row.<col>) with no base64/hex codec -> buffer.
    'abuse_vault_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'archive_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'audit_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'backup_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'forensic_export_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'gd_push_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'report_signing_keys.private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/chain-signing-keys.js', proof: 'decryptConfig(row.private_key_encrypted)' },
    'cloud_iac_signing_keys.private_key_wrapped': { shape: 'json', storage: 'buffer', ev: 'server/services/cloud-iac-signing-keys.js', proof: 'decryptConfig(row.private_key_wrapped)' },

    // tier1-derived: hardware seals. sealToHardware returns base64(JSON{iv,ct,tag}).
    'ha_node.wrap_private_sealed': { shape: 'utf8', storage: 'base64', ev: 'server/services/ha/ha-keys.js', proof: 'unsealFromHardware(row.wrap_private_sealed)' },
    'ha_node.sealed_promotion_kek': { shape: 'raw', storage: 'base64', ev: 'server/services/ha/ha-pairing.js', proof: 'sealed_promotion_kek = ?' },

    // replicated tier1
    'ca_authority.ca_private_key_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/ca.js', proof: 'encryptConfig({ pem: caKeyPem })' },
    'integration_config.config_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/services/account-review.js', proof: 'decryptConfig(row.config_encrypted)' },
    'sdn_integrations.api_credentials_encrypted': { shape: 'json', storage: 'buffer', ev: 'server/routes/sdn.js', proof: 'encryptConfig(credentials)' },
    'storage_destinations.credentials_encrypted': { shape: 'json', storage: 'base64', ev: 'server/services/storage-destinations.js', proof: "Buffer.from(stored, 'base64')" },
    'malware_scanner_integrations.credentials_encrypted': { shape: 'json', storage: 'base64', ev: 'server/services/integration-manager.js', proof: "Buffer.from(row.credentials_encrypted, 'base64')" },
    'external_restore_sources.credentials_encrypted': { shape: 'json', storage: 'base64', ev: 'server/services/external-restore.js', proof: "Buffer.from(sourceRow.credentials_encrypted, 'base64')" },
    'scheduling_platform_config.credentials_encrypted': { shape: 'json', storage: 'base64', ev: 'server/services/scheduling-sync.js', proof: 'base64 blob' },
    'kms_providers.credentials_encrypted': { shape: 'json', storage: 'hex', ev: 'server/services/kms-providers.js', proof: "Buffer.from(hexOrNull, 'hex')" },
    'gd_push_config.api_key_encrypted': { shape: 'utf8', storage: 'base64', ev: 'server/services/gd-push.js', proof: 'base64-encoded' },
    'notification_config.sms_auth_token_encrypted': { shape: 'utf8', storage: 'buffer', ev: 'server/routes/notifications.js', proof: "encrypt(smsAuthToken, 'TIER1_ENCRYPTION_KEY')" },

    // tier3 (excluded from the operational registry; encoding recorded for coverage)
    'peer_board_messages.content_encrypted': { shape: 'utf8', storage: 'buffer', ev: 'server/routes/peer-board.js', proof: 'encryptTier3(content)' },
  },

  gd: {
    // GD signing keys + ca + integration credentials go through gd-encryption,
    // whose encryptConfig returns a self-describing JSON envelope STRING.
    'archive_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },
    'audit_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },
    'backup_signing_keys.private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },
    'report_signing_keys.private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },
    'forensic_export_chain_signing_keys.private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },
    'cloud_iac_signing_keys.private_key_wrapped': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-backup-signing-keys.js', proof: "require('./gd-encryption')" },

    'gd_ha_node.wrap_private_sealed': { shape: 'utf8', storage: 'base64', ev: 'packages/global-dashboard-server/services/gd-ha-keys.js', proof: 'unsealFromHardware(row.wrap_private_sealed)' },
    'gd_ha_node.sealed_promotion_kek': { shape: 'raw', storage: 'base64', ev: 'packages/global-dashboard-server/services/gd-ha-pairing.js', proof: 'sealed_promotion_kek = ?' },

    'ca_authority.ca_private_key_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-ca.js', proof: 'decryptConfig(row.ca_private_key_encrypted)' },
    'storage_destinations.credentials_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-storage-destinations.js', proof: 'self-describing' },
    'malware_scanner_integrations.credentials_encrypted': { shape: 'json', storage: 'envelope', ev: 'packages/global-dashboard-server/services/gd-integration-manager.js', proof: 'decryptConfig(row.credentials_encrypted)' },
    'external_restore_sources.credentials_encrypted': { shape: 'json', storage: 'base64', ev: 'packages/global-dashboard-server/services/gd-external-restore.js', proof: "Buffer.from(sourceRow.credentials_encrypted, 'base64')" },
  },
};

// ---------------------------------------------------------------------------
// MANUAL_CLASSIFICATION -- markerless candidates, with file evidence + reason.
// Authoritative over the automatic CLASS pass. shape/storage for tier1-derived
// and tier3 entries come from ENCODING; client-sealed/unused/not-ciphertext have
// no KEK encoding. `evidence` must still mention the column (staleness guard).
// ---------------------------------------------------------------------------
const MANUAL_CLASSIFICATION = {
  mc: {
    'ha_node.wrap_private_sealed': { class: 'tier1-derived', evidence: 'server/services/ha/ha-keys.js', reason: 'HKDF-derived local seal of the pairing wrap private key (ha-keys.sealToHardware)' },
    'ha_node.sealed_promotion_kek': { class: 'tier1-derived', evidence: 'server/services/ha/ha-pairing.js', reason: 'promotion-time transport seal of the shared KEK; installed at pairing/failover, never the KEK itself' },

    'peer_abuse_flags.content_encrypted': { class: 'client-sealed', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed flagger note (multi-recipient Team-Lead envelope); server stores verbatim, decrypts in Management Console only' },
    'peer_abuse_evidence_vault.sealed_content_encrypted': { class: 'client-sealed', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed post body envelope; server never holds a key' },
    'peer_abuse_evidence_vault.context_encrypted': { class: 'client-sealed', evidence: 'server/routes/peer-flags.js', reason: 'client-sealed thread-context envelope; server never holds a key' },
    'analyst_key_recovery_wraps.wrapped_sk': { class: 'client-sealed', evidence: 'server/routes/analyst-keys.js', reason: 'client-supplied x25519-sealedbox wrap of the analyst secret key; validated as base64, never decrypted server-side' },

    'peer_board_messages.content_encrypted': { class: 'tier3', evidence: 'server/routes/peer-board.js', reason: 'Tier-3 encryptTier3 of the post body (analyst-tier key), not a KEK column; shares the content_encrypted name with the client-sealed peer_abuse_flags column' },

    'ai_provider_config.config_encrypted': { class: 'unused', evidence: 'server/db/init.js', reason: 'no writer in tree; superseded config path; dropped in B-4' },
    'automation_systems.api_key_encrypted': { class: 'unused', evidence: 'server/db/init.js', reason: 'no writer in tree; dropped in B-4' },
    'external_restore_sources.backup_decryption_key_encrypted': { class: 'unused', evidence: 'server/db/init.js', reason: 'no writer in tree; dropped in B-4' },

    'auth_recovery.credential_hash': { class: 'not-ciphertext', evidence: 'server/db/init.js', reason: 'a hash, not a KEK-sealed secret' },
    'backup_schedules.encrypted': { class: 'not-ciphertext', evidence: 'server/db/init.js', reason: 'INTEGER boolean flag (whether the destination is encrypted), not ciphertext' },
    'backups.wrapped_key_path': { class: 'not-ciphertext', evidence: 'server/db/init.js', reason: 'a filesystem path to a wrapped key, not the ciphertext itself' },
    'peer_abuse_evidence_vault.sealed_at': { class: 'not-ciphertext', evidence: 'server/db/init.js', reason: 'a timestamp (datetime), not ciphertext' },
    'webauthn_credentials.credential_id': { class: 'not-ciphertext', evidence: 'server/db/init.js', reason: 'a WebAuthn credential identifier, not a KEK-sealed secret' },
  },

  gd: {
    'gd_ha_node.wrap_private_sealed': { class: 'tier1-derived', evidence: 'packages/global-dashboard-server/services/gd-ha-keys.js', reason: 'HKDF-derived local seal of the pairing wrap private key' },
    'gd_ha_node.sealed_promotion_kek': { class: 'tier1-derived', evidence: 'packages/global-dashboard-server/services/gd-ha-pairing.js', reason: 'promotion-time transport seal of the shared KEK' },

    'external_restore_sources.backup_decryption_key_encrypted': { class: 'unused', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'no writer in tree; dropped in B-4' },

    'management_consoles.api_key': { class: 'not-ciphertext', evidence: 'packages/global-dashboard-server/index.js', reason: 'MC-trust shared-secret bearer token, matched by equality (WHERE api_key = ?); not KEK ciphertext' },
    'auth_recovery.credential_hash': { class: 'not-ciphertext', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a hash, not a KEK-sealed secret' },
    'backup_schedules.encrypted': { class: 'not-ciphertext', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'INTEGER boolean flag, not ciphertext' },
    'backups.wrapped_key_path': { class: 'not-ciphertext', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a filesystem path to a wrapped key, not the ciphertext itself' },
    'webauthn_credentials.credential_id': { class: 'not-ciphertext', evidence: 'packages/global-dashboard-server/db-init.js', reason: 'a WebAuthn credential identifier, not a KEK-sealed secret' },
  },
};

// ---------------------------------------------------------------------------
// Expected derivation on the shipped tree (the acceptance test). Counts over
// the meaningful classes; not-ciphertext is reported but not pinned.
// ---------------------------------------------------------------------------
const EXPECTED = {
  mc: { tier1: 19, 'tier1-derived': 2, tier3: 1, 'client-sealed': 4, unused: 3 },
  gd: { tier1: 10, 'tier1-derived': 2, tier3: 0, 'client-sealed': 0, unused: 1 },
};
const NODE_LOCAL_EXPECTED = { mc: 9, gd: 6 };

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------
function fileContains(relFile, needle) {
  try { return fs.readFileSync(path.join(ROOT, relFile), 'utf8').indexOf(needle) !== -1; }
  catch (e) { return false; }
}

// Codecs the source directly co-locates with the column (a sanity cross-check on
// the declared storage; shared column names can widen this, so it only fails on
// a positively wrong buffer/envelope claim, never on a plausible one).
function observedCodecs(index, col) {
  const set = { base64: false, hex: false };
  const reB64 = new RegExp('Buffer\\.from\\([^,]*\\b' + col + '\\b[^,]*,\\s*[\'"]base64[\'"]');
  const reHex = new RegExp('Buffer\\.from\\([^,]*\\b' + col + '\\b[^,]*,\\s*[\'"]hex[\'"]');
  for (const f of index) {
    for (const line of f.lines) {
      if (reB64.test(line)) set.base64 = true;
      if (reHex.test(line)) set.hex = true;
    }
  }
  return set;
}

// ---------------------------------------------------------------------------
// Derive one server.
// ---------------------------------------------------------------------------
function derive(server) {
  const isExcluded = loadExcludePredicate(server);
  const candidates = deriveCandidates(server);
  const index = indexSource(server);
  const manual = MANUAL_CLASSIFICATION[server] || {};
  const enc = ENCODING[server] || {};

  const rows = [];
  const unclassified = [];
  const staleManual = [];
  const missingEncoding = [];
  const encodingDrift = [];
  const candidateKeys = new Set(candidates.map(function (c) { return c.table + '.' + c.column; }));

  for (const c of candidates) {
    const key = c.table + '.' + c.column;
    const domain = isExcluded(c.table) ? 'node-local' : 'replicated';

    // CLASS: manual first, else automatic.
    let cls, classSource, classEvidence, reason = null;
    if (Object.prototype.hasOwnProperty.call(manual, key)) {
      const m = manual[key];
      if (!fileContains(m.evidence, c.column)) {
        staleManual.push({ key: key, reason: 'evidence file no longer mentions the column: ' + m.evidence });
      }
      cls = m.class; classSource = 'manual'; classEvidence = { file: m.evidence, line: null }; reason = m.reason;
    } else {
      const auto = classifyAuto(index, c.column);
      if (auto) { cls = auto.class; classSource = 'auto'; classEvidence = auto.evidence; }
      else { cls = 'UNCLASSIFIED'; classSource = 'none'; classEvidence = null; unclassified.push(key); }
    }

    // SHAPE / STORAGE: from ENCODING for encoded classes; else none.
    let shape = 'n-a', storage = 'n-a', encEvidence = null;
    if (ENCODED_CLASSES.indexOf(cls) !== -1) {
      if (Object.prototype.hasOwnProperty.call(enc, key)) {
        const e = enc[key];
        shape = e.shape; storage = e.storage; encEvidence = { file: e.ev, proof: e.proof };
        if (SHAPES.indexOf(shape) === -1) encodingDrift.push({ key: key, reason: 'invalid shape: ' + shape });
        if (STORAGES.indexOf(storage) === -1) encodingDrift.push({ key: key, reason: 'invalid storage: ' + storage });
        if (!fileContains(e.ev, e.proof)) {
          encodingDrift.push({ key: key, reason: 'ENCODING proof not found in ' + e.ev + ': ' + e.proof });
        }
        const obs = observedCodecs(index, c.column);
        if (storage === 'buffer' && (obs.base64 || obs.hex)) {
          encodingDrift.push({ key: key, reason: 'declared buffer but source co-locates a base64/hex codec for the column' });
        }
      } else {
        missingEncoding.push(key);
      }
    } else if (cls === 'client-sealed') {
      storage = 'opaque';
    }

    rows.push({
      table: c.table, column: c.column, decl: c.decl, domain: domain,
      class: cls, shape: shape, storage: storage,
      classSource: classSource, classEvidence: classEvidence, encEvidence: encEvidence, reason: reason,
    });
  }

  // Stale MANUAL entries whose column is no longer a candidate.
  for (const key of Object.keys(manual)) {
    if (!candidateKeys.has(key)) staleManual.push({ key: key, reason: 'column is no longer a schema candidate' });
  }
  // Orphan ENCODING entries whose column is not a candidate.
  for (const key of Object.keys(enc)) {
    if (!candidateKeys.has(key)) encodingDrift.push({ key: key, reason: 'ENCODING entry for a non-candidate column' });
  }

  const counts = {};
  for (const cl of ALL_CLASSES) counts[cl] = 0;
  let nodeLocalTier1 = 0, replicatedTier1 = 0;
  for (const r of rows) {
    if (Object.prototype.hasOwnProperty.call(counts, r.class)) counts[r.class] += 1;
    if (r.class === 'tier1') { if (r.domain === 'node-local') nodeLocalTier1 += 1; else replicatedTier1 += 1; }
  }

  return {
    server: server, rows: rows.sort(rowSort), counts: counts,
    nodeLocalTier1: nodeLocalTier1, replicatedTier1: replicatedTier1,
    unclassified: unclassified, staleManual: staleManual,
    missingEncoding: missingEncoding, encodingDrift: encodingDrift,
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
    if (d.counts[cl] !== exp[cl]) problems.push(d.server + ': expected ' + exp[cl] + ' ' + cl + ', derived ' + d.counts[cl]);
  }
  if (d.nodeLocalTier1 !== NODE_LOCAL_EXPECTED[d.server]) {
    problems.push(d.server + ': expected ' + NODE_LOCAL_EXPECTED[d.server] + ' node-local tier1, derived ' + d.nodeLocalTier1);
  }
  for (const key of d.unclassified) problems.push(d.server + ': UNCLASSIFIED candidate ' + key);
  for (const key of d.missingEncoding) problems.push(d.server + ': tier1/derived/tier3 column has no ENCODING entry: ' + key);
  for (const s of d.staleManual) problems.push(d.server + ': stale MANUAL entry ' + s.key + ' (' + s.reason + ')');
  for (const s of d.encodingDrift) problems.push(d.server + ': ENCODING drift ' + s.key + ' (' + s.reason + ')');
  return problems;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------
function pad(s, n) { s = String(s); while (s.length < n) s += ' '; return s; }

function printSummary(d) {
  console.log('== ' + d.server.toUpperCase() + ' (' + SERVERS[d.server].label + ') ==');
  console.log('   tier1           ' + d.counts.tier1 + '  (node-local ' + d.nodeLocalTier1 + ', replicated ' + d.replicatedTier1 + ')');
  console.log('   tier1-derived   ' + d.counts['tier1-derived']);
  console.log('   tier3           ' + d.counts.tier3);
  console.log('   client-sealed   ' + d.counts['client-sealed']);
  console.log('   unused          ' + d.counts.unused);
  console.log('   not-ciphertext  ' + d.counts['not-ciphertext']);
  console.log('   ---- candidates ' + d.rows.length + ', unclassified ' + d.unclassified.length +
    ', missing-encoding ' + d.missingEncoding.length + ', stale-manual ' + d.staleManual.length +
    ', encoding-drift ' + d.encodingDrift.length);
  console.log('');
  console.log('   Tier-1 registry (tier1 + tier1-derived):');
  for (const r of d.rows) {
    if (r.class !== 'tier1' && r.class !== 'tier1-derived') continue;
    console.log('     [' + pad(r.domain, 10) + '] ' + pad(r.class, 13) + ' ' + pad(r.shape, 4) + ' ' + pad(r.storage, 8) + ' ' + r.table + '.' + r.column);
  }
  console.log('');
}

function emitModule(d) {
  const S = SERVERS[d.server];
  const registry = d.rows
    .filter(function (r) { return r.class === 'tier1' || r.class === 'tier1-derived'; })
    .map(function (r) {
      return "  { table: '" + r.table + "', column: '" + r.column + "', domain: '" + r.domain +
        "', class: '" + r.class + "', shape: '" + r.shape + "', storage: '" + r.storage + "' },";
    });
  const out = [];
  out.push("'use strict';");
  out.push('');
  out.push('/*');
  out.push(' * ' + path.basename(S.emitPath) + ' -- GENERATED by scripts/derive-tier1-registry.js.');
  out.push(' * DO NOT EDIT BY HAND. Regenerate: node scripts/derive-tier1-registry.js --emit ' + d.server);
  out.push(' *');
  out.push(' * The Tier-1 columns of the ' + S.label + ' schema: those sealed under a KEK this');
  out.push(' * server holds. domain node-local uses the node own KEK; domain replicated uses the');
  out.push(' * shared (active) KEK. class tier1-derived is HKDF-sealed from the KEK. shape is the');
  out.push(' * plaintext serialization (json|utf8|raw); storage is the at-rest encoding');
  out.push(' * (buffer|base64|hex|envelope).');
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
    server: d.server, counts: d.counts,
    nodeLocalTier1: d.nodeLocalTier1, replicatedTier1: d.replicatedTier1,
    unclassified: d.unclassified, missingEncoding: d.missingEncoding,
    staleManual: d.staleManual, encodingDrift: d.encodingDrift,
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
