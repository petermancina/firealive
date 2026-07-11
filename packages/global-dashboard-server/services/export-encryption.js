// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE -- Export Encryption at Rest (FA-ENC1) -- Global Dashboard variant
//
// Seals forensic-export artifacts at rest. Each artifact
// (the gzipped tar archive, and its manifest.json sidecar) is written as a
// self-describing FA-ENC1 file: a fresh per-artifact AES-256-GCM data key
// encrypts the plaintext, and that data key is wrapped under the GD-server's own
// Tier-1 KEK via gd-encryption (the GD-server has no key-wrapping-providers
// registry; the Management Console and the GD keep independent KEKs). The raw
// data key never touches disk.
//
// The delivered (downloaded) package is unchanged: the server decrypts on
// authenticated download and streams the standard signed tar.gz. This module
// only changes the at-rest representation on the server.
//
// FA-ENC1 FILE LAYOUT
//
//   offset 0    magic       6 bytes    ASCII "FAENC1"
//   offset 6    version     1 byte     0x01
//   offset 7    role        1 byte     0x01 = archive, 0x02 = manifest
//   offset 8    headerLen   4 bytes    uint32 big-endian
//   offset 12   headerJSON  headerLen bytes (UTF-8)
//               ciphertext  remaining bytes
//
//   headerJSON = {
//     alg:       "aes-256-gcm",
//     role:      "archive" | "manifest",
//     export_id: "<id>",
//     iv:        "<base64, 12 bytes>",
//     tag:       "<base64, 16 bytes>",
//     kek:       <gd-encryption wrap {v,scheme:'gd-tier1',wrapped}> | null
//   }
//
// AEAD: the GCM additional authenticated data is the ASCII string
//   "FAENC1|v1|<role>|<export_id>"
// so the tag also authenticates the role and export id. A ciphertext file moved
// between two artifacts, or between two exports, fails to open. The file is
// self-describing: with the KEK alone (no database), any artifact decrypts,
// which is the disaster-recovery property.
//
// API
//   sealWithKey(plaintext, dataKey, { exportId, role })  -> framed Buffer   (keyless; tests/regression)
//   openWithKey(framed, dataKey)                         -> plaintext Buffer
//   sealArtifact(plaintext, { exportId, role, db })      -> { framed, scheme, kekRef }  (async; KEK-wrap)
//   openArtifact(framed, { db })                         -> plaintext Buffer            (async; KEK-unwrap)
//   isFramed(buf)                                        -> boolean
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const gdEncryption = require('./gd-encryption');

const MAGIC = Buffer.from('FAENC1', 'latin1');
const MAGIC_STRING = 'FAENC1';
const VERSION = 1;

const ROLE_ARCHIVE = 'archive';
const ROLE_MANIFEST = 'manifest';
const ROLE_BYTE = { archive: 1, manifest: 2 };
const ROLE_NAME = { 1: 'archive', 2: 'manifest' };

const ALG = 'aes-256-gcm';
const IV_LENGTH_BYTES = 12;
const TAG_LENGTH_BYTES = 16;
const KEY_LENGTH_BYTES = 32;
const HEADER_OFFSET = 12;

const SCHEME_GD_TIER1 = 'gd-tier1';
const DEFAULT_SCHEME = SCHEME_GD_TIER1;
const DEFAULT_KEK_REFERENCE = null;

function assertRole(role) {
  if (role !== ROLE_ARCHIVE && role !== ROLE_MANIFEST) {
    throw new Error('export-encryption: role must be ' + ROLE_ARCHIVE + ' or ' + ROLE_MANIFEST + ' (got ' + String(role) + ')');
  }
}

function assertExportId(exportId) {
  if (typeof exportId !== 'string' || exportId === '') {
    throw new Error('export-encryption: exportId required (non-empty string)');
  }
}

function buildAad(role, exportId) {
  return Buffer.from(MAGIC_STRING + '|v' + VERSION + '|' + role + '|' + exportId, 'utf-8');
}

function uint32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

// Build a framed FA-ENC1 buffer. kek is the wrapped-key envelope object, or
// null for the keyless (test/regression) path.
function buildFrame(plaintext, dataKey, opts) {
  if (!Buffer.isBuffer(plaintext)) {
    throw new Error('export-encryption: plaintext must be a Buffer');
  }
  if (!Buffer.isBuffer(dataKey) || dataKey.length !== KEY_LENGTH_BYTES) {
    throw new Error('export-encryption: dataKey must be a ' + KEY_LENGTH_BYTES + '-byte Buffer');
  }
  const role = opts.role;
  const exportId = opts.exportId;
  assertRole(role);
  assertExportId(exportId);

  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const aad = buildAad(role, exportId);
  const cipher = crypto.createCipheriv(ALG, dataKey, iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const header = {
    alg: ALG,
    role: role,
    export_id: exportId,
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    kek: opts.kek || null,
  };
  const headerJson = Buffer.from(JSON.stringify(header), 'utf-8');

  return Buffer.concat([
    MAGIC,
    Buffer.from([VERSION]),
    Buffer.from([ROLE_BYTE[role]]),
    uint32be(headerJson.length),
    headerJson,
    ciphertext,
  ]);
}

function parseFrame(framed) {
  if (!Buffer.isBuffer(framed) || framed.length < HEADER_OFFSET) {
    throw new Error('export-encryption: framed buffer too short to be FA-ENC1');
  }
  if (framed.subarray(0, 6).toString('latin1') !== MAGIC_STRING) {
    throw new Error('export-encryption: bad magic (not an FA-ENC1 artifact)');
  }
  const version = framed[6];
  if (version !== VERSION) {
    throw new Error('export-encryption: unsupported FA-ENC1 version ' + version + ' (expected ' + VERSION + ')');
  }
  const roleByte = framed[7];
  const role = ROLE_NAME[roleByte];
  if (!role) {
    throw new Error('export-encryption: unknown FA-ENC1 role byte ' + roleByte);
  }
  const headerLen = framed.readUInt32BE(8);
  if (framed.length < HEADER_OFFSET + headerLen) {
    throw new Error('export-encryption: truncated FA-ENC1 header');
  }
  let header;
  try {
    header = JSON.parse(framed.subarray(HEADER_OFFSET, HEADER_OFFSET + headerLen).toString('utf-8'));
  } catch (err) {
    throw new Error('export-encryption: FA-ENC1 header is not valid JSON: ' + err.message);
  }
  if (!header || typeof header !== 'object') {
    throw new Error('export-encryption: FA-ENC1 header is not a JSON object');
  }
  if (header.role !== role) {
    throw new Error('export-encryption: FA-ENC1 header role does not match the role byte');
  }
  assertExportId(header.export_id);
  const ciphertext = framed.subarray(HEADER_OFFSET + headerLen);
  return { role: role, header: header, ciphertext: ciphertext };
}

function decryptFrame(parsed, dataKey) {
  if (!Buffer.isBuffer(dataKey) || dataKey.length !== KEY_LENGTH_BYTES) {
    throw new Error('export-encryption: dataKey must be a ' + KEY_LENGTH_BYTES + '-byte Buffer');
  }
  const header = parsed.header;
  const iv = Buffer.from(header.iv, 'base64');
  const tag = Buffer.from(header.tag, 'base64');
  if (iv.length !== IV_LENGTH_BYTES) {
    throw new Error('export-encryption: FA-ENC1 iv is not ' + IV_LENGTH_BYTES + ' bytes');
  }
  if (tag.length !== TAG_LENGTH_BYTES) {
    throw new Error('export-encryption: FA-ENC1 tag is not ' + TAG_LENGTH_BYTES + ' bytes');
  }
  const aad = buildAad(header.role, header.export_id);
  const decipher = crypto.createDecipheriv(ALG, dataKey, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
}

// ---- Public: keyless AEAD core (tests / regression) ----

function sealWithKey(plaintext, dataKey, opts) {
  const o = opts || {};
  return buildFrame(plaintext, dataKey, { role: o.role, exportId: o.exportId, kek: null });
}

function openWithKey(framed, dataKey) {
  return decryptFrame(parseFrame(framed), dataKey);
}

// ---- Public: KEK-wrapped seal / open ----

async function sealArtifact(plaintext, opts) {
  const o = opts || {};
  const role = o.role;
  const exportId = o.exportId;
  assertRole(role);
  assertExportId(exportId);

  // The GD wraps the per-artifact data key under its own derived Tier-1 KEK via
  // gd-encryption (the GD has no key-wrapping-providers registry). The wrapped
  // form is the gd-encryption envelope string, carried in the FA-ENC1 header.
  const dataKey = crypto.randomBytes(KEY_LENGTH_BYTES);
  const wrapped = gdEncryption.encryptConfigWithKey({ k: dataKey.toString('base64') }, gdEncryption.deriveKek());
  const kek = { v: 1, scheme: SCHEME_GD_TIER1, wrapped: wrapped };
  const framed = buildFrame(plaintext, dataKey, { role: role, exportId: exportId, kek: kek });
  dataKey.fill(0);
  return { framed: framed, scheme: SCHEME_GD_TIER1, kekRef: null };
}

async function openArtifact(framed, opts) {
  const parsed = parseFrame(framed);
  const kek = parsed.header.kek;
  if (!kek || typeof kek !== 'object') {
    throw new Error('export-encryption: FA-ENC1 artifact carries no wrapped key (use openWithKey for keyless frames)');
  }
  if (kek.scheme !== SCHEME_GD_TIER1) {
    throw new Error('export-encryption: unexpected GD wrap scheme ' + String(kek.scheme));
  }
  const unwrapped = gdEncryption.decryptConfigWithKey(kek.wrapped, gdEncryption.deriveKek());
  const dataKey = Buffer.from(unwrapped.k, 'base64');
  try {
    return decryptFrame(parsed, dataKey);
  } finally {
    dataKey.fill(0);
  }
}

// ---- Public: framing probe (legacy-plaintext detection) ----

function isFramed(buf) {
  return Buffer.isBuffer(buf) && buf.length >= 6 && buf.subarray(0, 6).toString('latin1') === MAGIC_STRING;
}

module.exports = {
  sealWithKey: sealWithKey,
  openWithKey: openWithKey,
  sealArtifact: sealArtifact,
  openArtifact: openArtifact,
  isFramed: isFramed,
  MAGIC_STRING: MAGIC_STRING,
  VERSION: VERSION,
  ROLE_ARCHIVE: ROLE_ARCHIVE,
  ROLE_MANIFEST: ROLE_MANIFEST,
  DEFAULT_SCHEME: DEFAULT_SCHEME,
  DEFAULT_KEK_REFERENCE: DEFAULT_KEK_REFERENCE,
};
