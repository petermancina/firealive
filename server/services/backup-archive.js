// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Backup Archive Builder/Extractor
//
// Produces and consumes the archive.tar.zst.enc file in a v2 backup
// directory. The pipeline:
//
//   buildArchive(buffer, name)
//     buffer   --[ tar with single ustar entry ]-->  tarred bytes
//     tarred   --[ zstd compress ]-->                 compressed bytes
//     compressed --[ AES-256-GCM, fresh ephemeral key, fresh IV ]-->
//       encrypted bytes (IV + authTag + ciphertext, in the
//       encryption.js convention)
//
//   extractArchive(encryptedBytes, ephemeralKey)
//     reverses every step, returns the original buffer + filename
//
// Returns the ephemeral 256-bit key alongside the encrypted bytes so
// the caller (the new backup.js engine in commit 9) can wrap that
// key with the KEK separately and store the wrapped result in
// wrapped-key.bin. The key is NEVER written to disk by this module
// or persisted in the database — its only authoritative storage
// is the wrapped form held by the caller.
//
// The SHA-256 of the final encrypted bytes is what the manifest
// records (file_hashes.archive.sha256) and what the restore service
// verifies before decrypting.
//
// MEMORY MODEL
//
// Buffered, not streaming. AES-GCM finalizes its auth tag only after
// all plaintext has been processed, so a true streaming pipeline
// cannot emit verified ciphertext incrementally regardless of how
// the upstream (tar, zstd) is structured. A buffered design also
// keeps the implementation simple and auditable.
//
// MAX_SOURCE_BYTES caps the input at 8 GB to bound peak memory at
// ~3x source size (raw + tarred + compressed + encrypted in flight).
// Customer databases beyond this would need the streaming optimization
// not landing in v1.0.30.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');
const { compress, decompress } = require('@mongodb-js/zstd');

const TAR_BLOCK_SIZE     = 512;
const TAR_MAGIC          = 'ustar\0';
const TAR_VERSION        = '00';
const ENC_ALGORITHM      = 'aes-256-gcm';
const KEY_LENGTH_BYTES   = 32;     // AES-256
const IV_LENGTH_BYTES    = 12;     // GCM standard
const TAG_LENGTH_BYTES   = 16;     // GCM standard
const MAX_SOURCE_BYTES   = 8 * 1024 * 1024 * 1024;   // 8 GB
const DEFAULT_ZSTD_LEVEL = 3;

// ── Tar (POSIX ustar) ────────────────────────────────────────────────────

/**
 * Build a single-entry POSIX ustar archive from a Buffer plus a filename.
 * The result is suitable input for any standard tar reader (and for
 * extractTar below).
 *
 * Layout:
 *   [ 512-byte header ]
 *   [ payload bytes, padded to next 512-byte boundary ]
 *   [ 1024 zero bytes — end-of-archive marker ]
 */
function buildTar(payload, filename) {
  if (!Buffer.isBuffer(payload)) {
    throw new Error('buildTar: payload must be a Buffer');
  }
  if (typeof filename !== 'string' || !filename || filename.length > 100) {
    throw new Error(`buildTar: filename must be a non-empty string of <=100 chars (got ${filename ? filename.length : 0})`);
  }

  const header = Buffer.alloc(TAR_BLOCK_SIZE);

  // Field layout per POSIX ustar:
  //   0   filename (100)
  //   100 mode (8 octal + null)
  //   108 uid (8)
  //   116 gid (8)
  //   124 size (12)
  //   136 mtime (12)
  //   148 chksum (8 — set to spaces during compute, then written as octal)
  //   156 typeflag (1)
  //   157 linkname (100)
  //   257 magic (6: "ustar\0")
  //   263 version (2: "00")
  //   265 uname (32)
  //   297 gname (32)
  //   329 devmajor (8)
  //   337 devminor (8)
  //   345 prefix (155)
  //   500 (12 zero pad)
  // Numeric fields are octal strings, NUL-terminated, left-zero-padded.

  // Octal numeric field writer. Width includes the trailing NUL except
  // for size and mtime which use NUL or space — we use NUL throughout.
  const writeOctal = (value, offset, width) => {
    const str = value.toString(8);
    if (str.length > width - 1) {
      throw new Error(`buildTar: octal value ${value} exceeds field width ${width - 1}`);
    }
    header.write(str.padStart(width - 1, '0'), offset, width - 1, 'ascii');
    header[offset + width - 1] = 0;
  };

  // Filename
  header.write(filename, 0, 100, 'ascii');
  // Mode — 0644 regular-file rw-r--r--
  writeOctal(0o644, 100, 8);
  // UID/GID — 0 (root); the archive is platform-portable so leave as 0
  writeOctal(0, 108, 8);
  writeOctal(0, 116, 8);
  // Size
  writeOctal(payload.length, 124, 12);
  // Mtime — current time as POSIX seconds
  writeOctal(Math.floor(Date.now() / 1000), 136, 12);
  // Checksum field is computed below; for the compute itself, treat
  // the 8-byte chksum field as ASCII spaces.
  for (let i = 148; i < 156; i++) header[i] = 0x20;
  // Typeflag '0' = regular file
  header[156] = 0x30;
  // Linkname stays zero-filled
  // Magic + version
  header.write(TAR_MAGIC, 257, 6, 'binary');
  header.write(TAR_VERSION, 263, 2, 'ascii');
  // uname/gname/devmajor/devminor/prefix all stay zero-filled

  // Compute checksum: simple sum of all header bytes
  let checksum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i++) checksum += header[i];
  // Write checksum as 6 octal digits + NUL + space
  // (The "+ space" is per the historical convention adopted by GNU tar.)
  writeOctal(checksum, 148, 7);
  header[155] = 0x20;

  // Pad payload to 512-byte boundary
  const padding = TAR_BLOCK_SIZE - (payload.length % TAR_BLOCK_SIZE);
  const paddedPayload = padding === TAR_BLOCK_SIZE
    ? payload
    : Buffer.concat([payload, Buffer.alloc(padding)]);

  // End-of-archive: two zero blocks
  const endMarker = Buffer.alloc(TAR_BLOCK_SIZE * 2);

  return Buffer.concat([header, paddedPayload, endMarker]);
}

/**
 * Extract a single-entry POSIX ustar archive. Returns
 * { name, payload }. Verifies header checksum; rejects multi-entry
 * archives (this module only ever produces single-entry archives).
 */
function extractTar(tarBytes) {
  if (!Buffer.isBuffer(tarBytes)) {
    throw new Error('extractTar: input must be a Buffer');
  }
  if (tarBytes.length < TAR_BLOCK_SIZE * 3) {
    throw new Error('extractTar: input too short to be a valid tar archive');
  }

  // Read the first header
  const header = tarBytes.subarray(0, TAR_BLOCK_SIZE);

  // Verify magic
  const magic = header.subarray(257, 263).toString('binary');
  if (magic !== TAR_MAGIC) {
    throw new Error(`extractTar: ustar magic missing (got ${JSON.stringify(magic)})`);
  }

  // Verify checksum
  const claimedChecksum = parseInt(header.subarray(148, 156).toString('ascii').replace(/\0.*$/, '').trim(), 8);
  if (Number.isNaN(claimedChecksum)) {
    throw new Error('extractTar: header checksum field is malformed');
  }
  let actualChecksum = 0;
  for (let i = 0; i < TAR_BLOCK_SIZE; i++) {
    actualChecksum += (i >= 148 && i < 156) ? 0x20 : header[i];
  }
  if (actualChecksum !== claimedChecksum) {
    throw new Error(`extractTar: header checksum mismatch (header claims ${claimedChecksum}, computed ${actualChecksum})`);
  }

  // Parse filename and size
  const nameRaw = header.subarray(0, 100).toString('ascii');
  const name = nameRaw.replace(/\0.*$/, '');
  const sizeStr = header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim();
  const size = parseInt(sizeStr, 8);
  if (Number.isNaN(size) || size < 0) {
    throw new Error(`extractTar: invalid size field '${sizeStr}'`);
  }

  // Verify typeflag is regular file
  const typeflag = header[156];
  if (typeflag !== 0x30 && typeflag !== 0x00) {
    // 0x30 = '0' regular, 0x00 = legacy regular per POSIX
    throw new Error(`extractTar: only regular file entries are supported (got typeflag 0x${typeflag.toString(16)})`);
  }

  // Read payload
  const payloadStart = TAR_BLOCK_SIZE;
  const payloadEnd = payloadStart + size;
  if (payloadEnd > tarBytes.length) {
    throw new Error(`extractTar: declared size ${size} extends beyond archive bytes`);
  }
  const payload = Buffer.from(tarBytes.subarray(payloadStart, payloadEnd));

  // Verify the next block (after padding) is the start of the
  // end-of-archive marker. We don't allow multi-entry archives;
  // a non-zero block here would mean a second entry.
  const paddedSize = Math.ceil(size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
  const nextBlockStart = TAR_BLOCK_SIZE + paddedSize;
  if (nextBlockStart < tarBytes.length) {
    const nextBlock = tarBytes.subarray(nextBlockStart, nextBlockStart + TAR_BLOCK_SIZE);
    let allZero = true;
    for (let i = 0; i < nextBlock.length; i++) {
      if (nextBlock[i] !== 0) { allZero = false; break; }
    }
    if (!allZero) {
      throw new Error('extractTar: multi-entry archive detected; only single-entry archives supported');
    }
  }

  return { name, payload };
}

// ── Public API ───────────────────────────────────────────────────────────

/**
 * Build an encrypted, compressed tar archive from a source buffer.
 *
 * Inputs:
 *   sourceBytes   Buffer  — the data to archive (typically a SQLite .db file's contents)
 *   sourceName    string  — the filename to record in the tar header
 *   options                — { compressionLevel? = 3 }
 *
 * Returns:
 *   {
 *     encryptedArchive: Buffer,    // [iv | authTag | ciphertext]
 *     ephemeralKey: Buffer,        // 32 bytes; CALLER MUST WRAP THIS
 *     sizeBytes: number,           // length of encryptedArchive
 *     sha256: string,              // 64 hex chars; manifest field value
 *   }
 *
 * Throws on:
 *   - sourceBytes not a Buffer
 *   - sourceBytes.length > MAX_SOURCE_BYTES
 *   - filename invalid for tar header
 *   - zstd compression failure (rare)
 */
async function buildArchive(sourceBytes, sourceName, options = {}) {
  if (!Buffer.isBuffer(sourceBytes)) {
    throw new Error('buildArchive: sourceBytes must be a Buffer');
  }
  if (sourceBytes.length > MAX_SOURCE_BYTES) {
    throw new Error(`buildArchive: source size ${sourceBytes.length} exceeds MAX_SOURCE_BYTES (${MAX_SOURCE_BYTES})`);
  }
  if (sourceBytes.length === 0) {
    throw new Error('buildArchive: sourceBytes is empty');
  }

  const compressionLevel = options.compressionLevel != null ? options.compressionLevel : DEFAULT_ZSTD_LEVEL;

  // 1. Tar
  const tarred = buildTar(sourceBytes, sourceName);

  // 2. Zstd compress
  const compressed = await compress(tarred, compressionLevel);

  // 3. AES-256-GCM encrypt
  const ephemeralKey = crypto.randomBytes(KEY_LENGTH_BYTES);
  const iv           = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher       = crypto.createCipheriv(ENC_ALGORITHM, ephemeralKey, iv);
  const ciphertext   = Buffer.concat([cipher.update(compressed), cipher.final()]);
  const authTag      = cipher.getAuthTag();

  // Same layout as encryption.js: [iv | tag | ciphertext]
  const encryptedArchive = Buffer.concat([iv, authTag, ciphertext]);
  const sha256 = crypto.createHash('sha256').update(encryptedArchive).digest('hex');

  return {
    encryptedArchive,
    ephemeralKey,
    sizeBytes: encryptedArchive.length,
    sha256,
  };
}

/**
 * Inverse of buildArchive. Takes the encrypted bytes and the
 * (already-unwrapped) ephemeral key, returns { name, payload }.
 *
 * Throws with a precise error on:
 *   - input too short to contain IV + tag
 *   - AES-GCM auth tag mismatch (any tampering of ciphertext, IV, or tag)
 *   - zstd decompression failure
 *   - tar parsing failure (malformed header, bad checksum, multi-entry, etc.)
 */
async function extractArchive(encryptedBytes, ephemeralKey) {
  if (!Buffer.isBuffer(encryptedBytes)) {
    throw new Error('extractArchive: encryptedBytes must be a Buffer');
  }
  if (!Buffer.isBuffer(ephemeralKey) || ephemeralKey.length !== KEY_LENGTH_BYTES) {
    throw new Error(`extractArchive: ephemeralKey must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
  if (encryptedBytes.length < IV_LENGTH_BYTES + TAG_LENGTH_BYTES + 1) {
    throw new Error('extractArchive: encryptedBytes too short to contain IV + auth tag + ciphertext');
  }

  // 1. Split into [iv | tag | ciphertext]
  const iv         = encryptedBytes.subarray(0, IV_LENGTH_BYTES);
  const authTag    = encryptedBytes.subarray(IV_LENGTH_BYTES, IV_LENGTH_BYTES + TAG_LENGTH_BYTES);
  const ciphertext = encryptedBytes.subarray(IV_LENGTH_BYTES + TAG_LENGTH_BYTES);

  // 2. AES-256-GCM decrypt
  const decipher = crypto.createDecipheriv(ENC_ALGORITHM, ephemeralKey, iv);
  decipher.setAuthTag(authTag);
  let compressed;
  try {
    compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error(`extractArchive: AES-GCM decryption failed (likely tampered ciphertext, IV, or tag): ${err.message}`);
  }

  // 3. Zstd decompress
  let tarred;
  try {
    tarred = await decompress(compressed);
  } catch (err) {
    throw new Error(`extractArchive: zstd decompression failed: ${err.message}`);
  }

  // 4. Untar
  const { name, payload } = extractTar(tarred);

  return { name, payload };
}

module.exports = {
  // public API
  buildArchive,
  extractArchive,

  // exported for tests
  buildTar,
  extractTar,

  // constants
  MAX_SOURCE_BYTES,
  KEY_LENGTH_BYTES,
  IV_LENGTH_BYTES,
  TAG_LENGTH_BYTES,
  DEFAULT_ZSTD_LEVEL,
};
