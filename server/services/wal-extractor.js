// ============================================================================
// server/services/wal-extractor.js
//
// R3l C61 — Page-level SHA-256 extractor over SQLite Write-Ahead Log frames.
//
// SQLite's WAL file is a binary append-only log of pages modified since the
// last checkpoint. Each frame represents one modified database page. Workstream
// 3 incremental + differential backups read this file (NEVER write to it) and
// archive frames that fall between a previous backup's wal_end_position and
// the current WAL tail, with one SHA-256 hash per page for integrity
// verification at restore time.
//
// This module is read-only. It does NOT take checkpoints, truncate the WAL,
// or modify any DB state. Checkpoint coordination lives in wal-checkpoint.js
// (R3l C62). Incremental archive writers live in backup-incremental.js
// (R3l C63) and backup-differential.js (R3l C64).
//
// WAL file format (from SQLite docs, section "Write-Ahead Log File Format"):
//
//   ┌──────────────────────────────────────────────────────┐
//   │ 32-byte WAL header                                   │
//   │   0-3:   magic number (0x377f0682 or 0x377f0683)     │
//   │   4-7:   format version (3007000)                    │
//   │   8-11:  database page size                          │
//   │  12-15:  checkpoint sequence number                  │
//   │  16-19:  salt-1                                      │
//   │  20-23:  salt-2                                      │
//   │  24-27:  checksum-1 of bytes 0-23                    │
//   │  28-31:  checksum-2 of bytes 0-23                    │
//   ├──────────────────────────────────────────────────────┤
//   │ Frame 1: 24-byte header + (pageSize) bytes of data   │
//   │  header  0-3:   database page number                 │
//   │          4-7:   db size in pages after commit (0     │
//   │                 for non-commit frames)               │
//   │          8-11:  salt-1 (must match WAL header)       │
//   │         12-15:  salt-2 (must match WAL header)       │
//   │         16-19:  cumulative checksum-1                │
//   │         20-23:  cumulative checksum-2                │
//   │  data:   pageSize bytes (raw database page bytes)    │
//   ├──────────────────────────────────────────────────────┤
//   │ Frame 2 ...                                          │
//   │ ...                                                  │
//   └──────────────────────────────────────────────────────┘
//
// Salt validation: any frame whose salt-1/salt-2 don't match the WAL header
// salts is considered invalid and signals end-of-WAL (SQLite re-salts on
// checkpoint, so stale frames from prior write epochs appear corrupted to a
// fresh reader). Truncated final frames (last frame shorter than expected)
// also terminate the read.
//
// Frame numbering: 1-indexed within the WAL. Frame N starts at byte offset
//   WAL_HEADER_SIZE + (N - 1) * (WAL_FRAME_HEADER_SIZE + pageSize)
// so a position string "offset:frameNo" is technically over-specified for a
// given pageSize, but serializing both fields lets readers identify their
// position without needing pageSize from the file header.
// ============================================================================

const fs = require('fs');
const crypto = require('crypto');

const WAL_HEADER_SIZE = 32;
const WAL_FRAME_HEADER_SIZE = 24;
const WAL_MAGIC_LE = 0x377f0682;
const WAL_MAGIC_BE = 0x377f0683;

// SQLite supports database page sizes between 512 and 65536. Anything outside
// this range in a parsed WAL header is structural corruption and the read is
// aborted with a descriptive error.
const MIN_PAGE_SIZE = 512;
const MAX_PAGE_SIZE = 65536;

/**
 * Parse the 32-byte WAL file header. Throws if magic is invalid or the
 * declared page size is outside SQLite's supported range.
 *
 * Returns:
 *   {
 *     magic: number,                  // 0x377f0682 or 0x377f0683
 *     bigEndian: boolean,             // true iff magic was 0x377f0683
 *     formatVersion: number,          // 3007000 for modern SQLite
 *     pageSize: number,               // raw value; 1 -> 65536 per SQLite docs
 *     checkpointSequence: number,
 *     salt1: number,
 *     salt2: number,
 *     checksum1: number,
 *     checksum2: number,
 *   }
 */
function parseWalHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < WAL_HEADER_SIZE) {
    throw new Error(`parseWalHeader: expected at least ${WAL_HEADER_SIZE} bytes, got ${buf ? buf.length : 'null'}`);
  }
  // Magic determines byte order. WAL headers are otherwise big-endian per spec,
  // but check both magic values for robustness.
  const magicBE = buf.readUInt32BE(0);
  let bigEndian;
  if (magicBE === WAL_MAGIC_LE) {
    bigEndian = false;
  } else if (magicBE === WAL_MAGIC_BE) {
    bigEndian = true;
  } else {
    throw new Error(`parseWalHeader: invalid magic 0x${magicBE.toString(16)}; not a SQLite WAL file`);
  }

  // SQLite WAL header is documented as always big-endian, with the magic
  // distinguishing read byte order for FRAME contents. We read header fields
  // big-endian regardless.
  const formatVersion = buf.readUInt32BE(4);
  let pageSize = buf.readUInt32BE(8);
  // SQLite encodes page_size=65536 as the value 1 for legacy reasons.
  if (pageSize === 1) pageSize = 65536;
  if (pageSize < MIN_PAGE_SIZE || pageSize > MAX_PAGE_SIZE || (pageSize & (pageSize - 1)) !== 0) {
    throw new Error(`parseWalHeader: invalid pageSize ${pageSize} (must be power-of-two in [${MIN_PAGE_SIZE}, ${MAX_PAGE_SIZE}])`);
  }

  return {
    magic: magicBE,
    bigEndian,
    formatVersion,
    pageSize,
    checkpointSequence: buf.readUInt32BE(12),
    salt1: buf.readUInt32BE(16),
    salt2: buf.readUInt32BE(20),
    checksum1: buf.readUInt32BE(24),
    checksum2: buf.readUInt32BE(28),
  };
}

/**
 * Parse a 24-byte WAL frame header. Caller must check salt1/salt2 against
 * the WAL header salts to determine validity.
 *
 * Returns:
 *   {
 *     pageNo: number,             // database page number this frame modifies
 *     dbSizeAfterCommit: number,  // nonzero only for commit frames
 *     salt1: number,
 *     salt2: number,
 *     checksum1: number,
 *     checksum2: number,
 *   }
 */
function parseFrameHeader(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < WAL_FRAME_HEADER_SIZE) {
    throw new Error(`parseFrameHeader: expected at least ${WAL_FRAME_HEADER_SIZE} bytes, got ${buf ? buf.length : 'null'}`);
  }
  return {
    pageNo: buf.readUInt32BE(0),
    dbSizeAfterCommit: buf.readUInt32BE(4),
    salt1: buf.readUInt32BE(8),
    salt2: buf.readUInt32BE(12),
    checksum1: buf.readUInt32BE(16),
    checksum2: buf.readUInt32BE(20),
  };
}

/**
 * Compute SHA-256 of a raw page buffer. Returns lowercase hex string.
 * Used by readWalFrames and streamWalPages to populate each frame's
 * integrity field. C63/C64 archive writers store these hashes in the
 * manifest; C65 restore validator re-computes and compares.
 */
function computePageSha256(pageBuf) {
  if (!Buffer.isBuffer(pageBuf)) {
    throw new Error(`computePageSha256: expected Buffer, got ${typeof pageBuf}`);
  }
  return crypto.createHash('sha256').update(pageBuf).digest('hex');
}

/**
 * Serialize a WAL position to the "offset:frameNo" TEXT format that the
 * backups.wal_start_position and backups.wal_end_position columns store
 * (added in R3l C55). Inverse of parseWalPosition.
 *
 * offset is byte offset within the WAL file; frameNo is the WAL frame
 * number that starts at that offset (or the count of frames already
 * past, for an end-of-data position).
 */
function serializeWalPosition({ offset, frameNo }) {
  if (!Number.isInteger(offset) || offset < 0) {
    throw new Error(`serializeWalPosition: offset must be non-negative integer, got ${offset}`);
  }
  if (!Number.isInteger(frameNo) || frameNo < 0) {
    throw new Error(`serializeWalPosition: frameNo must be non-negative integer, got ${frameNo}`);
  }
  return `${offset}:${frameNo}`;
}

/**
 * Parse an "offset:frameNo" position string. Returns {offset, frameNo}.
 * Throws on malformed input. Inverse of serializeWalPosition.
 */
function parseWalPosition(s) {
  if (typeof s !== 'string') {
    throw new Error(`parseWalPosition: expected string, got ${typeof s}`);
  }
  const match = s.match(/^(\d+):(\d+)$/);
  if (!match) {
    throw new Error(`parseWalPosition: malformed position '${s}'; expected 'offset:frameNo'`);
  }
  return {
    offset: parseInt(match[1], 10),
    frameNo: parseInt(match[2], 10),
  };
}

/**
 * Compute the byte offset of frame N within a WAL of given page size.
 * Frames are 1-indexed. frame=0 returns WAL_HEADER_SIZE (just past header).
 */
function frameOffset(frameNo, pageSize) {
  if (frameNo < 0) throw new Error(`frameOffset: frameNo must be >= 0, got ${frameNo}`);
  return WAL_HEADER_SIZE + frameNo * (WAL_FRAME_HEADER_SIZE + pageSize);
}

/**
 * Open a WAL file and read frames starting from a given startFrameNo
 * (0-indexed; 0 = read from the beginning of frames).
 *
 * Each frame's salts are validated against the WAL header. Invalid salt
 * means end-of-WAL (SQLite re-salts at checkpoint, so any stale frame
 * from a prior write epoch fails salt check). Truncated final frames
 * also terminate the read.
 *
 * The page data bytes themselves are NOT retained in memory — each page
 * is hashed and the bytes are discarded. This keeps memory usage bounded
 * regardless of WAL size. C63 incremental backup uses streamWalPages
 * (below) when it needs the page bytes for archive write.
 *
 * Returns:
 *   {
 *     header: {pageSize, salt1, salt2, ...},        // from parseWalHeader
 *     frames: [
 *       {
 *         frameNo,                  // 1-indexed within the WAL
 *         pageNo,                   // DB page this frame modifies
 *         byteOffset,               // start of this frame's 24-byte header
 *         dbSizeAfterCommit,        // 0 for non-commit frames
 *         sha256,                   // hex SHA-256 of the page bytes
 *       },
 *       ...
 *     ],
 *     endOffset,                    // offset just past the last valid frame
 *     endFrameNo,                   // frame_no of the last valid frame (0 if no frames read)
 *     truncated,                    // true if WAL ended partway through a frame
 *     invalidSaltAtFrame,           // frame_no where salt validation failed, or null
 *   }
 */
function readWalFrames(walFilePath, options = {}) {
  const startFrameNo = Number.isInteger(options.startFrameNo) ? options.startFrameNo : 0;
  if (startFrameNo < 0) {
    throw new Error(`readWalFrames: startFrameNo must be >= 0, got ${startFrameNo}`);
  }

  const fd = fs.openSync(walFilePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size < WAL_HEADER_SIZE) {
      // No WAL data at all (or header truncated). Return empty.
      return {
        header: null,
        frames: [],
        endOffset: 0,
        endFrameNo: 0,
        truncated: stat.size > 0,  // partial header counts as truncated
        invalidSaltAtFrame: null,
      };
    }

    const headerBuf = Buffer.alloc(WAL_HEADER_SIZE);
    fs.readSync(fd, headerBuf, 0, WAL_HEADER_SIZE, 0);
    const header = parseWalHeader(headerBuf);
    const pageSize = header.pageSize;
    const frameTotalSize = WAL_FRAME_HEADER_SIZE + pageSize;

    const frames = [];
    let cursor = WAL_HEADER_SIZE;
    let frameNo = 0;
    let truncated = false;
    let invalidSaltAtFrame = null;

    const frameHeaderBuf = Buffer.alloc(WAL_FRAME_HEADER_SIZE);
    const pageBuf = Buffer.alloc(pageSize);

    while (cursor + frameTotalSize <= stat.size) {
      frameNo += 1;
      // Skip frames before startFrameNo for caller-requested range slicing.
      // We still validate them (salt check) but don't append to results.
      const skip = frameNo <= startFrameNo;

      const fhRead = fs.readSync(fd, frameHeaderBuf, 0, WAL_FRAME_HEADER_SIZE, cursor);
      if (fhRead < WAL_FRAME_HEADER_SIZE) {
        truncated = true;
        break;
      }
      const frameHeader = parseFrameHeader(frameHeaderBuf);

      // Salt check: stale frames after a checkpoint fail this and we stop.
      if (frameHeader.salt1 !== header.salt1 || frameHeader.salt2 !== header.salt2) {
        invalidSaltAtFrame = frameNo;
        break;
      }

      const pageRead = fs.readSync(fd, pageBuf, 0, pageSize, cursor + WAL_FRAME_HEADER_SIZE);
      if (pageRead < pageSize) {
        truncated = true;
        break;
      }

      if (!skip) {
        const sha256 = computePageSha256(pageBuf);
        frames.push({
          frameNo,
          pageNo: frameHeader.pageNo,
          byteOffset: cursor,
          dbSizeAfterCommit: frameHeader.dbSizeAfterCommit,
          sha256,
        });
      }

      cursor += frameTotalSize;
    }

    return {
      header,
      frames,
      endOffset: cursor,
      endFrameNo: frameNo - (truncated || invalidSaltAtFrame !== null ? 1 : 0),
      truncated,
      invalidSaltAtFrame,
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Stream WAL frames through a consumer callback. For each valid frame
 * (within optional startFrameNo / endFrameNo bounds, both 1-indexed),
 * the consumer receives:
 *   {
 *     frameNo,
 *     pageNo,
 *     byteOffset,
 *     dbSizeAfterCommit,
 *     pageBuf,            // raw page bytes (do NOT retain across calls;
 *                         // the same Buffer is reused for performance)
 *     sha256,             // already-computed for convenience
 *   }
 *
 * Returns the same summary shape as readWalFrames except frames is the
 * count of frames passed to the consumer, not an array.
 *
 * Used by C63 backup-incremental.js to write each WAL page into the
 * archive without holding the entire WAL in memory.
 */
function streamWalPages(walFilePath, consumer, options = {}) {
  if (typeof consumer !== 'function') {
    throw new Error('streamWalPages: consumer must be a function');
  }
  const startFrameNo = Number.isInteger(options.startFrameNo) ? options.startFrameNo : 0;
  const endFrameNo = Number.isInteger(options.endFrameNo) ? options.endFrameNo : Infinity;
  if (startFrameNo < 0) {
    throw new Error(`streamWalPages: startFrameNo must be >= 0, got ${startFrameNo}`);
  }
  if (endFrameNo < startFrameNo) {
    throw new Error(`streamWalPages: endFrameNo (${endFrameNo}) must be >= startFrameNo (${startFrameNo})`);
  }

  const fd = fs.openSync(walFilePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size < WAL_HEADER_SIZE) {
      return {
        header: null,
        frameCount: 0,
        endOffset: 0,
        endFrameNo: 0,
        truncated: stat.size > 0,
        invalidSaltAtFrame: null,
      };
    }

    const headerBuf = Buffer.alloc(WAL_HEADER_SIZE);
    fs.readSync(fd, headerBuf, 0, WAL_HEADER_SIZE, 0);
    const header = parseWalHeader(headerBuf);
    const pageSize = header.pageSize;
    const frameTotalSize = WAL_FRAME_HEADER_SIZE + pageSize;

    let cursor = WAL_HEADER_SIZE;
    let frameNo = 0;
    let frameCount = 0;
    let truncated = false;
    let invalidSaltAtFrame = null;

    const frameHeaderBuf = Buffer.alloc(WAL_FRAME_HEADER_SIZE);
    const pageBuf = Buffer.alloc(pageSize);

    while (cursor + frameTotalSize <= stat.size) {
      frameNo += 1;
      if (frameNo > endFrameNo) break;

      const fhRead = fs.readSync(fd, frameHeaderBuf, 0, WAL_FRAME_HEADER_SIZE, cursor);
      if (fhRead < WAL_FRAME_HEADER_SIZE) {
        truncated = true;
        break;
      }
      const frameHeader = parseFrameHeader(frameHeaderBuf);
      if (frameHeader.salt1 !== header.salt1 || frameHeader.salt2 !== header.salt2) {
        invalidSaltAtFrame = frameNo;
        break;
      }
      const pageRead = fs.readSync(fd, pageBuf, 0, pageSize, cursor + WAL_FRAME_HEADER_SIZE);
      if (pageRead < pageSize) {
        truncated = true;
        break;
      }

      if (frameNo >= startFrameNo) {
        const sha256 = computePageSha256(pageBuf);
        consumer({
          frameNo,
          pageNo: frameHeader.pageNo,
          byteOffset: cursor,
          dbSizeAfterCommit: frameHeader.dbSizeAfterCommit,
          pageBuf,
          sha256,
        });
        frameCount += 1;
      }

      cursor += frameTotalSize;
    }

    return {
      header,
      frameCount,
      endOffset: cursor,
      endFrameNo: frameNo - (truncated || invalidSaltAtFrame !== null ? 1 : 0),
      truncated,
      invalidSaltAtFrame,
    };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Convenience: return the current WAL end position (offset, frameNo)
 * suitable for storing as backups.wal_end_position on a backup that
 * just captured everything up to "now". Equivalent to
 *   readWalFrames(walFilePath).endOffset / .endFrameNo
 * but doesn't allocate the frames array.
 */
function getWalCurrentPosition(walFilePath) {
  const fd = fs.openSync(walFilePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size < WAL_HEADER_SIZE) {
      return { offset: 0, frameNo: 0, exists: false };
    }
    const headerBuf = Buffer.alloc(WAL_HEADER_SIZE);
    fs.readSync(fd, headerBuf, 0, WAL_HEADER_SIZE, 0);
    const header = parseWalHeader(headerBuf);
    const pageSize = header.pageSize;
    const frameTotalSize = WAL_FRAME_HEADER_SIZE + pageSize;

    let cursor = WAL_HEADER_SIZE;
    let frameNo = 0;

    const frameHeaderBuf = Buffer.alloc(WAL_FRAME_HEADER_SIZE);

    while (cursor + frameTotalSize <= stat.size) {
      const fhRead = fs.readSync(fd, frameHeaderBuf, 0, WAL_FRAME_HEADER_SIZE, cursor);
      if (fhRead < WAL_FRAME_HEADER_SIZE) break;
      const frameHeader = parseFrameHeader(frameHeaderBuf);
      if (frameHeader.salt1 !== header.salt1 || frameHeader.salt2 !== header.salt2) break;
      frameNo += 1;
      cursor += frameTotalSize;
    }

    return { offset: cursor, frameNo, exists: true, pageSize };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = {
  WAL_HEADER_SIZE,
  WAL_FRAME_HEADER_SIZE,
  WAL_MAGIC_LE,
  WAL_MAGIC_BE,
  MIN_PAGE_SIZE,
  MAX_PAGE_SIZE,
  parseWalHeader,
  parseFrameHeader,
  computePageSha256,
  serializeWalPosition,
  parseWalPosition,
  frameOffset,
  readWalFrames,
  streamWalPages,
  getWalCurrentPosition,
};
