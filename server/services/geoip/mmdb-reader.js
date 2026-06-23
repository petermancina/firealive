// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Pure-Node MaxMind DB (MMDB) Reader (B5n)
//
// A dependency-free reader for the MaxMind DB binary format, scoped to what
// login geo-fencing needs: resolve a client IP to an ISO-3166-1 alpha-2 country
// code. It implements the format directly (no third-party MMDB library) so the
// geo-fencing supply chain stays inside FireAlive.
//
// Format (per the MaxMind DB File Format Specification):
//   1. Binary search tree   — node_count nodes, each holding two record_size-bit
//                             records (left = next bit 0, right = next bit 1).
//   2. 16-byte separator     — all zeros, between tree and data section.
//   3. Data section          — typed-encoding records pointed to by the tree.
//   4. Metadata section      — at the END of the file, located by scanning for
//                             the marker 0xAB 0xCD 0xEF "MaxMind.com"; itself a
//                             typed-encoding map (node_count, record_size,
//                             ip_version, database_type, build_epoch, ...).
//
// IPv4 lookups in an IPv6 database follow 96 zero bits from the root before the
// 32 address bits (IPv4 is stored under ::/96), matching libmaxminddb and the
// reference readers.
//
// open(buffer) -> { meta, lookup(ip), lookupCountry(ip) }
//   meta              parsed metadata (node_count, record_size, ip_version,
//                     database_type, build_epoch, ...).
//   lookup(ip)        full decoded data record for ip, or null.
//   lookupCountry(ip) country.iso_code for ip, or null.
//
// The reader is defensive: a malformed file yields null lookups or a thrown
// Error at open() rather than a crash or an unbounded loop (decode depth is
// capped and all reads are bounds-checked). Callers still scan + format-validate
// + hash-verify the file before trusting it; this is defense in depth.
// ═══════════════════════════════════════════════════════════════════════════════

const { parseIp } = require('./ip-utils');

const METADATA_MARKER = Buffer.concat([
  Buffer.from([0xab, 0xcd, 0xef]),
  Buffer.from('MaxMind.com', 'ascii'),
]);

const MAX_DECODE_DEPTH = 512;
const METADATA_MAX_SIZE = 128 * 1024; // metadata lives in the last 128 KiB

// Locate the start of the metadata map (the offset just past the last marker).
function findMetadataStart(buf) {
  const searchFrom = Math.max(0, buf.length - METADATA_MAX_SIZE);
  const idx = buf.lastIndexOf(METADATA_MARKER, buf.length, undefined);
  if (idx === -1 || idx < searchFrom) return -1;
  return idx + METADATA_MARKER.length;
}

// Decode one typed-encoding value at offset, with pointerBase as the base
// for pointer resolution (the data section start, or the metadata start when
// decoding metadata). Returns { value, offset } where offset is just past the
// value. Bounds- and depth-checked.
function decode(buf, offset, pointerBase, depth) {
  if (depth > MAX_DECODE_DEPTH) throw new Error('mmdb: decode depth exceeded');
  if (offset < 0 || offset >= buf.length) throw new Error('mmdb: read past end of buffer');

  let ctrl = buf[offset];
  offset += 1;
  let type = ctrl >> 5;
  if (type === 0) {
    if (offset >= buf.length) throw new Error('mmdb: truncated extended type');
    type = buf[offset] + 7;
    offset += 1;
  }

  // Pointer (type 1): the low bits encode an offset into the data section.
  if (type === 1) {
    const pointerSize = (ctrl >> 3) & 0x3;
    let pointer;
    if (pointerSize === 0) {
      pointer = ((ctrl & 0x7) << 8) | buf[offset];
      offset += 1;
    } else if (pointerSize === 1) {
      pointer = (((ctrl & 0x7) << 16) | (buf[offset] << 8) | buf[offset + 1]) + 2048;
      offset += 2;
    } else if (pointerSize === 2) {
      pointer = (((ctrl & 0x7) << 24) | (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]) + 526336;
      offset += 3;
    } else {
      pointer = buf.readUInt32BE(offset);
      offset += 4;
    }
    const resolved = decode(buf, pointerBase + pointer, pointerBase, depth + 1);
    return { value: resolved.value, offset: offset };
  }

  // Size for all non-pointer types.
  let size = ctrl & 0x1f;
  if (size === 29) {
    size = 29 + buf[offset];
    offset += 1;
  } else if (size === 30) {
    size = 285 + ((buf[offset] << 8) | buf[offset + 1]);
    offset += 2;
  } else if (size === 31) {
    size = 65821 + ((buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]);
    offset += 3;
  }

  switch (type) {
    case 2: { // utf8_string
      if (offset + size > buf.length) throw new Error('mmdb: string past end');
      return { value: buf.toString('utf8', offset, offset + size), offset: offset + size };
    }
    case 5: // uint16
    case 6: // uint32
    case 9: // uint64
    case 10: { // uint128
      if (offset + size > buf.length) throw new Error('mmdb: uint past end');
      let n = 0n;
      for (let i = 0; i < size; i++) n = (n << 8n) + BigInt(buf[offset + i]);
      const value = n <= 9007199254740991n ? Number(n) : n;
      return { value: value, offset: offset + size };
    }
    case 7: { // map
      const map = {};
      let o = offset;
      for (let i = 0; i < size; i++) {
        const k = decode(buf, o, pointerBase, depth + 1);
        o = k.offset;
        const v = decode(buf, o, pointerBase, depth + 1);
        o = v.offset;
        map[String(k.value)] = v.value;
      }
      return { value: map, offset: o };
    }
    case 11: { // array
      const arr = [];
      let o = offset;
      for (let i = 0; i < size; i++) {
        const v = decode(buf, o, pointerBase, depth + 1);
        o = v.offset;
        arr.push(v.value);
      }
      return { value: arr, offset: o };
    }
    case 14: { // boolean (size is the value; no payload bytes)
      return { value: size !== 0, offset: offset };
    }
    case 4: { // bytes
      if (offset + size > buf.length) throw new Error('mmdb: bytes past end');
      return { value: buf.slice(offset, offset + size), offset: offset + size };
    }
    case 8: { // int32 (two's complement, big-endian, size bytes)
      if (offset + size > buf.length) throw new Error('mmdb: int32 past end');
      let n = 0;
      for (let i = 0; i < size; i++) n = (n * 256) + buf[offset + i];
      if (size > 0 && (buf[offset] & 0x80)) n -= Math.pow(2, size * 8);
      return { value: n, offset: offset + size };
    }
    case 3: { // double
      if (offset + size > buf.length) throw new Error('mmdb: double past end');
      return { value: size === 8 ? buf.readDoubleBE(offset) : 0, offset: offset + size };
    }
    case 15: { // float
      if (offset + size > buf.length) throw new Error('mmdb: float past end');
      return { value: size === 4 ? buf.readFloatBE(offset) : 0, offset: offset + size };
    }
    default: { // data_cache_container (12), end_marker (13), or unknown: skip
      if (offset + size > buf.length) throw new Error('mmdb: value past end');
      return { value: null, offset: offset + size };
    }
  }
}

function toNumber(v) {
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'number') return v;
  return null;
}

// Read one record (left = which 0, right = which 1) from the node at byte
// offset o, for a 24/28/32-bit record size.
function readRecord(buf, o, recordSize, which) {
  if (recordSize === 28) {
    if (which === 0) {
      return ((buf[o + 3] & 0xf0) << 20) | (buf[o] << 16) | (buf[o + 1] << 8) | buf[o + 2];
    }
    return ((buf[o + 3] & 0x0f) << 24) | (buf[o + 4] << 16) | (buf[o + 5] << 8) | buf[o + 6];
  }
  if (recordSize === 24) {
    const b = which === 0 ? o : o + 3;
    return (buf[b] << 16) | (buf[b + 1] << 8) | buf[b + 2];
  }
  // 32-bit
  const b = which === 0 ? o : o + 4;
  return buf.readUInt32BE(b);
}

// MSB-first bit array for an address, mapped into the database's tree space.
// IPv4 in a v6 database is prefixed with 96 zero bits (IPv4 lives under ::/96).
function addressBits(parsed, dbIpVersion) {
  const bits = [];
  if (parsed.version === 4) {
    for (let i = 31; i >= 0; i--) bits.push(Number((parsed.value >> BigInt(i)) & 1n));
    if (dbIpVersion === 6) {
      const prefix = new Array(96).fill(0);
      return prefix.concat(bits);
    }
    return bits;
  }
  if (dbIpVersion === 4) return null; // cannot look up IPv6 in an IPv4 database
  for (let i = 127; i >= 0; i--) bits.push(Number((parsed.value >> BigInt(i)) & 1n));
  return bits;
}

// Parse the buffer and return a reader. Throws on a structurally invalid file.
function open(buffer) {
  if (!Buffer.isBuffer(buffer)) throw new Error('mmdb: a Buffer is required');
  const buf = buffer;

  const metaStart = findMetadataStart(buf);
  if (metaStart === -1) throw new Error('mmdb: metadata marker not found');

  const rawMeta = decode(buf, metaStart, metaStart, 0).value;
  if (!rawMeta || typeof rawMeta !== 'object') throw new Error('mmdb: metadata is not a map');

  const meta = {
    node_count: toNumber(rawMeta.node_count),
    record_size: toNumber(rawMeta.record_size),
    ip_version: toNumber(rawMeta.ip_version),
    database_type: typeof rawMeta.database_type === 'string' ? rawMeta.database_type : '',
    build_epoch: toNumber(rawMeta.build_epoch),
    binary_format_major_version: toNumber(rawMeta.binary_format_major_version),
    binary_format_minor_version: toNumber(rawMeta.binary_format_minor_version),
    description: rawMeta.description && typeof rawMeta.description === 'object' ? rawMeta.description : {},
    languages: Array.isArray(rawMeta.languages) ? rawMeta.languages : [],
  };

  if (meta.record_size !== 24 && meta.record_size !== 28 && meta.record_size !== 32) {
    throw new Error('mmdb: unsupported record_size ' + meta.record_size);
  }
  if (!Number.isInteger(meta.node_count) || meta.node_count <= 0) {
    throw new Error('mmdb: invalid node_count');
  }
  if (meta.ip_version !== 4 && meta.ip_version !== 6) {
    throw new Error('mmdb: invalid ip_version ' + meta.ip_version);
  }

  const recordSize = meta.record_size;
  const nodeCount = meta.node_count;
  const nodeSizeBytes = recordSize / 4; // 6, 7, or 8
  const searchTreeSize = nodeCount * nodeSizeBytes;
  const dataSectionStart = searchTreeSize + 16;

  if (dataSectionStart > buf.length) throw new Error('mmdb: tree size exceeds file');

  // Walk the tree for an address. Returns the tree record value at the leaf:
  //   null            -> no record (the empty value, nodeCount)
  //   > nodeCount     -> a data-section pointer
  function findRecord(bits) {
    let node = 0;
    for (let i = 0; i < bits.length; i++) {
      if (node >= nodeCount) break;
      const rec = readRecord(buf, node * nodeSizeBytes, recordSize, bits[i]);
      if (rec === nodeCount) return null;
      if (rec > nodeCount) return rec;
      node = rec;
    }
    return null;
  }

  function lookup(ip) {
    const parsed = parseIp(ip);
    if (!parsed) return null;
    const bits = addressBits(parsed, meta.ip_version);
    if (!bits) return null;
    const rec = findRecord(bits);
    if (rec === null) return null;
    const dataOffset = dataSectionStart + (rec - nodeCount - 16);
    if (dataOffset < dataSectionStart || dataOffset >= buf.length) return null;
    try {
      return decode(buf, dataOffset, dataSectionStart, 0).value;
    } catch (err) {
      return null;
    }
  }

  function lookupCountry(ip) {
    const data = lookup(ip);
    if (data && data.country && typeof data.country.iso_code === 'string') {
      return data.country.iso_code;
    }
    return null;
  }

  return { meta, lookup, lookupCountry };
}

module.exports = { open };
