// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — GGUF Header Validator (defensive)
//
// Part of the model-file integrity & safety gate. The loader (node-llama-cpp /
// llama.cpp) parses the GGUF in-process, so a malformed header that triggers a
// parser overflow is in-process RCE. This validator defangs that attack surface
// by sanity-checking the GGUF header BEFORE the native loader ever reads the
// file: magic, version, the tensor/metadata counts (absolute caps, numeric-
// precision, and a relative-to-file-size plausibility bound), and a bounded walk
// of the metadata key/value records to reject out-of-bounds lengths, unknown
// value types, and nested arrays.
//
// It is a DEFENSIVE VALIDATOR, not a full parser (decision 14):
//   - It reads only a header prefix (default 16 MB), never the whole multi-GB file.
//   - It is conservative and biased AGAINST false positives: a legitimate file
//     whose metadata runs past the read prefix is ACCEPTED (the walk stops at the
//     prefix boundary). It rejects only on a definitive inconsistency — a length
//     that overflows the real file size, an invalid value-type byte, an absurd
//     count, or a nested array.
//
// validateGguf(filePath, opts?) -> { ok, reason, code, meta }
//   meta = { magicOk, version, tensorCount, kvCount, kvParsed, truncatedAtPrefix }
// ═══════════════════════════════════════════════════════════════════════════════

const fs = require('fs');

const GGUF_MAGIC = 0x46554747; // 'GGUF' little-endian
const ACCEPTED_VERSIONS = new Set([2, 3]);

// GGUF metadata value types (gguf_metadata_value_type)
const T_STRING = 8;
const T_ARRAY = 9;
const SCALAR_WIDTH = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };
const KNOWN_TYPE = new Set([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

const DEFAULTS = {
  maxHeaderBytes: 16 * 1024 * 1024, // header prefix to read
  maxTensors: 1000000n,
  maxKv: 1000000n,
  maxKeyLen: 65536n,
  maxStrLen: 64n * 1024n * 1024n,    // a single metadata string
  maxArrayLen: 100000000n,           // array element count (e.g. tokenizer vocab)
  minTensorInfoBytes: 20n,           // conservative on-disk floor per tensor info
  minKvBytes: 12n,                   // conservative on-disk floor per kv record
};

function rej(code, reason, meta) {
  return { ok: false, reason, code, meta: meta || {} };
}

function validateGguf(filePath, opts) {
  const o = Object.assign({}, DEFAULTS, opts || {});

  let st;
  try { st = fs.statSync(filePath); }
  catch (e) { return rej('io_error', 'cannot stat file: ' + e.message); }
  const fileSize = st.size;
  const fileBig = BigInt(fileSize);
  if (fileSize < 24) return rej('too_small', 'file smaller than a GGUF header (24 bytes)');

  const readLen = Math.min(fileSize, o.maxHeaderBytes);
  const buf = Buffer.allocUnsafe(readLen);
  let fd;
  try {
    fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, readLen, 0);
  } catch (e) {
    return rej('io_error', 'cannot read file: ' + e.message);
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch (_) { /* ignore */ } }
  }

  const magic = buf.readUInt32LE(0);
  if (magic !== GGUF_MAGIC) return rej('bad_magic', 'not a GGUF file (bad magic)', { magicOk: false });

  const version = buf.readUInt32LE(4);
  if (!ACCEPTED_VERSIONS.has(version)) {
    return rej('bad_version', 'unsupported GGUF version ' + version, { magicOk: true, version });
  }

  const tensorCount = buf.readBigUInt64LE(8);
  const kvCount = buf.readBigUInt64LE(16);
  const meta = { magicOk: true, version, tensorCount: null, kvCount: null, kvParsed: 0, truncatedAtPrefix: false };

  if (tensorCount > o.maxTensors) return rej('tensor_count_oob', 'tensor_count exceeds bound', meta);
  if (kvCount > o.maxKv) return rej('kv_count_oob', 'metadata_kv_count exceeds bound', meta);
  // Relative plausibility: the declared counts cannot require more on-disk bytes
  // than the file holds. Catches absurd counts crafted to overflow the loader's
  // allocations, with no false positives on real files (counts << fileSize/min).
  if (tensorCount * o.minTensorInfoBytes > fileBig) return rej('tensor_count_oob', 'tensor_count implausible vs file size', meta);
  if (kvCount * o.minKvBytes > fileBig) return rej('kv_count_oob', 'metadata_kv_count implausible vs file size', meta);

  meta.tensorCount = Number(tensorCount);
  meta.kvCount = Number(kvCount);

  // Bounded walk of the metadata KV records. Stops (accepts) at the prefix
  // boundary; rejects only on a definitive OOB/overflow/invalid-type/nested-array.
  let off = 24;
  for (let i = 0n; i < kvCount; i++) {
    if (off + 8 > readLen) { meta.truncatedAtPrefix = true; break; }
    const keyLen = buf.readBigUInt64LE(off);
    if (keyLen > o.maxKeyLen || BigInt(off) + 8n + keyLen > fileBig) {
      return rej('kv_key_oob', 'metadata key length out of bounds', meta);
    }
    off += 8 + Number(keyLen);
    if (off + 4 > readLen) { meta.truncatedAtPrefix = true; break; }
    const vtype = buf.readUInt32LE(off);
    off += 4;
    const r = skipValue(buf, off, readLen, fileBig, vtype, o, 0);
    if (r.reject) return rej(r.code, r.reason, meta);
    if (r.truncated) { meta.truncatedAtPrefix = true; break; }
    off = r.off;
    meta.kvParsed++;
  }

  return { ok: true, reason: null, code: null, meta };
}

// Advance `off` past one metadata value of type `vtype`. depth guards against
// nested arrays (GGUF does not allow them). Returns {off} | {truncated} | {reject,code,reason}.
function skipValue(buf, off, readLen, fileBig, vtype, o, depth) {
  if (!KNOWN_TYPE.has(vtype)) return { reject: true, code: 'bad_value_type', reason: 'unknown metadata value type ' + vtype };

  if (Object.prototype.hasOwnProperty.call(SCALAR_WIDTH, vtype)) {
    const w = SCALAR_WIDTH[vtype];
    if (BigInt(off) + BigInt(w) > fileBig) return { reject: true, code: 'value_oob', reason: 'scalar value overruns file' };
    if (off + w > readLen) return { truncated: true };
    return { off: off + w };
  }

  if (vtype === T_STRING) {
    if (off + 8 > readLen) return { truncated: true };
    const strLen = buf.readBigUInt64LE(off);
    if (strLen > o.maxStrLen || BigInt(off) + 8n + strLen > fileBig) {
      return { reject: true, code: 'str_oob', reason: 'metadata string length out of bounds' };
    }
    const next = off + 8 + Number(strLen);
    if (next > readLen) return { truncated: true };
    return { off: next };
  }

  if (vtype === T_ARRAY) {
    if (depth > 0) return { reject: true, code: 'nested_array', reason: 'nested arrays are not valid GGUF' };
    if (off + 12 > readLen) return { truncated: true };
    const arrType = buf.readUInt32LE(off);
    const arrLen = buf.readBigUInt64LE(off + 4);
    off += 12;
    if (!KNOWN_TYPE.has(arrType)) return { reject: true, code: 'bad_value_type', reason: 'unknown array element type ' + arrType };
    if (arrType === T_ARRAY) return { reject: true, code: 'nested_array', reason: 'array of arrays is not valid GGUF' };
    if (arrLen > o.maxArrayLen) return { reject: true, code: 'array_oob', reason: 'array length exceeds bound' };

    if (Object.prototype.hasOwnProperty.call(SCALAR_WIDTH, arrType)) {
      // Fixed-width elements: bound the total against the file, then advance.
      const total = arrLen * BigInt(SCALAR_WIDTH[arrType]);
      if (BigInt(off) + total > fileBig) return { reject: true, code: 'array_oob', reason: 'fixed-width array overruns file' };
      const end = BigInt(off) + total;
      if (end > BigInt(readLen)) return { truncated: true };
      return { off: Number(end) };
    }
    if (arrType === T_STRING) {
      // Walk string elements within the prefix; truncate (accept) if it runs past.
      for (let j = 0n; j < arrLen; j++) {
        if (off + 8 > readLen) return { truncated: true };
        const sLen = buf.readBigUInt64LE(off);
        if (sLen > o.maxStrLen || BigInt(off) + 8n + sLen > fileBig) {
          return { reject: true, code: 'str_oob', reason: 'array string element out of bounds' };
        }
        const next = off + 8 + Number(sLen);
        if (next > readLen) return { truncated: true };
        off = next;
      }
      return { off };
    }
    return { reject: true, code: 'bad_value_type', reason: 'unhandled array element type ' + arrType };
  }

  return { reject: true, code: 'bad_value_type', reason: 'unhandled value type ' + vtype };
}

module.exports = { validateGguf, GGUF_MAGIC };
