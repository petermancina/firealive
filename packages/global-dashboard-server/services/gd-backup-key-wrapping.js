// =============================================================================
// FIREALIVE GD -- Backup Key Wrapping
//
// Wraps and unwraps the per-backup ephemeral 256-bit data key that
// gd-backup-archive produced, storing the result as wrapped-key.bin in a v2
// backup directory.
//
// This is the GD's deliberately thin counterpart to the Regional
// backup-key-wrapping service. The Regional module is a KMS-provider registry
// (env-var / aws-kms / azure-keyvault / gcp-kms / hashicorp-vault, each a
// self-registering provider). The GD wraps ALL of its secrets -- destination
// credentials, signing private keys, and now backup data keys -- through the
// single GD Tier-1 KEK via gd-encryption. So there is no provider registry: one
// scheme, 'gd-tier1', backed by gd-encryption's AES-256-GCM envelope under the
// KEK derived from GD_ENCRYPTION_KEY.
//
// The public interface, envelope shape, and defense-in-depth checks match the
// Regional service so the manifest and restore paths are identical:
//
//   wrapKey(ephemeralKey, options)  -> Buffer (wrapped-key.bin contents)
//   unwrapKey(envelopeBytes, expectedScheme, expectedRef, options) -> Buffer (key)
//
// The wrapped-key.bin envelope:
//   { "v": 1, "scheme": "gd-tier1", "ref": "GD_ENCRYPTION_KEY",
//     "wrapped": "<base64 of the gd-encryption envelope string>" }
//
// unwrapKey verifies the envelope's scheme/ref match the manifest-declared
// values before unwrapping, even though the manifest's file hash would also
// catch a swapped wrapped-key.bin. Two redundant integrity gates is the
// SOC-grade design. Cloud-KMS KEK parity (adding an 'aws-kms' etc. scheme here)
// is a deferred future item; the envelope's scheme field is the forward-compat
// seam for it.
// =============================================================================

const { encryptConfigWithKey, decryptConfigWithKey, deriveKek } = require('./gd-encryption');
const gdTier1Kek = require('./gd-tier1-kek');

const ENVELOPE_VERSION = 1;
const KEY_LENGTH_BYTES = 32;                 // AES-256 data key
const DEFAULT_SCHEME = 'gd-tier1';
const DEFAULT_KEK_REFERENCE = 'GD_ENCRYPTION_KEY';
const SUPPORTED_SCHEMES = ['gd-tier1'];

/**
 * Serialize an outer wrapping envelope object to the wrapped-key.bin bytes
 * (JSON as UTF-8).
 */
function serializeEnvelope(envelope) {
  return Buffer.from(JSON.stringify(envelope), 'utf-8');
}

/**
 * Parse wrapped-key.bin bytes (or a string) into the outer envelope object.
 * Validates the version and the required fields. Throws on malformed input.
 */
function parseEnvelope(envelopeBytes) {
  const text = Buffer.isBuffer(envelopeBytes)
    ? envelopeBytes.toString('utf-8')
    : String(envelopeBytes);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new Error(`gd-backup-key-wrapping: envelope is not valid JSON: ${err.message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('gd-backup-key-wrapping: envelope is not a JSON object');
  }
  if (parsed.v !== ENVELOPE_VERSION) {
    throw new Error(`gd-backup-key-wrapping: envelope version ${parsed.v} unsupported (expected ${ENVELOPE_VERSION})`);
  }
  for (const required of ['scheme', 'ref', 'wrapped']) {
    if (parsed[required] === undefined || parsed[required] === null) {
      throw new Error(`gd-backup-key-wrapping: envelope missing required field '${required}'`);
    }
  }
  return parsed;
}

/**
 * Wrap an ephemeral 256-bit data key.
 *
 * Inputs:
 *   ephemeralKey  Buffer (32 bytes, AES-256)
 *   options       { scheme?, kekReference?, logger? } -- all optional; scheme
 *                 defaults to 'gd-tier1', kekReference to 'GD_ENCRYPTION_KEY'
 *
 * Returns: Buffer -- the wrapped-key.bin file contents (JSON envelope as UTF-8).
 *
 * Async to match the Regional interface and to leave room for a future async
 * cloud-KMS scheme; the gd-tier1 path is synchronous internally.
 */
async function wrapKey(ephemeralKey, options = {}) {
  if (!Buffer.isBuffer(ephemeralKey) || ephemeralKey.length !== KEY_LENGTH_BYTES) {
    throw new Error(`gd-backup-key-wrapping: ephemeralKey must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
  const scheme = typeof options.scheme === 'string' && options.scheme ? options.scheme : DEFAULT_SCHEME;
  const ref = typeof options.kekReference === 'string' && options.kekReference ? options.kekReference : DEFAULT_KEK_REFERENCE;

  if (!SUPPORTED_SCHEMES.includes(scheme)) {
    throw new Error(`gd-backup-key-wrapping: unknown scheme '${scheme}' (supported: ${SUPPORTED_SCHEMES.join(', ')})`);
  }

  // Wrap the raw key through the GD Tier-1 KEK. gd-encryption serializes the
  // object, AES-256-GCM-encrypts it under the KEK, and returns a self-describing
  // envelope string. We carry that string, base64-encoded, in the outer
  // envelope's `wrapped` field.
  const gdEnvelope = encryptConfigWithKey({ k: ephemeralKey.toString('base64') }, deriveKek());

  const envelope = {
    v: ENVELOPE_VERSION,
    scheme,
    ref,
    wrapped: Buffer.from(gdEnvelope, 'utf-8').toString('base64'),
  };
  return serializeEnvelope(envelope);
}

/**
 * Unwrap a wrapped-key.bin file back to the raw 32-byte ephemeral key.
 *
 * Inputs:
 *   envelopeBytes    Buffer or string -- the wrapped-key.bin contents
 *   expectedScheme   string -- the manifest-declared scheme
 *   expectedRef      string -- the manifest-declared kek_reference
 *   options          { logger? } (optional)
 *
 * Defense-in-depth: throws if the envelope's claimed scheme/ref do not match
 * expectedScheme/expectedRef, even though the manifest's file hash would also
 * catch this.
 *
 * Returns: Buffer (32 bytes -- the ephemeral key).
 */
async function unwrapKey(envelopeBytes, expectedScheme, expectedRef, options = {}) {
  if (typeof expectedScheme !== 'string' || !expectedScheme) {
    throw new Error('gd-backup-key-wrapping: expectedScheme required for unwrap');
  }
  if (typeof expectedRef !== 'string' || !expectedRef) {
    throw new Error('gd-backup-key-wrapping: expectedRef required for unwrap');
  }
  if (!SUPPORTED_SCHEMES.includes(expectedScheme)) {
    throw new Error(`gd-backup-key-wrapping: unknown scheme '${expectedScheme}' (supported: ${SUPPORTED_SCHEMES.join(', ')})`);
  }

  const envelope = parseEnvelope(envelopeBytes);

  if (envelope.scheme !== expectedScheme) {
    throw new Error(
      `gd-backup-key-wrapping: envelope scheme '${envelope.scheme}' ` +
      `does not match manifest-declared scheme '${expectedScheme}'`,
    );
  }
  if (envelope.ref !== expectedRef) {
    throw new Error(
      `gd-backup-key-wrapping: envelope ref '${envelope.ref}' ` +
      `does not match manifest-declared ref '${expectedRef}'`,
    );
  }

  const gdEnvelope = Buffer.from(envelope.wrapped, 'base64').toString('utf-8');
  let obj;
  try {
    obj = decryptConfigWithKey(gdEnvelope, deriveKek());
  } catch (err) {
    // Unwrap failures (wrong KEK, tampered wrapped bytes) are permanent; no
    // retry helps.
    throw new Error(`gd-backup-key-wrapping: unwrap failed (wrong KEK or tampered wrapped key): ${err.message}`);
  }
  if (!obj || typeof obj.k !== 'string') {
    throw new Error('gd-backup-key-wrapping: unwrapped envelope missing key material');
  }
  const key = Buffer.from(obj.k, 'base64');
  if (key.length !== KEY_LENGTH_BYTES) {
    throw new Error(`gd-backup-key-wrapping: unwrapped key is ${key.length} bytes, expected ${KEY_LENGTH_BYTES}`);
  }
  return key;
}

// Fingerprint of the KEK this backup was wrapped under (D-R2-4). The GD wraps every backup DEK
// under the single GD Tier-1 KEK (scheme 'gd-tier1': wrapKey -> deriveKek() -> resolveTier1Kek(),
// which is ownKek), so the backup's KEK fingerprint is ownKek's -- the same ownKekFingerprint the
// boot gate and envelope use. The manifest salts it per backup_id. No provider registry here.
function resolveKekFingerprint(scheme) {
  const s = scheme || DEFAULT_SCHEME;
  if (!SUPPORTED_SCHEMES.includes(s)) {
    throw new Error(`gd-backup-key-wrapping: unknown scheme '${s}' for KEK fingerprint`);
  }
  return gdTier1Kek.ownKekFingerprint().toString('hex');
}

module.exports = {
  wrapKey,
  unwrapKey,
  resolveKekFingerprint,
  parseEnvelope,
  serializeEnvelope,
  ENVELOPE_VERSION,
  KEY_LENGTH_BYTES,
  DEFAULT_SCHEME,
  DEFAULT_KEK_REFERENCE,
  SUPPORTED_SCHEMES,
};
