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

// B6g: the provider registry. Requiring the provider modules is what registers
// them -- each calls base.registerProvider at load. A provider whose SDK is not
// installed stays unregistered rather than crashing the server, which is why the
// requires are individually guarded.
const providerBase = require('./gd-key-wrapping-providers/base');
for (const mod of [
  './gd-key-wrapping-providers/gd-tier1',
  './gd-key-wrapping-providers/aws-kms',
  './gd-key-wrapping-providers/azure-keyvault',
  './gd-key-wrapping-providers/gcp-kms',
  './gd-key-wrapping-providers/hashicorp-vault',
]) {
  try { require(mod); } catch (_e) { /* SDK absent: that provider is simply unavailable */ }
}

const ENVELOPE_VERSION = 1;
const KEY_LENGTH_BYTES = 32;                 // AES-256 data key
const DEFAULT_SCHEME = 'gd-tier1';
const DEFAULT_KEK_REFERENCE = 'GD_ENCRYPTION_KEY';
// B6g: the registry's view rather than a literal. gd-tier1 is asserted present
// rather than assumed: it is the scheme every existing manifest records, and a
// build that failed to register it would turn every historical backup
// unreadable with a message about an unknown scheme.
function supportedSchemes() {
  const names = providerBase.listProviders().map((p) => (typeof p === 'string' ? p : p.name));
  if (names.indexOf(DEFAULT_SCHEME) === -1) {
    throw new Error(
      "gd-backup-key-wrapping: the '" + DEFAULT_SCHEME + "' provider is not registered. "
      + 'Every GD backup ever taken records that scheme, so this build cannot read any of them.',
    );
  }
  return names;
}

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

  const schemes = supportedSchemes();
  if (!schemes.includes(scheme)) {
    throw new Error(`gd-backup-key-wrapping: unknown scheme '${scheme}' (supported: ${schemes.join(', ')})`);
  }

  // B6g: delegate to the registered provider. The gd-tier1 provider reproduces
  // the pre-registry calls byte-for-byte -- encryptConfigWithKey({ k: <base64> },
  // deriveKek()) then utf-8 -> base64 -- so an archive written before this change
  // and one written after are indistinguishable.
  const impl = providerBase.getProvider(scheme);
  if (!impl) {
    throw new Error(`gd-backup-key-wrapping: scheme '${scheme}' is not registered on this server`);
  }
  const wrapped = await impl.wrap(ephemeralKey, options.config || {}, options.credentials || null, options);

  const envelope = {
    v: ENVELOPE_VERSION,
    scheme,
    ref,
    wrapped,
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
  const schemes = supportedSchemes();
  if (!schemes.includes(expectedScheme)) {
    throw new Error(`gd-backup-key-wrapping: unknown scheme '${expectedScheme}' (supported: ${schemes.join(', ')})`);
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

  // B6g: delegate to the provider the MANIFEST names, not the one currently
  // configured. A backup wrapped under a provider that has since been retired
  // still restores, which is the whole reason retirement exists as a state
  // distinct from deletion.
  const impl = providerBase.getProvider(expectedScheme);
  if (!impl) {
    throw new Error(
      `gd-backup-key-wrapping: this backup was wrapped with scheme '${expectedScheme}', `
      + 'which is not registered on this server. The archive is intact; the provider module '
      + 'that opens it is missing.',
    );
  }
  let key;
  try {
    key = await impl.unwrap(envelope.wrapped, options.config || {}, options.credentials || null, options);
  } catch (err) {
    // Unwrap failures (wrong KEK, tampered wrapped bytes) are permanent; no
    // retry helps.
    throw new Error(`gd-backup-key-wrapping: unwrap failed (wrong KEK or tampered wrapped key): ${err.message}`);
  }
  // The length check stays HERE as well as in the provider. A provider is a
  // registered module and a future one could return the wrong thing; this is the
  // chokepoint every restore passes through, so it is where the invariant that
  // matters to the caller belongs.
  if (!Buffer.isBuffer(key)) {
    throw new Error('gd-backup-key-wrapping: provider returned a non-Buffer key');
  }
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

// D-R2-2: unwrap a wrapped DEK with a PROVIDED raw KEK instead of the GD Tier-1 KEK. Used ONLY by
// the offline import-rekey tool, where the source KEK is recovered transiently from the source
// recovery code and the DEK was wrapped under it. Same inner envelope as unwrapKey
// (encryptConfigWithKey under the KEK, base64 in the outer envelope); the raw KEK is the caller's
// to scrub. Does not check scheme/ref -- the offline tool supplies the KEK deliberately.
function unwrapKeyWithRawKek(envelopeBytes, rawKek) {
  if (!Buffer.isBuffer(rawKek) || rawKek.length !== KEY_LENGTH_BYTES) {
    throw new Error(`gd-backup-key-wrapping: rawKek must be a ${KEY_LENGTH_BYTES}-byte Buffer`);
  }
  const envelope = parseEnvelope(envelopeBytes);
  const gdEnvelope = Buffer.from(envelope.wrapped, 'base64').toString('utf-8');
  let obj;
  try {
    obj = decryptConfigWithKey(gdEnvelope, rawKek);
  } catch (err) {
    throw new Error(`gd-backup-key-wrapping: raw-KEK unwrap failed (wrong KEK or tampered wrapped key): ${err.message}`);
  }
  if (!obj || typeof obj.k !== 'string') {
    throw new Error('gd-backup-key-wrapping: unwrapped envelope missing key material');
  }
  return Buffer.from(obj.k, 'base64');
}

module.exports = {
  wrapKey,
  unwrapKey,
  unwrapKeyWithRawKek,
  resolveKekFingerprint,
  parseEnvelope,
  serializeEnvelope,
  ENVELOPE_VERSION,
  KEY_LENGTH_BYTES,
  DEFAULT_SCHEME,
  DEFAULT_KEK_REFERENCE,
  // B6g: a function now, not a frozen literal. Callers that read it get the
  // registry's live view; the name is kept so existing call sites keep working.
  supportedSchemes,
  get SUPPORTED_SCHEMES() { return supportedSchemes(); },
};
