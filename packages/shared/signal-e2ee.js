'use strict';

//
// FireAlive — shared Signal-protocol End-to-End-Encryption wrapper.
//
// Wraps @signalapp/libsignal-client (the audited Signal protocol reference
// implementation: X3DH + PQXDH for session setup, Double Ratchet for messages).
// NO cryptography is implemented here — every primitive call goes to libsignal.
//
// Design constraints (see U3-DETAILED-BUILD-PLAN section 0.1 / 2e):
//   * Runs ONLY in an Electron main process. Identity private keys and ratchet
//     state never cross the IPC bridge.
//   * libsignal is INJECTED by the host app (deps.libsignal). This file performs
//     no `require('@signalapp/libsignal-client')`, so it resolves and bundles
//     regardless of which app's node_modules the native module lives in. The
//     host app `require`s libsignal from its own node_modules and passes it in.
//   * Persistence is INJECTED (deps.backend). The host wires it to an
//     OS-keychain-sealed store (Electron safeStorage). All record bytes handed
//     to the backend are already libsignal-serialized; sealing-at-rest is the
//     backend's job.
//   * Two cryptographically separated key DOMAINS ('peer' and 'lead'). Create one
//     instance per domain; keys are namespaced by domain so the two never mix.
//
// All libsignal API shapes below were verified against signalapp/libsignal
// node/ts (index.ts, EcKeys.ts, ProtocolTypes.ts) for client v0.94.x.
//
// deps = {
//   libsignal,            // the @signalapp/libsignal-client module object
//   backend,              // { get(k):Promise<string|null>, set(k,v):Promise<void>,
//                         //   delete(k):Promise<void>, list(prefix):Promise<string[]> }
//                         //   values are base64 strings (sealed at rest by the host)
//   domain,               // 'peer' | 'lead'
//   selfUserId,           // stable string identifier for the local user (this domain)
//   deviceId,             // optional, defaults to 1 (single-device model)
// }
//

const SAFETY_NUMBER_ITERATIONS = 5200; // Signal's standard; both parties must match
const SAFETY_NUMBER_VERSION = 2; // fingerprint format version; cosmetic, must match

function createSignalE2EE(deps) {
  if (!deps || typeof deps !== 'object') {
    throw new Error('signal-e2ee: deps object is required');
  }
  const { libsignal, backend } = deps;
  const domain = deps.domain;
  const selfUserId = deps.selfUserId;
  const deviceId = deps.deviceId == null ? 1 : deps.deviceId;

  if (!libsignal) throw new Error('signal-e2ee: deps.libsignal is required');
  if (!backend) throw new Error('signal-e2ee: deps.backend is required');
  if (domain !== 'peer' && domain !== 'lead') {
    throw new Error("signal-e2ee: deps.domain must be 'peer' or 'lead'");
  }
  if (!selfUserId) throw new Error('signal-e2ee: deps.selfUserId is required');

  const {
    PrivateKey,
    PublicKey,
    IdentityKeyPair,
    PreKeyRecord,
    SignedPreKeyRecord,
    KyberPreKeyRecord,
    KEMKeyPair,
    KEMPublicKey,
    PreKeyBundle,
    ProtocolAddress,
    SessionRecord,
    SignalMessage,
    PreKeySignalMessage,
    SessionStore,
    IdentityKeyStore,
    PreKeyStore,
    SignedPreKeyStore,
    KyberPreKeyStore,
    Fingerprint,
    CiphertextMessageType,
    IdentityChange,
  } = libsignal;

  // ---- key namespacing (domain isolation) + small codecs --------------------

  const ns = (k) => domain + ':' + k;
  const b64 = (u8) => Buffer.from(u8).toString('base64');
  const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
  const utf8 = (s) => new TextEncoder().encode(s);

  async function bget(key) {
    const v = await backend.get(ns(key));
    return v == null ? null : v;
  }
  const bset = (key, value) => backend.set(ns(key), value);
  const bdel = (key) => backend.delete(ns(key));
  const blist = (prefix) => backend.list(ns(prefix));

  function randomRegistrationId() {
    // libsignal registration ids are 14-bit (1..16380). Not secret — an installation id.
    const buf = new Uint32Array(1);
    globalThis.crypto.getRandomValues(buf);
    return (buf[0] % 16380) + 1;
  }

  const KEY_IDENTITY = 'identity:keypair';
  const KEY_REGID = 'identity:registrationId';
  const sessionKey = (a) => 'session:' + a.name() + ':' + a.deviceId();
  const remoteIdKey = (a) => 'remoteIdentity:' + a.name() + ':' + a.deviceId();
  const preKeyKey = (id) => 'preKey:' + id;
  const signedPreKeyKey = (id) => 'signedPreKey:' + id;
  const kyberPreKeyKey = (id) => 'kyberPreKey:' + id;

  // ---- libsignal store implementations (backed by the injected backend) -----

  class Sessions extends SessionStore {
    async saveSession(name, record) {
      await bset(sessionKey(name), b64(record.serialize()));
    }
    async getSession(name) {
      const v = await bget(sessionKey(name));
      return v == null ? null : SessionRecord.deserialize(unb64(v));
    }
    async getExistingSessions(addresses) {
      const out = [];
      for (const a of addresses) {
        const v = await bget(sessionKey(a));
        if (v == null) {
          throw new Error('signal-e2ee: no session for ' + a.name());
        }
        out.push(SessionRecord.deserialize(unb64(v)));
      }
      return out;
    }
  }

  class Identity extends IdentityKeyStore {
    async getIdentityKey() {
      const v = await bget(KEY_IDENTITY);
      if (v == null) {
        throw new Error('signal-e2ee: identity not initialized; call init() first');
      }
      return IdentityKeyPair.deserialize(unb64(v)).privateKey;
    }
    async getLocalRegistrationId() {
      const v = await bget(KEY_REGID);
      if (v == null) {
        throw new Error('signal-e2ee: registration id not initialized; call init() first');
      }
      return parseInt(v, 10);
    }
    async saveIdentity(name, key) {
      const existing = await bget(remoteIdKey(name));
      const incoming = b64(key.serialize());
      await bset(remoteIdKey(name), incoming);
      if (existing != null && existing !== incoming) {
        return IdentityChange.ReplacedExisting;
      }
      return IdentityChange.NewOrUnchanged;
    }
    async isTrustedIdentity(name, key /*, direction */) {
      // Trust on first use; thereafter the key must match what we pinned.
      // Out-of-band safety-number comparison (see safetyNumber()) is what
      // actually defends against a server-substituted key.
      const existing = await bget(remoteIdKey(name));
      if (existing == null) return true;
      return existing === b64(key.serialize());
    }
    async getIdentity(name) {
      const v = await bget(remoteIdKey(name));
      return v == null ? null : PublicKey.deserialize(unb64(v));
    }
  }

  class PreKeys extends PreKeyStore {
    async savePreKey(id, record) {
      await bset(preKeyKey(id), b64(record.serialize()));
    }
    async getPreKey(id) {
      const v = await bget(preKeyKey(id));
      if (v == null) throw new Error('signal-e2ee: missing one-time pre-key ' + id);
      return PreKeyRecord.deserialize(unb64(v));
    }
    async removePreKey(id) {
      await bdel(preKeyKey(id));
    }
  }

  class SignedPreKeys extends SignedPreKeyStore {
    async saveSignedPreKey(id, record) {
      await bset(signedPreKeyKey(id), b64(record.serialize()));
    }
    async getSignedPreKey(id) {
      const v = await bget(signedPreKeyKey(id));
      if (v == null) throw new Error('signal-e2ee: missing signed pre-key ' + id);
      return SignedPreKeyRecord.deserialize(unb64(v));
    }
  }

  class KyberPreKeys extends KyberPreKeyStore {
    async saveKyberPreKey(id, record) {
      await bset(kyberPreKeyKey(id), b64(record.serialize()));
    }
    async getKyberPreKey(id) {
      const v = await bget(kyberPreKeyKey(id));
      if (v == null) throw new Error('signal-e2ee: missing kyber pre-key ' + id);
      return KyberPreKeyRecord.deserialize(unb64(v));
    }
    async markKyberPreKeyUsed(/* id, ecPreKeyId, baseKey */) {
      // Last-resort semantics: the kyber pre-key is retained for reuse rather than
      // consumed, so sessions can still be initiated after one-time EC pre-keys are
      // exhausted. Forward secrecy for the ongoing conversation comes from the
      // Double Ratchet regardless.
    }
  }

  const sessions = new Sessions();
  const identity = new Identity();
  const preKeys = new PreKeys();
  const signedPreKeys = new SignedPreKeys();
  const kyberPreKeys = new KyberPreKeys();

  const addr = (userId) => ProtocolAddress.new(String(userId), deviceId);
  const selfAddr = () => addr(selfUserId);

  // ---- identity + pre-key generation / publishing ---------------------------

  async function init() {
    const have = await bget(KEY_IDENTITY);
    if (have == null) {
      const idKeyPair = IdentityKeyPair.generate();
      await bset(KEY_IDENTITY, b64(idKeyPair.serialize()));
      await bset(KEY_REGID, String(randomRegistrationId()));
    }
  }

  async function getIdentityKeyPair() {
    const v = await bget(KEY_IDENTITY);
    if (v == null) throw new Error('signal-e2ee: identity not initialized; call init() first');
    return IdentityKeyPair.deserialize(unb64(v));
  }

  async function generateSignedPreKey(id) {
    const idKeyPair = await getIdentityKeyPair();
    const priv = PrivateKey.generate();
    const pub = priv.getPublicKey();
    const signature = idKeyPair.privateKey.sign(pub.serialize());
    const record = SignedPreKeyRecord.new(id, Date.now(), pub, priv, signature);
    await signedPreKeys.saveSignedPreKey(id, record);
    return { id, publicKey: b64(pub.serialize()), signature: b64(signature) };
  }

  async function generateKyberPreKey(id) {
    const idKeyPair = await getIdentityKeyPair();
    const kemPair = KEMKeyPair.generate();
    const pub = kemPair.getPublicKey();
    const signature = idKeyPair.privateKey.sign(pub.serialize());
    const record = KyberPreKeyRecord.new(id, Date.now(), kemPair, signature);
    await kyberPreKeys.saveKyberPreKey(id, record);
    return { id, publicKey: b64(pub.serialize()), signature: b64(signature) };
  }

  async function generateOneTimePreKeys(startId, count) {
    const out = [];
    for (let i = 0; i < count; i++) {
      const id = startId + i;
      const priv = PrivateKey.generate();
      const pub = priv.getPublicKey();
      await preKeys.savePreKey(id, PreKeyRecord.new(id, pub, priv));
      out.push({ id, publicKey: b64(pub.serialize()) });
    }
    return out;
  }

  // Produce the public bundle to publish to the server's content-blind pre-key
  // store. Private material stays local (sealed by the backend).
  async function buildPublishableBundle(opts) {
    const oneTimeCount = (opts && opts.oneTimeCount) || 50;
    const signedPreKeyId = (opts && opts.signedPreKeyId) || 1;
    const kyberPreKeyId = (opts && opts.kyberPreKeyId) || 1;
    const oneTimeStartId = (opts && opts.oneTimeStartId) || 1;

    await init();
    const idKeyPair = await getIdentityKeyPair();
    const registrationId = await identity.getLocalRegistrationId();
    const signedPreKey = await generateSignedPreKey(signedPreKeyId);
    const kyberPreKey = await generateKyberPreKey(kyberPreKeyId);
    const oneTimePreKeys = await generateOneTimePreKeys(oneTimeStartId, oneTimeCount);

    return {
      domain,
      registrationId,
      deviceId,
      identityKey: b64(idKeyPair.publicKey.serialize()),
      signedPreKey,
      kyberPreKey,
      oneTimePreKeys,
    };
  }

  // ---- session establishment (X3DH/PQXDH) -----------------------------------

  // bundleJson is one entry the server handed out (one one-time pre-key consumed,
  // or null if the peer's supply was depleted).
  async function processPeerBundle(remoteUserId, bundleJson) {
    await init();
    const remote = addr(remoteUserId);
    const otp = bundleJson.oneTimePreKey || null;
    const bundle = PreKeyBundle.new(
      bundleJson.registrationId,
      bundleJson.deviceId == null ? 1 : bundleJson.deviceId,
      otp ? otp.id : null,
      otp ? PublicKey.deserialize(unb64(otp.publicKey)) : null,
      bundleJson.signedPreKey.id,
      PublicKey.deserialize(unb64(bundleJson.signedPreKey.publicKey)),
      unb64(bundleJson.signedPreKey.signature),
      PublicKey.deserialize(unb64(bundleJson.identityKey)),
      bundleJson.kyberPreKey.id,
      KEMPublicKey.deserialize(unb64(bundleJson.kyberPreKey.publicKey)),
      unb64(bundleJson.kyberPreKey.signature)
    );
    await libsignal.processPreKeyBundle(
      bundle,
      remote,
      selfAddr(),
      sessions,
      identity
    );
  }

  async function hasSession(remoteUserId) {
    return (await sessions.getSession(addr(remoteUserId))) != null;
  }

  // ---- message encrypt / decrypt (Double Ratchet) ---------------------------

  // Returns { type, body } — type is a CiphertextMessageType, body is base64.
  // The relay stores these opaquely (it cannot read them) plus routing/ordering.
  async function encrypt(remoteUserId, plaintext) {
    await init();
    const message = typeof plaintext === 'string' ? utf8(plaintext) : plaintext;
    const ciphertext = await libsignal.signalEncrypt(
      message,
      addr(remoteUserId),
      selfAddr(),
      sessions,
      identity
    );
    return { type: ciphertext.type(), body: b64(ciphertext.serialize()) };
  }

  // envelope = { type, body } as produced by encrypt() on the far side.
  // Returns the decrypted bytes (Buffer). Caller decodes (e.g. .toString('utf8')).
  async function decrypt(remoteUserId, envelope) {
    await init();
    const remote = addr(remoteUserId);
    const bytes = unb64(envelope.body);
    let plaintext;
    if (envelope.type === CiphertextMessageType.PreKey) {
      plaintext = await libsignal.signalDecryptPreKey(
        PreKeySignalMessage.deserialize(bytes),
        remote,
        selfAddr(),
        sessions,
        identity,
        preKeys,
        signedPreKeys,
        kyberPreKeys
      );
    } else if (envelope.type === CiphertextMessageType.Whisper) {
      plaintext = await libsignal.signalDecrypt(
        SignalMessage.deserialize(bytes),
        remote,
        selfAddr(),
        sessions,
        identity
      );
    } else {
      throw new Error('signal-e2ee: unsupported message type ' + envelope.type);
    }
    return Buffer.from(plaintext);
  }

  // ---- out-of-band verification (safety number) -----------------------------

  // Both parties compute the same displayable string (the local/remote pair is
  // swapped on each side, which the fingerprint is symmetric over). They compare
  // it over a trusted channel to detect a server-substituted key.
  async function safetyNumber(remoteUserId, opts) {
    const localId = (opts && opts.localId) || selfUserId;
    const remoteId = (opts && opts.remoteId) || remoteUserId;
    const idKeyPair = await getIdentityKeyPair();
    const remoteIdentity = await identity.getIdentity(addr(remoteUserId));
    if (remoteIdentity == null) {
      throw new Error('signal-e2ee: no remote identity yet; establish a session first');
    }
    const fp = Fingerprint.new(
      SAFETY_NUMBER_ITERATIONS,
      SAFETY_NUMBER_VERSION,
      utf8(String(localId)),
      idKeyPair.publicKey,
      utf8(String(remoteId)),
      remoteIdentity
    );
    return fp.displayableFingerprint().toString();
  }

  return {
    domain,
    init,
    getLocalRegistrationId: () => identity.getLocalRegistrationId(),
    buildPublishableBundle,
    generateSignedPreKey,
    generateKyberPreKey,
    generateOneTimePreKeys,
    processPeerBundle,
    hasSession,
    encrypt,
    decrypt,
    safetyNumber,
  };
}

module.exports = { createSignalE2EE };
