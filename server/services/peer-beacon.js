// ─────────────────────────────────────────────────────────────────────────────
// FIREALIVE ── Subnet Peer-Beacon (Anti-Cloning)
// Copyright (C) 2026 Peter Mancina
// SPDX-License-Identifier: AGPL-3.0-or-later
// ─────────────────────────────────────────────────────────────────────────────
//
// Signed subnet peer-beacon (B5e, Block C, decision D4). Every node periodically
// broadcasts an Ed25519-signed identity beacon on the local subnet and listens
// for others. Seeing our OWN fingerprint coming from another host means a clone
// of this deployment is running on the same network; seeing our instanceId with
// a DIFFERENT fingerprint means the identity has forked. Either way the listener
// hands the detection to the caller-supplied onDetection callback (the wiring
// quarantines and raises the loud alert).
//
// The beacon is SIGNED so a receiver acts only on authentic beacons -- a random
// host on the subnet cannot forge one to provoke a false quarantine. A genuine
// clone holds the same key and CAN sign valid beacons, which is exactly what we
// want to detect: a valid beacon for our identity from an address that is not
// ours. Verifying other nodes' beacons is plain Ed25519 verification with the
// public key carried in the beacon; signing our own goes through the anchor so
// the vTPM path (Block D) signs via the TPM with no change here.

const crypto = require('crypto');
const os = require('os');
const { logger } = require('./logger');

const VERSION = 1;
const DEFAULT_PORT = 47100;
const DEFAULT_BROADCAST = '255.255.255.255';
const DEFAULT_INTERVAL_MS = 30000;
const DEFAULT_ROLE = 'regional-server';

function computeFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// The exact bytes that are signed and verified -- every field except the sig, in
// a fixed key order so signer and verifier agree byte-for-byte.
function beaconSigningBytes(b) {
  return Buffer.from(JSON.stringify({
    v: b.v,
    role: b.role,
    instanceId: b.instanceId,
    fingerprint: b.fingerprint,
    ts: b.ts,
    nonce: b.nonce,
  }));
}

// Build a signed beacon for this instance, or null if no identity is established
// (nothing to sign with yet).
function buildBeacon(db, opts) {
  opts = opts || {};
  const anchor = require('./instance-anchor');
  const identity = anchor.load({ db: db });
  if (!identity) {
    return null;
  }
  const beacon = {
    v: VERSION,
    role: opts.role || DEFAULT_ROLE,
    instanceId: identity.instanceId,
    publicKey: identity.publicKey,
    fingerprint: identity.fingerprint,
    ts: Date.now(),
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const sig = anchor.sign({ db: db, identity: identity, data: beaconSigningBytes(beacon) });
  if (!sig) {
    return null;
  }
  beacon.sig = Buffer.from(sig).toString('base64');
  return beacon;
}

// Verify a received beacon: structure, fingerprint-matches-public-key, signature.
function verifyBeacon(beacon) {
  try {
    if (!beacon || typeof beacon !== 'object') {
      return { valid: false, reason: 'not an object' };
    }
    if (beacon.v !== VERSION) {
      return { valid: false, reason: 'version mismatch' };
    }
    const required = ['role', 'instanceId', 'publicKey', 'fingerprint', 'nonce', 'sig'];
    for (let i = 0; i < required.length; i++) {
      const k = required[i];
      if (typeof beacon[k] !== 'string' || !beacon[k]) {
        return { valid: false, reason: 'missing field ' + k };
      }
    }
    if (computeFingerprint(beacon.publicKey) !== beacon.fingerprint) {
      return { valid: false, reason: 'fingerprint does not match public key' };
    }
    const pub = crypto.createPublicKey(beacon.publicKey);
    const sig = Buffer.from(beacon.sig, 'base64');
    if (!crypto.verify(null, beaconSigningBytes(beacon), pub, sig)) {
      return { valid: false, reason: 'bad signature' };
    }
    return { valid: true, instanceId: beacon.instanceId, fingerprint: beacon.fingerprint };
  } catch (err) {
    return { valid: false, reason: err && err.message ? err.message : String(err) };
  }
}

// Classify a verified beacon relative to our own identity.
//   self   our identity arriving from one of our own addresses (broadcast echo)
//   clone  our fingerprint from another host -- a copy on the subnet
//   fork   our instanceId but a different fingerprint -- identity diverged
//   ok     a different, legitimate node
function classifyBeacon(self, beacon, fromAddress) {
  if (!self || !self.fingerprint) {
    return { verdict: 'ok' };
  }
  if (beacon.fingerprint === self.fingerprint) {
    const local = self.localAddresses || [];
    if (fromAddress && local.indexOf(fromAddress) !== -1) {
      return { verdict: 'self' };
    }
    return { verdict: 'clone', fingerprint: beacon.fingerprint, instanceId: beacon.instanceId, from: fromAddress || null };
  }
  if (self.instanceId && beacon.instanceId === self.instanceId) {
    return { verdict: 'fork', fingerprint: beacon.fingerprint, instanceId: beacon.instanceId, from: fromAddress || null };
  }
  return { verdict: 'ok' };
}

// Our own identity plus the list of local IP addresses (so we can recognize our
// own broadcast echo and not report ourselves as a clone).
function loadSelf(db) {
  let identity = null;
  try {
    const anchor = require('./instance-anchor');
    identity = anchor.load({ db: db });
  } catch (err) {
    identity = null;
  }
  const localAddresses = [];
  try {
    const ifaces = os.networkInterfaces();
    const names = Object.keys(ifaces);
    for (let i = 0; i < names.length; i++) {
      const list = ifaces[names[i]] || [];
      for (let j = 0; j < list.length; j++) {
        if (list[j] && list[j].address) {
          localAddresses.push(list[j].address);
        }
      }
    }
  } catch (err) {
    // best effort
  }
  return {
    instanceId: identity ? identity.instanceId : null,
    fingerprint: identity ? identity.fingerprint : null,
    localAddresses: localAddresses,
  };
}

// Start broadcasting and listening. opts: { port, broadcastAddress, intervalMs,
// role, onDetection }. Returns a handle with stop(). Best-effort: socket errors
// are logged, never thrown, so the beacon can never take the process down.
function start(db, opts) {
  opts = opts || {};
  const dgram = require('dgram');
  const port = opts.port || DEFAULT_PORT;
  const broadcastAddress = opts.broadcastAddress || DEFAULT_BROADCAST;
  const intervalMs = opts.intervalMs || DEFAULT_INTERVAL_MS;
  const role = opts.role || DEFAULT_ROLE;
  const onDetection = typeof opts.onDetection === 'function' ? opts.onDetection : function () {};

  const self = loadSelf(db);
  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

  socket.on('error', function (err) {
    logger.warn('peer-beacon socket error', { error: err && err.message ? err.message : String(err) });
  });

  socket.on('message', function (data, rinfo) {
    let beacon;
    try {
      beacon = JSON.parse(data.toString('utf8'));
    } catch (err) {
      return;
    }
    const checked = verifyBeacon(beacon);
    if (!checked.valid) {
      return;
    }
    const verdict = classifyBeacon(self, beacon, rinfo ? rinfo.address : null);
    if (verdict.verdict === 'clone' || verdict.verdict === 'fork') {
      try {
        onDetection(verdict);
      } catch (cbErr) {
        logger.warn('peer-beacon onDetection callback failed', { error: cbErr.message });
      }
    }
  });

  socket.bind(port, function () {
    try {
      socket.setBroadcast(true);
    } catch (err) {
      // not all platforms allow broadcast; the listener still works
    }
  });

  const send = function () {
    try {
      const beacon = buildBeacon(db, { role: role });
      if (!beacon) {
        return;
      }
      const buf = Buffer.from(JSON.stringify(beacon));
      socket.send(buf, 0, buf.length, port, broadcastAddress);
    } catch (err) {
      logger.warn('peer-beacon send failed', { error: err && err.message ? err.message : String(err) });
    }
  };

  const timer = setInterval(send, intervalMs);
  if (timer.unref) {
    timer.unref();
  }
  send();

  return {
    stop: function () {
      clearInterval(timer);
      try {
        socket.close();
      } catch (err) {
        // already closed
      }
    },
  };
}

module.exports = {
  VERSION,
  DEFAULT_PORT,
  computeFingerprint,
  beaconSigningBytes,
  buildBeacon,
  verifyBeacon,
  classifyBeacon,
  loadSelf,
  start,
};
