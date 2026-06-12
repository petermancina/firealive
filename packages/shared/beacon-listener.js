'use strict';

//
// FireAlive -- shared subnet beacon LISTENER (anti-cloning, client side).
//
// Listen-only counterpart to server/services/peer-beacon.js. Runs in an Electron
// main process (MC / AC / GD / ARC): it binds the beacon UDP port, verifies the
// Ed25519-signed beacons that FireAlive servers broadcast, and raises a detection
// when it observes a CLONED or FORKED server identity on the local subnet -- two
// distinct server identities for the same role live at once, or (when anchor
// pinning is supplied) a server whose identity is not the one this client trusts.
// It NEVER broadcasts and holds no identity of its own (clients have none to
// announce); SO_BROADCAST is a send-side option and is deliberately not set.
//
// The verify helpers below MUST stay byte-compatible with
// server/services/peer-beacon.js (VERSION, beaconSigningBytes field order, the
// fingerprint = SHA-256 of the SPKI DER, Ed25519 verify). A beacon that does not
// verify is ignored, so a random host cannot forge one to provoke a false alarm.
//
// A genuine re-key (migration re-mints the server identity) REPLACES the old
// identity, which then stops broadcasting and ages out of the recent window; a
// CLONE broadcasts concurrently with the authentic server, so two distinct
// identities are live in the window at once -- that concurrency is the signal.

const crypto = require('crypto');

const VERSION = 1;
const DEFAULT_PORT = 47100;
// Two distinct identities must be seen within this window to count as concurrent.
// Three beacon intervals (server default 30s) so a single missed beacon does not
// prematurely age an identity out.
const DEFAULT_WINDOW_MS = 90000;

function computeFingerprint(publicKeyPem) {
  const der = crypto.createPublicKey(publicKeyPem).export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex');
}

// MUST match server/services/peer-beacon.js exactly.
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

// Verify a received server beacon: structure, fingerprint-matches-public-key,
// signature. MUST match server/services/peer-beacon.js.
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

// Record a verified beacon into state and classify it.
//   ignored   a role we are not watching
//   foreign   pinned mode: a fingerprint other than the trusted (pinned) one
//   conflict  unpinned mode: >= 2 distinct server identities for this role live in the window
//   ok        the trusted pinned identity, or the only live identity for this role
// state is a Map of fingerprint -> { fingerprint, role, firstSeen, lastSeen, addresses }.
function classifyObservation(state, beacon, fromAddr, opts) {
  opts = opts || {};
  const now = (opts.now != null) ? opts.now : Date.now();
  const windowMs = (opts.windowMs != null) ? opts.windowMs : DEFAULT_WINDOW_MS;
  const expectedRole = opts.expectedRole || null;
  const pinnedFingerprint = opts.pinnedFingerprint || null;

  if (expectedRole && beacon.role !== expectedRole) {
    return { verdict: 'ignored', reason: 'other role' };
  }

  let rec = state.get(beacon.fingerprint);
  if (!rec) {
    rec = { fingerprint: beacon.fingerprint, role: beacon.role, firstSeen: now, lastSeen: now, addresses: [] };
    state.set(beacon.fingerprint, rec);
  }
  rec.lastSeen = now;
  if (fromAddr && rec.addresses.indexOf(fromAddr) === -1) {
    rec.addresses.push(fromAddr);
  }

  if (pinnedFingerprint) {
    // Pinned mode: exactly one identity is trusted. The pinned fingerprint is
    // always ok; anything else is foreign. (The concurrent-conflict check below
    // is the unpinned fallback used before anchor pinning lands.)
    if (beacon.fingerprint !== pinnedFingerprint) {
      return {
        verdict: 'foreign',
        role: beacon.role,
        fingerprint: beacon.fingerprint,
        from: fromAddr || null,
        pinnedFingerprint: pinnedFingerprint,
      };
    }
    return { verdict: 'ok', role: beacon.role, fingerprint: beacon.fingerprint };
  }

  const live = [];
  state.forEach(function (r) {
    if (expectedRole && r.role !== expectedRole) {
      return;
    }
    if (now - r.lastSeen <= windowMs) {
      live.push(r.fingerprint);
    }
  });
  if (live.length >= 2) {
    const others = live.filter(function (fp) { return fp !== beacon.fingerprint; });
    return {
      verdict: 'conflict',
      role: beacon.role,
      fingerprint: beacon.fingerprint,
      from: fromAddr || null,
      otherFingerprints: others,
    };
  }

  return { verdict: 'ok', role: beacon.role, fingerprint: beacon.fingerprint };
}

// Begin listening. opts: { port, expectedRole, pinnedFingerprint, windowMs,
// onDetection, logger }. Returns { state, stop() }. Best-effort: socket errors
// are logged (if a logger is given), never thrown.
function start(opts) {
  opts = opts || {};
  const dgram = require('dgram');
  const port = opts.port || DEFAULT_PORT;
  const onDetection = typeof opts.onDetection === 'function' ? opts.onDetection : function () {};
  const log = opts.logger || null;
  const state = new Map();

  const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });

  socket.on('error', function (err) {
    if (log && log.warn) {
      log.warn('beacon-listener socket error', { error: err && err.message ? err.message : String(err) });
    }
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
    const fromAddr = rinfo ? rinfo.address : null;
    const verdict = classifyObservation(state, beacon, fromAddr, {
      expectedRole: opts.expectedRole || null,
      pinnedFingerprint: opts.pinnedFingerprint || null,
      windowMs: opts.windowMs,
    });
    if (verdict.verdict === 'conflict' || verdict.verdict === 'foreign') {
      try {
        onDetection(verdict);
      } catch (cbErr) {
        if (log && log.warn) {
          log.warn('beacon-listener onDetection failed', { error: cbErr.message });
        }
      }
    }
  });

  // Listen-only: bind to receive subnet broadcasts; never send, never setBroadcast.
  socket.bind(port);

  return {
    state: state,
    stop: function () {
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
  DEFAULT_WINDOW_MS,
  computeFingerprint,
  beaconSigningBytes,
  verifyBeacon,
  classifyObservation,
  start,
};
