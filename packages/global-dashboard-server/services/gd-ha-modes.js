// FIREALIVE GLOBAL DASHBOARD -- HA per-mode tailoring (B6d)
//
// The GD twin of server/services/ha/ha-modes.js. HA composes with the deployment
// mode without weakening that mode's trust boundary. This module is the single
// seam the pairing flow consults so the mode-specific rules live in one place:
//
//   assertModePairingAllowed(db, peerAssertedAttestation)
//     - bare-metal / virtualized: no extra gate. Device-key binding over the
//       host TPM / vTPM is already enforced by the pairing handshake.
//     - cloud: BOTH peers must be attested confidential VMs. The local host is
//       re-verified from its kernel (gd-cloud-attestation.verifyAttestation) and
//       the peer's asserted report is verified against the bundled roots
//       (gd-cloud-attestation.verifyPeerAttestation). A non-confidential local
//       node, or a peer that cannot prove a current confidential guest (a spot /
//       autoscaled / ephemeral box included), is refused. Throws on refusal.
//     - sdn / sase: no extra attestation gate here; segment admission is handled
//       by registerHaSegments below (sdn) or the operator connector-source
//       allow-list (sase -- see note on registerHaSegments).
//
//   registerHaSegments(db)
//     - sdn: register the paired peer's endpoint as a FireAlive-managed permitted
//       segment so the SDN admission gate (gd-sdn-admission) admits the active<->
//       passive east-west link. The org's existing client segments already cover
//       traffic arriving via their load balancer. No-op in other modes.
//     - sase: no auto-registration -- gd-sase-admission has no system-segment
//       mechanism; its dark-app boundary is an operator-declared connector-source
//       allow-list, so the operator must add the HA peer's source there (documented
//       in the operator runbook). Returns { registered: false } like other modes.
//
// Pure orchestration over the injected db handle; the attestation and segment-
// admission mechanics live in gd-cloud-attestation and gd-sdn-admission. ASCII
// only; no template literals. All requires are services/ siblings.

const mode = require('./gd-deployment-mode');
const cloudAttestation = require('./gd-cloud-attestation');
const sdnAdmission = require('./gd-sdn-admission');

const CLOUD = 'cloud';
const SDN = 'sdn';

// Extract the host (IP or hostname) from a peer endpoint, accepting a full URL
// (https://host:port), a host:port pair, or a bare host.
function hostOf(endpoint) {
  const s = String(endpoint || '').trim();
  if (!s) {
    return null;
  }
  try {
    const u = new URL(s);
    if (u.hostname) {
      return u.hostname;
    }
  } catch (e) {
    // not a full URL; fall through to host:port parsing
  }
  const noScheme = s.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  const hostPort = noScheme.split('/')[0];
  const host = hostPort.split(':')[0];
  return host || null;
}

function assertModePairingAllowed(db, peerAssertedAttestation) {
  const m = mode.getMode(db);
  if (m !== CLOUD) {
    return { allowed: true, mode: m };
  }

  // Local node must be a verified, current confidential VM.
  const localR = cloudAttestation.verifyAttestation({});
  if (!localR || localR.verified !== true) {
    const reason = (localR && localR.reason) ? localR.reason : 'attestation unavailable';
    throw new Error('gd-ha-modes: local node is not a verified confidential VM in Cloud Mode; cannot pair (' + reason + ')');
  }

  // Peer must present a valid attestation for a current confidential guest.
  const peerR = cloudAttestation.verifyPeerAttestation(peerAssertedAttestation || {}, { now: Date.now() });
  if (!peerR || peerR.verified !== true) {
    const reason = (peerR && peerR.reason) ? peerR.reason : 'no peer attestation presented';
    throw new Error('gd-ha-modes: HA peer is not an attested confidential VM; refusing to pair (' + reason + ')');
  }

  return { allowed: true, mode: m, localTech: localR.tech, peerTech: peerR.tech };
}

function registerHaSegments(db) {
  const m = mode.getMode(db);
  if (m !== SDN) {
    return { registered: false, mode: m };
  }
  const peer = db.prepare("SELECT peer_endpoint FROM gd_ha_peer WHERE status = 'paired' LIMIT 1").get();
  if (!peer || !peer.peer_endpoint) {
    return { registered: false, mode: m, reason: 'no paired peer' };
  }
  const host = hostOf(peer.peer_endpoint);
  if (!host) {
    return { registered: false, mode: m, reason: 'peer endpoint has no host' };
  }
  sdnAdmission.registerSystemSegment(db, host, 'ha-peer');
  return { registered: true, mode: m, segment: host };
}

module.exports = {
  hostOf,
  assertModePairingAllowed,
  registerHaSegments,
};
