// FIREALIVE -- Confidential-computing detection and attestation (B5h Cloud Mode, C8)
//
// Cloud Mode requires the regional server to run inside a confidential VM:
// memory-in-use is encrypted and isolated from co-tenants and the cloud
// provider, which a plain vTPM does not provide. This module decides, at mode
// establishment and at every boot, whether the host is a genuine confidential
// guest, and it is fail-closed -- if no confidential-computing environment is
// detected, verification fails and Cloud Mode does not seal or serve.
//
// What this module does in-phase (real, runs on hardware):
//   - detectConfidentialComputing() inspects the guest attestation devices the
//     Linux kernel creates ONLY inside a genuine confidential guest
//     (/dev/sev-guest for AMD SEV-SNP, /dev/tdx_guest for Intel TDX,
//     /dev/nitro_enclaves for AWS Nitro Enclaves) and the kernel confidential-
//     computing sysfs directory (/sys/kernel/coco). The kernel sets these from
//     CPU state that a hypervisor cannot fabricate at the guest level, so their
//     presence is a real local confidential-computing signal.
//
// What is platform-validation-pending (a later hardening pass, like the TPM
// leaf ops):
//   - The full REMOTE attestation -- fetching a signed attestation report or
//     quote from the guest device and validating it against the AMD/Intel
//     certificate chain, or via the provider attestation service (Azure
//     Attestation, GCP Confidential Space, AWS Nitro attestation). That path
//     needs real hardware and a native/provider integration not added in this
//     phase. verifyAttestation() therefore returns platformValidationPending
//     true when a confidential guest is detected, and the genuine-report path
//     is validated on a real confidential VM at release.
//
// The filesystem probe is injectable so the detection logic is unit-tested with
// fixtures (no real devices in CI). ASCII only; no template literals.

const fs = require('fs');

const CC_SEV_SNP = 'sev-snp';
const CC_TDX = 'tdx';
const CC_NITRO = 'nitro';
const CC_NONE = null;

// Guest attestation devices created by the kernel inside a confidential guest.
const SEV_SNP_GUEST_DEVICES = ['/dev/sev-guest'];
const TDX_GUEST_DEVICES = ['/dev/tdx_guest', '/dev/tdx-guest'];
const NITRO_ENCLAVE_DEVICES = ['/dev/nitro_enclaves'];
const COCO_SYSFS = '/sys/kernel/coco';

function defaultProbe() {
  return {
    exists: function (p) {
      try { return fs.existsSync(p); } catch (e) { return false; }
    },
  };
}

function firstExisting(probe, paths) {
  for (let i = 0; i < paths.length; i += 1) {
    if (probe.exists(paths[i])) return paths[i];
  }
  return null;
}

// Returns { present, tech, source }. tech is CC_SEV_SNP / CC_TDX / CC_NITRO when
// a confidential guest device is found, else CC_NONE (null) with present false.
function detectConfidentialComputing(probe) {
  const p = probe || defaultProbe();
  const sev = firstExisting(p, SEV_SNP_GUEST_DEVICES);
  if (sev) return { present: true, tech: CC_SEV_SNP, source: sev };
  const tdx = firstExisting(p, TDX_GUEST_DEVICES);
  if (tdx) return { present: true, tech: CC_TDX, source: tdx };
  const nitro = firstExisting(p, NITRO_ENCLAVE_DEVICES);
  if (nitro) return { present: true, tech: CC_NITRO, source: nitro };
  return { present: false, tech: CC_NONE, source: null };
}

// Verify the host is a confidential VM. Fail-closed: verified is false with a
// reason when no confidential guest is detected. When one is detected, the local
// kernel signal is the in-phase gate (verified true) and the full remote
// attestation is platform-validation-pending. opts.probe injects a filesystem
// probe for testing.
function verifyAttestation(opts) {
  const options = opts || {};
  const probe = options.probe || defaultProbe();
  const cc = detectConfidentialComputing(probe);
  if (!cc.present) {
    return {
      verified: false,
      tech: CC_NONE,
      reason: 'no confidential-computing guest detected; Cloud Mode requires a confidential VM',
      platformValidationPending: false,
    };
  }
  const cocoPresent = probe.exists(COCO_SYSFS);
  let reason = 'confidential-computing guest detected (' + cc.tech + ' via ' + cc.source + ')';
  if (cocoPresent) reason = reason + '; kernel coco sysfs present';
  reason = reason + '; remote attestation platform-validation-pending';
  return {
    verified: true,
    tech: cc.tech,
    reason: reason,
    platformValidationPending: true,
  };
}

module.exports = {
  detectConfidentialComputing,
  verifyAttestation,
  CC_SEV_SNP,
  CC_TDX,
  CC_NITRO,
  CC_NONE,
};
