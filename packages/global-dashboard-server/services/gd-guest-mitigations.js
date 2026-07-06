// FIREALIVE GD -- Guest-side CPU side-channel mitigation gate (B6c PR-5, verbatim twin)
//
// In Cloud Mode, the GD server's confidential VM shares physical CPU hardware with
// other tenants. Confidential computing (AMD SEV-SNP / Intel TDX) encrypts and
// integrity-protects guest memory, so a co-tenant or the host cannot read or
// tamper with RAM -- but micro-architectural side channels (cache timing,
// speculative execution leakage) are closed by the guest kernel plus CPU
// microcode, not by the confidential-VM boundary. This module reads the kernel's
// per-vulnerability status from /sys/devices/system/cpu/vulnerabilities/ and
// fails closed when an in-scope cross-tenant side-channel family is reported
// Vulnerable (unmitigated). It is the guest-side complement to the remote
// attestation TCB-version floor (which checks firmware currency from the signed
// report); this checks that the running kernel has the corresponding mitigations
// actually enabled.
//
// An operator may mark a specific family not-applicable on a given CPU via
// opts.overrides; overrides are surfaced in the result so the caller can audit
// them. A family whose status file is absent or unrecognized is reported as
// unknown -- by default unknown does not fail the gate (a confidential-VM-capable
// kernel is recent enough to report every in-scope family, so absent normally
// means the kernel predates that entry, not that the CPU is unmitigated), but
// opts.strictUnknown promotes unknown to a fail-closed condition for the most
// conservative deployments. A definite Vulnerable always fails the gate.
//
// The filesystem reader is injectable so the gate is unit-tested with fixtures
// (no real sysfs in CI). ASCII only; no template literals.

const fs = require('fs');

const VULN_DIR = '/sys/devices/system/cpu/vulnerabilities';

// Cross-VM / cross-tenant side-channel families relevant to co-tenancy. Each is
// a file under VULN_DIR whose contents the kernel sets to one of:
//   "Not affected"          -- CPU is not susceptible
//   "Mitigation: <how>"     -- susceptible but mitigated
//   "Vulnerable[: <why>]"   -- susceptible and NOT mitigated  (fail-closed)
const IN_SCOPE = [
  'spectre_v2',
  'mds',
  'l1tf',
  'retbleed',
  'gather_data_sampling',
  'spec_rstack_overflow',
  'mmio_stale_data',
];

function defaultReader() {
  return {
    // Returns the file contents trimmed, or null if absent / unreadable.
    read: function (p) {
      try { return fs.readFileSync(p, 'utf8').trim(); } catch (e) { return null; }
    },
  };
}

// Classify a single kernel status string into 'ok' (not affected or mitigated),
// 'vulnerable' (susceptible and unmitigated), or 'unknown' (absent / unrecognized).
function classify(status) {
  if (status == null) return 'unknown';
  const s = String(status).toLowerCase();
  if (s.indexOf('not affected') === 0) return 'ok';
  if (s.indexOf('mitigation') === 0) return 'ok';
  if (s.indexOf('vulnerable') === 0) return 'vulnerable';
  return 'unknown';
}

// Evaluate the in-scope families.
//   opts.reader        injectable filesystem reader (testing / fixtures)
//   opts.dir           override VULN_DIR (testing)
//   opts.overrides     array of family names the operator marks not-applicable
//   opts.strictUnknown when true, an unknown family also fails the gate
//
// Returns { ok, vulnerable, unknown, overridden, details }. ok is false
// (fail-closed) when any non-overridden in-scope family is Vulnerable, or
// (with strictUnknown) when any is unknown.
function evaluateMitigations(opts) {
  const options = opts || {};
  const reader = options.reader || defaultReader();
  const dir = options.dir || VULN_DIR;
  const strictUnknown = options.strictUnknown === true;

  const overrideSet = {};
  const ov = options.overrides || [];
  for (let i = 0; i < ov.length; i += 1) overrideSet[ov[i]] = true;

  const vulnerable = [];
  const unknown = [];
  const overridden = [];
  const details = {};

  for (let j = 0; j < IN_SCOPE.length; j += 1) {
    const fam = IN_SCOPE[j];
    const status = reader.read(dir + '/' + fam);
    const cls = classify(status);
    details[fam] = { status: status, classification: cls };
    if (overrideSet[fam]) { overridden.push(fam); continue; }
    if (cls === 'vulnerable') vulnerable.push(fam);
    else if (cls === 'unknown') unknown.push(fam);
  }

  const ok = vulnerable.length === 0 && (!strictUnknown || unknown.length === 0);
  return {
    ok: ok,
    vulnerable: vulnerable,
    unknown: unknown,
    overridden: overridden,
    details: details,
  };
}

// Build a short, log-friendly reason string from an evaluation result. Used by
// the boot gate when refusing or recording the mitigation posture.
function summarize(result) {
  if (result.ok && result.vulnerable.length === 0 && result.unknown.length === 0) {
    return 'all in-scope cross-tenant side-channel families mitigated or not-affected';
  }
  const parts = [];
  if (result.vulnerable.length > 0) parts.push('vulnerable: ' + result.vulnerable.join(', '));
  if (result.unknown.length > 0) parts.push('unknown: ' + result.unknown.join(', '));
  if (result.overridden.length > 0) parts.push('overridden: ' + result.overridden.join(', '));
  return parts.join('; ');
}

module.exports = {
  evaluateMitigations,
  classify,
  summarize,
  IN_SCOPE,
  VULN_DIR,
};
