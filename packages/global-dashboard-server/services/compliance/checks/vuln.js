// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Check Functions: Vulnerability Mgmt
//
// R3g PR2 (v1.0.33): GD-side counterpart to MC PR1's checks/vuln.js.
// Both files export the same 5 function names so framework definitions
// reference these checks uniformly across MC and GD. Implementations
// differ because the GD has a substantially smaller vulnerability-
// management surface than the MC.
//
// Each function returns { status, detail } where status is one of
// 'pass' | 'warning' | 'fail'.
//
// PLATFORM STATE NOTES (GD-specific gaps relative to MC)
//
//   - GD has no malware_scanner_integrations table. The GD is a
//     CISO-tier aggregator; it does not process uploaded files from
//     analysts and has no per-file content-scanning surface. File-
//     content malware scanning at the analyst-data layer is enforced
//     at the MC, not the GD. checkMalwareProtection adapts accordingly.
//   - GD has no integration_config table. Cloud integrations
//     (cloud_aws / cloud_gcp / cloud_azure) do not exist on the GD;
//     cloud vuln scanning is operator-managed via cloud-native services.
//   - GD has no startup integrity verification. There is no
//     SKIP_INTEGRITY_CHECK env var consumption in the GD's index.js,
//     and no version-manifest comparison at app boot. The GD trusts
//     its codebase at startup; integrity is a deployment-time
//     concern (signed installers, hash verification of release
//     artifacts, container image signing) rather than a runtime check.
//     checkIntegrityVerification returns warning surfacing this honest
//     gap.
//   - GD HAS system_meta.fuse_counter (anti-rollback) but the value
//     seeded by db-init.js (currently '31') is stale relative to
//     package.json's reported version (1.0.32). checkPatchManagement
//     reports whatever value is in system_meta; the value-vs-version
//     consistency is a separate cleanup item, not a compliance gap.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkMalwareProtection ───────────────────────────────────────────────────
// Verifies malware protection posture on the GD. The GD has no
// malware_scanner_integrations table and no per-file content-
// scanning surface (no analyst uploads on the GD). File-content
// malware scanning at the analyst-data layer is enforced at the MC,
// not the GD. Host-level antivirus on the GD operating system is
// customer-responsibility.
//
// Maps to controls including: SOC 2 CC6.8 Threats from Malware,
// NIST CSF DE.CM-09 / PR.PS-05, ISO 27001 A.8.7 Protection against
// malware, NIST 800-53 SI-3 Malicious Code Protection, NIS2
// Art.21(2)(g), Cyber Essentials "Malware protection".
function checkMalwareProtection() {
  return {
    status: 'warning',
    detail: 'GD has no in-platform malware scanner integration (no malware_scanner_integrations table) — by design, the GD does not process uploaded files from analysts. File-content scanning at the analyst-data layer is enforced at the MC, not the GD. Host-level antivirus on the GD server\'s operating system (Microsoft Defender, ClamAV, CrowdStrike Falcon agent, etc.) is customer-responsibility and operator-managed off-platform.',
  };
}

// ── checkPatchManagement ─────────────────────────────────────────────────────
// Verifies the anti-rollback fuse counter is set in system_meta.
// Unlike the MC, the GD has no startup integrity verification or
// SKIP_INTEGRITY_CHECK env var to evaluate; the fuse alone is the
// GD's anti-rollback signal. Patch management beyond that (host OS
// patching, Node.js runtime updates, dependency patching) is
// operator-managed.
//
// Maps to controls including: SOC 2 CC8.1 Change Management,
// NIST CSF PR.PS-02 / PR.PS-03, ISO 27001 A.8.19 / A.8.32,
// NIST 800-53 SI-2 Flaw Remediation / SA-22 Unsupported System
// Components, Cyber Essentials "Security update management".
function checkPatchManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!fuse || !fuse.value) {
    return {
      status: 'fail',
      detail: 'fuse_counter not set in system_meta on the GD. Anti-rollback protection inactive.',
    };
  }
  const fuseInt = parseInt(fuse.value, 10);
  if (isNaN(fuseInt) || fuseInt < 1) {
    return {
      status: 'fail',
      detail: `fuse_counter on the GD has invalid value "${fuse.value}". Anti-rollback protection inactive.`,
    };
  }
  return {
    status: 'pass',
    detail: `Patch management: GD anti-rollback fuse at ${fuseInt}. AGPL-3.0 source transparency permits operator audit of all released versions. Host OS / Node.js runtime / dependency patching is operator-managed off-platform.`,
  };
}

// ── checkVulnScanning ────────────────────────────────────────────────────────
// Verifies vulnerability scanning posture. The GD has no in-platform
// vuln scan history (no scan-result table; no malware_scanner_
// integrations for proxy signal). Infrastructure vulnerability
// scanning (Nessus / Qualys / OpenVAS / Trivy / Snyk) against the
// GD's deployment environment, OS packages, and Node dependencies
// is operator-responsibility and enumerated in framework
// customerResponsibility lists.
//
// Maps to controls including: SOC 2 CC7.1 Monitoring, NIST CSF
// PR.PS-05 / RS.MA-02, ISO 27001 A.8.8 Management of technical
// vulnerabilities, NIST 800-53 RA-5, NIS2 Art.21(2)(g).
function checkVulnScanning() {
  return {
    status: 'warning',
    detail: 'GD has no in-platform vulnerability scan history (no scan-result table). Infrastructure vuln scanning (Nessus / Qualys / OpenVAS / Trivy / Snyk against the deployment environment, OS packages, and Node.js dependencies) is operator-responsibility. SOC-grade norm is at least quarterly external scans plus dependency vulnerability monitoring (Snyk / npm audit / Dependabot or equivalent) integrated into the deployment CI.',
  };
}

// ── checkCloudVulnScanning ───────────────────────────────────────────────────
// Verifies cloud vulnerability scanning posture. The GD has no
// integration_config table; cloud integrations (cloud_aws /
// cloud_gcp / cloud_azure) do not exist on the GD. Cloud vuln
// scanning is operator-responsibility via cloud-native services
// (AWS Inspector, Azure Defender for Cloud, GCP Security Command
// Center) or third-party tools. The C2 phase (in-platform cloud
// vuln scanning) is deferred per BUILD-PLAN-v16 and applies to the
// MC; GD-side cloud vuln scanning is not currently in any phase plan.
//
// Maps to controls including: SOC 2 CC7.1, NIST CSF PR.PS-05,
// ISO 27001 A.5.23 Information security for use of cloud services,
// NIST 800-53 RA-5, DORA Art.15.
function checkCloudVulnScanning() {
  return {
    status: 'pass',
    detail: 'Cloud vulnerability scanning is customer-responsibility (AWS Inspector / Azure Defender for Cloud / GCP Security Command Center / Wiz / Lacework). The GD has no integration_config table and no in-platform cloud vuln scanning; the GD\'s cloud posture is whatever cloud-native services the operator runs against the GD\'s underlying infrastructure (VMs, container hosts, managed databases).',
  };
}

// ── checkIntegrityVerification ───────────────────────────────────────────────
// Verifies the startup integrity check is active. The GD has no
// startup integrity verification of any kind (no SKIP_INTEGRITY_CHECK
// env var consumption, no version-manifest comparison at app boot).
// Integrity is a deployment-time concern (signed installers, hash
// verification of release artifacts, container image signing) rather
// than a runtime check. Honest gap.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01 / PR.DS-10,
// ISO 27001 A.8.9 Configuration management, NIST 800-53 SI-7
// Software/Firmware/Information Integrity, NIS2 Art.21(2)(g).
function checkIntegrityVerification() {
  return {
    status: 'warning',
    detail: 'GD has no startup integrity verification (no SKIP_INTEGRITY_CHECK env var consumption; no version-manifest comparison at app boot). Anti-rollback fuse alone is insufficient for SOC-grade integrity assurance. Deployment-time integrity is operator-responsibility: signed installers, hash verification of release artifacts (sha256sum of the GD distribution), container image signing if deployed via container. A future GD enhancement could add a startup verifier that hashes the GD\'s index.js + db-init.js + package.json against a release-time manifest and refuses to start on mismatch; currently not implemented.',
  };
}

module.exports = {
  checkMalwareProtection,
  checkPatchManagement,
  checkVulnScanning,
  checkCloudVulnScanning,
  checkIntegrityVerification,
};
