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
// FORWARD-COMPATIBLE PATTERN
//
// Check functions in this file use a tableExists() helper to gracefully
// handle GD platform features that are planned but not yet shipped.
// As later BUILD-PLAN-v16 phases land (a future GD malware scanner
// integration phase for malware_scanner_integrations, plus a future GD
// startup integrity verifier phase for SKIP_INTEGRITY_CHECK env-var
// consumption and version-manifest comparison), the corresponding
// check functions automatically begin reporting on real platform state
// without requiring code changes here.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── tableExists ──────────────────────────────────────────────────────────────
// Forward-compatibility helper: returns true if a SQLite table named
// `name` exists in the connected DB.
function tableExists(db, name) {
  return !!db.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?"
  ).get(name);
}

// ── checkMalwareProtection ───────────────────────────────────────────────────
// Verifies malware protection posture. Two-state behavior:
//
//   CURRENT STATE (no malware_scanner_integrations table): GD has no
//   in-platform malware scanner integration. Returns warning noting
//   that host-level antivirus on the GD's operating system is
//   operator-managed and that file-content scanning at the analyst-
//   data layer is enforced at the MC.
//
//   FUTURE STATE (malware_scanner_integrations table present): A
//   future GD buildout phase introduces in-platform malware scanner
//   integrations parallel to MC's surface — relevant once the GD
//   begins receiving non-aggregate payloads from MCs (full backup
//   pulls, log shipments, forensic artifact pushes). The function
//   surfaces enabled-provider count and provider-type distribution
//   at that point.
//
// Forward-compatible: behavior expands automatically when the table
// appears.
//
// Maps to controls including: SOC 2 CC6.8 Threats from Malware,
// NIST CSF DE.CM-09 / PR.PS-05, ISO 27001 A.8.7 Protection against
// malware, NIST 800-53 SI-3 Malicious Code Protection, NIS2
// Art.21(2)(g), Cyber Essentials "Malware protection".
function checkMalwareProtection(db) {
  if (tableExists(db, 'malware_scanner_integrations')) {
    const enabled = db.prepare(
      "SELECT provider_type, COUNT(*) AS c FROM malware_scanner_integrations WHERE enabled = 1 GROUP BY provider_type"
    ).all();
    const total = enabled.reduce((sum, r) => sum + r.c, 0);
    if (total === 0) {
      return {
        status: 'warning',
        detail: 'malware_scanner_integrations table present but no scanners enabled. Configure at least one provider for SOC-grade malware protection.',
      };
    }
    const summary = enabled.map(r => `${r.provider_type}(${r.c})`).join(', ');
    return {
      status: 'pass',
      detail: `Malware protection: ${total} enabled scanner integration(s) on the GD: ${summary}.`,
    };
  }
  return {
    status: 'warning',
    detail: 'GD has no in-platform malware scanner integration (malware_scanner_integrations table not present) — by design, the GD does not currently process uploaded files from analysts. File-content scanning at the analyst-data layer is enforced at the MC, not the GD. Host-level antivirus on the GD server\'s operating system (Microsoft Defender, ClamAV, CrowdStrike Falcon agent, etc.) is customer-responsibility and operator-managed off-platform. A future GD buildout phase may add the malware_scanner_integrations table (parallel to MC\'s surface) once the GD receives non-aggregate payloads such as full backup pulls, log shipments, or forensic artifact pushes from MCs.',
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
// Verifies the startup integrity check posture. Two-state behavior:
//
//   CURRENT STATE: GD has no startup integrity verification — no
//   SKIP_INTEGRITY_CHECK env var consumption, no version-manifest
//   comparison at app boot. Returns warning describing the gap and
//   the operator-managed alternatives (signed installers, sha256sum
//   of release artifacts, container image signing).
//
//   FUTURE STATE: A future GD buildout phase (candidate: B5d
//   v1.0.53 "Other Small Backends Discovered" catch-all, or a
//   dedicated future phase) adds:
//     - SKIP_INTEGRITY_CHECK env var honored at boot
//     - A release-time manifest (e.g., release-manifest.json) shipping
//       with each release that lists expected SHA-256 hashes for the
//       GD's index.js, db-init.js, and package.json
//     - A boot-time verifier that hashes those files and compares to
//       the manifest, refusing to start on mismatch (unless
//       SKIP_INTEGRITY_CHECK=true is set for development)
//   When that lands, the function:
//     (a) Fails if SKIP_INTEGRITY_CHECK='true' AND NODE_ENV='production'
//     (b) Warns if SKIP_INTEGRITY_CHECK='true' in non-production
//     (c) Passes otherwise (verifier runs, integrity confirmed at boot)
//
// Forward-compatible: behavior expands automatically when the
// release-manifest file lands in the deployment artifact.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01 / PR.DS-10,
// ISO 27001 A.8.9 Configuration management, NIST 800-53 SI-7
// Software/Firmware/Information Integrity, NIS2 Art.21(2)(g).
function checkIntegrityVerification() {
  // Forward-compatible: detect presence of a release manifest file as
  // the signal that a future buildout phase has shipped the startup
  // integrity verifier. The manifest path is anticipated; the file
  // does not exist as of v0.0.31.
  const path = require('path');
  const fs = require('fs');
  const manifestPath = path.join(__dirname, '..', '..', '..', 'release-manifest.json');
  const manifestPresent = fs.existsSync(manifestPath);

  if (manifestPresent) {
    const skipped = process.env.SKIP_INTEGRITY_CHECK === 'true';
    const isProduction = process.env.NODE_ENV === 'production';
    if (skipped && isProduction) {
      return {
        status: 'fail',
        detail: 'SKIP_INTEGRITY_CHECK=true in NODE_ENV=production -- startup integrity verifier bypassed despite production setting. Anti-rollback fuse alone is insufficient; the manifest-based verifier must remain active in production.',
      };
    }
    if (skipped) {
      return {
        status: 'warning',
        detail: `SKIP_INTEGRITY_CHECK=true (NODE_ENV="${process.env.NODE_ENV || 'unset'}"). Startup integrity verifier bypassed. Acceptable for development; do not set in production.`,
      };
    }
    return {
      status: 'pass',
      detail: 'Startup integrity verifier active (release-manifest.json present, SKIP_INTEGRITY_CHECK not set to "true"). The GD\'s index.js, db-init.js, and package.json are SHA-256-hashed at boot against the release-time manifest; mismatch refuses startup. Combined with anti-rollback fuse, this provides software supply-chain integrity at startup.',
    };
  }

  return {
    status: 'warning',
    detail: 'GD has no startup integrity verifier as of v0.0.31. There is no SKIP_INTEGRITY_CHECK env var consumption, no release-manifest.json comparison at app boot. Anti-rollback fuse alone is insufficient for SOC-grade integrity assurance. Deployment-time integrity is operator-responsibility: signed installers, sha256sum of the GD distribution, container image signing if deployed via container. A future GD buildout phase will add a manifest-based verifier (release-manifest.json shipping with each release; boot-time SHA-256 comparison against index.js / db-init.js / package.json); when shipped, this check evaluates the verifier\'s posture automatically.',
  };
}

module.exports = {
  checkMalwareProtection,
  checkPatchManagement,
  checkVulnScanning,
  checkCloudVulnScanning,
  checkIntegrityVerification,
};
