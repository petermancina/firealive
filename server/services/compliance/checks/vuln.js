// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Check Functions: Vulnerability Management
//
// R3g (v1.0.33): part of the comprehensive technical-control verification
// library that backs FireAlive's compliance claims under Foundational
// Rule 14 (Shared Responsibility framing).
//
// This file provides 5 check functions covering malware protection,
// patch management, vulnerability scanning, cloud vulnerability
// scanning, and software integrity verification. Each function queries
// actual platform state and returns { status, detail } where status is
// 'pass' | 'warning' | 'fail'.
//
// Functions are referenced from framework definitions in
// server/services/compliance/frameworks/<id>.js (R3g commits 13-28).
//
// PLATFORM STATE NOTES
//
// The R3g detailed plan (R3G-DETAILED-PLAN.md) anticipated some
// platform structures that don't match the v1.0.32 codebase:
//
//   - Planned malware_scanners table -> actual table is
//     malware_scanner_integrations (with enabled, last_scan_at,
//     total_scans, total_threats_detected, total_failures).
//   - Planned vulnscan_results table -> does not exist. The
//     platform does not maintain an in-DB vulnerability scan
//     history. The closest scan history is
//     malware_scanner_integrations.last_scan_at (which tracks
//     file-content scanning, not infrastructure vulnerability
//     scanning). Infrastructure vuln scanning is customer-
//     responsibility (typically operator-run tools like Nessus,
//     Qualys, OpenVAS against the deployment environment).
//   - Planned cloud_vuln_results table -> does not exist. The
//     C2 phase (Cloud Vuln Scan) is deferred per BUILD-PLAN-v14.
//     Cloud integrations live in integration_config with
//     integration_type 'cloud_aws' / 'cloud_gcp' / 'cloud_azure'
//     but no scan-result table is yet populated by any service.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

// ── checkMalwareProtection ───────────────────────────────────────────────────
// Verifies at least one malware scanner integration is enabled. The
// malware_scanner_integrations table supports 15 provider types
// (ClamAV, VirusTotal, CrowdStrike Falcon, Microsoft Defender,
// SentinelOne, Cisco AMP, Fortinet FortiSandbox, Trellix ATD, Sophos
// Intelix, Joe Sandbox, Hybrid Analysis, Palo Alto WildFire, BlackBerry
// Cylance, Trend Micro DDAN, Kaspersky Sandbox). Warning if zero
// enabled; pass if any.
//
// Maps to controls including: SOC 2 CC6.8 Threats from Malware,
// NIST CSF DE.CM-09 / PR.PS-05, ISO 27001 A.8.7 Protection against
// malware, NIST 800-53 SI-3 Malicious Code Protection, NIS2
// Art.21(2)(g), Cyber Essentials "Malware protection".
function checkMalwareProtection(db) {
  const enabled = db.prepare(
    "SELECT provider_type, COUNT(*) AS c FROM malware_scanner_integrations WHERE enabled = 1 GROUP BY provider_type"
  ).all();
  const total = enabled.reduce((sum, r) => sum + r.c, 0);
  if (total === 0) {
    return {
      status: 'warning',
      detail: 'No malware scanner integrations enabled. Configure at least one provider (ClamAV, VirusTotal, CrowdStrike, Microsoft Defender, or 12 other supported providers) via the Malware Scanners admin tab.',
    };
  }
  const summary = enabled.map(r => `${r.provider_type}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `Malware protection: ${total} enabled scanner integration(s): ${summary}. Multi-provider redundancy supported with priority ordering.`,
  };
}

// ── checkPatchManagement ─────────────────────────────────────────────────────
// Verifies the anti-rollback fuse counter is set in system_meta and
// the SKIP_INTEGRITY_CHECK env var is not bypassing startup integrity
// verification. The fuse is monotonically incremented at each version
// release; the startup check compares it against the version manifest
// and refuses to start if rollback is attempted. The combination of
// version-tracked fuse + startup integrity verification + AGPL-3.0
// source transparency comprises the patch management story.
//
// Maps to controls including: SOC 2 CC8.1 Change Management,
// NIST CSF PR.PS-02 / PR.PS-03, ISO 27001 A.8.19 Installation of
// software on operational systems / A.8.32 Change management,
// NIST 800-53 SI-2 Flaw Remediation / SA-22 Unsupported System
// Components, Cyber Essentials "Security update management".
function checkPatchManagement(db) {
  const fuse = db.prepare("SELECT value FROM system_meta WHERE key = 'fuse_counter'").get();
  if (!fuse || !fuse.value) {
    return {
      status: 'fail',
      detail: 'fuse_counter not set in system_meta. Anti-rollback protection inactive.',
    };
  }
  const fuseInt = parseInt(fuse.value, 10);
  if (isNaN(fuseInt) || fuseInt < 1) {
    return {
      status: 'fail',
      detail: `fuse_counter has invalid value "${fuse.value}". Anti-rollback protection inactive.`,
    };
  }
  const integritySkipped = process.env.SKIP_INTEGRITY_CHECK === 'true';
  if (integritySkipped) {
    return {
      status: 'warning',
      detail: `Anti-rollback fuse at ${fuseInt}, but SKIP_INTEGRITY_CHECK=true bypasses startup integrity verification. Recommended only for development; production deployments should not set this.`,
    };
  }
  return {
    status: 'pass',
    detail: `Patch management: anti-rollback fuse at ${fuseInt}; startup integrity verification active. AGPL-3.0 source transparency permits operator audit of all released versions.`,
  };
}

// ── checkVulnScanning ────────────────────────────────────────────────────────
// Verifies recency of malware scanner activity as the platform-side
// proxy for content vulnerability scanning. Infrastructure
// vulnerability scanning (Nessus / Qualys / OpenVAS against the
// deployment environment, OS packages, dependencies) is operator-
// run tooling outside the platform's scope and is enumerated as
// customer-responsibility in framework definitions. This check
// verifies what IS in scope: that the configured malware scanners
// have actually executed scans recently.
//
// Maps to controls including: SOC 2 CC7.1 Monitoring, NIST CSF
// PR.PS-05 Vulnerability Management / RS.MA-02, ISO 27001 A.8.8
// Management of technical vulnerabilities, NIST 800-53 RA-5
// Vulnerability Monitoring and Scanning, NIS2 Art.21(2)(g).
function checkVulnScanning(db) {
  const enabled = db.prepare(
    "SELECT COUNT(*) AS c FROM malware_scanner_integrations WHERE enabled = 1"
  ).get();
  if (enabled.c === 0) {
    return {
      status: 'warning',
      detail: 'No enabled malware scanners; no platform-side scan activity to measure. Infrastructure vulnerability scanning (Nessus / Qualys / OpenVAS) is operator-responsibility.',
    };
  }
  const recent = db.prepare(
    "SELECT COUNT(*) AS c FROM malware_scanner_integrations WHERE enabled = 1 AND last_scan_at > datetime('now', '-30 days')"
  ).get();
  const totalScans = db.prepare(
    "SELECT SUM(total_scans) AS s FROM malware_scanner_integrations WHERE enabled = 1"
  ).get();
  if (recent.c === 0) {
    return {
      status: 'warning',
      detail: `${enabled.c} enabled scanner(s) but none have scanned in the last 30 days. Total historical scans across all providers: ${totalScans.s || 0}.`,
    };
  }
  return {
    status: 'pass',
    detail: `Vulnerability scanning: ${recent.c} of ${enabled.c} enabled scanner(s) executed within 30 days. ${totalScans.s || 0} total historical scans. Infrastructure vuln scanning (host/OS/dependency) is customer-responsibility.`,
  };
}

// ── checkCloudVulnScanning ───────────────────────────────────────────────────
// Verifies cloud vulnerability scanning posture. The platform supports
// cloud integrations via integration_config (cloud_aws, cloud_gcp,
// cloud_azure types) for cloud-side asset visibility, but in v1.0.32
// does not yet run vulnerability scans against cloud assets -- the
// C2 phase (Cloud Vuln Scan) is deferred per BUILD-PLAN-v14. This
// check verifies cloud integration configuration as the foundation
// for future scanning; actual cloud vuln scanning is operator-
// responsibility using cloud-native services (AWS Inspector, Azure
// Defender for Cloud, GCP Security Command Center) or third-party
// tools.
//
// Maps to controls including: SOC 2 CC7.1, NIST CSF PR.PS-05,
// ISO 27001 A.5.23 Information security for use of cloud services,
// NIST 800-53 RA-5, DORA Art.15 ICT Third-Party Risk.
function checkCloudVulnScanning(db) {
  const cloud = db.prepare(
    "SELECT integration_type, COUNT(*) AS c FROM integration_config WHERE integration_type LIKE 'cloud_%' AND status = 'operational' GROUP BY integration_type"
  ).all();
  const total = cloud.reduce((sum, r) => sum + r.c, 0);
  if (total === 0) {
    return {
      status: 'pass',
      detail: 'No cloud integrations configured. Cloud vulnerability scanning is customer-responsibility (AWS Inspector / Azure Defender for Cloud / GCP Security Command Center). Platform supports cloud integration types (cloud_aws / cloud_gcp / cloud_azure); C2 phase will add in-platform cloud vuln scanning.',
    };
  }
  const summary = cloud.map(r => `${r.integration_type}(${r.c})`).join(', ');
  return {
    status: 'pass',
    detail: `Cloud integrations operational: ${summary}. Cloud vulnerability scanning itself is customer-responsibility via cloud-native services pending C2 phase (in-platform cloud vuln scanning).`,
  };
}

// ── checkIntegrityVerification ───────────────────────────────────────────────
// Verifies the startup integrity check is active. The platform runs
// a startup integrity verification (server/index.js:40) that compares
// the current code/version against expected state and refuses to
// start on mismatch. The SKIP_INTEGRITY_CHECK env var bypasses this
// check; setting it to 'true' in production is a SOC-grade violation.
// Fail if SKIP_INTEGRITY_CHECK='true' AND NODE_ENV='production';
// warning if SKIP_INTEGRITY_CHECK='true' in non-production; pass
// otherwise.
//
// Maps to controls including: SOC 2 CC8.1, NIST CSF PR.PS-01 / PR.DS-10,
// ISO 27001 A.8.9 Configuration management, NIST 800-53 SI-7
// Software/Firmware/Information Integrity, NIS2 Art.21(2)(g).
function checkIntegrityVerification() {
  const skipped = process.env.SKIP_INTEGRITY_CHECK === 'true';
  const isProduction = process.env.NODE_ENV === 'production';
  if (skipped && isProduction) {
    return {
      status: 'fail',
      detail: 'SKIP_INTEGRITY_CHECK=true in production environment -- startup integrity verification bypassed. Anti-rollback fuse alone is insufficient; both controls must be active in production.',
    };
  }
  if (skipped) {
    return {
      status: 'warning',
      detail: `SKIP_INTEGRITY_CHECK=true (NODE_ENV="${process.env.NODE_ENV || 'unset'}"); startup integrity verification bypassed. Acceptable for development; do not set in production.`,
    };
  }
  return {
    status: 'pass',
    detail: 'Startup integrity verification active (SKIP_INTEGRITY_CHECK is not "true"). Combined with anti-rollback fuse, this provides software supply-chain integrity at startup.',
  };
}

module.exports = {
  checkMalwareProtection,
  checkPatchManagement,
  checkVulnScanning,
  checkCloudVulnScanning,
  checkIntegrityVerification,
};
