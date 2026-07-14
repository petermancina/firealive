// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: Cyber Essentials (UK)
//
// R3g (v1.0.33): coverage of the UK National Cyber Security Centre
// (NCSC) Cyber Essentials scheme under the Shared Responsibility
// schema. Cyber Essentials is a baseline cybersecurity hygiene
// certification focused on 5 technical control areas.
//
// APPLICABILITY
//
//   Cyber Essentials is voluntary. An organization pursues
//   certification typically because:
//     - UK Government contracts (since 2014) often mandate Cyber
//       Essentials at minimum for bidders handling certain types
//       of information (the contract specifies which level)
//     - Insurance providers may offer reduced premiums for
//       certified organizations
//     - Cyber Essentials Plus is required for some MOD and
//       Ministry of Defence contracts
//     - Customer/procurement requirements
//
//   FireAlive is NOT itself Cyber Essentials certified. The Cyber
//   Essentials scheme does not name FireAlive nor any class to
//   which FireAlive belongs as required to undergo certification.
//
//   This framework definition is provided for customers pursuing
//   Cyber Essentials or Cyber Essentials Plus certification who
//   have adopted FireAlive. The technical controls in the platform
//   support the customer\'s compliance with the 5 Cyber Essentials
//   control areas at the platform layer. The customer remains
//   responsible for scope definition (which assets are in scope --
//   typically the whole organization for Cyber Essentials, vs more
//   focused scope for some Plus engagements), asset inventory,
//   policy documentation, evidence preparation for the assessor,
//   and annual recertification.
//
//   For customers not pursuing UK certifications, this framework
//   report can be ignored without consequence.
//
// AUTHORITY
//
//   UK National Cyber Security Centre (NCSC), part of GCHQ.
//   Scheme operations delegated to IASME Consortium (since 2020) as
//   the sole Cyber Essentials Partner. Certification bodies
//   accredited by IASME perform assessments.
//
// VARIANTS
//
//   Cyber Essentials: self-assessment questionnaire (SAQ) verified
//   by a certification body. Annual recertification.
//
//   Cyber Essentials Plus: includes Cyber Essentials SAQ plus
//   external technical audit including authenticated vulnerability
//   scans and simulated phishing test. Annual recertification.
//
//   Both certifications share the same 5 technical control areas
//   and the same control content; the difference is the evidence
//   bar (self-attestation vs external audit).
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   The 5 technical control areas:
//     1. Firewalls (boundary firewalls and internet gateways)
//     2. Secure configuration
//     3. User access control
//     4. Malware protection
//     5. Security update management
//
//   verifiedControls map platform implementations to each area.
//   customerResponsibility covers scope definition, asset
//   inventory, policy documentation, BYOD policy, supplier-managed-
//   cloud scope clarification, and evidence preparation -- all
//   operator-side work that the technical controls do not address.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'Cyber Essentials (UK)',
  authority: 'UK National Cyber Security Centre (NCSC) via IASME Consortium',
  citation: 'Cyber Essentials Requirements for IT Infrastructure v3.2 (current scheme version)',
  verifiedControls: [
    // ── Control 1: Firewalls ─────────────────────────────────────────────────
    {
      id: 'CE-1.1',
      name: 'Firewalls -- Boundary Protection',
      check: checks.checkSystemBoundaries,
      mapping: 'integration_config enumerates external system boundaries; status field evidences operational state. Network-layer firewalls (reverse proxy + cloud security groups) are operator-managed; the platform provides the application-layer enumeration that supports the firewall ruleset.',
    },
    {
      id: 'CE-1.2',
      name: 'Firewalls -- Network Segmentation',
      check: checks.checkNetworkSegmentation,
      mapping: 'Tier-1 vs Tier-3 segmentation via distinct AES-256-GCM encryption keys at application layer; anti-replay middleware on /api/internal/ routes; network-level segmentation (VLANs, subnets, security groups) is operator-managed.',
    },
    // ── Control 2: Secure Configuration ─────────────────────────────────────
    {
      id: 'CE-2.1',
      name: 'Secure Configuration -- Production Hardening',
      check: checks.checkSecureBaseline,
      mapping: 'NODE_ENV=production activates secure-baseline elements: enforceMinTls (HTTPS enforcement), mTLS on internal routes, production error handling (no stack traces in responses), hardened security headers. Non-production functionality deactivated.',
    },
    {
      id: 'CE-2.2',
      name: 'Secure Configuration -- Change Control',
      check: checks.checkConfigLockState,
      mapping: 'Config Lock (R3e v1.0.32) gates platform-configuration changes in production; requires unlock + admin role + a fresh user-verified WebAuthn hardware-passkey step-up. Default-configuration changes blocked unless explicitly authorized.',
    },
    {
      id: 'CE-2.3',
      name: 'Secure Configuration -- Default Password Replacement',
      check: checks.checkPasswordPolicy,
      mapping: 'Login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant); no password is stored, so no password-length policy applies. No default accounts ship with the platform; admin accounts are operator-created at deployment and enrolled with a hardware security key.',
    },
    // ── Control 3: User Access Control ──────────────────────────────────────
    {
      id: 'CE-3.1',
      name: 'User Access Control -- Access Restriction',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware enforces access decisions; scoped API keys for programmatic access with explicit permission lists.',
    },
    {
      id: 'CE-3.2',
      name: 'User Access Control -- Unique User Accounts',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at database layer; no shared accounts; pseudonym_uuid for analyst identity continuity across rotations preserves accountability.',
    },
    {
      id: 'CE-3.3',
      name: 'User Access Control -- Privileged Account Separation',
      check: checks.checkPrivilegedSeparation,
      mapping: 'Admin role separation (admins <= 25% of active users) implements the Cyber Essentials principle that administrative accounts are not used for routine work; separate-account-for-admin-tasks pattern.',
    },
    {
      id: 'CE-3.4',
      name: 'User Access Control -- Multi-Factor Authentication',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials. Cyber Essentials v3.2 requires MFA for cloud-service admin accounts; FireAlive enforces a hardware passkey for all roles.',
    },
    {
      id: 'CE-3.5',
      name: 'User Access Control -- Session Management',
      check: checks.checkSessionTimeout,
      mapping: 'JWT_EXPIRY environment variable bounds session lifetime; SOC-grade default <= 30 minutes ensures inactive sessions terminate. Refresh token rotation handles legitimate long-running sessions transparently.',
    },
    // ── Control 4: Malware Protection ────────────────────────────────────────
    {
      id: 'CE-4.1',
      name: 'Malware Protection',
      check: checks.checkMalwareProtection,
      mapping: 'malware_scanner_integrations supports 15 providers (ClamAV, VirusTotal, CrowdStrike, Microsoft Defender, etc.); multi-provider redundancy via priority configuration. Operator-managed AV/EDR coverage across workstations is complementary.',
    },
    // ── Control 5: Security Update Management ────────────────────────────────
    {
      id: 'CE-5.1',
      name: 'Security Update Management',
      check: checks.checkPatchManagement,
      mapping: 'Anti-rollback fuse_counter enforces monotonic version increment (currently at 25); startup integrity check rejects rollback attempts; AGPL-3.0 source transparency for software-update auditing. Cyber Essentials v3.2 requires high/critical patches within 14 days.',
    },
  ],
  customerResponsibility: [
    {
      id: 'CE-Scope-1',
      name: 'Scope of Certification',
      category: 'documentation',
      detail: 'Determine and document the scope of the Cyber Essentials certification. Default scope is whole-organization (all internet-facing assets, all user devices, all servers). Limited scope is permitted only where the limited scope is genuinely isolated. Document the boundary clearly for the assessor.',
    },
    {
      id: 'CE-Scope-2',
      name: 'Asset Inventory',
      category: 'documentation',
      detail: 'Maintain an inventory of all in-scope devices (user devices, servers, network equipment, cloud services) and the operating system / firmware versions. Inventory must be current as of the certification application; the assessor may sample-verify entries.',
    },
    {
      id: 'CE-Scope-3',
      name: 'Cloud Service Scope Classification',
      category: 'procedural',
      detail: 'Classify each cloud service (IaaS, PaaS, SaaS) per the Cyber Essentials Cloud Services scoping guidance. For SaaS (like FireAlive): the customer is responsible for user accounts, access permissions, and MFA configuration; the SaaS provider is responsible for the underlying infrastructure. Document the responsibility split per service.',
    },
    {
      id: 'CE-Scope-4',
      name: 'BYOD Policy and Coverage',
      category: 'documentation',
      detail: 'If employees use personal devices to access organizational data, those devices are in scope. Document the BYOD policy including device management, security software requirements, and acceptable use. Alternative: prohibit BYOD by policy and enforce technically.',
    },
    {
      id: 'CE-Policy-1',
      name: 'Password Policy Documentation',
      category: 'documentation',
      detail: 'The platform is passwordless: login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant), which satisfies the Cyber Essentials v3.2 MFA expectation without a password. No password policy to document; communicate the hardware-key requirement to staff.',
    },
    {
      id: 'CE-Policy-2',
      name: 'Patch Management Procedure',
      category: 'documentation',
      detail: 'Document the patch management procedure. High/critical-severity patches (CVSS >= 7.0) must be applied within 14 days of release. Identify the procedure for emergency patches, regression testing, and rollback. Communicate to IT staff with assigned responsibilities.',
    },
    {
      id: 'CE-Policy-3',
      name: 'Change Management Documentation',
      category: 'documentation',
      detail: 'Document the change management procedure including the workflow for requesting, reviewing, approving, deploying, and reviewing configuration changes. The platform supports this through Config Lock and audit logging; the procedural framework is operator-side.',
    },
    {
      id: 'CE-Policy-4',
      name: 'Acceptable Use Policy',
      category: 'documentation',
      detail: 'Document and communicate an acceptable use policy covering organizational devices, organizational data, internet access from organizational equipment, and personal device use. Require staff acknowledgment; review and reissue at defined frequency.',
    },
    {
      id: 'CE-Evidence-1',
      name: 'Evidence Preparation for Self-Assessment Questionnaire',
      category: 'procedural',
      detail: 'For Cyber Essentials: assemble evidence supporting each SAQ answer (configuration screenshots, policy excerpts, training records, technical-control screenshots). The assessor may request follow-up documentation. Allow 2-4 weeks for evidence-collection cycle prior to submission.',
    },
    {
      id: 'CE-Evidence-2',
      name: 'External Audit Preparation (Cyber Essentials Plus)',
      category: 'procedural',
      detail: 'For Cyber Essentials Plus: prepare for external technical audit including authenticated vulnerability scans on a sample of in-scope devices and simulated phishing test on a sample of users. Coordinate with the IASME-accredited certification body in advance.',
    },
    {
      id: 'CE-Operational-1',
      name: 'Annual Recertification Scheduling',
      category: 'procedural',
      detail: 'Both Cyber Essentials and Cyber Essentials Plus require annual recertification. Schedule the recertification cycle 60-90 days before certificate expiry to allow for assessment, remediation of any findings, and certificate issuance.',
    },
    {
      id: 'CE-Operational-2',
      name: 'Incident Management',
      category: 'procedural',
      detail: 'Cyber Essentials v3.2 does not require an incident response plan explicitly (it focuses on prevention), but Cyber Essentials Plus assessment may ask about incident management procedures. Document the incident response procedure at a minimum (detection, escalation, containment, recovery, lessons learned).',
    },
  ],
  note: 'Cyber Essentials is operated by NCSC under license to IASME Consortium (since 2020). The scheme is updated periodically (v3.2 is the current major version). UK Government contracts requiring "Cyber Essentials" typically accept either Cyber Essentials or Cyber Essentials Plus; contracts requiring "Cyber Essentials Plus" specifically require the audited variant. Annual recertification is mandatory. The scheme is recognized in some international procurement contexts (Australia, some EU Member States) but is fundamentally UK-anchored. Customers pursuing wider international certifications may prefer ISO 27001 (see commit 21a framework definition).',
});
