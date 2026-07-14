// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: Cyber Essentials (UK)
//
// R3g PR2 (v1.0.33): GD-side coverage of the UK National Cyber
// Security Centre (NCSC) Cyber Essentials scheme under the Shared
// Responsibility schema. GD-side counterpart to MC PR1's
// frameworks/cyber_essentials.js. Same metadata, same citation, same
// customerResponsibility list (Cyber Essentials scope and policy
// requirements are scheme-defined and framework-level not platform-
// specific); adapted verifiedControls for the GD's surface.
//
// Cyber Essentials is a baseline cybersecurity hygiene certification
// focused on 5 technical control areas.
//
// APPLICABILITY (per Foundational Rule 16)
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
//   have adopted FireAlive. The GD\'s technical controls support
//   the customer\'s compliance with the 5 Cyber Essentials control
//   areas at the governance / cross-region aggregation tier; the
//   customer remains responsible for scope definition, asset
//   inventory, policy documentation, evidence preparation for the
//   assessor, and annual recertification.
//
//   For customers not pursuing UK certifications, this framework
//   report can be ignored without consequence.
//
// AUTHORITY
//
//   UK National Cyber Security Centre (NCSC), part of GCHQ. Scheme
//   operations delegated to IASME Consortium (since 2020) as the
//   sole Cyber Essentials Partner. Certification bodies accredited
//   by IASME perform assessments.
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
//   verifiedControls map GD-layer platform implementations to each
//   area. customerResponsibility covers scope definition, asset
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
      mapping: 'Layer 1 (current): management_consoles enumerates the connected MCs (the GD\'s primary external system boundaries). Layer 2 (post-B5b v1.0.51 et seq.): integration_config will enumerate SOAR / SIEM / cloud / IAM vendor integrations. Network-layer firewalls (reverse proxy + cloud security groups) are operator-managed; the platform provides the application-layer enumeration that supports the firewall ruleset.',
    },
    {
      id: 'CE-1.2',
      name: 'Firewalls -- Network Segmentation',
      check: checks.checkNetworkSegmentation,
      mapping: 'GD data segmentation is architectural rather than crypto-keyed: only aggregate metrics (regional_metrics, no analyst-identifying fields) and account data reach the GD. API-layer role-array enforcement via authMiddleware. The GD has no /api/internal/ routes (no anti-replay middleware on internal routes is needed). Network-level segmentation (VLANs, subnets, security groups isolating the GD port) is operator-managed.',
    },
    // ── Control 2: Secure Configuration ─────────────────────────────────────
    {
      id: 'CE-2.1',
      name: 'Secure Configuration -- Production Hardening',
      check: checks.checkSecureBaseline,
      mapping: 'NODE_ENV=production is set for industry convention but has no in-platform gated behavior on the GD as of v0.0.31 (no enforceMinTls, no production-mode error handling, no mTLS on /api/internal/ routes). Secure-baseline elements (HTTPS, error sanitization, network isolation) are entirely operator-managed at the reverse-proxy / deployment layer.',
    },
    {
      id: 'CE-2.2',
      name: 'Secure Configuration -- Change Control',
      check: checks.checkConfigLockState,
      mapping: 'GD Config Lock server-side persistence is live (the config_lock_state singleton; the config-write chokepoint refuses writes while the GD is locked). Unlock requires a fresh hardware-passkey assertion (a UV step-up), the GD twin of the MC R3e v1.0.32 config-lock and, like the MC config-lock, a phishing-resistant hardware-passkey step-up. Configuration-change discipline is additionally backed by route-middleware role gating (CISO-only writes).',
    },
    {
      id: 'CE-2.3',
      name: 'Secure Configuration -- Default Password Replacement',
      check: checks.checkPasswordPolicy,
      mapping: 'GD is passwordless -- login is a FIDO2 hardware passkey (B5n3), so there is no password to gate and no MIN_PASSWORD_LENGTH policy applies; the credential-strength control is the phishing-resistant hardware key. No default accounts ship with the platform; CISO / VP / readonly accounts are operator-created at deployment with operator-chosen credentials.',
    },
    // ── Control 3: User Access Control ──────────────────────────────────────
    {
      id: 'CE-3.1',
      name: 'User Access Control -- Access Restriction',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware enforces access decisions with role-array gating on every /api route; MC-trust api_keys for inbound MC push authentication with explicit per-MC scoping.',
    },
    {
      id: 'CE-3.2',
      name: 'User Access Control -- Unique User Accounts',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at the database layer (UNIQUE on users.username); no shared accounts on the GD. Pseudonym continuity for analyst identity is enforced upstream at the MC layer (architectural boundary — the GD does not store analyst identities).',
    },
    {
      id: 'CE-3.3',
      name: 'User Access Control -- Privileged Account Separation',
      check: checks.checkPrivilegedSeparation,
      mapping: 'SoD model for the GD: 1-2 CISO-role users provides least-privilege; new users default to readonly tier unless explicitly promoted. This implements the Cyber Essentials principle that administrative accounts are not used for routine work; the separate-account-for-admin-tasks pattern is encoded in the ciso / vp / readonly role split.',
    },
    {
      id: 'CE-3.4',
      name: 'User Access Control -- Multi-Factor Authentication',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant): login refuses a session without a user-verified hardware passkey in webauthn_credentials. Cyber Essentials v3.2 requires MFA for cloud-service admin accounts, satisfied by the hardware passkey.',
    },
    {
      id: 'CE-3.5',
      name: 'User Access Control -- Session Management',
      check: checks.checkSessionTimeout,
      mapping: 'JWT expiresIn hardcoded "8h" on the GD matches CISO operational rhythm but exceeds the SOC-grade 30-minute norm. For shorter idle timeouts in Cyber Essentials Plus contexts, reverse-proxy session cookies with shorter TTL are operator-managed.',
    },
    // ── Control 4: Malware Protection ────────────────────────────────────────
    {
      id: 'CE-4.1',
      name: 'Malware Protection',
      check: checks.checkMalwareProtection,
      mapping: 'The GD now has an in-platform host/endpoint EDR seam (the malware_scanner_integrations registry — eleven providers, credentials AES-256-GCM-encrypted), additive on top of the in-platform runtime-monitor baseline. By design the GD still does not process uploaded files from analysts; file-content scanning at the analyst-data layer is enforced at the MC. Host-level antivirus on the GD server OS (Microsoft Defender / ClamAV / CrowdStrike Falcon agent / similar) plus AV/EDR coverage across workstations interacting with the GD remains operator-managed defense-in-depth.',
    },
    // ── Control 5: Security Update Management ────────────────────────────────
    {
      id: 'CE-5.1',
      name: 'Security Update Management',
      check: checks.checkPatchManagement,
      mapping: 'system_meta.fuse_counter tracks platform version (seeded by db-init.js). The GD manifest now carries a package.json fuseCounter (72); the boot-time check comparing it against system_meta.fuse_counter (and so enforcing anti-rollback) still awaits the GD startup-verifier phase, so the fuse is reported but not yet enforcing. AGPL-3.0 source transparency for software-update auditing. Host OS / Node.js runtime / dependency patching is operator-managed; Cyber Essentials v3.2 requires high/critical patches within 14 days.',
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
      name: 'Credential Policy Documentation',
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
      detail: 'Document the change management procedure including the workflow for requesting, reviewing, approving, deploying, and reviewing configuration changes. The platform will support this through Config Lock and audit logging once Config Lock server-side persistence lands; the procedural framework is operator-side.',
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
  note: 'Cyber Essentials is operated by NCSC under license to IASME Consortium (since 2020). The scheme is updated periodically (v3.2 is the current major version). UK Government contracts requiring "Cyber Essentials" typically accept either Cyber Essentials or Cyber Essentials Plus; contracts requiring "Cyber Essentials Plus" specifically require the audited variant. Annual recertification is mandatory. The scheme is recognized in some international procurement contexts (Australia, some EU Member States) but is fundamentally UK-anchored. Customers pursuing wider international certifications may prefer ISO 27001 (see iso_27001 framework definition in this same library). The GD\'s role in a Cyber Essentials scope is the governance / cross-region aggregation tier; if the analyst-data MC layer is also in scope, both layers are typically captured in the SAQ.',
});
