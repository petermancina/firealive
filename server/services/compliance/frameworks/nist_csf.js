// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: NIST CSF 2.0
//
// R3g (v1.0.33): comprehensive NIST Cybersecurity Framework 2.0
// coverage under the Shared Responsibility schema, covering all 6
// Functions (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER).
//
// AUTHORITY
//
//   US National Institute of Standards and Technology (NIST).
//   The Cybersecurity Framework is voluntary guidance; it is not
//   regulation. Many regulators and procurement requirements
//   reference CSF (HHS for healthcare, DoD for defense contractors,
//   state CISOs for state agencies, large enterprises for vendors).
//
// SCOPE
//
//   NIST Cybersecurity Framework 2.0 (Feb 2024 release). The 2.0
//   update introduced:
//     - GOVERN function (previously implicit; now explicit in 2.0)
//     - Expanded Cybersecurity Supply Chain Risk Management
//       (GV.SC, previously ID.SC in CSF 1.1)
//     - Tier maturity model (Tier 1 Partial through Tier 4
//       Adaptive) -- operator-side, not platform-verifiable
//     - Profile concept (Current Profile, Target Profile) --
//       operator-side strategic planning tool
//
//   This framework definition covers all 6 Functions across
//   verifiedControls (technical subcategories) and
//   customerResponsibility (governance, risk-management,
//   awareness/training, communication subcategories).
//
// PROFILE AND TIER NOTES
//
//   Profile (Current vs Target gap analysis): customer-responsibility
//   strategic planning exercise. The platform supports the
//   identification of Current Profile capabilities but does not
//   generate Target Profile artifacts.
//
//   Tier (Partial / Risk Informed / Repeatable / Adaptive): the
//   maturity classification is a customer self-assessment.
//   FireAlive's technical-control surface enables the practices that
//   distinguish higher Tiers (continuous monitoring, automated
//   response, integration with supply chain risk management).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'NIST CSF 2.0',
  authority: 'US National Institute of Standards and Technology',
  citation: 'NIST Cybersecurity Framework Version 2.0 (Feb 2024)',
  verifiedControls: [
    // ── GOVERN ───────────────────────────────────────────────────────────────
    {
      id: 'GV.SC-04',
      name: 'Suppliers are Known and Prioritized by Criticality',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config tracks all third-party integrations with type (SOAR/SIEM/IAM/cloud/KMS/etc.); last_test_at evidences ongoing monitoring of supplier reachability. Criticality assessment is operator-side.',
    },
    {
      id: 'GV.SC-07',
      name: 'Risks Posed by a Supplier are Identified, Recorded, Prioritized',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Every configured integration has at least one historical test result evidencing operational behavior; formal vendor risk review (questionnaires, SOC 2 review, DPA) is customer-side documentation.',
    },
    // ── IDENTIFY ─────────────────────────────────────────────────────────────
    {
      id: 'ID.AM-02',
      name: 'Software Platforms and Applications are Inventoried',
      check: checks.checkBoundaries,
      mapping: 'Software boundaries enumerated via integration_config types and tiered classification; the FireAlive platform itself is one inventoried application with documented dependencies and integration points.',
    },
    // ── PROTECT ──────────────────────────────────────────────────────────────
    {
      id: 'PR.AA-01',
      name: 'Identities and Credentials are Managed',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced; pseudonym_uuid for analyst identity continuity across rotations; api_keys for programmatic identities with scoping.',
    },
    {
      id: 'PR.AA-03',
      name: 'Users, Services, Hardware are Authenticated',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with HS256 signing; SSO via SAML/OIDC/LDAP integration_config types; mTLS for internal service-to-service authentication on /api/internal/ routes.',
    },
    {
      id: 'PR.AA-03 [MFA]',
      name: 'Multi-Factor Authentication for Privileged Roles',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials. CSF 2.0 implementation examples emphasize phishing-resistant MFA for privileged accounts; a hardware passkey is phishing-resistant by construction (unlike a shared TOTP secret).',
    },
    {
      id: 'PR.AA-05',
      name: 'Access Permissions, Entitlements, and Authorizations are Managed',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware enforces permissions; api_keys.scopes provides granular programmatic access scoping; USER_ROLE_CHANGED audit events track permission changes.',
    },
    {
      id: 'PR.DS-01',
      name: 'Data-at-Rest is Protected',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM via TIER1_ENCRYPTION_KEY + TIER3_ENCRYPTION_KEY (distinct keys); tier-based segmentation prevents tier-1 key exposure from leaking tier-3 data.',
    },
    {
      id: 'PR.DS-02',
      name: 'Data-in-Transit is Protected',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement when NODE_ENV=production via enforceMinTls middleware; TLS 1.2+ at reverse proxy; mTLS on /api/internal/; encrypted backup destinations (SFTP, S3/GCS/Azure SSE).',
    },
    {
      id: 'PR.DS-10',
      name: 'Data-in-Use is Protected (Integrity)',
      check: checks.checkAuditIntegrity,
      mapping: 'audit_log append-only by API contract; SIEM streaming exports immutable evidence externally; signed log batches via Ed25519 (signLogBatch); decryption integrity verification via AES-GCM authentication tags.',
    },
    {
      id: 'PR.DS-11',
      name: 'Backups of Data are Created, Protected, Maintained, Tested',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules + backup_pushes track automated execution; multi-destination support (local/S3/GCS/Azure/SFTP) for redundancy; SHA-256 verification on backup contents; restore_approvals workflow tests recovery quarterly.',
    },
    {
      id: 'PR.IR-01',
      name: 'Networks and Environments are Protected from Unauthorized Access',
      check: checks.checkNetworkSegmentation,
      mapping: 'Tier-1 vs Tier-3 segmentation via distinct AES-256 encryption keys at the application layer; anti-replay middleware (R3d-3-pt5); reverse proxy + cloud security groups handle network-layer segmentation operator-side.',
    },
    {
      id: 'PR.PS-01',
      name: 'Configuration Management Practices are Established',
      check: checks.checkConfigLockState,
      mapping: 'Config Lock (R3e v1.0.32) gates platform-configuration changes; requires unlock + admin role + a fresh user-verified WebAuthn hardware-passkey step-up; lock state tracked in config_lock_state singleton with audit-trail attribution.',
    },
    {
      id: 'PR.PS-02',
      name: 'Software is Maintained, Replaced, Removed Commensurate with Risk',
      check: checks.checkPatchManagement,
      mapping: 'Anti-rollback fuse_counter (currently at 25) enforces monotonic version increment; package.json fuseCounter mismatch fails startup integrity check; AGPL-3.0 license provides transparency for software-maintenance auditing.',
    },
    {
      id: 'PR.PS-05',
      name: 'Installation/Execution of Unauthorized Software is Prevented',
      check: checks.checkMalwareProtection,
      mapping: 'malware_scanner_integrations supports 15 providers (ClamAV, VirusTotal, CrowdStrike, etc.); operator-configured priority for multi-provider redundancy; scan results recorded for compliance evidence.',
    },
    // ── DETECT ───────────────────────────────────────────────────────────────
    {
      id: 'DE.CM-01',
      name: 'Networks and Network Services are Monitored',
      check: checks.checkAnomalyDetection,
      mapping: 'bandwidthMonitor middleware detects bandwidth spikes; apiLimiter rate limiting catches traffic anomalies; integration with SIEM via CEF streaming enables external correlation analytics.',
    },
    {
      id: 'DE.CM-09',
      name: 'Computing Hardware and Software is Monitored for Adverse Events',
      check: checks.checkIntegrityVerification,
      mapping: 'Startup integrity check verifies package.json fuseCounter matches system_meta; SKIP_INTEGRITY_CHECK env var must NOT be "true" in production; integrity failures are loud (process exits with error code).',
    },
    {
      id: 'DE.AE-02',
      name: 'Potentially Adverse Events are Analyzed',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware captures every /api/ request; SIEM streaming enables correlation across events; alert thresholds (notification_config) trigger automated escalation on adverse patterns.',
    },
    // ── RESPOND ──────────────────────────────────────────────────────────────
    {
      id: 'RS.MA-02',
      name: 'Incident Reports are Triaged and Validated',
      check: checks.checkIrPlanExists,
      mapping: 'ir_policies table stores incident response plans + scenario playbooks; sla_config tracks MTTA / MTTR commitments per priority; notification channels deliver alerts to designated responders.',
    },
    // ── RECOVER ──────────────────────────────────────────────────────────────
    {
      id: 'RC.RP-01',
      name: 'Incident Recovery Plan is Executed',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination backup architecture survives single-destination compromise; restore_approvals workflow with second-person approval prevents unilateral recovery actions; SHA-256 verification on restored data.',
    },
  ],
  customerResponsibility: [
    // ── GOVERN: Organizational Context ───────────────────────────────────────
    {
      id: 'GV.OC-01',
      name: 'Organizational Mission Understood',
      category: 'organizational',
      detail: 'The organizational mission is understood and informs cybersecurity risk management. Document the mission, vision, and how cybersecurity supports each.',
    },
    {
      id: 'GV.OC-03',
      name: 'Legal, Regulatory, and Contractual Requirements Understood',
      category: 'procedural',
      detail: 'Legal, regulatory, and contractual requirements regarding cybersecurity -- including privacy and civil liberties obligations -- are understood and managed. Maintain a compliance register mapping requirements to controls.',
    },
    {
      id: 'GV.OC-04',
      name: 'Critical Objectives, Capabilities, Services Documented',
      category: 'organizational',
      detail: 'Critical objectives, capabilities, and services that external stakeholders depend on are documented. Business impact analysis identifies what loss tolerance is acceptable for each.',
    },
    // ── GOVERN: Risk Management Strategy ────────────────────────────────────
    {
      id: 'GV.RM-01',
      name: 'Risk Management Objectives Established and Agreed',
      category: 'procedural',
      detail: 'Risk management objectives are established and agreed to by organizational stakeholders. Document objectives in a risk management charter or policy.',
    },
    {
      id: 'GV.RM-02',
      name: 'Risk Appetite and Tolerance Established',
      category: 'procedural',
      detail: 'Risk appetite and risk tolerance statements are established, communicated, and maintained. Quantitative or qualitative thresholds for which risks the organization will accept, mitigate, transfer, or avoid.',
    },
    {
      id: 'GV.RM-04',
      name: 'Strategic Direction Describes Response Options',
      category: 'procedural',
      detail: 'Strategic direction that describes appropriate risk response options is established and communicated. Document acceptable response patterns (accept, transfer, mitigate, avoid) per risk category.',
    },
    {
      id: 'GV.RM-06',
      name: 'Standardized Risk Methodology',
      category: 'procedural',
      detail: 'A standardized method for calculating, documenting, categorizing, and prioritizing cybersecurity risks is established and communicated. Document the methodology (e.g., NIST 800-30 / FAIR / OCTAVE / proprietary).',
    },
    // ── GOVERN: Roles, Responsibilities, Authorities ────────────────────────
    {
      id: 'GV.RR-01',
      name: 'Leadership Accountable for Cybersecurity Risk',
      category: 'organizational',
      detail: 'Organizational leadership is responsible and accountable for cybersecurity risk and fosters a culture that is risk-aware, ethical, and continually improving. Board-level accountability and CISO reporting line.',
    },
    {
      id: 'GV.RR-02',
      name: 'Roles, Responsibilities, Authorities Established and Communicated',
      category: 'organizational',
      detail: 'Roles, responsibilities, and authorities related to cybersecurity risk management are established, communicated, understood, and enforced. RACI matrix; role-specific job descriptions and KPIs.',
    },
    {
      id: 'GV.RR-03',
      name: 'Adequate Resources Allocated',
      category: 'organizational',
      detail: 'Adequate resources are allocated commensurate with cybersecurity risk strategy, roles, responsibilities, and policies. Budget approval cycles include explicit cybersecurity line items.',
    },
    {
      id: 'GV.RR-04',
      name: 'Cybersecurity in HR Practices',
      category: 'procedural',
      detail: 'Cybersecurity is included in human resources practices. Background checks (proportional to access sensitivity), separation-of-duties enforced via HR controls, performance reviews include security objectives.',
    },
    // ── GOVERN: Policy ───────────────────────────────────────────────────────
    {
      id: 'GV.PO-01',
      name: 'Cybersecurity Policy Established',
      category: 'documentation',
      detail: 'Policy for managing cybersecurity risks is established based on organizational context, cybersecurity strategy, and priorities and is communicated and enforced. Top-level information security policy approved by board.',
    },
    {
      id: 'GV.PO-02',
      name: 'Policy Reviewed, Updated, Communicated',
      category: 'documentation',
      detail: 'Policy for managing cybersecurity risks is reviewed, updated, communicated, and enforced to reflect changes in requirements, threats, technology, and organizational mission. Annual policy review cycle.',
    },
    // ── GOVERN: Oversight ────────────────────────────────────────────────────
    {
      id: 'GV.OV-01',
      name: 'Cybersecurity Strategy Outcomes Reviewed',
      category: 'procedural',
      detail: 'Cybersecurity risk management strategy outcomes are reviewed to inform/adjust strategy and direction. Quarterly or annual review of strategy effectiveness; metrics dashboard for executive leadership.',
    },
    {
      id: 'GV.OV-03',
      name: 'Cybersecurity Performance Evaluated',
      category: 'procedural',
      detail: 'Organizational cybersecurity risk management performance is evaluated and reviewed for adjustments needed. KPIs and KRIs tracked over time; trend analysis informs strategic adjustments.',
    },
    // ── GOVERN: Supply Chain ────────────────────────────────────────────────
    {
      id: 'GV.SC-01',
      name: 'Cyber Supply Chain Risk Management Program Established',
      category: 'procedural',
      detail: 'A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders. Document the program scope, methodology, and governance.',
    },
    {
      id: 'GV.SC-03',
      name: 'Supply Chain Risk Integrated with Enterprise Risk',
      category: 'procedural',
      detail: 'Cybersecurity supply chain risk management is integrated into cybersecurity and enterprise risk management, risk assessment, and improvement processes. Supplier risks roll up into enterprise risk register.',
    },
    // ── IDENTIFY: Asset Management ──────────────────────────────────────────
    {
      id: 'ID.AM-01',
      name: 'Hardware Inventory',
      category: 'procedural',
      detail: 'Inventories of hardware managed by the organization are maintained. Operator maintains hardware inventory; for cloud-hosted FireAlive, the cloud provider\'s asset inventory supplements operator-side inventory.',
    },
    {
      id: 'ID.AM-03',
      name: 'Communications and Data Flows Mapped',
      category: 'procedural',
      detail: 'Representations of the organization\'s authorized network communication and internal and external network data flows are maintained. Data flow diagrams (DFDs) capturing PII/PHI flows across services.',
    },
    {
      id: 'ID.AM-04',
      name: 'Inventory of Services Provided by Suppliers',
      category: 'documentation',
      detail: 'Inventories of services provided by suppliers are maintained. Vendor catalog with service descriptions, data accessed, integration types, and contractual security commitments.',
    },
    {
      id: 'ID.AM-05',
      name: 'Assets Prioritized by Classification and Criticality',
      category: 'procedural',
      detail: 'Assets are prioritized based on classification, criticality, resources, and impact on the mission. Asset inventory includes criticality tier and recovery time objective (RTO) per asset.',
    },
    // ── IDENTIFY: Risk Assessment ────────────────────────────────────────────
    {
      id: 'ID.RA-01',
      name: 'Vulnerabilities Identified, Validated, Recorded',
      category: 'procedural',
      detail: 'Vulnerabilities in assets are identified, validated, and recorded. Vulnerability management process documented; tracking from discovery through remediation; SLAs by severity.',
    },
    {
      id: 'ID.RA-05',
      name: 'Threats, Vulnerabilities, Likelihoods, Impacts Used to Understand Risk',
      category: 'procedural',
      detail: 'Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform risk response prioritization. Risk register includes all four dimensions per identified risk.',
    },
    {
      id: 'ID.RA-06',
      name: 'Risk Responses Chosen, Prioritized, Planned, Tracked, Communicated',
      category: 'procedural',
      detail: 'Risk responses are chosen, prioritized, planned, tracked, and communicated. Risk treatment plans documented; ownership assigned; review cadence established.',
    },
    {
      id: 'ID.RA-09',
      name: 'Authenticity and Integrity of Software Verified',
      category: 'procedural',
      detail: 'The authenticity and integrity of hardware and software are assessed prior to acquisition and use. Software bill of materials (SBOM) review; signed releases verified; supply chain attack mitigation procedures.',
    },
    // ── PROTECT: Awareness and Training ──────────────────────────────────────
    {
      id: 'PR.AT-01',
      name: 'Personnel Cybersecurity Awareness Training',
      category: 'training',
      detail: 'Personnel are provided with cybersecurity awareness and training so they can perform their cybersecurity-related duties. Annual training cadence at minimum; role-based training for technical staff; tracking via LMS.',
    },
    {
      id: 'PR.AT-02',
      name: 'Privileged User Training',
      category: 'training',
      detail: 'Individuals in specialized roles are provided with awareness and training so they can perform their cybersecurity-related duties. Privileged accounts (admins) receive enhanced training including incident response.',
    },
    // ── DETECT: Adverse Event Analysis ───────────────────────────────────────
    {
      id: 'DE.AE-04',
      name: 'Estimated Impact and Scope of Adverse Events Analyzed',
      category: 'procedural',
      detail: 'The estimated impact and scope of adverse events are understood. Document the analysis methodology (taxonomies, scoring rubrics) and escalation thresholds.',
    },
    {
      id: 'DE.AE-07',
      name: 'Cyber Threat Intelligence Integrated',
      category: 'procedural',
      detail: 'Cyber threat intelligence and other contextual information are integrated into the analysis. Threat-intel feed subscriptions; ISAC/ISAO participation; integration with SIEM correlation rules.',
    },
    // ── RESPOND: Incident Response Reporting and Communication ──────────────
    {
      id: 'RS.CO-02',
      name: 'Internal and External Stakeholders Notified',
      category: 'procedural',
      detail: 'Internal and external stakeholders are notified of incidents. Communication matrix per incident severity; pre-drafted templates; legal/PR involvement workflow.',
    },
    {
      id: 'RS.CO-03',
      name: 'Information Shared with Designated Internal and External Stakeholders',
      category: 'procedural',
      detail: 'Information is shared with designated internal and external stakeholders. Procedures for sharing while protecting confidentiality; coordinated disclosure processes; law enforcement liaison.',
    },
    // ── RECOVER: Communication ──────────────────────────────────────────────
    {
      id: 'RC.CO-03',
      name: 'Recovery Activities and Progress Communicated',
      category: 'procedural',
      detail: 'Recovery activities and progress in restoring operational capabilities are communicated to designated internal and external stakeholders. Status updates per defined cadence (daily during major incident, weekly during recovery).',
    },
    {
      id: 'RC.CO-04',
      name: 'Public Updates on Incident Recovery Shared',
      category: 'procedural',
      detail: 'Public updates on incident recovery are shared using approved methods and messaging. Crisis communications plan; pre-approved spokespersons; templated status page updates.',
    },
  ],
  note: 'CSF 2.0 is voluntary guidance, not a regulation. Many regulators reference CSF for the technical-control baseline; CSF Profile (Current Profile vs Target Profile gap analysis) and CSF Tier (Partial/Risk Informed/Repeatable/Adaptive maturity classification) are operator-side strategic planning exercises that the framework definition does not replicate. The 2.0 release\'s most significant addition is the GOVERN function, which makes governance an explicit Function on par with the original five; mature CSF programs should expect their auditors to examine GOVERN subcategory implementation evidence.',
});
