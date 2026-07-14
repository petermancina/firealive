// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: NIST CSF 2.0
//
// R3g PR2 (v1.0.33): GD-side NIST Cybersecurity Framework 2.0 coverage
// under the Shared Responsibility schema, covering all 6 Functions
// (GOVERN, IDENTIFY, PROTECT, DETECT, RESPOND, RECOVER). GD-side
// counterpart to MC PR1's frameworks/nist_csf.js. Same metadata, same
// citation, same customerResponsibility list (CSF subcategories are
// NIST-defined and framework-level not platform-specific); adapted
// verifiedControls for the GD's surface.
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
// APPLICABILITY (per Foundational Rule 16)
//
//   This framework definition is provided as a service to operators
//   adopting NIST CSF 2.0 as their cybersecurity risk management
//   baseline. The GD's compliance posture supports the operator's
//   CSF program at the governance / cross-region aggregation layer;
//   the MC layer (and its compliance reports) covers the operational
//   analyst-data layer.
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
      mapping: 'Layer 1 (current): management_consoles tracks each connected MC (the GD\'s third-party data sources) with last_sync timestamps. Layer 2 (post-B5b v1.0.51): integration_config will track SOAR / SIEM / cloud / IAM / ticketing vendor integrations. Criticality assessment is operator-side.',
    },
    {
      id: 'GV.SC-07',
      name: 'Risks Posed by a Supplier are Identified, Recorded, Prioritized',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Each active MC documented with country and regulatory_framework on management_consoles for jurisdictional risk context; baseline operational evidence via last_sync history. Layer 2 (post-B5b): integration_config last_test_at provides per-integration testing baseline. Formal vendor risk review (questionnaires, SOC 2 collection, DPA) is customer-side documentation.',
    },
    // ── IDENTIFY ─────────────────────────────────────────────────────────────
    {
      id: 'ID.AM-02',
      name: 'Software Platforms and Applications are Inventoried',
      check: checks.checkBoundaries,
      mapping: 'Software boundaries on the GD: the GD application itself (packages/global-dashboard-server), its dependencies (npm dependency tree), and the connected MCs (management_consoles) as third-party data sources. Layer 2 integrations land via B5b. Inventory of operating environment (host OS, Node.js runtime, infrastructure) is operator-side.',
    },
    // ── PROTECT ──────────────────────────────────────────────────────────────
    {
      id: 'PR.AA-01',
      name: 'Identities and Credentials are Managed',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at the database layer (UNIQUE on users.username); MC-trust api_keys (management_consoles.api_key) for inbound MC push authentication with 90-day rotation recommended. R3g PR3 adds signing_keys registry for cryptographically signed MC pushes.',
    },
    {
      id: 'PR.AA-03',
      name: 'Users, Services, Hardware are Authenticated',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with operator-configured GD_JWT_SECRET (HMAC-SHA256). SSO via SAML / OIDC / LDAP planned for B5b (v1.0.51); until then, users.auth_method is informational and authentication is a FIDO2 hardware passkey. MC-to-GD service authentication via management_consoles.api_key shared secret.',
    },
    {
      id: 'PR.AA-03 [MFA]',
      name: 'Multi-Factor Authentication for Privileged Roles',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant): login refuses a session without a user-verified hardware passkey in webauthn_credentials. CSF 2.0 implementation examples emphasize phishing-resistant MFA for privileged accounts; real TOTP verification + WebAuthn/FIDO2 are future MFA-hardening pass.',
    },
    {
      id: 'PR.AA-05',
      name: 'Access Permissions, Entitlements, and Authorizations are Managed',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware enforces permissions with role-array checks. Permission and role changes audit-logged via the request-logging middleware (CONFIG_UPDATED events emitted by PUT /api/config/:key and PATCH /api/users/:id).',
    },
    {
      id: 'PR.DS-01',
      name: 'Data-at-Rest is Protected',
      check: checks.checkEncryption,
      mapping: 'GD_JWT_SECRET (HMAC-SHA256 signing key) is the application-layer cryptographic foundation. Data-at-rest protection is filesystem-level on the SQLite database file at GD_DB_PATH (operator-managed disk encryption: LUKS / FileVault / BitLocker / AWS EBS encryption). A future GD KMS integration phase would add application-layer at-rest encryption parallel to MC\'s TIER1/TIER3 pattern.',
    },
    {
      id: 'PR.DS-02',
      name: 'Data-in-Transit is Protected',
      check: checks.checkTransmission,
      mapping: 'TLS termination at the reverse proxy (operator-managed nginx / Caddy / cloud load balancer); reject plaintext HTTP at the proxy. GD has no application-layer HTTPS enforcement as of v0.0.31. Backup destinations support encrypted=true via backup_schedules; destination-side encryption (S3 SSE / GCS CMEK / Azure SE) is operator-managed.',
    },
    {
      id: 'PR.DS-10',
      name: 'Data-in-Use is Protected (Integrity)',
      check: checks.checkAuditIntegrity,
      mapping: 'audit_log is append-only by API contract (no UPDATE or DELETE routes expose modification). Cryptographic hash chain (SHA-256 hash + prev_hash columns) lands in B5a (v1.0.50); when shipped, the check verifies chain integrity by walking it linearly.',
    },
    {
      id: 'PR.DS-11',
      name: 'Backups of Data are Created, Protected, Maintained, Tested',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules table holds active=1 schedules; backups table records completed backups with SHA-256 integrity hash. POST /api/backups/trigger bootstraps a manual backup. Note: GD has no restore workflow as of v0.0.31, so backup TESTING is off-platform discipline (provision side-by-side instance, restore, verify).',
    },
    {
      id: 'PR.IR-01',
      name: 'Networks and Environments are Protected from Unauthorized Access',
      check: checks.checkNetworkSegmentation,
      mapping: 'GD data segmentation is architectural rather than crypto-keyed: only aggregate metrics (regional_metrics, no analyst-identifying fields) and account data (users) reach the GD. API-layer enforcement via role-array authMiddleware. Network-layer segmentation (firewall rules, security groups isolating the GD port) is operator-managed at the deployment layer.',
    },
    {
      id: 'PR.PS-01',
      name: 'Configuration Management Practices are Established',
      check: checks.checkConfigLockState,
      mapping: 'GD Config Lock server-side persistence is live (the config_lock_state singleton; the config-write chokepoint refuses writes while the GD is locked). Unlock requires a fresh hardware-passkey assertion (a UV step-up), the GD twin of the MC R3e v1.0.32 config-lock and hardened beyond the MC TOTP-MFA unlock.',
    },
    {
      id: 'PR.PS-02',
      name: 'Software is Maintained, Replaced, Removed Commensurate with Risk',
      check: checks.checkPatchManagement,
      mapping: 'system_meta.fuse_counter is seeded by db-init.js and the GD manifest now carries a package.json fuseCounter (72); the boot-time check comparing the two (and so enforcing anti-rollback) still awaits the GD startup-verifier phase, so the fuse is reported but not yet enforcing. AGPL-3.0 license provides transparency for software-maintenance auditing. Host OS / Node.js runtime / dependency patching is operator-managed.',
    },
    {
      id: 'PR.PS-05',
      name: 'Installation/Execution of Unauthorized Software is Prevented',
      check: checks.checkMalwareProtection,
      mapping: 'The GD now has an in-platform host/endpoint EDR seam (the malware_scanner_integrations registry — eleven providers, credentials AES-256-GCM-encrypted), additive on top of the in-platform runtime-monitor baseline. By design the GD still does not process uploaded files from analysts; file-content scanning at the analyst-data layer is enforced at the MC. Host-level antivirus on the GD server OS remains operator-managed defense-in-depth.',
    },
    // ── DETECT ───────────────────────────────────────────────────────────────
    {
      id: 'DE.CM-01',
      name: 'Networks and Network Services are Monitored',
      check: checks.checkAnomalyDetection,
      mapping: 'apiLimiter (express-rate-limit, 1000 req/15min per IP) provides rate-limit anomaly detection; auth_log records LOGIN_FAILED events for IP-pattern-based anomaly review. B3 (v1.0.48) wires runtime monitoring with anomaly detection on aggregate metrics streams from MCs.',
    },
    {
      id: 'DE.CM-09',
      name: 'Computing Hardware and Software is Monitored for Adverse Events',
      check: checks.checkIntegrityVerification,
      mapping: 'GD has no startup integrity verifier as of v0.0.31 (no SKIP_INTEGRITY_CHECK env var consumption; no release-manifest.json comparison at boot). A future GD buildout phase will add a manifest-based verifier (release-manifest.json shipping with each release; boot-time SHA-256 comparison against index.js / db-init.js / package.json); when shipped, this check evaluates the verifier\'s posture automatically.',
    },
    {
      id: 'DE.AE-02',
      name: 'Potentially Adverse Events are Analyzed',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware records every /api request (except /api/health) to audit_log with user_id, event_type, detail, ip, severity, timestamp. SIEM streaming for external correlation lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. Alert thresholds (notification_config) trigger automated escalation on configured patterns.',
    },
    // ── RESPOND ──────────────────────────────────────────────────────────────
    {
      id: 'RS.MA-02',
      name: 'Incident Reports are Triaged and Validated',
      check: checks.checkIrPlanExists,
      mapping: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO / governance-tier incident response planning is operator-managed off-platform. notification_config provides delivery-channel configuration for threshold-based alerts.',
    },
    // ── RECOVER ──────────────────────────────────────────────────────────────
    {
      id: 'RC.RP-01',
      name: 'Incident Recovery Plan is Executed',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination resilience via active backup_schedules pointing to different destination values (local + S3 / GCS / Azure combinations); SHA-256 verification on each backup. Note: GD has no restore workflow as of v0.0.31; recovery plan execution is off-platform until a future restore-workflow phase ships.',
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
      detail: 'A cybersecurity supply chain risk management program, strategy, objectives, policies, and processes are established and agreed to by organizational stakeholders. Document the program scope, methodology, and governance. The GD\'s primary supply-chain entries are the MCs (which are themselves operated under per-region SOC governance) and the GD\'s software dependencies (npm tree).',
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
      detail: 'Representations of the organization\'s authorized network communication and internal and external network data flows are maintained. Data flow diagrams (DFDs) capturing PII/PHI flows across services, with explicit attention to the MC → GD aggregate metric push channel.',
    },
    {
      id: 'ID.AM-04',
      name: 'Inventory of Services Provided by Suppliers',
      category: 'documentation',
      detail: 'Inventories of services provided by suppliers are maintained. Vendor catalog with service descriptions, data accessed, integration types, and contractual security commitments. The MCs connected to the GD count as supplier services from the GD\'s perspective.',
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
      detail: 'The authenticity and integrity of hardware and software are assessed prior to acquisition and use. Software bill of materials (SBOM) review; signed releases verified; supply chain attack mitigation procedures. Apply to GD deployment artifacts: verify sha256sum of distributions, sign container images.',
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
      detail: 'Individuals in specialized roles are provided with awareness and training so they can perform their cybersecurity-related duties. CISO-role users on the GD merit heightened training including incident response, supply chain security, and cross-region governance.',
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
  note: 'CSF 2.0 is voluntary guidance, not a regulation. Many regulators reference CSF for the technical-control baseline; CSF Profile (Current Profile vs Target Profile gap analysis) and CSF Tier (Partial/Risk Informed/Repeatable/Adaptive maturity classification) are operator-side strategic planning exercises that the framework definition does not replicate. The 2.0 release\'s most significant addition is the GOVERN function, which makes governance an explicit Function on par with the original five; mature CSF programs should expect their auditors to examine GOVERN subcategory implementation evidence. The GD\'s role in CSF is at the governance / cross-region aggregation tier; analyst-level operational controls are covered at the MC layer.',
});
