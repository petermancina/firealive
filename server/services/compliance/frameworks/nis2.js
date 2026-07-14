// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: NIS2
//
// R3g (v1.0.33): coverage of the EU Network and Information Security
// Directive 2 (NIS2) under the Shared Responsibility schema. NIS2
// significantly expanded the original NIS Directive\'s scope and
// strengthened cybersecurity obligations for essential and important
// entities across critical sectors.
//
// APPLICABILITY
//
//   NIS2 applies to ~160,000 entities across the EU classified as:
//
//     "Essential entities" (Annex I): utilities (electricity, oil,
//     gas, hydrogen, district heating), transport (air, rail, water,
//     road), banking, financial market infrastructure, health
//     (hospitals, manufacturers of pharmaceuticals/medical devices,
//     blood-product entities, EU reference laboratories), drinking
//     water, waste water, digital infrastructure (IXPs, DNS providers,
//     TLD name registries, cloud computing service providers, data
//     centre providers, CDN providers, trust service providers,
//     public electronic communications networks/services), ICT
//     service management (B2B managed service providers and managed
//     security service providers), public administration (central
//     government, regional government if Member State elects), space.
//
//     "Important entities" (Annex II): postal/courier services,
//     waste management, manufacture, production and distribution of
//     chemicals, food production/processing/distribution,
//     manufacture of medical devices/computer-electronic-optical
//     products/electrical equipment/machinery/motor vehicles/other
//     transport equipment, digital providers (online marketplaces,
//     online search engines, social networking platforms), research.
//
//   FireAlive is NOT inherently in either category. NIS2 does not
//   name FireAlive nor classify it as essential or important.
//   FireAlive could be a TPP serving entities in either category --
//   in which case the financial-, healthcare-, or other-sector
//   entity bears NIS2 regulatory responsibility and may need to
//   manage FireAlive as a third-party supplier under Art.21(2)(d)
//   supply chain security obligations.
//
//   This framework definition is provided for customers that ARE
//   essential or important entities under NIS2 and have adopted
//   FireAlive in their SOC operations. The technical controls
//   support the customer\'s Art.21(2) risk management obligations;
//   the customer remains responsible for Art.20 management body
//   accountability, Art.21(2)(g) workforce training, Art.23
//   incident reporting workflow, and Art.26-27 registration with
//   competent authorities.
//
//   For non-essential/non-important customers, this framework
//   report can be ignored without consequence.
//
// AUTHORITY
//
//   European Commission and national competent authorities (NCAs)
//   designated by each Member State. Computer Security Incident
//   Response Teams (CSIRTs) at national level receive incident
//   notifications. The Cooperation Group facilitates cross-border
//   cooperation; ENISA provides EU-level technical support.
//
// PENALTIES
//
//   Significant under Art.34: up to EUR 10M or 2% of total
//   worldwide annual turnover (whichever higher) for essential
//   entities; up to EUR 7M or 1.4% for important entities.
//   Management body members can be held personally liable under
//   Art.20(1).
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Directive (EU) 2022/2555 -- Network and Information Security
//   Directive 2. Entered into force 16 January 2023; Member State
//   transposition deadline 17 October 2024. Member State
//   implementing laws may add national specifics (penalties,
//   national authorities, sector-specific provisions).
//
//   verifiedControls map technical platform implementations to
//   Art.21(2) cybersecurity risk management measures and Art.23
//   reporting timing. customerResponsibility covers Art.20
//   governance, Art.21(2)(g) training delivery, Art.21(2)(i)
//   personnel security, Art.22 risk assessment cooperation,
//   Art.23 reporting workflow, Art.26-27 registration, Art.31-32
//   supervisory cooperation.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'NIS2',
  authority: 'European Commission / national competent authorities and CSIRTs',
  citation: 'Directive (EU) 2022/2555 -- Network and Information Security Directive 2',
  verifiedControls: [
    // ── Art.21(2) Cybersecurity Risk Management Measures ────────────────────
    {
      id: 'Art.21(2)(a)',
      name: 'Risk Analysis and Information System Security Policies',
      check: checks.checkChangeManagement,
      mapping: 'Anti-rollback fuse_counter + audit-logged configuration changes evidence change-control hygiene; risk-analysis methodology and information-system-security policies are operator-side documentation under Art.21(2)(a).',
    },
    {
      id: 'Art.21(2)(b)',
      name: 'Incident Handling',
      check: checks.checkIrPlanExists,
      mapping: 'ir_policies table stores IR plans + scenario playbooks; sla_config tracks MTTA/MTTR commitments; notification_config provides multi-channel alert delivery. The procedural incident-handling workflow is operator-side.',
    },
    {
      id: 'Art.21(2)(c) [Backup]',
      name: 'Business Continuity -- Backup Management',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules drive automated execution; backup_pushes evidence recent runs; SHA-256 verification ensures integrity. Art.21(2)(c) explicitly requires backup management and disaster recovery.',
    },
    {
      id: 'Art.21(2)(c) [DR]',
      name: 'Business Continuity -- Disaster Recovery',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination backup architecture (local + S3/GCS/Azure/SFTP combinations) prevents single-destination failure from defeating recovery; restore_approvals workflow tests recovery quarterly.',
    },
    {
      id: 'Art.21(2)(d) [Supply Chain]',
      name: 'Supply Chain Security -- Vendor Monitoring',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config tracks all ICT third-party arrangements; last_test_at evidences ongoing health monitoring. The financial/healthcare/other-sector entity\'s supply chain risk register listing FireAlive as a TPP is operator-side documentation.',
    },
    {
      id: 'Art.21(2)(d) [Vendor Risk]',
      name: 'Supply Chain Security -- Vendor Risk Assessment',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Every configured integration has at least one operational test recorded; formal vendor risk review (questionnaires, SOC 2 reports, DPA execution) is customer-side documentation. NIS2 Art.21(3) requires Member States to ensure entities take vulnerabilities/quality-of-development of suppliers into account.',
    },
    {
      id: 'Art.21(2)(e) [Acquisition]',
      name: 'Security in Acquisition, Development, Maintenance -- Config Lock',
      check: checks.checkConfigLockState,
      mapping: 'Config Lock (R3e v1.0.32) gates platform-configuration changes in production; requires unlock + admin role + a fresh user-verified WebAuthn hardware-passkey step-up. Acquisition / development / maintenance security at the platform configuration level.',
    },
    {
      id: 'Art.21(2)(e) [Patch]',
      name: 'Security in Acquisition, Development, Maintenance -- Patch Management',
      check: checks.checkPatchManagement,
      mapping: 'Anti-rollback fuse_counter enforces monotonic version increment; startup integrity check rejects rollback attempts. Patch management at the operator infrastructure layer is operator-managed using their patch-management procedure.',
    },
    {
      id: 'Art.21(2)(f)',
      name: 'Effectiveness Assessment of Cybersecurity Risk Management Measures',
      check: checks.checkDrTestRecency,
      mapping: 'restore_approvals.status=consumed records evidence regular DR testing; quarterly cadence supports the Art.21(2)(f) requirement for assessment of measures effectiveness.',
    },
    {
      id: 'Art.21(2)(g)',
      name: 'Cyber Hygiene -- Password Policy',
      check: checks.checkPasswordPolicy,
      mapping: 'Login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant); no password is stored, so no password-length policy applies. Cyber hygiene technical foundation; awareness training delivery is operator-side under Art.21(2)(g).',
    },
    {
      id: 'Art.21(2)(h) [Crypto]',
      name: 'Cryptography -- Algorithm Strength',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM via TIER1/TIER3 keys (distinct); state-of-the-art symmetric cryptography supports Art.21(2)(h) policies and procedures regarding cryptography.',
    },
    {
      id: 'Art.21(2)(h) [Keys]',
      name: 'Cryptography -- Key Management',
      check: checks.checkKeyRotation,
      mapping: 'backup_signing_keys 180-day rotation cadence; kms_providers integration with AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault for hardware-backed key custody.',
    },
    {
      id: 'Art.21(2)(i)',
      name: 'Human Resources Security, Access Control, Asset Management',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware; scoped API keys. HR security (background checks, training, termination procedures) and asset management (inventory) are operator-side.',
    },
    {
      id: 'Art.21(2)(j) [MFA]',
      name: 'Multi-Factor Authentication',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials. NIS2 Art.21(2)(j) explicitly requires MFA or continuous authentication; FireAlive enforces a hardware passkey for all roles.',
    },
    {
      id: 'Art.21(2)(j) [Comms]',
      name: 'Secured Communications',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement when NODE_ENV=production via enforceMinTls middleware; TLS 1.2+ at reverse proxy; mTLS on /api/internal/ routes. Secure voice/video communications and emergency communication systems are operator-side.',
    },
    // ── Art.23 Reporting Obligations ─────────────────────────────────────────
    {
      id: 'Art.23',
      name: 'Reporting of Significant Incidents (24h / 72h / 1mo)',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery. NIS2 reporting clock under Art.23: early warning to CSIRT within 24h of becoming aware; incident notification within 72h; intermediate report on request; final report within 1 month. Reporting workflow and templates are operator-side.',
    },
  ],
  customerResponsibility: [
    // ── Art.20 Governance ────────────────────────────────────────────────────
    {
      id: 'Art.20(1)',
      name: 'Management Body Approval of Cybersecurity Risk Management Measures',
      category: 'organizational',
      detail: 'Management bodies of essential and important entities approve the cybersecurity risk-management measures and oversee their implementation. Management body members can be held personally liable for non-compliance. Document the approval process, decisions, and review cadence.',
    },
    {
      id: 'Art.20(2)',
      name: 'Management Body Training',
      category: 'training',
      detail: 'Members of the management body follow training to gain sufficient knowledge and skills to identify cybersecurity risks and assess the impact on services provided. Member-level training is mandatory and must be evidenced.',
    },
    // ── Art.21(2)(g) Workforce Training ──────────────────────────────────────
    {
      id: 'Art.21(2)(g) [Training]',
      name: 'Workforce Cyber Hygiene Training Delivery',
      category: 'training',
      detail: 'Provide regular cybersecurity training to all employees on a similar basis. Topics include password hygiene, phishing awareness, incident reporting, secure remote-working practices. Document attendance, content, and assessment.',
    },
    // ── Art.21(2)(i) HR Security ────────────────────────────────────────────
    {
      id: 'Art.21(2)(i) [HR]',
      name: 'Human Resources Security Procedures',
      category: 'procedural',
      detail: 'Define personnel-security procedures: pre-employment screening proportional to role sensitivity, security responsibilities in contracts, ongoing monitoring, termination procedures including access revocation and asset return.',
    },
    // ── Art.22 EU-Coordinated Risk Assessment ────────────────────────────────
    {
      id: 'Art.22',
      name: 'Cooperation with EU-Coordinated Risk Assessments',
      category: 'procedural',
      detail: 'Cooperate with EU-level coordinated security risk assessments of critical supply chains. Provide requested information to the Cooperation Group / ENISA. Document the procedure for responding to such requests; designate point of contact.',
    },
    // ── Art.23 Reporting Workflow ────────────────────────────────────────────
    {
      id: 'Art.23(1)',
      name: 'Early Warning to CSIRT (24 hours)',
      category: 'procedural',
      detail: 'Submit early warning to the relevant CSIRT or competent authority within 24 hours of becoming aware of a significant incident. The early warning must include whether the incident is suspected of being caused by unlawful or malicious acts or could have cross-border impact.',
    },
    {
      id: 'Art.23(2)',
      name: 'Incident Notification (72 hours)',
      category: 'procedural',
      detail: 'Submit incident notification within 72 hours of becoming aware. Notification includes initial assessment of severity, impact, and indicators of compromise where available. Use the standardized notification template prescribed by the implementing regulatory technical standard.',
    },
    {
      id: 'Art.23(3)',
      name: 'Intermediate Report on Request',
      category: 'procedural',
      detail: 'Provide intermediate report to the competent authority on request, with status updates and any relevant changes. Maintain capacity to produce intermediate reports during an active incident response.',
    },
    {
      id: 'Art.23(4)',
      name: 'Final Report (1 month)',
      category: 'procedural',
      detail: 'Submit final report within 1 month after submission of the incident notification. Final report includes: detailed description, type of threat / root cause, applied / ongoing mitigation measures, cross-border impact if any. Final report drives lessons-learned cycle.',
    },
    {
      id: 'Art.23(7)',
      name: 'Significant Cyber Threat Notification (Voluntary)',
      category: 'procedural',
      detail: 'Voluntary notification of significant cyber threats (not actual incidents) to the CSIRT or competent authority. Supports sector-wide situational awareness. Document the criteria for voluntary notification and the procedure.',
    },
    // ── Art.24 ICT Standards ─────────────────────────────────────────────────
    {
      id: 'Art.24',
      name: 'Use of European or International Standards',
      category: 'procedural',
      detail: 'In order to demonstrate compliance with the Art.21(2) measures, Member States may require use of particular ICT products, services and processes certified under European cybersecurity certification schemes (per Regulation EU 2019/881). Track applicable national-level Art.24 requirements.',
    },
    // ── Art.26-27 Registration ──────────────────────────────────────────────
    {
      id: 'Art.26',
      name: 'Registration with Competent Authority',
      category: 'documentation',
      detail: 'Register the entity\'s details with the competent authority designated by the Member State of main establishment: legal name, address, sector, contact details, list of Member States where the entity provides services. Notify changes promptly.',
    },
    {
      id: 'Art.27',
      name: 'Establishment of Lead Authority',
      category: 'procedural',
      detail: 'For entities providing services in multiple Member States, the competent authority of the Member State of main establishment acts as the lead authority. Cooperate with cross-border supervisory actions. Document the designated lead authority and engagement procedures.',
    },
    // ── Art.31-32 Supervision and Enforcement ────────────────────────────────
    {
      id: 'Art.31-32',
      name: 'Cooperation with Supervisory Authorities',
      category: 'procedural',
      detail: 'Cooperate with competent authority supervisory activities: provide on-site inspection access, requested information, security audits, security scans, evidence of compliance. Maintain readiness for ex-ante (essential entities) and ex-post (important entities) supervision.',
    },
    // ── Art.33 Enforcement Measures ─────────────────────────────────────────
    {
      id: 'Art.33',
      name: 'Preparedness for Enforcement Measures',
      category: 'organizational',
      detail: 'Maintain readiness for enforcement measures including binding instructions, orders to comply, designation of monitoring officer, and ultimately administrative fines and suspension of certification. Document the response procedure for enforcement actions and management-body briefing protocols.',
    },
    // ── Art.34 Administrative Fines ──────────────────────────────────────────
    {
      id: 'Art.34',
      name: 'Administrative Fines Risk Awareness',
      category: 'organizational',
      detail: 'Up to EUR 10M or 2% of total worldwide annual turnover (whichever higher) for essential entities; up to EUR 7M or 1.4% for important entities. Document the risk in enterprise risk register; ensure D&O insurance covers personal-liability exposure for management body members under Art.20(1).',
    },
    // ── Art.21(2)(c) Crisis Management ──────────────────────────────────────
    {
      id: 'Art.21(2)(c) [Crisis]',
      name: 'Crisis Management Plan',
      category: 'documentation',
      detail: 'Document crisis management plan covering: crisis declaration triggers, crisis management team composition and roles, communication procedures (internal and external), coordination with authorities, business continuity activation, recovery and reconstitution procedures.',
    },
    // ── Member State implementing law ───────────────────────────────────────
    {
      id: 'National Law',
      name: 'Member State Transposition Awareness',
      category: 'procedural',
      detail: 'NIS2 is a Directive (not a Regulation): Member States transpose into national law with possible national specifics. Track the applicable national implementing law for the entity\'s Member State of main establishment; some Member States have added stricter requirements, additional categories, or specific sectoral provisions.',
    },
  ],
  note: 'NIS2 entered into force 16 January 2023; transposition deadline was 17 October 2024. NIS2 replaced the 2016 NIS Directive with substantially expanded scope (~160k entities versus ~20k under NIS1). Member State implementation may add national requirements not enumerated here. The Cooperation Group, EU-CyCLONe (EU Cyber Crises Liaison Organisation Network), and CSIRTs Network coordinate cross-border response. Personal liability for management body members under Art.20(1) is novel and significant -- some Member States have implemented this with criminal penalties in addition to administrative fines. NIS2 should be examined alongside DORA (financial sector), CER (Critical Entities Resilience Directive), and Cyber Resilience Act (manufacturers of products with digital elements) for overlapping or sector-specific obligations.',
});
