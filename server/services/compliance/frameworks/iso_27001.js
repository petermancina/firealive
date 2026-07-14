// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: ISO/IEC 27001:2022
//
// R3g (v1.0.33): comprehensive ISO/IEC 27001:2022 Information
// Security Management System coverage under the Shared
// Responsibility schema. ISO 27001 is the international standard for
// information security management systems; certification is a
// frequent procurement and vendor-management requirement,
// particularly for enterprise customers in Europe, the UK, and
// global financial services.
//
// APPLICABILITY
//
//   ISO 27001 is voluntary. An organization pursues ISO 27001
//   certification by establishing an Information Security Management
//   System (ISMS), undergoing an external audit by an accredited
//   certification body, and obtaining a certificate that is then
//   subject to annual surveillance audits and triennial
//   recertification.
//
//   FireAlive is NOT itself ISO 27001 certified, and is not
//   automatically scoped by the standard. ISO 27001 does not name
//   FireAlive nor any class to which FireAlive belongs as required
//   to undergo certification; certification is a choice made by an
//   organization based on its own customer, contractual, and
//   procurement context.
//
//   This framework definition is provided as a service to customers
//   pursuing ISO 27001 certification (or maintaining an existing
//   certification) who have adopted FireAlive in their SOC
//   operations. FireAlive\'s technical controls support the operator
//   in meeting Annex A 2022 control set obligations; the operator
//   remains responsible for the management system requirements
//   (Clauses 4-10), the Statement of Applicability, internal
//   audits, management review, and ongoing certification cycle.
//
//   For customers not pursuing ISO 27001, this framework report can
//   be ignored without consequence.
//
// AUTHORITY
//
//   International Organization for Standardization (ISO) and the
//   International Electrotechnical Commission (IEC), via Joint
//   Technical Committee 1 / Subcommittee 27 (JTC 1/SC 27). National
//   bodies (e.g., BSI in UK, DIN in Germany, ANSI in US) adopt the
//   standard nationally; accredited certification bodies (BSI, DNV,
//   Bureau Veritas, etc.) issue certifications.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   ISO/IEC 27001:2022 -- the third edition. Major changes from
//   27001:2013:
//     - Annex A reorganized from 114 controls in 14 categories to
//       93 controls in 4 themes (organizational, people, physical,
//       technological)
//     - 11 new controls introduced (e.g., A.5.7 threat intelligence,
//       A.5.23 cloud services, A.8.10 information deletion, A.8.11
//       data masking, A.8.12 data leakage prevention)
//     - Clauses 4-10 (the management system) refined with minor
//       wording changes
//
//   Transition period for certified organizations from 27001:2013
//   to 27001:2022 ended 31 October 2025; certificates against 2013
//   are no longer valid. New certifications are issued against the
//   2022 edition.
//
//   verifiedControls cover technical Annex A 2022 controls
//   (predominantly A.5 organizational with technical implementations
//   + A.8 technological). customerResponsibility covers Clauses
//   4-10 (the management system itself) + non-technical Annex A
//   controls (A.5 policy/process, A.6 people, A.7 physical, plus
//   procedural A.8 entries).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'ISO/IEC 27001:2022',
  authority: 'International Organization for Standardization / IEC (ISO/IEC JTC 1/SC 27)',
  citation: 'ISO/IEC 27001:2022 -- Information security, cybersecurity and privacy protection -- Information security management systems -- Requirements',
  verifiedControls: [
    // ── A.5 Organizational Controls (technical implementations) ─────────────
    {
      id: 'A.5.15',
      name: 'Access Control',
      check: checks.checkAccessControl,
      mapping: 'Rules to control physical and logical access to information and other associated assets. RBAC via users.role + scoped API keys; route-level authMiddleware; access decisions audit-logged.',
    },
    {
      id: 'A.5.16',
      name: 'Identity Management',
      check: checks.checkUniqueUsers,
      mapping: 'Full life cycle of identities is managed. Unique username constraint at database layer; pseudonym_uuid for analyst continuity across rotations; api_keys for programmatic identity with explicit scopes.',
    },
    {
      id: 'A.5.17',
      name: 'Authentication Information',
      check: checks.checkAuthentication,
      mapping: 'Allocation and management of authentication information controlled. JWT_SECRET-based signing; SSO via SAML/OIDC/LDAP integration_config types; bcrypt password hashing.',
    },
    {
      id: 'A.5.18',
      name: 'Access Rights',
      check: checks.checkApiKeyRotation,
      mapping: 'Access rights to information and other associated assets provisioned, reviewed, modified, removed. API key 90-day rotation cadence; USER_ROLE_CHANGED audit events; offboarding workflow handles rights removal.',
    },
    {
      id: 'A.5.21',
      name: 'Managing Information Security in the ICT Supply Chain',
      check: checks.checkIntegrationHealth,
      mapping: 'Processes and procedures defined and implemented to manage information security risks associated with the ICT products and services supply chain. integration_config enumerates all ICT supply chain elements; status field evidences ongoing health monitoring.',
    },
    {
      id: 'A.5.22',
      name: 'Monitoring, Review and Change Management of Supplier Services',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Regular monitoring, review, evaluation and change management of supplier information security practices and service delivery. last_test_at field evidences ongoing supplier review; formal vendor review (questionnaires, SOC 2 review) is operator-side.',
    },
    {
      id: 'A.5.23',
      name: 'Information Security for Use of Cloud Services',
      check: checks.checkKmsProvider,
      mapping: 'Processes for acquisition, use, management and exit from cloud services. kms_providers integration supports AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault with credential-encrypted-at-rest and last_probe_status validation.',
    },
    {
      id: 'A.5.30',
      name: 'ICT Readiness for Business Continuity',
      check: checks.checkBackupMultiDestination,
      mapping: 'ICT readiness planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements. Multi-destination backup architecture survives single-destination compromise; restore_approvals workflow tests recovery quarterly.',
    },
    // ── A.6 People Controls (technical aspect) ──────────────────────────────
    {
      id: 'A.6.7',
      name: 'Remote Working',
      check: checks.checkSessionTimeout,
      mapping: 'Security measures implemented when personnel are working remotely to protect information accessed, processed or stored outside the organization\'s premises. JWT_EXPIRY bounds remote-access session lifetime; refresh token rotation handles persistent sessions transparently.',
    },
    // ── A.8 Technological Controls ──────────────────────────────────────────
    {
      id: 'A.8.3',
      name: 'Information Access Restriction',
      check: checks.checkPrivilegedSeparation,
      mapping: 'Access to information and other associated assets restricted in accordance with the established topic-specific policy on access control. Admin role separation (admins <= 25% of active users) implements least-privilege at the role level.',
    },
    {
      id: 'A.8.5',
      name: 'Secure Authentication',
      check: checks.checkMfaEnforcement,
      mapping: 'Secure authentication technologies and procedures implemented based on information access restrictions and the topic-specific policy on access control. FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials.',
    },
    {
      id: 'A.8.7',
      name: 'Protection Against Malware',
      check: checks.checkMalwareProtection,
      mapping: 'Protection against malware implemented and supported by appropriate user awareness. malware_scanner_integrations supports 15 providers; multi-provider redundancy via priority configuration.',
    },
    {
      id: 'A.8.8',
      name: 'Management of Technical Vulnerabilities',
      check: checks.checkVulnScanning,
      mapping: 'Information about technical vulnerabilities of information systems in use obtained; the organization\'s exposure to such vulnerabilities evaluated and appropriate measures taken. Platform-side malware scanning; infrastructure-side vuln management is operator-side.',
    },
    {
      id: 'A.8.9',
      name: 'Configuration Management',
      check: checks.checkConfigLockState,
      mapping: 'Configurations, including security configurations, of hardware, software, services and networks established, documented, implemented, monitored and reviewed. Config Lock (R3e) gates platform-configuration changes in production; lock state in config_lock_state singleton.',
    },
    {
      id: 'A.8.13',
      name: 'Information Backup',
      check: checks.checkBackupFrequency,
      mapping: 'Backup copies of information, software and systems maintained and regularly tested in accordance with the agreed topic-specific policy on backup. backup_schedules drive automated execution; backup_pushes evidence recent runs; SHA-256 verification ensures integrity.',
    },
    {
      id: 'A.8.15',
      name: 'Logging',
      check: checks.checkAuditControls,
      mapping: 'Logs that record activities, exceptions, faults and other relevant events produced, stored, protected and analysed. auditMiddleware records every /api/ request; signed log batches (signLogBatch Ed25519); SIEM streaming externalizes logs.',
    },
    {
      id: 'A.8.16',
      name: 'Monitoring Activities',
      check: checks.checkLogVolumeReasonable,
      mapping: 'Networks, systems and applications monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents. Log volume monitoring detects zero-volume (logging failure) or anomalous spikes (potential incident).',
    },
    {
      id: 'A.8.20',
      name: 'Networks Security',
      check: checks.checkNetworkSegmentation,
      mapping: 'Networks and network devices secured, managed and controlled to protect information in systems and applications. Tier-1 vs Tier-3 segmentation at application layer; anti-replay middleware; reverse proxy + cloud security groups handle network-layer segmentation operator-side.',
    },
    {
      id: 'A.8.24',
      name: 'Use of Cryptography',
      check: checks.checkKeyRotation,
      mapping: 'Rules for effective use of cryptography, including cryptographic key management, defined and implemented. backup_signing_keys 180-day rotation cadence; chain_signing_keys for backup chain integrity; AES-256-GCM at rest; TLS 1.2+ in transit.',
    },
    {
      id: 'A.8.25',
      name: 'Secure Development Life Cycle',
      check: checks.checkChangeManagement,
      mapping: 'Rules for the secure development of software and systems established and applied. Anti-rollback fuse_counter enforces monotonic versioning; configuration changes audit-logged via CONFIG_UPDATED events; AGPL-3.0 source transparency.',
    },
  ],
  customerResponsibility: [
    // ── Clause 4 Context of the Organization ─────────────────────────────────
    {
      id: 'Clause 4.1',
      name: 'Understanding the Organization and Its Context',
      category: 'organizational',
      detail: 'Determine external and internal issues that are relevant to the organization\'s purpose and that affect its ability to achieve the intended outcomes of its ISMS. Document the organizational context including industry, regulatory environment, key stakeholders, and strategic objectives.',
    },
    {
      id: 'Clause 4.2',
      name: 'Understanding Needs and Expectations of Interested Parties',
      category: 'organizational',
      detail: 'Determine the interested parties relevant to the ISMS and the requirements of these interested parties (regulatory, contractual, customer, employee). Maintain a list of interested-party requirements that the ISMS must address.',
    },
    {
      id: 'Clause 4.3',
      name: 'Determining the Scope of the ISMS',
      category: 'documentation',
      detail: 'Determine the boundaries and applicability of the ISMS to establish its scope. The scope statement is required documented information; it identifies covered services, locations, technologies, and any exclusions with justification.',
    },
    {
      id: 'Clause 4.4',
      name: 'Information Security Management System',
      category: 'procedural',
      detail: 'Establish, implement, maintain and continually improve an ISMS, including the processes needed and their interactions, in accordance with the requirements of ISO 27001:2022.',
    },
    // ── Clause 5 Leadership ──────────────────────────────────────────────────
    {
      id: 'Clause 5.1',
      name: 'Leadership and Commitment',
      category: 'organizational',
      detail: 'Top management demonstrate leadership and commitment with respect to the ISMS: establish information security policy and objectives compatible with strategic direction, ensure ISMS requirements integrated into business processes, ensure resources are available, communicate the importance of effective information security management.',
    },
    {
      id: 'Clause 5.2',
      name: 'Information Security Policy',
      category: 'documentation',
      detail: 'Top management establish an information security policy that is appropriate to the purpose of the organization, includes information security objectives or framework for setting them, includes commitment to satisfy applicable requirements, and includes commitment to continual improvement. Policy is documented, communicated, and available to interested parties.',
    },
    {
      id: 'Clause 5.3',
      name: 'Organizational Roles, Responsibilities, and Authorities',
      category: 'organizational',
      detail: 'Top management ensure that responsibilities and authorities for roles relevant to information security are assigned and communicated. Document the CISO/security officer role, reporting line, and authority to make ISMS-related decisions.',
    },
    // ── Clause 6 Planning ────────────────────────────────────────────────────
    {
      id: 'Clause 6.1.2',
      name: 'Information Security Risk Assessment',
      category: 'procedural',
      detail: 'Define and apply an information security risk assessment process that establishes risk acceptance criteria, ensures repeatable results, identifies risks associated with confidentiality / integrity / availability of information, identifies risk owners, and analyses and evaluates risks. Document the methodology and results.',
    },
    {
      id: 'Clause 6.1.3 [SoA]',
      name: 'Information Security Risk Treatment + Statement of Applicability',
      category: 'documentation',
      detail: 'Apply an information security risk treatment process to select appropriate risk treatment options, determine all controls necessary, compare with Annex A. Produce a Statement of Applicability containing necessary controls and the justification for inclusions/exclusions of Annex A controls. Required documented information.',
    },
    {
      id: 'Clause 6.2',
      name: 'Information Security Objectives and Planning to Achieve Them',
      category: 'procedural',
      detail: 'Establish information security objectives at relevant functions and levels. Objectives are consistent with the information security policy, measurable, take into account applicable requirements, are monitored, communicated, and updated as appropriate.',
    },
    {
      id: 'Clause 6.3',
      name: 'Planning of Changes',
      category: 'procedural',
      detail: 'When changes to the ISMS are needed, the organization shall carry them out in a planned manner. Document change planning, risk assessment of changes, and approval process.',
    },
    // ── Clause 7 Support ─────────────────────────────────────────────────────
    {
      id: 'Clause 7.2',
      name: 'Competence',
      category: 'training',
      detail: 'Determine the necessary competence of person(s) doing work under its control that affects information security performance; ensure they are competent on the basis of education, training, or experience; take actions to acquire necessary competence; retain documented information as evidence.',
    },
    {
      id: 'Clause 7.3',
      name: 'Awareness',
      category: 'training',
      detail: 'Persons doing work under the organization\'s control are aware of the information security policy, their contribution to ISMS effectiveness including benefits of improved information security performance, and the implications of not conforming with ISMS requirements.',
    },
    {
      id: 'Clause 7.4',
      name: 'Communication',
      category: 'procedural',
      detail: 'Determine the need for internal and external communications relevant to the ISMS including on what, when, with whom, how, and who communicates. Document communications procedures for stakeholders and authorities.',
    },
    {
      id: 'Clause 7.5',
      name: 'Documented Information',
      category: 'documentation',
      detail: 'The ISMS shall include documented information required by ISO 27001 and determined by the organization as necessary for ISMS effectiveness. Control creation, updating, distribution, access, retrieval, retention and disposition of documented information.',
    },
    // ── Clause 8 Operation ──────────────────────────────────────────────────
    {
      id: 'Clause 8.1',
      name: 'Operational Planning and Control',
      category: 'procedural',
      detail: 'Plan, implement and control the processes needed to meet information security requirements and to implement the actions determined in 6.1. Implement risk treatment plan (Clause 8.3). Retain documented information to the extent necessary to have confidence that the processes have been carried out as planned.',
    },
    // ── Clause 9 Performance Evaluation ─────────────────────────────────────
    {
      id: 'Clause 9.1',
      name: 'Monitoring, Measurement, Analysis and Evaluation',
      category: 'procedural',
      detail: 'Determine what needs to be monitored and measured, including information security processes and controls; methods of monitoring, measurement, analysis and evaluation; when monitoring/measurement performed; who performs; when results analysed and evaluated.',
    },
    {
      id: 'Clause 9.2',
      name: 'Internal Audit',
      category: 'procedural',
      detail: 'Conduct internal audits at planned intervals to provide information on whether the ISMS conforms to the organization\'s own requirements and ISO 27001 requirements, and whether it is effectively implemented and maintained. Maintain an internal audit programme.',
    },
    {
      id: 'Clause 9.3',
      name: 'Management Review',
      category: 'organizational',
      detail: 'Top management review the organization\'s ISMS at planned intervals to ensure its continuing suitability, adequacy, and effectiveness. Inputs include audit results, customer feedback, achievement of objectives, nonconformities, risk assessment results, opportunities for improvement.',
    },
    // ── Clause 10 Improvement ────────────────────────────────────────────────
    {
      id: 'Clause 10.1',
      name: 'Continual Improvement',
      category: 'procedural',
      detail: 'Continually improve the suitability, adequacy and effectiveness of the ISMS. Document improvement initiatives, monitor progress, and incorporate learnings into the ISMS.',
    },
    {
      id: 'Clause 10.2',
      name: 'Nonconformity and Corrective Action',
      category: 'procedural',
      detail: 'When a nonconformity occurs, react to it and as applicable take action to control and correct it and deal with the consequences. Evaluate the need for action to eliminate causes of nonconformity. Implement action needed. Review effectiveness. Retain documented information.',
    },
    // ── Selected Annex A.5 Organizational Controls (non-technical) ──────────
    {
      id: 'A.5.1',
      name: 'Policies for Information Security',
      category: 'documentation',
      detail: 'Information security policy and topic-specific policies defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals or when significant changes occur.',
    },
    {
      id: 'A.5.7',
      name: 'Threat Intelligence',
      category: 'procedural',
      detail: 'Information relating to information security threats collected and analyzed to produce threat intelligence. Sources: open-source feeds, industry ISACs/ISAOs, paid threat intel subscriptions, internal sources. Use to inform risk assessments and control selection. New in 27001:2022.',
    },
    {
      id: 'A.5.19',
      name: 'Information Security in Supplier Relationships',
      category: 'procedural',
      detail: 'Processes and procedures defined and implemented to manage information security risks associated with the use of supplier products or services. Document supplier risk assessment methodology, security requirements per supplier tier, and ongoing review cadence.',
    },
    {
      id: 'A.5.20',
      name: 'Addressing Information Security Within Supplier Agreements',
      category: 'documentation',
      detail: 'Relevant information security requirements established and agreed with each supplier based on supplier relationships. Document security clauses in contracts including data protection, breach notification, audit rights, return/destruction of information, sub-supplier management.',
    },
    {
      id: 'A.5.34',
      name: 'Privacy and Protection of Personally Identifiable Information (PII)',
      category: 'procedural',
      detail: 'Identify and meet requirements regarding the preservation of privacy and protection of PII according to applicable laws and regulations and contractual requirements. Document privacy program; align with applicable privacy frameworks (GDPR, CCPA, etc.).',
    },
    // ── Selected Annex A.6 People Controls ──────────────────────────────────
    {
      id: 'A.6.1',
      name: 'Screening',
      category: 'procedural',
      detail: 'Background verification checks on all candidates to become personnel carried out prior to joining the organization and on an ongoing basis taking into consideration applicable laws, regulations and ethics and proportional to the business requirements, the classification of information to be accessed and the perceived risks.',
    },
    {
      id: 'A.6.3',
      name: 'Information Security Awareness, Education and Training',
      category: 'training',
      detail: 'Personnel of the organization and relevant interested parties receive appropriate information security awareness, education and training and regular updates of the organization\'s information security policy, topic-specific policies and procedures, as relevant for their job function.',
    },
    {
      id: 'A.6.8',
      name: 'Information Security Event Reporting',
      category: 'procedural',
      detail: 'Mechanism provided for personnel to report observed or suspected information security events through appropriate channels in a timely manner. Channel publicized; training on what constitutes an event and how to report; no-retaliation policy.',
    },
    // ── Selected Annex A.7 Physical Controls ────────────────────────────────
    {
      id: 'A.7.1',
      name: 'Physical Security Perimeters',
      category: 'physical',
      detail: 'Security perimeters defined and used to protect areas that contain information and other associated assets. For cloud-hosted FireAlive: covered by cloud provider\'s ISO 27001 certification and SOC 2. For self-hosted: facility perimeter (fencing, walls, access control points).',
    },
    {
      id: 'A.7.2',
      name: 'Physical Entry',
      category: 'physical',
      detail: 'Secure areas protected by appropriate entry controls and access points. Badge access; visitor logs; escort policies; tailgate prevention; surveillance at entry points.',
    },
    {
      id: 'A.7.10',
      name: 'Storage Media',
      category: 'physical',
      detail: 'Storage media managed through their life cycle of acquisition, use, transportation and disposal in accordance with the organization\'s classification scheme and handling requirements. Asset inventory; secure transit; sanitization or destruction at end-of-life.',
    },
  ],
  note: 'ISO 27001:2022 is the third edition. The transition from ISO 27001:2013 ended 31 October 2025; certificates against the 2013 edition are no longer valid. New certifications and surveillance audits are conducted against the 2022 edition. The 2022 reorganization of Annex A (from 114 controls in 14 categories to 93 controls in 4 themes) means existing 2013 Statements of Applicability must be remapped to 2022 control IDs. Eleven new controls were introduced in 2022; threat intelligence (A.5.7), cloud services (A.5.23), and data leakage prevention (A.8.12) are commonly highlighted by auditors. The Statement of Applicability remains the central artifact; auditors examine it first.',
});
