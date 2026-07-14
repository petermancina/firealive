// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: FISMA / NIST SP 800-53 Rev 5
//
// R3g (v1.0.33): comprehensive Federal Information Security
// Modernization Act coverage via the NIST SP 800-53 Rev 5 control
// catalog. FISMA is the statutory framework; NIST 800-53 is the
// implementing control catalog.
//
// APPLICABILITY
//
//   FISMA applies to US federal information systems and to
//   information systems operated by contractors on behalf of federal
//   agencies. The scope extends to:
//     - Federal agency information systems
//     - Cloud services used by federal agencies (via FedRAMP
//       authorization, which is FISMA + 800-53 + cloud-specific
//       controls)
//     - Contractor systems processing, storing, or transmitting
//       federal information
//
//   FireAlive is NOT a federal information system, NOT a FedRAMP-
//   authorized cloud service, and NOT automatically scoped by
//   FISMA. FISMA does not name FireAlive nor any class to which
//   FireAlive belongs as required to undergo FISMA assessment.
//
//   This framework definition is provided as a service to customers
//   that ARE federal agencies, federal contractors handling federal
//   information, or organizations subject to FISMA-derived
//   requirements (e.g., state agencies adopting NIST 800-53 by
//   reference, defense industrial base contractors under CMMC which
//   uses 800-171 derived from 800-53). For such customers,
//   FireAlive\'s technical controls support compliance with the
//   technical control families (AC, AU, CM, IA, IR, SC, SI, etc.);
//   the customer\'s Authorization to Operate (ATO) process,
//   continuous monitoring, and agency-level governance remain their
//   responsibility.
//
//   For non-federal-sector customers, this framework report can be
//   ignored without consequence. FedRAMP authorization is a
//   separate, more rigorous process for cloud providers serving
//   federal customers; this framework definition does not constitute
//   a FedRAMP package.
//
// AUTHORITY
//
//   US Office of Management and Budget (OMB) oversees FISMA
//   implementation across executive branch agencies. NIST publishes
//   the SP 800-series guidance including 800-53 (control catalog),
//   800-53A (assessment procedures), 800-37 (Risk Management
//   Framework), and 800-171 (Controlled Unclassified Information).
//
//   The Cybersecurity and Infrastructure Security Agency (CISA)
//   provides operational guidance and binding operational
//   directives. Agency Chief Information Security Officers (CISOs)
//   are responsible for agency-level FISMA compliance.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   NIST SP 800-53 Rev 5 (September 2020), the current revision.
//   Rev 5 introduced significant changes from Rev 4:
//     - Privacy controls integrated with security controls (single
//       catalog instead of separate Appendix J)
//     - Supply chain risk management family (SR) added
//     - PII processing and transparency family (PT) added
//     - Control outcomes refocused (more outcome-oriented language)
//     - Federated structure: controls applicable to systems,
//       organizations, and individuals
//
//   verifiedControls cover the technical control families with
//   platform implementation: AC, AU, CM, CP, IA, IR, SC, SI, SR
//   (selected high-value controls). customerResponsibility covers
//   the procedural / programmatic / personnel families: AT, CA, CP,
//   IR (programmatic side), MP, PE, PL, PM, PS, RA, SA, SR
//   (programmatic side).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'FISMA / NIST SP 800-53 Rev 5',
  authority: 'US Office of Management and Budget / National Institute of Standards and Technology',
  citation: 'Federal Information Security Modernization Act of 2014 (44 U.S.C. § 3551 et seq.) implemented via NIST Special Publication 800-53 Revision 5',
  verifiedControls: [
    // ── AC Access Control ───────────────────────────────────────────────────
    {
      id: 'AC-2',
      name: 'Account Management',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint at database layer; pseudonym_uuid for analyst identity continuity; api_keys for programmatic identities. Account lifecycle (creation, modification, disabling, deletion) audit-logged via USER_CREATED / USER_ROLE_CHANGED / USER_DEACTIVATED events.',
    },
    {
      id: 'AC-3',
      name: 'Access Enforcement',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware enforces access decisions; api_keys.scopes provides programmatic-access granularity.',
    },
    {
      id: 'AC-6',
      name: 'Least Privilege',
      check: checks.checkPrivilegedSeparation,
      mapping: 'Admin role separation (admins <= 25% of active users) implements AC-6 at the role level; separation of duties enforced through role-vs-Config-Lock attribution check.',
    },
    {
      id: 'AC-7',
      name: 'Unsuccessful Logon Attempts',
      check: checks.checkAccountLockout,
      mapping: 'apiLimiter (express-rate-limit) provides rate-based protection (1000 req / 15 min hardcoded); auth_log tracks failed-login attempts via action LIKE "%FAIL%" for downstream IP-blocking integration.',
    },
    {
      id: 'AC-11',
      name: 'Session Lock',
      check: checks.checkSessionTimeout,
      mapping: 'JWT_EXPIRY environment variable bounds session lifetime; SOC-grade default <= 30 minutes meets AC-11 session-lock expectation.',
    },
    {
      id: 'AC-17',
      name: 'Remote Access',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement when NODE_ENV=production via enforceMinTls middleware; TLS 1.2+ at reverse proxy; mTLS on /api/internal/ routes. Remote-access protection through encrypted transport.',
    },
    // ── AU Audit and Accountability ─────────────────────────────────────────
    {
      id: 'AU-2',
      name: 'Event Logging',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request to audit_log; SIEM streaming (CEF format) externalizes events for AU-2 organization-wide event-correlation requirements.',
    },
    {
      id: 'AU-3',
      name: 'Content of Audit Records',
      check: checks.checkAuditControls,
      mapping: 'Each audit_log entry includes timestamp, user_id, event_type, action detail, source IP. AU-3(1) extended content (associated user identity, type of event, source location) is fully captured.',
    },
    {
      id: 'AU-9',
      name: 'Protection of Audit Information',
      check: checks.checkAuditIntegrity,
      mapping: 'audit_log append-only by API contract (no UPDATE/DELETE endpoints expose modification); SIEM streaming creates tamper-evident external copy; signed log batches via Ed25519 (signLogBatch).',
    },
    {
      id: 'AU-11',
      name: 'Audit Record Retention',
      check: checks.checkAuditRetention,
      mapping: 'audit_log is unbounded (no auto-truncation); operator provisions storage to align with FISMA / agency retention policy (typically 3-7 years for federal contexts).',
    },
    {
      id: 'AU-12',
      name: 'Audit Record Generation',
      check: checks.checkLogVolumeReasonable,
      mapping: 'Log volume monitoring detects zero-volume (logging failure -- AU-5 alert condition) or anomalous spikes (potential incident or runaway process). Generation is structurally enforced via auditMiddleware.',
    },
    // ── CM Configuration Management ─────────────────────────────────────────
    {
      id: 'CM-3',
      name: 'Configuration Change Control',
      check: checks.checkChangeManagement,
      mapping: 'Anti-rollback fuse_counter in system_meta plus package.json fuseCounter validation; CONFIG_UPDATED audit events; AGPL-3.0 source transparency. Configuration changes are tracked and reviewable.',
    },
    {
      id: 'CM-5',
      name: 'Access Restrictions for Change',
      check: checks.checkConfigLockState,
      mapping: 'Config Lock (R3e v1.0.32) gates platform-configuration changes in production; requires unlock + admin role + a fresh user-verified WebAuthn hardware-passkey step-up. Lock state and lock attribution tracked in config_lock_state singleton.',
    },
    {
      id: 'CM-7',
      name: 'Least Functionality',
      check: checks.checkSecureBaseline,
      mapping: 'NODE_ENV=production activates secure-baseline elements: enforceMinTls, mTLS on internal routes, production error handling, hardened security headers. Non-production functionality (verbose error messages, dev endpoints) deactivated.',
    },
    // ── CP Contingency Planning ─────────────────────────────────────────────
    {
      id: 'CP-9',
      name: 'System Backup',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules drive automated execution; backup_pushes evidence recent runs with SHA-256 verification. CP-9 backup requirements satisfied with daily or more frequent automated backups.',
    },
    {
      id: 'CP-10',
      name: 'System Recovery and Reconstitution',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination backup architecture (local + S3/GCS/Azure/SFTP combinations) supports CP-10 recovery from single-destination failure; restore_approvals workflow with second-person approval prevents unauthorized recovery.',
    },
    // ── IA Identification and Authentication ────────────────────────────────
    {
      id: 'IA-2',
      name: 'Identification and Authentication (Organizational Users)',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with JWT_SECRET signing; SSO via SAML/OIDC/LDAP integration_config types. IA-2(1) MFA for privileged accounts requires checkMfaEnforcement (see below).',
    },
    {
      id: 'IA-2(1)',
      name: 'MFA for Privileged Accounts',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials. IA-2(1) explicitly requires MFA for privileged accounts; FireAlive enforces a hardware passkey for all roles including admins.',
    },
    {
      id: 'IA-5',
      name: 'Authenticator Management',
      check: checks.checkPasswordPolicy,
      mapping: '12-character minimum password length hardcoded in server/routes/password.js; bcrypt hashing with platform-configured cost factor. IA-5(1) password-based authentication minimum length requirement satisfied.',
    },
    // ── IR Incident Response ────────────────────────────────────────────────
    {
      id: 'IR-4',
      name: 'Incident Handling',
      check: checks.checkIrPlanExists,
      mapping: 'ir_policies table stores IR plans + scenario playbooks; sla_config tracks MTTA/MTTR commitments; notification channels deliver alerts to designated responders.',
    },
    {
      id: 'IR-6',
      name: 'Incident Reporting',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery. Federal incident reporting (1-hour USCERT notification under OMB M-21-31) is operator-side workflow.',
    },
    // ── SC System and Communications Protection ─────────────────────────────
    {
      id: 'SC-7',
      name: 'Boundary Protection',
      check: checks.checkSystemBoundaries,
      mapping: 'integration_config enumerates external system boundaries; status field evidences operational state. Boundary protection at the network layer (firewalls, security groups) is operator-managed at the cloud or data-center level.',
    },
    {
      id: 'SC-8',
      name: 'Transmission Confidentiality and Integrity',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement when NODE_ENV=production; TLS 1.2+ at reverse proxy; mTLS on /api/internal/. TLS provides both confidentiality (encryption) and integrity (MAC) per SC-8(1).',
    },
    {
      id: 'SC-12',
      name: 'Cryptographic Key Establishment and Management',
      check: checks.checkKeyRotation,
      mapping: 'backup_signing_keys 180-day rotation cadence; chain_signing_keys for backup chain integrity; kms_providers integration with AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault for hardware-backed key custody.',
    },
    {
      id: 'SC-13',
      name: 'Cryptographic Protection',
      check: checks.checkAlgorithmStrength,
      mapping: 'AES-256-GCM authenticated encryption at rest; FIPS 140-3 compatible algorithms; cipher selection meets SC-13 cryptographic-protection requirement.',
    },
    {
      id: 'SC-28',
      name: 'Protection of Information at Rest',
      check: checks.checkEncryption,
      mapping: 'TIER1/TIER3 encryption keys (distinct) provide tier-based segmentation; AES-256-GCM at rest. SC-28(1) cryptographic protection of information at rest is satisfied.',
    },
    // ── SI System and Information Integrity ─────────────────────────────────
    {
      id: 'SI-2',
      name: 'Flaw Remediation',
      check: checks.checkPatchManagement,
      mapping: 'Anti-rollback fuse_counter enforces monotonic version increment; startup integrity check rejects rollback attempts. Operator handles infrastructure-side patch management via their patch-management program.',
    },
    {
      id: 'SI-3',
      name: 'Malicious Code Protection',
      check: checks.checkMalwareProtection,
      mapping: 'malware_scanner_integrations supports 15 providers (ClamAV, VirusTotal, CrowdStrike, Microsoft Defender, etc.); multi-provider redundancy via priority configuration.',
    },
    {
      id: 'SI-4',
      name: 'System Monitoring',
      check: checks.checkAnomalyDetection,
      mapping: 'bandwidthMonitor middleware detects bandwidth spikes; apiLimiter rate limiting; SIEM streaming enables external correlation analytics. SI-4(2) automated tools and mechanisms requirement supported.',
    },
    {
      id: 'SI-7',
      name: 'Software, Firmware, Information Integrity',
      check: checks.checkIntegrityVerification,
      mapping: 'Startup integrity check verifies package.json fuseCounter matches system_meta; SKIP_INTEGRITY_CHECK env var must NOT be "true" in production. Integrity failures fail loudly with process exit.',
    },
    // ── SR Supply Chain Risk Management ─────────────────────────────────────
    {
      id: 'SR-3',
      name: 'Supply Chain Controls and Processes',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config enumerates supply chain elements (cloud providers, SaaS, software dependencies); last_test_at evidences ongoing monitoring. SR-3 organization-defined supply chain protection methods supported.',
    },
    {
      id: 'SR-5',
      name: 'Acquisition Strategies, Tools, and Methods',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Every configured integration has at least one operational test recorded; formal supply-chain risk review (SOC 2 reports, attestations, supplier risk assessments) is operator-side documentation.',
    },
  ],
  customerResponsibility: [
    // ── AT Awareness and Training ────────────────────────────────────────────
    {
      id: 'AT-1',
      name: 'Policy and Procedures',
      category: 'documentation',
      detail: 'Develop, document, and disseminate awareness and training policy and procedures consistent with applicable federal laws, executive orders, directives, regulations, policies, standards, and guidelines.',
    },
    {
      id: 'AT-2',
      name: 'Literacy Training and Awareness',
      category: 'training',
      detail: 'Provide security and privacy literacy training to system users (employees, contractors, others) as part of initial training, when required by system changes, and at least annually.',
    },
    {
      id: 'AT-3',
      name: 'Role-Based Training',
      category: 'training',
      detail: 'Provide role-based security and privacy training to personnel with assigned security and privacy roles. Topics: practical exercises in system development, system administration, incident response, system management.',
    },
    {
      id: 'AT-4',
      name: 'Training Records',
      category: 'documentation',
      detail: 'Document and monitor information security and privacy training activities. Retain individual training records for a defined period; provide records to auditors during FISMA assessment.',
    },
    // ── CA Assessment, Authorization, and Monitoring ────────────────────────
    {
      id: 'CA-2',
      name: 'Control Assessments',
      category: 'procedural',
      detail: 'Select an appropriate assessor or assessment team; develop a control assessment plan; ensure assessment is independent. Assess the security and privacy controls in the system and its environment annually and as part of continuous monitoring.',
    },
    {
      id: 'CA-5',
      name: 'Plan of Action and Milestones (POA&M)',
      category: 'procedural',
      detail: 'Develop a plan of action and milestones for the system to document the planned remedial actions to correct weaknesses or deficiencies. Update POA&M based on findings from assessments, security impact analyses, and continuous monitoring.',
    },
    {
      id: 'CA-6',
      name: 'Authorization to Operate (ATO)',
      category: 'documentation',
      detail: 'Assign senior official as the authorizing official; ensure authorizing official authorizes the system prior to commencing operations. ATO documentation includes the System Security Plan (SSP), Security Assessment Report (SAR), POA&M.',
    },
    // ── CP Contingency Planning (programmatic) ──────────────────────────────
    {
      id: 'CP-2',
      name: 'Contingency Plan',
      category: 'documentation',
      detail: 'Develop a contingency plan identifying essential missions and business functions and associated contingency requirements; recovery objectives, restoration priorities, and metrics; contingency roles and responsibilities. Address loss of operational capability and a clear path to restoration.',
    },
    {
      id: 'CP-3',
      name: 'Contingency Training',
      category: 'training',
      detail: 'Provide contingency training to personnel consistent with assigned roles and responsibilities within 10 days of assuming a contingency role or responsibility, when required by system changes, and at least annually.',
    },
    {
      id: 'CP-4',
      name: 'Contingency Plan Testing',
      category: 'procedural',
      detail: 'Test the contingency plan for the system using defined tests at the defined frequency (typically annually); review the contingency plan test results; initiate corrective actions, if needed.',
    },
    // ── IR Incident Response (programmatic) ─────────────────────────────────
    {
      id: 'IR-2',
      name: 'Incident Response Training',
      category: 'training',
      detail: 'Provide incident response training to system users consistent with assigned roles and responsibilities. Training updated within defined timeframes and at defined frequency.',
    },
    {
      id: 'IR-3',
      name: 'Incident Response Testing',
      category: 'procedural',
      detail: 'Test the effectiveness of the incident response capability for the system at defined frequency using defined tests. Document the results; initiate corrective actions, if needed.',
    },
    {
      id: 'IR-8',
      name: 'Incident Response Plan',
      category: 'documentation',
      detail: 'Develop an incident response plan that provides the organization with a roadmap for implementing its incident response capability. Distribute copies to defined incident response personnel; update post-test/post-incident; protect from unauthorized disclosure.',
    },
    // ── MP Media Protection ─────────────────────────────────────────────────
    {
      id: 'MP-2',
      name: 'Media Access',
      category: 'physical',
      detail: 'Restrict access to defined types of digital and non-digital media to authorized individuals using defined security measures. For cloud-hosted FireAlive: media protection delegated to cloud provider FedRAMP authorization.',
    },
    {
      id: 'MP-6',
      name: 'Media Sanitization',
      category: 'procedural',
      detail: 'Sanitize defined media prior to disposal, release out of organizational control, or release for reuse using defined sanitization techniques and procedures in accordance with applicable federal and organizational standards (NIST SP 800-88).',
    },
    // ── PE Physical and Environmental Protection ────────────────────────────
    {
      id: 'PE-2',
      name: 'Physical Access Authorizations',
      category: 'physical',
      detail: 'Develop, approve, and maintain a list of individuals with authorized access to the facility where the system resides; issue authorization credentials; review the list quarterly; remove from the list when access is no longer required.',
    },
    {
      id: 'PE-3',
      name: 'Physical Access Control',
      category: 'physical',
      detail: 'Enforce physical access authorizations at facility entry/exit points; maintain physical access audit logs for entry points; control access to areas within the facility designated as publicly accessible; escort visitors and monitor visitor activity.',
    },
    // ── PL Planning ──────────────────────────────────────────────────────────
    {
      id: 'PL-2',
      name: 'System Security and Privacy Plans',
      category: 'documentation',
      detail: 'Develop security and privacy plans for the system that are consistent with the organization\'s enterprise architecture; explicitly define the constituent system components; describe the operational environment; provide the security categorization. Distribute copies to defined personnel and update at defined frequency.',
    },
    {
      id: 'PL-4',
      name: 'Rules of Behavior',
      category: 'documentation',
      detail: 'Establish and provide to individuals requiring access to the system, the rules that describe responsibilities and expected behavior for information and system usage, security, and privacy. Receive a documented acknowledgment from such individuals.',
    },
    // ── PM Program Management ────────────────────────────────────────────────
    {
      id: 'PM-2',
      name: 'Information Security Program Leadership Role',
      category: 'organizational',
      detail: 'Appoint a senior agency information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program. (Federal designation: CISO or equivalent.)',
    },
    {
      id: 'PM-9',
      name: 'Risk Management Strategy',
      category: 'organizational',
      detail: 'Develop a comprehensive strategy to manage security, privacy, and supply chain risks associated with operating and using the system; implement the risk management strategy consistently across the organization; review and update the strategy at defined frequency.',
    },
    // ── PS Personnel Security ───────────────────────────────────────────────
    {
      id: 'PS-3',
      name: 'Personnel Screening',
      category: 'procedural',
      detail: 'Screen individuals prior to authorizing access to the system; rescreen individuals at defined intervals in accordance with defined conditions. For federal contractors: align with E-Verify and security clearance requirements as applicable.',
    },
    {
      id: 'PS-4',
      name: 'Personnel Termination',
      category: 'procedural',
      detail: 'Upon termination of individual employment, disable system access within defined time period; terminate or revoke any authenticators or credentials; conduct exit interviews including security debriefing; retrieve all property; retain access to organizational information.',
    },
    {
      id: 'PS-7',
      name: 'External Personnel Security',
      category: 'procedural',
      detail: 'Establish personnel security requirements (including security roles and responsibilities) for external providers; require external providers to comply with personnel security policies; document personnel security requirements; require notification of personnel transfers or terminations.',
    },
    // ── RA Risk Assessment ──────────────────────────────────────────────────
    {
      id: 'RA-3',
      name: 'Risk Assessment',
      category: 'procedural',
      detail: 'Conduct a risk assessment, including: identifying threats to and vulnerabilities in the system, determining the likelihood and magnitude of harm. Integrate risk assessment results and risk management decisions from the organization and mission/business processes. Document and review at defined frequency.',
    },
    {
      id: 'RA-5',
      name: 'Vulnerability Monitoring and Scanning',
      category: 'procedural',
      detail: 'Monitor and scan for vulnerabilities in the system and hosted applications at defined frequency and randomly in accordance with defined process. Implement vulnerability remediation procedures; share information obtained from vulnerability monitoring activities.',
    },
    // ── SA System and Services Acquisition ───────────────────────────────────
    {
      id: 'SA-9',
      name: 'External System Services',
      category: 'documentation',
      detail: 'Require that providers of external system services comply with organizational security and privacy requirements and employ defined security controls; define and document organization-managed roles and responsibilities with regard to external system services. FireAlive itself qualifies as an external system service in this sense for federal customers.',
    },
    // ── SR Supply Chain (programmatic) ──────────────────────────────────────
    {
      id: 'SR-2',
      name: 'Supply Chain Risk Management Plan',
      category: 'documentation',
      detail: 'Develop a plan for managing supply chain risks associated with the research and development, design, manufacturing, acquisition, delivery, integration, operations and maintenance, and disposal of the system. Update the plan at defined frequency.',
    },
  ],
  note: 'FISMA Modernization Act of 2014 succeeded FISMA 2002. NIST SP 800-53 Rev 5 (Sep 2020) is the current revision; Rev 4 is no longer current. FedRAMP authorization (for cloud services serving federal agencies) is a separate, more rigorous process built on 800-53 plus FedRAMP-specific controls; this framework definition does not constitute a FedRAMP package. CMMC (Cybersecurity Maturity Model Certification) for the Defense Industrial Base uses NIST 800-171, which is a subset of 800-53 tailored for non-federal systems handling Controlled Unclassified Information; CMMC compliance can leverage many of the same technical controls. Federal Information Processing Standards (FIPS) categorize systems as Low / Moderate / High impact; controls are tailored accordingly. The Authorization to Operate (ATO) is the central artifact and is owned by the agency authorizing official.',
});
