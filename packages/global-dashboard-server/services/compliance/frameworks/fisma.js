// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: FISMA / NIST SP 800-53 Rev 5
//
// R3g PR2 (v1.0.33): GD-side FISMA / NIST SP 800-53 Rev 5 coverage
// under the Shared Responsibility schema. GD-side counterpart to MC
// PR1's frameworks/fisma.js. Same metadata, same citation, same
// customerResponsibility list (NIST control families are
// NIST-defined and framework-level not platform-specific); adapted
// verifiedControls for the GD's surface.
//
// APPLICABILITY (per Foundational Rule 16)
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
//   uses 800-171 derived from 800-53). For such customers, the GD\'s
//   technical controls support compliance with the technical control
//   families (AC, AU, CM, IA, IR, SC, SI, SR) at the governance /
//   cross-region aggregation tier; the customer\'s Authorization to
//   Operate (ATO) process, continuous monitoring, and agency-level
//   governance remain their responsibility.
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
      mapping: 'Unique username constraint at database layer (UNIQUE on users.username); MC-trust api_keys (management_consoles.api_key) for programmatic identities authenticating inbound pushes. Account lifecycle (creation, modification, deactivation via users.active=0) audit-logged via the request-logging middleware. Analyst-identity continuity (pseudonym_uuid) is enforced at the MC layer.',
    },
    {
      id: 'AC-3',
      name: 'Access Enforcement',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware enforces access decisions with role-array gating on every /api route; MC-trust api_keys provide programmatic access scoping for inbound MC pushes.',
    },
    {
      id: 'AC-6',
      name: 'Least Privilege',
      check: checks.checkPrivilegedSeparation,
      mapping: 'SoD model for the GD: 1-2 CISO-role users provides least-privilege; new users default to readonly tier unless explicitly promoted. authMiddleware role-array gating implements per-route least-privilege.',
    },
    {
      id: 'AC-7',
      name: 'Unsuccessful Logon Attempts',
      check: checks.checkAccountLockout,
      mapping: 'apiLimiter (express-rate-limit) provides rate-based protection (1000 req / 15 min hardcoded); auth_log tracks failed-login attempts (action = LOGIN_FAILED) for downstream IP-blocking integration at the reverse proxy or WAF layer.',
    },
    {
      id: 'AC-11',
      name: 'Session Lock',
      check: checks.checkSessionTimeout,
      mapping: 'JWT expiresIn hardcoded "8h" on the GD matches CISO operational rhythm but exceeds the AC-11 / SOC-grade 30-minute norm. For shorter idle timeouts in federal contexts, reverse-proxy session cookies with shorter TTL are operator-managed.',
    },
    {
      id: 'AC-17',
      name: 'Remote Access',
      check: checks.checkTransmission,
      mapping: 'TLS termination at the reverse proxy (operator-managed nginx / Caddy / cloud load balancer); reject plaintext HTTP at the proxy. The GD has no application-layer HTTPS enforcement as of v0.0.31. Remote-access protection through encrypted transport is reverse-proxy responsibility.',
    },
    // ── AU Audit and Accountability ─────────────────────────────────────────
    {
      id: 'AU-2',
      name: 'Event Logging',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware records every /api request (except /api/health) to audit_log with user_id, event_type, detail, ip, severity, timestamp. SIEM streaming for external correlation lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship.',
    },
    {
      id: 'AU-3',
      name: 'Content of Audit Records',
      check: checks.checkAuditControls,
      mapping: 'Each audit_log entry includes timestamp, user_id, event_type, detail, ip, severity. AU-3(1) extended content (associated user identity, type of event, source location) is captured.',
    },
    {
      id: 'AU-9',
      name: 'Protection of Audit Information',
      check: checks.checkAuditIntegrity,
      mapping: 'audit_log append-only by API contract (no UPDATE or DELETE routes expose modification). Cryptographic hash chain (SHA-256 hash + prev_hash columns) lands in B5a (v1.0.50); when shipped, the check verifies chain integrity by walking it linearly. External tamper-evident copy via SIEM streaming awaits integration_config + B3.',
    },
    {
      id: 'AU-11',
      name: 'Audit Record Retention',
      check: checks.checkAuditRetention,
      mapping: 'audit_log retention is unbounded (no auto-truncation; storage-capacity-limited at GD_DB_PATH). Operator provisions storage to align with FISMA / agency retention policy (typically 3-7 years for federal contexts).',
    },
    {
      id: 'AU-12',
      name: 'Audit Record Generation',
      check: checks.checkLogVolumeReasonable,
      mapping: 'Log volume monitoring detects zero-volume (logging failure -- AU-5 alert condition) or anomalous spikes (potential incident or DoS). Generation is structurally enforced via the request-logging middleware.',
    },
    // ── CM Configuration Management ─────────────────────────────────────────
    {
      id: 'CM-3',
      name: 'Configuration Change Control',
      check: checks.checkChangeManagement,
      mapping: 'system_meta.fuse_counter tracks platform version (seeded by db-init.js); CONFIG_UPDATED audit events emitted by PUT /api/config/:key; AGPL-3.0 source transparency. Configuration changes are tracked and reviewable. Future GD startup-verifier phase will add boot-time fuse-vs-package integrity check.',
    },
    {
      id: 'CM-5',
      name: 'Access Restrictions for Change',
      check: checks.checkConfigLockState,
      mapping: 'GD Config Lock server-side persistence is live (the config_lock_state singleton; the config-write chokepoint refuses writes while the GD is locked). Unlock requires a fresh hardware-passkey assertion (a UV step-up), the GD twin of the MC R3e v1.0.32 config-lock and hardened beyond the MC TOTP-MFA unlock. Configuration-change discipline is additionally backed by route-middleware role gating (CISO-only writes).',
    },
    {
      id: 'CM-7',
      name: 'Least Functionality',
      check: checks.checkSecureBaseline,
      mapping: 'NODE_ENV=production is set for industry convention but has no in-platform gated behavior on the GD as of v0.0.31 (no enforceMinTls, no production-mode error handling, no mTLS on /api/internal/ routes, no /api/internal/ routes at all). Secure-baseline elements (HTTPS, error sanitization, network isolation) are entirely operator-managed at the reverse-proxy / deployment layer.',
    },
    // ── CP Contingency Planning ─────────────────────────────────────────────
    {
      id: 'CP-9',
      name: 'System Backup',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules drive automated execution; backups table records completed backups with SHA-256 integrity hash and timestamp; POST /api/backups/trigger bootstraps a manual backup. CP-9 backup requirements satisfied with daily or more frequent automated backups.',
    },
    {
      id: 'CP-10',
      name: 'System Recovery and Reconstitution',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination resilience via active backup_schedules pointing to different destination values supports CP-10 recovery from single-destination failure. Note: GD has no in-platform restore workflow as of v0.0.31; second-person approval and recovery testing are off-platform discipline until a future restore-workflow phase ships.',
    },
    // ── IA Identification and Authentication ────────────────────────────────
    {
      id: 'IA-2',
      name: 'Identification and Authentication (Organizational Users)',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with operator-configured GD_JWT_SECRET. SSO via SAML / OIDC / LDAP planned for B5b (v1.0.51); until then, authentication is a FIDO2 hardware passkey. IA-2(1) MFA for privileged accounts requires checkMfaEnforcement (see below).',
    },
    {
      id: 'IA-2(1)',
      name: 'MFA for Privileged Accounts',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant): login refuses a session without a user-verified hardware passkey in webauthn_credentials. IA-2(1) explicitly requires MFA for privileged accounts; real verification lands in a future MFA-hardening pass.',
    },
    {
      id: 'IA-5',
      name: 'Authenticator Management',
      check: checks.checkPasswordPolicy,
      mapping: 'GD is passwordless -- login is a FIDO2 hardware passkey (B5n3), so there is no password to gate and no MIN_PASSWORD_LENGTH policy applies; the credential-strength control is the phishing-resistant hardware key. Operator-managed discipline: provision strong passwords at account creation; a future GD enhancement may add a password-policy endpoint.',
    },
    // ── IR Incident Response ────────────────────────────────────────────────
    {
      id: 'IR-4',
      name: 'Incident Handling',
      check: checks.checkIrPlanExists,
      mapping: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO / governance-tier incident response planning is operator-managed off-platform. notification_config provides delivery channels for threshold-based alerts.',
    },
    {
      id: 'IR-6',
      name: 'Incident Reporting',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. Federal incident reporting (1-hour USCERT notification under OMB M-21-31) is operator-managed off-platform workflow.',
    },
    // ── SC System and Communications Protection ─────────────────────────────
    {
      id: 'SC-7',
      name: 'Boundary Protection',
      check: checks.checkSystemBoundaries,
      mapping: 'Layer 1 (current): management_consoles enumerates the connected MCs (the GD\'s primary third-party data sources). Layer 2 (post-B5b v1.0.51 et seq.): integration_config will enumerate external system boundaries. Network-layer boundary protection (firewalls, security groups) is operator-managed at the cloud or data-center level.',
    },
    {
      id: 'SC-8',
      name: 'Transmission Confidentiality and Integrity',
      check: checks.checkTransmission,
      mapping: 'TLS termination at the reverse proxy (operator-managed); TLS 1.2+ minimum. GD has no application-layer HTTPS enforcement and no mTLS on /api/internal/ (no /api/internal/ routes exist on the GD). TLS provides both confidentiality (encryption) and integrity (MAC) per SC-8(1) at the reverse-proxy layer.',
    },
    {
      id: 'SC-12',
      name: 'Cryptographic Key Establishment and Management',
      check: checks.checkKeyRotation,
      mapping: 'GD_JWT_SECRET rotation is operator-managed (quarterly cadence recommended; restart invalidates all existing JWTs). MC-trust api_keys rotate per 90-day cadence. Backup-signing-key registries (backup_signing_keys, chain_signing_keys) await future GD backup-signing phase; R3g PR3 adds signing_keys for MC-push verification. Hardware-backed KMS integration awaits future GD KMS phase.',
    },
    {
      id: 'SC-13',
      name: 'Cryptographic Protection',
      check: checks.checkAlgorithmStrength,
      mapping: 'HMAC-SHA256 for JWT signing (GD_JWT_SECRET, 32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). The GD-layer cryptographic surface is narrower than the MC (which encrypts analyst-data tiers with AES-256-GCM). FIPS 140-3 compatible algorithms are used; FIPS-validated cryptographic modules at the deployment layer are operator-managed.',
    },
    {
      id: 'SC-28',
      name: 'Protection of Information at Rest',
      check: checks.checkEncryption,
      mapping: 'GD has no application-layer at-rest encryption as of v0.0.31. Data-at-rest protection is filesystem-level on the SQLite database file at GD_DB_PATH (operator-managed disk encryption: LUKS / FileVault / BitLocker / AWS EBS encryption). SC-28(1) cryptographic protection of information at rest is satisfied at the OS/volume layer; application-layer encryption awaits a future GD KMS integration phase.',
    },
    // ── SI System and Information Integrity ─────────────────────────────────
    {
      id: 'SI-2',
      name: 'Flaw Remediation',
      check: checks.checkPatchManagement,
      mapping: 'system_meta.fuse_counter tracks platform version. package.json now carries a fuseCounter field (added in B6a); there is still no startup integrity check comparing the manifest fuse to system_meta.fuse_counter (planned for a future GD startup-verifier phase). Host OS / Node.js runtime / dependency patching is operator-managed via the customer\'s patch-management program; npm audit / Snyk / Dependabot in CI is the SOC-grade norm.',
    },
    {
      id: 'SI-3',
      name: 'Malicious Code Protection',
      check: checks.checkMalwareProtection,
      mapping: 'The GD now has an in-platform host/endpoint EDR seam (the malware_scanner_integrations registry — eleven providers, credentials AES-256-GCM-encrypted), additive on top of the in-platform runtime-monitor baseline. By design the GD still does not process uploaded files from analysts; file-content scanning at the analyst-data layer is enforced at the MC. Host-level antivirus on the GD server OS (Microsoft Defender / ClamAV / CrowdStrike Falcon agent / similar) remains operator-managed defense-in-depth.',
    },
    {
      id: 'SI-4',
      name: 'System Monitoring',
      check: checks.checkAnomalyDetection,
      mapping: 'apiLimiter (express-rate-limit, 1000 req/15min per IP) provides rate-limit anomaly detection; auth_log records LOGIN_FAILED events for IP-pattern-based anomaly review. B3 (v1.0.48) wires runtime monitoring with anomaly detection on aggregate metrics streams from MCs. SI-4(2) automated tools and mechanisms requirement supported via apiLimiter + future B3 wiring.',
    },
    {
      id: 'SI-7',
      name: 'Software, Firmware, Information Integrity',
      check: checks.checkIntegrityVerification,
      mapping: 'GD has no startup integrity verifier as of v0.0.31 (no SKIP_INTEGRITY_CHECK env var consumption; no release-manifest.json comparison at boot). A future GD buildout phase will add a manifest-based verifier (release-manifest.json shipping with each release; boot-time SHA-256 comparison against index.js / db-init.js / package.json). Until then, deployment-time integrity is operator-managed.',
    },
    // ── SR Supply Chain Risk Management ─────────────────────────────────────
    {
      id: 'SR-3',
      name: 'Supply Chain Controls and Processes',
      check: checks.checkIntegrationHealth,
      mapping: 'Layer 1 (current): management_consoles enumerates the connected MCs (the GD\'s primary supply-chain entries) with last_sync timestamps. Layer 2 (post-B5b v1.0.51): integration_config will enumerate SOAR / SIEM / cloud / IAM vendor integrations with last_test_at fields.',
    },
    {
      id: 'SR-5',
      name: 'Acquisition Strategies, Tools, and Methods',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Each active MC documented with country and regulatory_framework on management_consoles. Layer 2 (post-B5b) adds integration_config last_test_at baseline operational evidence. Formal supply-chain risk review (SOC 2 reports, attestations, supplier risk assessments) is operator-side documentation.',
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
      detail: 'Assign senior official as the authorizing official; ensure authorizing official authorizes the system prior to commencing operations. ATO documentation includes the System Security Plan (SSP), Security Assessment Report (SAR), POA&M. If the GD is in scope, both governance-tier and analyst-tier (MC) layers should be documented in the SSP with separate security categorizations.',
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
      detail: 'Test the contingency plan for the system using defined tests at the defined frequency (typically annually); review the contingency plan test results; initiate corrective actions, if needed. Note: GD-side recovery testing is currently off-platform discipline.',
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
      detail: 'Develop an incident response plan that provides the organization with a roadmap for implementing its incident response capability. Distribute copies to defined incident response personnel; update post-test/post-incident; protect from unauthorized disclosure. GD-layer IR scenarios to address: GD compromise, GD database corruption, suspicious aggregate metrics from an MC, MC api_key compromise.',
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
      detail: 'Appoint a senior agency information security officer with the mission and resources to coordinate, develop, implement, and maintain an organization-wide information security program. (Federal designation: CISO or equivalent.) On the GD, the senior CISO-role user maps naturally to this role for the agency\'s GD instance.',
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
      detail: 'Upon termination of individual employment, disable system access within defined time period; terminate or revoke any authenticators or credentials; conduct exit interviews including security debriefing; retrieve all property; retain access to organizational information. On the GD: PATCH /api/users/:id with active=0 is the technical mechanism; the procedural trigger is operator-side.',
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
  note: 'FISMA Modernization Act of 2014 succeeded FISMA 2002. NIST SP 800-53 Rev 5 (Sep 2020) is the current revision; Rev 4 is no longer current. FedRAMP authorization (for cloud services serving federal agencies) is a separate, more rigorous process built on 800-53 plus FedRAMP-specific controls; this framework definition does not constitute a FedRAMP package. CMMC (Cybersecurity Maturity Model Certification) for the Defense Industrial Base uses NIST 800-171, which is a subset of 800-53 tailored for non-federal systems handling Controlled Unclassified Information; CMMC compliance can leverage many of the same technical controls. Federal Information Processing Standards (FIPS) categorize systems as Low / Moderate / High impact; controls are tailored accordingly. The Authorization to Operate (ATO) is the central artifact and is owned by the agency authorizing official. The GD\'s role in a federal ATO scope is the governance / cross-region aggregation tier; if the analyst-data MC layer is also in scope, both layers should be documented in the SSP with separate security categorizations.',
});
