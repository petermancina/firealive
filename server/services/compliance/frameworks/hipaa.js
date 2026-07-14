// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: HIPAA
//
// R3g (v1.0.33): comprehensive HIPAA Security Rule + Breach
// Notification Rule coverage under the Shared Responsibility schema.
//
// AUTHORITY
//
//   US Department of Health and Human Services (HHS), Office for
//   Civil Rights (OCR). Enforced under HITECH Act amendments to HIPAA.
//
// SCOPE
//
//   45 CFR Parts 160 (general administrative requirements), 162
//   (administrative requirements for transactions), and 164 (security
//   and privacy of ePHI). This framework definition focuses on:
//
//     - 164.308 Administrative Safeguards
//     - 164.310 Physical Safeguards
//     - 164.312 Technical Safeguards
//     - 164.400-414 Breach Notification Rule
//
//   Privacy Rule controls (164.500-534) are not enumerated here --
//   the Security Rule is the in-scope ruleset for technical platform
//   compliance reporting. Operators handling ePHI must additionally
//   meet Privacy Rule requirements through their policies and
//   workflows; those are documented separately in their HIPAA
//   compliance program.
//
// VERIFIED VS CUSTOMER RESPONSIBILITY
//
//   verifiedControls (this file): 19 entries covering all 164.312
//   Technical Safeguards plus the 6 directly-mappable 164.308
//   Administrative Safeguards that have technical implementations
//   (audit review, access management, password management, backup
//   plan, DR plan, DR testing).
//
//   customerResponsibility (this file): 42 entries covering the
//   remaining 164.308 Administrative Safeguards, all 164.310
//   Physical Safeguards, and the 164.400-414 Breach Notification
//   Rule. These are organizational/procedural/physical/training/
//   documentation controls that the platform cannot verify on the
//   customer's behalf; they are enumerated here so an auditor or
//   operator can see the complete HIPAA compliance surface in one
//   report.
//
// ADDRESSABLE VS REQUIRED IMPLEMENTATION SPECIFICATIONS
//
//   HIPAA distinguishes "Required" (must implement) from "Addressable"
//   (must implement if reasonable and appropriate; if not, document
//   the alternative). For technical controls in this file, the
//   FireAlive platform implements both Required and Addressable
//   specifications uniformly -- treating Addressable as Required is
//   industry best practice and SOC-grade norm. The mapping field
//   notes the HIPAA classification for each control.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'HIPAA',
  authority: 'US Department of Health and Human Services, Office for Civil Rights',
  citation: '45 CFR Parts 160, 162, 164 -- Health Insurance Portability and Accountability Act, Security Rule + Breach Notification Rule',
  verifiedControls: [
    // ── 164.312 Technical Safeguards ─────────────────────────────────────────
    {
      id: '164.312(a)(1)',
      name: 'Access Control (Standard)',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role + scoped API keys. Required Standard. FireAlive enforces unique user IDs, role assignment, and per-user role audit trail (USER_ROLE_CHANGED in audit_log).',
    },
    {
      id: '164.312(a)(2)(i)',
      name: 'Unique User Identification (Required)',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at the database layer (UNIQUE on users.username). Required implementation specification under 164.312(a)(2).',
    },
    {
      id: '164.312(a)(2)(ii)',
      name: 'Emergency Access Procedure (Required)',
      check: checks.checkPrivilegedSeparation,
      mapping: 'Admin role separation supports emergency access via SoD: admins <= 25% of active users prevents standing emergency privileges; emergency access via Config Lock unlock + admin role + a WebAuthn hardware-passkey step-up. Required implementation specification.',
    },
    {
      id: '164.312(a)(2)(iii)',
      name: 'Automatic Logoff (Addressable)',
      check: checks.checkSessionTimeout,
      mapping: 'JWT_EXPIRY environment variable bounds session lifetime; SOC-grade default <= 30 minutes. Refresh token rotation handles long-running sessions transparently. Addressable specification, implemented as Required.',
    },
    {
      id: '164.312(a)(2)(iv)',
      name: 'Encryption and Decryption (Addressable)',
      check: checks.checkEncryption,
      mapping: 'TIER1_ENCRYPTION_KEY (operational data) + TIER3_ENCRYPTION_KEY (sensitive PII/PHI) -- distinct AES-256-GCM keys with tier-based segmentation. Addressable specification, implemented as Required.',
    },
    {
      id: '164.312(b)',
      name: 'Audit Controls (Standard)',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request to audit_log with user_id, action, IP, timestamp. SIEM streaming (when SIEM_ENABLED=true) provides external tamper-evident export. Required Standard.',
    },
    {
      id: '164.312(c)(1)',
      name: 'Integrity Controls (Standard)',
      check: checks.checkAuditIntegrity,
      mapping: 'audit_log is append-only by API contract (no UPDATE/DELETE endpoints expose modification); SIEM streaming exports immutable evidence to external system; signed log batches via signLogBatch (Ed25519). Required Standard.',
    },
    {
      id: '164.312(c)(2)',
      name: 'Mechanism to Authenticate ePHI (Addressable)',
      check: checks.checkAlgorithmStrength,
      mapping: 'AES-256-GCM authenticated encryption provides cryptographic integrity verification on encrypted ePHI; tampered ciphertext fails GCM tag verification at decryption time. Addressable specification, implemented as Required.',
    },
    {
      id: '164.312(d)',
      name: 'Person or Entity Authentication (Standard)',
      check: checks.checkAuthentication,
      mapping: 'JWT-based authentication with configured JWT_SECRET; SSO via SAML/OIDC/LDAP integration_config types. Required Standard.',
    },
    {
      id: '164.312(d) [MFA]',
      name: 'Multi-Factor Authentication (Industry Standard)',
      check: checks.checkMfaEnforcement,
      mapping: 'FIDO2 hardware-passkey MFA (AAL3, phishing-resistant) enforced at login via users.mfa_enrollment_required + webauthn_credentials. A user-verified hardware credential is the SOC-grade interpretation of "verify person" required by modern OCR guidance for ePHI access.',
    },
    {
      id: '164.312(e)(1)',
      name: 'Transmission Security (Standard)',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement when NODE_ENV=production via enforceMinTls middleware; mTLS on /api/internal/ routes; reverse-proxy TLS termination with operator-managed certificates. Required Standard.',
    },
    {
      id: '164.312(e)(2)(i)',
      name: 'Integrity Controls (Transmission) (Addressable)',
      check: checks.checkTlsMinVersion,
      mapping: 'TLS 1.2 minimum enforced at reverse proxy (operator-configured); TLS provides per-segment integrity via MAC authentication. Addressable specification, implemented as Required.',
    },
    {
      id: '164.312(e)(2)(ii)',
      name: 'Encryption (Transmission) (Addressable)',
      check: checks.checkEncryption,
      mapping: 'TLS 1.2+ at the reverse proxy encrypts all in-transit traffic; backup destinations support encrypted protocols (SFTP, S3/GCS/Azure with SSE). Addressable specification, implemented as Required.',
    },
    // ── 164.308 Administrative Safeguards with technical implementations ────
    {
      id: '164.308(a)(1)(ii)(D)',
      name: 'Information System Activity Review (Required)',
      check: checks.checkLogVolumeReasonable,
      mapping: 'audit_log volume monitoring detects zero-volume (logging failure) or anomalous spikes (potential incident). Required implementation specification under 164.308(a)(1).',
    },
    {
      id: '164.308(a)(4)(ii)(C)',
      name: 'Access Establishment and Modification (Addressable)',
      check: checks.checkApiKeyRotation,
      mapping: 'API key rotation (90-day SOC-grade cadence); user role changes audit-logged via USER_ROLE_CHANGED events. Addressable specification, implemented as Required.',
    },
    {
      id: '164.308(a)(5)(ii)(D)',
      name: 'Password Management (Addressable)',
      check: checks.checkPasswordPolicy,
      mapping: 'Login is a user-verified FIDO2 hardware passkey (AAL3, phishing-resistant); no password is stored, so no password-length policy applies. Addressable specification, implemented as Required.',
    },
    {
      id: '164.308(a)(7)(ii)(A)',
      name: 'Data Backup Plan (Required)',
      check: checks.checkBackupFrequency,
      mapping: 'Multi-destination backup architecture with configurable schedule via backup_schedules; recent backup_pushes confirm execution. Required implementation specification under 164.308(a)(7).',
    },
    {
      id: '164.308(a)(7)(ii)(B)',
      name: 'Disaster Recovery Plan (Required)',
      check: checks.checkBackupMultiDestination,
      mapping: 'At least two backup destinations of different adapter types prevent single-point-of-failure during disaster recovery. Required implementation specification.',
    },
    {
      id: '164.308(a)(7)(ii)(D)',
      name: 'Testing and Revision Procedures (Addressable)',
      check: checks.checkDrTestRecency,
      mapping: 'Restore approvals (status=consumed) within last 90 days evidence quarterly DR drill execution. Addressable specification, implemented as Required.',
    },
  ],
  customerResponsibility: [
    // ── 164.308 Administrative Safeguards ────────────────────────────────────
    {
      id: '164.308(a)(1)(i)',
      name: 'Security Management Process (Standard)',
      category: 'organizational',
      detail: 'Implement policies and procedures to prevent, detect, contain, and correct security violations. The covered entity must establish the overarching information security program; the platform supports this through audit logging, incident response infrastructure, and access controls but cannot define the program itself.',
    },
    {
      id: '164.308(a)(1)(ii)(A)',
      name: 'Risk Analysis (Required)',
      category: 'procedural',
      detail: 'Conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI. Document risk analysis methodology, scope, findings, and treatment plans. OCR enforces strict risk-analysis requirements; insufficient risk analysis is the single most-cited HIPAA violation.',
    },
    {
      id: '164.308(a)(1)(ii)(B)',
      name: 'Risk Management (Required)',
      category: 'procedural',
      detail: 'Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level. Track risk treatment decisions; document accepted residual risks; review and update risk management decisions annually or upon material change.',
    },
    {
      id: '164.308(a)(1)(ii)(C)',
      name: 'Sanction Policy (Required)',
      category: 'procedural',
      detail: 'Apply appropriate sanctions against workforce members who fail to comply with the security policies and procedures of the covered entity. Document the sanction policy, communicate it to workforce, and apply consistently. Sanctions must be documented in HR records.',
    },
    {
      id: '164.308(a)(2)',
      name: 'Assigned Security Responsibility (Standard)',
      category: 'organizational',
      detail: 'Identify the security official who is responsible for the development and implementation of the policies and procedures required by the Security Rule. Designate by name, role, and contact information; document in policy. Single point of accountability is required.',
    },
    {
      id: '164.308(a)(3)(i)',
      name: 'Workforce Security (Standard)',
      category: 'organizational',
      detail: 'Implement policies and procedures to ensure that all members of the workforce have appropriate access to ePHI and to prevent those workforce members who do not have access from obtaining access.',
    },
    {
      id: '164.308(a)(3)(ii)(A)',
      name: 'Authorization and/or Supervision (Addressable)',
      category: 'procedural',
      detail: 'Implement procedures for the authorization and/or supervision of workforce members who work with ePHI or in locations where it might be accessed. Document the approval workflow for ePHI access.',
    },
    {
      id: '164.308(a)(3)(ii)(B)',
      name: 'Workforce Clearance Procedure (Addressable)',
      category: 'procedural',
      detail: 'Implement procedures to determine that the access of a workforce member to ePHI is appropriate. Background checks and reference verification proportional to role sensitivity.',
    },
    {
      id: '164.308(a)(3)(ii)(C)',
      name: 'Termination Procedures (Addressable)',
      category: 'procedural',
      detail: 'Implement procedures for terminating access to ePHI when employment ends or when there is no further need. The platform supports offboarding (active=0 soft delete), but the procedural trigger -- knowing when to deactivate -- is operator-side.',
    },
    {
      id: '164.308(a)(4)(i)',
      name: 'Information Access Management (Standard)',
      category: 'procedural',
      detail: 'Implement policies and procedures for authorizing access to ePHI consistent with the Privacy Rule. Define the access-granting workflow and document approvals.',
    },
    {
      id: '164.308(a)(4)(ii)(A)',
      name: 'Isolating Healthcare Clearinghouse Functions (Required)',
      category: 'procedural',
      detail: 'If healthcare clearinghouse functions are part of a larger organization, implement policies and procedures to protect ePHI from unauthorized access by the larger organization. Network and access segmentation is operator-managed.',
    },
    {
      id: '164.308(a)(4)(ii)(B)',
      name: 'Access Authorization (Addressable)',
      category: 'procedural',
      detail: 'Implement policies and procedures for granting access to ePHI through access to a workstation, transaction, program, process, or other mechanism. Document the access-request and approval process.',
    },
    {
      id: '164.308(a)(5)(i)',
      name: 'Security Awareness and Training (Standard)',
      category: 'training',
      detail: 'Implement a security awareness and training program for all members of the workforce (including management). Annual training is the SOC-grade norm; document attendance and content updates.',
    },
    {
      id: '164.308(a)(5)(ii)(A)',
      name: 'Security Reminders (Addressable)',
      category: 'training',
      detail: 'Periodic security reminders distributed to the workforce. Phishing simulations, posters, email reminders, and brown-bag sessions are common implementations.',
    },
    {
      id: '164.308(a)(5)(ii)(B)',
      name: 'Protection from Malicious Software (Addressable)',
      category: 'procedural',
      detail: 'Procedures for guarding against, detecting, and reporting malicious software. The platform supports malware scanning integration (15 providers); operator establishes endpoint AV/EDR coverage across the workforce.',
    },
    {
      id: '164.308(a)(5)(ii)(C)',
      name: 'Log-in Monitoring (Addressable)',
      category: 'procedural',
      detail: 'Procedures for monitoring log-in attempts and reporting discrepancies. The platform logs all auth attempts (auth_log table); operator establishes the review cadence and escalation process for anomalies.',
    },
    {
      id: '164.308(a)(6)(i)',
      name: 'Security Incident Procedures (Standard)',
      category: 'procedural',
      detail: 'Implement policies and procedures to address security incidents. Document the incident response process; the platform supports IR plan storage (ir_policies table) but the policies themselves are operator-authored.',
    },
    {
      id: '164.308(a)(6)(ii)',
      name: 'Response and Reporting (Required)',
      category: 'procedural',
      detail: 'Identify and respond to suspected or known security incidents; mitigate harmful effects; document incidents and outcomes. Document the response in your incident tracking system.',
    },
    {
      id: '164.308(a)(7)(i)',
      name: 'Contingency Plan (Standard)',
      category: 'procedural',
      detail: 'Establish (and implement as needed) policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI. Operator authors the contingency plan; platform provides backup/restore infrastructure.',
    },
    {
      id: '164.308(a)(7)(ii)(C)',
      name: 'Emergency Mode Operation Plan (Required)',
      category: 'procedural',
      detail: 'Procedures to enable continuation of critical business processes for protection of ePHI security while operating in emergency mode. Document the emergency-mode access procedures.',
    },
    {
      id: '164.308(a)(7)(ii)(E)',
      name: 'Applications and Data Criticality Analysis (Addressable)',
      category: 'procedural',
      detail: 'Assess the relative criticality of specific applications and data in support of other contingency-plan components. Document criticality rankings for ePHI systems and their dependencies.',
    },
    {
      id: '164.308(a)(8)',
      name: 'Evaluation (Standard)',
      category: 'procedural',
      detail: 'Periodic technical and non-technical evaluation, based initially upon the standards implemented under this rule and subsequently in response to environmental or operational changes affecting the security of ePHI. Annual external audit is the SOC-grade norm.',
    },
    {
      id: '164.308(b)(1)',
      name: 'Business Associate Contracts (Standard)',
      category: 'documentation',
      detail: 'Obtain satisfactory assurances that the business associate will appropriately safeguard ePHI. Maintain executed BAAs with every business associate (cloud providers, MSPs, software vendors that process ePHI on your behalf).',
    },
    {
      id: '164.308(b)(3)',
      name: 'Written Contract or Other Arrangement (Required)',
      category: 'documentation',
      detail: 'The contract or other arrangement between the covered entity and the business associate must meet the applicable requirements of 164.314(a). Use HHS template BAA or attorney-reviewed equivalent.',
    },
    // ── 164.310 Physical Safeguards ──────────────────────────────────────────
    {
      id: '164.310(a)(1)',
      name: 'Facility Access Controls (Standard)',
      category: 'physical',
      detail: 'Limit physical access to electronic information systems and the facility or facilities in which they are housed, while ensuring that properly authorized access is allowed. Badge access, visitor logs, locked server rooms, surveillance. For cloud-hosted FireAlive: covered by the cloud provider\'s SOC 2 Type II.',
    },
    {
      id: '164.310(a)(2)(i)',
      name: 'Contingency Operations (Addressable)',
      category: 'procedural',
      detail: 'Procedures that allow facility access in support of restoration of lost data under the disaster recovery plan and emergency mode operations plan. Document facility access procedures for emergency restoration personnel.',
    },
    {
      id: '164.310(a)(2)(ii)',
      name: 'Facility Security Plan (Addressable)',
      category: 'documentation',
      detail: 'Policies and procedures to safeguard the facility and the equipment therein from unauthorized physical access, tampering, and theft. Document the facility security plan; for cloud deployments, reference the cloud provider\'s facility security documentation.',
    },
    {
      id: '164.310(a)(2)(iii)',
      name: 'Access Control and Validation Procedures (Addressable)',
      category: 'physical',
      detail: 'Procedures to control and validate a person\'s access to facilities based on their role or function. Visitor management, escort policies, multi-zone access. Cloud providers handle this for cloud-hosted FireAlive.',
    },
    {
      id: '164.310(a)(2)(iv)',
      name: 'Maintenance Records (Addressable)',
      category: 'documentation',
      detail: 'Policies and procedures to document repairs and modifications to the physical components of a facility that are related to security (e.g., hardware, walls, doors, and locks). Maintenance logs retained per retention policy.',
    },
    {
      id: '164.310(b)',
      name: 'Workstation Use (Standard)',
      category: 'procedural',
      detail: 'Policies and procedures that specify the proper functions to be performed, the manner in which those functions are to be performed, and the physical attributes of the surroundings of a specific workstation or class of workstations that can access ePHI. Workstation use policy in employee handbook.',
    },
    {
      id: '164.310(c)',
      name: 'Workstation Security (Standard)',
      category: 'physical',
      detail: 'Physical safeguards for all workstations that access ePHI to restrict access to authorized users. Endpoint encryption (FileVault/BitLocker), automatic screen lock, MDM enrollment, anti-theft measures.',
    },
    {
      id: '164.310(d)(1)',
      name: 'Device and Media Controls (Standard)',
      category: 'physical',
      detail: 'Policies and procedures that govern the receipt and removal of hardware and electronic media that contain ePHI into and out of a facility, and the movement of these items within the facility. Asset inventory and chain-of-custody tracking.',
    },
    {
      id: '164.310(d)(2)(i)',
      name: 'Disposal (Required)',
      category: 'procedural',
      detail: 'Policies and procedures to address the final disposition of ePHI, and/or the hardware or electronic media on which it is stored. Cryptographic erasure or physical destruction; certificates of destruction retained.',
    },
    {
      id: '164.310(d)(2)(ii)',
      name: 'Media Re-use (Required)',
      category: 'procedural',
      detail: 'Procedures for removal of ePHI from electronic media before the media are made available for re-use. NIST SP 800-88-compliant sanitization.',
    },
    {
      id: '164.310(d)(2)(iii)',
      name: 'Accountability (Addressable)',
      category: 'documentation',
      detail: 'Maintain a record of the movements of hardware and electronic media and any person responsible therefore. Asset transfer logs in IT inventory system.',
    },
    {
      id: '164.310(d)(2)(iv)',
      name: 'Data Backup and Storage (Addressable)',
      category: 'procedural',
      detail: 'Create a retrievable, exact copy of ePHI, when needed, before movement of equipment. The platform supports backup creation; operator schedules pre-movement backups and verifies retrievability.',
    },
    // ── 164.400-414 Breach Notification Rule ─────────────────────────────────
    {
      id: '164.404',
      name: 'Notification to Individuals (Required)',
      category: 'procedural',
      detail: 'Notify each individual whose unsecured PHI has been, or is reasonably believed to have been, accessed, acquired, used, or disclosed as a result of a breach. Notification within 60 calendar days of discovery; specific content requirements (description, types of info, steps to protect, contact info).',
    },
    {
      id: '164.406',
      name: 'Notification to the Media (Required)',
      category: 'procedural',
      detail: 'For breaches affecting more than 500 residents of a State or jurisdiction, notify prominent media outlets serving the affected State or jurisdiction. Same 60-day deadline as individual notification.',
    },
    {
      id: '164.408',
      name: 'Notification to the Secretary (Required)',
      category: 'procedural',
      detail: 'Notify the HHS Secretary of breaches via the OCR breach portal. For breaches affecting 500+ individuals: within 60 days. For breaches affecting <500: annual log submission within 60 days of year end.',
    },
    {
      id: '164.410',
      name: 'Notification by Business Associate (Required)',
      category: 'procedural',
      detail: 'A business associate must notify the covered entity following the discovery of a breach. Generally within 60 calendar days; BAA may require shorter timelines. Document the BA notification process in your BAA.',
    },
    {
      id: '164.412',
      name: 'Law Enforcement Delay (Standard)',
      category: 'procedural',
      detail: 'If a law enforcement official determines that notification would impede a criminal investigation or cause damage to national security, the covered entity may delay notification. Document the law enforcement request and the delay period.',
    },
    {
      id: '164.414',
      name: 'Administrative Requirements and Burden of Proof (Required)',
      category: 'documentation',
      detail: 'Maintain documentation that all required notifications were made or that an exception applies. Burden of proof for non-notification (e.g., low probability of compromise risk assessment) rests with the covered entity. Retain breach documentation for 6 years.',
    },
  ],
  note: 'HIPAA is one of the most enforced US federal privacy regimes; OCR conducts random audits and follow-on investigations after breach reports. The 6-year documentation retention requirement is longer than the SOC 2 industry-standard 7-year retention; operators should provision audit_log storage and policy-document storage accordingly. Operators handling ePHI must additionally comply with the Privacy Rule (164.500-534), which is not enumerated in this framework definition because it is workflow-and-disclosure-focused rather than technical-control-focused.',
});
