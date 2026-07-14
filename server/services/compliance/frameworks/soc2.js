// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: SOC 2 Type II
//
// R3g (v1.0.33): comprehensive SOC 2 Trust Services Criteria coverage
// under the Shared Responsibility schema, covering the Security
// (Common Criteria, mandatory), Availability, and Confidentiality
// trust services categories.
//
// AUTHORITY
//
//   American Institute of Certified Public Accountants (AICPA).
//   SOC 2 reports are issued by independent CPA firms; AICPA owns
//   and updates the Trust Services Criteria.
//
// SCOPE
//
//   AICPA TSP Section 100, Trust Services Criteria for Security,
//   Availability, Processing Integrity, Confidentiality, and
//   Privacy (2022 Points of Focus).
//
//   This framework definition covers:
//     - CC (Common Criteria / Security): mandatory in every SOC 2
//     - A1 (Availability): SaaS / service-platform standard add-on
//     - C1 (Confidentiality): designated confidential information
//
//   NOT covered in this framework definition:
//     - PI1 (Processing Integrity): typically pursued by transaction-
//       processing entities (financial reconciliation, payment
//       processing). Operators pursuing PI1 must define their own
//       processing-integrity controls beyond the platform scope.
//     - P (Privacy): GDPR/CCPA/LGPD frameworks (commits 19, 26, 27)
//       cover privacy controls in their respective regulatory
//       contexts. Operators pursuing SOC 2 Privacy must enumerate
//       privacy commitments in their privacy notice and map them
//       to TSP P1.0-P8.0 separately.
//
// SOC 2 TYPE II VS TYPE I
//
//   SOC 2 Type I evaluates control design at a point in time.
//   SOC 2 Type II evaluates operating effectiveness over a period
//   (typically 6-12 months). Type II is the report customers and
//   procurement teams expect; Type I is a precursor or initial
//   audit. This framework definition supports both.
//
// AUDIT WINDOW AND EVIDENCE RETENTION
//
//   SOC 2 Type II audit windows are typically 6 months (initial)
//   or 12 months (subsequent). The 7-year evidence retention norm
//   exceeds typical regulatory requirements -- plan audit_log
//   capacity accordingly.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'SOC 2 Type II',
  authority: 'American Institute of Certified Public Accountants (AICPA)',
  citation: 'Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (AICPA TSP Section 100)',
  verifiedControls: [
    // ── CC6 Logical and Physical Access Controls ─────────────────────────────
    {
      id: 'CC6.1',
      name: 'Logical Access Software',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware gates; scoped API keys (api_keys table) for programmatic access. Each access decision is recorded in audit_log.',
    },
    {
      id: 'CC6.2',
      name: 'New User Registration and Authorization',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at database layer; admin-only user creation endpoint; new-user provisioning audit-logged via USER_CREATED events.',
    },
    {
      id: 'CC6.3',
      name: 'Access Modification and Removal',
      check: checks.checkApiKeyRotation,
      mapping: 'API key 90-day rotation cadence; user role changes audit-logged via USER_ROLE_CHANGED; offboarding workflow (active=0 soft delete) preserves audit trail. Access modifications are tracked end-to-end.',
    },
    {
      id: 'CC6.6',
      name: 'External User Access',
      check: checks.checkBoundaries,
      mapping: 'Tier-1/Tier-3 data classification with API-layer boundary enforcement; integration_config types track all external system connections; scoped API keys for partner/external programmatic access.',
    },
    {
      id: 'CC6.7',
      name: 'Transmission and Disposal Restrictions',
      check: checks.checkTransmission,
      mapping: 'HTTPS enforcement via enforceMinTls middleware (NODE_ENV=production); TLS 1.2+ at reverse proxy; mTLS on /api/internal/ routes; backup destination transmission encrypted (SFTP, S3/GCS/Azure SSE).',
    },
    {
      id: 'CC6.8',
      name: 'Malicious Software Prevention',
      check: checks.checkMalwareProtection,
      mapping: 'malware_scanner_integrations supports 15 providers (ClamAV, VirusTotal, CrowdStrike, Microsoft Defender, plus 11 more). Operator-configured priority for multi-provider redundancy.',
    },
    // ── CC7 System Operations ────────────────────────────────────────────────
    {
      id: 'CC7.1',
      name: 'Vulnerability Detection',
      check: checks.checkVulnScanning,
      mapping: 'Platform-side malware scanning via malware_scanner_integrations; infrastructure-side vuln scanning (Nessus/Qualys/OpenVAS/Trivy) is operator-side per Shared Responsibility. C2 phase will add in-platform infrastructure vuln scanning.',
    },
    {
      id: 'CC7.2',
      name: 'System Monitoring',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request; SIEM streaming (CEF format) provides external correlation when SIEM_ENABLED=true; runtime metrics endpoint for operational visibility.',
    },
    {
      id: 'CC7.3',
      name: 'Anomaly Detection and Evaluation',
      check: checks.checkAnomalyDetection,
      mapping: 'bandwidthMonitor middleware detects bandwidth spikes; apiLimiter rate limiting; anti-rollback fuse integrity check; account review schedules. Anomalies trigger notifications via configured channels.',
    },
    {
      id: 'CC7.4',
      name: 'Incident Response',
      check: checks.checkIrPlanExists,
      mapping: 'ir_policies table stores incident response plans + scenario playbooks; sla_config tracks MTTA / MTTR commitments per priority; notification channels (email, SMS, webhook, PagerDuty) deliver incident alerts.',
    },
    {
      id: 'CC7.5',
      name: 'Recovery and Restoration',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination backup architecture (local + S3 / GCS / Azure / SFTP combinations); restore_approvals workflow with second-person approval; SHA-256 verification on restored data.',
    },
    // ── CC8 Change Management ────────────────────────────────────────────────
    {
      id: 'CC8.1',
      name: 'Change Management Process',
      check: checks.checkChangeManagement,
      mapping: 'Anti-rollback fuse_counter in system_meta + package.json fuseCounter (mismatch fails startup); audit_log records every configuration change via CONFIG_UPDATED / *_CONFIG_UPDATED events; AGPL-3.0 source transparency for code-level changes.',
    },
    {
      id: 'CC8.1 [Config Lock]',
      name: 'Configuration Change Restriction',
      check: checks.checkConfigLockState,
      mapping: 'Config Lock (R3e v1.0.32) gates platform-configuration changes in production; requires unlock + admin role + a fresh user-verified WebAuthn hardware-passkey step-up to modify. Lock state tracked in config_lock_state singleton.',
    },
    // ── CC9 Risk Mitigation ──────────────────────────────────────────────────
    {
      id: 'CC9.1',
      name: 'Risk Mitigation Activities',
      check: checks.checkBackups,
      mapping: 'Multi-destination backups, encryption tiering, anti-replay middleware, Config Lock, MFA enforcement, KMS provider integration -- defense-in-depth approach to risk mitigation across categories.',
    },
    {
      id: 'CC9.2',
      name: 'Vendor and Business Partner Management',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config tracks all vendor integrations (SOAR, SIEM, ticketing, IAM, cloud, malware scanners, KMS providers); status / last_test_at fields evidence ongoing vendor monitoring.',
    },
    {
      id: 'CC9.2 [Risk Assessment]',
      name: 'Vendor Risk Assessment',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Every configured vendor integration has at least one operational test recorded; operator completes formal vendor risk review (vendor SOC 2, DPA, questionnaire) externally as customer-responsibility.',
    },
    // ── A1 Availability ──────────────────────────────────────────────────────
    {
      id: 'A1.2',
      name: 'Environmental Threats and Backup',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules + backup_pushes track automated backup execution; multi-destination architecture survives single-destination failure; recent backup_pushes.status=succeeded evidences operational backups.',
    },
    {
      id: 'A1.3',
      name: 'Recovery Testing',
      check: checks.checkDrTestRecency,
      mapping: 'restore_approvals.status=consumed within last 90 days evidences quarterly DR drill execution; SOC-grade norm is at-least-quarterly testing; auditor will examine restore_approvals records.',
    },
    // ── C1 Confidentiality ───────────────────────────────────────────────────
    {
      id: 'C1.1',
      name: 'Confidential Information Identification',
      check: checks.checkDataClassification,
      mapping: 'users.tier classification (Tier-1 operational / Tier-2 moderate / Tier-3 sensitive PII/wellbeing) drives encryption-key segmentation and access boundary enforcement.',
    },
    {
      id: 'C1.2',
      name: 'Confidential Information Disposal',
      check: checks.checkRetentionPolicy,
      mapping: 'storage_destinations.retention_days enforces destination-side pruning; offboarding workflow (active=0 + pseudonym rotation) implements right-to-erasure for analyst data; audit trail preserved separately for compliance retention.',
    },
  ],
  customerResponsibility: [
    // ── CC1 Control Environment ──────────────────────────────────────────────
    {
      id: 'CC1.1',
      name: 'Board Oversight and Governance Commitment',
      category: 'organizational',
      detail: 'Demonstrate a commitment to integrity and ethical values from the top. Board (or equivalent governance body) reviews and approves the information security program; board minutes evidence oversight cadence.',
    },
    {
      id: 'CC1.2',
      name: 'Board Independence and Risk Oversight',
      category: 'organizational',
      detail: 'Board exercises independent oversight of management. Document board independence (composition, charters), risk-committee structure, and information-security reporting cadence to the board.',
    },
    {
      id: 'CC1.3',
      name: 'Organizational Structure and Reporting Lines',
      category: 'organizational',
      detail: 'Establish structures, reporting lines, and appropriate authorities and responsibilities in pursuit of objectives. Document the org chart, security organization, and escalation paths.',
    },
    {
      id: 'CC1.4',
      name: 'Personnel Competence',
      category: 'organizational',
      detail: 'Demonstrate a commitment to attract, develop, and retain competent individuals in alignment with objectives. Document hiring criteria, training programs, performance reviews, and succession planning for security-critical roles.',
    },
    {
      id: 'CC1.5',
      name: 'Personnel Accountability',
      category: 'organizational',
      detail: 'Hold individuals accountable for their internal control responsibilities. Performance evaluations include security-objective performance; sanction policy documented and applied consistently.',
    },
    // ── CC2 Communication and Information ────────────────────────────────────
    {
      id: 'CC2.1',
      name: 'Quality of Information',
      category: 'procedural',
      detail: 'Obtain or generate and use relevant, quality information to support the functioning of internal control. Document information sources, validation procedures, and quality-assurance processes.',
    },
    {
      id: 'CC2.2',
      name: 'Internal Communication of Controls',
      category: 'procedural',
      detail: 'Internally communicate information, including objectives and responsibilities for internal control. Maintain a current security policy library accessible to all personnel; require periodic acknowledgment.',
    },
    {
      id: 'CC2.3',
      name: 'External Communication',
      category: 'procedural',
      detail: 'Communicate with external parties regarding matters affecting the functioning of internal control. Customer-facing security commitments (SLAs, security pages), regulator notifications, incident communications.',
    },
    // ── CC3 Risk Assessment ──────────────────────────────────────────────────
    {
      id: 'CC3.1',
      name: 'Risk Assessment Objectives',
      category: 'procedural',
      detail: 'Specify objectives with sufficient clarity to enable identification and assessment of risks. Document the risk-assessment scope, objectives, and methodology in a written risk-assessment procedure.',
    },
    {
      id: 'CC3.2',
      name: 'Risk Identification and Analysis',
      category: 'procedural',
      detail: 'Identify risks to the achievement of objectives across the entity and analyze risks as a basis for determining how risks should be managed. Risk register with severity, likelihood, and treatment plans.',
    },
    {
      id: 'CC3.3',
      name: 'Fraud Risk Consideration',
      category: 'procedural',
      detail: 'Consider the potential for fraud in assessing risks. Document fraud-risk assessment for in-scope processes (e.g., privileged-access abuse, financial reporting if applicable).',
    },
    {
      id: 'CC3.4',
      name: 'Significant Change Risk',
      category: 'procedural',
      detail: 'Identify and assess changes that could significantly impact the system of internal control. New product launches, regulatory changes, major vendor changes, key-personnel departures trigger re-assessment.',
    },
    // ── CC4 Monitoring Activities ────────────────────────────────────────────
    {
      id: 'CC4.1',
      name: 'Ongoing and Separate Evaluations',
      category: 'procedural',
      detail: 'Select, develop, and perform ongoing and/or separate evaluations to ascertain whether the components of internal control are present and functioning. Periodic internal audits, control self-assessments, automated monitoring.',
    },
    {
      id: 'CC4.2',
      name: 'Communication of Deficiencies',
      category: 'procedural',
      detail: 'Evaluate and communicate internal control deficiencies in a timely manner to those parties responsible for taking corrective action. Tracking system for control gaps, remediation plans, and follow-up validation.',
    },
    // ── CC5 Control Activities ──────────────────────────────────────────────
    {
      id: 'CC5.1',
      name: 'Risk Mitigation Control Selection',
      category: 'procedural',
      detail: 'Select and develop control activities that contribute to the mitigation of risks to the achievement of objectives to acceptable levels. Mapping of risks-to-controls; control owners; effectiveness review.',
    },
    {
      id: 'CC5.3',
      name: 'Policy Deployment',
      category: 'documentation',
      detail: 'Deploy control activities through policies that establish what is expected and procedures that put policies into action. Written security policies, approved by management, communicated to workforce, reviewed annually.',
    },
    // ── CC6 Physical Access (CC6.4) ─────────────────────────────────────────
    {
      id: 'CC6.4',
      name: 'Physical Access Controls',
      category: 'physical',
      detail: 'Restrict physical access to facilities and protected information assets to authorized personnel. For cloud-hosted FireAlive: covered by the cloud provider\'s SOC 2 Type II (request from vendor). For self-hosted: badge access, locked server rooms, visitor logs.',
    },
    {
      id: 'CC6.5',
      name: 'Logical and Physical Access Removal',
      category: 'procedural',
      detail: 'Discontinue logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished. Termination workflow triggers offboarding (platform-side) + facility-access revocation (operator-side).',
    },
    // ── CC9 Vendor Management (procedural side) ─────────────────────────────
    {
      id: 'CC9.2 [Vendor SOC 2 Collection]',
      name: 'Vendor SOC 2 Report Review',
      category: 'documentation',
      detail: 'Collect and review SOC 2 Type II reports (or equivalent) from each in-scope vendor. Document review findings; track CUEC (complementary user entity controls) and incorporate into your control set. Annual cadence at minimum.',
    },
    // ── Availability (A1.1) ──────────────────────────────────────────────────
    {
      id: 'A1.1',
      name: 'Capacity Planning',
      category: 'procedural',
      detail: 'Manage processing capacity and usage to achieve availability commitments. Document capacity planning methodology, monitoring of utilization trends, and procurement triggers for scaling.',
    },
    // ── Confidentiality (C1.x procedural side) ──────────────────────────────
    {
      id: 'C1.1 [Designation]',
      name: 'Designation of Confidential Information',
      category: 'documentation',
      detail: 'Identify and maintain confidential information to meet the entity\'s objectives related to confidentiality. Document what constitutes "confidential" in your context (customer PII, employee wellbeing data, trade secrets, etc.).',
    },
    // ── Cross-cutting customer responsibilities ─────────────────────────────
    {
      id: 'Security Awareness Training',
      name: 'Workforce Security Training Program',
      category: 'training',
      detail: 'Provide initial and recurring security awareness training to all workforce. SOC 2 auditors examine training completion records; annual cadence is the standard expectation. Track attendance, content, and acknowledgments.',
    },
    {
      id: 'Vendor Management Procedures',
      name: 'Vendor Onboarding and Monitoring Procedures',
      category: 'procedural',
      detail: 'Document the vendor onboarding workflow: risk assessment, contract execution with security commitments (BAAs, DPAs, security exhibits), ongoing monitoring (re-evaluation cadence, off-cycle triggers).',
    },
    {
      id: 'Change Management Policy',
      name: 'Change Management Policy and Procedures',
      category: 'documentation',
      detail: 'Document the change management process: change request submission, risk review, approval gates, testing requirements, deployment procedures, post-deployment validation, rollback procedures.',
    },
    {
      id: 'Incident Response Procedures',
      name: 'Incident Response Procedures (Operator Authored)',
      category: 'procedural',
      detail: 'Author the incident-response policies the platform stores. Define incident severity classification, escalation procedures, communication templates, regulator notification timing, post-incident review process.',
    },
    {
      id: 'Risk Assessment Cadence',
      name: 'Risk Assessment Annual Refresh',
      category: 'procedural',
      detail: 'Refresh the enterprise risk assessment at least annually. Document the methodology, scope, findings, and treatment decisions. Auditor will request the most-recent risk assessment as evidence.',
    },
    {
      id: 'Background Checks',
      name: 'Personnel Background Checks',
      category: 'procedural',
      detail: 'Conduct background checks on personnel with access to in-scope systems, proportional to the sensitivity of the access. Document background-check procedures and exception handling.',
    },
    {
      id: 'Segregation of Duties',
      name: 'Segregation of Duties Policy',
      category: 'procedural',
      detail: 'Define segregation of duties for sensitive functions (e.g., the person who initiates a change cannot approve it; the person who configures Config Lock cannot also unlock and modify). Document the role/function matrix.',
    },
  ],
  note: 'SOC 2 Type II audit windows are typically 6-12 months. Auditor independence is paramount; do not engage your CPA firm for both attestation and remediation consulting. The 7-year evidence retention norm exceeds typical regulatory minimums -- plan audit_log capacity accordingly. The Trust Services Criteria were last updated in 2022; verify your auditor uses the current version. For SaaS platforms, the typical SOC 2 scope is Security + Availability + Confidentiality; Processing Integrity is typically pursued only by transaction-processing entities; Privacy is typically pursued separately or via GDPR/CCPA-aligned controls.',
});
