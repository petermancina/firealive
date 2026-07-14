// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: SOC 2 Type II
//
// R3g PR2 (v1.0.33): GD-side SOC 2 Trust Services Criteria coverage
// under the Shared Responsibility schema, covering Security (Common
// Criteria, mandatory), Availability, and Confidentiality categories.
// GD-side counterpart to MC PR1's frameworks/soc2.js. Same metadata,
// same citation, same customerResponsibility list (framework-level
// facts), adapted verifiedControls for GD's surface (governance-tier
// aggregator with smaller in-platform feature set than the MC).
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
//       processing entities. The GD aggregates governance-tier metrics
//       and does not perform transaction processing.
//     - P (Privacy): GDPR/CCPA/LGPD frameworks in this same library
//       cover privacy controls in their respective regulatory contexts.
//
// APPLICABILITY (per Foundational Rule 16)
//
//   FireAlive itself may or may not pursue SOC 2 attestation; this
//   framework definition is provided as a service to operators
//   running FireAlive who themselves seek SOC 2 attestation. The
//   GD's compliance posture supports the operator's overall SOC 2
//   scope at the governance / cross-region aggregation layer; the
//   MC layer (and its compliance reports) covers analyst-level
//   operational data.
//
// SOC 2 TYPE II VS TYPE I
//
//   SOC 2 Type I evaluates control design at a point in time.
//   SOC 2 Type II evaluates operating effectiveness over a period
//   (typically 6-12 months). This framework definition supports both.
//
// AUDIT WINDOW AND EVIDENCE RETENTION
//
//   SOC 2 Type II audit windows are typically 6 months (initial)
//   or 12 months (subsequent). The 7-year evidence retention norm
//   exceeds typical regulatory requirements -- plan audit_log
//   capacity on the GD\'s SQLite file accordingly.
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
      mapping: 'Role-based access control via users.role (ciso / vp / readonly); route-level authMiddleware gates with role-array checks on every /api route; MC-trust api_keys (management_consoles.api_key) for inbound MC push authentication. Each authenticated request recorded in audit_log via the request-logging middleware.',
    },
    {
      id: 'CC6.2',
      name: 'New User Registration and Authorization',
      check: checks.checkUniqueUsers,
      mapping: 'Unique username constraint enforced at the database layer (UNIQUE on users.username); CISO-only user creation endpoint; account creation logged via the request-logging middleware in audit_log.',
    },
    {
      id: 'CC6.3',
      name: 'Access Modification and Removal',
      check: checks.checkApiKeyRotation,
      mapping: 'MC-trust api_key 90-day rotation cadence (management_consoles.api_key re-registered via PATCH /api/management-consoles/:id); user role and active-status changes audit-logged via CONFIG_UPDATED events; offboarding workflow (users.active=0) preserves audit trail. R3g PR3 introduces signing_keys registry supplementing api_key shared-secret authentication.',
    },
    {
      id: 'CC6.6',
      name: 'External User Access',
      check: checks.checkBoundaries,
      mapping: 'GD\'s external-user surface is the connected MCs (management_consoles table); each MC pushes aggregate metrics inbound on its api_key. Per Foundational Rule 20, GD never writes back to MC state — MCs are pure inbound dependencies. Layer 2 external integrations (SOAR / SIEM / cloud / IAM) land via B5b (v1.0.51) and onward through the integration_config table.',
    },
    {
      id: 'CC6.7',
      name: 'Transmission and Disposal Restrictions',
      check: checks.checkTransmission,
      mapping: 'TLS termination at reverse proxy (operator-managed nginx / Caddy / cloud load balancer); reject plaintext HTTP at proxy before requests reach the GD. Backup destinations support encrypted=true via backup_schedules; destination-side at-rest encryption (S3 SSE / GCS CMEK / Azure SE) is operator-managed. The GD has no application-layer HTTPS enforcement as of v0.0.31; NODE_ENV=production is informational.',
    },
    {
      id: 'CC6.8',
      name: 'Malicious Software Prevention',
      check: checks.checkMalwareProtection,
      mapping: 'The GD now has an in-platform host/endpoint EDR seam (the malware_scanner_integrations registry — eleven providers, credentials AES-256-GCM-encrypted), additive on top of the in-platform runtime-monitor baseline. By design the GD still does not process uploaded files from analysts (file-content scanning is enforced at the MC layer). Host-level antivirus on the GD server OS (Microsoft Defender / ClamAV / CrowdStrike Falcon agent / similar) remains operator-managed defense-in-depth.',
    },
    // ── CC7 System Operations ────────────────────────────────────────────────
    {
      id: 'CC7.1',
      name: 'Vulnerability Detection',
      check: checks.checkVulnScanning,
      mapping: 'GD has no in-platform vuln scan history (no scan-result table). Infrastructure vuln scanning (Nessus / Qualys / OpenVAS / Trivy / Snyk) against the GD deployment is operator-responsibility; CI/CD integration of dependency vulnerability monitoring (npm audit / Snyk / Dependabot) is the SOC-grade norm.',
    },
    {
      id: 'CC7.2',
      name: 'System Monitoring',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware (inline in packages/global-dashboard-server/index.js) records every /api request (except /api/health) to audit_log; SIEM streaming for external correlation lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. /api/health, /api/system/version (R3l C8) and /api/system/connected-clients (R3l C9) endpoints provide operational visibility.',
    },
    {
      id: 'CC7.3',
      name: 'Anomaly Detection and Evaluation',
      check: checks.checkAnomalyDetection,
      mapping: 'apiLimiter (express-rate-limit, 1000 req/15min per IP) provides rate-limit anomaly detection; auth_log records LOGIN_FAILED events for IP-pattern-based anomaly review; B3 (v1.0.48) wires runtime monitoring with anomaly detection on aggregate metrics streams from MCs.',
    },
    {
      id: 'CC7.4',
      name: 'Incident Response',
      check: checks.checkIrPlanExists,
      mapping: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO / governance-tier incident response planning is operator-managed off-platform. notification_config provides delivery-channel configuration (email, sms, recipients) for threshold-based alerts.',
    },
    {
      id: 'CC7.5',
      name: 'Recovery and Restoration',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination resilience via active backup_schedules pointing to different destination values (local + S3 / GCS / Azure combinations). Each backup records SHA-256 hash for integrity verification. Note: GD has no restore workflow as of v0.0.31 — see CC9.1 / A1.3 for the off-platform DR drill discipline.',
    },
    // ── CC8 Change Management ────────────────────────────────────────────────
    {
      id: 'CC8.1',
      name: 'Change Management Process',
      check: checks.checkChangeManagement,
      mapping: 'Anti-rollback fuse_counter in system_meta (seeded by db-init.js); audit_log records every configuration change via CONFIG_UPDATED events emitted by PUT /api/config/:key. AGPL-3.0 source transparency for code-level changes. Note: package.json now carries a fuseCounter field (added in B6a); the startup fuse-vs-package comparison that would enforce it awaits a future GD startup-verifier phase.',
    },
    {
      id: 'CC8.1 [Config Lock]',
      name: 'Configuration Change Restriction',
      check: checks.checkConfigLockState,
      mapping: 'GD Config Lock server-side persistence is live (the config_lock_state singleton; the config-write chokepoint refuses writes while the GD is locked). Unlock requires a fresh hardware-passkey assertion (a UV step-up), the GD twin of the MC R3e v1.0.32 config-lock and, like the MC config-lock, a phishing-resistant hardware-passkey step-up. Configuration-change discipline is additionally backed by route-middleware role gating (CISO-only writes).',
    },
    // ── CC9 Risk Mitigation ──────────────────────────────────────────────────
    {
      id: 'CC9.1',
      name: 'Risk Mitigation Activities',
      check: checks.checkBackups,
      mapping: 'Defense-in-depth on the GD\'s current surface: multi-destination backups, encrypted backup option, rate limiting, MFA enrollment, role-based access, audit logging, Config Lock (server-side, hardware-passkey unlock). Several SOC-grade defenses (hash chain, anti-replay, signing keys, KMS) await specific BUILD-PLAN-v16 phases (B5a, R3g PR3 signing keys, future GD KMS phase).',
    },
    {
      id: 'CC9.2',
      name: 'Vendor and Business Partner Management',
      check: checks.checkIntegrationHealth,
      mapping: 'Layer 1 (current): management_consoles tracks each connected MC (the GD\'s third-party data sources) with last_sync timestamps for freshness monitoring. Layer 2 (post-B5b v1.0.51): integration_config will track SOAR / SIEM / cloud / IAM / ticketing vendor integrations with status / last_test_at fields.',
    },
    {
      id: 'CC9.2 [Risk Assessment]',
      name: 'Vendor Risk Assessment',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Each active MC documented with country and regulatory_framework on management_consoles; baseline operational evidence available via last_sync history. Layer 2 integrations (post-B5b) will add last_test_at-based baseline evidence. Formal vendor risk review (vendor SOC 2 collection, DPA negotiation, questionnaires) is customer-responsibility on top of platform-tracked evidence.',
    },
    // ── A1 Availability ──────────────────────────────────────────────────────
    {
      id: 'A1.2',
      name: 'Environmental Threats and Backup',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules table holds active=1 schedules; backups table records completed backups with SHA-256 integrity hash and timestamp. Recent backups (within 48h) evidence operational backup execution. POST /api/backups/trigger bootstraps a manual backup when needed.',
    },
    {
      id: 'A1.3',
      name: 'Recovery Testing',
      check: checks.checkDrTestRecency,
      mapping: 'GD has no in-platform DR test infrastructure as of v0.0.31 — /api/regression-test runs a real integration-test suite but is not a backup-restore drill; no restore workflow; no restore_approvals table. Off-platform DR drill discipline: provision a side-by-side GD instance, restore from backup, verify recovery. SOC-grade norm is quarterly DR testing; auditor will examine documented drill records.',
    },
    // ── C1 Confidentiality ───────────────────────────────────────────────────
    {
      id: 'C1.1',
      name: 'Confidential Information Identification',
      check: checks.checkDataClassification,
      mapping: 'GD data classification is architectural rather than per-row tier-based: only aggregate metrics (regional_metrics, no analyst-identifying fields) and account data (users, role-gated by CISO / VP / readonly) reach the GD. Analyst-level data classification is enforced at the MC layer.',
    },
    {
      id: 'C1.2',
      name: 'Confidential Information Disposal',
      check: checks.checkRetentionPolicy,
      mapping: 'backup_schedules.retention_days enforces destination-side pruning of backups. No analyst-data tables on the GD, so no analyst-data erasure surface; data-subject-rights for GD users (CISO / VP / readonly accounts) is operator-managed off-platform until /api/users CRUD endpoints ship.',
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
      detail: 'Discontinue logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished. Termination workflow triggers offboarding (platform-side via users.active=0) + facility-access revocation (operator-side).',
    },
    // ── CC9 Vendor Management (procedural side) ─────────────────────────────
    {
      id: 'CC9.2 [Vendor SOC 2 Collection]',
      name: 'Vendor SOC 2 Report Review',
      category: 'documentation',
      detail: 'Collect and review SOC 2 Type II reports (or equivalent) from each in-scope vendor. Document review findings; track CUEC (complementary user entity controls) and incorporate into your control set. Annual cadence at minimum. The MCs connected to the GD count as in-scope vendor relationships when considered as the GD\'s third-party data sources.',
    },
    // ── Availability (A1.1) ──────────────────────────────────────────────────
    {
      id: 'A1.1',
      name: 'Capacity Planning',
      category: 'procedural',
      detail: 'Manage processing capacity and usage to achieve availability commitments. Document capacity planning methodology, monitoring of utilization trends, and procurement triggers for scaling. For the GD specifically: monitor SQLite database growth at GD_DB_PATH and audit_log volume; plan for the projected scale of connected MCs.',
    },
    // ── Confidentiality (C1.x procedural side) ──────────────────────────────
    {
      id: 'C1.1 [Designation]',
      name: 'Designation of Confidential Information',
      category: 'documentation',
      detail: 'Identify and maintain confidential information to meet the entity\'s objectives related to confidentiality. Document what constitutes "confidential" in your context — for the GD layer, this is typically aggregate operational metrics, MC trust credentials, and CISO-tier account information.',
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
      detail: 'Document the vendor onboarding workflow: risk assessment, contract execution with security commitments (BAAs, DPAs, security exhibits), ongoing monitoring (re-evaluation cadence, off-cycle triggers). Apply to MCs joining the GD: each MC registration is a vendor onboarding event from the GD\'s perspective.',
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
      detail: 'Author the incident response policies for the GD layer. Define incident severity classification, escalation procedures, communication templates, regulator notification timing, post-incident review process. Until ir_policies persistence ships on the GD, store these documents in your operator wiki / DMS.',
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
      detail: 'Conduct background checks on personnel with access to in-scope systems, proportional to the sensitivity of the access. Document background-check procedures and exception handling. CISO-role users on the GD merit heightened background-check rigor due to broad GD authority.',
    },
    {
      id: 'Segregation of Duties',
      name: 'Segregation of Duties Policy',
      category: 'procedural',
      detail: 'Define segregation of duties for sensitive functions (e.g., the person who configures backup schedules should not also be the sole reviewer of restore drills). Document the role/function matrix; on the GD, the CISO / VP / readonly tiers map to broad SoD strata but operator-level SoD detail beyond that is policy-defined.',
    },
  ],
  note: 'SOC 2 Type II audit windows are typically 6-12 months. Auditor independence is paramount; do not engage your CPA firm for both attestation and remediation consulting. The 7-year evidence retention norm exceeds typical regulatory minimums -- plan GD audit_log capacity accordingly. The Trust Services Criteria were last updated in 2022; verify your auditor uses the current version. For the GD\'s aggregation-tier role, the typical SOC 2 scope is Security + Availability + Confidentiality; Privacy is typically pursued separately or via GDPR/CCPA-aligned controls (separate framework definitions in this library). The GD sits above the MC layer in the FireAlive architecture; if your audit includes the MC, the MC\'s compliance reports cover analyst-level operational controls.',
});
