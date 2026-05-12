// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: DORA
//
// R3g (v1.0.33): comprehensive Digital Operational Resilience Act
// coverage under the Shared Responsibility schema.
//
// APPLICABILITY
//
//   DORA applies to EU financial entities -- banks, investment firms,
//   payment and e-money institutions, insurance and reinsurance
//   undertakings, crypto-asset service providers, trading venues,
//   central counterparties, central securities depositories,
//   crowdfunding service providers, and (under Chapter V Section II
//   designation) critical ICT third-party service providers serving
//   these financial entities.
//
//   FireAlive is NOT a regulated entity under DORA. FireAlive is a
//   horizontal SOC wellbeing platform with no inherent financial-
//   services scope; DORA does not name FireAlive nor any class to
//   which FireAlive belongs as automatically requiring DORA audit.
//
//   This framework definition is provided as a service to customers
//   that ARE DORA-regulated financial entities and have adopted
//   FireAlive in their SOC operations. For such customers,
//   FireAlive\'s technical controls (audit logging, encryption,
//   backup, IR plan storage, integration monitoring, etc.) support
//   compliance with their Art.6-13 ICT risk management duties. The
//   financial entity bears DORA regulatory responsibility throughout
//   and must additionally manage FireAlive as one of their ICT
//   third-party arrangements per Chapter V Art.28-30 (TPP register,
//   pre-contractual risk assessment, written ICT services
//   arrangements). Adopting FireAlive neither establishes nor
//   discharges any DORA obligation on FireAlive itself.
//
//   For non-financial-sector customers, this framework report can be
//   ignored without consequence; running it produces no FireAlive
//   obligation.
//
// AUTHORITY
//
//   European Banking Authority (EBA), European Securities and Markets
//   Authority (ESMA), and European Insurance and Occupational
//   Pensions Authority (EIOPA) -- collectively the European
//   Supervisory Authorities (ESAs). National competent authorities
//   (NCAs) enforce in each Member State.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Regulation (EU) 2022/2554 -- Digital Operational Resilience Act.
//   In force since 16 January 2023; application date 17 January 2025.
//   This file covers technical-control mappings from Chapter II (ICT
//   Risk Management), Chapter III (Incident Management), Chapter IV
//   (Resilience Testing), and Chapter V Section I (TPP Risk
//   Management principles). Chapter V Section II (critical TPP
//   oversight framework, Art.31-44) and Chapter VI (information
//   sharing, Art.45) primarily govern designated critical TPPs and
//   the ESAs themselves, not typical financial-entity customers, and
//   are referenced in the note rather than mapped as controls.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'DORA',
  authority: 'European Supervisory Authorities (EBA / ESMA / EIOPA) and national competent authorities',
  citation: 'Regulation (EU) 2022/2554 -- Digital Operational Resilience Act',
  verifiedControls: [
    // ── Chapter II ICT Risk Management ──────────────────────────────────────
    {
      id: 'Art.6',
      name: 'ICT Risk Management Framework',
      check: checks.checkChangeManagement,
      mapping: 'Anti-rollback fuse_counter plus configuration-change audit trail evidence platform-level change discipline; the financial entity integrates these signals into its overall ICT risk management framework documentation under Art.6.',
    },
    {
      id: 'Art.7',
      name: 'ICT Systems, Protocols and Tools',
      check: checks.checkSystemBoundaries,
      mapping: 'integration_config enumerates all ICT systems and protocols the platform connects to (SOAR, SIEM, ticketing, IAM, cloud, KMS); status field evidences operational state. Art.7 inventory of ICT components is supported by exporting this enumeration.',
    },
    {
      id: 'Art.8',
      name: 'Identification of ICT-Supported Business Functions',
      check: checks.checkBoundaries,
      mapping: 'Tier classification + integration_config types provide the technical inputs the financial entity needs to map FireAlive components to its business functions. Final business-function mapping is operator-side documentation under Art.8.',
    },
    {
      id: 'Art.9(2)',
      name: 'Protection and Prevention -- Encryption',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM at rest via distinct TIER1/TIER3 keys; TLS 1.2+ in transit. State-of-the-art cryptographic protection consistent with Art.9(2) "appropriate" technical measures.',
    },
    {
      id: 'Art.9(3)',
      name: 'Cryptographic Key Management',
      check: checks.checkKmsProvider,
      mapping: 'kms_providers integration with AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault provides hardware-backed key custody where required; last_probe_status evidences ongoing provider trust validation.',
    },
    {
      id: 'Art.10',
      name: 'Detection of Anomalous Activities',
      check: checks.checkAnomalyDetection,
      mapping: 'bandwidthMonitor middleware detects bandwidth spikes; apiLimiter rate limiting catches traffic anomalies; CEF SIEM streaming enables correlation across the financial entity\'s broader detection estate.',
    },
    {
      id: 'Art.11',
      name: 'Response and Recovery -- IR Plans',
      check: checks.checkIrPlanExists,
      mapping: 'ir_policies table stores IR plans + scenario playbooks; sla_config tracks MTTA/MTTR commitments; notification channels deliver alerts. RTO/RPO commitments under Art.11(7) are operator-side and documented in their business continuity policy.',
    },
    {
      id: 'Art.12(1)',
      name: 'Backup Policies and Procedures',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules + backup_pushes track automated backup execution; configurable schedule supports operator-defined RPO commitments; recent backup_pushes.status=succeeded evidences operational backups.',
    },
    {
      id: 'Art.12(2)',
      name: 'Restoration and Recovery -- Diversified Backup',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination architecture (local + S3/GCS/Azure/SFTP combinations) prevents single-destination failure from defeating backup-based recovery, supporting Art.12(2) redundancy expectations for critical ICT functions.',
    },
    {
      id: 'Art.13',
      name: 'Learning and Evolving',
      check: checks.checkChangeManagement,
      mapping: 'Audit trail of configuration changes (CONFIG_UPDATED events) plus anti-rollback fuse evidence post-incident lessons being incorporated into platform configuration. Operator documents incident-driven framework refinement separately under Art.13.',
    },
    // ── Chapter III ICT-Related Incident Management ─────────────────────────
    {
      id: 'Art.17',
      name: 'ICT-Related Incident Management Process',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware captures every /api/ event; SIEM streaming preserves incident evidence externally; ir_policies define management process steps. Final incident management workflow and classification methodology are operator-side.',
    },
    {
      id: 'Art.19',
      name: 'Reporting of Major ICT-Related Incidents (4h / 72h / 1mo)',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery to support the financial entity meeting Art.19 deadlines: initial notification within 4 hours of incident classification (max 24h after detection), intermediate report within 72h, final report within 1 month. Reporting workflow and templates are operator-side.',
    },
    // ── Chapter IV Digital Operational Resilience Testing ───────────────────
    {
      id: 'Art.24-25',
      name: 'Digital Operational Resilience Testing Programme',
      check: checks.checkDrTestRecency,
      mapping: 'restore_approvals.status=consumed records evidence DR drill execution; quarterly cadence aligns with Art.24 annual minimum (more frequent recommended for critical functions). Threat-led penetration testing under Art.26 is operator-coordinated with third-party testers.',
    },
    {
      id: 'Art.25',
      name: 'Vulnerability Assessments and Scans',
      check: checks.checkVulnScanning,
      mapping: 'Platform-side malware scanning via malware_scanner_integrations; infrastructure-side vulnerability assessment is operator-side (per Shared Responsibility) using tools like Nessus/Qualys/OpenVAS. Annual vulnerability assessment required under Art.25(2)(a).',
    },
    // ── Chapter V Section I ICT Third-Party Risk Management ─────────────────
    {
      id: 'Art.28(1)',
      name: 'ICT Third-Party Risk Strategy',
      check: checks.checkIntegrationHealth,
      mapping: 'integration_config tracks all third-party ICT arrangements the platform integrates with; last_test_at evidences ongoing health monitoring. The financial entity\'s own TPP risk strategy (which lists FireAlive as one of its TPPs) is operator-side documentation.',
    },
    {
      id: 'Art.28(4)',
      name: 'Pre-Contractual ICT Third-Party Risk Assessment',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Every configured integration has at least one operational test recorded; formal pre-contractual risk assessment under Art.28(4) (due diligence, conflict-of-interest screening, financial entity\'s assessment of its TPPs including FireAlive) is operator-side documentation.',
    },
    {
      id: 'Art.30',
      name: 'Concentration Risk -- Signing Trust Registry',
      check: checks.checkSigningKeyRegistry,
      mapping: 'backup_signing_keys + chain_signing_keys registries enable cryptographically-verified trust relationships across deployments, supporting concentration-risk mitigation through cross-deployment signature verification. Art.30 explicitly addresses concentration of ICT third-party arrangements at the financial-entity level.',
    },
  ],
  customerResponsibility: [
    // ── Chapter II ICT Risk Management (governance, strategy) ────────────────
    {
      id: 'Art.5(1)',
      name: 'Governance and Organisational Arrangements',
      category: 'organizational',
      detail: 'Management body of the financial entity bears ultimate responsibility for the ICT risk management framework. Document the governance structure, ICT risk reporting lines, and management body involvement in approving and overseeing ICT risk decisions.',
    },
    {
      id: 'Art.5(2)',
      name: 'Management Body Responsibility for ICT Risk',
      category: 'organizational',
      detail: 'The management body shall be ultimately responsible for managing ICT risk. Define explicit ICT risk responsibilities in management body charters; board minutes evidence oversight cadence; member training on ICT risk per Art.5(4)(d).',
    },
    {
      id: 'Art.5(4)',
      name: 'Digital Operational Resilience Strategy',
      category: 'procedural',
      detail: 'Document the digital operational resilience strategy: risk tolerance, security objectives, ICT business continuity arrangements, response coordination, performance indicators. The strategy is reviewed periodically and approved by the management body.',
    },
    {
      id: 'Art.6(8)',
      name: 'Annual Review of ICT Risk Management Framework',
      category: 'procedural',
      detail: 'Review the ICT risk management framework at least annually, and upon occurrence of major ICT-related incidents. Document findings, gaps, and treatment plans. Submit findings to the management body for approval of changes.',
    },
    {
      id: 'Art.14',
      name: 'Crisis Communication and External Communication',
      category: 'procedural',
      detail: 'Establish ICT-related crisis communication plans for clients, counterparties, and competent authorities. Designate communication owners; maintain templates; align with broader corporate crisis communications. Training and exercises maintain readiness.',
    },
    {
      id: 'Art.16',
      name: 'Simplified ICT Risk Management Framework (Small Entities)',
      category: 'procedural',
      detail: 'Entities meeting the small / non-interconnected criteria in Art.16(1) may apply a simplified framework. Document which provisions are simplified and the rationale; maintain the relevant board-approved simplified framework documentation.',
    },
    {
      id: 'Art.17',
      name: 'ICT Incident Management Process Documentation',
      category: 'documentation',
      detail: 'Document the ICT-related incident management process: detection inputs, escalation criteria, classification methodology, response steps, root-cause analysis, post-incident review. The platform provides evidence stores; the documented process is operator-side.',
    },
    {
      id: 'Art.18',
      name: 'Incident Classification Methodology',
      category: 'procedural',
      detail: 'Apply the classification criteria from Art.18(1) and the regulatory technical standards: clients affected, data loss, financial impact, criticality of services, geographical spread, reputational impact. Document the methodology and decision trail for each classification.',
    },
    {
      id: 'Art.19(1)',
      name: 'Initial Notification of Major ICT-Related Incidents (4 hours)',
      category: 'procedural',
      detail: 'Notify the competent authority within 4 hours of incident classification as major (maximum 24 hours after detection). Use the standard reporting template (Art.20 regulatory technical standard); designate notification owner with after-hours coverage.',
    },
    {
      id: 'Art.19(2)',
      name: 'Intermediate Report (72 hours)',
      category: 'procedural',
      detail: 'Submit an intermediate report within 72 hours of the initial notification. Update with additional information on impact, root cause, mitigation actions, and time-to-resolution estimate.',
    },
    {
      id: 'Art.19(3)',
      name: 'Final Report (1 month)',
      category: 'procedural',
      detail: 'Submit the final report no later than 1 month after the initial notification. Include comprehensive root cause analysis, full impact assessment, completed mitigation actions, lessons learned, and changes to the ICT risk management framework.',
    },
    {
      id: 'Art.19(5)',
      name: 'Voluntary Cyber Threat Notification',
      category: 'procedural',
      detail: 'Voluntary notification of significant cyber threats (not actual incidents) supports sector-wide situational awareness. Document the criteria for voluntary notification and the workflow for assembling the threat report.',
    },
    {
      id: 'Art.23',
      name: 'Payment-Related Incident Reporting',
      category: 'procedural',
      detail: 'For operational or security payment-related incidents involving credit institutions, payment institutions, account information service providers, electronic money institutions, and CMS providers: additional reporting under PSD2 / DORA harmonisation. Track payment-related incident workflow separately if in scope.',
    },
    {
      id: 'Art.24',
      name: 'General Testing Programme',
      category: 'procedural',
      detail: 'Establish a digital operational resilience testing programme. Define test scope, methodology, success criteria, frequency, and remediation. Programme is approved by the management body and reviewed annually.',
    },
    {
      id: 'Art.25(2)',
      name: 'Annual Vulnerability Assessment',
      category: 'procedural',
      detail: 'Perform vulnerability assessment of ICT systems supporting critical or important functions at least annually. The platform exposes infrastructure for scanning; the financial entity\'s vulnerability management program is operator-side documentation.',
    },
    {
      id: 'Art.26',
      name: 'Threat-Led Penetration Testing (TLPT) Every 3 Years',
      category: 'procedural',
      detail: 'TLPT mandatory at least every 3 years for financial entities identified by the competent authority. TLPT covers the most critical functions and ICT supporting infrastructure. Coordination with TIBER-EU framework; mutual recognition across competent authorities.',
    },
    {
      id: 'Art.27',
      name: 'TLPT Tester Requirements',
      category: 'documentation',
      detail: 'TLPT testers must meet the highest professional standards, hold relevant certifications, follow approved methodologies (TIBER-EU compatible), and carry sufficient professional indemnity insurance. Document tester qualifications and procurement process.',
    },
    {
      id: 'Art.28',
      name: 'ICT Third-Party Service Provider Register',
      category: 'documentation',
      detail: 'Maintain a register of information for all ICT third-party arrangements (including FireAlive). Register includes: service description, criticality, contract terms, data processed, locations, exit strategy, alternatives. Update upon material changes.',
    },
    {
      id: 'Art.30',
      name: 'Register Submission to Competent Authorities',
      category: 'documentation',
      detail: 'Submit the ICT TPP register to the competent authority on request or per annual reporting cadence under regulatory technical standards. Pre-format register data in the prescribed structured format.',
    },
    {
      id: 'Art.30(2)(a)-(d)',
      name: 'Pre-Contractual Due Diligence',
      category: 'procedural',
      detail: 'Before entering into ICT TPP arrangements: assess all relevant risks including concentration risk, conduct due diligence on TPP\'s ability to provide the function with appropriate ICT risk management, identify potential conflicts of interest, ensure the TPP meets ICT security standards.',
    },
    {
      id: 'Art.30(3)',
      name: 'Written ICT Services Arrangements',
      category: 'documentation',
      detail: 'All ICT third-party arrangements documented in writing with content prescribed by Art.30(2) and (3): description of services, locations, performance metrics, audit and access rights, termination clauses, data-handling obligations, business continuity expectations, security incident notification.',
    },
    {
      id: 'Art.31-44',
      name: 'Critical TPP Designation and Oversight Cooperation',
      category: 'organizational',
      detail: 'Financial entities cooperate with ESAs in the oversight of critical ICT third-party service providers designated under Art.31. Where FireAlive itself becomes designated as critical (hypothetical -- not currently designated), the financial entity\'s arrangement with FireAlive may be subject to additional oversight outputs from the Lead Overseer.',
    },
  ],
  note: 'DORA application date was 17 January 2025; financial entities are expected to be fully compliant. Chapter V Section II critical TPP oversight (Art.31-44) operates at the ESA level, not the financial-entity level -- financial entities cooperate with oversight outputs but do not themselves designate critical TPPs. The "critical TPP" designation criteria include systemic impact, substitutability, and interconnectedness; hyperscale cloud providers and major SaaS infrastructure providers are likely candidates over time. The framework definition\'s applicability remains constant regardless of designation status: FireAlive is not currently a critical TPP, and the operator (financial entity) bears DORA regulatory responsibility throughout.',
});
