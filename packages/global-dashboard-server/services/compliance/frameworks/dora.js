// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: DORA
//
// R3g PR2 (v1.0.33): GD-side Digital Operational Resilience Act
// coverage under the Shared Responsibility schema. GD-side counterpart
// to MC PR1's frameworks/dora.js.
//
// APPLICABILITY (per Foundational Rule 16 — CRITICAL FRAMING)
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
//   FireAlive\'s Global Dashboard specifically is a CISO-tier
//   aggregation layer, not a regulated payment system, trading venue,
//   or settlement infrastructure.
//
//   This framework definition is provided as a service to customers
//   that ARE DORA-regulated financial entities and have adopted
//   FireAlive in their SOC operations. For such customers, the GD\'s
//   technical controls (audit logging, encryption, backup policies,
//   integration monitoring, etc.) support compliance with their
//   Art.6-13 ICT risk management duties at the governance /
//   cross-region aggregation tier. The financial entity bears DORA
//   regulatory responsibility throughout and must additionally manage
//   FireAlive as one of their ICT third-party arrangements per
//   Chapter V Art.28-30 (TPP register, pre-contractual risk
//   assessment, written ICT services arrangements). Adopting FireAlive
//   neither establishes nor discharges any DORA obligation on
//   FireAlive itself.
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
      mapping: 'system_meta.fuse_counter + audit_log CONFIG_UPDATED events evidence platform-level change discipline at the GD layer. The financial entity integrates these signals into its overall ICT risk management framework documentation under Art.6.',
    },
    {
      id: 'Art.7',
      name: 'ICT Systems, Protocols and Tools',
      check: checks.checkSystemBoundaries,
      mapping: 'Layer 1 (current): management_consoles enumerates the connected MCs (the GD\'s primary third-party data sources). Layer 2 (post-B5b v1.0.51 et seq.): integration_config will enumerate SOAR / SIEM / cloud / IAM / ticketing integrations with status field. Art.7 inventory of ICT components is supported by exporting these enumerations.',
    },
    {
      id: 'Art.8',
      name: 'Identification of ICT-Supported Business Functions',
      check: checks.checkBoundaries,
      mapping: 'GD\'s architectural role is governance-tier aggregation across regional SOCs (the MCs). The GD holds only aggregate metrics and account data; analyst-level operational data lives at the MC. Business-function mapping under Art.8 is operator-side documentation built atop the platform\'s technical inventory.',
    },
    {
      id: 'Art.9(2)',
      name: 'Protection and Prevention -- Encryption',
      check: checks.checkEncryption,
      mapping: 'GD_JWT_SECRET HMAC-SHA256 for JWT signing (32 bytes minimum) is the application-layer cryptographic foundation. Data-at-rest protection is filesystem-level on the SQLite database file at GD_DB_PATH (operator-managed disk encryption: LUKS / FileVault / BitLocker / AWS EBS encryption). TLS 1.2+ at the reverse proxy for in-transit. State-of-the-art cryptographic protection consistent with Art.9(2) "appropriate" technical measures, with the application-layer at-rest gap closed by a future GD KMS integration phase.',
    },
    {
      id: 'Art.9(3)',
      name: 'Cryptographic Key Management',
      check: checks.checkKmsProvider,
      mapping: 'GD has not yet integrated with an external KMS (kms_providers table not present as of v0.0.31). Data-at-rest protection is filesystem-level; operator-managed disk encryption provides the at-rest guarantee. A future GD KMS integration phase (B-phase track in BUILD-PLAN-v16) will introduce hardware-backed key custody (AWS KMS / Azure Key Vault / GCP KMS / HashiCorp Vault); until then, hardware-backed cryptographic key management is operator-managed at the cloud/infrastructure layer.',
    },
    {
      id: 'Art.10',
      name: 'Detection of Anomalous Activities',
      check: checks.checkAnomalyDetection,
      mapping: 'apiLimiter (express-rate-limit, 1000 req/15min per IP) provides rate-limit anomaly detection; auth_log records LOGIN_FAILED events for IP-pattern-based anomaly review. B3 (v1.0.48) wires runtime monitoring with anomaly detection on aggregate metrics streams from MCs. SIEM correlation across the financial entity\'s broader detection estate awaits integration_config and B3 SIEM/SOAR wiring.',
    },
    {
      id: 'Art.11',
      name: 'Response and Recovery -- IR Plans',
      check: checks.checkIrPlanExists,
      mapping: 'GD has no application-layer IR policy registry (no ir_policies table or document-upload endpoint as of v0.0.31). CISO / governance-tier incident response planning is operator-managed off-platform. notification_config provides delivery channels for threshold-based alerts. RTO/RPO commitments under Art.11(7) are operator-side and documented in the financial entity\'s business continuity policy.',
    },
    {
      id: 'Art.12(1)',
      name: 'Backup Policies and Procedures',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules table holds active=1 schedules; backups table records completed backups with SHA-256 integrity hash and timestamp. Recent backups (within 48h) evidence operational backup execution; POST /api/backups/trigger bootstraps a manual backup. Configurable frequency supports operator-defined RPO commitments.',
    },
    {
      id: 'Art.12(2)',
      name: 'Restoration and Recovery -- Diversified Backup',
      check: checks.checkBackupMultiDestination,
      mapping: 'Multi-destination resilience via active backup_schedules pointing to different destination values (local + S3 / GCS / Azure combinations); single-destination configurations cannot survive a destination failure. Supports Art.12(2) redundancy expectations for critical ICT functions. Note: GD has no in-platform restore workflow as of v0.0.31; restoration drill is off-platform discipline.',
    },
    {
      id: 'Art.13',
      name: 'Learning and Evolving',
      check: checks.checkChangeManagement,
      mapping: 'Audit trail of configuration changes (CONFIG_UPDATED events from PUT /api/config/:key) plus system_meta.fuse_counter evidence post-incident lessons being incorporated into platform configuration. Operator documents incident-driven framework refinement separately under Art.13.',
    },
    // ── Chapter III ICT-Related Incident Management ─────────────────────────
    {
      id: 'Art.17',
      name: 'ICT-Related Incident Management Process',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware (inline in packages/global-dashboard-server/index.js) records every /api request (except /api/health) to audit_log. SIEM streaming preserves incident evidence externally when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship. ir_policies registry awaits a future GD buildout phase; until then, IR management process documentation lives off-platform.',
    },
    {
      id: 'Art.19',
      name: 'Reporting of Major ICT-Related Incidents (4h / 72h / 1mo)',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. The financial entity tracks Art.19 deadlines (initial within 4h of major classification, intermediate within 72h, final within 1mo) off-platform; notification_config delivery channels support rapid alert dispatch when triggered.',
    },
    // ── Chapter IV Digital Operational Resilience Testing ───────────────────
    {
      id: 'Art.24-25',
      name: 'Digital Operational Resilience Testing Programme',
      check: checks.checkDrTestRecency,
      mapping: 'GD has no in-platform DR test infrastructure as of v0.0.31 (no restore workflow; /api/regression-test runs a real integration-test suite but is not a backup-restore drill). Art.24 annual minimum is operator-managed off-platform discipline: provision side-by-side GD instance, restore from backup, verify recovery. Threat-led penetration testing under Art.26 is operator-coordinated with third-party testers regardless of platform feature state.',
    },
    {
      id: 'Art.25',
      name: 'Vulnerability Assessments and Scans',
      check: checks.checkVulnScanning,
      mapping: 'GD has no in-platform vuln scan history (no scan-result table). Infrastructure-side vulnerability assessment is operator-side (per Shared Responsibility) using tools like Nessus / Qualys / OpenVAS / Trivy / Snyk. Annual vulnerability assessment required under Art.25(2)(a); financial-entity scope and methodology are operator-side documentation.',
    },
    // ── Chapter V Section I ICT Third-Party Risk Management ─────────────────
    {
      id: 'Art.28(1)',
      name: 'ICT Third-Party Risk Strategy',
      check: checks.checkIntegrationHealth,
      mapping: 'Layer 1 (current): management_consoles tracks each connected MC with last_sync timestamp for freshness monitoring. Layer 2 (post-B5b v1.0.51 et seq.): integration_config will track SOAR / SIEM / cloud / IAM vendor integrations with last_test_at for ongoing health monitoring. The financial entity\'s own TPP risk strategy (which lists FireAlive as one of its TPPs) is operator-side documentation.',
    },
    {
      id: 'Art.28(4)',
      name: 'Pre-Contractual ICT Third-Party Risk Assessment',
      check: checks.checkVendorRiskAssessment,
      mapping: 'Each active MC documented with country and regulatory_framework on management_consoles for jurisdictional risk context. Formal pre-contractual risk assessment under Art.28(4) (due diligence on FireAlive\'s ability to provide the function with appropriate ICT risk management, conflict-of-interest screening, financial entity\'s assessment of FireAlive among its TPPs) is operator-side documentation.',
    },
    {
      id: 'Art.30',
      name: 'Concentration Risk -- Signing Trust Registry',
      check: checks.checkSigningKeyRegistry,
      mapping: 'No signing-key registries on the GD as of v0.0.31 (no backup_signing_keys, no chain_signing_keys, no signing_keys table). R3g PR3 introduces signing_keys for MC-trust verification (each connected MC registers a signing key; GD verifies inbound compliance-report pushes). Future GD backup-signing phase will add backup_signing_keys + chain_signing_keys. Until those phases ship, MC → GD trust is api_key-based and operator-managed, with concentration-risk mitigation handled through the financial entity\'s broader vendor-diversification strategy.',
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
  note: 'DORA application date was 17 January 2025; financial entities are expected to be fully compliant. Chapter V Section II critical TPP oversight (Art.31-44) operates at the ESA level, not the financial-entity level -- financial entities cooperate with oversight outputs but do not themselves designate critical TPPs. The "critical TPP" designation criteria include systemic impact, substitutability, and interconnectedness; hyperscale cloud providers and major SaaS infrastructure providers are likely candidates over time. The framework definition\'s applicability remains constant regardless of designation status: FireAlive is not currently a critical TPP, and the operator (financial entity) bears DORA regulatory responsibility throughout. The GD is the governance-tier aggregation layer in the FireAlive architecture; analyst-level operational ICT controls (at the SOC tier) are evaluated at the MC layer per its DORA framework definition.',
});
