// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE GLOBAL DASHBOARD — Compliance Framework: GDPR
//
// R3g PR2 (v1.0.33): GD-side GDPR coverage under the Shared
// Responsibility schema. GD-side counterpart to MC PR1's
// frameworks/gdpr.js. Same metadata, same citation, same
// customerResponsibility list (GDPR articles are EU-defined and
// framework-level not platform-specific); adapted verifiedControls
// for the GD's surface.
//
// GDPR has the broadest customer-responsibility surface of any
// framework in this platform's compliance suite -- most articles
// establish duties of data controllers and processors that the
// platform supports but cannot discharge on the customer's behalf.
//
// AUTHORITY
//
//   European Data Protection Board (EDPB) coordinates EU-level
//   guidance; enforcement is national, by each Member State's data
//   protection authority (e.g., CNIL in France, ICO in UK pre-Brexit
//   and now via UK GDPR, Garante in Italy, BfDI in Germany).
//
//   Penalties are significant: up to EUR 20M or 4% of global annual
//   turnover (whichever is higher) for serious violations under
//   Art.83(5). Lower-tier violations (Art.83(4)) cap at EUR 10M or 2%.
//
// SCOPE
//
//   Regulation (EU) 2016/679 -- General Data Protection Regulation.
//   In force since May 2018. Applies to:
//     - Controllers and processors established in the EU
//     - Controllers and processors NOT in the EU but processing
//       personal data of data subjects in the EU when offering goods
//       /services or monitoring behaviour (Art.3 extraterritorial)
//
//   UK GDPR is materially equivalent post-Brexit; this framework
//   definition serves both with the same controls (UK enforcement is
//   the ICO; UK penalty caps are slightly different in GBP).
//
// APPLICABILITY (per Foundational Rule 16)
//
//   At the GD layer, the data-subject surface is narrow: only GD
//   user accounts (CISO / VP / readonly) are direct data subjects
//   on the GD itself. Analyst-level personal data (which is the
//   bulk of GDPR-relevant data in the FireAlive ecosystem) lives at
//   the MC layer; the MC's GDPR framework definition covers analyst-
//   level controls. The GD aggregates non-identifying metrics from
//   the MCs per the architectural data model.
//
//   Where the operator is a GDPR controller or processor, this
//   framework supports the operator's overall GDPR program at the
//   governance / cross-region aggregation layer.
//
// SHARED RESPONSIBILITY EMPHASIS
//
//   The 15 verifiedControls in this file cover the security-of-
//   processing (Art.32), data-protection-by-design (Art.25), records
//   (Art.30), breach notification timing (Art.33), right to erasure
//   (Art.17), and transfers (Chapter V) -- the articles with concrete
//   technical implementation expectations.
//
//   The 25 customerResponsibility entries cover the procedural and
//   organizational surface: lawful basis identification (Art.6),
//   consent management (Art.7), data subject information (Art.13-14),
//   the remaining data subject rights procedures (Art.15-16, 18-22),
//   controller responsibility (Art.24), processor contracts (Art.28),
//   DPIA (Art.35), DPO designation/position/tasks (Art.37-39), and
//   transfer mechanism selection (Art.44-49).
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'GDPR',
  authority: 'European Data Protection Board / national supervisory authorities',
  citation: 'Regulation (EU) 2016/679 -- General Data Protection Regulation',
  verifiedControls: [
    // ── Art.5 Principles ─────────────────────────────────────────────────────
    {
      id: 'Art.5(1)(f)',
      name: 'Integrity and Confidentiality',
      check: checks.checkEncryption,
      mapping: 'GD_JWT_SECRET (HMAC-SHA256, 32 bytes minimum) provides the application-layer cryptographic foundation for session integrity. Data-at-rest protection is filesystem-level on the SQLite database file (operator-managed disk encryption: LUKS / FileVault / BitLocker / AWS EBS encryption). A future GD KMS integration phase would add application-layer at-rest encryption.',
    },
    {
      id: 'Art.5(2)',
      name: 'Accountability',
      check: checks.checkAuditControls,
      mapping: 'Request-logging middleware records every /api request (except /api/health) to audit_log with user_id, event_type, detail, ip, severity, timestamp. SIEM streaming for external evidence of processing activities lands when integration_config + B3 SIEM/SOAR wiring (v1.0.48) ship.',
    },
    // ── Art.25 Data Protection by Design and by Default ─────────────────────
    {
      id: 'Art.25(1)',
      name: 'Data Protection by Design',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role (ciso / vp / readonly) + authMiddleware role-array gating on every /api route. Architectural data segmentation: the GD holds only aggregate metrics (regional_metrics, no analyst-identifying fields) and account data — by design, analyst-level data tables do not exist on the GD. Access decisions are technical-control gated, not policy-relied.',
    },
    {
      id: 'Art.25(2)',
      name: 'Data Protection by Default',
      check: checks.checkPrivilegedSeparation,
      mapping: 'SoD model for the GD: 1-2 CISO-role users provides minimum-privilege default; new users default to readonly tier unless explicitly promoted. Per Foundational Rule 20, the GD never writes back to MC state — read-only-by-default at the inter-system layer. Least-privilege is the platform default, not an opt-in.',
    },
    // ── Art.30 Records of Processing Activities ──────────────────────────────
    {
      id: 'Art.30',
      name: 'Records of Processing Activities (Controller)',
      check: checks.checkAuditRetention,
      mapping: 'audit_log retains processing activity records bounded only by storage capacity at GD_DB_PATH (no auto-truncation). Operator provisions retention to align with Art.30 record-keeping requirements (typically multi-year). For active retention enforcement: manual export via GET /api/audit-logs/export/:format on a documented cadence to an external WORM destination.',
    },
    // ── Art.32 Security of Processing ────────────────────────────────────────
    {
      id: 'Art.32(1)(a) [Pseudonymisation]',
      name: 'Pseudonymisation of Personal Data',
      check: checks.checkPseudonymization,
      mapping: 'Pseudonymization is enforced upstream at the MC layer (each MC keys analyst behavioral signals to a pseudonym BEFORE producing aggregate metrics for push to the GD). The GD receives only aggregates; the identity-to-signal linkage never reaches the GD per the architectural data model. Verify by inspecting regional_metrics — fields are mc_id + aggregate counts/percentages with no analyst-identifying columns.',
    },
    {
      id: 'Art.32(1)(a) [Encryption]',
      name: 'Encryption of Personal Data',
      check: checks.checkAlgorithmStrength,
      mapping: 'GD_JWT_SECRET HMAC-SHA256 for JWT signing (32 bytes minimum); no passwords stored (passwordless FIDO2 hardware-passkey login). TLS 1.2+ at reverse proxy for in-transit protection (operator-managed). Backup destinations support encrypted=true via backup_schedules. State-of-the-art expectation for Art.32 "appropriate technical measures" met at GD layer for the cryptographic surface the GD owns; deployment-layer cryptography (disk encryption, TLS termination) is operator-managed.',
    },
    {
      id: 'Art.32(1)(b)',
      name: 'Ongoing Confidentiality, Integrity, Availability, Resilience',
      check: checks.checkSystemBoundaries,
      mapping: 'Boundary enforcement via management_consoles status tracking (the GD\'s third-party data sources). Layer 2 integrations (SOAR / SIEM / cloud / IAM via integration_config) land in B5b (v1.0.51) and onward. Resilience via multi-destination backup_schedules; apiLimiter rate limiting. Several SOC-grade defenses (hash chain B5a, anti-replay, signing keys R3g PR3, KMS) await specific BUILD-PLAN-v16 phases.',
    },
    {
      id: 'Art.32(1)(c)',
      name: 'Restoration of Availability and Access',
      check: checks.checkBackupFrequency,
      mapping: 'backup_schedules drive automated periodic backups; backups table records completed backups with SHA-256 integrity hash. POST /api/backups/trigger executes a manual backup. Note: GD has no restore workflow as of v0.0.31 — Art.32(1)(c) requires the ability to RESTORE availability, which is currently off-platform discipline (provision side-by-side instance, restore from backup, verify).',
    },
    {
      id: 'Art.32(1)(d)',
      name: 'Regular Testing of Technical and Organisational Measures',
      check: checks.checkDrTestRecency,
      mapping: 'GD has no in-platform DR test infrastructure as of v0.0.31 (no restore workflow; /api/regression-test runs a real integration-test suite but is not a backup-restore drill). Art.32(1)(d) explicitly requires regular testing; quarterly is SOC-grade industry norm. Off-platform discipline applies until a future restore-workflow phase ships.',
    },
    {
      id: 'Art.32(2)',
      name: 'Risk-Appropriate Security Measures',
      check: checks.checkVulnScanning,
      mapping: 'GD has no in-platform vuln scan history. Infrastructure vuln scanning (Nessus / Qualys / OpenVAS / Trivy / Snyk) against the GD deployment is operator-responsibility. Risk assessment under Art.32(2) considers the state of the art, costs, and the nature of processing.',
    },
    // ── Art.33 Breach Notification ───────────────────────────────────────────
    {
      id: 'Art.33(1)',
      name: 'Breach Notification to Supervisory Authority (72 hours)',
      check: checks.checkNotificationTiming,
      mapping: 'GD has no sla_config table; notification_config holds domain-specific thresholds (burnout, SLA, turnover) and delivery channels (email, sms, recipients) but no incident MTTA/MTTR timings. The 72-hour notification clock under Art.33(1) is a hard regulatory deadline; operator-managed off-platform tracking of incident-severity timings until a future phase adds sla_config to the GD.',
    },
    // ── Art.17 Right to Erasure ──────────────────────────────────────────────
    {
      id: 'Art.17',
      name: 'Right to Erasure (Right to be Forgotten)',
      check: checks.checkDataSubjectRights,
      mapping: 'GD\'s data-subject surface is narrow: only GD users (CISO / VP / readonly accounts) are direct data subjects on the GD. Account-level erasure via users.active=0 soft delete (CISO-only). No dedicated DELETE /api/users/:id endpoint as of v0.0.31; full erasure currently operator-managed via direct DB operations preserving audit trail required for Art.5(2) accountability. Right to erasure under Art.17 is subject to exceptions (Art.17(3)) including legal obligations and public-interest archiving.',
    },
    // ── Art.20 Right to Data Portability ─────────────────────────────────────
    {
      id: 'Art.20',
      name: 'Right to Data Portability',
      check: checks.checkDataSubjectRights,
      mapping: 'GET /api/audit-logs/export/:format produces structured exports of audit_log entries (covering a GD user\'s activity history) in machine-readable formats. Operator extends with subject-specific export endpoints as needed for Art.20 portability requests covering account data beyond audit logs.',
    },
    // ── Chapter V Transfers ──────────────────────────────────────────────────
    {
      id: 'Ch.V',
      name: 'Cross-Border Transfers Outside EEA',
      check: checks.checkCrossBorderTransferControls,
      mapping: 'management_consoles.country tracks each MC\'s jurisdiction; config \'gd_residency\' key documents the GD server\'s own jurisdiction. MC → GD aggregate metric pushes may cross borders when MC country differs from GD residency. Chapter V transfer mechanism selection (Art.45 adequacy, Art.46 SCCs, Art.47 BCRs, Art.49 derogations) is operator-side documentation tracked off-platform per cross-border data flow.',
    },
  ],
  customerResponsibility: [
    // ── Chapter II Principles + Lawfulness ───────────────────────────────────
    {
      id: 'Art.6',
      name: 'Lawful Basis for Processing',
      category: 'procedural',
      detail: 'Identify and document the lawful basis for each processing activity from the six options in Art.6(1): consent, contract, legal obligation, vital interests, public task, legitimate interests. Cannot rely on consent for processing that is also based on another lawful basis; cannot retroactively change basis.',
    },
    {
      id: 'Art.7',
      name: 'Conditions for Consent',
      category: 'procedural',
      detail: 'When relying on consent (Art.6(1)(a)): consent must be freely given, specific, informed, unambiguous; demonstrable; revocable as easily as given; granular; not bundled with other terms. Maintain consent records linking consent acts to identifiable data subjects.',
    },
    {
      id: 'Art.8',
      name: 'Children\'s Consent',
      category: 'procedural',
      detail: 'When offering information society services directly to a child (default Member State age 16, may be reduced to 13), require parental/guardian consent for children below the age threshold. Verify the consent-giver\'s authority using available technology and reasonable effort.',
    },
    {
      id: 'Art.9',
      name: 'Processing of Special Categories of Data',
      category: 'procedural',
      detail: 'Special categories (Art.9(1)) include racial/ethnic origin, political opinions, religious beliefs, trade union membership, genetic/biometric data, health data, sex life or sexual orientation. Processing prohibited unless an Art.9(2) exception applies. Document the applicable exception.',
    },
    // ── Chapter III Data Subject Information and Rights ─────────────────────
    {
      id: 'Art.13',
      name: 'Information to be Provided (Data Collected from Subject)',
      category: 'documentation',
      detail: 'Privacy notice content when collecting personal data directly: controller identity + contact, DPO contact, processing purposes and lawful basis, recipients, transfer mechanism, retention period, data subject rights, supervisory authority complaint right, source-of-data (if not from subject), automated decision-making logic.',
    },
    {
      id: 'Art.14',
      name: 'Information to be Provided (Data NOT Obtained from Subject)',
      category: 'documentation',
      detail: 'When data is obtained other than from the data subject (e.g., from a data broker, partner, public source): provide Art.13 information within reasonable period (max 1 month), unless covered by Art.14(5) exceptions (impossible/disproportionate effort, legal obligation requires processing, professional secrecy).',
    },
    {
      id: 'Art.15',
      name: 'Right of Access by the Data Subject',
      category: 'procedural',
      detail: 'Data subject right to obtain confirmation of processing + access to their personal data + the Art.13/14 information. Respond within 1 month (extendable +2 months for complex/numerous requests, with notification). First copy free; charge reasonable fee for additional copies.',
    },
    {
      id: 'Art.16',
      name: 'Right to Rectification',
      category: 'procedural',
      detail: 'Data subject right to obtain rectification of inaccurate personal data and completion of incomplete data. Implement rectification workflow + notification to recipients (Art.19) unless impossible or disproportionate effort.',
    },
    {
      id: 'Art.18',
      name: 'Right to Restriction of Processing',
      category: 'procedural',
      detail: 'Data subject right to restrict processing in specified circumstances (accuracy contested, processing unlawful, no longer needed but required by subject, objection pending). Implement restriction flag + processing-restriction logic + notification to recipients (Art.19).',
    },
    {
      id: 'Art.19',
      name: 'Notification to Recipients',
      category: 'procedural',
      detail: 'Notify each recipient to whom personal data has been disclosed of rectification, erasure, or restriction unless impossible or disproportionate effort. Maintain recipient log to support this notification obligation.',
    },
    {
      id: 'Art.21',
      name: 'Right to Object',
      category: 'procedural',
      detail: 'Data subject right to object to processing based on legitimate interests, direct marketing, or scientific/historical research. For direct marketing, the objection is absolute (no balancing test). Implement object-flag + processing-cessation workflow.',
    },
    {
      id: 'Art.22',
      name: 'Automated Individual Decision-Making',
      category: 'procedural',
      detail: 'Data subject right not to be subject to a decision based solely on automated processing including profiling, with legal or similarly significant effects, unless: necessary for contract, authorised by Member State law, or based on explicit consent. Provide safeguards including human intervention. Document automated decisions in scope.',
    },
    // ── Chapter IV Controller and Processor ──────────────────────────────────
    {
      id: 'Art.24',
      name: 'Responsibility of the Controller',
      category: 'organizational',
      detail: 'Implement appropriate technical and organisational measures to ensure and demonstrate that processing is performed in accordance with GDPR. Maintain compliance documentation; review and update measures; consider Codes of Conduct or certification mechanisms.',
    },
    {
      id: 'Art.26',
      name: 'Joint Controllers Arrangement',
      category: 'documentation',
      detail: 'Where two or more controllers jointly determine purposes and means of processing, determine their respective Art.13/14 transparency and Art.15-22 data subject rights responsibilities by transparent arrangement. Make the essence of the arrangement available to data subjects.',
    },
    {
      id: 'Art.27',
      name: 'Representative Designation (Non-EU Controllers/Processors)',
      category: 'documentation',
      detail: 'When Art.3(2) extraterritorial scope applies, designate in writing a representative in the EU. Representative serves as point of contact for supervisory authorities and data subjects. Documentation provided to representative for ongoing processing.',
    },
    {
      id: 'Art.28',
      name: 'Processor Contracts (DPAs)',
      category: 'documentation',
      detail: 'Use only processors providing sufficient guarantees of appropriate measures. Govern processing by contract or other legal act (Data Processing Agreement) covering subject matter, duration, nature/purpose of processing, types of data, categories of data subjects, controller obligations and rights, processor obligations under Art.28(3). The MCs connected to the GD often warrant DPA structuring depending on the operator\'s controller/processor model across regions.',
    },
    {
      id: 'Art.31',
      name: 'Cooperation with Supervisory Authority',
      category: 'procedural',
      detail: 'Cooperate, on request, with the supervisory authority in the performance of its tasks. Document the procedure for responding to supervisory authority inquiries; designate primary supervisory authority under one-stop-shop mechanism if cross-border processing.',
    },
    {
      id: 'Art.34',
      name: 'Communication of Personal Data Breach to the Data Subject',
      category: 'procedural',
      detail: 'When breach is likely to result in high risk to rights/freedoms, communicate without undue delay using clear/plain language. Communication must describe nature of breach, DPO contact, likely consequences, measures taken/proposed. Exception for low-risk breaches and when subsequent measures eliminate the risk.',
    },
    {
      id: 'Art.35',
      name: 'Data Protection Impact Assessment (DPIA)',
      category: 'procedural',
      detail: 'Conduct DPIA prior to processing when likely to result in high risk to rights/freedoms (systematic monitoring, large-scale special category processing, public area systematic monitoring). DPIA contains description of processing, necessity/proportionality assessment, risk assessment, mitigation measures.',
    },
    {
      id: 'Art.36',
      name: 'Prior Consultation with Supervisory Authority',
      category: 'procedural',
      detail: 'When DPIA indicates high residual risk that cannot be mitigated, consult the supervisory authority before processing. Authority advises within 8 weeks (extendable +6 weeks). Document the consultation request, response, and changes to processing.',
    },
    {
      id: 'Art.37-39',
      name: 'Data Protection Officer (DPO) Designation, Position, Tasks',
      category: 'organizational',
      detail: 'Designate DPO when: public authority, core activities require systematic monitoring on large scale, or core activities involve large-scale special category/criminal data processing. DPO must have expert knowledge, be independent, report to highest management, be involved in all data protection issues. Publish DPO contact and notify supervisory authority.',
    },
    // ── Chapter V Transfers ──────────────────────────────────────────────────
    {
      id: 'Art.44',
      name: 'General Principle for Transfers',
      category: 'procedural',
      detail: 'Any transfer of personal data outside the EEA must comply with Chapter V transfer mechanisms in addition to other GDPR provisions. Document the transfer scenario (countries, recipients, data categories, purposes) and the legal mechanism selected. The GD\'s management_consoles + gd_residency surface provides the technical inventory; legal mechanism documentation lives off-platform.',
    },
    {
      id: 'Art.45',
      name: 'Adequacy Decisions',
      category: 'documentation',
      detail: 'Transfers to countries with European Commission adequacy decisions (currently includes UK, Switzerland, Japan, South Korea, Israel, New Zealand, Argentina, Canada-commercial, EU-US Data Privacy Framework certified entities, and others) require no additional safeguards. Maintain list of adequacy-covered transfers.',
    },
    {
      id: 'Art.46-47',
      name: 'Appropriate Safeguards (SCCs, BCRs)',
      category: 'documentation',
      detail: 'For non-adequacy transfers, implement appropriate safeguards: Standard Contractual Clauses (SCCs, 2021 EU Commission version), Binding Corporate Rules (BCRs) approved by competent supervisory authority, certification mechanisms (Art.42), or approved codes of conduct (Art.40). Schrems II Transfer Impact Assessment (TIA) required for SCCs.',
    },
    {
      id: 'Art.49',
      name: 'Derogations for Specific Situations',
      category: 'procedural',
      detail: 'Limited derogations for specific situations: explicit consent (subject informed of risks), necessary for contract performance, public interest, legal claims, vital interests, public register. Use derogations sparingly; document the specific Art.49(1) ground relied on per transfer.',
    },
  ],
  note: 'GDPR is the most comprehensive privacy regulation by reach and severity. Penalties under Art.83 reach EUR 20M or 4% of global annual turnover. The "one-stop-shop" mechanism (Art.56) means cross-border processing has a single lead supervisory authority, but other concerned authorities retain inputs. UK GDPR is materially equivalent post-Brexit (separate ICO enforcement). Schrems II (2020) invalidated Privacy Shield and tightened SCCs; the EU-US Data Privacy Framework (2023) restored a transfer mechanism for certified US entities but its long-term stability remains contested. Operators handling EU personal data should monitor EDPB guidelines and national supervisory authority decisions. The GD\'s direct GDPR data-subject surface is narrow (GD user accounts only); the bulk of analyst-level GDPR concerns are evaluated at the MC layer.',
});
