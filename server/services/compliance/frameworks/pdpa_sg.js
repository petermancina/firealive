// ═══════════════════════════════════════════════════════════════════════════════
// FIREALIVE — Compliance Framework: PDPA (Singapore)
//
// R3g (v1.0.33): coverage of Singapore\'s Personal Data Protection
// Act 2012 (as amended) under the Shared Responsibility schema.
//
// APPLICABILITY
//
//   PDPA applies to organisations that collect, use, or disclose
//   personal data of individuals in Singapore in the course of
//   their activities. Extraterritorial reach: applies whether or
//   not the organisation has a physical presence in Singapore,
//   provided the personal data of Singapore-located individuals is
//   processed.
//
//   FireAlive is NOT inherently subject to PDPA. The statute does
//   not name FireAlive nor any class to which FireAlive belongs as
//   automatically scoped; applicability depends on each operator\'s
//   business activities and Singapore exposure.
//
//   This framework definition is provided for customers processing
//   personal data of Singapore individuals and have adopted
//   FireAlive in their SOC operations. The technical controls
//   support compliance with §24 protection obligation, §25
//   retention limitation, §26 transfer limitation, §21-22 access
//   and correction, and §26D breach notification timing. The
//   customer remains responsible for §11 compliance accountability,
//   §11A Data Protection Officer designation, §13-17 consent
//   management, §18 notification, §26C PDPC notification workflow,
//   and §26D affected-individual notification workflow.
//
//   For customers not processing Singapore personal data, this
//   framework report can be ignored without consequence.
//
// AUTHORITY
//
//   Personal Data Protection Commission (PDPC), the regulatory
//   authority established under PDPA Part II. PDPC is part of the
//   Infocomm Media Development Authority (IMDA) for administrative
//   support. PDPC has investigation, direction, and enforcement
//   powers.
//
// PENALTIES
//
//   Following the 2022 financial penalty amendments (in force 1
//   October 2022), maximum penalty is the higher of:
//     - SGD 1,000,000 per offence
//     - 10% of annual turnover in Singapore (for organisations
//       with annual turnover in Singapore exceeding SGD 10
//       million)
//
//   Pre-2022, the cap was SGD 1,000,000 only, regardless of
//   organisation size. The 2022 amendment substantially increased
//   enforcement exposure for larger organisations.
//
// SCOPE OF THIS FRAMEWORK DEFINITION
//
//   Personal Data Protection Act 2012 (Act 26 of 2012) as amended,
//   focusing on Part IV Data Protection Provisions:
//     - §11 Compliance with the Act
//     - §11A-12 Data Protection Officer
//     - §13-17 Consent obligations (including deemed consent and
//       deemed consent by notification under 2020 amendments)
//     - §18 Notification obligation
//     - §21-22 Access and Correction obligations
//     - §23 Accuracy obligation
//     - §24 Protection obligation
//     - §25 Retention limitation obligation
//     - §26 Transfer limitation obligation
//     - §26A-26E Data Breach Notification obligation (added by
//       2020 amendments, in force February 2021)
//
//   verifiedControls map platform implementations to §24
//   protection, §25 retention, §26 transfer, §21-22 access and
//   correction, §26D breach notification, and §11A DPO support.
//   customerResponsibility covers §11 accountability, §11A DPO
//   designation, §13-17 consent management, §18 notification,
//   §23 accuracy, §26B-D breach workflow, and PDPC sub-regulation
//   tracking.
//
//   The Do-Not-Call (DNC) Registry under PDPA Part IX is a
//   distinct compliance regime not covered here; operators
//   sending unsolicited marketing communications to Singapore
//   numbers should additionally implement DNC checks.
//
// AGPL-3.0-or-later
// ═══════════════════════════════════════════════════════════════════════════════

module.exports = (checks) => ({
  name: 'PDPA (Singapore)',
  authority: 'Personal Data Protection Commission (PDPC)',
  citation: 'Personal Data Protection Act 2012 (Act 26 of 2012) as amended',
  verifiedControls: [
    {
      id: '§24 [Encryption]',
      name: 'Protection Obligation -- Encryption',
      check: checks.checkEncryption,
      mapping: 'AES-256-GCM at rest via TIER1/TIER3 keys (distinct); TLS 1.2+ at reverse proxy in transit. §24 requires reasonable security arrangements to protect personal data in possession or under control of the organisation against unauthorised access, collection, use, disclosure, copying, modification, disposal or similar risks.',
    },
    {
      id: '§24 [Access]',
      name: 'Protection Obligation -- Access Control',
      check: checks.checkAccessControl,
      mapping: 'Role-based access control via users.role; route-level authMiddleware; scoped API keys. §24 protection obligation includes administrative measures restricting access to authorised personnel.',
    },
    {
      id: '§25',
      name: 'Retention Limitation Obligation',
      check: checks.checkRetentionPolicy,
      mapping: 'Configurable retention policies via retention_config; offboarding workflow honors retention obligations while supporting deletion when allowable. §25 requires personal data to be ceased to be retained when the purpose for collection is no longer being served and retention is no longer necessary for legal or business purposes.',
    },
    {
      id: '§26',
      name: 'Transfer Limitation Obligation',
      check: checks.checkCrossBorderTransferControls,
      mapping: 'integration_config tracks cross-border data flows; cross_border_transfer_controls table records adequacy decisions and contractual safeguards. §26 prohibits transfer of personal data outside Singapore except in accordance with PDPC requirements for ensuring comparable protection.',
    },
    {
      id: '§21',
      name: 'Access Obligation',
      check: checks.checkDataSubjectRights,
      mapping: 'POST /api/legal-hold/export produces structured exports (user record + audit history). §21 requires organisations to provide individuals with their personal data and information about how it has been used or disclosed within the past year; response workflow is operator-side.',
    },
    {
      id: '§22',
      name: 'Correction Obligation',
      check: checks.checkDataSubjectRights,
      mapping: 'User-update endpoints permit correction of personal data per §22. Where information has been disclosed to other organisations, the organisation must send corrected information to those organisations unless they no longer need it.',
    },
    {
      id: '§26D',
      name: 'Breach Notification Timing (3 days PDPC / concurrent affected individuals)',
      check: checks.checkNotificationTiming,
      mapping: 'sla_config tracks internal MTTA/MTTR; notification_config provides multi-channel alert delivery. §26C requires PDPC notification within 3 calendar days of assessment that breach is notifiable (results in significant harm or affects 500+ individuals). §26D requires concurrent notification to affected individuals.',
    },
    {
      id: '§11A',
      name: 'Data Protection Officer Support',
      check: checks.checkAuditControls,
      mapping: 'auditMiddleware records every /api/ request to audit_log; SIEM streaming provides external evidence. §11A requires designation of one or more DPOs whose business contact information is publicly available; comprehensive audit trail supports the DPO\'s ongoing oversight function.',
    },
  ],
  customerResponsibility: [
    {
      id: '§11',
      name: 'Compliance Accountability',
      category: 'organizational',
      detail: 'Organisations are responsible for personal data in their possession or under their control, including data processed by data intermediaries. Develop and implement policies and practices necessary for compliance; communicate to staff; make policies available on request. Liability extends to data intermediary actions.',
    },
    {
      id: '§11A',
      name: 'Data Protection Officer (DPO) Designation',
      category: 'organizational',
      detail: 'Designate at least one DPO responsible for ensuring compliance with PDPA. Make DPO business contact information publicly available (typically on the organisation website). DPO duties include policy implementation, training, complaint handling, liaison with PDPC. DPO may be an internal role or outsourced.',
    },
    {
      id: '§13-17',
      name: 'Consent Management',
      category: 'procedural',
      detail: 'Obtain consent for collection, use, or disclosure of personal data (except where deemed consent under §15, deemed consent by notification under §15A, or other statutory exceptions apply). §15A deemed consent by notification permits processing without express consent if reasonable notice is given. Document consent records, type of consent, scope.',
    },
    {
      id: '§17 [Purpose]',
      name: 'Purpose Limitation Documentation',
      category: 'documentation',
      detail: 'Personal data collected, used, or disclosed only for purposes that a reasonable person would consider appropriate in the circumstances and to which consent (or deemed consent / exception) applies. Document the purposes for each personal data category and processing activity.',
    },
    {
      id: '§18',
      name: 'Notification Obligation',
      category: 'procedural',
      detail: 'On or before collecting, using, or disclosing personal data, inform the individual of the purposes. Notification can be in the privacy notice, consent form, or otherwise. Document notification mechanisms; verify notification preceded collection.',
    },
    {
      id: '§23',
      name: 'Accuracy Obligation',
      category: 'procedural',
      detail: 'Make reasonable efforts to ensure personal data collected by or on behalf of the organisation is accurate and complete, especially if the data is likely to be used to make a decision affecting the individual or be disclosed to another organisation. Document accuracy-maintenance procedures.',
    },
    {
      id: '§26B(1)',
      name: 'Significant Harm Threshold Determination',
      category: 'procedural',
      detail: 'Assess each data breach against the notifiability threshold under §26B(1): (a) results in or is likely to result in significant harm to affected individuals, OR (b) is of significant scale (500 or more individuals). Document the determination methodology and decision trail. Reasonable expedition expected.',
    },
    {
      id: '§26C [Workflow]',
      name: 'PDPC Notification Workflow (3 calendar days)',
      category: 'procedural',
      detail: 'Notify PDPC of notifiable breach as soon as practicable but in any case no later than 3 calendar days after assessment. Notification template prescribed; include circumstances, types of personal data involved, individuals affected, remedial actions, contact for follow-up.',
    },
    {
      id: '§26D [Workflow]',
      name: 'Affected Individual Notification Workflow (Concurrent)',
      category: 'procedural',
      detail: 'Notify affected individuals concurrent with PDPC notification (so the individual notification is also as soon as practicable, capped at 3 calendar days after assessment). Notification in writing, by any means under §26D(2). Exemptions for law-enforcement-directed delay or where remedial action eliminates significant harm.',
    },
    {
      id: '§26E',
      name: 'Breach Notification Exemptions Awareness',
      category: 'procedural',
      detail: 'Awareness of §26E exemptions to notification: (a) where remedial action eliminates significant harm to affected individuals, (b) where data is rendered unusable through encryption or other means making it unintelligible, (c) where PDPC permits non-notification. Document the exemption-claim analysis when invoked.',
    },
    {
      id: 'Workforce-Training',
      name: 'Workforce PDPA Training',
      category: 'training',
      detail: 'Train personnel handling personal data on PDPA obligations including consent, purpose limitation, access/correction request handling, breach reporting, DPO escalation. PDPC has published guidance on training expectations; document training cadence and role-specific content.',
    },
    {
      id: 'DNC-Registry',
      name: 'Do-Not-Call (DNC) Registry Awareness',
      category: 'procedural',
      detail: 'PDPA Part IX governs Do-Not-Call Registry for marketing communications to Singapore telephone numbers. If the organisation sends unsolicited marketing to Singapore numbers, additional DNC obligations apply (separate from this framework definition). Implement DNC check before marketing.',
    },
    {
      id: 'Sector-Specific',
      name: 'Sector-Specific Considerations',
      category: 'procedural',
      detail: 'Financial sector entities additionally subject to Monetary Authority of Singapore (MAS) PSN (Payment Services Notice), TRM (Technology Risk Management) Guidelines, and other MAS notices. Healthcare under various Ministry of Health regulations. Identify sectoral overlays applicable to the entity.',
    },
    {
      id: 'PDPC-Guidance',
      name: 'PDPC Advisory Guidelines and Public Consultation Tracking',
      category: 'procedural',
      detail: 'PDPC issues Advisory Guidelines covering personal data handling in specific sectors (selected industries, telecoms, real estate, social services, etc.) and on specific topics (anonymisation, AI, cloud computing). Track PDPC public consultations on draft guidelines; participate where the entity has standing interest.',
    },
  ],
  note: 'PDPA 2012 has been amended multiple times. Key amendments: 2020 amendment (in force February 2021) introduced mandatory breach notification (§26A-E) and deemed consent by notification (§15A); 2022 amendment (in force 1 October 2022) substantially increased financial penalties to higher of SGD 1M or 10% annual Singapore turnover. The breach notification regime is one of the faster-clock-time regimes globally (3 calendar days), shorter than GDPR\'s 72 hours but with a higher notifiability threshold (significant harm OR 500+ individuals). Operators processing Singapore data alongside EU or other jurisdictions can leverage substantial overlap in protection-obligation implementations but must track jurisdiction-specific procedural rules. Singapore positions itself as a data-protection-friendly hub in Southeast Asia; the PDPA framework is influential across ASEAN.',
});
